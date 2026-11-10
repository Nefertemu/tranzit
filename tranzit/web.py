"""Веб-панель: HTTPS, секретный путь, вход по паролю, JSON API."""
import http.server
import json
import os
import re
import secrets
import socket
import ssl
import threading
import time

from . import VERSION, engine, monitor, netutil, nodes, store

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
PLAIN = os.environ.get("TRANZIT_HTTP") == "1"  # только для разработки
SESSION_TTL = 7 * 86400
MAX_BODY = 1 << 20

_sessions = {}   # token -> истекает
_fails = {}      # ip -> [число неудач, заблокирован до]
_guard = threading.Lock()
_doctor = {"at": 0, "data": []}


class ApiError(Exception):
    def __init__(self, code, text):
        super().__init__(text)
        self.code = code


def _find(items, item_id, what):
    for x in items:
        if x["id"] == item_id:
            return x
    raise ApiError(404, "%s не найден — возможно, его уже удалили. Обновите страницу." % what)


# ── действия ────────────────────────────────────────────────────────────

def api_state(_body):
    s = store.load()
    tr = engine.traffic(s)
    now = time.time()
    if now - _doctor["at"] > 20:
        _doctor["data"], _doctor["at"] = engine.doctor(s), now
    rules = [dict(r, **tr.get(r["id"], {"up": 0, "down": 0})) for r in s["rules"]]
    # ключи протоколов наружу не отдаём — только названия; сами ключи — по кнопке
    servers = [dict(sv, used=sum(1 for r in s["rules"] if r["dip"] == sv["ip"]),
                    protocols=sorted(sv.get("protocols", {})), **monitor.view(sv["ip"]))
               for sv in s["servers"]]
    settings = dict(s["settings"])
    settings["tg_token_set"] = bool(settings.pop("tg_token"))
    try:
        uptime = float(open("/proc/uptime").read().split()[0])
    except (OSError, ValueError):
        uptime = 0
    return {"rules": rules, "servers": servers, "settings": settings,
            "local": sorted((s.get("local") or {}).get("protocols", {})),
            "catalog": {k: {"title": v[0], "proto": v[1], "port": v[2]} for k, v in nodes.PROTOCOLS.items()},
            "system": {"host": socket.gethostname(), "ip": netutil.local_ip(), "version": VERSION,
                       "load": round(os.getloadavg()[0], 2), "uptime": int(uptime),
                       "problems": _doctor["data"], "dry": store.DRY}}


def _changed():
    _doctor["at"] = 0


def rule_create(body):
    with store.edit() as s:
        r = store.validate_rule(s, body, busy=engine.listening())
        r["id"] = store.new_id(s["rules"])
        r["created"] = int(time.time())
        s["rules"].append(r)
        store.ensure_server(s, r["dip"])
        engine.apply(s)
    _changed()
    return r


def rule_update(body, rid):
    with store.edit() as s:
        old = _find(s["rules"], rid, "Правило")
        merged = dict(old, **{k: v for k, v in body.items() if k not in ("id", "created")})
        busy = engine.listening() if merged.get("lport") != old["lport"] or merged.get("proto") != old["proto"] else None
        new = store.validate_rule(s, merged, rule_id=rid, busy=busy)
        old.update(new)
        store.ensure_server(s, old["dip"])
        engine.apply(s)
    _changed()
    return old


def rule_delete(_body, rid):
    with store.edit() as s:
        _find(s["rules"], rid, "Правило")
        s["rules"] = [r for r in s["rules"] if r["id"] != rid]
        engine.apply(s)
    _changed()
    return {"ok": True}


def server_update(body, sid):
    with store.edit() as s:
        sv = store.validate_server(body, _find(s["servers"], sid, "Сервер"))
    return sv


def server_delete(_body, sid):
    with store.edit() as s:
        sv = _find(s["servers"], sid, "Сервер")
        used = [r for r in s["rules"] if r["dip"] == sv["ip"]]
        if used:
            raise store.Invalid("На этот сервер ведут правила (%d). Сначала удалите их." % len(used))
        s["servers"] = [x for x in s["servers"] if x["id"] != sid]
    return {"ok": True}


def server_geo(_body, sid):
    ip = _find(store.load()["servers"], sid, "Сервер")["ip"]
    found = netutil.geo(ip)
    if not found:
        raise ApiError(502, "Справочник адресов не ответил. Попробуйте позже.")
    with store.edit() as s:
        _find(s["servers"], sid, "Сервер")["geo"] = found
    return {"geo": found}


def server_ping(_body, sid):
    s = store.load()
    sv = _find(s["servers"], sid, "Сервер")
    ports = [r.get("dport") or r["lport"] for r in s["rules"] if r["dip"] == sv["ip"] and r["proto"] != "udp"]
    return {"ms": monitor.probe(sv["ip"], [p for p in ports if "-" not in p])}


def node_install(body):
    return nodes.start(body)


def job_view(_body, jid):
    job = nodes.jobs.get(jid)
    if not job:
        raise ApiError(404, "Эта установка уже забыта — панель перезапускалась. Обновите страницу.")
    if job["status"] != "run":
        _changed()
    return {"status": job["status"], "log": job["log"], "target": job["target"]}


def server_keys(_body, sid):
    s = store.load()
    return {"keys": nodes.keys(s, _find(s["servers"], sid, "Сервер"))}


def local_keys(_body):
    return {"keys": nodes.keys(store.load())}


def settings_update(body):
    with store.edit() as s:
        old_bbr = s["settings"].get("bbr")
        s["settings"] = store.validate_settings(body, s["settings"])
        if s["settings"]["bbr"] != old_bbr:
            engine.apply(s)
    return {"ok": True}


def telegram_test(_body):
    if not monitor.notify(store.load()["settings"], "✅ Проверка связи: панель Tranzit может вам писать."):
        raise store.Invalid("Сообщение не ушло. Проверьте токен и Chat ID, и что вы нажали «Start» у бота.")
    return {"ok": True}


def password_change(body):
    panel = store.read_json(store.PANEL, {})
    if not store.check_password(str(body.get("old", "")), panel):
        raise store.Invalid("Текущий пароль не подошёл")
    new = str(body.get("new", ""))
    if len(new) < 10:
        raise store.Invalid("Новый пароль — не короче 10 символов")
    store.set_password(new)
    with _guard:
        _sessions.clear()
    return {"ok": True, "relogin": True}


def backup(_body):
    s = store.load()
    return {"tranzit_backup": 1, "rules": s["rules"], "servers": s["servers"], "settings": s["settings"],
            "local": s.get("local") or {}}


def restore(body):
    if body.get("tranzit_backup") != 1 or not isinstance(body.get("rules"), list):
        raise store.Invalid("Это не файл резервной копии Tranzit")
    with store.edit() as s:
        fresh = {"rules": [], "servers": [], "settings": s["settings"], "local": s.get("local") or {}}
        for raw in body["rules"]:
            r = store.validate_rule(fresh, raw)
            r["id"] = store.new_id(fresh["rules"])
            r["created"] = int(raw.get("created") or time.time())
            fresh["rules"].append(r)
            store.ensure_server(fresh, r["dip"])
        for raw in body.get("servers") or []:
            if isinstance(raw, dict) and raw.get("ip"):
                sv = store.ensure_server(fresh, store.check_ip(raw["ip"]))
                store.validate_server(raw, sv)
                sv["geo"] = str(raw.get("geo") or "")[:120]
                if isinstance(raw.get("protocols"), dict):
                    sv["protocols"] = {k: v for k, v in raw["protocols"].items()
                                       if k in nodes.PROTOCOLS and isinstance(v, dict) and isinstance(v.get("port"), int)}
                    sv["ssh_port"] = raw.get("ssh_port") if isinstance(raw.get("ssh_port"), int) else 22
        if isinstance(body.get("settings"), dict):
            fresh["settings"] = store.validate_settings(body["settings"], s["settings"])
        engine.apply(fresh)
        s.clear()
        s.update(fresh)
    _changed()
    return {"ok": True, "rules": len(fresh["rules"])}


ROUTES = [
    ("GET", r"state", api_state),
    ("POST", r"rules", rule_create),
    ("PUT", r"rules/([0-9a-f]{6})", rule_update),
    ("DELETE", r"rules/([0-9a-f]{6})", rule_delete),
    ("PUT", r"servers/([0-9a-f]{6})", server_update),
    ("DELETE", r"servers/([0-9a-f]{6})", server_delete),
    ("POST", r"servers/([0-9a-f]{6})/geo", server_geo),
    ("POST", r"servers/([0-9a-f]{6})/ping", server_ping),
    ("POST", r"nodes", node_install),
    ("GET", r"jobs/([0-9a-f]{6})", job_view),
    ("GET", r"servers/([0-9a-f]{6})/keys", server_keys),
    ("GET", r"local/keys", local_keys),
    ("PUT", r"settings", settings_update),
    ("POST", r"telegram-test", telegram_test),
    ("POST", r"password", password_change),
    ("GET", r"backup", backup),
    ("POST", r"restore", restore),
]


# ── HTTP ────────────────────────────────────────────────────────────────

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "tranzit"
    sys_version = ""
    timeout = 30
    base = "/"

    def log_message(self, *args):
        pass

    def _send(self, code, body=b"", ctype="application/json; charset=utf-8", extra=()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
                         "img-src 'self' data:; frame-ancestors 'none'")
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code=200, extra=()):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode(), extra=extra)

    def _session(self):
        m = re.search(r"(?:^|;\s*)tz_s=([A-Za-z0-9_-]{20,})", self.headers.get("Cookie", ""))
        if not m:
            return None
        with _guard:
            exp = _sessions.get(m.group(1))
            if exp and exp > time.time():
                return m.group(1)
            _sessions.pop(m.group(1), None)
        return None

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n > MAX_BODY:
            raise ApiError(413, "Слишком большой запрос")
        if not n:
            return {}
        try:
            data = json.loads(self.rfile.read(n).decode())
        except (ValueError, UnicodeDecodeError):
            raise ApiError(400, "Запрос не разобран")
        if not isinstance(data, dict):
            raise ApiError(400, "Запрос не разобран")
        return data

    def _cookie(self, token, age):
        return ("Set-Cookie", "tz_s=%s; Path=%s; Max-Age=%d; HttpOnly; SameSite=Strict%s"
                % (token, self.base, age, "" if PLAIN else "; Secure"))

    def _login(self):
        ip, now = self.client_address[0], time.time()
        with _guard:
            f = _fails.get(ip, [0, 0])
            if f[1] > now:
                raise ApiError(429, "Слишком много попыток. Подождите %d с." % (f[1] - now + 1))
        body = self._body()
        if not store.check_password(str(body.get("password", "")), store.read_json(store.PANEL, {})):
            with _guard:
                f = _fails.setdefault(ip, [0, 0])
                f[0] += 1
                if f[0] >= 5:
                    f[0], f[1] = 0, now + 60 * 5
                if len(_fails) > 5000:
                    _fails.clear()
            time.sleep(0.5)
            raise ApiError(401, "Пароль не подошёл")
        token = secrets.token_urlsafe(32)
        with _guard:
            _fails.pop(ip, None)
            for t in [t for t, exp in _sessions.items() if exp < now]:
                del _sessions[t]
            _sessions[token] = now + SESSION_TTL
        self._json({"ok": True}, extra=[self._cookie(token, SESSION_TTL)])

    def _handle(self):
        path = self.path.split("?", 1)[0]
        if path == self.base.rstrip("/") and self.base != "/":
            return self._send(301, extra=[("Location", self.base)])
        if not path.startswith(self.base):
            return self._send(404, b"", "text/plain")  # без секретного пути панели как будто нет
        sub = path[len(self.base):]
        method = self.command
        if method == "GET" and sub in ("", "index.html"):
            with open(os.path.join(STATIC, "index.html"), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if not sub.startswith("api/"):
            return self._send(404, b"", "text/plain")
        sub = sub[4:]
        try:
            if method != "GET" and self.headers.get("X-Requested-With") != "tranzit":
                raise ApiError(403, "Запрос отклонён")
            if method == "POST" and sub == "login":
                return self._login()
            token = self._session()
            if method == "POST" and sub == "logout":
                with _guard:
                    _sessions.pop(token, None)
                return self._json({"ok": True}, extra=[self._cookie("x", 0)])
            if not token:
                raise ApiError(401, "Нужен вход")
            for m, pattern, fn in ROUTES:
                found = re.fullmatch(pattern, sub)
                if m == method and found:
                    body = self._body() if method != "GET" else {}
                    return self._json(fn(body, *found.groups()))
            raise ApiError(404, "Нет такого действия")
        except ApiError as e:
            self._json({"error": str(e)}, e.code)
        except store.Invalid as e:
            self._json({"error": str(e)}, 400)
        except engine.EngineError as e:
            self._json({"error": str(e)}, 500)

    do_GET = do_POST = do_PUT = do_DELETE = _handle


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64
    tls = None

    def get_request(self):
        sock, addr = self.socket.accept()
        if self.tls:
            sock.settimeout(15)
            # рукопожатие — в потоке запроса, чтобы зависший клиент не держал приём остальных
            sock = self.tls.wrap_socket(sock, server_side=True, do_handshake_on_connect=False)
        return sock, addr

    def handle_error(self, request, client_address):
        pass  # сканеры и оборванные соединения — не событие


def serve():
    panel = store.read_json(store.PANEL, {})
    if not panel.get("port") or not panel.get("path"):
        raise SystemExit("Панель не настроена. Выполните: tranzit init")
    Handler.base = "/%s/" % panel["path"]
    host = panel.get("bind", "0.0.0.0")
    srv = Server((host, int(panel["port"])), Handler)
    if not PLAIN:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(panel.get("cert") or os.path.join(store.ETC, "tls", "cert.pem"),
                            panel.get("key") or os.path.join(store.ETC, "tls", "key.pem"))
        srv.tls = ctx
    try:
        with store.locked():
            engine.apply(store.load())
    except engine.EngineError as e:
        print("tranzit: %s" % e, flush=True)
    monitor.start()
    print("tranzit %s: панель на порту %s" % (VERSION, panel["port"]), flush=True)
    srv.serve_forever()

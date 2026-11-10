"""Фоновая проверка серверов выхода и Telegram: тревоги и короткие команды."""
import collections
import concurrent.futures
import json
import socket
import threading
import time
import urllib.parse
import urllib.request

from . import engine, netutil, store

HIST = 240  # точек истории на сервер

_lock = threading.Lock()
history = {}   # ip -> deque([ts, ms|None])
status = {}    # ip -> {"fails": n, "down": bool, "slow": n, "slow_alert": bool}
_stop = threading.Event()


def tg_call(token, method, params, timeout=15):
    data = urllib.parse.urlencode(params).encode()
    url = "https://api.telegram.org/bot%s/%s" % (token, method)
    with urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=timeout) as r:
        return json.loads(r.read().decode())


def notify(settings, text):
    """Отправить сообщение владельцу. True — ушло."""
    if not settings.get("tg_token") or not settings.get("tg_chat"):
        return False
    try:
        tg_call(settings["tg_token"], "sendMessage",
                {"chat_id": settings["tg_chat"], "text": "%s\n— %s" % (text, socket.gethostname())})
        return True
    except (OSError, ValueError):
        return False


def _label(sv):
    return "%s (%s)" % (sv["name"], sv["ip"]) if sv.get("name") else sv["ip"]


def _targets(state):
    out = []
    for sv in state["servers"]:
        if not sv.get("monitor", True):
            continue
        ports = [r.get("dport") or r["lport"] for r in state["rules"]
                 if r["dip"] == sv["ip"] and r["proto"] != "udp" and "-" not in (r.get("dport") or r["lport"])]
        out.append((sv, ports))
    return out


def probe(ip, ports=()):
    ms = netutil.measure(ip, ports)
    with _lock:
        history.setdefault(ip, collections.deque(maxlen=HIST)).append([int(time.time()), ms])
    return ms


def _check(state):
    settings = state["settings"]
    need = settings["mon_fails"]
    targets = _targets(state)
    if not targets:
        return
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda t: probe(t[0]["ip"], t[1]), targets))
    for (sv, _), ms in zip(targets, results):
        st = status.setdefault(sv["ip"], {"fails": 0, "down": False, "slow": 0, "slow_alert": False})
        if ms is None:
            st["fails"] += 1
            if st["fails"] >= need and not st["down"]:
                st["down"] = True
                notify(settings, "🔴 Сервер %s не отвечает (%d проверок подряд)" % (_label(sv), st["fails"]))
            continue
        if st["down"]:
            notify(settings, "🟢 Сервер %s снова отвечает, задержка %.0f мс" % (_label(sv), ms))
        st["fails"], st["down"] = 0, False
        th = sv.get("threshold") or 0
        if th and ms > th:
            st["slow"] += 1
            if st["slow"] >= need and not st["slow_alert"]:
                st["slow_alert"] = True
                notify(settings, "🟡 Сервер %s: задержка %.0f мс, выше порога %d мс" % (_label(sv), ms, th))
        else:
            if st["slow_alert"]:
                notify(settings, "🟢 Сервер %s: задержка вернулась в норму, %.0f мс" % (_label(sv), ms))
            st["slow"], st["slow_alert"] = 0, False


def _monitor_loop():
    n = 0
    while not _stop.is_set():
        try:
            state = store.load()
            _check(state)
            known = {sv["ip"] for sv in state["servers"]}
            with _lock:
                for ip in [i for i in history if i not in known]:
                    history.pop(ip, None)
                    status.pop(ip, None)
            n += 1
            if n % 5 == 0:
                engine.snapshot()
            wait = state["settings"]["mon_interval"]
        except Exception:  # фоновый поток не должен умирать из-за одной ошибки
            wait = 30
        _stop.wait(wait)


# ── бот ─────────────────────────────────────────────────────────────────

def _fmt_bytes(n):
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if n < 1024 or unit == "ТБ":
            return ("%.1f %s" % (n, unit)) if unit != "Б" else "%d Б" % n
        n /= 1024


def _cmd_status(state):
    lines = []
    for sv in state["servers"]:
        with _lock:
            h = history.get(sv["ip"])
            last = h[-1][1] if h else None
            seen = bool(h)
        mark = "⚪" if not seen else ("🔴" if last is None else "🟢")
        tail = "нет данных" if not seen else ("не отвечает" if last is None else "%.0f мс" % last)
        lines.append("%s %s — %s" % (mark, _label(sv), tail))
    return "\n".join(lines) or "Серверов пока нет. Добавьте правило в панели."


def _cmd_rules(state):
    tr = engine.traffic(state)
    lines = []
    for r in state["rules"]:
        t = tr.get(r["id"], {"up": 0, "down": 0})
        lines.append("%s %s %s/%s → %s:%s  ↑%s ↓%s" % (
            "▶️" if r.get("enabled", True) else "⏸", r.get("name") or "без имени", r["lport"], r["proto"],
            r["dip"], r.get("dport") or r["lport"], _fmt_bytes(t["up"]), _fmt_bytes(t["down"])))
    return "\n".join(lines) or "Правил пока нет."


def _cmd_ping(state):
    lines = []
    for sv, ports in _targets(state) or [(sv, []) for sv in state["servers"]]:
        ms = probe(sv["ip"], ports)
        lines.append("%s — %s" % (_label(sv), "не отвечает" if ms is None else "%.1f мс" % ms))
    return "\n".join(lines) or "Серверов пока нет."


HELP = "Команды:\n/status — серверы выхода\n/rules — правила и трафик\n/ping — замерить задержку сейчас"


def _bot_loop():
    offset, token_seen = 0, ""
    while not _stop.is_set():
        settings = store.load()["settings"]
        token = settings.get("tg_token")
        if not token:
            _stop.wait(5)
            continue
        if token != token_seen:
            offset, token_seen = 0, token
        try:
            res = tg_call(token, "getUpdates", {"offset": offset, "timeout": 25}, timeout=35)
        except (OSError, ValueError):
            _stop.wait(10)
            continue
        for upd in res.get("result", []):
            offset = upd["update_id"] + 1
            msg = upd.get("message") or {}
            chat = str((msg.get("chat") or {}).get("id", ""))
            text = (msg.get("text") or "").split("@")[0].strip().lower()
            if not chat:
                continue
            try:
                if not settings.get("tg_chat"):
                    reply = "Ваш Chat ID: %s\nВпишите его в панели: Настройки → Telegram." % chat
                elif chat != settings["tg_chat"]:
                    continue  # чужим не отвечаем вовсе
                elif text == "/status":
                    reply = _cmd_status(store.load())
                elif text == "/rules":
                    reply = _cmd_rules(store.load())
                elif text == "/ping":
                    reply = _cmd_ping(store.load())
                else:
                    reply = HELP
                tg_call(token, "sendMessage", {"chat_id": chat, "text": reply})
            except (OSError, ValueError):
                pass


def start():
    for fn in (_monitor_loop, _bot_loop):
        threading.Thread(target=fn, daemon=True, name=fn.__name__).start()


def view(ip, points=60):
    """Что показать в панели про сервер."""
    with _lock:
        h = list(history.get(ip, ()))[-points:]
    st = status.get(ip, {})
    return {"ms": h[-1][1] if h else None, "seen": bool(h), "down": bool(st.get("down")),
            "hist": [p[1] for p in h]}

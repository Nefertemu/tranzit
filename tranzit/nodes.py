"""Ноды: вход по SSH и установка протоколов — на сервер выхода или на этот сервер."""
import base64
import os
import re
import secrets
import subprocess
import threading
import time

from . import engine, netutil, store

SSH_DIR = os.path.join(store.ETC, "ssh")
KEY = os.path.join(SSH_DIR, "id_ed25519")
KNOWN = os.path.join(SSH_DIR, "known_hosts")
ASKPASS = os.path.join(SSH_DIR, "askpass")

# протокол: название, транспорт, порт по умолчанию
PROTOCOLS = {
    "vless": ("VLESS + Reality (Xray)", "tcp", 443),
    "wg": ("WireGuard", "udp", 51820),
    "awg": ("AmneziaWG", "udp", 51821),
    "mtproto": ("MTProto (прокси Telegram)", "tcp", 8443),
}
_HOST = re.compile(r"^(?=.{4,80}$)[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")

jobs = {}
_jobs_lock = threading.Lock()


class Fail(Exception):
    pass


# ── запрос ──────────────────────────────────────────────────────────────

def parse_request(body):
    """Проверить всё, что придёт в сценарий установки: туда попадают только числа и имена сайтов."""
    local = body.get("target") == "local"
    req = {"local": local, "name": str(body.get("name") or "").strip()[:60], "protocols": {}}
    if not local:
        req["ip"] = store.check_ip(body.get("ip", ""))
        try:
            req["ssh_port"] = int(body.get("ssh_port") or 22)
        except (TypeError, ValueError):
            raise store.Invalid("Порт SSH — число, обычно 22")
        if not 1 <= req["ssh_port"] <= 65535:
            raise store.Invalid("Порт SSH — число, обычно 22")
        req["password"] = str(body.get("password") or "")
        if len(req["password"]) > 200 or "\n" in req["password"]:
            raise store.Invalid("Пароль не похож на пароль")
    chosen = body.get("protocols")
    if not isinstance(chosen, dict) or not chosen:
        raise store.Invalid("Отметьте хотя бы один протокол")
    seen = set()
    for kind, opt in chosen.items():
        if kind not in PROTOCOLS or not isinstance(opt, dict):
            raise store.Invalid("Неизвестный протокол: %s" % kind)
        lo, hi = store.parse_ports(opt.get("port") or PROTOCOLS[kind][2])
        if lo != hi:
            raise store.Invalid("%s: нужен один порт, не диапазон" % PROTOCOLS[kind][0])
        if (PROTOCOLS[kind][1], lo) in seen:
            raise store.Invalid("Порт %d выбран для двух протоколов сразу" % lo)
        seen.add((PROTOCOLS[kind][1], lo))
        p = {"port": lo}
        if kind in ("wg", "awg"):
            try:
                p["clients"] = int(opt.get("clients") or 3)
            except (TypeError, ValueError):
                raise store.Invalid("Число устройств — от 1 до 20")
            if not 1 <= p["clients"] <= 20:
                raise store.Invalid("Число устройств — от 1 до 20")
        if kind in ("vless", "mtproto"):
            host = str(opt.get("host") or ("www.microsoft.com" if kind == "vless" else "www.google.com")).strip().lower()
            if not _HOST.match(host):
                raise store.Invalid("%s: сайт для маскировки — имя вида www.example.com" % PROTOCOLS[kind][0])
            p["host"] = host
        req["protocols"][kind] = p
    if local:
        busy = engine.listening()
        for kind, p in req["protocols"].items():
            proto = PROTOCOLS[kind][1]
            for r in store.load()["rules"]:
                lo, hi = store.parse_ports(r["lport"])
                if lo <= p["port"] <= hi and r["proto"] in (proto, "both"):
                    raise store.Invalid("Порт %d занят правилом проброса «%s»" % (p["port"], r.get("name") or r["lport"]))
            done = (store.load().get("local") or {}).get("protocols", {})
            if p["port"] in busy[proto] and kind not in done:
                raise store.Invalid("Порт %d/%s на этом сервере уже занят другой службой" % (p["port"], proto))
    return req


# ── сценарий установки (выполняется на ноде от root) ────────────────────

SCRIPT = r'''
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive LC_ALL=C
D=/etc/tranzit-node
fail() { echo "ОШИБКА: $*"; exit 1; }
emit() { printf '@@R %s %s\n' "$1" "$(printf '%s' "$2" | base64 | tr -d '\n')"; }
[ "$(id -u)" = 0 ] || fail "нужен вход под root"
command -v apt-get >/dev/null || fail "поддерживаются только Debian и Ubuntu"
command -v systemctl >/dev/null || fail "на сервере нет systemd"
mkdir -p $D; chmod 700 $D
APT_DONE=""
pkg() {
    if [ -z "$APT_DONE" ]; then echo "Обновляю список пакетов…"; apt-get update -qq || fail "apt-get update не прошёл"; APT_DONE=1; fi
    echo "Ставлю пакеты: $*"
    apt-get install -y -qq "$@" >/dev/null || fail "не поставились пакеты: $*"
}
open_port() {
    if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then ufw allow "$1" >/dev/null; fi
}
alive() { sleep 2; systemctl is-active -q "$1" || { journalctl -u "$1" -n 15 --no-pager || true; fail "служба $1 не запустилась"; }; }
IFACE=$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
[ -n "$IFACE" ] || fail "не нашёл сетевой интерфейс с выходом в интернет"

do_vless() {
    local f=$D/vless.env cfg=/usr/local/etc/xray/config.json
    if [ ! -f $f ]; then
        echo "== VLESS + Reality =="
        if [ -s $cfg ] && grep -q '"inbounds"' $cfg; then fail "на сервере уже настроен Xray ($cfg) — чужую настройку не трогаю"; fi
        pkg curl openssl ca-certificates unzip
        if ! command -v xray >/dev/null && [ ! -x /usr/local/bin/xray ]; then
            echo "Скачиваю Xray…"
            bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null 2>&1 || fail "Xray не установился (нет доступа к GitHub?)"
        fi
        local X=/usr/local/bin/xray uuid keys priv pub sid
        uuid=$($X uuid); keys=$($X x25519)
        priv=$(printf '%s\n' "$keys" | sed -n 1p | awk '{print $NF}')
        pub=$(printf '%s\n' "$keys" | sed -n 2p | awk '{print $NF}')
        sid=$(openssl rand -hex 8)
        [ -n "$priv" ] && [ -n "$pub" ] || fail "Xray не выдал ключи"
        mkdir -p /usr/local/etc/xray
        cat > $cfg <<EOF
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"0.0.0.0","port":$VLESS_PORT,"protocol":"vless",
  "settings":{"clients":[{"id":"$uuid","flow":"xtls-rprx-vision"}],"decryption":"none"},
  "streamSettings":{"network":"tcp","security":"reality",
   "realitySettings":{"dest":"$VLESS_HOST:443","serverNames":["$VLESS_HOST"],"privateKey":"$priv","shortIds":["$sid"]}},
  "sniffing":{"enabled":true,"destOverride":["http","tls","quic"]}}],
 "outbounds":[{"protocol":"freedom","tag":"direct"}]}
EOF
        chmod 644 $cfg
        printf 'V_PORT=%s\nV_HOST=%s\nV_UUID=%s\nV_PUB=%s\nV_SID=%s\n' "$VLESS_PORT" "$VLESS_HOST" "$uuid" "$pub" "$sid" > $f
        systemctl enable -q xray; systemctl restart xray
    else
        echo "VLESS уже установлен — беру прежние ключи"
    fi
    . $f
    alive xray; open_port "$V_PORT/tcp"
    emit vless.port "$V_PORT"; emit vless.host "$V_HOST"; emit vless.uuid "$V_UUID"; emit vless.pub "$V_PUB"; emit vless.sid "$V_SID"
}

# do_tunnel <wg|awg> <программа> <каталог> <интерфейс> <подсеть> <порт> <устройств>
do_tunnel() (
    kind=$1; tool=$2; dir=$3; ifn=$4; net=$5; port=$6; n=$7; f=$D/$kind.env
    if [ ! -f $f ]; then
        umask 077; mkdir -p "$dir"
        spriv=$($tool genkey); spub=$(printf '%s' "$spriv" | $tool pubkey); extra=""
        if [ "$kind" = awg ]; then
            s1=$((RANDOM % 100 + 20)); s2=$((RANDOM % 100 + 20)); [ "$s2" = "$((s1 + 56))" ] && s2=$((s2 + 1))
            extra="Jc = $((RANDOM % 5 + 4))|Jmin = 50|Jmax = 1000|S1 = $s1|S2 = $s2"
            for i in 1 2 3 4; do extra="$extra|H$i = $(( (RANDOM << 15 | RANDOM) + 5 + (i - 1) * 1073741824 ))"; done
        fi
        {
            echo "[Interface]"; echo "Address = $net.1/24"; echo "ListenPort = $port"; echo "PrivateKey = $spriv"
            [ -n "$extra" ] && printf '%s\n' "$extra" | tr '|' '\n'
            echo "PostUp = nft -f $D/$kind.nft"; echo "PostDown = nft delete table ip tz$kind"
        } > "$dir/$ifn.conf"
        keys=""
        for i in $(seq 1 "$n"); do
            cpriv=$($tool genkey); cpub=$(printf '%s' "$cpriv" | $tool pubkey); keys="$keys $cpriv"
            printf '\n[Peer]\nPublicKey = %s\nAllowedIPs = %s.%s/32\n' "$cpub" "$net" "$((i + 1))" >> "$dir/$ifn.conf"
        done
        cat > $D/$kind.nft <<EOF
table ip tz$kind
delete table ip tz$kind
table ip tz$kind {
	chain post { type nat hook postrouting priority srcnat; policy accept;
		ip saddr $net.0/24 oifname "$IFACE" masquerade
	}
	chain fwd { type filter hook forward priority filter; policy accept;
		tcp flags syn tcp option maxseg size set rt mtu
	}
}
EOF
        echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/90-tranzit-node.conf
        sysctl -q -p /etc/sysctl.d/90-tranzit-node.conf
        printf 'T_PORT=%s\nT_SPUB="%s"\nT_NET=%s\nT_KEYS="%s"\nT_EXTRA="%s"\n' "$port" "$spub" "$net" "${keys# }" "$extra" > $f
        systemctl enable -q "$tool-quick@$ifn"; systemctl restart "$tool-quick@$ifn"
    else
        echo "Уже установлен — беру прежние ключи"
    fi
    . $f
    systemctl is-active -q "$tool-quick@$ifn" || { journalctl -u "$tool-quick@$ifn" -n 15 --no-pager || true; fail "туннель $ifn не поднялся"; }
    open_port "$T_PORT/udp"
    emit $kind.port "$T_PORT"; emit $kind.spub "$T_SPUB"; emit $kind.net "$T_NET"; emit $kind.keys "$T_KEYS"; emit $kind.extra "$T_EXTRA"
)

do_wg() {
    echo "== WireGuard =="
    [ -f $D/wg.env ] || pkg wireguard-tools nftables
    do_tunnel wg wg /etc/wireguard tzwg 10.66.66 "$WG_PORT" "$WG_CLIENTS"
}

do_awg() {
    echo "== AmneziaWG =="
    if [ ! -f $D/awg.env ] && ! command -v awg >/dev/null; then
        grep -qi ubuntu /etc/os-release || fail "AmneziaWG пока ставится только на Ubuntu (на этом сервере другая система)"
        pkg software-properties-common nftables "linux-headers-$(uname -r)"
        echo "Подключаю хранилище Amnezia и собираю модуль ядра — это несколько минут…"
        add-apt-repository -y ppa:amnezia/ppa >/dev/null 2>&1 || fail "не подключилось хранилище ppa:amnezia/ppa"
        APT_DONE=""; pkg amneziawg
        command -v awg >/dev/null || fail "пакет amneziawg поставился, но команды awg нет"
    fi
    do_tunnel awg awg /etc/amnezia/amneziawg tzawg 10.77.77 "$AWG_PORT" "$AWG_CLIENTS"
}

do_mtproto() {
    local f=$D/mtproto.env a url t secret
    if [ ! -f $f ]; then
        echo "== MTProto =="
        pkg curl ca-certificates tar
        case "$(uname -m)" in x86_64) a=amd64 ;; aarch64) a=arm64 ;; *) fail "MTProto: процессор $(uname -m) не поддерживается" ;; esac
        url=$(curl -fsSL https://api.github.com/repos/9seconds/mtg/releases/latest | grep -o "https://[^\"]*linux-$a\.tar\.gz" | head -1) || true
        [ -n "$url" ] || fail "не нашёл сборку mtg на GitHub"
        t=$(mktemp -d); curl -fsSL "$url" | tar -xz -C "$t" || fail "mtg не скачался"
        install -m 755 "$(find "$t" -type f -name mtg | head -1)" /usr/local/bin/mtg; rm -rf "$t"
        secret=$(/usr/local/bin/mtg generate-secret --hex "$MT_HOST") || fail "mtg не выдал секрет"
        cat > /etc/systemd/system/tranzit-mtg.service <<EOF
[Unit]
Description=Tranzit: MTProto (mtg)
After=network-online.target
[Service]
ExecStart=/usr/local/bin/mtg simple-run 0.0.0.0:$MT_PORT $secret
Restart=always
RestartSec=3
DynamicUser=true
AmbientCapabilities=CAP_NET_BIND_SERVICE
[Install]
WantedBy=multi-user.target
EOF
        printf 'M_PORT=%s\nM_SECRET=%s\n' "$MT_PORT" "$secret" > $f
        systemctl daemon-reload; systemctl enable -q tranzit-mtg; systemctl restart tranzit-mtg
    else
        echo "MTProto уже установлен — беру прежний секрет"
    fi
    . $f
    alive tranzit-mtg; open_port "$M_PORT/tcp"
    emit mtproto.port "$M_PORT"; emit mtproto.secret "$M_SECRET"
}
'''


def build_script(req):
    p = req["protocols"]
    head, calls = [], []
    if "vless" in p:
        head += ["VLESS_PORT=%d" % p["vless"]["port"], "VLESS_HOST=%s" % p["vless"]["host"]]
        calls.append("do_vless")
    if "wg" in p:
        head += ["WG_PORT=%d" % p["wg"]["port"], "WG_CLIENTS=%d" % p["wg"]["clients"]]
        calls.append("do_wg")
    if "awg" in p:
        head += ["AWG_PORT=%d" % p["awg"]["port"], "AWG_CLIENTS=%d" % p["awg"]["clients"]]
        calls.append("do_awg")
    if "mtproto" in p:
        head += ["MT_PORT=%d" % p["mtproto"]["port"], "MT_HOST=%s" % p["mtproto"]["host"]]
        calls.append("do_mtproto")
    return "\n".join(head) + SCRIPT + "\n".join(calls) + '\necho "Готово."\n'


# ── SSH ─────────────────────────────────────────────────────────────────

def _ensure_key():
    os.makedirs(SSH_DIR, mode=0o700, exist_ok=True)
    if not os.path.exists(KEY):
        p = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "tranzit-panel", "-f", KEY],
                           capture_output=True, text=True)
        if p.returncode != 0:
            raise Fail("Не получилось создать SSH-ключ панели: %s" % p.stderr.strip())
    if not os.path.exists(ASKPASS):
        fd = os.open(ASKPASS, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o700)
        with os.fdopen(fd, "w") as f:
            f.write('#!/bin/sh\nprintf \'%s\\n\' "$TRANZIT_SSH_PASS"\n')


def _ssh(req, password=None):
    cmd = ["ssh", "-F", "/dev/null", "-p", str(req["ssh_port"]), "-o", "StrictHostKeyChecking=accept-new",
           "-o", "UserKnownHostsFile=%s" % KNOWN, "-o", "ConnectTimeout=12", "-o", "ServerAliveInterval=15",
           "-o", "LogLevel=ERROR"]
    env = dict(os.environ)
    if password is None:
        cmd += ["-i", KEY, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes"]
    else:
        # пароль отдаёт ssh маленькая программа-подсказчик; в списке процессов его нет
        cmd += ["-o", "PubkeyAuthentication=no", "-o", "PreferredAuthentications=password,keyboard-interactive",
                "-o", "NumberOfPasswordPrompts=1"]
        env.update(SSH_ASKPASS=ASKPASS, SSH_ASKPASS_REQUIRE="force", DISPLAY=":0", TRANZIT_SSH_PASS=password)
    return cmd + ["root@%s" % req["ip"]], env


def _connect(req, log):
    """Добиться входа по ключу панели. Пароль нужен один раз и нигде не сохраняется."""
    _ensure_key()
    cmd, env = _ssh(req)
    try:
        if subprocess.run(cmd + ["true"], env=env, capture_output=True, timeout=30, stdin=subprocess.DEVNULL).returncode == 0:
            log("Вход по ключу панели работает.")
            return
    except subprocess.TimeoutExpired:
        raise Fail("Сервер %s не ответил по SSH на порту %d" % (req["ip"], req["ssh_port"]))
    if not req.get("password"):
        raise Fail("Панель ещё не знает этот сервер — нужен пароль root.")
    log("Вхожу по паролю и оставляю на сервере ключ панели…")
    # пароль введён заново — значит, сервер могли переустановить: старый отпечаток забываем
    subprocess.run(["ssh-keygen", "-R", "[%s]:%d" % (req["ip"], req["ssh_port"]), "-f", KNOWN], capture_output=True)
    subprocess.run(["ssh-keygen", "-R", req["ip"], "-f", KNOWN], capture_output=True)
    pub = open(KEY + ".pub").read().strip()
    remote = ('umask 077; mkdir -p ~/.ssh; k=$(cat); grep -qxF "$k" ~/.ssh/authorized_keys 2>/dev/null '
              '|| printf "%s\\n" "$k" >> ~/.ssh/authorized_keys')
    cmd, env = _ssh(req, req["password"])
    try:
        p = subprocess.run(cmd + [remote], env=env, input=pub, capture_output=True, text=True, timeout=40,
                           start_new_session=True)
    except subprocess.TimeoutExpired:
        raise Fail("Сервер %s не ответил по SSH на порту %d" % (req["ip"], req["ssh_port"]))
    if p.returncode != 0:
        err = p.stderr.strip()
        if "Permission denied" in err:
            raise Fail("Пароль не подошёл — или на сервере запрещён вход root по паролю (PermitRootLogin, PasswordAuthentication).")
        raise Fail("Не удалось войти на %s: %s" % (req["ip"], err.splitlines()[-1] if err else "нет ответа"))
    cmd, env = _ssh(req)
    if subprocess.run(cmd + ["true"], env=env, capture_output=True, timeout=30, stdin=subprocess.DEVNULL).returncode != 0:
        raise Fail("Ключ панели записан, но вход по нему не работает — на сервере запрещён вход root по ключу?")


def _run_script(cmd, env, script, log):
    proc = subprocess.Popen(cmd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, errors="replace")
    proc.stdin.write(script)
    proc.stdin.close()
    results = {}
    for line in proc.stdout:
        line = line.rstrip("\n")
        if line.startswith("@@R "):
            parts = line.split(" ", 2)
            try:
                results[parts[1]] = base64.b64decode(parts[2] if len(parts) > 2 else "").decode()
            except ValueError:
                pass
        elif line.strip():
            log(line[:500])
    if proc.wait() != 0:
        raise Fail("Установка остановилась — причина в строках выше.")
    return results


def _fake(req):
    """Демо-режим: ничего не ставим, возвращаем правдоподобные данные."""
    out = {}
    for kind, p in req["protocols"].items():
        out[kind + ".port"] = str(p["port"])
        if kind == "vless":
            out.update({"vless.host": p["host"], "vless.uuid": "00000000-0000-4000-8000-000000000000",
                        "vless.pub": "DEMO_PUBLIC_KEY", "vless.sid": "0123456789abcdef"})
        elif kind == "mtproto":
            out["mtproto.secret"] = "ee" + "00" * 16
        else:
            out.update({kind + ".spub": "DEMO_SERVER_KEY=", kind + ".net": "10.66.66",
                        kind + ".keys": " ".join("DEMO_CLIENT_KEY_%d=" % i for i in range(p["clients"])),
                        kind + ".extra": "Jc = 4|Jmin = 50|Jmax = 1000" if kind == "awg" else ""})
    return out


# ── итог: запомнить ключи, создать пробросы ─────────────────────────────

def _group(results):
    out = {}
    for key, value in results.items():
        kind, _, field = key.partition(".")
        if kind in PROTOCOLS and field:
            out.setdefault(kind, {})[field] = value
    for kind, data in out.items():
        data["port"] = int(data.get("port") or PROTOCOLS[kind][2])
    return out


def _entry_port(state, ip, kind, port, name):
    """Порт на сервере-входе, который ведёт на протокол ноды. Нет правила — создаём."""
    proto = PROTOCOLS[kind][1]
    for r in state["rules"]:
        if r["dip"] == ip and r["proto"] == proto and (r.get("dport") or r["lport"]) == str(port):
            return r["lport"], False
    busy = engine.listening()
    for k, d in (state.get("local") or {}).get("protocols", {}).items():  # порты протоколов этого сервера
        busy[PROTOCOLS[k][1]].add(d["port"])
    candidates = [port] + [secrets.randbelow(40000) + 20000 for _ in range(30)]
    for lport in candidates:
        data = {"proto": proto, "lport": lport, "dip": ip, "dport": port, "kind": kind if kind != "awg" else "wg",
                "name": ("%s · %s" % (name, PROTOCOLS[kind][0])) if name else PROTOCOLS[kind][0]}
        try:
            r = store.validate_rule(state, data, busy=busy)
        except store.Invalid:
            continue
        r["id"] = store.new_id(state["rules"])
        r["created"] = int(time.time())
        state["rules"].append(r)
        return r["lport"], True
    raise Fail("Не нашёлся свободный порт на этом сервере для %s" % PROTOCOLS[kind][0])


def _finish(req, results, log):
    found = _group(results)
    missing = [PROTOCOLS[k][0] for k in req["protocols"] if k not in found]
    if missing:
        raise Fail("Сервер не вернул данные для: %s" % ", ".join(missing))
    with store.edit() as s:
        if req["local"]:
            s.setdefault("local", {}).setdefault("protocols", {}).update(found)
            return
        sv = store.ensure_server(s, req["ip"])
        if req["name"]:
            sv["name"] = req["name"]
        sv["ssh_port"] = req["ssh_port"]
        sv.setdefault("protocols", {}).update(found)
        for kind, data in found.items():
            lport, created = _entry_port(s, req["ip"], kind, data["port"], sv.get("name"))
            if created:
                log("Проброс: порт %s этого сервера → %s:%d (%s)" % (lport, req["ip"], data["port"], PROTOCOLS[kind][0]))
        engine.apply(s)


def _work(job, req):
    def log(text):
        job["log"].append(text)
    try:
        script = build_script(req)
        if store.DRY:
            log("Демо-режим: настоящей установки нет.")
            time.sleep(1.5)
            results = _fake(req)
        elif req["local"]:
            log("Ставлю на этот сервер…")
            results = _run_script(["bash", "-s"], dict(os.environ), script, log)
        else:
            log("Подключаюсь к %s…" % req["ip"])
            _connect(req, log)
            cmd, env = _ssh(req)
            results = _run_script(cmd + ["bash -s"], env, script, log)
        _finish(req, results, log)
        log("Готово. Ключи — по кнопке «Ключи» у сервера.")
        job["status"] = "ok"
    except (Fail, store.Invalid, engine.EngineError) as e:
        log("✗ %s" % e)
        job["status"] = "fail"
    except Exception as e:  # поток не должен оставить задачу «в работе» навсегда
        log("✗ Внутренняя ошибка: %s" % e)
        job["status"] = "fail"
    finally:
        req.pop("password", None)
        job["done"] = time.time()


def start(body):
    req = parse_request(body)
    with _jobs_lock:
        if any(j["status"] == "run" for j in jobs.values()):
            raise store.Invalid("Одна установка уже идёт — дождитесь её окончания")
        for jid in [j for j, v in jobs.items() if v.get("done") and time.time() - v["done"] > 3600]:
            del jobs[jid]
        jid = secrets.token_hex(3)
        jobs[jid] = job = {"status": "run", "log": [], "done": None,
                           "target": "этот сервер" if req["local"] else req["ip"]}
    threading.Thread(target=_work, args=(job, req), daemon=True, name="node-install").start()
    return {"job": jid}


# ── ключи для клиентов ──────────────────────────────────────────────────

def keys(state, server=None):
    """Готовые ссылки и файлы. Адрес в них — сервер-вход: в этом и есть каскад."""
    entry = netutil.local_ip() or "IP-СЕРВЕРА"
    if server is None:
        protocols, label = (state.get("local") or {}).get("protocols", {}), "Tranzit"
    else:
        protocols, label = server.get("protocols", {}), server.get("name") or server["ip"]
    out = []
    for kind, d in protocols.items():
        port = d["port"]
        if server is not None:
            proto = PROTOCOLS[kind][1]
            rule = next((r for r in state["rules"] if r["dip"] == server["ip"] and r["proto"] in (proto, "both")
                         and (r.get("dport") or r["lport"]) == str(d["port"])), None)
            if not rule:
                out.append({"title": PROTOCOLS[kind][0], "kind": "note",
                            "text": "Проброс на этот протокол удалён. Создайте правило на порт %d/%s сервера %s."
                                    % (d["port"], proto, server["ip"])})
                continue
            port = rule["lport"]
        title = PROTOCOLS[kind][0]
        if kind == "vless":
            out.append({"title": title, "kind": "link", "text":
                        "vless://%s@%s:%s?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=chrome"
                        "&pbk=%s&sid=%s&type=tcp#%s" % (d["uuid"], entry, port, d["host"], d["pub"], d["sid"],
                                                       re.sub(r"[^\w.-]+", "-", label))})
        elif kind == "mtproto":
            out.append({"title": title, "kind": "link",
                        "text": "https://t.me/proxy?server=%s&port=%s&secret=%s" % (entry, port, d["secret"])})
        else:
            extra = [x for x in (d.get("extra") or "").split("|") if x]
            for i, key in enumerate((d.get("keys") or "").split()):
                lines = ["[Interface]", "PrivateKey = %s" % key, "Address = %s.%d/32" % (d["net"], i + 2),
                         "DNS = 1.1.1.1, 8.8.8.8", "MTU = 1280"] + extra + \
                        ["", "[Peer]", "PublicKey = %s" % d["spub"], "AllowedIPs = 0.0.0.0/0",
                         "Endpoint = %s:%s" % (entry, port), "PersistentKeepalive = 25"]
                out.append({"title": "%s — устройство %d" % (title, i + 1), "kind": "conf", "text": "\n".join(lines) + "\n"})
    return out

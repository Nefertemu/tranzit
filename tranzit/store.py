"""Хранилище: состояние на диске, блокировка, проверка введённых данных."""
import contextlib
import copy
import fcntl
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import time

ETC = os.environ.get("TRANZIT_ETC", "/etc/tranzit")
DRY = os.environ.get("TRANZIT_DRY") == "1"

STATE = os.path.join(ETC, "state.json")
PANEL = os.path.join(ETC, "panel.json")
STATS = os.path.join(ETC, "stats.json")

DEFAULTS = {
    "rules": [],
    "servers": [],
    "settings": {
        "tg_token": "",
        "tg_chat": "",
        "mon_interval": 60,
        "mon_fails": 3,
        "bbr": True,
    },
}

KINDS = ("wg", "vless", "mtproto", "custom")
PROTOS = ("tcp", "udp", "both")


class Invalid(ValueError):
    """Ошибка в данных, которую надо показать человеку как есть."""


def read_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return copy.deepcopy(default)
    except (OSError, ValueError):
        return copy.deepcopy(default)


def write_json(path, data):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = "%s.%s.tmp" % (path, secrets.token_hex(4))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


@contextlib.contextmanager
def locked():
    """Одна запись за раз — и между потоками, и между панелью и командой."""
    os.makedirs(ETC, mode=0o700, exist_ok=True)
    with open(os.path.join(ETC, ".lock"), "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield


def load():
    s = read_json(STATE, DEFAULTS)
    for k, v in DEFAULTS.items():
        s.setdefault(k, copy.deepcopy(v))
    for k, v in DEFAULTS["settings"].items():
        s["settings"].setdefault(k, v)
    return s


@contextlib.contextmanager
def edit():
    """Изменить состояние. Исключение внутри блока — на диск ничего не пишется."""
    with locked():
        s = load()
        yield s
        write_json(STATE, s)


# ── проверка данных ─────────────────────────────────────────────────────

def check_ip(value):
    try:
        ip = ipaddress.IPv4Address(str(value).strip())
    except ValueError:
        raise Invalid("Нужен адрес IPv4, например 203.0.113.10")
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
        raise Invalid("Адрес %s не подходит для проброса" % ip)
    return str(ip)


def parse_ports(value):
    """'443' → (443, 443); '1000-2000' → (1000, 2000)."""
    text = str(value).strip().replace(":", "-")
    parts = text.split("-")
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        raise Invalid("Порт — число от 1 до 65535 или диапазон вида 1000-2000")
    if len(nums) == 1:
        nums = nums * 2
    if len(nums) != 2 or not all(1 <= n <= 65535 for n in nums) or nums[0] > nums[1]:
        raise Invalid("Порт — число от 1 до 65535 или диапазон вида 1000-2000")
    return nums[0], nums[1]


def fmt_ports(pair):
    return str(pair[0]) if pair[0] == pair[1] else "%d-%d" % pair


def _protos(p):
    return {"tcp", "udp"} if p == "both" else {p}


def validate_rule(state, data, rule_id=None, busy=None):
    """Привести правило к нормальному виду или бросить Invalid."""
    proto = str(data.get("proto", "")).lower()
    if proto not in PROTOS:
        raise Invalid("Протокол: tcp, udp или both")
    kind = data.get("kind") if data.get("kind") in KINDS else "custom"
    lp = parse_ports(data.get("lport", ""))
    dip = check_ip(data.get("dip", ""))
    raw_dport = str(data.get("dport", "") or "").strip()
    dport = ""
    if raw_dport:
        dp = parse_ports(raw_dport)
        if dp != lp:
            if lp[0] != lp[1] or dp[0] != dp[1]:
                raise Invalid("Для диапазона портов порт назначения менять нельзя — оставьте его пустым")
            dport = fmt_ports(dp)
    name = str(data.get("name", "") or "").strip()[:60]

    for r in state["rules"]:
        if r["id"] == rule_id:
            continue
        other = parse_ports(r["lport"])
        if _protos(r["proto"]) & _protos(proto) and lp[0] <= other[1] and other[0] <= lp[1]:
            raise Invalid("Порт %s уже занят правилом «%s»" % (fmt_ports(lp), r.get("name") or r["lport"]))

    if busy and not data.get("force"):
        for p in sorted(_protos(proto)):
            hit = [n for n in busy.get(p, ()) if lp[0] <= n <= lp[1]]
            if hit:
                raise Invalid(
                    "Порт %d/%s на этом сервере слушает локальная служба — проброс заберёт её трафик. "
                    "Выберите другой входящий порт." % (hit[0], p))

    return {
        "name": name, "kind": kind, "proto": proto,
        "lport": fmt_ports(lp), "dip": dip, "dport": dport,
        "enabled": bool(data.get("enabled", True)),
    }


def new_id(items):
    while True:
        i = secrets.token_hex(3)
        if all(x["id"] != i for x in items):
            return i


def ensure_server(state, ip):
    for sv in state["servers"]:
        if sv["ip"] == ip:
            return sv
    sv = {"id": new_id(state["servers"]), "ip": ip, "name": "", "note": "",
          "geo": "", "monitor": True, "threshold": 0}
    state["servers"].append(sv)
    return sv


def validate_server(data, sv):
    sv["name"] = str(data.get("name", sv.get("name", "")) or "").strip()[:60]
    sv["note"] = str(data.get("note", sv.get("note", "")) or "").strip()[:200]
    sv["monitor"] = bool(data.get("monitor", sv.get("monitor", True)))
    try:
        th = int(data.get("threshold", sv.get("threshold", 0)) or 0)
    except (TypeError, ValueError):
        raise Invalid("Порог задержки — число в миллисекундах")
    if not 0 <= th <= 10000:
        raise Invalid("Порог задержки — от 0 (выключен) до 10000 мс")
    sv["threshold"] = th
    return sv


def validate_settings(data, cur):
    out = dict(cur)
    if "tg_token" in data:
        tok = str(data["tg_token"] or "").strip()
        if tok and (":" not in tok or len(tok) > 100 or any(c.isspace() for c in tok)):
            raise Invalid("Токен бота выглядит как 123456:ABC… — скопируйте его целиком из @BotFather")
        out["tg_token"] = tok
    if "tg_chat" in data:
        chat = str(data["tg_chat"] or "").strip()
        if chat and not chat.lstrip("-").isdigit():
            raise Invalid("Chat ID — число. Напишите боту /start, он подскажет ваш")
        out["tg_chat"] = chat
    for key, lo, hi, what in (("mon_interval", 10, 3600, "Интервал проверки — от 10 до 3600 секунд"),
                              ("mon_fails", 1, 20, "Число неудач до тревоги — от 1 до 20")):
        if key in data:
            try:
                v = int(data[key])
            except (TypeError, ValueError):
                raise Invalid(what)
            if not lo <= v <= hi:
                raise Invalid(what)
            out[key] = v
    if "bbr" in data:
        out["bbr"] = bool(data["bbr"])
    return out


# ── пароль панели ───────────────────────────────────────────────────────

def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000)
    return salt, digest.hex()


def check_password(password, panel):
    if not panel.get("salt") or not panel.get("hash"):
        return False
    _, digest = hash_password(password, panel["salt"])
    return hmac.compare_digest(digest, panel["hash"])


def set_password(password):
    with locked():
        panel = read_json(PANEL, {})
        panel["salt"], panel["hash"] = hash_password(password)
        panel["changed"] = int(time.time())
        write_json(PANEL, panel)

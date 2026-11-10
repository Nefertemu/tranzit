"""Движок пробросов: своя таблица nftables, загружается целиком и атомарно."""
import json
import os
import shutil
import subprocess

from . import store

TABLE = "tranzit"
RULESET = os.path.join(store.ETC, "ruleset.nft")
SYSCTL = "/etc/sysctl.d/90-tranzit.conf"


class EngineError(RuntimeError):
    pass


def _run(cmd, stdin=None, timeout=20):
    try:
        p = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "%s: команда не найдена" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "", "%s: не ответила за %d с" % (cmd[0], timeout)


def _protos(rule):
    return ("tcp", "udp") if rule["proto"] == "both" else (rule["proto"],)


def render(state):
    """Полный текст таблицы. Старая заменяется новой одной транзакцией."""
    pre, fwd, counters, dests = [], [], [], set()
    for r in state["rules"]:
        if not r.get("enabled", True):
            continue
        rid, dip, lport = r["id"], r["dip"], r["lport"]
        dport = r.get("dport") or lport
        target = "%s:%s" % (dip, r["dport"]) if r.get("dport") else dip
        dests.add(dip)
        counters += ['\tcounter u_%s { }' % rid, '\tcounter d_%s { }' % rid]
        for p in _protos(r):
            pre.append("\t\tfib daddr type local %s dport %s dnat to %s" % (p, lport, target))
            fwd.append('\t\tct status dnat ip daddr %s %s dport %s counter name "u_%s" accept' % (dip, p, dport, rid))
            fwd.append('\t\tct status dnat ip saddr %s %s sport %s counter name "d_%s" accept' % (dip, p, dport, rid))
    lines = ["table ip %s" % TABLE, "delete table ip %s" % TABLE, "table ip %s {" % TABLE]
    lines += counters
    lines += ["\tchain prerouting {", "\t\ttype nat hook prerouting priority dstnat; policy accept;"] + pre + ["\t}"]
    lines += ["\tchain postrouting {", "\t\ttype nat hook postrouting priority srcnat; policy accept;"]
    if dests:
        lines.append("\t\tct status dnat ip daddr { %s } masquerade" % ", ".join(sorted(dests)))
    lines += ["\t}", "\tchain forward {", "\t\ttype filter hook forward priority filter; policy accept;"]
    if fwd:
        lines.append("\t\tct status dnat tcp flags syn tcp option maxseg size set rt mtu")
    lines += fwd + ["\t}", "}", ""]
    return "\n".join(lines)


def _live_counters():
    """{'u_ab12cd': bytes, ...} из загруженной таблицы; None — таблицы нет."""
    if store.DRY:
        return {}
    rc, out, _ = _run(["nft", "-j", "list", "counters", "table", "ip", TABLE])
    if rc != 0:
        return None
    res = {}
    try:
        for item in json.loads(out).get("nftables", []):
            c = item.get("counter")
            if c:
                res[c["name"]] = int(c.get("bytes", 0))
    except (ValueError, KeyError, TypeError):
        return None
    return res


def _fold(stats, live, ids):
    """Счётчики живут в ядре и обнуляются при перезагрузке таблицы — копим на диске."""
    for rid in ids:
        st = stats.setdefault(rid, {"up": 0, "down": 0, "lu": 0, "ld": 0})
        if live is not None:
            st["lu"], st["ld"] = live.get("u_" + rid, st["lu"]), live.get("d_" + rid, st["ld"])
    for rid in list(stats):
        if rid not in ids:
            del stats[rid]
    return stats


def snapshot():
    """Раз в несколько минут запоминаем показания — чтобы пережить перезагрузку."""
    with store.locked():
        ids = [r["id"] for r in store.load()["rules"]]
        stats = _fold(store.read_json(store.STATS, {}), _live_counters(), ids)
        store.write_json(store.STATS, stats)


def traffic(state):
    live = _live_counters()
    stats = store.read_json(store.STATS, {})
    out = {}
    for r in state["rules"]:
        st = stats.get(r["id"], {})
        lu, ld = st.get("lu", 0), st.get("ld", 0)
        if live is not None:
            lu, ld = live.get("u_" + r["id"], lu), live.get("d_" + r["id"], ld)
        out[r["id"]] = {"up": st.get("up", 0) + lu, "down": st.get("down", 0) + ld}
    return out


def apply(state):
    """Загрузить правила в ядро. Вызывать под store.locked() / внутри store.edit()."""
    text = render(state)
    ids = [r["id"] for r in state["rules"]]
    stats = _fold(store.read_json(store.STATS, {}), _live_counters(), ids)
    if store.DRY:
        store.write_json(store.STATS, stats)
        return text
    os.makedirs(store.ETC, mode=0o700, exist_ok=True)
    tmp = RULESET + ".new"
    with open(tmp, "w") as f:
        f.write(text)
    rc, _, err = _run(["nft", "-f", tmp])
    if rc != 0:
        os.unlink(tmp)
        raise EngineError("nftables не принял правила: %s" % (err.strip() or "код %d" % rc))
    os.replace(tmp, RULESET)
    for st in stats.values():  # таблица новая — счётчики в ядре снова с нуля
        st["up"] += st["lu"]
        st["down"] += st["ld"]
        st["lu"] = st["ld"] = 0
    store.write_json(store.STATS, stats)
    _sysctl(state["settings"].get("bbr", True))
    _allow_forward()
    return text


def _sysctl(bbr):
    lines = ["# tranzit: пересылка пакетов нужна для пробросов", "net.ipv4.ip_forward = 1"]
    if bbr:
        lines += ["net.core.default_qdisc = fq", "net.ipv4.tcp_congestion_control = bbr"]
    text = "\n".join(lines) + "\n"
    try:
        old = open(SYSCTL).read()
    except OSError:
        old = None
    if old != text:
        with open(SYSCTL, "w") as f:
            f.write(text)
    if bbr:
        _run(["modprobe", "tcp_bbr"])
    _run(["sysctl", "-q", "-p", SYSCTL])


def _allow_forward():
    """Docker и ufw ставят FORWARD в DROP в своей таблице — наш accept её не отменяет."""
    if not shutil.which("iptables"):
        return
    rc, out, _ = _run(["iptables", "-S", "FORWARD"])
    if rc != 0 or "-P FORWARD DROP" not in out:
        return
    rule = ["FORWARD", "-m", "conntrack", "--ctstate", "DNAT", "-m", "comment", "--comment", "tranzit", "-j", "ACCEPT"]
    if _run(["iptables", "-C"] + rule)[0] != 0:
        _run(["iptables", "-I"] + rule)


def remove():
    """Убрать всё, что движок оставил в системе."""
    if store.DRY:
        return
    _run(["nft", "delete", "table", "ip", TABLE])
    if shutil.which("iptables"):
        _run(["iptables", "-D", "FORWARD", "-m", "conntrack", "--ctstate", "DNAT",
              "-m", "comment", "--comment", "tranzit", "-j", "ACCEPT"])
    for path in (SYSCTL, RULESET):
        try:
            os.unlink(path)
        except OSError:
            pass


def loaded():
    if store.DRY:
        return True
    return _run(["nft", "list", "table", "ip", TABLE])[0] == 0


def listening():
    """Порты, которые на этом сервере уже слушают локальные службы."""
    res = {"tcp": set(), "udp": set()}
    if store.DRY:
        return res
    for proto, flag in (("tcp", "-tln"), ("udp", "-uln")):
        rc, out, _ = _run(["ss", "-H", flag])
        if rc != 0:
            continue
        for line in out.splitlines():
            cols = line.split()
            if len(cols) < 5:
                continue
            addr, _, port = cols[3].rpartition(":")
            if port.isdigit() and not addr.startswith("127.") and addr != "[::1]":
                res[proto].add(int(port))
    return res


def doctor(state):
    """Список неполадок простыми словами: [{'level': 'err'|'warn', 'text': ...}]."""
    if store.DRY:
        return []
    out = []
    if not shutil.which("nft"):
        return [{"level": "err", "text": "Не установлен nftables — пробросы не работают. Поставьте: apt install nftables"}]
    active = [r for r in state["rules"] if r.get("enabled", True)]
    if active and not loaded():
        out.append({"level": "err", "text": "Правила не загружены в ядро. Выполните на сервере: tranzit apply"})
    try:
        if active and open("/proc/sys/net/ipv4/ip_forward").read().strip() != "1":
            out.append({"level": "err", "text": "В системе выключена пересылка пакетов (ip_forward). Выполните: tranzit apply"})
    except OSError:
        pass
    busy = listening()
    for r in active:
        lo, hi = store.parse_ports(r["lport"])
        for p in _protos(r):
            hit = [n for n in busy[p] if lo <= n <= hi]
            if hit:
                out.append({"level": "warn", "text": "Порт %d/%s слушает локальная служба, но правило «%s» уводит его трафик на %s"
                            % (hit[0], p, r.get("name") or r["lport"], r["dip"])})
    return out

"""Команда tranzit: то же, что в панели, из терминала."""
import argparse
import getpass
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time

from . import VERSION, engine, netutil, store

INSTALL_CONF = os.path.join(store.ETC, "install.conf")


def _root():
    if not store.DRY and os.geteuid() != 0:
        sys.exit("Нужны права root: sudo tranzit …")


def _fmt_bytes(n):
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if n < 1024 or unit == "ТБ":
            return "%d Б" % n if unit == "Б" else "%.1f %s" % (n, unit)
        n /= 1024


def _url(panel):
    scheme = "http" if os.environ.get("TRANZIT_HTTP") == "1" else "https"
    return "%s://%s:%s/%s/" % (scheme, netutil.local_ip() or "IP-сервера", panel["port"], panel["path"])


def _free_port():
    for _ in range(50):
        port = secrets.randbelow(40000) + 20000
        with socket.socket() as s:
            try:
                s.bind(("0.0.0.0", port))
                return port
            except OSError:
                continue
    sys.exit("Не нашёлся свободный порт для панели")


def cmd_init(args):
    """Первая настройка: порт, секретный путь, пароль, сертификат. Повторный запуск ничего не ломает."""
    _root()
    panel = store.read_json(store.PANEL, {})
    password = None
    if not panel.get("port"):
        panel["port"] = _free_port()
    if not panel.get("path"):
        panel["path"] = secrets.token_urlsafe(9)
    if not panel.get("hash"):
        password = secrets.token_urlsafe(12)
        panel["salt"], panel["hash"] = store.hash_password(password)
    with store.locked():
        store.write_json(store.PANEL, panel)
    tls = os.path.join(store.ETC, "tls")
    cert, key = os.path.join(tls, "cert.pem"), os.path.join(tls, "key.pem")
    if not os.path.exists(cert) and os.environ.get("TRANZIT_HTTP") != "1":
        os.makedirs(tls, mode=0o700, exist_ok=True)
        p = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                            "-subj", "/CN=tranzit", "-keyout", key, "-out", cert], capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit("Не получилось создать сертификат: %s" % p.stderr.strip())
        os.chmod(key, 0o600)
    if not os.path.exists(store.STATE):
        with store.edit():
            pass
    print("Панель:  %s" % _url(panel))
    if password:
        print("Пароль:  %s" % password)
        print("Пароль показан один раз. Забыли — команда: tranzit passwd")


def cmd_panel(args):
    panel = store.read_json(store.PANEL, {})
    if not panel.get("port"):
        sys.exit("Панель не настроена. Выполните: tranzit init")
    print(_url(panel))


def cmd_passwd(args):
    _root()
    if args.random or not sys.stdin.isatty():
        password = secrets.token_urlsafe(12)
        print("Новый пароль: %s" % password)
    else:
        password = getpass.getpass("Новый пароль (не короче 10 символов): ")
        if len(password) < 10:
            sys.exit("Слишком короткий. Пароль не изменён.")
        if getpass.getpass("Ещё раз: ") != password:
            sys.exit("Пароли не совпали. Пароль не изменён.")
    store.set_password(password)
    subprocess.run(["systemctl", "try-restart", "tranzit"], capture_output=True)
    print("Пароль изменён. Все открытые входы в панель закрыты.")


def cmd_list(args):
    s = store.load()
    if not s["rules"]:
        print("Правил пока нет. Добавить: tranzit add udp 51820 203.0.113.10")
        return
    tr = engine.traffic(s)
    names = {sv["ip"]: sv["name"] for sv in s["servers"] if sv.get("name")}
    print("%-7s %-4s %-5s %-12s %-24s %-11s %-11s %s" % ("id", "", "прот", "вход", "куда", "отправлено", "получено", "имя"))
    for r in s["rules"]:
        t = tr[r["id"]]
        to = "%s:%s" % (r["dip"], r.get("dport") or r["lport"])
        print("%-7s %-4s %-5s %-12s %-24s %-11s %-11s %s" % (
            r["id"], "вкл" if r.get("enabled", True) else "выкл", r["proto"], r["lport"], to,
            _fmt_bytes(t["up"]), _fmt_bytes(t["down"]),
            r.get("name") or names.get(r["dip"], "")))


def cmd_add(args):
    _root()
    dip, _, dport = args.to.partition(":")
    data = {"proto": args.proto, "lport": args.port, "dip": dip, "dport": dport,
            "name": args.name or "", "force": args.force}
    try:
        with store.edit() as s:
            r = store.validate_rule(s, data, busy=engine.listening())
            r["id"] = store.new_id(s["rules"])
            r["created"] = int(time.time())
            s["rules"].append(r)
            store.ensure_server(s, r["dip"])
            engine.apply(s)
    except (store.Invalid, engine.EngineError) as e:
        sys.exit("Правило не создано: %s" % e)
    print("Готово: %s/%s → %s:%s (id %s)" % (r["lport"], r["proto"], r["dip"], r.get("dport") or r["lport"], r["id"]))
    print("В приложении-клиенте укажите адрес этого сервера: %s, порт %s" % (netutil.local_ip() or "IP сервера", r["lport"]))


def _change(rule_id, fn, done):
    _root()
    try:
        with store.edit() as s:
            if not any(r["id"] == rule_id for r in s["rules"]):
                sys.exit("Правила с id %s нет. Список: tranzit list" % rule_id)
            fn(s)
            engine.apply(s)
    except engine.EngineError as e:
        sys.exit("Не получилось: %s" % e)
    print(done)


def cmd_del(args):
    def fn(s):
        s["rules"] = [r for r in s["rules"] if r["id"] != args.id]
    _change(args.id, fn, "Правило %s удалено." % args.id)


def cmd_on(args):
    def fn(s):
        for r in s["rules"]:
            if r["id"] == args.id:
                r["enabled"] = True
    _change(args.id, fn, "Правило %s включено." % args.id)


def cmd_off(args):
    def fn(s):
        for r in s["rules"]:
            if r["id"] == args.id:
                r["enabled"] = False
    _change(args.id, fn, "Правило %s выключено." % args.id)


def cmd_apply(args):
    _root()
    try:
        with store.locked():
            engine.apply(store.load())
    except engine.EngineError as e:
        sys.exit(str(e))
    print("Правила загружены.")


def cmd_status(args):
    s = store.load()
    panel = store.read_json(store.PANEL, {})
    active = sum(1 for r in s["rules"] if r.get("enabled", True))
    print("Tranzit %s" % VERSION)
    if panel.get("port"):
        print("Панель:  %s" % _url(panel))
    if shutil.which("systemctl"):
        st = subprocess.run(["systemctl", "is-active", "tranzit"], capture_output=True, text=True).stdout.strip()
        print("Служба:  %s" % {"active": "работает", "inactive": "остановлена", "failed": "упала — journalctl -u tranzit -n 30"}.get(st, st or "?"))
    print("Правила: %d, включено %d" % (len(s["rules"]), active))
    problems = engine.doctor(s)
    for p in problems:
        print("  %s %s" % ("✗" if p["level"] == "err" else "!", p["text"]))
    if not problems:
        print("Неполадок не найдено.")


def cmd_show(args):
    """Напечатать текст правил nftables, ничего не меняя."""
    print(engine.render(store.load()))


def cmd_serve(args):
    from . import web
    web.serve()


def cmd_update(args):
    _root()
    conf = {}
    try:
        for line in open(INSTALL_CONF):
            k, _, v = line.strip().partition("=")
            conf[k] = v
    except OSError:
        sys.exit("Не знаю, откуда ставили Tranzit. Запустите установщик заново.")
    script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "install.sh")
    env = dict(os.environ, TRANZIT_REPO=conf.get("REPO", ""), TRANZIT_REF=conf.get("REF", "main"))
    os.execvpe("bash", ["bash", script], env)


def cmd_uninstall(args):
    _root()
    if not args.yes:
        print("Будут удалены: пробросы, панель, служба и настройки в %s." % store.ETC)
        if input("Напишите «да», чтобы удалить: ").strip().lower() not in ("да", "yes"):
            sys.exit("Отменено, ничего не удалено.")
    subprocess.run(["systemctl", "disable", "--now", "tranzit"], capture_output=True)
    engine.remove()
    for path in ("/etc/systemd/system/tranzit.service", "/usr/local/bin/tranzit"):
        try:
            os.unlink(path)
        except OSError:
            pass
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    shutil.rmtree(store.ETC, ignore_errors=True)
    shutil.rmtree("/opt/tranzit", ignore_errors=True)
    print("Tranzit удалён. Пробросы сняты.")


def main():
    ap = argparse.ArgumentParser(prog="tranzit", description="Tranzit %s — каскадные пробросы портов с веб-панелью" % VERSION)
    sub = ap.add_subparsers(dest="cmd", metavar="команда")

    def add(name, fn, text):
        p = sub.add_parser(name, help=text, description=text)
        p.set_defaults(fn=fn)
        return p

    add("status", cmd_status, "состояние и неполадки")
    add("panel", cmd_panel, "адрес панели")
    p = add("passwd", cmd_passwd, "сменить пароль панели")
    p.add_argument("--random", action="store_true", help="придумать случайный и показать")
    add("list", cmd_list, "правила и трафик")
    p = add("add", cmd_add, "добавить проброс: tranzit add udp 51820 203.0.113.10[:порт]")
    p.add_argument("proto", choices=store.PROTOS)
    p.add_argument("port", help="входящий порт или диапазон 1000-2000")
    p.add_argument("to", help="адрес назначения, можно с портом: 203.0.113.10:443")
    p.add_argument("--name", help="название правила")
    p.add_argument("--force", action="store_true", help="не проверять, занят ли порт локальной службой")
    for name, fn, text in (("del", cmd_del, "удалить правило"), ("on", cmd_on, "включить правило"), ("off", cmd_off, "выключить правило")):
        add(name, fn, text).add_argument("id")
    add("apply", cmd_apply, "заново загрузить правила в ядро")
    add("show", cmd_show, "показать текст правил nftables")
    add("update", cmd_update, "обновить Tranzit с GitHub")
    add("uninstall", cmd_uninstall, "удалить Tranzit и снять пробросы").add_argument("--yes", action="store_true")
    add("init", cmd_init, "первая настройка панели")
    add("serve", cmd_serve, "запустить панель (это делает служба)")

    args = ap.parse_args()
    if not args.cmd:
        cmd_status(args)
        print("\nВсе команды: tranzit --help")
        return
    args.fn(args)

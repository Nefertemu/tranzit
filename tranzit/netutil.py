"""Сеть: замер задержки, свой адрес, GeoIP по запросу."""
import json
import re
import socket
import subprocess
import sys
import time
import urllib.request

_TIME = re.compile(r"time[=<]\s*([\d.]+)\s*ms")


def icmp(ip, timeout=2):
    wait = str(timeout * 1000) if sys.platform == "darwin" else str(timeout)
    try:
        p = subprocess.run(["ping", "-n", "-c", "1", "-W", wait, ip],
                           capture_output=True, text=True, timeout=timeout + 2)
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = _TIME.search(p.stdout)
    return float(m.group(1)) if p.returncode == 0 and m else None


def tcp(ip, port, timeout=2):
    start = time.monotonic()
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout):
            return (time.monotonic() - start) * 1000
    except (OSError, ValueError):
        return None


def measure(ip, tcp_ports=()):
    """Задержка в мс или None. Многие серверы не отвечают на ping — тогда пробуем TCP-порты правил."""
    ms = icmp(ip)
    if ms is None:
        for port in list(tcp_ports)[:3]:
            ms = tcp(ip, port)
            if ms is not None:
                break
    return round(ms, 1) if ms is not None else None


def local_ip():
    """Адрес, с которого сервер выходит наружу. Пакеты при этом не отправляются."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("1.1.1.1", 80))
            return s.getsockname()[0]
    except OSError:
        return ""


def geo(ip):
    """Страна и провайдер адреса. Единственный запрос наружу, только по кнопке."""
    try:
        req = urllib.request.Request("https://ipwho.is/%s" % ip, headers={"User-Agent": "curl/8"})
        with urllib.request.urlopen(req, timeout=6) as r:
            d = json.loads(r.read().decode())
    except (OSError, ValueError):
        return ""
    if not d.get("success", True):
        return ""
    parts = [d.get("country_code") or d.get("country") or "", d.get("city") or "",
             (d.get("connection") or {}).get("isp") or ""]
    return ", ".join(p for p in parts if p)

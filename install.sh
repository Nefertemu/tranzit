#!/usr/bin/env bash
# Tranzit — установка и обновление одной командой.
#
#   Открытый репозиторий:
#     bash <(curl -fsSL https://raw.githubusercontent.com/Nefertemu/tranzit/main/install.sh)
#
#   Закрытый репозиторий (ключ GitHub с правом читать этот репозиторий):
#     export GH_TOKEN=<ключ>
#     bash <(curl -fsSL -H "Authorization: token $GH_TOKEN" https://raw.githubusercontent.com/Nefertemu/tranzit/main/install.sh)
#
# Повторный запуск обновляет программу; правила, пароль и настройки остаются.
set -euo pipefail

main() {
    local repo="${TRANZIT_REPO:-Nefertemu/tranzit}" ref="${TRANZIT_REF:-main}"
    local dir=/opt/tranzit etc=/etc/tranzit token="${GH_TOKEN:-}"
    local say="  •" work

    [ "$(id -u)" = 0 ] || { echo "Запустите от root: sudo -i, затем команду ещё раз." >&2; exit 1; }
    [ "$(uname -s)" = Linux ] || { echo "Tranzit ставится на сервер с Linux (Debian 12+, Ubuntu 22.04+)." >&2; exit 1; }
    [ -z "$token" ] && [ -r "$etc/gh_token" ] && token="$(cat "$etc/gh_token")"

    echo "Tranzit: установка из $repo ($ref)"

    # ── пакеты ──
    local need=()
    command -v python3 >/dev/null || need+=(python3)
    command -v nft >/dev/null || need+=(nftables)
    command -v openssl >/dev/null || need+=(openssl)
    command -v ping >/dev/null || need+=(iputils-ping)
    command -v curl >/dev/null || need+=(curl)
    command -v tar >/dev/null || need+=(tar)
    command -v ss >/dev/null || need+=(iproute2)
    command -v ssh >/dev/null || need+=(openssh-client)
    if [ "${#need[@]}" -gt 0 ]; then
        echo "$say ставлю пакеты: ${need[*]}"
        if command -v apt-get >/dev/null; then
            DEBIAN_FRONTEND=noninteractive apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${need[@]}" ca-certificates >/dev/null
        elif command -v dnf >/dev/null; then
            dnf install -y -q $(printf '%s\n' "${need[@]}" | sed 's/^iputils-ping$/iputils/; s/^openssh-client$/openssh-clients/') >/dev/null
        else
            echo "Не знаю менеджер пакетов этой системы. Поставьте вручную: ${need[*]}" >&2; exit 1
        fi
    fi
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
        || { echo "Нужен Python 3.9 или новее. На этой системе: $(python3 -V 2>&1)." >&2; exit 1; }

    # ── код ──
    work="$(mktemp -d)"
    trap 'rm -rf "$work"' EXIT
    echo "$say скачиваю программу"
    local url="https://api.github.com/repos/$repo/tarball/$ref"
    # ключ уходит в curl через stdin: в списке процессов его не видно
    if [ -n "$token" ]; then
        printf 'header = "Authorization: token %s"\n' "$token" | curl -fsSL -K - -o "$work/src.tgz" "$url"
    else
        curl -fsSL -o "$work/src.tgz" "$url"
    fi || { echo "Не скачалось с GitHub. Если репозиторий закрытый — задайте ключ: export GH_TOKEN=<ключ>" >&2; exit 1; }
    mkdir "$work/src"
    tar -xzf "$work/src.tgz" -C "$work/src" --strip-components=1
    [ -f "$work/src/tranzit/cli.py" ] || { echo "В скачанном архиве нет программы — проверьте имя репозитория и ветку." >&2; exit 1; }

    rm -rf "$dir.new"
    mkdir -p "$dir.new"
    cp -R "$work/src/tranzit" "$work/src/install.sh" "$dir.new/"
    rm -rf "$dir.old"
    [ -d "$dir" ] && mv "$dir" "$dir.old"
    mv "$dir.new" "$dir"
    rm -rf "$dir.old"

    install -d -m 700 "$etc"
    printf 'REPO=%s\nREF=%s\n' "$repo" "$ref" > "$etc/install.conf"
    if [ -n "$token" ]; then
        ( umask 077; printf '%s' "$token" > "$etc/gh_token" )
    fi

    cat > /usr/local/bin/tranzit <<'EOF'
#!/bin/sh
cd /opt/tranzit && exec python3 -m tranzit "$@"
EOF
    chmod 755 /usr/local/bin/tranzit

    # ── служба ──
    cat > /etc/systemd/system/tranzit.service <<'EOF'
[Unit]
Description=Tranzit: каскадные пробросы и панель
After=network-online.target nftables.service
Wants=network-online.target

[Service]
WorkingDirectory=/opt/tranzit
ExecStart=/usr/bin/env python3 -m tranzit serve
Restart=always
RestartSec=3
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload

    echo "$say настраиваю панель"
    local first; first="$(tranzit init)"
    systemctl enable -q tranzit
    systemctl restart tranzit
    sleep 1
    if ! systemctl is-active -q tranzit; then
        echo "Служба не запустилась. Что случилось: journalctl -u tranzit -n 30" >&2; exit 1
    fi

    local port; port="$(python3 -c "import json;print(json.load(open('$etc/panel.json'))['port'])")"
    if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
        ufw allow "$port/tcp" >/dev/null && echo "$say открыл порт панели $port в ufw"
    fi

    echo
    echo "Готово. Tranzit $(tranzit status | head -1 | awk '{print $2}') работает."
    echo "$first"
    echo
    echo "Сертификат панели самоподписанный: браузер один раз предупредит — это ожидаемо."
    echo "Команда на сервере: tranzit   (адрес панели — tranzit panel, новый пароль — tranzit passwd)"
}

main "$@"

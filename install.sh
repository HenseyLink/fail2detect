#!/usr/bin/env bash
# Установщик fail2detect:
#   bash <(curl -fsSL https://raw.githubusercontent.com/fail2detect/fail2detect/main/install.sh)
set -euo pipefail

REPO="${F2D_REPO:-fail2detect/fail2detect}"
BRANCH="${F2D_BRANCH:-main}"
DEST="/opt/fail2detect"
MODE="${1:-}"

red()   { printf '\033[1;31m%s\033[0m\n' "$*"; }
green() { printf '\033[1;32m%s\033[0m\n' "$*"; }

[[ $EUID -eq 0 ]] || { red "Запустите от root"; exit 1; }
[[ "$(uname -s)" == Linux ]] || { red "Только Linux"; exit 1; }

if command -v apt-get >/dev/null; then
    apt-get update -qq >/dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables curl jq iproute2 gawk coreutils util-linux tar >/dev/null
elif command -v dnf >/dev/null; then
    dnf install -y -q nftables curl jq iproute gawk coreutils util-linux tar >/dev/null
fi

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
if [[ -n "$SRC_DIR" && -f "$SRC_DIR/fail2detect" && -d "$SRC_DIR/lib" ]]; then
    cp -a "$SRC_DIR/." "$tmp/src"   # установка из локальной копии репозитория
else
    curl -fsSL "https://codeload.github.com/${REPO}/tar.gz/refs/heads/${BRANCH}" -o "$tmp/f2d.tgz"
    mkdir -p "$tmp/src"; tar -xzf "$tmp/f2d.tgz" -C "$tmp/src" --strip-components=1
fi
for f in "$tmp/src/fail2detect" "$tmp/src"/lib/*.sh; do bash -n "$f" || { red "Повреждён файл: $f"; exit 1; }; done

rm -rf "$DEST.new"; mkdir -p "$DEST.new"
cp -a "$tmp/src/fail2detect" "$tmp/src/lib" "$tmp/src/conf" "$tmp/src/systemd" "$DEST.new/"
[[ -f "$tmp/src/README.md" ]] && cp "$tmp/src/README.md" "$DEST.new/"
rm -rf "$DEST.old"; [[ -d "$DEST" ]] && mv "$DEST" "$DEST.old"
mv "$DEST.new" "$DEST"; rm -rf "$DEST.old"
chmod 755 "$DEST/fail2detect"
ln -sf "$DEST/fail2detect" /usr/local/bin/fail2detect

mkdir -p /etc/fail2detect/jail.d /var/lib/fail2detect /var/log/fail2detect
chmod 700 /etc/fail2detect /var/lib/fail2detect
[[ -f /etc/fail2detect/fail2detect.conf ]] || install -m 600 "$DEST/conf/fail2detect.conf" /etc/fail2detect/fail2detect.conf
for f in "$DEST"/conf/jail.d/*.conf; do
    [[ -f "/etc/fail2detect/jail.d/$(basename "$f")" ]] || install -m 644 "$f" /etc/fail2detect/jail.d/
done

if [[ "$MODE" == --update ]]; then
    for u in fail2detect.service fail2detect-blocklist.service fail2detect-blocklist.timer; do
        install -m 644 "$DEST/systemd/$u" "/etc/systemd/system/$u"
    done
    systemctl daemon-reload
    systemctl is-enabled --quiet fail2detect 2>/dev/null && systemctl restart fail2detect
    green "fail2detect обновлён до $("$DEST/fail2detect" version)"
    exit 0
fi

green "fail2detect установлен: /usr/local/bin/fail2detect"
echo
if [[ -t 0 ]] || [[ -e /dev/tty ]]; then
    read -r -p "Запустить мастер настройки сейчас? [Y/n]: " a </dev/tty || a=y
    [[ "${a:-y}" =~ ^[nNнН] ]] || exec /usr/local/bin/fail2detect setup </dev/tty
fi
echo "Дальше: fail2detect setup"

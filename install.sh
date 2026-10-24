#!/usr/bin/env bash
# Установщик fail2detect:
#   bash <(curl -fsSL https://raw.githubusercontent.com/HenseyLink/fail2detect/main/install.sh)
set -euo pipefail

REPO="${F2D_REPO:-HenseyLink/fail2detect}"
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
mv "$DEST.new" "$DEST"
chmod 755 "$DEST/fail2detect"
ln -sf "$DEST/fail2detect" /usr/local/bin/fail2detect
# короткая команда f2d — только если это имя свободно или уже наше
SHORT=/usr/local/bin/f2d
if [[ ! -e "$SHORT" && ! -L "$SHORT" ]] || [[ "$(readlink -f "$SHORT" 2>/dev/null)" == "$DEST/fail2detect" ]]; then
    ln -sf "$DEST/fail2detect" "$SHORT"
else
    red "$SHORT уже занят другой программой — короткое имя f2d не создано, используйте fail2detect"
fi

mkdir -p /etc/fail2detect/jail.d /var/lib/fail2detect /var/log/fail2detect
chmod 700 /etc/fail2detect /var/lib/fail2detect
[[ -f /etc/fail2detect/fail2detect.conf ]] || install -m 600 "$DEST/conf/fail2detect.conf" /etc/fail2detect/fail2detect.conf
# jail'ы: новые — ставим; не изменённые пользователем (кроме ENABLED) — обновляем,
# сохраняя его ENABLED; изменённые вручную — не трогаем
for f in "$DEST"/conf/jail.d/*.conf; do
    name=$(basename "$f"); cur="/etc/fail2detect/jail.d/$name"; old="$DEST.old/conf/jail.d/$name"
    if [[ ! -f "$cur" ]]; then
        install -m 644 "$f" "$cur"
    elif [[ -f "$old" ]] && ! cmp -s "$f" "$old" && \
         diff -q <(grep -v '^ENABLED=' "$cur") <(grep -v '^ENABLED=' "$old") >/dev/null; then
        en=$(grep -m1 '^ENABLED=' "$cur")
        install -m 644 "$f" "$cur"
        [[ -n "$en" ]] && sed -i "s/^ENABLED=.*/$en/" "$cur"
        echo "jail $name обновлён"
    fi
done
rm -rf "$DEST.old"

if [[ "$MODE" == --update ]]; then
    for u in fail2detect.service fail2detect-blocklist.service fail2detect-blocklist.timer; do
        install -m 644 "$DEST/systemd/$u" "/etc/systemd/system/$u"
    done
    systemctl daemon-reload
    systemctl is-enabled --quiet fail2detect 2>/dev/null && systemctl restart fail2detect
    green "fail2detect обновлён до $("$DEST/fail2detect" version)"
    exit 0
fi

green "fail2detect установлен: /usr/local/bin/fail2detect (коротко: f2d)"
echo
if [[ -t 0 ]] || [[ -e /dev/tty ]]; then
    read -r -p "Запустить мастер настройки сейчас? [Y/n]: " a </dev/tty || a=y
    [[ "${a:-y}" =~ ^[nNнН] ]] || exec /usr/local/bin/fail2detect setup </dev/tty
fi
echo "Дальше: fail2detect setup"

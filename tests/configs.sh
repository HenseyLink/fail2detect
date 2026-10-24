#!/usr/bin/env bash
# Проверка сгенерированных конфигов настоящими движками:
#   * Xray: каждый транспорт → полный конфиг (как его соберёт Remnawave) → `xray run -test`
#   * nginx: конфиг панели/подписки/selfsteal → `nginx -t`
# Нужен Docker. Запуск: tests/configs.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
XRAY_IMAGE="${XRAY_IMAGE:-ghcr.io/xtls/xray-core:latest}"
NGINX_IMAGE="${NGINX_IMAGE:-nginx:1.29-alpine}"
export NO_COLOR=1 F2D_CONF_DIR="$WORK/etc"
mkdir -p "$F2D_CONF_DIR"

# shellcheck source=/dev/null
for m in common detect transport certs web; do source "$ROOT/lib/$m.sh"; done

FAIL=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n%s\n' "$1" "${2:-}" | sed 's/^/        /;1s/^        //'; }

# самоподписанные сертификаты
mkcert() {   # dir domain
    mkdir -p "$1"
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=$2" -addext "subjectAltName=DNS:$2" \
        -keyout "$1/privkey.pem" -out "$1/fullchain.pem" >/dev/null 2>&1
}

printf '\n== Xray (%s)\n' "$XRAY_IMAGE"
mkcert "$WORK/xray-certs" node.example.com
uuid="2c5a3c3e-7b8f-4b4d-9a3e-2f1d3c4b5a6f"
for t in "${TRANSPORTS[@]}"; do
    obfs=""; [[ "$t" == hysteria2 ]] && obfs="testpassword"
    inb=$(inbound_build "$t" "IN_$t" 8443 node.example.com "" "" "" "" "$obfs")
    # клиенты — так их добавляет Remnawave (addUsersToInbound)
    inb=$(jq --arg id "$uuid" 'if .protocol == "hysteria" then .settings.clients = [{id:$id, auth:$id, email:"1"}]
        else .settings.clients = [{id:$id, email:"1"} + (if .streamSettings.network == "raw" then {flow:"xtls-rprx-vision"} else {} end)] end' <<<"$inb")
    profile_config "$inb" > "$WORK/$t.json"
    # от имени владельца файлов: образ Xray не root, а ключ — 600 (remnanode же работает от root)
    if res=$(docker run --rm --user "$(id -u):$(id -g)" -v "$WORK/$t.json:/c.json:ro" -v "$WORK/xray-certs:$XRAY_CERT_DIR:ro" -v /dev/shm:/dev/shm \
            "$XRAY_IMAGE" run -test -c /c.json 2>&1); then
        pass "xray: $t"
    else
        fail "xray: $t" "$(tail -5 <<<"$res")"
    fi
done
# набор транспортов в одном профиле (443/tcp и 443/udp одновременно, общий ключ Reality)
source "$ROOT/lib/installer.sh"
parse_transports_arg "tcp-reality:443,hysteria2:443,grpc-reality:8443,xhttp-reality:4443,xhttp-tls:2083,grpc-tls:2087"
T_DOMAIN=node.example.com; T_TARGET=""; T_OBFS="testpassword"
inbs=$(build_inbounds SET | jq --arg id "$uuid" 'map(if .protocol == "hysteria" then .settings.clients = [{id:$id, auth:$id, email:"1"}]
    else .settings.clients = [{id:$id, email:"1"} + (if .streamSettings.network == "raw" then {flow:"xtls-rprx-vision"} else {} end)] end)')
profile_config "$inbs" > "$WORK/set.json"
if res=$(docker run --rm --user "$(id -u):$(id -g)" -v "$WORK/set.json:/c.json:ro" -v "$WORK/xray-certs:$XRAY_CERT_DIR:ro" "$XRAY_IMAGE" run -test -c /c.json 2>&1); then
    pass "xray: 6 транспортов в одном профиле"
else
    fail "xray: 6 транспортов в одном профиле" "$(tail -5 <<<"$res")"
fi
# чужой target для Reality
inb=$(inbound_build tcp-reality T 443 "" "www.microsoft.com:443" | jq --arg id "$uuid" '.settings.clients=[{id:$id, flow:"xtls-rprx-vision"}]')
profile_config "$inb" > "$WORK/ext.json"
docker run --rm -v "$WORK/ext.json:/c.json:ro" "$XRAY_IMAGE" run -test -c /c.json >/dev/null 2>&1 \
    && pass "xray: tcp-reality с внешним target" || fail "xray: tcp-reality с внешним target"

printf '\n== nginx (%s)\n' "$NGINX_IMAGE"
LE="$WORK/le/live"
for d in panel.example.com sub.example.com node.example.com; do mkcert "$LE/$d" "$d"; done
cert_dir() { echo "/etc/letsencrypt/live/$1"; }
check_nginx() {   # name
    web_render > "$WORK/nginx.conf"
    if res=$(docker run --rm -v "$WORK/nginx.conf:/etc/nginx/conf.d/default.conf:ro" -v "$WORK/le:/etc/letsencrypt:ro" \
            "$NGINX_IMAGE" nginx -t 2>&1); then pass "nginx: $1"
    else fail "nginx: $1" "$(grep -E 'emerg|error' <<<"$res" | head -3)"; fi
}
web_set PANEL_DOMAIN panel.example.com; web_set PANEL_KEY_NAME abcdefgh; web_set PANEL_KEY_VALUE Secret123
web_set WEB_PORT 443
check_nginx "только панель на 443"
web_set SUB_DOMAIN sub.example.com; web_set SELFSTEAL_DOMAIN node.example.com
check_nginx "панель + подписка + selfsteal"
web_set WEB_PORT ""
check_nginx "только unix-сокет (Xray занял 443)"
: > "$F2D_WEB_ENV"; web_set SELFSTEAL_DOMAIN node.example.com
check_nginx "нода: только selfsteal"

printf '\nИтого: %d fail\n' "$FAIL"
(( FAIL == 0 ))

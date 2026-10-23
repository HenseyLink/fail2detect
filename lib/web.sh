#!/usr/bin/env bash
# fail2detect — nginx-фронт: панель, страница подписки, selfsteal-сайт.
#
# Один nginx (контейнер f2d-nginx, сеть хоста) на сервер. Всегда слушает
# unix-сокет /dev/shm/nginx.sock (с proxy_protocol) — туда Reality отдаёт
# «чужие» подключения. Если 443/tcp не занят Xray, nginx слушает и его
# напрямую (WEB_PORT). Панель скрыта за секретным ключом: без cookie или
# ?<ключ>=<значение> nginx молча рвёт соединение (444), сканер панель не видит.

F2D_WEB_DIR="/opt/fail2detect-web"
F2D_WEB_CONTAINER="f2d-nginx"
F2D_WEB_ENV="${F2D_CONF_DIR}/web.env"
F2D_WEB_ROOT="/var/www/fail2detect"

web_load() {
    PANEL_DOMAIN=""; SUB_DOMAIN=""; SELFSTEAL_DOMAIN=""; WEB_PORT=""; PANEL_KEY_NAME=""; PANEL_KEY_VALUE=""
    # shellcheck disable=SC1090
    [[ -f "$F2D_WEB_ENV" ]] && source "$F2D_WEB_ENV"
    return 0
}
web_set() {   # KEY VALUE
    mkdir -p "$F2D_CONF_DIR"; touch "$F2D_WEB_ENV"; chmod 600 "$F2D_WEB_ENV"
    sed -i "/^$1=/d" "$F2D_WEB_ENV"
    printf '%s="%s"\n' "$1" "$2" >> "$F2D_WEB_ENV"
    printf -v "$1" '%s' "$2"
}

web_installed() { [[ -f "$F2D_WEB_DIR/docker-compose.yml" ]]; }

panel_login_url() {
    web_load
    [[ -n "$PANEL_DOMAIN" ]] || return 1
    local port=""; [[ -n "$WEB_PORT" && "$WEB_PORT" != 443 ]] && port=":$WEB_PORT"
    echo "https://${PANEL_DOMAIN}${port}/auth/login?${PANEL_KEY_NAME}=${PANEL_KEY_VALUE}"
}

_web_ssl() {   # domain -> строки ssl_certificate
    local dir; dir=$(cert_dir "$1") || { err "Нет сертификата для $1"; return 1; }
    printf '    ssl_certificate %s/fullchain.pem;\n    ssl_certificate_key %s/privkey.pem;\n' "$dir" "$dir"
}

_web_listen() {   # [default_server]
    printf '    listen unix:%s ssl proxy_protocol%s;\n' "$NGINX_SOCK" "${1:+ $1}"
    [[ -n "$WEB_PORT" ]] && printf '    listen %s ssl%s;\n    listen [::]:%s ssl%s;\n' "$WEB_PORT" "${1:+ $1}" "$WEB_PORT" "${1:+ $1}"
    printf '    http2 on;\n'
}

web_render() {
    web_load
    cat <<EOF
# Сгенерировано fail2detect — правьте $F2D_WEB_ENV и выполните: fail2detect web apply
server_names_hash_bucket_size 128;
map \$http_upgrade \$connection_upgrade { default upgrade; "" close; }

# реальный IP клиента из PROXY protocol (подключения от Reality через unix-сокет)
set_real_ip_from unix:;
real_ip_header proxy_protocol;

ssl_protocols TLSv1.2 TLSv1.3;
ssl_ecdh_curve X25519:prime256v1:secp384r1;
ssl_prefer_server_ciphers off;
ssl_session_timeout 1d;
ssl_session_cache shared:F2D:10m;
ssl_session_tickets off;
server_tokens off;

log_format f2d '\$remote_addr - \$remote_user [\$time_local] "\$request" \$status \$body_bytes_sent "\$http_referer" "\$http_user_agent"';
access_log /dev/stdout f2d;

EOF
    if [[ -n "$PANEL_DOMAIN" ]]; then
        cat <<EOF
# панель: пускаем с секретной cookie, с ?ключом в ссылке входа или с Bearer-токеном API
map \$cookie_${PANEL_KEY_NAME} \$f2d_cookie { "${PANEL_KEY_VALUE}" 1; default 0; }
map \$arg_${PANEL_KEY_NAME} \$f2d_arg { "${PANEL_KEY_VALUE}" 1; default 0; }
map \$http_authorization \$f2d_bearer { "~^Bearer\\s+\\S+" 1; default 0; }
map "\$f2d_cookie\$f2d_arg\$f2d_bearer" \$f2d_authorized { "000" 0; default 1; }
map \$f2d_arg \$f2d_set_cookie { 1 "${PANEL_KEY_NAME}=${PANEL_KEY_VALUE}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=31536000"; default ""; }

server {
    server_name ${PANEL_DOMAIN};
$(_web_listen)
$(_web_ssl "$PANEL_DOMAIN")

    location /api/sub/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    location / {
        if (\$f2d_authorized = 0) { return 444; }
        add_header Set-Cookie \$f2d_set_cookie;
        proxy_http_version 1.1;
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host \$host;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;
    }
}

EOF
    fi
    if [[ -n "$SUB_DOMAIN" ]]; then
        cat <<EOF
server {
    server_name ${SUB_DOMAIN};
$(_web_listen)
$(_web_ssl "$SUB_DOMAIN")

    location / {
        proxy_http_version 1.1;
        proxy_pass http://127.0.0.1:3010;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}

EOF
    fi
    if [[ -n "$SELFSTEAL_DOMAIN" ]]; then
        cat <<EOF
# selfsteal: обычный сайт, который видит сканер, пришедший на порт Reality
server {
    server_name ${SELFSTEAL_DOMAIN};
$(_web_listen)
$(_web_ssl "$SELFSTEAL_DOMAIN")
    root /var/www/html;
    index index.html;
    location / { try_files \$uri \$uri/ /index.html; }
}

EOF
    fi
    cat <<EOF
# всё остальное (сканеры по IP, чужие SNI) — обрыв рукопожатия
server {
$(_web_listen default_server)
    server_name _;
    ssl_reject_handshake on;
}
EOF
}

# простой нейтральный сайт-заглушка для selfsteal
web_site_generate() {
    [[ -f "$F2D_WEB_ROOT/index.html" ]] && return 0
    local names=("Northwind Studio" "Bluefield Labs" "Arcadia Design" "Lumen Works" "Cedar Analytics" "Harbor Media")
    local name="${names[RANDOM % ${#names[@]}]}" year; year=$(date +%Y)
    mkdir -p "$F2D_WEB_ROOT"
    cat > "$F2D_WEB_ROOT/index.html" <<EOF
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${name}</title>
<style>
body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#1d2433;background:#f6f7fb}
header{padding:28px 8vw;display:flex;justify-content:space-between;align-items:center}
header b{font-size:20px} nav a{margin-left:22px;color:#4a5568;text-decoration:none}
main{padding:12vh 8vw 10vh;max-width:760px}
h1{font-size:44px;line-height:1.1;margin:0 0 18px} p{font-size:18px;color:#4a5568;line-height:1.6}
.btn{display:inline-block;margin-top:22px;padding:12px 22px;border-radius:8px;background:#2b4acb;color:#fff;text-decoration:none}
footer{padding:28px 8vw;color:#8a94a6;font-size:14px}
</style></head>
<body><header><b>${name}</b><nav><a href="#">Services</a><a href="#">Work</a><a href="#">Contact</a></nav></header>
<main><h1>We build calm, reliable software.</h1>
<p>Product design, engineering and data for teams that care about the details. Our new website is on its way.</p>
<a class="btn" href="#">Get in touch</a></main>
<footer>&copy; ${year} ${name}</footer></body></html>
EOF
}

web_apply() {
    require_docker
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx remnawave-nginx; then
        err "На сервере работает nginx от eGames (remnawave-nginx) — он уже владеет $NGINX_SOCK."
        err "Второй nginx не ставлю: сайты/панель здесь настраиваются скриптом eGames."
        return 1
    fi
    web_load
    mkdir -p "$F2D_WEB_DIR"
    web_site_generate
    local conf; conf=$(web_render) || return 1
    printf '%s\n' "$conf" > "$F2D_WEB_DIR/nginx.conf.new"
    if [[ ! -f "$F2D_WEB_DIR/docker-compose.yml" ]]; then
        cat > "$F2D_WEB_DIR/docker-compose.yml" <<EOF
services:
  f2d-nginx:
    image: nginx:1.29-alpine
    container_name: ${F2D_WEB_CONTAINER}
    restart: always
    network_mode: host
    command: sh -c 'rm -f ${NGINX_SOCK} && exec nginx -g "daemon off;"'
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - /etc/letsencrypt:/etc/letsencrypt:ro
      - /dev/shm:/dev/shm:rw
      - ${F2D_WEB_ROOT}:/var/www/html:ro
    logging:
      driver: json-file
      options: { max-size: 20m, max-file: "3" }
EOF
    fi
    # проверяем конфиг тем же образом до замены рабочего
    if docker run --rm -v "$F2D_WEB_DIR/nginx.conf.new:/etc/nginx/conf.d/default.conf:ro" \
        -v /etc/letsencrypt:/etc/letsencrypt:ro nginx:1.29-alpine nginx -t >/dev/null 2>"$F2D_WEB_DIR/nginx.err"; then
        mv -f "$F2D_WEB_DIR/nginx.conf.new" "$F2D_WEB_DIR/nginx.conf"
    else
        err "nginx отверг конфиг:"; tail -5 "$F2D_WEB_DIR/nginx.err" >&2; return 1
    fi
    (cd "$F2D_WEB_DIR" && docker compose up -d >/dev/null 2>&1) || { err "nginx не запустился"; return 1; }
    docker exec "$F2D_WEB_CONTAINER" nginx -s reload >/dev/null 2>&1
    local i; for i in $(seq 1 10); do [[ -S "$NGINX_SOCK" ]] && break; sleep 1; done
    ok "nginx обновлён${WEB_PORT:+ (порт $WEB_PORT)}"
}

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
F2D_ACME_ROOT="/var/www/acme"

web_load() {
    PANEL_DOMAIN=""; SUB_DOMAIN=""; SELFSTEAL_DOMAIN=""; WEB_PORT=""; WEB_HTTP=""; PANEL_KEY_NAME=""; PANEL_KEY_VALUE=""
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
    # как у обычного сайта: настоящие страницы и настоящий 404, а не одна страница на любой адрес
    error_page 404 /404.html;
    location / { try_files \$uri \$uri/ =404; }
    location = /404.html { internal; }
    location /assets/ { expires 7d; add_header Cache-Control "public"; }
    location = /favicon.ico { try_files /favicon.svg =404; }
}

EOF
    fi
    if [[ "$WEB_HTTP" == yes ]]; then
        local names="" d; for d in "$PANEL_DOMAIN" "$SUB_DOMAIN" "$SELFSTEAL_DOMAIN"; do [[ -n "$d" ]] && names+="$d "; done
        cat <<EOF
# HTTP: ACME (выпуск сертификатов без остановки nginx) и переход на HTTPS — как у любого сайта
server {
    listen 80;
    listen [::]:80;
    server_name ${names% };
    location /.well-known/acme-challenge/ { root ${F2D_ACME_ROOT}; }
    location / { return 301 https://\$host\$request_uri; }
}
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    location /.well-known/acme-challenge/ { root ${F2D_ACME_ROOT}; }
    location / { return 444; }
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

# порт 80 у nginx: свободен или уже наш
_web_http_possible() {
    ss -H -tln '( sport = :80 )' 2>/dev/null | grep -q . || return 0
    docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$F2D_WEB_CONTAINER" && ss -H -tlnp '( sport = :80 )' 2>/dev/null | grep -q '"nginx"'
}

web_site_generate() { site_generate "$F2D_WEB_ROOT"; }

web_apply() {
    require_docker
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx remnawave-nginx; then
        err "На сервере уже работает другой nginx (remnawave-nginx) — он владеет $NGINX_SOCK."
        err "Второй nginx не ставлю: сайты и панель здесь настраивает тот установщик."
        return 1
    fi
    web_load
    mkdir -p "$F2D_WEB_DIR" "$F2D_ACME_ROOT"
    web_site_generate
    # HTTP (80): только если есть что отдавать и порт не занят чужим
    if [[ -n "$PANEL_DOMAIN$SUB_DOMAIN$SELFSTEAL_DOMAIN" && "${WEB_HTTP_OFF:-}" != yes ]] && _web_http_possible; then WEB_HTTP=yes; else WEB_HTTP=""; fi
    web_set WEB_HTTP "$WEB_HTTP"
    local conf; conf=$(web_render) || return 1
    printf '%s\n' "$conf" > "$F2D_WEB_DIR/nginx.conf.new"
    # compose — наш файл, переписываем всегда (новые тома у старых установок)
    if true; then
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
      - ${F2D_ACME_ROOT}:${F2D_ACME_ROOT}:ro
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
    # порты, на которых сайт открывается напрямую
    if [[ "$WEB_HTTP" == yes ]]; then list_add PUBLIC_TCP 80; ufw_allow 80 tcp "" "fail2detect web"; fi
    if [[ -n "$WEB_PORT" ]]; then list_add PUBLIC_TCP "$WEB_PORT"; ufw_allow "$WEB_PORT" tcp "" "fail2detect web"; fi
    fw_apply >/dev/null 2>&1
    docker exec "$F2D_WEB_CONTAINER" nginx -s reload >/dev/null 2>&1
    local i; for i in $(seq 1 10); do [[ -S "$NGINX_SOCK" ]] && break; sleep 1; done
    ok "nginx обновлён${WEB_PORT:+ (порт $WEB_PORT)}$([[ "$WEB_HTTP" == yes ]] && echo ", HTTP 80 → HTTPS")"
}

# починить/настроить маскировку на уже работающей ноде, без переустановки
web_selfsteal_setup() {   # домен
    local dom="$1"
    [[ -n "$dom" ]] || die "fail2detect web selfsteal <домен ноды>"
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx remnawave-nginx; then
        die "Сайт здесь отдаёт nginx установщика (remnawave-nginx) — настраивайте его там"
    fi
    web_load
    cert_ensure "$dom" || die "Не удалось получить сертификат для $dom"
    web_set SELFSTEAL_DOMAIN "$dom"
    if [[ -z "$WEB_PORT" && ",$(fw_xray_ports tcp)," != *",443,"* ]] && ! ss -H -tln '( sport = :443 )' 2>/dev/null | grep -q .; then
        web_set WEB_PORT 443
    fi
    web_apply || return 1
    web_selfsteal_check "$dom"
}

# ---------- проверка сайта-маскировки ----------
# Проверяет то же, что увидит сканер: nginx за сокетом (как его зовёт Reality),
# Reality-порты Xray (неавторизованный TLS → сайт), прямой 443 и HTTP → HTTPS.
web_selfsteal_check() {   # [домен]
    web_load
    local dom="${1:-$SELFSTEAL_DOMAIN}" code body bad=0 p any=no
    [[ -n "$dom" ]] || { warn "Selfsteal-домен не задан: fail2detect web selfsteal <домен ноды>"; return 1; }
    title "Сайт-маскировка: $dom"
    body=$(mktemp)
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx remnawave-nginx; then
        info "Сайт отдаёт nginx установщика (remnawave-nginx) — fail2detect его не трогает"
    fi
    # 1) nginx через unix-сокет с PROXY protocol — так подключается Reality
    if [[ -S "$NGINX_SOCK" ]]; then
        code=$(curl -sk --max-time 6 --unix-socket "$NGINX_SOCK" --haproxy-protocol -o "$body" -w '%{http_code}' "https://$dom/" 2>/dev/null)
        if [[ "$code" == 200 ]]; then ok "nginx за сокетом отдаёт сайт «$(grep -o '<title>[^<]*' "$body" | head -1 | sed 's/<title>//')»"
        else err "nginx за сокетом ответил ${code:-ничего} — нет server-блока для $dom (исправить: fail2detect web selfsteal $dom)"; bad=1; fi
        code=$(curl -sk --max-time 6 --unix-socket "$NGINX_SOCK" --haproxy-protocol -o /dev/null -w '%{http_code}' "https://$dom/f2d-$RANDOM-nope" 2>/dev/null)
        [[ "$code" == 404 ]] && ok "Несуществующая страница — настоящий 404" || warn "Несуществующая страница отвечает $code (у обычного сайта — 404)"
    else
        err "Нет сокета $NGINX_SOCK — nginx не запущен"; bad=1
    fi
    # 2) через Xray: неавторизованный TLS на Reality-порту должен получить сайт с настоящим сертификатом
    local xp; xp=$(fw_xray_ports tcp 2>/dev/null); [[ -n "$xp" ]] || xp=$(detect_xray_ports)
    for p in ${xp//,/ }; do
        code=$(curl -s --max-time 8 --resolve "$dom:$p:127.0.0.1" -o /dev/null -w '%{http_code}' "https://$dom:$p/" 2>/dev/null); local rc=$?
        if [[ "$code" == 200 ]]; then ok "Порт $p (Reality): браузер видит сайт, сертификат $dom настоящий"; any=yes
        elif ((rc == 60)); then warn "Порт $p: сайт есть, но сертификат не подходит к $dom"
        fi
    done
    [[ "$any" == yes ]] || { err "Ни один порт Xray не отдаёт сайт — проверьте target Reality ($NGINX_SOCK, xver 1) и serverNames ($dom)"; bad=1; }
    # 3) прямой HTTPS на WEB_PORT и HTTP → HTTPS
    if [[ -n "$WEB_PORT" ]]; then
        code=$(curl -s --max-time 6 --resolve "$dom:$WEB_PORT:127.0.0.1" -o /dev/null -w '%{http_code}' "https://$dom:$WEB_PORT/" 2>/dev/null)
        [[ "$code" == 200 ]] && ok "https://$dom$([[ $WEB_PORT != 443 ]] && echo ":$WEB_PORT")/ — сайт" || warn "Порт $WEB_PORT отвечает ${code:-ничего}"
    elif [[ "$any" == yes && ",$xp," != *",443,"* && " $xp " != *" 443 "* ]]; then
        warn "Reality не на 443, а nginx не слушает 443 — https://$dom/ в браузере не откроется (fail2detect web site --port443)"
    fi
    if [[ "$WEB_HTTP" == yes ]]; then
        code=$(curl -s --max-time 6 --resolve "$dom:80:127.0.0.1" -o /dev/null -w '%{http_code} %{redirect_url}' "http://$dom/" 2>/dev/null)
        [[ "$code" == 301* ]] && ok "http://$dom/ → HTTPS" || warn "HTTP 80 отвечает «${code:-ничего}»"
    else
        warn "HTTP (80) не обслуживается — http://$dom в браузере не откроется"
    fi
    rm -f "$body"
    ((bad == 0))
}

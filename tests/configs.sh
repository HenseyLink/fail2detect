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
for m in common detect transport certs site web rurules; do source "$ROOT/lib/$m.sh"; done

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
# российский трафик: правила в профиле — Xray должен их принять (geosite:category-ru, ruleTag)
for pol in block direct; do
    inb=$(inbound_build tcp-reality T 443 "" "www.microsoft.com:443" | jq --arg id "$uuid" '.settings.clients=[{id:$id, flow:"xtls-rprx-vision"}]')
    # объём как у RIPE (~11 тыс. сетей, > 128 КБ) — Xray и наш код должны это переварить
    { seq 0 10999 | awk '{print int($1/256) + 1 "." ($1 % 256) ".0.0/16"}'; echo '2a00:1::/32'; } > "$WORK/ru-pfx"
    cfg=$(NODE_RU_POLICY=off profile_config "$inb")
    ru_apply_to_config "$cfg" "$(ru_rules_json "$pol" yes "$WORK/ru-pfx")" > "$WORK/ru-$pol.json"
    if res=$(docker run --rm -v "$WORK/ru-$pol.json:/c.json:ro" "$XRAY_IMAGE" run -test -c /c.json 2>&1); then
        pass "xray: российский трафик — $pol (зоны, сервисы, geosite:category-ru, geoip:ru, сети RIPE)"
    else
        fail "xray: российский трафик — $pol" "$(tail -5 <<<"$res")"
    fi
done
# чужой target для Reality
inb=$(inbound_build tcp-reality T 443 "" "www.microsoft.com:443" | jq --arg id "$uuid" '.settings.clients=[{id:$id, flow:"xtls-rprx-vision"}]')
profile_config "$inb" > "$WORK/ext.json"
docker run --rm -v "$WORK/ext.json:/c.json:ro" "$XRAY_IMAGE" run -test -c /c.json >/dev/null 2>&1 \
    && pass "xray: tcp-reality с внешним target" || fail "xray: tcp-reality с внешним target"

# балансировщик: шаблон подписки Xray JSON, в который панель подставит хосты
# (здесь — как это сделает Remnawave: outbound'ы proxy, proxy-2, wl)
source "$ROOT/lib/balancer.sh"
vless() {   # tag
    jq -n --arg t "$1" --arg id "$uuid" '{tag:$t, protocol:"vless", settings:{vnext:[{address:"203.0.113.10", port:443,
        users:[{id:$id, encryption:"none", flow:"xtls-rprx-vision"}]}]}, streamSettings:{network:"raw", security:"reality",
        realitySettings:{serverName:"www.example.com", fingerprint:"chrome", publicKey:"nT0eWyNk7hS8DM-FdyJ5b8oA9i4X8kTpo6hZ8aRL2Hk", shortId:"ab"}}}'
}
for wl in no yes; do
    outs=$( { vless proxy; vless proxy-2; vless proxy-3; [[ $wl == no ]] || vless wl; } | jq -s '.')
    balancer_template_json "" "$wl" | jq --argjson o "$outs" 'del(.remnawave) | .outbounds = $o + .outbounds' > "$WORK/bal-$wl.json"
    if res=$(docker run --rm -v "$WORK/bal-$wl.json:/c.json:ro" "$XRAY_IMAGE" run -test -c /c.json 2>&1); then
        pass "xray: балансировщик (мосты для белых списков: $wl)"
    else
        fail "xray: балансировщик (мосты: $wl)" "$(tail -5 <<<"$res")"
    fi
done

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

web_set WEB_HTTP yes
check_nginx "нода: selfsteal + HTTP 80 (ACME, переход на HTTPS)"
web_set PANEL_DOMAIN panel.example.com; web_set SUB_DOMAIN sub.example.com; web_set WEB_PORT 443
check_nginx "всё вместе + HTTP 80"

# сайт-маскировка вживую: то, что видит браузер и сканер
printf '\n== сайт-маскировка в nginx\n'
F2D_WEB_ROOT="$WORK/site"; SELFSTEAL_DOMAIN=node.example.com site_generate "$F2D_WEB_ROOT"
: > "$F2D_WEB_ENV"; web_set SELFSTEAL_DOMAIN node.example.com; web_set WEB_PORT 443; web_set WEB_HTTP yes
NGINX_SOCK=/dev/shm/nginx.sock web_render > "$WORK/site.conf"
mkdir -p "$WORK/acme"
cid=$(docker run -d -p 127.0.0.1:18443:443 -p 127.0.0.1:18080:80 -v "$WORK/site.conf:/etc/nginx/conf.d/default.conf:ro" \
    -v "$WORK/le:/etc/letsencrypt:ro" -v "$F2D_WEB_ROOT:/var/www/html:ro" -v "$WORK/acme:/var/www/acme:ro" "$NGINX_IMAGE")
for _ in $(seq 1 20); do curl -sk -o /dev/null --resolve node.example.com:18443:127.0.0.1 https://node.example.com:18443/ && break; sleep 0.5; done
req() { curl -sk --max-time 5 --resolve "node.example.com:$2:127.0.0.1" -o /dev/null -w '%{http_code}' "$1" || true; }
[[ "$(req https://node.example.com:18443/ 18443)" == 200 ]] && pass "главная — 200" || fail "главная" "$(docker logs "$cid" 2>&1 | tail -3)"
[[ "$(req https://node.example.com:18443/services/ 18443)" == 200 && "$(req https://node.example.com:18443/assets/site.css 18443)" == 200 ]] && pass "страницы и стили" || fail "страницы"
[[ "$(req https://node.example.com:18443/wp-login.php 18443)" == 404 ]] && pass "несуществующий адрес — настоящий 404" || fail "404"
{ curl -sk --resolve node.example.com:18443:127.0.0.1 https://node.example.com:18443/nope || true; } | grep -q 'Page not found' && pass "страница 404 оформлена как сайт" || fail "тело 404"
[[ "$(req http://node.example.com:18080/about/ 18080)" == 301 ]] && pass "HTTP → 301 на HTTPS" || fail "HTTP 301"
[[ "$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' --resolve other.example:18443:127.0.0.1 https://other.example:18443/ || true)" == 000 ]] && pass "чужой SNI — обрыв рукопожатия" || fail "чужой SNI"
# через unix-сокет с PROXY protocol — как подключается Reality
docker exec "$cid" sh -c 'apk add -q curl >/dev/null 2>&1 || true'
code=$(docker exec "$cid" curl -sk --max-time 5 --unix-socket /dev/shm/nginx.sock --haproxy-protocol -o /dev/null -w '%{http_code}' https://node.example.com/ 2>/dev/null) || true
[[ "$code" == 200 ]] && pass "сокет + PROXY protocol (путь Reality) — сайт" || fail "сокет Reality" "код ${code:-нет}"
docker rm -f "$cid" >/dev/null

# резервная копия: настоящий PostgreSQL — дамп → новая чистая база → данные на месте
printf '\n== копия базы панели (PostgreSQL)\n'
source "$ROOT/lib/backup.sh"
PG_IMAGE="${PG_IMAGE:-postgres:17-alpine}"
F2D_BACKUP_ROOT="$WORK/pgroot"; mkdir -p "$F2D_BACKUP_ROOT$RW_PANEL_DIR"; echo 'POSTGRES_USER=postgres' > "$F2D_BACKUP_ROOT$RW_PANEL_DIR/.env"
F2D_BACKUP_DIR="$WORK/bk"; mkdir -p "$F2D_BACKUP_DIR"
pg_up() { docker run -d --name "$1" -e POSTGRES_PASSWORD=pw "$PG_IMAGE" >/dev/null; RW_DB_CONTAINER="$1" bk_db_wait 60; }
pg_up f2d-pg-old && pass "старая база поднята" || fail "postgres не поднялся"
docker exec f2d-pg-old psql -U postgres -q -c "create table users (id serial primary key, username text, sub_uuid uuid default gen_random_uuid());
    create table nodes (id serial, name text); insert into users (username) select 'user-' || g || '-' || md5(g::text) from generate_series(1, 120000) g;
    insert into nodes (name) values ('de1'), ('nl1');" >/dev/null
RW_DB_CONTAINER=f2d-pg-old bk_dump_db "$WORK/db.sql.gz" && pass "дамп: $(gzip -dc "$WORK/db.sql.gz" | wc -l | tr -d ' ') строк SQL" || fail "дамп"
pg_up f2d-pg-new && pass "новая чистая база" || fail "новая база"
RW_DB_CONTAINER=f2d-pg-new bk_load_db "$WORK/db.sql.gz" && pass "дамп загружен в новую базу" || fail "загрузка" "$(tail -5 "$F2D_BACKUP_DIR/restore-psql.log" 2>/dev/null)"
c=$(RW_DB_CONTAINER=f2d-pg-new bk_db_counts)
[[ "$c" == "users=120000 nodes=2" ]] && pass "данные на месте: $c" || fail "данные после восстановления" "$c"
a=$(docker exec f2d-pg-old psql -U postgres -tAc "select string_agg(sub_uuid::text, ',' order by id) from users")
b=$(docker exec f2d-pg-new psql -U postgres -tAc "select string_agg(sub_uuid::text, ',' order by id) from users")
[[ -n "$a" && "$a" == "$b" ]] && pass "ссылки подписок (UUID) совпадают побайтно" || fail "UUID подписок разошлись"
# шифрование на настоящем дампе
bk_encrypt "$WORK/db.sql.gz" "$WORK/db.enc" 'p4ssw0rd!' && bk_decrypt "$WORK/db.enc" "$WORK/db.dec" 'p4ssw0rd!' && cmp -s "$WORK/db.sql.gz" "$WORK/db.dec" \
    && pass "шифрование AES-256 туда и обратно — без потерь" || fail "шифрование дампа"
docker rm -f f2d-pg-old f2d-pg-new >/dev/null
unset F2D_BACKUP_ROOT

printf '\nИтого: %d fail\n' "$FAIL"
(( FAIL == 0 ))

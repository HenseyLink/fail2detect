#!/usr/bin/env bash
# shellcheck disable=SC2317,SC2329  # заглушки функций вызываются из подключаемых модулей
# Тесты fail2detect. Части с nftables нужны root и nft (запускайте через
# tests/run.sh — он поднимет изолированный контейнер). Без nft выполняются
# только тесты регулярок и CLI.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

export NO_COLOR=1
export F2D_CONF_DIR="$WORK/etc" F2D_STATE_DIR="$WORK/state" F2D_LOG_DIR="$WORK/log"
mkdir -p "$F2D_CONF_DIR/jail.d"
cp "$ROOT"/conf/jail.d/*.conf "$F2D_CONF_DIR/jail.d/"

PASS=0; FAIL=0
pass() { PASS=$((PASS + 1)); printf '  ok    %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n' "$1"; [[ -n "${2:-}" ]] && printf '        %s\n' "$2"; }
check() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi; }
section() { printf '\n== %s\n' "$1"; }

# shellcheck source=/dev/null
for m in common detect firewall jail transport certs site web remnawave balancer rurules installer remove backup panel setup ipquality geocheck update speedtest bench censorcheck; do source "$ROOT/lib/$m.sh"; done
load_config
GEO_LOOKUP=no

# окружение сервера — заглушки детекта
STUB_NODE=yes; STUB_PANEL=no
has_node()  { [[ "$STUB_NODE" == yes ]]; }
has_panel() { [[ "$STUB_PANEL" == yes ]]; }
has_sub_page() { false; }
detect_ssh_ports()  { echo 2233; }
detect_xray_ports() { echo 443; }
detect_web_ports() { :; }
detect_node_api_port() { echo 2222; }
detect_panel_ips()  { echo "198.51.100.200 2001:db8:abcd::1"; }
wan_iface() { echo eth0; }
STUB_MODE=nft
fw_mode() { echo "$STUB_MODE"; }
ufw_active() { false; }

# ---------------------------------------------------------------- регулярки
section "Регулярки jail'ов"
for exp in "$ROOT"/tests/fixtures/*.expected; do
    j=$(basename "$exp" .expected)
    got=$(jail_test "$j" "$ROOT/tests/fixtures/$j.log" 2>&1 | awk '$1 ~ /^[0-9]+$/ {print $2}' | sort)
    want=$(sort "$exp")
    if [[ "$got" == "$want" ]]; then pass "jail $j: $(wc -l <<<"$want" | tr -d ' ') IP"
    else fail "jail $j" "ожидали: $(tr '\n' ' ' <<<"$want")| получили: $(tr '\n' ' ' <<<"$got")"; fi
done

section "Вспомогательные функции"
check "is_ipv4 1.2.3.4"           is_ipv4 1.2.3.4
check "is_ipv4 отвергает 1.2.3.256" bash -c "source '$ROOT/lib/common.sh'; ! is_ipv4 1.2.3.256"
check "is_ipv4 CIDR /24"          is_ipv4 10.0.0.0/24
check "is_ipv6 2001:db8::1"       is_ipv6 2001:db8::1
check "частный 100.64.1.1 (CGNAT)" is_private_ip 100.64.1.1
check "публичный 8.8.8.8"         bash -c "source '$ROOT/lib/common.sh'; ! is_private_ip 8.8.8.8"
check "ip_in_list по CIDR"        ip_in_list 203.0.113.77 "10.0.0.1 203.0.113.0/24"
check "ip_in_list мимо CIDR"      bash -c "source '$ROOT/lib/common.sh'; source '$ROOT/lib/jail.sh'; ! ip_in_list 203.0.114.1 203.0.113.0/24"
[[ "$(to_seconds 7d)" == 604800 ]] && pass "to_seconds 7d" || fail "to_seconds 7d"

section "Транспорты"
for t in "${TRANSPORTS[@]}"; do
    inb=$(inbound_build "$t" "T" 8443 node.example.com 2>/dev/null) || { fail "inbound $t"; continue; }
    got=$(transport_of_inbound <<<"$inb")
    [[ "$got" == "$t" ]] && pass "inbound $t → распознаётся обратно" || fail "inbound $t" "распознан как $got"
    hf=$(host_fields "$inb" node.example.com)
    [[ "$(jq -r .port <<<"$hf")" == 8443 && "$(jq -r .sni <<<"$hf")" == node.example.com ]] && pass "host $t" || fail "host $t" "$hf"
done
[[ "$(transport_l4 hysteria2)" == udp && "$(transport_l4 xhttp-tls)" == tcp ]] && pass "l4 tcp/udp" || fail "l4 tcp/udp"
k=$(x25519_keys); [[ ${#k} -eq 87 ]] && pass "x25519: два ключа по 43 символа" || fail "x25519" "$k"
inb=$(inbound_build tcp-reality T 443 "" "www.microsoft.com:443")
[[ "$(jq -r '.streamSettings.realitySettings | .target + " " + .serverNames[0] + " " + (.xver|tostring)' <<<"$inb")" == "www.microsoft.com:443 www.microsoft.com null" ]] \
    && pass "Reality с чужим target (без xver)" || fail "Reality с чужим target" "$(jq -c .streamSettings.realitySettings <<<"$inb")"
inb=$(inbound_build xhttp-reality T 443 d.example.com "" "/keep" "PRIV" "SID")
[[ "$(jq -r '.streamSettings | .xhttpSettings.path + " " + .realitySettings.privateKey + " " + .realitySettings.shortIds[0]' <<<"$inb")" == "/keep PRIV SID" ]] \
    && pass "смена транспорта сохраняет ключи и path" || fail "сохранение ключей и path"

section "Несколько транспортов на одной ноде"
parse_transports_arg "tcp-reality:443,hysteria2:443,grpc-reality:8443,xhttp-reality:4443"
[[ "${#T_LIST[@]}" == 4 && "${T_PORTS[hysteria2]}" == 443 && "$(transports_arg)" == "tcp-reality:443,hysteria2:443,grpc-reality:8443,xhttp-reality:4443" ]] \
    && pass "--transports разбирается и собирается обратно" || fail "--transports" "$(transports_arg)"
T_DOMAIN=node.example.com; T_TARGET=""; T_OBFS=obfs123
inbs=$(build_inbounds NODE_ABC)
[[ "$(jq length <<<"$inbs")" == 4 ]] && pass "набор: 4 inbound'а" || fail "набор" "$(jq length <<<"$inbs")"
[[ "$(jq -r '[.[].tag] | unique | length' <<<"$inbs")" == 4 ]] && pass "теги уникальны: $(jq -r '[.[].tag] | join(" ")' <<<"$inbs")" || fail "теги"
[[ "$(jq -r '[.[] | .streamSettings.realitySettings.privateKey // empty] | unique | length' <<<"$inbs")" == 1 ]] && pass "ключ Reality общий для всех Reality-транспортов" || fail "общий ключ Reality"
[[ "$(jq -r '.[] | select(.protocol=="hysteria") | .streamSettings.finalmask.udp[0].settings.password' <<<"$inbs")" == obfs123 ]] && pass "Salamander только у Hysteria2" || fail "Salamander"
T_TARGET="www.microsoft.com:443"; parse_transports_arg "tcp-reality:443,xhttp-tls:2083"
inbs=$(build_inbounds N2)
[[ "$(jq -r '.[0].streamSettings.realitySettings.serverNames[0] + " " + .[1].streamSettings.tlsSettings.serverName' <<<"$inbs")" == "www.microsoft.com node.example.com" ]] \
    && pass "чужой сайт для Reality + свой домен для TLS" || fail "SNI Reality/TLS" "$(jq -c '[.[0].streamSettings.realitySettings.serverNames, .[1].streamSettings.tlsSettings.serverName]' <<<"$inbs")"
# интерактивный выбор: «набор» (7), порты по умолчанию, свой сайт, без Salamander
ask_domain() { REPLY=node.example.com; }
ASK_PORT_NOCHECK=1 ask_transports < <(printf '7\n\n\n\n\n1\nn\n') >/dev/null 2>&1
[[ "${T_LIST[*]}" == "tcp-reality hysteria2 grpc-reality xhttp-reality" && "${T_PORTS[grpc-reality]}" == 8443 && "$T_DOMAIN" == node.example.com && -z "$T_OBFS" ]] \
    && pass "выбор «набор»: 4 транспорта, порты по умолчанию" || fail "выбор набора" "${T_LIST[*]} | ${T_PORTS[grpc-reality]:-} | $T_DOMAIN"
ASK_PORT_NOCHECK=1 ask_transports < <(printf '1 6 1\n\n\n1\nn\n') >/dev/null 2>&1
[[ "${T_LIST[*]}" == "tcp-reality hysteria2" ]] && pass "выбор «1 6 1»: без повторов" || fail "выбор 1 6 1" "${T_LIST[*]}"
ASK_PORT_NOCHECK=1 ask_transports < <(printf '1 3\n443\n443\n2083\n1\n') >/dev/null 2>&1
[[ "${T_PORTS[xhttp-tls]}" == 2083 ]] && pass "один TCP-порт двум транспортам не отдаётся" || fail "конфликт портов" "${T_PORTS[xhttp-tls]:-}"
unset -f ask_domain; T_TARGET=""; T_OBFS=""

section "docker-compose ноды (разные установщики и отступы)"
node_dir() { echo "$WORK/node"; }
for fx in compose-nginx compose-caddy; do
    mkdir -p "$WORK/node"; cp "$ROOT/tests/fixtures/$fx.yml" "$WORK/node/docker-compose.yml"
    node_compose_add_certs; rc=$?
    f="$WORK/node/docker-compose.yml"
    [[ $rc == 0 && "$(grep -c xray-certs "$f")" == 1 ]] && pass "$fx: монтирование добавлено" || fail "$fx: монтирование" "rc=$rc"
    # строка с сертификатами стоит в volumes сервиса remnanode и с тем же отступом, что соседние элементы
    blk=$(awk '/^ *remnanode:/{f=1} f&&/^[^ ]/{f=0} f' "$f")
    ind_new=$(grep 'xray-certs' <<<"$blk" | sed -E 's/^( *).*/\1/' | awk '{print length}')
    ind_sib=$(grep -m1 '/dev/shm' <<<"$blk" | sed -E 's/^( *).*/\1/' | awk '{print length}')
    [[ -n "$ind_new" && "$ind_new" == "$ind_sib" ]] && pass "$fx: отступ совпадает с соседями ($ind_new)" || fail "$fx: отступ" "новый=$ind_new соседи=$ind_sib"
    diff <(awk '/^ *remnanode:/{exit} {print}' "$ROOT/tests/fixtures/$fx.yml") <(awk '/^ *remnanode:/{exit} {print}' "$f") >/dev/null \
        && pass "$fx: остальные сервисы не тронуты" || fail "$fx: изменены другие сервисы"
    node_compose_add_certs && fail "$fx: повторный запуск изменил файл" || pass "$fx: повторный запуск ничего не меняет"
done
printf 'services:\n    remnanode:\n        image: remnawave/node\n' > "$WORK/node/docker-compose.yml"
node_compose_add_certs && grep -q '^        volumes:$' "$WORK/node/docker-compose.yml" && grep -q '^          - ./certs' "$WORK/node/docker-compose.yml" \
    && pass "сервис без volumes: секция добавлена" || fail "сервис без volumes" "$(cat "$WORK/node/docker-compose.yml")"
STUB_NODE=yes

section "Сертификаты (certbot и Caddy)"
mkc() { mkdir -p "$1"; openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=$3" -addext "subjectAltName=DNS:$3" \
          -keyout "$1/$2.key" -out "$1/$2.crt" >/dev/null 2>&1; }
CR="$WORK/caddy/certificates/acme-v02.api.letsencrypt.org-directory"
mkc "$CR/lv.example.com" lv.example.com lv.example.com
mkc "$CR/wildcard_.example.org" wildcard_.example.org '*.example.org'
LE_LIVE="$WORK/le-empty"; export F2D_CADDY_ROOTS="$WORK/caddy/certificates"
r=$(cert_files lv.example.com); [[ "$r" == *"/lv.example.com/lv.example.com.crt "*" caddy" ]] && pass "сертификат Caddy найден" || fail "сертификат Caddy" "$r"
r=$(cert_files node.example.org); [[ "$r" == *wildcard_.example.org* ]] && pass "wildcard Caddy покрывает поддомен" || fail "wildcard Caddy" "$r"
cert_files other.example.net >/dev/null && fail "нашёлся чужой сертификат" || pass "чужой домен — не найден"
if date -d now >/dev/null 2>&1; then   # GNU date (на Linux всегда)
    d=$(cert_days_left "$CR/lv.example.com/lv.example.com.crt"); [[ "$d" =~ ^(29|30)$ ]] && pass "срок сертификата: $d дн." || fail "срок сертификата" "$d"
fi
mkdir -p "$WORK/node/certs"; node_dir() { echo "$WORK/node"; }; has_node() { true; }; docker() { :; }
NODE_TLS_DOMAIN=lv.example.com; cert_sync_node
cmp -s "$CR/lv.example.com/lv.example.com.crt" "$WORK/node/certs/fullchain.pem" && pass "сертификат Caddy скопирован в ноду" || fail "копия в ноду"
NODE_TLS_DOMAIN=""; unset F2D_CADDY_ROOTS; unset -f docker

section "IPQuality: IP2Location и AbuseIPDB"
mkdir -p "$WORK/ipq"; cp "$ROOT/tests/fixtures/ip2location-page.html" "$WORK/ipq/ip2loc"; cp "$ROOT/tests/fixtures/abuseipdb.json" "$WORK/ipq/abuseipdb"
declare -A G=(); ABUSEIPDB_KEY="test"; gc_parse "$WORK/ipq" 78.135.77.114
[[ "${G[ip2loc.asntype]}|${G[ip2loc.cc]}|${G[ip2loc.risk]}|${G[ip2loc.server]}" == "DCH|TR|3|true" ]] && pass "IP2Location: DCH, TR, fraud 3, сервер" || fail "IP2Location" "${G[ip2loc.asntype]}|${G[ip2loc.cc]}|${G[ip2loc.risk]}|${G[ip2loc.server]}"
[[ "${G[abuseipdb.risk]}|${G[abuseipdb.cc]}|${G[abuseipdb.abuser]}|${G[abuseipdb.server]}|${G[abuseipdb.reports]}" == "37|TR|true|true|12" ]] \
    && pass "AbuseIPDB: риск 37, TR, абьюзер, сервер, 12 жалоб" || fail "AbuseIPDB" "${G[abuseipdb.risk]}|${G[abuseipdb.cc]}|${G[abuseipdb.abuser]}|${G[abuseipdb.server]}|${G[abuseipdb.reports]}"
read -r t _ <<<"$(usage_ru "${G[abuseipdb.asntype]}")"; [[ "$t" == Хостинг ]] && pass "тип AbuseIPDB → Хостинг" || fail "тип AbuseIPDB" "$t"
read -r t _ <<<"$(usage_ru DCH)"; [[ "$t" == Хостинг ]] && pass "тип IP2Location DCH → Хостинг" || fail "DCH" "$t"
read -r t _ <<<"$(usage_ru "ISP/MOB")"; [[ "$t" == Мобильный ]] && pass "тип IP2Location ISP/MOB → Мобильный" || fail "ISP/MOB" "$t"
ABUSEIPDB_KEY=""; G=(); gc_parse "$WORK/ipq" 78.135.77.114; [[ "${G[abuseipdb.asntype]}" == nokey ]] && pass "без ключа AbuseIPDB — пометка «нужен ключ»" || fail "без ключа"
unset G

section "GeoCheck: эталонная страна и расхождения"
# IP зарегистрирован в TR, сервер в Болгарии: эталон — BG (большинство гео-баз), не реестр
geo_out=$(
    is_ipv4() { [[ "$1" =~ ^[0-9.]+$ ]]; }
    curl() { case "$*" in *api.ipify.org*) echo 203.0.113.7;; *api6.ipify.org*) return 7;;
                          *rdap.db.ripe.net*) echo '{"country":"TR"}';; *ipinfo.io/widget*) echo '{"data":{"org":"AS64500 Test"}}';; esac; }
    gr_svc() { case "$1" in jetbrains|microsoft) echo US;; gemini|youtube_premium|spotify_signup|disney_access|reddit_guest) echo Да;; google_captcha) echo Нет;; *) echo BG;; esac; }
    gr_cdn() { echo "BG (SOF)"; }
    gr_geoip() { case "$1" in ifconfig) echo US;; ripe) echo TR;; *) echo BG;; esac; }
    geocheck_run --full 2>&1 )
grep -q 'Страна (IPv4): BG — так видят 15 из 16; по реестру TR' <<<"$geo_out" && pass "эталон — страна большинства гео-баз (BG), реестр (TR) — пометкой" || fail "эталон GeoCheck" "$geo_out"
odd=$(sed -n '/^Видят другую страну/,/^!/p' <<<"$geo_out")
grep -q '^JetBrains  *US' <<<"$odd" && grep -q '^ifconfig.co  *US' <<<"$odd" && ! grep -q 'rdap\|TR' <<<"$odd" \
    && pass "расхождения — таблицей, без реестра RIPE и без «не TR»" || fail "таблица расхождений" "$odd"
grep -q 'с другой страной: 3' <<<"$geo_out" && pass "итог: 3 сервиса с другой страной" || fail "итог расхождений" "$geo_out"
unset geo_out odd

section "Удаление: защита от лишнего"
for bad in / /etc /opt /root /home "$WORK"; do
    _safe_rmdir "$bad" 2>/dev/null && fail "_safe_rmdir согласился удалить $bad" || pass "_safe_rmdir отказал: $bad"
done

section "Мобильные абоненты (CGNAT)"
# portscan: 10 стуков в один порт — не бан; 6 разных портов — бан
bans=(); ban_add() { bans+=("$1"); }
# (через < <(…): в конвейере jail_loop шёл бы в подоболочке и баны терялись)
jail_loop portscan < <(
    for i in $(seq 1 10); do echo "[UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=95.24.1.1 DST=10.0.0.1 LEN=60 PROTO=TCP SPT=4$i DPT=8080 WINDOW=1 RES=0x00 SYN URGP=0"; done
    for i in 1 2 3 4 5 6; do echo "[UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=95.24.2.2 DST=10.0.0.1 LEN=60 PROTO=TCP SPT=5 DPT=$((20 + i)) WINDOW=1 RES=0x00 SYN URGP=0"; done
    for i in 1 2 3 4 5; do echo "[UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=95.24.3.3 DST=10.0.0.1 LEN=60 PROTO=TCP SPT=5 DPT=$((30 + i)) WINDOW=1 RES=0x00 SYN URGP=0"; done
)
[[ " ${bans[*]:-} " != *" 95.24.1.1 "* ]] && pass "10 стуков в ОДИН порт (шум за CGNAT) — без бана" || fail "бан за стуки в один порт"
[[ " ${bans[*]:-} " == *" 95.24.2.2 "* ]] && pass "6 РАЗНЫХ закрытых портов (сканер) — бан" || fail "сканер не забанен" "${bans[*]:-}"
[[ " ${bans[*]:-} " != *" 95.24.3.3 "* ]] && pass "5 разных портов — ещё без бана" || fail "бан раньше порога"
# jail без DISTINCT (sshd) по-прежнему банит по числу совпадений
jail_loop sshd < <(for i in 1 2 3 4 5; do echo "Failed password for root from 45.8.8.8 port 1 ssh2"; done)
[[ " ${bans[*]:-} " == *" 45.8.8.8 "* ]] && pass "sshd: 5 неудач — бан (счётчик без DISTINCT)" || fail "sshd не банит" "${bans[*]:-}"
unset -f ban_add; source "$ROOT/lib/jail.sh"
# правила: забаненным открыты порты Xray (except-xray), при all — нет
NODE_XRAY_PORTS="443/tcp 443/udp"; BAN_SCOPE=except-xray
r=$(fw_render)
grep -q 'saddr @banned4 tcp dport @xray_tcp accept' <<<"$r" && grep -q 'set xray_tcp .*443' <<<"$r" && pass "бан не закрывает порты Xray (except-xray)" || fail "except-xray"
[[ $(grep -n 'saddr @block4 drop' <<<"$r" | head -1 | cut -d: -f1) -lt $(grep -n 'saddr @banned4 tcp dport @xray_tcp' <<<"$r" | cut -d: -f1) ]] \
    && pass "блок-листы сканеров срабатывают раньше исключения для Xray" || fail "порядок block/banned"
BAN_SCOPE=all; r=$(fw_render)
grep -q 'dport @xray_tcp accept' <<<"$r" && fail "BAN_SCOPE=all всё ещё открывает Xray" || pass "BAN_SCOPE=all закрывает всё"
BAN_SCOPE=except-xray; NODE_XRAY_PORTS=""
# блок-листы: сети шире /16 отбрасываются, government идёт через фильтр
printf '# test\n8.0.0.0/8\n1.2.3.0/24\n5.6.7.8\n2001:db8::/16\n2a01:4f8::/32\n' > "$WORK/bl.txt"
ensure_dirs; BLOCKLISTS="t government"; BLOCKLIST_URL_t="file://$WORK/bl.txt"; BLOCKLIST_URL_government="file://$WORK/bl.txt"
# (government здесь — тот же тестовый файл без подписей: фильтр пропускает /24 и /32)
blocklist_update >"$WORK/bl.out" 2>&1
[[ "$(tr '\n' ' ' < "$F2D_STATE_DIR/blocklist4.txt")" == "1.2.3.0/24 5.6.7.8 " ]] && pass "IPv4: /8 отброшен, /24 и /32 оставлены" || fail "фильтр IPv4" "$(cat "$F2D_STATE_DIR/blocklist4.txt")"
[[ "$(cat "$F2D_STATE_DIR/blocklist6.txt")" == "2a01:4f8::/32" ]] && pass "IPv6: /16 отброшен" || fail "фильтр IPv6" "$(cat "$F2D_STATE_DIR/blocklist6.txt")"
grep -q '1.2.3.0/24' "$F2D_STATE_DIR/blocklist4.txt" && pass "government загружается (через фильтр)" || fail "government"
# фильтр government: абонентские пулы, CDN, Qrator и крупные сети — прочь; госорганы — остаются
gout=$(gov_filter < "$ROOT/tests/fixtures/government-sample.list" 2>/dev/null)
[[ "$(tr '\n' ' ' <<<"$gout")" == "37.29.55.192/30 195.98.43.104/29 " ]] \
    && pass "government: остались прокуратура и МВД, убраны GPRS-пул, NGENIX, Qrator, /19" || fail "фильтр government" "$(tr '\n' ' ' <<<"$gout")"
BLOCKLISTS="antiscanner skipa"; : > "$F2D_STATE_DIR/blocklist4.txt"; : > "$F2D_STATE_DIR/blocklist6.txt"

section "Порты Xray не выпадают из разрешённых"
xp_save="$NODE_XRAY_PORTS"; config_set NODE_XRAY_PORTS "443/tcp 2053/udp"
stubs_save=$(declare -f detect_xray_ports detect_xray_udp_ports)   # вернуть после теста
detect_xray_ports() { :; }; detect_xray_udp_ports() { :; }   # Xray как раз перезапускается
[[ " $(fw_public_tcp) " == *" 443 "* && " $(fw_public_udp) " == *" 2053 "* ]] && pass "известные порты открыты, даже пока Xray не слушает" || fail "известные порты" "tcp=$(fw_public_tcp) udp=$(fw_public_udp)"
nftlog="$WORK/nft.log"; : > "$nftlog"
nft() { echo "nft $*" >> "$nftlog"; }
detect_xray_ports() { echo "443 9443"; }; detect_xray_udp_ports() { echo "443"; }   # панель прислала новые inbound'ы
xray_ports_sync >/dev/null 2>&1; load_config
[[ " $NODE_XRAY_PORTS " == *" 9443/tcp "* && " $NODE_XRAY_PORTS " == *" 443/udp "* ]] && pass "новые порты Xray запомнены: $NODE_XRAY_PORTS" || fail "новые порты" "$NODE_XRAY_PORTS"
grep -q 'add element inet fail2detect pub_tcp { 9443 }' "$nftlog" && grep -q 'pub_udp { 443 }' "$nftlog" && pass "новые порты сразу открыты в фаерволе" || fail "открытие портов" "$(cat "$nftlog")"
: > "$nftlog"; xray_ports_sync >/dev/null 2>&1; [[ ! -s "$nftlog" ]] && pass "повторная проверка ничего не трогает" || fail "повтор трогает nft"
# три строки лога об одном IP подряд — один бан, срок не растёт
: > "$F2D_BANS_DB"; for i in 1 2 3; do ban_add 79.139.188.244 86400 portscan "тест" >/dev/null; done
[[ "$(grep -c 'add element' "$nftlog")" == 1 && "$(awk -F'\t' '$2=="BAN" && $3=="79.139.188.244"' "$F2D_AUDIT_LOG" | wc -l | tr -d ' ')" == 1 ]] \
    && pass "три лога подряд — один бан, без 1→2→4 дней" || fail "эскалация бана" "$(grep -c 'add element' "$nftlog")"
unset -f nft detect_xray_ports detect_xray_udp_ports; eval "$stubs_save"   # заглушки теста, а не настоящий detect.sh
config_set NODE_XRAY_PORTS "$xp_save"; load_config; : > "$F2D_BANS_DB"

section "Вопросы и e-mail для сертификата"
REPLY="me@example.com"; confirm "ok?" n < <(printf 'y\n') >/dev/null 2>&1
[[ "$REPLY" == me@example.com ]] && pass "confirm не затирает введённое ранее (REPLY)" || fail "confirm затёр REPLY" "$REPLY"
CERT_EMAIL=""; cert_ask_email < <(printf 'nelisyt@example.com\ny\n') >/dev/null 2>&1
[[ "$CERT_EMAIL" == nelisyt@example.com ]] && pass "e-mail после «верно? y» — это e-mail, а не «y»" || fail "e-mail" "$CERT_EMAIL"
CERT_EMAIL=""; cert_ask_email < <(printf 'not-an-email\nok@example.org\ny\n') >/dev/null 2>&1
[[ "$CERT_EMAIL" == ok@example.org ]] && pass "неверный e-mail переспрашивается" || fail "переспрос e-mail" "$CERT_EMAIL"
cert_email_valid y && fail "«y» принят за e-mail" || pass "«y» не считается e-mail'ом"
# выпуск: не удался -> ничего не запомнено; удался -> запомнено
cert_files() { return 1; }; cert_deps() { :; }; cert_hooks_install() { :; }
_cert_issue() { return 1; }
config_set CERT_METHOD ""; config_set CERT_EMAIL ""; CERT_METHOD=""; CERT_EMAIL=""
cert_ensure x.example.com < <(printf '1\nfail@example.com\ny\nn\n') >/dev/null 2>&1
load_config
[[ -z "$CERT_METHOD" && -z "$CERT_EMAIL" ]] && pass "после неудачи способ и e-mail не запомнены" || fail "запомнено после неудачи" "$CERT_METHOD $CERT_EMAIL"
_cert_issue() { return 0; }
cert_ensure x.example.com < <(printf '1\ngood@example.com\ny\n') >/dev/null 2>&1
load_config
[[ "$CERT_METHOD" == http && "$CERT_EMAIL" == good@example.com ]] && pass "после успеха способ и e-mail запомнены" || fail "после успеха" "$CERT_METHOD $CERT_EMAIL"
config_set CERT_EMAIL "y"; load_config
cert_ensure x.example.com < <(printf '1\nnew@example.com\ny\n') >/dev/null 2>&1
load_config
[[ "$CERT_EMAIL" == new@example.com ]] && pass "сохранённый «y» распознан и переспрошен" || fail "сохранённый y" "$CERT_EMAIL"
unset -f cert_files cert_deps cert_hooks_install _cert_issue
# shellcheck source=/dev/null
source "$ROOT/lib/certs.sh"
config_set CERT_METHOD ""; config_set CERT_EMAIL ""; load_config

section "Адрес API панели"
[[ "$(rw_parse_url 'https://panel.example.com/auth/login?zDXqulmc=ZAKdtFMm')" == $'https://panel.example.com\tzDXqulmc=ZAKdtFMm' ]] \
    && pass "ссылка входа → адрес + cookie" || fail "ссылка входа" "$(rw_parse_url 'https://panel.example.com/auth/login?zDXqulmc=ZAKdtFMm')"
[[ "$(rw_parse_url 'https://panel.example.com/')" == $'https://panel.example.com\t' ]] && pass "голый адрес не меняется" || fail "голый адрес"
[[ "$(rw_parse_url 'http://127.0.0.1:3000')" == $'http://127.0.0.1:3000\t' ]] && pass "локальный API с портом" || fail "локальный API с портом"

section "Балансировщик"
def='{"routing":{"rules":[{"type":"field","network":"tcp,udp","outboundTag":"proxy"},{"domain":["geosite:private"],"outboundTag":"direct"}]},"outbounds":[{"tag":"proxy","protocol":"vless"},{"tag":"direct","protocol":"freedom"}]}'
t=$(balancer_template_json "$def" no)
[[ -n "$t" ]] && pass "шаблон собирается (jq $(jq --version))" || fail "шаблон не собрался"
[[ $(jq -c '.routing.rules' <<<"$t") == '[{"domain":["geosite:private"],"outboundTag":"direct"},{"network":"tcp,udp","balancerTag":"auto"}]' ]] \
    && pass "правила Default сохранены, «всё → proxy» заменено балансировщиком" || fail "правила шаблона" "$(jq -c '.routing.rules' <<<"$t")"
jq -e '.outbounds | map(.tag) == ["direct"]' >/dev/null <<<"${t:-null}" && pass "тег proxy оставлен подставленным хостам" || fail "outbound proxy из Default"
jq -e '.remnawave.injectHosts == [{"selector":{"type":"tagRegex","pattern":"^F2D_BAL$"},"selectFrom":"ALL","tagPrefix":"proxy"}]
    and .routing.balancers[0].fallbackTag == "proxy" and .routing.balancers[0].strategy.type == "leastLoad"' >/dev/null <<<"${t:-null}" \
    && pass "без мостов: пул по тегу F2D_BAL, fallback — proxy" || fail "шаблон без мостов"
t=$(balancer_template_json "" yes); [[ -n "$t" ]] || t=null
jq -e '(.remnawave.injectHosts | map(.tagPrefix)) == ["proxy","wl"] and .burstObservatory.subjectSelector == ["proxy","wl"]
    and .routing.balancers[0].selector == ["proxy"] and .routing.balancers[0].fallbackTag == "wl"' >/dev/null <<<"$t" \
    && pass "белые списки: мосты пингуются, но трафик на них — только когда пул молчит" || fail "шаблон с мостами"
# панель-заглушка: теги хостов
API_LOG="$WORK/api.log"; : > "$API_LOG"
HOSTS='{"response":[{"uuid":"h1","remark":"de1 · TCP Reality","address":"1.1.1.1","port":443,"tags":["EU"],"inbound":{}},
  {"uuid":"h2","remark":"de1 · Hysteria 2","address":"1.1.1.1","port":443,"tags":["F2D_BAL"],"inbound":{}},
  {"uuid":"h3","remark":"fi1 · TCP Reality","address":"2.2.2.2","port":443,"tags":[],"inbound":{}}]}'
rw_api() { echo "$1 $2 ${3:-}" >> "$API_LOG"; if [[ "$1" == GET ]]; then echo "$HOSTS"; else echo '{"response":{"uuid":"x"}}'; fi; }
balancer_tag_node_hosts de1 >/dev/null 2>&1
grep -q 'PATCH /api/hosts {"uuid":"h1","tags":\["EU","F2D_BAL"\]}' "$API_LOG" && pass "хосты новой ноды получают тег F2D_BAL (старые теги целы)" || fail "тег новой ноды" "$(cat "$API_LOG")"
grep -q '"h2"' "$API_LOG" && fail "повторно помечен уже помеченный хост" || pass "уже помеченный хост не трогается"
grep -q '"h3"' "$API_LOG" && fail "помечен хост чужой ноды" || pass "хосты других нод не трогаются"
: > "$API_LOG"; bal_set_tag h2 F2D_BAL del
grep -q '{"uuid":"h2","tags":\[\]}' "$API_LOG" && pass "тег снимается" || fail "снятие тега" "$(cat "$API_LOG")"
# весь сценарий setup: у хостов нет тегов/шаблона — пустые поля не должны сдвигать uuid inbound'а
P1=11111111-1111-4111-8111-111111111111; I1=22222222-2222-4222-8222-222222222222
HOSTS=$(jq -nc --arg p "$P1" --arg i "$I1" '{response: [
  {uuid:"h1", remark:"de1 · TCP Reality", address:"1.1.1.1", port:443, tags:[], isHidden:false, xrayJsonTemplateUuid:null, inbound:{configProfileUuid:$p, configProfileInboundUuid:$i}},
  {uuid:"h2", remark:"fi1 · TCP Reality", address:"2.2.2.2", port:443, tags:[], isHidden:false, xrayJsonTemplateUuid:null, inbound:{configProfileUuid:$p, configProfileInboundUuid:$i}},
  {uuid:"h3", remark:"ru-wl · TCP Reality", address:"3.3.3.3", port:8443, tags:[], isHidden:false, xrayJsonTemplateUuid:null, inbound:{configProfileUuid:$p, configProfileInboundUuid:$i}}]}')
rw_api() {
    echo "$1 $2 ${3:-}" >> "$API_LOG"
    case "$1 $2" in
        "GET /api/hosts") echo "$HOSTS";;
        "GET /api/subscription-templates") echo '{"response":{"templates":[{"uuid":"d0","name":"Default","templateType":"XRAY_JSON"}]}}';;
        "GET /api/subscription-templates/d0") echo '{"response":{"templateJson":{}}}';;
        "GET /api/subscription-settings") echo '{"response":{"uuid":"s1","serveJsonAtBaseSubscription":false}}';;
        "PATCH /api/subscription-settings") jq -c '{response: {uuid: .uuid, serveJsonAtBaseSubscription: .serveJsonAtBaseSubscription}}' <<<"$3";;
        "GET /api/external-squads") echo '{"response":{"externalSquads":[{"name":"partners","subscriptionSettings":{"serveJsonAtBaseSubscription":false}}]}}';;
        *) echo '{"response":{"uuid":"33333333-3333-4333-8333-333333333333"}}';;
    esac
}
req_saved=$(declare -f require_root rw_need_api); require_root() { :; }; rw_need_api() { :; }
: > "$API_LOG"
balancer_setup < <(printf '1 2\n3\n⚡ Авто\n') >/dev/null 2>&1; rc=$?
body=$(grep '^POST /api/hosts ' "$API_LOG" | cut -d' ' -f3-)
[[ $rc == 0 ]] && jq -e --arg p "$P1" --arg i "$I1" '.inbound == {configProfileUuid:$p, configProfileInboundUuid:$i} and .address == "1.1.1.1" and .port == 443
    and .remark == "⚡ Авто" and .xrayJsonTemplateUuid != null and (.excludeFromSubscriptionTypes | index("XRAY_JSON") | not)' >/dev/null <<<"$body" \
    && pass "setup: запись «Авто» создаётся с inbound'ом первой ноды" || fail "setup: запись «Авто»" "rc=$rc body=$body"
grep -q '"uuid":"h3","tags":\["F2D_WL"\]' "$API_LOG" && grep -q '"uuid":"h1","tags":\["F2D_BAL"\]' "$API_LOG" \
    && pass "setup: пул и мост помечены тегами" || fail "setup: теги"
grep -q 'PATCH /api/subscription-settings {"uuid":"s1","serveJsonAtBaseSubscription":true}' "$API_LOG" \
    && pass "setup: включён JSON на базовом пути подписки (Happ/INCY увидят «Авто»)" || fail "setup: serveJsonAtBaseSubscription"
grep -q '^BALANCER_JSON_BASE_SET="yes"' "$F2D_CONF" && pass "setup: запомнено, что настройку включил fail2detect" || fail "setup: BALANCER_JSON_BASE_SET"
out=$(bal_json_base_enable 2>&1 </dev/null); grep -q partners <<<"$out" && pass "предупреждение про внешний squad с выключенным JSON" || fail "внешний squad" "$out"
unset -f require_root rw_need_api; eval "$req_saved"
unset -f rw_api; source "$ROOT/lib/remnawave.sh"

section "Обновления"
for p in "0.4.0-beta 0.3.0-beta" "0.3.0 0.3.0-beta" "0.10.0 0.9.9" "2.1.10 2.1.9" "v2.2.0 2.1.9"; do
    read -r a b <<<"$p"; version_gt "$a" "$b" && pass "$a новее $b" || fail "$a новее $b"
done
for p in "0.3.0-beta 0.3.0" "0.3.0 0.3.0" "0.9.9 0.10.0"; do
    read -r a b <<<"$p"; version_gt "$a" "$b" && fail "$a не новее $b" || pass "$a не новее $b"
done
rm -f "$F2D_UPDATE_CACHE"; mkdir -p "$F2D_STATE_DIR"
REMOTE_CALLS=0
f2d_remote_version() { REMOTE_CALLS=$((REMOTE_CALLS + 1)); echo "9.9.9"; }
v=$(f2d_update_available) && [[ "$v" == 9.9.9 ]] && pass "новая версия найдена" || fail "новая версия" "$v"
f2d_remote_version() { echo "SHOULD-NOT-CALL"; }
v=$(f2d_update_available) && [[ "$v" == 9.9.9 ]] && pass "повторная проверка берётся из кэша (без сети)" || fail "кэш проверки" "$v"
f2d_remote_version() { echo "$F2D_VERSION"; }
f2d_update_available --force >/dev/null && fail "своя версия принята за обновление" || pass "своя версия — обновления нет"
f2d_remote_version() { echo ""; }
rm -f "$F2D_UPDATE_CACHE"; f2d_update_available >/dev/null && fail "без сети найдено обновление" || pass "без сети меню не ругается"
UPDATE_CHECK=no; f2d_remote_version() { echo 9.9.9; }
rm -f "$F2D_UPDATE_CACHE"; f2d_update_available >/dev/null && fail "UPDATE_CHECK=no не отключил проверку" || pass "UPDATE_CHECK=no отключает проверку при запуске"
UPDATE_CHECK=yes; unset -f f2d_remote_version; rm -f "$F2D_UPDATE_CACHE"
[[ "$(compose_service_image "$ROOT/tests/fixtures/compose-caddy.yml" remnanode)" == remnawave/node:latest ]] && pass "образ ноды в compose (отступ 4)" || fail "образ ноды (caddy)"
[[ "$(compose_service_image "$ROOT/tests/fixtures/compose-nginx.yml" remnanode)" == remnawave/node ]] && pass "образ ноды в compose (отступ 2)" || fail "образ ноды (nginx)"
# обновление ноды: docker-заглушка, pull приносит новый образ
RWD="$WORK/rwnode"; mkdir -p "$RWD"; printf 'services:\n  remnanode:\n    image: remnawave/node:latest\n' > "$RWD/docker-compose.yml"
DOCKER_LOG="$WORK/docker.log"; : > "$DOCKER_LOG"; IMG="$WORK/img-id"; echo old > "$IMG"
sync_saved=$(declare -f xray_ports_sync)
docker() {
    echo "$*" >> "$DOCKER_LOG"
    case "$1 $2" in
        "compose config") return 1;;
        "compose pull") echo new > "$IMG";;   # pull идёт в подоболочке — состояние в файле
        "image inspect") case "$*" in *Labels*) [[ $(<"$IMG") == old ]] && echo 2.1.0 || echo 2.2.0;; *.Id*) echo "sha256:$(<"$IMG")";; esac;;
        "inspect -f") echo true;;
    esac
    return 0
}
eval 'xray_ports_sync() { echo sync >> "$DOCKER_LOG"; }'   # через eval: shellcheck 0.9 иначе считает вызовы выше «до определения»
out=$(rw_update_one node "$RWD" remnanode remnawave/node 2>&1)
grep -q '2.1.0 → 2.2.0' <<<"$out" && grep -q 'compose up -d' "$DOCKER_LOG" && grep -q sync "$DOCKER_LOG" \
    && pass "нода: pull → перезапуск → фаервол подтянул порты" || fail "обновление ноды" "$out"
: > "$DOCKER_LOG"
out=$(rw_update_one node "$RWD" remnanode remnawave/node 2>&1)
grep -q 'уже последняя' <<<"$out" && ! grep -q 'compose up' "$DOCKER_LOG" && pass "без нового образа контейнер не перезапускается" || fail "лишний перезапуск" "$out"
# закреплённая версия: предлагается переключить на последний релиз
printf 'services:\n  remnanode:\n    image: remnawave/node:2.1.0\n' > "$RWD/docker-compose.yml"
rw_latest_release() { echo 2.2.0; }
rw_unpin_image "$RWD" remnanode remnawave/node:2.1.0 remnawave/node < <(echo y) >/dev/null 2>&1
grep -q 'image: remnawave/node:2.2.0' "$RWD/docker-compose.yml" && pass "закреплённый тег 2.1.0 → 2.2.0" || fail "закреплённый тег" "$(cat "$RWD/docker-compose.yml")"
unset -f docker rw_latest_release; eval "$sync_saved"
# shellcheck source=/dev/null
source "$ROOT/lib/update.sh"

section "Speedtest"
# ширину считаем в символах, как в самом fail2detect (он включает UTF-8 локаль сам)
st_lc_saved="${LC_ALL:-}"; export LC_ALL=C.UTF-8
st=$(printf '%s\n' 10 20 30 40 50 | st_stats)
[[ "$st" == "5 30.00 30.00 20.00 40.00 48.00 10.00 50.00 15.81" ]] && pass "перцентили с интерполяцией, джиттер = ст. отклонение" || fail "st_stats" "$st"
[[ "$(printf '%s\n' 7 | st_stats)" == "1 7.00 7.00 7.00 7.00 7.00 7.00 7.00 0.00" ]] && pass "одно значение" || fail "st_stats n=1"
[[ -z "$(st_stats < /dev/null)" ]] && pass "пустая выборка — пусто" || fail "st_stats пусто"
[[ "$(printf '%s\n' 90 100 110 | st_cv)" == 10.0 ]] && pass "коэффициент вариации" || fail "st_cv"
[[ -z "$(printf '%s\n' 100 100 | st_cv)" ]] && pass "CV не считается по 2 значениям" || fail "st_cv n=2"
m=$(st_mos 20 2 0); awk -v m="$m" 'BEGIN{exit !(m >= 4.0)}' && pass "MOS: 20 мс без потерь ≥ 4 ($m)" || fail "MOS хороший" "$m"
m1=$(st_mos 30 5 0); m2=$(st_mos 30 5 10); awk -v a="$m1" -v b="$m2" 'BEGIN{exit !(b < a)}' && pass "MOS падает с потерями ($m1 → $m2)" || fail "MOS потери"
for p in "0 A+" "5 A+" "29 A" "60 B" "150 C" "399 D" "800 F" "-3 A+"; do
    read -r v g <<<"$p"; [[ "$(st_bloat_grade "$v")" == "$g" ]] || { fail "bufferbloat $v → $g" "$(st_bloat_grade "$v")"; continue; }
done; pass "оценки Bufferbloat по порогам"
for p in "3 A" "10 B" "15 C" "30 D" "40 F"; do read -r v g <<<"$p"; [[ "$(st_stab_grade "$v")" == "$g" ]] || fail "стабильность $v → $g"; done; pass "оценки стабильности по порогам"
[[ "$(st_loss_label 0)" == Отлично && "$(st_loss_label 2.0)" == Приемлемо && "$(st_loss_label 7)" == "Очень плохо" ]] && pass "метки потерь" || fail "метки потерь"
# окна скорости: 1 МБ за [0.5; 1.0] → в окнах 2 и 3 по 0.5 МБ = 16 Мбит/с
printf '100.5 101.0 1000000\n' > "$WORK/ev"
[[ "$(st_series "$WORK/ev" 100 2 102 | tr '\n' ' ')" == "0.00 0.00 16.00 16.00 0.00 0.00 0.00 0.00 " ]] && pass "байты передачи раскладываются по окнам 250 мс" || fail "st_series" "$(st_series "$WORK/ev" 100 2 102 | tr '\n' ' ')"
[[ "$(st_series "$WORK/ev" 100 10 101 | wc -l | tr -d ' ')" == 4 ]] && pass "во время фазы — только прошедшие окна" || fail "st_series текущие окна"
[[ "$(seq 1 40 | st_steady 10 | head -1)" == 9 ]] && pass "разгон: первые 20% фазы (2 с = 8 окон) отброшены" || fail "st_steady" "$(seq 1 40 | st_steady 10 | head -1)"
[[ "$(seq 1 20 | st_steady 4 | head -1)" == 5 ]] && pass "разгон не короче 1 с" || fail "st_steady 1 с"
widths_ok() { local l; while IFS= read -r l; do [[ ${#l} == "$1" ]] || return 1; done; }   # ширина в символах
max_width() { local l m=0; while IFS= read -r l; do ((${#l} > m)) && m=${#l}; done; echo "$m"; }
# рисование: строки ровно нужной ширины, UTF-8 не режется (mawk/BSD awk)
out=$(printf '%s\n' 10 50 100 30 | st_chart 20 5 100 "" | sed 's/\x1b\[[0-9;]*m//g')
(( $(wc -l <<<"$out") == 5 )) && ! grep -q $'\xef\xbf\xbd' <<<"$out" && widths_ok 20 <<<"$out" \
    && pass "график: 5 строк по 20 символов" || fail "st_chart" "$out"
grep -q '█' <<<"$out" && pass "график рисует блоки" || fail "st_chart блоки"
out=$(st_strip 30 10 20 25 30 40 "0 50" "" | sed 's/\x1b\[[0-9;]*m//g')
[[ ${#out} == 30 && "$out" == *├*▓*┃*▓*┤* ]] && pass "полоса задержки: ├─▓┃▓─┤ шириной 30" || fail "st_strip" "$out"
err=$(_st_lat_box 40 "$WORK/нет-такого.lat" "◷ При отдаче" "" "0 100" 2>&1 >/dev/null)
[[ -z "$err" ]] && pass "панель задержки до начала фазы: без ошибок на экран" || fail "_st_lat_box без файла" "$err"
[[ "$(_st_chunk 1000 down)" == 262144 && "$(_st_chunk 50000000 down)" == 33554432 && "$(_st_chunk 1e9 down)" == 67108864 \
   && "$(_st_chunk 1e9 up)" == 16777216 ]] && pass "размер запроса: ≈0.6 с потока, степень двойки, пределы" \
   || fail "_st_chunk" "$(_st_chunk 1000 down) $(_st_chunk 50000000 down) $(_st_chunk 1e9 down) $(_st_chunk 1e9 up)"
box=$(_st_box 30 "" "Заголовок" "строка" | sed 's/\x1b\[[0-9;]*m//g')
widths_ok 30 <<<"$box" && pass "рамка ровно 30 символов" || fail "_st_box" "$box"
# итог из сохранённых замеров
ST_T="$WORK/st"; mkdir -p "$ST_T"
printf '%s\n' 20 21 22 20 23 > "$ST_T/idle.lat"; printf '%s\n' 40 42 45 41 > "$ST_T/down.lat"; printf '%s\n' 30 31 29 > "$ST_T/up.lat"
echo 1000 > "$ST_T/down.t0"; echo 2000 > "$ST_T/up.t0"
: > "$ST_T/down.ev"; : > "$ST_T/up.ev"
for i in $(seq 0 39); do awk -v i="$i" 'BEGIN{printf "%.2f %.2f 3125000\n", 1000 + i * 0.25, 1000 + (i + 1) * 0.25}' >> "$ST_T/down.ev"
    awk -v i="$i" 'BEGIN{printf "%.2f %.2f 1562500\n", 2000 + i * 0.25, 2000 + (i + 1) * 0.25}' >> "$ST_T/up.ev"; done
{ for i in $(seq 1 49); do echo "ok 15"; done; echo lost; } > "$ST_T/udp"
echo '{"ip":"203.0.113.5","asn":64500,"org":"Test","colo":"FRA","colo_city":"Frankfurt"}' > "$ST_T/meta.json"
printf 'family=IPv4\niface=eth0\ndns=1.2\ntls_ms=30\ntls=TLSv1.3\n' > "$ST_T/net"
r=$(EPOCHREALTIME=3000.0 st_result_json 10 10)
jq -e '.download.med == 100 and .upload.med == 50 and .idle_latency.med == 21 and .bufferbloat_ms == 20.5
    and .udp.loss == 2 and .udp.recv == 49 and .udp.label == "Приемлемо" and .cv_worst == 0 and .net.iface == "eth0"' >/dev/null <<<"$r" \
    && pass "итог: 100/50 Мбит/с, bufferbloat +20.5 мс, потери 2%" || fail "st_result_json" "$r"
echo "$r" > "$ST_T/result.json"
out=$(COLUMNS=120 st_render 10 10 yes | sed 's/\x1b\[[0-9;]*m//g')
grep -q 'Bufferbloat   A ' <<<"$out" && grep -q 'Приемлемо' <<<"$out" && pass "итоговый экран: оценки и потери" || fail "st_render" "$out"
(( $(tail -n +3 <<<"$out" | max_width) <= 120 )) && pass "итоговый экран не шире 120 колонок" || fail "ширина экрана" "$(tail -n +3 <<<"$out" | max_width)"
out=$(COLUMNS=80 st_render 10 10 yes | sed 's/\x1b\[[0-9;]*m//g')
(( $(tail -n +3 <<<"$out" | max_width) <= 80 )) && pass "узкий терминал (80): панели друг под другом" || fail "ширина 80" "$(tail -n +3 <<<"$out" | max_width)"
# движок на Rust: аргументы, переключатель автосохранения → конфиг, запасной bash
cat > "$WORK/f2d-speed" <<'STUB'
#!/usr/bin/env bash
echo "$*" > "${0%/*}/speed.args"
while [[ $# -gt 0 ]]; do [[ "$1" == --state-out ]] && echo SPEEDTEST_SAVE=no > "$2"; shift; done
STUB
chmod +x "$WORK/f2d-speed"
# тесты идут от root (контейнер) — config_set вызывается
( st_cfg=""; config_set() { st_cfg="$1=$2"; }
  F2D_SPEED_BIN="$WORK/f2d-speed" SPEEDTEST_SAVE=yes speedtest_run --quick >/dev/null 2>&1; echo "$st_cfg" > "$WORK/speed.cfg" ) 2>/dev/null
grep -q -- "--history-dir $ST_HISTORY_DIR --f2d-version $F2D_VERSION --state-out .* --quick" "$WORK/speed.args" \
    && pass "f2d speed запускает f2d-speed с историей, версией и --quick" || fail "аргументы f2d-speed" "$(cat "$WORK/speed.args")"
[[ "$(cat "$WORK/speed.cfg")" == "SPEEDTEST_SAVE=no" ]] && pass "A в дашборде Rust сохраняется в конфиг" || fail "автосохранение → конфиг" "$(cat "$WORK/speed.cfg")"
# релиза нет (curl падает) — пусто, отметка «не пробовать сутки», запасной bash
mkdir -p "$WORK/st-state"
( curl() { return 22; }; uname() { [[ "$1" == -s ]] && echo Linux || echo x86_64; }
  F2D_STATE_DIR="$WORK/st-state" speedtest_bin >/dev/null 2>&1 && echo found || echo none ) > "$WORK/speed.bin"
[[ "$(cat "$WORK/speed.bin")" == none && -f "$WORK/st-state/bin/.miss-$F2D_VERSION" ]] \
    && pass "без релиза f2d-speed — bash-версия, повтор загрузки не раньше чем через сутки" || fail "speedtest_bin без релиза" "$(ls -a "$WORK/st-state/bin" 2>&1)"
if [[ -n "$st_lc_saved" ]]; then export LC_ALL="$st_lc_saved"; else unset LC_ALL; fi

section "Бенчмарк сети"
st_lc_saved="${LC_ALL:-}"; export LC_ALL=C.UTF-8
iputils=$'PING st.spb.ertelecom.ru (1.2.3.4) 56(84) bytes of data.\n\n--- st.spb.ertelecom.ru ping statistics ---\n5 packets transmitted, 4 received, 20% packet loss, time 804ms\nrtt min/avg/max/mdev = 46.512/47.031/47.990/0.512 ms'
busybox=$'--- 1.2.3.4 ping statistics ---\n5 packets transmitted, 5 packets received, 0% packet loss\nround-trip min/avg/max = 10.1/12.5/15.0 ms'
[[ "$(bench_parse_ping <<<"$iputils")" == "47.031 20" ]] && pass "ping (iputils): среднее и потери" || fail "ping iputils" "$(bench_parse_ping <<<"$iputils")"
[[ "$(bench_parse_ping <<<"$busybox")" == "12.5 0" ]] && pass "ping (busybox)" || fail "ping busybox" "$(bench_parse_ping <<<"$busybox")"
[[ "$(bench_parse_ping <<<$'5 packets transmitted, 0 received, 100% packet loss')" == "- 100" ]] && pass "ping без ответа — 100% потерь" || fail "ping 100%"
[[ "$(bench_parse_iperf <<<'{"end":{"sum_sent":{"bits_per_second":9.1e8},"sum_received":{"bits_per_second":912345678}}}')" == 912.35 ]] \
    && pass "iperf3 JSON: скорость принимающей стороны" || fail "iperf3 JSON"
[[ "$(bench_parse_iperf <<<'{"error":"the server is busy running a test. try again later"}')" == "ERR the server is busy running a test. try again later" ]] \
    && pass "iperf3 JSON: ошибка" || fail "iperf3 ошибка"
[[ "$(_bench_err_ru "ERR the server is busy running a test")" == "сервер занят" && "$(_bench_err_ru "ERR unable to connect to server: Connection refused")" == недоступен ]] \
    && pass "ошибки iperf3 по-русски" || fail "ошибки iperf3"
r=$(bench_parse_ookla <<<'{"type":"log"}
{"type":"result","ping":{"latency":71.234},"download":{"bandwidth":62500000},"upload":{"bandwidth":12500000},"server":{"name":"Leaseweb","location":"Amsterdam"}}')
[[ "$r" == $'71.2\x1f500\x1f100\x1fAmsterdam · Leaseweb' ]] && pass "Ookla JSON: пинг, ↓500 ↑100 Мбит/с, сервер" || fail "Ookla JSON" "$r"
bars() { bench_bar "$1" "" | sed 's/\x1b\[[0-9;]*m//g' | tr -cd '▰' | wc -m | tr -d ' '; }
[[ "$(bars 1)" == 1 && "$(bars 100)" == 6 && "$(bars 10000)" == 12 && "$(bars 0)" == 0 ]] && pass "шкала логарифмическая: 1→1, 100→6, 10000→12 делений" || fail "bench_bar" "$(bars 1) $(bars 100) $(bars 10000)"
# занятый сервер: повтор на соседнем порту
IPERF_LOG="$WORK/iperf.log"; : > "$IPERF_LOG"
iperf3() {
    [[ "$1" == --help ]] && { echo "--connect-timeout"; return; }
    local port=""; while (($#)); do [[ "$1" == -p ]] && port="$2"; shift; done
    echo "$port" >> "$IPERF_LOG"
    if [[ "$port" == 5201 ]]; then echo '{"error":"the server is busy running a test. try again later"}'
    else echo '{"end":{"sum_received":{"bits_per_second":500000000}}}'; fi
}
timeout() { shift; "$@"; }
BENCH_THREADS=8; BENCH_DUR=1
[[ "$(bench_iperf host 5201 yes)" == 500 && "$(tr '\n' ' ' < "$IPERF_LOG")" == "5201 5202 " ]] && pass "сервер занят → следующий порт" || fail "повтор iperf3" "$(cat "$IPERF_LOG")"
# полный прогон: один сервер отвечает, второй недоступен
ping() { local h="${*: -1}"; [[ "$h" == bad.example ]] && { echo "5 packets transmitted, 0 received, 100% packet loss"; return 1; }
    printf '5 packets transmitted, 5 received, 0%% packet loss\nrtt min/avg/max/mdev = 9/10.0/11/1 ms\n'; }
curl() { case "$*" in *telnet://bad.example*) echo 0;; *speed.cloudflare.com/meta*) echo '{"clientIp":"203.0.113.9","asn":64500,"asOrganization":"Test","country":"NL"}';; *) command curl "$@";; esac; }
BENCH_RU=('good.example:5203:Москва:Тест' 'bad.example:5201:Казань:Тест')
out=$(bench_run ru --json 2>/dev/null)
jq -e 'length == 2 and .[0].download == 500 and .[0].upload == 500 and .[0].ping == 10 and .[1].error == "недоступен" and .[1].download == null' >/dev/null <<<"$out" \
    && pass "bench ru --json: результаты и недоступный сервер" || fail "bench --json" "$out"
out=$(bench_run ru --ping 2>/dev/null | sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g' | tr '\r' '\n')
grep -q 'Москва.*10.0 мс' <<<"$out" && grep -q 'Казань.*недоступен' <<<"$out" && grep -q 'ответили 1/2' <<<"$out" && ! grep -q '↓ —' <<<"$out" \
    && pass "bench --ping: строки, итог без пустых ↓/↑" || fail "bench --ping" "$out"
unset -f iperf3 timeout ping curl bars
# shellcheck source=/dev/null
source "$ROOT/lib/bench.sh"
if [[ -n "$st_lc_saved" ]]; then export LC_ALL="$st_lc_saved"; else unset LC_ALL; fi

section "CensorCheck"
st_lc_saved="${LC_ALL:-}"; export LC_ALL=C.UTF-8
cc_bogus_ip 127.0.0.1 && cc_bogus_ip 10.10.1.1 && cc_bogus_ip 0.0.0.0 && ! cc_bogus_ip 8.8.8.8 && pass "служебные адреса DNS-заглушек" || fail "cc_bogus_ip"
for p in "131072 206 0 ok" "16384 206 28 cut" "0 206 28 stall" "0 000 28 tls" "0 000 7 conn" "60000 206 28 slow" "262144 200 0 ok"; do
    read -r b c x want <<<"$p"; [[ "$(cc_16k_verdict "$b" "$c" "$x")" == "$want" ]] || fail "16 КБ: $p" "$(cc_16k_verdict "$b" "$c" "$x")"
done; pass "16 КБ: без обрыва / обрыв ~16 КБ / данные не идут / TLS / нет соединения"
[[ "$(_cc_http_cell '{"code":302,"redirect":"http://warning.rt.ru/?id=1","exit":0}')" == "302 → стоп-стр." ]] && pass "HTTP → стоп-страница провайдера" || fail "стоп-страница"
[[ "$(_cc_http_cell '{"code":0,"redirect":null,"exit":28}')" == таймаут && "$(_cc_http_cell '{"code":0,"redirect":null,"exit":56}')" == сброс ]] && pass "таймаут и сброс" || fail "таймаут/сброс"
# классификация сайта: заглушки сети
CC_NET=""
cc_resolve_sys() { case "$1" in spoof.example) echo 10.0.0.1;; dead.example) echo 203.0.113.66;; *) echo 203.0.113.10;; esac; }
cc_resolve_doh() { case "$1" in dead.example) echo 203.0.113.77;; *) echo 203.0.113.10;; esac; }
cc_tcp() { [[ "$1" == 203.0.113.66 ]] && return 1; [[ "$CC_NET" == ipblock ]] && return 1; return 0; }
cc_req() { case "$CC_NET" in
    ok) [[ "$1" == http://* ]] && echo "302|http://warning.rt.ru/|0" || echo "200||0";;
    sni|tls) [[ "$1" == http://* ]] && echo "200||0" || echo "000||28";;
    451) echo "451||0";; esac; }
cc_nosni() { [[ "$CC_NET" == sni ]]; }
v() { cc_check_site "$1" | jq -r '.verdict + " " + .dns'; }
CC_NET=ok;  [[ "$(v site.example)" == "stub_http ok" ]] && pass "HTTPS работает, HTTP → стоп-страница" || fail "stub_http" "$(v site.example)"
CC_NET=sni; [[ "$(v site.example)" == "sni ok" ]] && pass "TLS с SNI обрывается, без SNI проходит → DPI по SNI" || fail "sni" "$(v site.example)"
CC_NET=tls; [[ "$(v site.example)" == "tls ok" ]] && pass "TLS обрывается и без SNI" || fail "tls" "$(v site.example)"
CC_NET=451; [[ "$(v site.example)" == "451 ok" ]] && pass "ответ 451" || fail "451"
CC_NET=ipblock; [[ "$(v site.example)" == "ip ok" ]] && pass "порты 80 и 443 закрыты → блок по IP" || fail "ip" "$(v site.example)"
CC_NET=ok;  [[ "$(v spoof.example)" == "stub_http spoofed" ]] && pass "DNS отдал частный адрес → подмена, проверка по IP из DoH" || fail "spoof" "$(v spoof.example)"
CC_NET=ok;  [[ "$(v dead.example)" == "stub_http spoofed" ]] && pass "системный IP мёртв, IP из DoH живой → подмена" || fail "dead→doh" "$(v dead.example)"
unset -f cc_resolve_sys cc_resolve_doh cc_tcp cc_req cc_nosni v
# shellcheck source=/dev/null
source "$ROOT/lib/censorcheck.sh"
if [[ -n "$st_lc_saved" ]]; then export LC_ALL="$st_lc_saved"; else unset LC_ALL; fi

section "Сайт-маскировка"
SR="$WORK/siteroot"
site_generate "$SR" >/dev/null
[[ -f "$SR/index.html" && -f "$SR/about/index.html" && -f "$SR/services/index.html" && -f "$SR/contact/index.html" && -f "$SR/404.html" \
   && -f "$SR/robots.txt" && -f "$SR/sitemap.xml" && -f "$SR/favicon.svg" && -f "$SR/assets/site.css" ]] && pass "сайт: 4 страницы, 404, robots, sitemap, favicon, стили" || fail "состав сайта" "$(cd "$SR" && find . -type f | sort | tr '\n' ' ')"
grep -q 'f2d-site v2' "$SR/index.html" && grep -q 'href="/services/"' "$SR/index.html" && ! grep -q 'on its way' "$SR/index.html" && pass "главная со ссылками, без «скоро будет»" || fail "главная"
echo '<html>my own site</html>' > "$SR/index.html"; site_generate "$SR"
grep -q 'my own site' "$SR/index.html" && pass "свой сайт пользователя не перезаписывается" || fail "свой сайт затёрт"
echo '<p>Our new website is on its way.</p>' > "$SR/index.html"; site_generate "$SR"
grep -q 'f2d-site v2' "$SR/index.html" && pass "старая одностраничная заглушка заменяется новым сайтом" || fail "замена старой заглушки"
a=$(grep -o '<title>[^<]*' "$SR/index.html"); site_generate "$SR" --force; b=$(grep -o '<title>[^<]*' "$SR/index.html")
[[ -n "$b" ]] && pass "regen: новый сайт ($b)" || fail "regen"
# конфиг nginx
F2D_WEB_ENV="$WORK/web.env"; : > "$F2D_WEB_ENV"; web_set SELFSTEAL_DOMAIN node.example.com; web_set WEB_HTTP yes
cert_dir() { echo "/etc/letsencrypt/live/$1"; }
conf=$(web_render)
# shellcheck disable=SC2016  # ищем буквальные $uri/$host из конфига nginx
grep -q 'try_files $uri $uri/ =404;' <<<"$conf" && grep -q 'error_page 404 /404.html;' <<<"$conf" && pass "nginx: настоящий 404 вместо index на любой адрес" || fail "404 в конфиге"
# shellcheck disable=SC2016
grep -q 'listen 80;' <<<"$conf" && grep -q 'acme-challenge' <<<"$conf" && grep -q 'return 301 https://$host$request_uri;' <<<"$conf" && pass "nginx: HTTP 80 — ACME и переход на HTTPS" || fail "HTTP 80 в конфиге"
web_set WEB_HTTP ""; grep -q 'listen 80' <<<"$(web_render)" && fail "HTTP 80 без WEB_HTTP" || pass "без WEB_HTTP порт 80 не слушается"
unset -f cert_dir; source "$ROOT/lib/certs.sh"

section "Резервные копии панели"
BR="$WORK/bkroot"; mkdir -p "$BR/opt/remnawave" "$BR/opt/subscription" "$BR/etc/fail2detect/jail.d" "$BR/etc/letsencrypt/live/p.example"
printf 'PANEL_DOMAIN=p.example\nSUB_PUBLIC_DOMAIN=s.example\nPOSTGRES_USER=rwuser\nAPP_SECRET=abc\n' > "$BR/opt/remnawave/.env"
echo 'services: {}' > "$BR/opt/remnawave/docker-compose.yml"
echo 'APP_PORT=3010' > "$BR/opt/subscription/.env"
printf 'RW_API_TOKEN="tok123"\nTG_BOT_TOKEN="bot1"\nSSH_PORTS="2222"\nPANEL_IPS="1.1.1.1"\n' > "$BR/etc/fail2detect/fail2detect.conf"
echo 'PANEL_DOMAIN="p.example"' > "$BR/etc/fail2detect/web.env"
echo cert > "$BR/etc/letsencrypt/live/p.example/fullchain.pem"
DOCKER_LOG="$WORK/docker-bk.log"; : > "$DOCKER_LOG"
docker() {
    echo "$*" >> "$DOCKER_LOG"
    case "$1" in
        ps) echo remnawave-db;;
        exec) case "$*" in
                *pg_dumpall*) printf -- '--\n-- PostgreSQL database cluster dump\n--\nCREATE TABLE users (id int);\n';;
                *"count(*) from users"*) echo 42;; *"count(*) from nodes"*) echo 3;; *"count(*) from hosts"*) echo 7;; *) return 1;;
              esac;;
        inspect) echo remnawave/backend:2;;
    esac
}
curl() { return 1; }
require_root() { :; }
F2D_BACKUP_ROOT="$BR"; F2D_BACKUP_PATHS="/opt/remnawave /opt/subscription /opt/remnanode /etc/fail2detect"; BKOUT="$WORK/bkout"
backup_create --out "$BKOUT" --no-password --quiet
f="$BACKUP_LAST"
[[ -f "$f" && "$f" == */panel-*.tar ]] && pass "копия создана: $(basename "$f")" || fail "backup_create" "$f"
grep -q 'pg_dumpall -U rwuser --clean --if-exists' "$DOCKER_LOG" && pass "дамп от пользователя БД из .env панели" || fail "пользователь БД" "$(cat "$DOCKER_LOG")"
[[ "$(tar -tf "$f" | sort | tr '\n' ' ')" == "db.sql.gz files.tar.gz manifest.json " ]] && pass "состав: manifest, db.sql.gz, files.tar.gz" || fail "состав копии" "$(tar -tf "$f")"
m=$(tar -xOf "$f" manifest.json)
jq -e '.format == 1 and .panel_domain == "p.example" and .sub_domain == "s.example" and .counts == "users=42 nodes=3 hosts=7"
    and .paths == ["/opt/remnawave", "/opt/subscription", "/etc/fail2detect", "/etc/letsencrypt"]' >/dev/null <<<"$m" \
    && pass "опись: домены, число пользователей/нод/хостов, пути (без отсутствующих)" || fail "manifest" "$m"
tar -xOf "$f" files.tar.gz | tar -tz | grep -q '^opt/remnawave/.env$' && pass "в копии .env панели (секреты)" || fail ".env в копии"
# большая база: начало дампа читается без ложного «пустой» (SIGPIPE при pipefail, как в fail2detect)
# (заглушки — вне $( … ): bash 5.1 не разбирает case внутри подстановки)
_big_docker() {
    case "$1" in
        ps) echo remnawave-db;;
        exec) printf -- '--\n-- PostgreSQL database cluster dump\n--\n'
              awk 'BEGIN { for (i = 0; i < 200000; i++) print "INSERT INTO users VALUES (" i ", 0123456789abcdef0123456789abcdef);" }';;
    esac
}
_bad_docker() {
    case "$1" in
        ps) echo remnawave-db;;
        exec) echo 'pg_dumpall: error: connection failed' >&2; return 1;;
    esac
}
big=$(set -o pipefail; docker() { _big_docker "$@"; }; bk_dump_db "$WORK/big.sql.gz" 2>&1 && echo OK)
[[ "$big" == *OK* ]] && pass "дамп большой базы (≈10 МБ SQL) с pipefail — принят" || fail "большой дамп" "$big"
err_out=$(docker() { _bad_docker "$@"; }; bk_dump_db "$WORK/bad.sql.gz" 2>&1)
[[ "$err_out" == *"connection failed"* ]] && pass "ошибка pg_dumpall показывается" || fail "текст ошибки pg_dumpall" "$err_out"
# шифрование
backup_create --out "$BKOUT" --password 'Secret-pass-1' --quiet; fe="$BACKUP_LAST"
[[ "$fe" == *.tar.enc ]] && ! tar -tf "$fe" >/dev/null 2>&1 && pass "с паролем — .tar.enc, без пароля не читается" || fail "шифрование"
ST="$WORK/unp"; mkdir -p "$ST"; F2D_BACKUP_PASS='Secret-pass-1' _bk_unpack "$fe" "$ST" && [[ -s "$ST/db.sql.gz" ]] && pass "расшифровка верным паролем" || fail "расшифровка"
rm -rf "$ST"; mkdir -p "$ST"; F2D_BACKUP_PASS='wrong-password' _bk_unpack "$fe" "$ST" 2>/dev/null && fail "неверный пароль принят" || pass "неверный пароль — отказ"
# чистка
F2D_BACKUP_DIR="$WORK/prune"; mkdir -p "$F2D_BACKUP_DIR"
for d in 20260101 20260102 20260103 20260104; do touch "$F2D_BACKUP_DIR/panel-h-$d-000000.tar"; done
backup_prune 2
left=$(cd "$F2D_BACKUP_DIR" && printf '%s ' panel-*)
[[ "$left" == "panel-h-20260103-000000.tar panel-h-20260104-000000.tar " ]] && pass "оставлены 2 последние копии" || fail "backup_prune" "$left"
# перенос настроек fail2detect: панельные ключи — да, фаервол/SSH — нет
SAVED_CONF_DIR="$F2D_CONF_DIR"; F2D_CONF_DIR="$WORK/newetc"; F2D_CONF="$F2D_CONF_DIR/fail2detect.conf"; mkdir -p "$F2D_CONF_DIR"
printf 'SSH_PORTS="22"\n' > "$F2D_CONF"
_bk_restore_conf "$BR/etc/fail2detect"
grep -q '^RW_API_TOKEN="tok123"' "$F2D_CONF" && grep -q '^TG_BOT_TOKEN="bot1"' "$F2D_CONF" && grep -q '^SSH_PORTS="22"' "$F2D_CONF" && ! grep -q PANEL_IPS "$F2D_CONF" && [[ -f "$F2D_CONF_DIR/web.env" ]] \
    && pass "настройки: токены и web.env перенесены, SSH и фаервол нового сервера не тронуты" || fail "_bk_restore_conf" "$(cat "$F2D_CONF")"
F2D_CONF_DIR="$SAVED_CONF_DIR"; F2D_CONF="$F2D_CONF_DIR/fail2detect.conf"; load_config
# нода: новый IP панели
UFW_LOG="$WORK/ufw.log"; : > "$UFW_LOG"
ufw_active() { true; }; ufw() { echo "ufw $*" >> "$UFW_LOG"; }; fw_apply() { :; }; has_node() { true; }
PANEL_IPS="1.1.1.1 9.9.9.9"; NODE_API_PORT=2222
node_panel_ip 5.5.5.5 --replace 1.1.1.1 >/dev/null
[[ "$PANEL_IPS" == "9.9.9.9 5.5.5.5" ]] && grep -q 'delete allow proto tcp from 1.1.1.1 to any port 2222' "$UFW_LOG" && grep -q 'allow proto tcp from 5.5.5.5 to any port 2222' "$UFW_LOG" \
    && pass "нода: IP панели заменён, правило UFW к API ноды обновлено" || fail "node_panel_ip" "$PANEL_IPS | $(cat "$UFW_LOG")"
node_panel_ip 6.6.6.6 >/dev/null; [[ "$PANEL_IPS" == 6.6.6.6 ]] && pass "без --replace — только новый IP" || fail "node_panel_ip замена всех"
config_set PANEL_IPS "198.51.100.200 2001:db8:abcd::1" >/dev/null
unset -f docker curl require_root ufw_active ufw fw_apply has_node
unset F2D_BACKUP_ROOT F2D_BACKUP_PATHS
F2D_BACKUP_DIR="${F2D_STATE_DIR}/backup"
# shellcheck source=/dev/null
for m in firewall detect; do source "$ROOT/lib/$m.sh"; done
eval "$stubs_save" 2>/dev/null; has_node()  { [[ "$STUB_NODE" == yes ]]; }; fw_mode() { echo "$STUB_MODE"; }; ufw_active() { false; }; wan_iface() { echo eth0; }
detect_ssh_ports() { echo 2233; }; detect_xray_ports() { echo 443; }; detect_node_api_port() { echo 2222; }; detect_panel_ips() { echo "198.51.100.200 2001:db8:abcd::1"; }
has_panel() { [[ "$STUB_PANEL" == yes ]]; }; has_sub_page() { false; }

section "Российский трафик на ноде"
[[ "$(ru_rules_json off no)" == "[]" ]] && pass "off — без правил" || fail "off"
r=$(ru_rules_json block no)
jq -e 'length == 2 and all(.outboundTag == "BLOCK") and (.[0].domain | index("geosite:category-ru") and index("domain:ru") and index("domain:xn--p1ai") and index("domain:yandex.net"))
    and .[1].ip == ["geoip:ru"]' >/dev/null <<<"$r" && pass "block: зоны .ru/.su/.рф, сервисы, geosite/geoip" || fail "block" "$r"
[[ "$(ru_rules_json direct no | jq -r '.[0].outboundTag')" == DIRECT ]] && pass "direct → DIRECT" || fail "direct"
printf '5.1.1.0/24\n2a00:1::/32\n' > "$WORK/pfx"
[[ "$(ru_rules_json block yes "$WORK/pfx" | jq -c '.[1].ip')" == '["geoip:ru","5.1.1.0/24","2a00:1::/32"]' ]] && pass "сети RIPE добавляются к geoip:ru" || fail "ripe в правилах"
base=$(NODE_RU_POLICY=off profile_config '{"tag":"x","port":1,"protocol":"vless"}')
c1=$(ru_apply_to_config "$base" "$r")
jq -e '.routing.rules[0].ip == ["geoip:private"] and .routing.rules[1].ruleTag == "f2d-ru-domains" and .routing.rules[2].ruleTag == "f2d-ru-ip"
    and .routing.rules[3].protocol == ["bittorrent"]' >/dev/null <<<"$c1" && pass "правила — сразу после блокировки частных сетей" || fail "порядок правил" "$(jq -c .routing.rules <<<"$c1")"
c2=$(ru_apply_to_config "$c1" "$(ru_rules_json direct no)")
[[ "$(jq '[.routing.rules[] | select(.ruleTag // "" | startswith("f2d-ru-"))] | length' <<<"$c2")" == 2 && "$(ru_policy_of "$c2")" == direct ]] \
    && pass "повторное применение заменяет, а не дублирует" || fail "дубли правил"
c3=$(ru_apply_to_config "$c2" '[]'); [[ "$(ru_policy_of "$c3")" == off && "$(jq '.routing.rules | length' <<<"$c3")" == 2 ]] && pass "off убирает только свои правила" || fail "off убирает"
big=$(seq 1 150 | awk '{print "10." $1 ".0.0/16"}' > "$WORK/pfx150"; ru_rules_json block yes "$WORK/pfx150")
[[ "$(ru_policy_of "$(ru_apply_to_config "$base" "$big")")" == "block ripe" ]] && pass "политика определяется (block + сети RIPE)" || fail "ru_policy_of ripe"
# чужой профиль без outbounds DIRECT/BLOCK — их добавим
c4=$(ru_apply_to_config '{"outbounds":[{"tag":"warp","protocol":"wireguard"}],"routing":{"rules":[]}}' "$r")
[[ "$(jq -c '[.outbounds[].tag]' <<<"$c4")" == '["warp","DIRECT","BLOCK"]' ]] && pass "в чужом профиле добавляются outbound'ы DIRECT/BLOCK" || fail "outbounds" "$(jq -c .outbounds <<<"$c4")"
[[ "$(printf '10.0.0.0/25\n10.0.0.128/25\n10.0.1.0/24\n10.0.0.0/24\n192.168.1.0/24\n192.168.3.0/24\n' | ru_aggregate_v4 | tr '\n' ' ')" == "10.0.0.0/23 192.168.1.0/24 192.168.3.0/24 " ]] \
    && pass "склейка IPv4: соседние и вложенные префиксы" || fail "ru_aggregate_v4"
# настоящий объём (как у RIPE: ~11 тыс. сетей, правило > 128 КБ): Linux не пропускает
# такой аргумент команды — всё должно идти через stdin/файлы
seq 0 11999 | awk '{print int($1/256) + 1 "." ($1 % 256) ".0.0/16"}' > "$WORK/pfx-big"
big=$(ru_rules_json direct yes "$WORK/pfx-big" 2>&1)
[[ "$(jq '.[1].ip | length' <<<"$big" 2>/dev/null)" == 12001 && ${#big} -gt 140000 ]] && pass "правила на 12 тыс. сетей ($(( ${#big} / 1024 )) КБ) собираются" || fail "большие правила" "${big:0:300}"
bigcfg=$(ru_apply_to_config "$base" "$big" 2>&1)
[[ "$(ru_policy_of "$bigcfg")" == "direct ripe" ]] && pass "большие правила встают в профиль" || fail "большие правила в профиль" "${bigcfg:0:300}"
body=$(rw_profile_body 11111111-2222-4333-8444-555555555555 <<<"$bigcfg" 2>&1)
jq -e '.uuid and (.config.routing.rules | length) > 3' >/dev/null 2>&1 <<<"$body" && pass "тело PATCH профиля с большими правилами" || fail "rw_profile_body" "${body:0:300}"
unset big bigcfg body
# профиль при установке: выбор block + RIPE (RIPE — заглушка)
curl() { jq -nc '{data: {resources: {ipv4: ([range(0; 1200)] | map("5.\(. / 256 | floor).\(. % 256).0/24")), ipv6: ["2a00:1::/32"]}}}'; }
RU_RIPE_CACHE="$WORK/ru-cache.txt"
p=$(NODE_RU_POLICY=block NODE_RU_RIPE=yes profile_config '{"tag":"x","port":1,"protocol":"vless"}')
jq -e '.routing.rules[1].outboundTag == "BLOCK" and (.routing.rules[2].ip | length) < 1200 and (.routing.rules[2].ip | index("2a00:1::/32"))' >/dev/null <<<"$p" \
    && pass "новый профиль: блок РФ + сети RIPE (склеены: $(jq '.routing.rules[2].ip | length' <<<"$p") из 1201)" || fail "profile_config с RU" "$(jq -c '.routing.rules[2].ip[:3]' <<<"$p")"
[[ -s "$RU_RIPE_CACHE" ]] && pass "список RIPE сохранён в кэш (на случай недоступности RIPE)" || fail "кэш RIPE"
curl() { return 22; }
[[ "$(ru_ripe_prefixes 2>/dev/null | wc -l | tr -d ' ')" -gt 0 ]] && pass "RIPE недоступен — берётся кэш" || fail "fallback на кэш"
unset -f curl

section "Где панель и нода"
DT="$WORK/detect"; mkdir -p "$DT/opt/remnawave" "$DT/root/rw" "$DT/opt/remnanode" "$DT/empty"
det() {   # «как видит сервер»: настоящие has_*/rw_locate из detect.sh, docker — заглушка с контейнерами из $CT
    ( source "$ROOT/lib/detect.sh"
      docker() { [[ "$1" == ps ]] && printf '%b' "${CT:-}"; }
      _RW_CT_DONE=""; RW_PANEL_DIR="$DT/opt/remnawave"; RW_NODE_DIR="$DT/opt/remnanode"; RW_SUB_DIR="$DT/empty"
      rw_locate; echo "$(server_role)|${RW_PANEL_DIR#"$DT"}|${RW_NODE_DIR#"$DT"}" )
}
printf 'services:\n  remnawave:\n    image: remnawave/backend:2\n' > "$DT/opt/remnawave/compose.yaml"
[[ "$(det)" == "панель|/opt/remnawave|/opt/remnanode" ]] && pass "compose.yaml (не docker-compose.yml)" || fail "compose.yaml" "$(det)"
rm "$DT/opt/remnawave/compose.yaml"; printf 'services:\n  backend:\n    image: "remnawave/backend:latest"\n' > "$DT/opt/remnawave/docker-compose.yml"
[[ "$(det)" == "панель|/opt/remnawave|/opt/remnanode" ]] && pass "сервис переименован — панель найдена по образу" || fail "по образу" "$(det)"
rm "$DT/opt/remnawave/docker-compose.yml"
printf 'services:\n  remnawave:\n    image: remnawave/backend:2\n  remnanode:\n    image: remnawave/node:latest\n' > "$DT/root/rw/docker-compose.yml"
CT="remnawave\tremnawave/backend:2\t$DT/root/rw\trunning\nremnanode\tremnawave/node:latest\t$DT/root/rw\trunning\n"
[[ "$(det)" == "панель+нода|/root/rw|/opt/remnanode" ]] && pass "панель не в /opt/remnawave — каталог найден по контейнеру" || fail "rw_locate" "$(det)"
CT=""; cp "$ROOT/tests/fixtures/compose-caddy.yml" "$DT/opt/remnanode/docker-compose.yml"
[[ "$(det)" == "нода|/opt/remnawave|/opt/remnanode" ]] && pass "нода из compose стороннего установщика" || fail "нода eGames" "$(det)"
rm "$DT/opt/remnanode/docker-compose.yml"; CT="remnawave\tremnawave/backend:2\t\texited\n"
[[ "$(det)" == "панель|/opt/remnawave|/opt/remnanode" ]] && pass "только контейнер (compose не найден) — панель всё равно видна" || fail "контейнер без compose" "$(det)"
CT=""; [[ "$(det)" == "не найдено|/opt/remnawave|/opt/remnanode" ]] && pass "пустой сервер — «не найдено»" || fail "пустой" "$(det)"
printf 'services:\n  nginx:\n    image: nginx\n' > "$DT/opt/remnawave/docker-compose.yml"
[[ "$(det)" == "не найдено|/opt/remnawave|/opt/remnanode" ]] && pass "чужой compose в каталоге — не панель" || fail "чужой compose" "$(det)"
unset CT

section "API панели: локальный адрес и повторы"
CURL_LOG="$WORK/curl-api.log"
_api_curl() {   # заглушка curl: коды ответа по очереди из $CURL_RC (файл), URL — в лог
    local a url="" ; for a in "$@"; do [[ "$a" == http* ]] && url="$a"; done
    if [[ "$url" == */api/auth/status ]]; then [[ "${LOCAL_UP:-yes}" == yes ]]; return; fi
    echo "$url" >> "$CURL_LOG"
    local rc; rc=$(head -1 "$CURL_RC"); sed -i.bak '1d' "$CURL_RC" 2>/dev/null
    [[ -z "$rc" || "$rc" == 0 ]] && { echo '{"response":{"uuid":"ok"}}'; return 0; }
    echo "curl: ($rc) Failed to connect to panel.example port 443: Couldn't connect to server" >&2; return "$rc"
}
api_case() {   # has_panel(yes|no) метод коды… → «URL-запросов|ответ|ошибка»
    ( local hp="$1" m="$2"; shift 2
      printf '%s\n' "$@" > "$CURL_RC"; : > "$CURL_LOG"
      source "$ROOT/lib/remnawave.sh"
      curl() { _api_curl "$@"; }; has_panel() { [[ "$hp" == yes ]]; }; sleep() { :; }; warn() { :; }
      rw_token() { echo tok; }; RW_API_URL="https://panel.example"; RW_API_COOKIE=""; _RW_LOCAL=""
      out=$(rw_api "$m" /api/config-profiles '{"a":1}' 2>/dev/null); rc=$?
      echo "$(wc -l < "$CURL_LOG" | tr -d ' ')|$(head -1 "$CURL_LOG")|${out:0:10}|$rc" )
}
CURL_RC="$WORK/curl-rc"
[[ "$(api_case yes PATCH 0)" == "1|http://127.0.0.1:3000/api/config-profiles|"*"|0" ]] && pass "сервер панели — запросы в 127.0.0.1:3000, не через домен" || fail "локальный API" "$(api_case yes PATCH 0)"
[[ "$(api_case no PATCH 0)" == "1|https://panel.example/api/config-profiles|"* ]] && pass "другой сервер — через RW_API_URL" || fail "удалённый API" "$(api_case no PATCH 0)"
[[ "$(api_case no PATCH 7 7 0)" == "3|"*'|{"response|0' ]] && pass "нет соединения (перезапуск Xray) — PATCH повторяется и проходит" || fail "повтор PATCH" "$(api_case no PATCH 7 7 0)"
[[ "$(api_case no PATCH 56 0)" == "1|"*"|56" ]] && pass "обрыв после отправки — PATCH не повторяется (без дублей)" || fail "PATCH 56" "$(api_case no PATCH 56 0)"
[[ "$(api_case no GET 28 0 0)" == "2|"* ]] && pass "чтение повторяется и при таймауте" || fail "повтор GET" "$(api_case no GET 28 0 0)"
r_err=$( (printf '%s\n' 7 7 7 7 7 7 7 > "$CURL_RC"; source "$ROOT/lib/remnawave.sh"
    curl() { _api_curl "$@"; }; has_panel() { false; }; sleep() { :; }; warn() { :; }; rw_token() { echo tok; }
    RW_API_URL="https://panel.example"; _RW_LOCAL=""; rw_api PATCH /x '{}' >/dev/null 2>&1; echo "$RW_API_ERROR") )
[[ "$r_err" == *"Couldn't connect"* ]] && pass "причина ошибки сохраняется (RW_API_ERROR)" || fail "RW_API_ERROR" "$r_err"

section "Обход в подписке (JSON-шаблоны)"
DEF_TPL='{"dns":{"servers":["1.1.1.1"]},"routing":{"rules":[{"type":"field","protocol":["bittorrent"],"outboundTag":"direct"}],"domainStrategy":"IPIfNonMatch"},"outbounds":[{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}]}'
br=$(ru_bypass_rules_json no)
jq -e 'length == 2 and all(.outboundTag == "direct") and (.[0].domain | index("domain:ru") and index("domain:yandex.net") and (index("geosite:category-ru") | not))
    and .[1].ip == ["geoip:ru"]' >/dev/null <<<"$br" && pass "обход → direct: зоны, сервисы, geoip:ru; без geosite:category-ru" || fail "правила обхода" "$br"
t1=$(ru_bypass_apply "$DEF_TPL" "$br")
jq -e '.routing.rules[0].ruleTag == "f2d-ru-bypass-domains" and .routing.rules[1].ruleTag == "f2d-ru-bypass-ip" and .routing.rules[2].protocol == ["bittorrent"]
    and ([.outbounds[].tag] == ["direct", "block"])' >/dev/null <<<"$t1" && pass "в стандартном шаблоне: обход первым, остальное на месте" || fail "ru_bypass_apply" "$(jq -c .routing.rules <<<"$t1")"
t2=$(ru_bypass_apply "$t1" "$br"); [[ "$(jq '[.routing.rules[] | select(.ruleTag // "" | startswith("f2d-ru-bypass"))] | length' <<<"$t2")" == 2 ]] && pass "повторно — без дублей" || fail "дубли обхода"
t3=$(ru_bypass_apply "$t2" '[]'); [[ "$(ru_bypass_of "$t3")" == off && "$(jq '.routing.rules | length' <<<"$t3")" == 1 ]] && pass "отключение убирает только обход" || fail "bypass off"
t4=$(ru_bypass_apply '{"outbounds":[{"tag":"block","protocol":"blackhole"}]}' "$br")
[[ "$(jq -c '[.outbounds[].tag]' <<<"$t4")" == '["block","direct"]' ]] && pass "нет direct — добавляется в конец (не первым: иначе всё пошло бы мимо VPN)" || fail "direct outbound" "$(jq -c .outbounds <<<"$t4")"
seq 0 500 | awk '{print "10." int($1/256) "." ($1%256) ".0/24"}' > "$WORK/bp-pfx"
[[ "$(ru_bypass_of "$(ru_bypass_apply "$DEF_TPL" "$(ru_bypass_rules_json yes "$WORK/bp-pfx")")")" == "bypass ripe" ]] && pass "обход + сети RIPE определяется" || fail "bypass ripe"
bal=$(balancer_template_json "$t1" no)
jq -e '(.routing.rules | map(.ruleTag // "") | index("f2d-ru-bypass-domains")) < (.routing.rules | map(.balancerTag // "") | index("auto"))' >/dev/null <<<"$bal" \
    && pass "балансировщик «Авто» сохраняет обход до правила «всё → auto»" || fail "обход в «Авто»" "$(jq -c .routing.rules <<<"$bal")"
# выбор шаблонов
BP_LOG="$WORK/bp-api.log"
_bp_api() {
    echo "$1 $2" >> "$BP_LOG"
    case "$1 $2" in
        "GET /api/subscription-templates") echo '{"response":{"templates":[{"uuid":"t1","name":"Default","templateType":"XRAY_JSON"},{"uuid":"t2","name":"fail2detect Auto","templateType":"XRAY_JSON"},{"uuid":"m1","name":"Default","templateType":"MIHOMO"}]}}';;
        "GET /api/subscription-templates/"*) jq -nc --argjson t "$DEF_TPL" '{response: {templateJson: $t}}';;
        "PATCH /api/subscription-templates") echo '{"response":{"uuid":"x"}}';;
        "GET /api/subscription-settings") echo '{"response":{"uuid":"s","serveJsonAtBaseSubscription":true}}';;
    esac
}
rw_api() { _bp_api "$@"; }; rw_need_api() { :; }; require_root() { :; }
: > "$BP_LOG"; node_ru_traffic bypass --no-ripe --template 1 >/dev/null 2>&1 </dev/null
[[ "$(grep -c '^PATCH' "$BP_LOG")" == 1 ]] && grep -q 'GET /api/subscription-templates/t1' "$BP_LOG" && ! grep -q 't2\|m1' "$BP_LOG" \
    && pass "обход только в выбранном шаблоне (Mihomo и прочие не трогаются)" || fail "выбор шаблонов" "$(cat "$BP_LOG")"
: > "$BP_LOG"; out=$(node_ru_traffic bypass --no-ripe 2>&1 </dev/null)
[[ "$(grep -c '^PATCH' "$BP_LOG")" == 0 && "$out" == *"--template"* ]] && pass "без выбора — отказ, ничего не меняется" || fail "без выбора" "$out"
unset -f rw_api rw_need_api require_root _bp_api
source "$ROOT/lib/remnawave.sh"

section "Российский трафик: выбор профилей"
RU_API_LOG="$WORK/ru-api.log"
_ru_api() {
    echo "$1 $2" >> "$RU_API_LOG"
    case "$1 $2" in
        "GET /api/config-profiles") echo '{"response":{"configProfiles":[{"uuid":"p1","name":"Main DE"},{"uuid":"p2","name":"Bridge RU"},{"uuid":"p3","name":"NL"}]}}';;
        "GET /api/config-profiles/p3") echo '{"response":{"config":{"routing":{"rules":[{"ruleTag":"f2d-ru-ip","ip":["geoip:ru"],"outboundTag":"BLOCK"}]}}}}';;
        "GET /api/config-profiles/"*) echo '{"response":{"config":{"routing":{"rules":[]}}}}';;
        "PATCH /api/config-profiles") echo '{"response":{"uuid":"x"}}';;
    esac
}
rw_api() { _ru_api "$@"; }; rw_need_api() { :; }; require_root() { :; }
patched() { grep -c '^PATCH' "$RU_API_LOG"; }
: > "$RU_API_LOG"; node_ru_traffic block --no-ripe --profile "Main DE" --profile 3 >/dev/null 2>&1 </dev/null
[[ "$(patched)" == 2 ]] && grep -q 'GET /api/config-profiles/p1' "$RU_API_LOG" && grep -q 'GET /api/config-profiles/p3' "$RU_API_LOG" && ! grep -q 'p2' "$RU_API_LOG" \
    && pass "по имени и номеру: «Main DE» и №3, мост не тронут" || fail "выбор профилей" "$(cat "$RU_API_LOG")"
: > "$RU_API_LOG"; out=$(node_ru_traffic direct --no-ripe 2>&1 </dev/null)
[[ "$(patched)" == 0 && "$out" == *"--profile"* ]] && pass "без выбора (не терминал) — отказ, ничего не меняется" || fail "без выбора" "$out"
: > "$RU_API_LOG"; node_ru_traffic off --all >/dev/null 2>&1 </dev/null
[[ "$(patched)" == 3 ]] && pass "--all — все профили" || fail "--all" "$(patched)"
: > "$RU_API_LOG"; node_ru_traffic update --no-ripe >/dev/null 2>&1 </dev/null
[[ "$(patched)" == 1 ]] && grep -q 'GET /api/config-profiles/p3' "$RU_API_LOG" && pass "update без выбора — только профили, где правило уже стоит" || fail "update" "$(cat "$RU_API_LOG")"
: > "$RU_API_LOG"; out=$(node_ru_traffic block --no-ripe --profile Нет 2>&1 </dev/null)
[[ "$(patched)" == 0 && "$out" == *"Нет профиля"* ]] && pass "несуществующий профиль — ошибка, ничего не меняется" || fail "чужое имя" "$out"
unset -f rw_api rw_need_api require_root _ru_api patched
source "$ROOT/lib/remnawave.sh"

section "Порт API ноды"
NP="$WORK/nodeport"; mkdir -p "$NP/panel" "$NP/node"
cat > "$NP/panel/docker-compose.yml" <<'YML'
services:
  remnawave:
    image: remnawave/backend:2
    ports:
      - '127.0.0.1:3000:${APP_PORT:-3000}'
  remnawave-subscription-page:
    image: remnawave/subscription-page:latest
    environment:
      - APP_PORT=3010
  remnanode:
    image: remnawave/node:latest
    network_mode: host
    environment:
      - NODE_PORT=2222

networks:
  remnawave-network:
    name: remnawave-network
YML
echo 'APP_PORT=3000' > "$NP/panel/.env"
nport() {   # настоящая detect_node_api_port; docker — заглушка с контейнерами из $CT
    ( source "$ROOT/lib/detect.sh"
      docker() { case "$1" in ps) printf '%b' "${CT:-}";; inspect) printf '%b' "${CT_ENV:-}";; esac; }
      _RW_CT_DONE=""; NODE_API_PORT=""; RW_PANEL_DIR="$NP/panel"; RW_NODE_DIR="$NP/node"
      detect_node_api_port )
}
[[ "$(nport)" == 2222 ]] && pass "панель «всё в одном» (eGames): 2222, а не APP_PORT=3010 подписки" || fail "порт ноды eGames" "$(nport)"
CT="remnanode\tremnawave/node:latest\t$NP/panel\trunning\n" CT_ENV="PATH=/bin\nNODE_PORT=4321\n"
[[ "$(CT="$CT" CT_ENV="$CT_ENV" nport)" == 4321 ]] && pass "порт из окружения работающего контейнера ноды" || fail "порт из контейнера" "$(CT="$CT" CT_ENV="$CT_ENV" nport)"
unset CT CT_ENV
printf 'services:\n  remnanode:\n    image: remnawave/node:latest\n    env_file: .env\n' > "$NP/node/docker-compose.yml"
printf 'NODE_PORT=5555\nSECRET_KEY=x\n' > "$NP/node/.env"
[[ "$(nport)" == 5555 ]] && pass "отдельный каталог ноды — порт из её .env" || fail "порт из .env ноды" "$(nport)"
rm -f "$NP/node/.env" "$NP/node/docker-compose.yml"
printf 'services:\n  remnawave:\n    image: remnawave/backend:2\n  remnanode:\n    image: remnawave/node:1.6\n    environment:\n      APP_PORT: 6666\n' > "$NP/panel/docker-compose.yml"
[[ "$(nport)" == 6666 ]] && pass "старые ноды: APP_PORT в блоке ноды" || fail "APP_PORT ноды" "$(nport)"
nft() { echo "table inet fail2detect { set node_api { type inet_service; elements = { 3010, 2222 } } }"; }
[[ "$(_fw_node_api_list)" == "3010,2222" ]] && _fw_node_api_has 2222 && ! _fw_node_api_has 222 && pass "порты из набора node_api действующих правил" || fail "_fw_node_api_list" "$(_fw_node_api_list)"
unset -f nft

section "Панель после переноса"
st_lc_saved="${LC_ALL:-}"; export LC_ALL=C.UTF-8
PD="$WORK/paneldir"; mkdir -p "$PD"; printf 'PANEL_DOMAIN=panel.example\n' > "$PD/.env"
# shellcheck disable=SC2031  # RW_PANEL_DIR меняется и в подоболочках det() выше — здесь своя копия
SAVED_PANEL_DIR="$RW_PANEL_DIR"; RW_PANEL_DIR="$PD"
F2D_WEB_ENV="$WORK/web-none.env"; : > "$F2D_WEB_ENV"
# shellcheck disable=SC2016  # буквальный конфиг nginx
printf 'map $http_cookie $auth_cookie {\n    default 0;\n    "~*AbcDef12=XyZ987qw" 1;\n}\n' > "$PD/nginx.conf"
[[ "$(panel_login_link)" == "https://panel.example/auth/login?AbcDef12=XyZ987qw" ]] && pass "ссылка входа из nginx.conf установщика eGames" || fail "eGames nginx" "$(panel_login_link)"
rm "$PD/nginx.conf"; printf '@unauth {\n    not header Cookie *k1=v2*\n    query k1=v2\n}\n' > "$PD/Caddyfile"
[[ "$(panel_login_link)" == "https://panel.example/auth/login?k1=v2" ]] && pass "ссылка входа из Caddyfile" || fail "Caddy" "$(panel_login_link)"
rm "$PD/Caddyfile"
printf 'PANEL_DOMAIN="panel.example"\nPANEL_KEY_NAME="kn"\nPANEL_KEY_VALUE="kv"\nWEB_PORT="443"\n' > "$F2D_WEB_ENV"
[[ "$(panel_login_link)" == "https://panel.example/auth/login?kn=kv" ]] && pass "ссылка входа fail2detect (web.env)" || fail "web.env" "$(panel_login_link)"
out=$(panel_access_info restored 2>&1)
grep -q 'прежние' <<<"$out" && grep -q 'не меняются' <<<"$out" && pass "без panel-admin.txt — «логин и пароль прежние»" || fail "прежние" "$out"
printf 'login=admin7\npassword=S3cret!\n' > "$F2D_CONF_DIR/panel-admin.txt"
out=$(panel_access_info 2>&1); grep -q 'admin7' <<<"$out" && grep -q 'S3cret!' <<<"$out" && pass "с panel-admin.txt — логин и пароль" || fail "panel-admin" "$out"
rm -f "$F2D_CONF_DIR/panel-admin.txt"
# нода на этом же сервере: шаги panel fix (адрес, включение, порт, UFW, связь, переподключение)
API_LOG="$WORK/api-panel.log"; : > "$API_LOG"; UFW_LOG="$WORK/ufw-panel.log"; : > "$UFW_LOG"
_fix_docker() {
    case "$*" in
        *"Gateway"*) echo "172.18.0.1 172.18.0.5";;
        "inspect remnawave -f {{range \$k, \$v := .NetworkSettings.Networks}}{{\$k}}{{\"\\n\"}}{{end}}") echo remnawave-network;;
        *"network inspect"*) echo "172.18.0.0/16";;
        "exec remnawave node -e"*) return "${PANEL_REACH:-0}";;
    esac
}
_fix_api() {
    echo "$*" >> "$API_LOG"
    case "$1 $2" in
        "GET /api/nodes") echo '{"response":[{"uuid":"n1","name":"local","address":"172.30.0.1","port":2222,"isDisabled":true},{"uuid":"n2","name":"de","address":"203.0.113.5","port":2222,"isDisabled":false}]}';;
        "GET /api/nodes/n1") echo "{\"response\":{\"isConnected\":${NODE_OK:-true},\"lastStatusMessage\":\"connect ECONNREFUSED 172.18.0.1:2222\"}}";;
        "PATCH /api/nodes"*|"POST /api/nodes"*) echo '{"response":{"uuid":"n1"}}';;
    esac
}
docker() { _fix_docker "$@"; }; rw_api() { _fix_api "$@"; }
ss() { echo "LISTEN 0 4096 *:2222"; }
has_node() { true; }; ufw_active() { true; }; ufw() { echo "ufw $*" >> "$UFW_LOG"; }; NODE_API_PORT=2222; sleep() { :; }
out=$(panel_fix_local_node 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
grep -q 'POST /api/nodes/n1/actions/enable' "$API_LOG" && grep -q 'Была выключена' <<<"$out" && pass "нода выключена в панели — включается" || fail "enable" "$out"
grep -q 'PATCH /api/nodes {"uuid":"n1","address":"172.18.0.1"}' "$API_LOG" && ! grep -q '"n2"' "$API_LOG" && pass "адрес → шлюз docker-сети, внешние ноды не тронуты" || fail "адрес ноды" "$(cat "$API_LOG")"
grep -q 'allow proto tcp from 172.18.0.0/16 to any port 2222' "$UFW_LOG" && pass "UFW: docker-сеть панели → API ноды" || fail "UFW docker" "$(cat "$UFW_LOG")"
grep -q 'POST /api/nodes/n1/actions/restart' "$API_LOG" && grep -q 'подключена к панели' <<<"$out" && pass "переподключение через API и ожидание" || fail "restart" "$out"
grep -q 'Нода слушает API на порту 2222' <<<"$out" && grep -q 'Контейнер панели достаёт' <<<"$out" && pass "каждый шаг виден в выводе" || fail "вывод шагов" "$out"
: > "$API_LOG"; out=$(PANEL_REACH=1 NODE_OK=false panel_fix_local_node 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
grep -q 'НЕ достаёт до 172.18.0.1:2222' <<<"$out" && grep -q 'ECONNREFUSED' <<<"$out" && pass "нет связи — названа причина и ответ панели" || fail "диагностика без связи" "$out"
unset -f docker rw_api ss has_node ufw_active ufw sleep _fix_docker _fix_api
RW_PANEL_DIR="$SAVED_PANEL_DIR"
# перенос: все ssh/scp — через одно подключение (пароль один раз), у scp порт — -P
SSH_LOG="$WORK/ssh.log"; : > "$SSH_LOG"
ssh() { echo "ssh $*" >> "$SSH_LOG"; }; scp() { echo "scp $*" >> "$SSH_LOG"; }
# через eval: shellcheck 0.9 иначе считает вызовы выше «до определения» (SC2218)
eval 'backup_create() { BACKUP_LAST="$WORK/panel-x.tar"; touch "$BACKUP_LAST"; }'
eval 'confirm() { [[ "$1" == Начать* ]]; }'
require_root() { :; }; have() { true; }; curl() { echo 198.51.100.1; }
F2D_BACKUP_DIR="$WORK/mig"; panel_migrate --to root@203.0.113.9 -p 2202 < <(echo y) >/dev/null 2>&1
n_ssh=$(grep -c '^ssh ' "$SSH_LOG"); n_ctl=$(grep -c 'ControlPath=' "$SSH_LOG")
[[ "$n_ssh" -ge 3 && "$n_ctl" == "$(wc -l < "$SSH_LOG" | tr -d ' ')" ]] && pass "перенос: все $(wc -l < "$SSH_LOG" | tr -d ' ') вызова ssh/scp — через ControlMaster" || fail "ControlMaster" "$(cat "$SSH_LOG")"
grep -q '^scp -P 2202 ' "$SSH_LOG" && ! grep -q '^scp -p ' "$SSH_LOG" && pass "scp получает порт как -P" || fail "scp -P" "$(grep ^scp "$SSH_LOG")"
grep -q -- '-O exit' "$SSH_LOG" && pass "мастер-подключение закрывается в конце" || fail "ssh -O exit"
unset -f ssh scp backup_create require_root have confirm curl
source "$ROOT/lib/common.sh"; source "$ROOT/lib/backup.sh"; load_config
F2D_BACKUP_DIR="${F2D_STATE_DIR}/backup"
if [[ -n "$st_lc_saved" ]]; then export LC_ALL="$st_lc_saved"; else unset LC_ALL; fi

section "Веб-серверы снаружи"
_web_ss() {
    cat <<'SS'
LISTEN 0 4096 0.0.0.0:80 0.0.0.0:* users:(("caddy",pid=611,fd=7))
LISTEN 0 4096 *:443 *:* users:(("caddy",pid=611,fd=8))
LISTEN 0 511 127.0.0.1:8080 0.0.0.0:* users:(("nginx",pid=700,fd=6))
LISTEN 0 4096 127.0.0.1:7443 0.0.0.0:* users:(("rw-core",pid=900,fd=3))
LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=500,fd=3))
SS
}
wp=$( (source "$ROOT/lib/detect.sh"; ss() { _web_ss; }; detect_web_ports) )
[[ "$wp" == "80 443" ]] && pass "Caddy снаружи на 80/443 найден, локальный nginx 127.0.0.1:8080 — нет" || fail "detect_web_ports" "$wp"
pub=$( (detect_web_ports() { echo "80 443"; }; detect_xray_ports() { :; }; has_panel() { false; }; has_sub_page() { false; }; has_node() { true; }
       detect_node_api_port() { echo 2222; }; fw_mode() { echo nft; }; PUBLIC_TCP=""; NODE_XRAY_PORTS=""; fw_public_tcp) )
[[ " $pub " == *" 80 "* && " $pub " == *" 443 "* ]] && pass "режим nft: 80 и 443 веб-сервера остаются открытыми ($pub)" || fail "fw_public_tcp + веб" "$pub"

section "IP панели в iptables сторонних установщиков"
IPT="$WORK/ipt.rules"; IPT_LOG="$WORK/ipt.log"
_ipt_reset() {
    cat > "$IPT" <<'R'
-P INPUT ACCEPT
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 2222 -j ACCEPT
-A INPUT -s 198.51.100.7/32 -p tcp -m tcp --dport 2222 -j ACCEPT
-A INPUT -s 203.0.113.50/32 -p tcp -m tcp --dport 2222 -j ACCEPT
-A INPUT -s 172.16.0.0/12 -p tcp -m tcp --dport 2222 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 2222 -j DROP
-A INPUT -p tcp -m tcp --dport 8888 -j ACCEPT
R
    : > "$IPT_LOG"
}
_ipt() {   # заглушка iptables: -S, -D (точная строка), -C, -I
    case "$1" in
        -S) cat "$IPT";;
        -D) shift; local l="-A $*"; grep -qxF -- "$l" "$IPT" || return 1; grep -vxF -- "$l" "$IPT" > "$IPT.n"; mv "$IPT.n" "$IPT"; echo "D ${l}" >> "$IPT_LOG";;
        # iptables -C|-I INPUT -p tcp --dport ПОРТ -s IP -j ACCEPT → $6 — порт, $8 — IP
        -C) grep -qE -- "-s $8(/32)? .*--dport $6 .*-j ACCEPT" "$IPT";;
        -I) { head -1 "$IPT"; echo "-A INPUT -s $8/32 -p tcp -m tcp --dport $6 -j ACCEPT"; tail -n +2 "$IPT"; } > "$IPT.n"; mv "$IPT.n" "$IPT"; echo "I $8" >> "$IPT_LOG";;
    esac
}
iptables() { _ipt "$@"; }; netfilter-persistent() { echo "SAVE" >> "$IPT_LOG"; }; have() { [[ "$1" != ip6tables ]] && command -v "$1" >/dev/null 2>&1 || [[ "$1" == iptables || "$1" == netfilter-persistent ]]; }
_ipt_reset; node_api_iptables_sync 2222 "192.0.2.10" 198.51.100.7 >/dev/null 2>&1
grep -q -- '-s 192.0.2.10/32 .*--dport 2222 -j ACCEPT' "$IPT" && ! grep -q 198.51.100.7 "$IPT" && grep -q 203.0.113.50 "$IPT" \
    && pass "--replace: старая панель убрана, новая добавлена, другой адрес не тронут" || fail "replace" "$(cat "$IPT")"
grep -q '127.0.0.1/32' "$IPT" && grep -q '172.16.0.0/12' "$IPT" && grep -q 'dport 8888' "$IPT" && grep -q -- '--dport 2222 -j DROP' "$IPT" \
    && pass "служебные правила, запрет и чужие порты на месте" || fail "служебные" "$(cat "$IPT")"
grep -qx SAVE "$IPT_LOG" && pass "правила сохранены (netfilter-persistent)" || fail "сохранение" "$(cat "$IPT_LOG")"
_ipt_reset; node_api_iptables_sync 2222 "192.0.2.10" >/dev/null 2>&1
! grep -qE '198.51.100.7|203.0.113.50' "$IPT" && grep -q 192.0.2.10 "$IPT" && pass "без --replace: все прежние публичные адреса заменены новым" || fail "замена всех" "$(cat "$IPT")"
_ipt_reset; sed -i.bak '/DROP/d' "$IPT"; node_api_iptables_sync 2222 "192.0.2.10" 198.51.100.7 >/dev/null 2>&1
! grep -q '^I ' "$IPT_LOG" && pass "запрета нет — новое правило не нужно и не добавляется" || fail "без DROP" "$(cat "$IPT_LOG")"
_ipt_reset; node_api_iptables_sync 2222 "192.0.2.10 198.51.100.7 203.0.113.50" >/dev/null 2>&1
[[ "$(grep -c '^D ' "$IPT_LOG")" == 0 && "$(grep -c '^I ' "$IPT_LOG")" == 1 ]] && pass "--add: старые остаются, добавлен только новый" || fail "add" "$(cat "$IPT_LOG")"
unset -f iptables netfilter-persistent have _ipt _ipt_reset
source "$ROOT/lib/common.sh"; load_config

section "Устойчивость (pipefail, ловушки)"
# IP администратора первым в длинном списке: с pipefail проверка не должна «терять» админа
_many_admins() { echo 203.0.113.7; seq 1 200000 | awk '{print "10." int($1/65536) "." int($1/256)%256 "." $1%256}'; }
adm=$(set -o pipefail; admin_ips() { _many_admins; }; TRUSTED_IPS=""; SSH_CLIENT=""; detect_panel_ips() { :; }; ban_ignored 203.0.113.7)
[[ "$adm" == *администратора* ]] && pass "админ первым в длинном списке входов — не банится (pipefail)" || fail "admin_ips + pipefail" "$adm"
# UFW включён и правил сотни: «Status: active» не теряется
_big_ufw() { echo "Status: active"; echo; for i in $(seq 1 3000); do echo "$i/tcp ALLOW Anywhere # rule $i"; done; }
# shellcheck source=/dev/null
uact=$( (set -o pipefail; source "$ROOT/lib/detect.sh"; have() { true; }; ufw() { _big_ufw; }; ufw_active && echo on || echo off) )
[[ "$uact" == on ]] && pass "ufw_active при 3000 правил и pipefail" || fail "ufw_active" "$uact"
# GeoCheck/IPQuality не оставляют «trap … RETURN» (он срабатывал в вызвавшей функции)
rtrap=$(trap -p RETURN)
[[ -z "$rtrap" ]] && pass "нет висящих RETURN-ловушек" || fail "RETURN trap" "$rtrap"
! grep -nE "trap [^#]*RETURN" "$ROOT"/lib/*.sh "$ROOT/fail2detect" | grep -v '^\s*#' | grep -vq '#.*trap … RETURN' \
    && pass "в коде нет trap … RETURN" || fail "trap RETURN в коде" "$(grep -nE 'trap [^#]*RETURN' "$ROOT"/lib/*.sh)"

section "CLI"
check "fail2detect --help" "$ROOT/fail2detect" --help
[[ "$("$ROOT/fail2detect" version)" == "fail2detect $F2D_VERSION" ]] && pass "fail2detect version" || fail "fail2detect version"

# ---------------------------------------------------------------- nftables
if [[ $EUID -ne 0 ]] || ! command -v nft >/dev/null; then
    printf '\n(nft или root недоступны — тесты nftables пропущены)\n'
else
    section "Синтаксис правил (nft -c) во всех режимах"
    for mode in nft ufw; do
        for flood in yes no; do
            for icmp in yes no; do
                for dg in yes no; do
                    STUB_MODE=$mode FLOOD_GUARD=$flood
                    STEALTH_ICMP=$icmp DOCKER_GUARD=$dg NODE_XRAY_PORTS="443/tcp 443/udp 8443/tcp"
                    [[ $dg == yes ]] && BAN_SCOPE=except-xray || BAN_SCOPE=all
                    fw_render > "$WORK/r.nft"
                    if out=$(nft -c -f "$WORK/r.nft" 2>&1); then
                        pass "mode=$mode flood=$flood icmp=$icmp docker_guard=$dg"
                    else
                        fail "mode=$mode flood=$flood icmp=$icmp docker_guard=$dg" "$(head -3 <<<"$out")"
                    fi
                done
            done
        done
    done
    STUB_NODE=no
    fw_render > "$WORK/r.nft"; check "без ноды (пустой node_api)" nft -c -f "$WORK/r.nft"
    STUB_NODE=yes
    TRUSTED_IPS="203.0.113.10 2001:db8::1 10.0.0.0/8"
    PUBLIC_TCP="8443 6000-6007"; PUBLIC_UDP="51820"
    fw_render > "$WORK/r.nft"; check "белый список, диапазоны портов, UDP" nft -c -f "$WORK/r.nft"

    section "Применение и состояние"
    STUB_MODE=nft FLOOD_GUARD=yes STEALTH_ICMP=yes DOCKER_GUARD=yes
    ensure_dirs
    : > "$F2D_STATE_DIR/blocklist4.txt"
    # /26 в разных /24 — несмежные, auto-merge их не склеит
    for i in $(seq 1 1200); do echo "11.$((i / 250)).$((i % 250)).0/26"; done >> "$F2D_STATE_DIR/blocklist4.txt"
    echo "2a0c:1::/32" > "$F2D_STATE_DIR/blocklist6.txt"
    check "fw_apply" fw_apply
    check "таблица загружена" nft list table inet fail2detect

    # служба, таймер блок-листов и пользователь могут применять правила одновременно
    pids=(); for i in 1 2 3 4 5; do ( fw_apply >/dev/null 2>"$WORK/par$i.err" ) & pids+=($!); done
    pfail=0; for p in "${pids[@]}"; do wait "$p" || pfail=$((pfail + 1)); done
    (( pfail == 0 )) && pass "5 одновременных fw_apply — все успешны" || fail "одновременные fw_apply" "упало: $pfail; $(cat "$WORK"/par*.err | head -3)"
    ls "$F2D_STATE_DIR"/fail2detect.nft.?????? >/dev/null 2>&1 && fail "остались временные файлы правил" || pass "временные файлы убраны"
    n=$(nft -j list set inet fail2detect block4 | jq '[.nftables[].set.elem // empty | .[]] | length')
    [[ "$n" == 1200 ]] && pass "блок-лист: 1200 подсетей (пачками по 500)" || fail "блок-лист" "в наборе $n вместо 1200"
    nft list set inet fail2detect pub_tcp | grep -q 2233 && pass "SSH-порт в pub_tcp" || fail "SSH-порт в pub_tcp"
    nft list set inet fail2detect pub_tcp | grep -q 2222 && fail "API ноды попал в публичные порты" || pass "API ноды не публичный"

    section "Баны"
    ban_add 45.9.9.9 300 test "тест" >/dev/null
    nft list set inet fail2detect banned4 | grep -q '45.9.9.9' && pass "бан IPv4 попал в nft" || fail "бан IPv4 попал в nft"
    nft list set inet fail2detect banned4 | grep -qE '45.9.9.9 timeout' && pass "бан с таймаутом" || fail "бан с таймаутом"
    ban_add 2a01:4f8::9 0 test "навсегда" >/dev/null
    nft list set inet fail2detect banned6 | grep -q '2a01:4f8::9' && pass "бан IPv6 навсегда" || fail "бан IPv6 навсегда"
    ban_add 198.51.100.200 300 test "панель" >/dev/null
    nft list set inet fail2detect banned4 | grep -q '198.51.100.200' && fail "IP панели забанен" || pass "IP панели не банится"
    ban_add 10.1.2.3 300 test "частный" >/dev/null
    nft list set inet fail2detect banned4 | grep -q '10.1.2.3' && fail "частный IP забанен" || pass "частный IP не банится"
    ban_list | grep -q 45.9.9.9 && pass "ban_list показывает бан" || fail "ban_list показывает бан"

    fw_apply >/dev/null
    nft list set inet fail2detect banned4 | grep -q '45.9.9.9' && pass "бан восстановлен после fw_apply" || fail "бан восстановлен после fw_apply"

    # повторный бан — когда IP попался снова ПОСЛЕ снятия бана (пока бан действует,
    # новые строки лога ничего не меняют — так не было эскалации 1→2→4 за секунду)
    ban_remove 45.9.9.9 quiet; ban_add 45.9.9.9 300 test "повтор" >/dev/null
    t=$(nft -j list set inet fail2detect banned4 | jq -r '.nftables[].set.elem // empty | .[] | select(.elem.val=="45.9.9.9") | .elem.timeout')
    [[ "$t" == 600 ]] && pass "повторный бан вдвое дольше (600 с)" || fail "повторный бан вдвое дольше" "timeout=$t"

    ban_add 45.6.6.6 300 test "x" >/dev/null; ban_add 45.6.6.7 300 test "x" >/dev/null
    ban_flush >/dev/null
    [[ -z "$(nft -j list set inet fail2detect banned4 | jq -r '.nftables[].set.elem // empty | .[]')" && ! -s "$F2D_BANS_DB" ]] \
        && pass "unban all снимает все баны" || fail "unban all"
    ban_add 45.9.9.9 300 test "повтор после flush" >/dev/null
    ban_remove 45.9.9.9 quiet
    nft list set inet fail2detect banned4 | grep -q '45.9.9.9' && fail "разбан" || pass "разбан убирает IP из nft"
    awk -F'\t' '$2=="UNBAN" && $3=="45.9.9.9"' "$F2D_AUDIT_LOG" | grep -q . && pass "разбан записан в аудит" || fail "разбан записан в аудит"
    awk -F'\t' '$2=="IGNORE" && $3=="198.51.100.200"' "$F2D_AUDIT_LOG" | grep -q . && pass "пропуск панели записан в аудит" || fail "пропуск панели в аудите"

    section "Jail end-to-end"
    for i in 1 2 3 4 5; do echo "Failed password for root from 45.8.8.8 port 1 ssh2"; done | jail_loop sshd
    nft list set inet fail2detect banned4 | grep -q '45.8.8.8' && pass "5 неудач SSH → бан" || fail "5 неудач SSH → бан"
    for i in 1 2 3 4; do echo "Failed password for root from 45.7.7.7 port 1 ssh2"; done | jail_loop sshd
    nft list set inet fail2detect banned4 | grep -q '45.7.7.7' && fail "4 неудачи — бан раньше порога" || pass "4 неудачи — без бана"

    section "Откат"
    PUBLIC_TCP="9999"; fw_apply >/dev/null
    nft list set inet fail2detect pub_tcp | grep -q 9999 && pass "новый порт применён" || fail "новый порт применён"
    fw_rollback >/dev/null 2>&1
    nft list set inet fail2detect pub_tcp | grep -q 9999 && fail "откат" "порт 9999 остался" || pass "откат вернул прежние правила"

    section "Удаление ноды"
    fw_apply >/dev/null
    mkdir -p /opt/remnanode/certs; cp "$ROOT/tests/fixtures/compose-caddy.yml" /opt/remnanode/docker-compose.yml
    docker() { echo "docker $*" >> "$WORK/docker.log"; }
    detect_xray_ports() { echo 443; }; detect_xray_udp_ports() { echo 443; }
    node_dir() { [[ -f /opt/remnanode/docker-compose.yml ]] && echo /opt/remnanode; }
    STUB_PANEL=no; PUBLIC_TCP="443 8443"; PUBLIC_UDP="443"; NODE_XRAY_PORTS="443/tcp 443/udp 8443/tcp"
    config_set PUBLIC_TCP "443 8443"; config_set PUBLIC_UDP "443"; config_set NODE_XRAY_PORTS "443/tcp 443/udp 8443/tcp"
    printf 'y\nn\n' | remove_node >/dev/null 2>&1
    [[ ! -d /opt/remnanode ]] && pass "каталог ноды удалён" || fail "каталог ноды остался"
    ls "$F2D_STATE_DIR"/backup/remnanode-*.tgz >/dev/null 2>&1 && pass "архив ноды создан" || fail "архив ноды"
    bk=""; for f in "$F2D_STATE_DIR"/backup/remnanode-*.tgz; do bk="$f"; done
    tar -tzf "$bk" | grep -q 'remnanode/docker-compose.yml' && pass "в архиве есть docker-compose.yml" || fail "содержимое архива"
    grep -q 'compose down' "$WORK/docker.log" && pass "контейнеры остановлены (docker compose down)" || fail "docker compose down не вызван"
    load_config
    [[ -z "$NODE_XRAY_PORTS" && " $PUBLIC_TCP " != *" 8443 "* && " $PUBLIC_UDP " != *" 443 "* ]] && pass "порты ноды закрыты" || fail "порты ноды" "tcp=$PUBLIC_TCP udp=$PUBLIC_UDP xray=$NODE_XRAY_PORTS"
    nft list set inet fail2detect pub_tcp | grep -q 2233 && pass "SSH-порт остался открыт" || fail "SSH-порт закрылся"
    unset -f docker detect_xray_ports detect_xray_udp_ports

    check "fw_disable удаляет таблицу" bash -c "nft delete table inet fail2detect && ! nft list table inet fail2detect"
fi

printf '\nИтого: %d ok, %d fail\n' "$PASS" "$FAIL"
(( FAIL == 0 ))

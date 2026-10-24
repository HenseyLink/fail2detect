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
for m in common detect firewall jail transport certs web remnawave installer remove setup ipquality; do source "$ROOT/lib/$m.sh"; done
load_config
GEO_LOOKUP=no

# окружение сервера — заглушки детекта
STUB_NODE=yes; STUB_PANEL=no
has_node()  { [[ "$STUB_NODE" == yes ]]; }
has_panel() { [[ "$STUB_PANEL" == yes ]]; }
has_sub_page() { false; }
detect_ssh_ports()  { echo 2233; }
detect_xray_ports() { echo 443; }
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

section "Удаление: защита от лишнего"
for bad in / /etc /opt /root /home "$WORK"; do
    _safe_rmdir "$bad" 2>/dev/null && fail "_safe_rmdir согласился удалить $bad" || pass "_safe_rmdir отказал: $bad"
done

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
                    STEALTH_ICMP=$icmp DOCKER_GUARD=$dg
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

    ban_add 45.9.9.9 300 test "повтор" >/dev/null
    t=$(nft -j list set inet fail2detect banned4 | jq -r '.nftables[].set.elem // empty | .[] | select(.elem.val=="45.9.9.9") | .elem.timeout')
    [[ "$t" == 600 ]] && pass "повторный бан вдвое дольше (600 с)" || fail "повторный бан вдвое дольше" "timeout=$t"

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

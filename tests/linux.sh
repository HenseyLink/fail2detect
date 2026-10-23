#!/usr/bin/env bash
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
for m in common detect firewall jail transport certs web remnawave installer setup; do source "$ROOT/lib/$m.sh"; done
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

section "docker-compose ноды (в т.ч. от других установщиков)"
mkdir -p "$WORK/node"
printf 'services:\n  remnawave-nginx:\n    image: nginx\n    volumes:\n      - ./a:/a\n\n  remnanode:\n    image: remnawave/node\n    volumes:\n      - /dev/shm:/dev/shm:rw\n' > "$WORK/node/docker-compose.yml"
node_dir() { echo "$WORK/node"; }
node_compose_add_certs
[[ "$(grep -c xray-certs "$WORK/node/docker-compose.yml")" == 1 ]] && pass "монтирование сертификатов добавлено один раз" || fail "монтирование сертификатов"
awk '/remnawave-nginx:/,/remnanode:/' "$WORK/node/docker-compose.yml" | grep -q xray-certs && fail "сертификаты попали в nginx" || pass "сервис nginx не тронут"
node_compose_add_certs && fail "повторный запуск изменил файл" || pass "повторный запуск ничего не меняет"
STUB_NODE=yes

section "Защита администратора"
# shellcheck disable=SC2317,SC2329
journalctl() { printf '%s\n' "Accepted publickey for root from 77.1.1.1 port 51000 ssh2: ED25519 SHA256:x" "Failed password for root from 77.2.2.2 port 1 ssh2"; }
# shellcheck disable=SC2317,SC2329
who() { [[ "${1:-}" == --ips ]] && echo "root     pts/0        2026-10-23 22:00 88.3.3.3"; }
[[ -n "$(ban_ignored 77.1.1.1)" ]] && pass "успешный вход по SSH → не банится" || fail "успешный вход по SSH → не банится"
[[ -n "$(ban_ignored 88.3.3.3)" ]] && pass "открытая SSH-сессия → не банится" || fail "открытая SSH-сессия → не банится"
[[ -z "$(ban_ignored 77.2.2.2)" ]] && pass "неудачный вход → банится" || fail "неудачный вход → банится"
unset -f journalctl who
is_yes yy && is_yes "Да" && is_yes " y" && ! is_yes n && ! is_yes "" && pass "is_yes: yy/Да/y — да, n/пусто — нет" || fail "is_yes"

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
    check "fw_disable удаляет таблицу" bash -c "nft delete table inet fail2detect && ! nft list table inet fail2detect"
fi

printf '\nИтого: %d ok, %d fail\n' "$PASS" "$FAIL"
(( FAIL == 0 ))

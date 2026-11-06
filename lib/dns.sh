#!/usr/bin/env bash
# fail2detect — DNS-записи через API Cloudflare и Spaceship.
#
# При установке панели, ноды и страницы подписки: если домен ещё не указывает
# на сервер, fail2detect предлагает создать A-запись сам и ждёт, пока она
# начнёт отвечать в публичном DNS (дальше — сертификат). Вручную: f2d dns.
#
# Cloudflare: API-токен с правом Zone → DNS → Edit. Тот же токен, что для
# сертификатов через DNS (хранится в cloudflare.ini). Запись — «DNS only»:
# через прокси Cloudflare Reality и Hysteria не работают.
# Spaceship: API-ключ и секрет (spaceship.com → API Manager, права
# dnsrecords:read и dnsrecords:write); DNS домена должен обслуживать Spaceship.

DNS_CONF="${F2D_CONF_DIR}/dns.conf"
CF_API="https://api.cloudflare.com/client/v4"
SS_API="https://spaceship.dev/api/v1"
DNS_WAIT_SECS="${DNS_WAIT_SECS:-180}"

dns_load() {
    DNS_PROVIDER=""; SS_KEY=""; SS_SECRET=""
    # shellcheck disable=SC1090
    [[ -r "$DNS_CONF" ]] && source "$DNS_CONF"
    CF_TOKEN=$(sed -n 's/^dns_cloudflare_api_token *= *//p' "$CF_INI" 2>/dev/null | head -1)
}

dns_configured() {
    dns_load
    case "$DNS_PROVIDER" in
        cloudflare) [[ -n "$CF_TOKEN" ]];;
        spaceship) [[ -n "$SS_KEY" && -n "$SS_SECRET" ]];;
        *) return 1;;
    esac
}

dns_label() { case "${1:-$DNS_PROVIDER}" in cloudflare) echo Cloudflare;; spaceship) echo Spaceship;; *) echo "—";; esac; }

_dns_save() {
    mkdir -p "$F2D_CONF_DIR"
    install -m 600 /dev/null "$DNS_CONF"
    printf 'DNS_PROVIDER=%q\nSS_KEY=%q\nSS_SECRET=%q\n' "$DNS_PROVIDER" "$SS_KEY" "$SS_SECRET" > "$DNS_CONF"
}

# тип записи по адресу
_dns_type() { is_ipv6 "$1" && echo AAAA || echo A; }

# ---------------------------------------------------------------- Cloudflare
_cf() {   # метод путь [json]
    local a=(-sS --max-time 20 -X "$1" "$CF_API$2" -H "Authorization: Bearer $CF_TOKEN" -H 'Content-Type: application/json')
    [[ -n "${3:-}" ]] && a+=(--data "$3")
    curl "${a[@]}" 2>/dev/null
}

_cf_err() { jq -r '[.errors[]?.message] | join("; ") | if . == "" then "нет ответа API" else . end' <<<"${1:-{\}}" 2>/dev/null || echo "нет ответа API"; }

# зона домена -> DNS_ZONE_ID, DNS_ZONE; перебираем от полного имени к корню.
# Вызывать напрямую, не через $( ): иначе DNS_ERR потеряется в подоболочке.
cf_zone() {   # fqdn
    local d="$1" r id
    DNS_ZONE=""; DNS_ZONE_ID=""
    while [[ "$d" == *.* ]]; do
        r=$(_cf GET "/zones?name=$d")
        id=$(jq -r '.result[0].id // empty' <<<"$r" 2>/dev/null)
        [[ -n "$id" ]] && { DNS_ZONE_ID="$id"; DNS_ZONE="$d"; return 0; }
        [[ "$(jq -r '.success' <<<"$r" 2>/dev/null)" == true ]] || { DNS_ERR=$(_cf_err "$r"); return 1; }
        d="${d#*.}"
    done
    DNS_ERR="зоны для $1 нет в аккаунте Cloudflare (или у токена нет к ней доступа)"
    return 1
}

cf_records() {   # zone_id fqdn type -> строки "id адрес proxied"
    _cf GET "/zones/$1/dns_records?type=$3&name=$2" | jq -r '.result[]? | "\(.id) \(.content) \(.proxied)"' 2>/dev/null
}

cf_write() {   # zone_id fqdn type ip [id] — создать или заменить
    local body r
    body=$(jq -nc --arg t "$3" --arg n "$2" --arg c "$4" '{type: $t, name: $n, content: $c, ttl: 1, proxied: false, comment: "fail2detect"}')
    if [[ -n "${5:-}" ]]; then r=$(_cf PUT "/zones/$1/dns_records/$5" "$body"); else r=$(_cf POST "/zones/$1/dns_records" "$body"); fi
    [[ "$(jq -r '.success' <<<"$r" 2>/dev/null)" == true ]] || { DNS_ERR=$(_cf_err "$r"); return 1; }
}

cf_delete() {   # zone_id record_id
    local r; r=$(_cf DELETE "/zones/$1/dns_records/$2")
    [[ "$(jq -r '.success' <<<"$r" 2>/dev/null)" == true ]] || { DNS_ERR=$(_cf_err "$r"); return 1; }
}

cf_verify() {
    local r; r=$(_cf GET "/user/tokens/verify")
    [[ "$(jq -r '.result.status // empty' <<<"$r" 2>/dev/null)" == active ]] || { DNS_ERR=$(_cf_err "$r"); return 1; }
}

# ---------------------------------------------------------------- Spaceship
_ss() {   # метод путь [json] -> SS_BODY, SS_CODE (вызывать без подоболочки)
    local a=(-sS --max-time 20 -X "$1" "$SS_API$2" -H "X-API-Key: $SS_KEY" -H "X-API-Secret: $SS_SECRET" -w $'\n%{http_code}')
    [[ -n "${3:-}" ]] && a+=(-H 'Content-Type: application/json' --data "$3")
    local out; out=$(curl "${a[@]}" 2>/dev/null)
    if [[ "$out" == *$'\n'* ]]; then SS_CODE="${out##*$'\n'}"; SS_BODY="${out%$'\n'*}"; else SS_CODE="${out:-000}"; SS_BODY=""; fi
}

_ss_err() {   # тело
    local m; m=$(jq -r '.detail // .message // ([.data[]?.details // empty] | join("; ")) // empty' <<<"${1:-{\}}" 2>/dev/null)
    case "$SS_CODE" in
        401|403) echo "ключ не подходит или у него нет прав dnsrecords:read/write${m:+ ($m)}";;
        429) echo "лимит запросов Spaceship, повторите через несколько минут";;
        000|"") echo "Spaceship не отвечает";;
        *) echo "HTTP $SS_CODE${m:+: $m}";;
    esac
}

# зона = домен в аккаунте -> DNS_ZONE; перебираем от полного имени к корню
ss_zone() {   # fqdn
    local d="$1"
    DNS_ZONE=""
    while [[ "$d" == *.* ]]; do
        _ss GET "/dns/records/$d?take=1&skip=0"
        [[ "$SS_CODE" == 200 ]] && { DNS_ZONE="$d"; return 0; }
        [[ "$SS_CODE" == 401 || "$SS_CODE" == 403 || "$SS_CODE" == 429 || "$SS_CODE" == 000 ]] && { DNS_ERR=$(_ss_err "$SS_BODY"); return 1; }
        d="${d#*.}"
    done
    DNS_ERR="домена $1 нет в аккаунте Spaceship (или его DNS обслуживает не Spaceship)"
    return 1
}

_ss_rel() { [[ "$1" == "$2" ]] && echo "@" || echo "${1%."$2"}"; }   # fqdn зона -> имя записи

ss_records() {   # зона fqdn type -> адреса
    local rel; rel=$(_ss_rel "$2" "$1")
    _ss GET "/dns/records/$1?take=500&skip=0"
    jq -r --arg n "$rel" --arg t "$3" '.items[]? | select(.type == $t and ((.name | ascii_downcase) == ($n | ascii_downcase))) | .address' <<<"${SS_BODY:-{\}}" 2>/dev/null
}

ss_write() {   # зона fqdn type ip
    local rel; rel=$(_ss_rel "$2" "$1")
    _ss PUT "/dns/records/$1" "$(jq -nc --arg t "$3" --arg n "$rel" --arg a "$4" '{force: true, items: [{type: $t, name: $n, address: $a, ttl: 600}]}')"
    [[ "$SS_CODE" == 2?? ]] || { DNS_ERR=$(_ss_err "$SS_BODY"); return 1; }
}

ss_delete() {   # зона fqdn type ip
    local rel; rel=$(_ss_rel "$2" "$1")
    _ss DELETE "/dns/records/$1" "$(jq -nc --arg t "$3" --arg n "$rel" --arg a "$4" '[{type: $t, name: $n, address: $a}]')"
    [[ "$SS_CODE" == 2?? ]] || { DNS_ERR=$(_ss_err "$SS_BODY"); return 1; }
}

# ---------------------------------------------------------------- общее
dns_get() {   # fqdn [type] -> текущие адреса у провайдера
    local t="${2:-A}"
    dns_configured || { DNS_ERR="DNS-провайдер не настроен: f2d dns setup"; return 1; }
    case "$DNS_PROVIDER" in
        cloudflare) cf_zone "$1" || return 1; cf_records "$DNS_ZONE_ID" "$1" "$t" | awk '{print $2}';;
        spaceship) ss_zone "$1" || return 1; ss_records "$DNS_ZONE" "$1" "$t";;
    esac
}

# создать запись или заменить старую (её адрес меняем только с согласия)
dns_set() {   # fqdn ip
    local fqdn="${1,,}" ip="$2" t z cur old id
    is_ip "$ip" || { DNS_ERR="«${ip}» — не IP-адрес"; return 1; }
    dns_configured || { DNS_ERR="DNS-провайдер не настроен: f2d dns setup"; return 1; }
    t=$(_dns_type "$ip")
    case "$DNS_PROVIDER" in
        cloudflare)
            cf_zone "$fqdn" || return 1; z="$DNS_ZONE_ID"
            cur=$(cf_records "$z" "$fqdn" "$t")
            if [[ -n "$cur" ]]; then
                read -r id old _ <<<"$cur"
                if [[ "$old" == "$ip" ]]; then
                    [[ "$cur" == *" true" ]] && { cf_write "$z" "$fqdn" "$t" "$ip" "$id" || return 1; ok "$fqdn: прокси Cloudflare выключен (DNS only)"; return 0; }
                    ok "$t-запись $fqdn → $ip уже есть ($(dns_label))"; return 0
                fi
                confirm "$t-запись $fqdn уже ведёт на $old — заменить на $ip?" n || { DNS_ERR="запись не тронута"; return 1; }
                cf_write "$z" "$fqdn" "$t" "$ip" "$id" || return 1
            else
                cf_write "$z" "$fqdn" "$t" "$ip" || return 1
            fi;;
        spaceship)
            ss_zone "$fqdn" || return 1; z="$DNS_ZONE"
            cur=$(ss_records "$z" "$fqdn" "$t")
            if grep -qxF "$ip" <<<"$cur"; then ok "$t-запись $fqdn → $ip уже есть ($(dns_label))"; return 0; fi
            if [[ -n "$cur" ]]; then
                confirm "$t-запись $fqdn уже ведёт на $(paste -sd, <<<"$cur") — заменить на $ip?" n || { DNS_ERR="запись не тронута"; return 1; }
                while IFS= read -r old; do [[ -n "$old" ]] && { ss_delete "$z" "$fqdn" "$t" "$old" || return 1; }; done <<<"$cur"
            fi
            ss_write "$z" "$fqdn" "$t" "$ip" || return 1;;
    esac
    ok "$t-запись $fqdn → $ip ($(dns_label))"
}

dns_remove() {   # fqdn [type]
    local fqdn="${1,,}" t="${2:-A}" z cur id addr n=0
    dns_configured || { DNS_ERR="DNS-провайдер не настроен: f2d dns setup"; return 1; }
    case "$DNS_PROVIDER" in
        cloudflare)
            cf_zone "$fqdn" || return 1; z="$DNS_ZONE_ID"
            cur=$(cf_records "$z" "$fqdn" "$t")
            while read -r id addr _; do [[ -n "$id" ]] && { cf_delete "$z" "$id" || return 1; n=$((n + 1)); }; done <<<"$cur";;
        spaceship)
            ss_zone "$fqdn" || return 1; z="$DNS_ZONE"
            while IFS= read -r addr; do [[ -n "$addr" ]] && { ss_delete "$z" "$fqdn" "$t" "$addr" || return 1; n=$((n + 1)); }; done < <(ss_records "$z" "$fqdn" "$t");;
    esac
    ((n)) && ok "Удалено $t-записей $fqdn: $n" || info "$t-записей $fqdn нет"
}

dns_list() {   # домен — записи A/AAAA/CNAME зоны
    dns_configured || { DNS_ERR="DNS-провайдер не настроен: f2d dns setup"; return 1; }
    case "$DNS_PROVIDER" in
        cloudflare)
            cf_zone "${1,,}" || return 1
            title "DNS-записи $DNS_ZONE ($(dns_label))"
            _cf GET "/zones/$DNS_ZONE_ID/dns_records?per_page=500" | jq -r '.result[]? | select(.type == "A" or .type == "AAAA" or .type == "CNAME")
                | "  \(.type)\t\(.name)\t\(.content)\t\(if .proxied then "прокси Cloudflare" else "DNS only" end)"' | column -t -s $'\t';;
        spaceship)
            ss_zone "${1,,}" || return 1
            title "DNS-записи $DNS_ZONE ($(dns_label))"
            _ss GET "/dns/records/$DNS_ZONE?take=500&skip=0"
            jq -r --arg z "$DNS_ZONE" '.items[]? | select(.type == "A" or .type == "AAAA" or .type == "CNAME")
                | "  \(.type)\t\(if .name == "@" then $z else .name + "." + $z end)\t\(.address // .cname // "")"' <<<"${SS_BODY:-{\}}" | column -t -s $'\t';;
    esac
}

# ждать, пока запись не начнёт отвечать в публичном DNS (Cloudflare и Google по DoH)
dns_public() {   # fqdn type
    local u
    for u in "https://cloudflare-dns.com/dns-query" "https://dns.google/resolve"; do
        curl -sS --max-time 6 -H 'accept: application/dns-json' "$u?name=$1&type=$2" 2>/dev/null | jq -r '.Answer[]?.data' 2>/dev/null
    done | sort -u
}

dns_wait() {   # fqdn ip
    local t end spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' i=0
    t=$(_dns_type "$2"); end=$(( $(date +%s) + DNS_WAIT_SECS ))
    while (( $(date +%s) < end )); do
        if dns_public "$1" "$t" | grep -qxF "$2"; then
            [[ -t 2 ]] && printf '\r\033[K' >&2
            ok "$1 отвечает в публичном DNS ($2)"; return 0
        fi
        [[ -t 2 ]] && printf '\r  %s%s%s Жду, пока %s появится в DNS…' "$C_CYAN" "${spin:i++%10:1}" "$C_RESET" "$1" >&2
        sleep 3
    done
    [[ -t 2 ]] && printf '\r\033[K' >&2
    warn "$1 пока не виден в публичном DNS — обычно это минуты; сертификат может не выпуститься с первого раза"
    return 1
}

# ---------------------------------------------------------------- настройка
dns_setup() {
    require_root; dns_load
    title "DNS-записи через API"
    echo "  Провайдер, где обслуживается DNS ваших доменов:"
    echo "   1. Cloudflare — API-токен с правом Zone → DNS → Edit"
    echo "   2. Spaceship — API-ключ и секрет (API Manager, права dnsrecords:read и dnsrecords:write)"
    echo "   3. Отключить"
    local def=1; [[ "$DNS_PROVIDER" == spaceship ]] && def=2
    ask "Провайдер" "$def"
    case "$REPLY" in
        1)
            if [[ -n "$CF_TOKEN" ]] && confirm "Токен Cloudflare уже сохранён ($(mask_secret "$CF_TOKEN")) — использовать его?" y; then :
            else
                echo "  ${C_GRAY}dash.cloudflare.com → My Profile → API Tokens → Create Token → «Edit zone DNS», зона — ваш домен${C_RESET}"
                read_secret "Cloudflare API token"; [[ -n "$REPLY" ]] || { warn "Токен не задан"; return 1; }
                CF_TOKEN="$REPLY"
            fi
            cf_verify || { err "Cloudflare: $DNS_ERR"; return 1; }
            mkdir -p "$F2D_CONF_DIR"; install -m 600 /dev/null "$CF_INI"
            printf 'dns_cloudflare_api_token = %s\n' "$CF_TOKEN" > "$CF_INI"
            DNS_PROVIDER=cloudflare;;
        2)
            echo "  ${C_GRAY}spaceship.com → API Manager → New API key, права dnsrecords:read и dnsrecords:write${C_RESET}"
            read_secret "Spaceship API key"; [[ -n "$REPLY" ]] || { warn "Ключ не задан"; return 1; }; SS_KEY="$REPLY"
            read_secret "Spaceship API secret"; [[ -n "$REPLY" ]] || { warn "Секрет не задан"; return 1; }; SS_SECRET="$REPLY"
            DNS_PROVIDER=spaceship;;
        3) DNS_PROVIDER=""; SS_KEY=""; SS_SECRET=""; _dns_save; ok "Создание DNS-записей отключено"; return 0;;
        *) return 1;;
    esac
    ask "Домен для проверки доступа (Enter — пропустить)" ""
    if [[ -n "$REPLY" ]]; then
        case "$DNS_PROVIDER" in cloudflare) cf_zone "${REPLY,,}";; spaceship) ss_zone "${REPLY,,}";; esac \
            || { err "$(dns_label): $DNS_ERR"; return 1; }
        ok "Доступ к зоне $DNS_ZONE есть"
    fi
    _dns_save
    ok "DNS-записи: $(dns_label). При установке панели, ноды и подписки fail2detect предложит создать запись сам."
}

# при установке: домен не указывает на сервер — предложить создать запись
dns_offer() {   # fqdn ip -> 0, если запись есть и видна
    local fqdn="$1" ip="$2"
    if ! dns_configured; then
        [[ "${F2D_ASSUME_YES:-0}" == 1 || ! -t 0 ]] && return 1
        confirm "Создать запись автоматически через API Cloudflare или Spaceship?" n || return 1
        dns_setup || return 1
    else
        confirm "Создать $(_dns_type "$ip")-запись $fqdn → $ip через $(dns_label)?" y || return 1
    fi
    dns_set "$fqdn" "$ip" || { err "$(dns_label): $DNS_ERR"; return 1; }
    dns_wait "$fqdn" "$ip"
}

dns_cli() {
    local sub="${1:-status}"; shift || true
    case "$sub" in
        setup) dns_setup;;
        status)
            if dns_configured; then ok "DNS-записи через $(dns_label)"
            else info "DNS-провайдер не настроен: f2d dns setup"; fi;;
        set|add)
            require_root
            local ip="${2:-}"; [[ -n "$ip" ]] || ip=$(public_ip) || die "Не удалось узнать IP сервера — укажите его"
            dns_set "${1:?домен}" "$ip" || die "$(dns_label): $DNS_ERR"
            [[ "${3:-}" == --no-wait ]] || dns_wait "$1" "$ip";;
        get) dns_configured || die "DNS-провайдер не настроен: f2d dns setup"
             case "$DNS_PROVIDER" in cloudflare) cf_zone "${1:?домен}";; spaceship) ss_zone "${1:?домен}";; esac || die "$(dns_label): $DNS_ERR"
             local t; for t in A AAAA; do dns_get "${1,,}" "$t" | sed "s/^/  $t  /"; done;;
        list) dns_list "${1:?домен (зона)}" || die "$(dns_label): $DNS_ERR";;
        remove|rm|del) require_root; dns_remove "${1:?домен}" "${2:-A}" || die "$(dns_label): $DNS_ERR";;
        *) die "dns setup | status | set <домен> [IP] | get <домен> | list <зона> | remove <домен> [A|AAAA]";;
    esac
}

menu_dns() {
    while true; do
        banner
        echo "  ${C_BOLD}DNS-записи${C_RESET} ${C_GRAY}($(dns_configured && dns_label || echo "не настроено"))${C_RESET}"
        menu_item 1 "Подключить Cloudflare или Spaceship"
        menu_item 2 "Создать или обновить A-запись"
        menu_item 3 "Записи домена"
        menu_item 4 "Удалить запись"
        menu_item 0 "Назад"
        ask "Выбор" ""
        case "$REPLY" in
            1) dns_setup;;
            2) ask "Домен (например node1.example.com)"; local d="$REPLY" ip
               if [[ -n "$d" ]]; then
                   ask "IP" "$(public_ip)"; ip="$REPLY"
                   if dns_set "$d" "$ip"; then dns_wait "$d" "$ip"; else err "$(dns_label): $DNS_ERR"; fi
               fi;;
            3) ask "Домен (зона, например example.com)"; [[ -n "$REPLY" ]] && { dns_list "$REPLY" || err "$(dns_label): $DNS_ERR"; };;
            4) ask "Домен"; local d="$REPLY"
               [[ -n "$d" ]] && confirm "Удалить A-запись $d?" n && { dns_remove "$d" || err "$(dns_label): $DNS_ERR"; };;
            0|q|"") return;;
        esac
        pause
    done
}

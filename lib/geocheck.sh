#!/usr/bin/env bash
# fail2detect — GeoCheck: как IP сервера видят гео-базы и сервисы.

UA_BROWSER='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36'

_gc() { curl -4 -sS --max-time 10 -A "$UA_BROWSER" "$@" 2>/dev/null; }

# provider -> "CC|город|сеть"
_geo_provider() {
    local p="$1" ip="$2" j
    case "$p" in
        ipinfo)    j=$(_gc "https://ipinfo.io/$ip/json");             jq -r '[.country, .city, .org] | map(. // "?") | join("|")' <<<"$j";;
        ip-api)    j=$(_gc "http://ip-api.com/json/$ip?fields=countryCode,city,as,hosting,proxy"); jq -r '[.countryCode, .city, .as + (if .hosting then " [hosting]" else "" end) + (if .proxy then " [proxy]" else "" end)] | map(. // "?") | join("|")' <<<"$j";;
        ipwhois)   j=$(_gc "https://ipwho.is/$ip");                    jq -r '[.country_code, .city, ("AS" + (.connection.asn|tostring) + " " + .connection.org)] | map(. // "?") | join("|")' <<<"$j";;
        ipapi.co)  j=$(_gc "https://ipapi.co/$ip/json/");             jq -r '[.country_code, .city, .org] | map(. // "?") | join("|")' <<<"$j";;
        ip.sb)     j=$(_gc "https://api.ip.sb/geoip/$ip");            jq -r '[.country_code, .city, ("AS" + (.asn|tostring) + " " + .isp)] | map(. // "?") | join("|")' <<<"$j";;
        ip2location) j=$(_gc "https://api.ip2location.io/?ip=$ip");   jq -r '[.country_code, .city_name, ("AS" + (.asn|tostring) + " " + .as) + (if .is_proxy then " [proxy]" else "" end)] | map(. // "?") | join("|")' <<<"$j";;
        cloudflare) j=$(_gc "https://www.cloudflare.com/cdn-cgi/trace"); echo "$(awk -F= '$1=="loc"{print $2}' <<<"$j")|—|—";;
    esac 2>/dev/null
}

# сервисы: печатает "статус|подробность", статус: ok|no|part|err
_svc() {
    local s="$1" body code
    case "$s" in
        youtube)
            body=$(_gc -L -H 'Accept-Language: en' -b 'SOCS=CAI; CONSENT=YES+' "https://www.youtube.com/premium")
            [[ -z "$body" ]] && { echo "err|нет ответа"; return; }
            local gl; gl=$(grep -oE '"GL":"[A-Z]{2}"' <<<"$body" | head -1 | cut -d'"' -f4)
            if grep -q 'www.google.cn' <<<"$body"; then echo "no|CN"
            elif grep -qi 'Premium is not available in your country' <<<"$body"; then echo "no|регион ${gl:-?}"
            else echo "ok|регион ${gl:-?}"; fi;;
        netflix)
            code=$(_gc -L -o /dev/null -w '%{http_code}' "https://www.netflix.com/title/81280792")
            case "$code" in
                200) echo "ok|полный каталог";;
                404) echo "part|только Originals";;
                403) echo "no|заблокирован";;
                *)   echo "err|HTTP $code";;
            esac;;
        chatgpt)
            body=$(_gc "https://api.openai.com/compliance/cookie_requirements")
            if [[ -z "$body" ]]; then echo "err|нет ответа"
            elif grep -q 'unsupported_country' <<<"$body"; then echo "no|страна не поддерживается"
            else echo "ok|доступен"; fi;;
        claude)
            local loc; loc=$(_gc -o /dev/null -w '%{http_code} %{redirect_url}' "https://claude.ai/")
            if [[ "$loc" == *unavailable* ]]; then echo "no|регион не поддерживается"
            elif [[ "$loc" == 2* || "$loc" == 3* ]]; then echo "ok|доступен"
            else echo "err|HTTP ${loc%% *} (вероятно, проверка Cloudflare)"; fi;;
        gemini)
            body=$(_gc "https://gemini.google.com")
            if [[ -z "$body" ]]; then echo "err|нет ответа"
            elif grep -q '45631641,null,true' <<<"$body"; then echo "ok|доступен"
            else echo "err|не удалось определить"; fi;;
        steam)
            body=$(_gc "https://store.steampowered.com/app/761830")
            local cur; cur=$(grep -oE '"priceCurrency" content="[A-Z]{3}"|priceCurrency":"[A-Z]{3}' <<<"$body" | grep -oE '[A-Z]{3}' | head -1)
            [[ -n "$cur" ]] && echo "ok|валюта $cur" || echo "err|не определено";;
        google)
            body=$(_gc "https://www.google.com/search?q=ip")
            if grep -qi 'unusual traffic\|recaptcha' <<<"$body"; then echo "part|капча (IP помечен)"
            else echo "ok|без капчи"; fi;;
    esac
}

geocheck_run() {
    local ip="${1:-}"
    have jq || die "Нужен jq"
    [[ -z "$ip" ]] && ip=$(public_ip)
    [[ -n "$ip" ]] || die "Не удалось определить IP"
    local tmp; tmp=$(mktemp -d); trap 'rm -rf "$tmp"' RETURN

    local providers=(ipinfo ip-api ipwhois ipapi.co ip.sb ip2location cloudflare)
    local services=(youtube netflix chatgpt claude gemini google steam)
    local p
    for p in "${providers[@]}"; do ( _geo_provider "$p" "$ip" > "$tmp/geo_$p" ) & done
    if [[ "$ip" == "$(public_ip)" ]]; then
        for p in "${services[@]}"; do ( _svc "$p" > "$tmp/svc_$p" ) & done
    else
        services=()   # сервисы проверяются только с самого сервера
    fi
    wait

    title "GeoCheck — $ip"
    printf '%s%-12s %-4s %-18s %s%s\n' "$C_BOLD" "БАЗА" "CC" "ГОРОД" "СЕТЬ" "$C_RESET"
    local -A cc_count=()
    for p in "${providers[@]}"; do
        local cc city net; IFS='|' read -r cc city net < "$tmp/geo_$p"
        [[ -z "$cc" || "$cc" == null ]] && { printf '%-12s %s—%s\n' "$p" "$C_GRAY" "$C_RESET"; continue; }
        cc_count[$cc]=$(( ${cc_count[$cc]:-0} + 1 ))
        printf '%-12s %s%-4s%s %-18s %s%s%s\n' "$p" "$C_WHITE" "$cc" "$C_RESET" "${city:0:18}" "$C_GRAY" "${net:0:44}" "$C_RESET"
    done
    local major="" best=0 k
    for k in "${!cc_count[@]}"; do (( cc_count[$k] > best )) && { best=${cc_count[$k]}; major=$k; }; done
    echo
    if (( ${#cc_count[@]} == 1 )); then ok "Все базы согласны: страна ${C_BOLD}$major${C_RESET}"
    else warn "Базы расходятся (${!cc_count[*]}); большинство считает: $major"; fi
    [[ "$major" == RU ]] && warn "IP определяется как российский — часть зарубежных сервисов будет недоступна клиентам"

    ((${#services[@]})) || return 0
    echo
    printf '%s%-12s %-10s %s%s\n' "$C_BOLD" "СЕРВИС" "СТАТУС" "ПОДРОБНО" "$C_RESET"
    for p in "${services[@]}"; do
        local st det; IFS='|' read -r st det < "$tmp/svc_$p"
        case "$st" in
            ok)   printf '%-12s %s%-10s%s %s\n' "$p" "$C_GREEN" "доступен" "$C_RESET" "$det";;
            part) printf '%-12s %s%-10s%s %s\n' "$p" "$C_YELLOW" "частично" "$C_RESET" "$det";;
            no)   printf '%-12s %s%-10s%s %s\n' "$p" "$C_RED" "нет" "$C_RESET" "$det";;
            *)    printf '%-12s %s%-10s%s %s\n' "$p" "$C_GRAY" "?" "$C_RESET" "$det";;
        esac
    done
}

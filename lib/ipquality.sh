#!/usr/bin/env bash
# fail2detect — IPQuality: отчёт о качестве IP (репутация, тип, риск).
#
# Структура отчёта — по мотивам IPQuality (https://github.com/xykt/IPQuality,
# AGPL-3.0); код написан заново и опрашивает только открытые источники без
# ключей: ipinfo, ipregistry, ip-api, proxycheck.io, Scamalytics, IP2Location,
# DB-IP. Для ноды VPN важнее всего разделы 2–4: как IP видят базы
# (провайдер или хостинг, VPN/прокси, риск) — именно по ним сервисы и
# регуляторы отличают VPN-сервер от обычного абонента.

UA_BROWSER='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36'
GC_DBS=(ipinfo ipregistry ipapi proxycheck scamalytics ip2loc dbip)
# короткие имена для узких колонок таблицы
declare -A GC_DB_SHORT=([ipinfo]=IPinfo [ipregistry]=ipregistry [ipapi]=ip-api [proxycheck]=proxycheck [scamalytics]=Scamalyt. [ip2loc]=IP2Loc [dbip]=DB-IP)
declare -A GC_DB_TITLE=([ipinfo]=IPinfo [ipregistry]=ipregistry [ipapi]=ip-api [proxycheck]=proxycheck [scamalytics]=Scamalytics [ip2loc]=IP2Location [dbip]=DB-IP)

_gc() { curl -4 -sS --max-time 12 -A "$UA_BROWSER" "$@" 2>/dev/null; }

# ---------- плашки ----------
if [[ -n "$C_RESET" ]]; then
    B_OK=$'\033[42;97m'; B_BAD=$'\033[41;97m'; B_WARN=$'\033[43;30m'
    T_GREEN=$'\033[32m'; T_YELLOW=$'\033[33m'; T_RED=$'\033[31m'
else
    B_OK=""; B_BAD=""; B_WARN=""; T_GREEN=""; T_YELLOW=""; T_RED=""
fi
# дополнить пробелами до ширины в СИМВОЛАХ (printf считает байты — кириллица ломает колонки)
pad() { local t="$1" w="${2:-0}"; printf '%s%*s' "$t" $(( w > ${#t} ? w - ${#t} : 0 )) ""; }

# badge вид текст [ширина] — текст на цветном фоне, дополненный пробелами до ширины
badge() {
    local kind="$1" text="$2" w="${3:-0}" col=""
    case "$kind" in ok) col="$B_OK";; bad) col="$B_BAD";; warn) col="$B_WARN";; esac
    if [[ -z "$col" ]]; then
        if [[ "$kind" =~ ^(ok|bad|warn)$ ]]; then [[ "$text" == \[* ]] && pad "$text" "$w" || pad "[$text]" "$w"
        else printf '%s%s%s' "$C_GRAY" "$(pad "$text" "$w")" "$C_RESET"; fi
        return
    fi
    local pad=$(( w - ${#text} - 2 )); (( pad < 0 )) && pad=0
    printf '%s %s %s%*s' "$col" "$text" "$C_RESET" "$pad" ""
}
# фактор риска: true -> красное «Да», false -> зелёное «Нет», иначе «—»
yn_badge() {
    case "$1" in
        true|yes|1) badge bad "Да" "$2";;
        false|no|0) badge ok "Нет" "$2";;
        *) badge none "—" "$2";;
    esac
}
# заголовок колонки: обрезать до ширины-1, чтобы колонки не слипались
colhead() { local t="$1" w="$2"; printf '%s%s%s' "$C_CYAN" "$(pad "${t:0:$((w - 1))}" "$w")" "$C_RESET"; }
label() { printf '%s%s%s' "$C_CYAN" "$(pad "$1" "${2:-22}")" "$C_RESET"; }
section() { printf '%s%s%s\n' "$C_BOLD$C_WHITE" "$1" "$C_RESET"; }

usage_ru() {   # тип сети -> "текст вид"
    case "${1,,}" in
        isp|residential|"line isp") echo "Провайдер ok";;
        mobile|wireless|cellular) echo "Мобильный ok";;
        business) echo "Бизнес ok";;
        education|edu) echo "Образование ok";;
        government|gov) echo "Госсектор warn";;
        hosting|datacenter|"data center"|cdn) echo "Хостинг bad";;
        vpn) echo "VPN bad";;
        ""|null|"?") echo "— none";;
        *) echo "$1 warn";;
    esac
}

risk_level() {   # score -> "текст вид"
    local s="${1%%.*}"
    [[ "$s" =~ ^[0-9]+$ ]] || { echo "— none"; return; }
    if (( s < 20 )); then echo "Низкий ok"; elif (( s < 60 )); then echo "Средний warn"
    elif (( s < 90 )); then echo "Высокий bad"; else echo "Очень_высокий bad"; fi
}

risk_bar() {   # score(0-100) -> полоса из 40 символов: зелёная/жёлтая/красная зоны
    local s="${1%%.*}" w=40 i out="" col
    [[ "$s" =~ ^[0-9]+$ ]] || s=0
    local fill=$(( s * w / 100 )); (( s > 0 && fill == 0 )) && fill=1
    for ((i = 0; i < w; i++)); do
        if (( i < w / 5 )); then col="$T_GREEN"; elif (( i < w * 3 / 5 )); then col="$T_YELLOW"; else col="$T_RED"; fi
        if (( i < fill )); then out+="${col}█"; else out+="${C_GRAY}░"; fi
    done
    printf '%s%s' "$out" "$C_RESET"
}

# ---------- сбор данных (всё параллельно, ответы — файлы в каталоге) ----------
gc_fetch_dbs() {   # dir ip
    local d="$1" ip="$2"
    ( _gc "https://ipinfo.io/widget/demo/$ip" > "$d/ipinfo" ) &
    ( _gc "https://api.ipregistry.co/$ip?key=tryout" -H 'Origin: https://ipregistry.co' > "$d/ipregistry" ) &
    ( _gc "http://ip-api.com/json/$ip?fields=status,countryCode,regionName,city,isp,as,mobile,proxy,hosting" > "$d/ipapi" ) &
    ( _gc "https://proxycheck.io/v2/$ip?vpn=1&asn=1&risk=1" > "$d/proxycheck" ) &
    ( _gc "https://scamalytics.com/ip/$ip" > "$d/scamalytics" ) &
    ( _gc "https://api.ip2location.io/?ip=$ip" > "$d/ip2loc" ) &
    ( _gc "https://api.db-ip.com/v2/free/$ip" > "$d/dbip" ) &
}

# разобрать ответы в ассоциативный массив G["база.поле"] (объявляет вызывающий)
gc_parse() {   # dir ip
    local d="$1" ip="$2" j
    j=$(cat "$d/ipinfo" 2>/dev/null)
    if jq -e .data.ip >/dev/null 2>&1 <<<"$j"; then
        eval "$(jq -r '.data | @sh "
            G[ipinfo.cc]=\(.country // "")
            G[ipinfo.city]=\(.city // "")
            G[ipinfo.region]=\(.region // "")
            G[ipinfo.org]=\(.org // "")
            G[ipinfo.asn]=\(.asn.asn // ((.org // "") | split(" ")[0]))
            G[ipinfo.asname]=\(.asn.name // "")
            G[ipinfo.route]=\(.asn.route // "")
            G[ipinfo.host]=\(.hostname // "")
            G[ipinfo.loc]=\(.loc // "")
            G[ipinfo.tz]=\(.timezone // "")
            G[ipinfo.reg]=\(.abuse.country // "")
            G[ipinfo.asntype]=\(.asn.type // "")
            G[ipinfo.comptype]=\(.company.type // "")
            G[ipinfo.proxy]=\(.privacy.proxy | if . == null then "" else tostring end)
            G[ipinfo.vpn]=\(.privacy.vpn | if . == null then "" else tostring end)
            G[ipinfo.tor]=\(.privacy.tor | if . == null then "" else tostring end)
            G[ipinfo.server]=\(.privacy.hosting | if . == null then "" else tostring end)"' <<<"$j")"
    fi
    j=$(cat "$d/ipregistry" 2>/dev/null)
    if jq -e .ip >/dev/null 2>&1 <<<"$j"; then
        eval "$(jq -r '@sh "
            G[ipregistry.cc]=\(.location.country.code // "")
            G[ipregistry.country]=\(.location.country.name // "")
            G[ipregistry.asntype]=\(.connection.type // "")
            G[ipregistry.comptype]=\(.company.type // "")
            G[ipregistry.proxy]=\(.security.is_proxy or .security.is_relay or .security.is_residential_proxy)
            G[ipregistry.vpn]=\(.security.is_vpn)
            G[ipregistry.tor]=\(.security.is_tor or .security.is_tor_exit)
            G[ipregistry.server]=\(.security.is_cloud_provider)
            G[ipregistry.abuser]=\(.security.is_abuser or .security.is_attacker or .security.is_threat)"' <<<"$j")"
    fi
    j=$(cat "$d/ipapi" 2>/dev/null)
    if [[ "$(jq -r .status <<<"$j" 2>/dev/null)" == success ]]; then
        eval "$(jq -r '@sh "
            G[ipapi.cc]=\(.countryCode // "")
            G[ipapi.proxy]=\(.proxy)
            G[ipapi.server]=\(.hosting)
            G[ipapi.asntype]=\(if .hosting then "hosting" elif .mobile then "mobile" else "isp" end)"' <<<"$j")"
    fi
    j=$(cat "$d/proxycheck" 2>/dev/null)
    if [[ "$(jq -r .status <<<"$j" 2>/dev/null)" == ok ]]; then
        eval "$(jq -r --arg ip "$ip" '.[$ip] | @sh "
            G[proxycheck.cc]=\(.isocode // "")
            G[proxycheck.type]=\(.type // "")
            G[proxycheck.risk]=\(.risk // "")
            G[proxycheck.proxy]=\((.proxy == "yes") and (.type != "VPN"))
            G[proxycheck.vpn]=\(.type == "VPN")
            G[proxycheck.tor]=\(.type == "TOR")
            G[proxycheck.server]=\((.type // "") | test("Hosting|VPN"))"' <<<"$j")"
    fi
    j=$(tr '\n' ' ' < "$d/scamalytics" 2>/dev/null)
    if [[ "$j" =~ \"score\":\"([0-9]+)\" ]]; then
        G[scamalytics.risk]="${BASH_REMATCH[1]}"
        local row name key
        for row in "Anonymizing VPN:vpn" "Tor Exit Node:tor" "Server:server" "Public Proxy:proxy" "Search Engine Robot:robot"; do
            name="${row%:*}"; key="${row##*:}"
            local re="<th>${name}</th>[[:space:]]*<td><div class=\"risk (yes|no)\""
            if [[ "$j" =~ $re ]]; then
                if [[ "${BASH_REMATCH[1]}" == yes ]]; then G[scamalytics.$key]=true; else G[scamalytics.$key]=false; fi
            fi
        done
        local rew='<th>Web Proxy</th>[[:space:]]*<td><div class="risk yes"'
        [[ "$j" =~ $rew ]] && G[scamalytics.proxy]=true
    fi
    j=$(cat "$d/ip2loc" 2>/dev/null)
    if jq -e .country_code >/dev/null 2>&1 <<<"$j"; then
        G[ip2loc.cc]=$(jq -r .country_code <<<"$j"); G[ip2loc.proxy]=$(jq -r '.is_proxy | if . == null then "" else tostring end' <<<"$j")
    fi
    j=$(cat "$d/dbip" 2>/dev/null)
    if jq -e .countryCode >/dev/null 2>&1 <<<"$j"; then
        G[dbip.cc]=$(jq -r .countryCode <<<"$j"); G[dbip.country]=$(jq -r .countryName <<<"$j")
    fi
    return 0
}

# ---------- сервисы: печатает "вид|регион", вид ok|warn|bad|none ----------
GC_SERVICES=(tiktok netflix youtube prime reddit chatgpt claude gemini)
declare -A GC_SVC_TITLE=([tiktok]=TikTok [netflix]=Netflix [youtube]=YouTube [prime]=PrimeVideo [reddit]=Reddit [chatgpt]=ChatGPT [claude]=Claude [gemini]=Gemini)

gc_service() {
    local s="$1" body code r
    case "$s" in
        tiktok)
            body=$(_gc -L "https://www.tiktok.com/explore")
            r=$(grep -oE '"region":"[A-Z]{2}"' <<<"$body" | head -1 | cut -d'"' -f4)
            if [[ -n "$r" ]]; then echo "ok|$r"; elif [[ -n "$body" ]]; then echo "bad|"; else echo "none|"; fi;;
        netflix)
            local a b
            a=$(_gc -L -o /dev/null -w '%{http_code} %{url_effective}' "https://www.netflix.com/title/81280792")
            b=$(_gc -L -o /dev/null -w '%{http_code}' "https://www.netflix.com/title/70143836")
            r=$(grep -oE 'netflix\.com/[a-z]{2}(-[a-z]{2})?/' <<<"$a" | sed -E 's#netflix\.com/([a-z]{2}).*#\1#' | tr '[:lower:]' '[:upper:]')
            if [[ "${a%% *}" == 200 && "$b" == 200 ]]; then echo "ok|${r:-US}"
            elif [[ "${a%% *}" == 200 || "$b" == 200 ]]; then echo "warn|$r"
            elif [[ "${a%% *}" == 403 ]]; then echo "bad|"
            else echo "none|"; fi;;
        youtube)
            body=$(_gc -L -H 'Accept-Language: en' -b 'SOCS=CAI; CONSENT=YES+' "https://www.youtube.com/premium")
            r=$(grep -oE '"GL":"[A-Z]{2}"' <<<"$body" | head -1 | cut -d'"' -f4)
            if [[ -z "$body" ]]; then echo "none|"
            elif grep -q 'www.google.cn' <<<"$body"; then echo "bad|CN"
            elif grep -qi 'Premium is not available in your country' <<<"$body"; then echo "bad|$r"
            else echo "ok|$r"; fi;;
        prime)
            body=$(_gc -L "https://www.primevideo.com")
            r=$(grep -oE '"currentTerritory":"[A-Z]{2}"' <<<"$body" | head -1 | cut -d'"' -f4)
            if grep -q '"isServiceRestricted":true' <<<"$body"; then echo "bad|"
            elif [[ -n "$r" ]]; then echo "ok|$r"; else echo "none|"; fi;;
        reddit)
            code=$(_gc -o /dev/null -w '%{http_code}' "https://www.reddit.com/")
            case "$code" in 200|301|302) echo "ok|";; 403|429) echo "bad|";; *) echo "none|";; esac;;
        chatgpt)
            local c i
            c=$(_gc "https://api.openai.com/compliance/cookie_requirements")
            i=$(_gc "https://ios.chat.openai.com/")
            r=$(_gc "https://chat.openai.com/cdn-cgi/trace" | sed -n 's/^loc=//p')
            if [[ -z "$c$i" ]]; then echo "none|$r"
            elif grep -q 'unsupported_country' <<<"$c" || grep -q 'VPN' <<<"$i"; then echo "bad|$r"
            else echo "ok|$r"; fi;;
        claude)
            r=$(_gc -o /dev/null -w '%{http_code} %{redirect_url}' "https://claude.ai/")
            if [[ "$r" == *unavailable* ]]; then echo "bad|"
            elif [[ "$r" == 2* || "$r" == 3* ]]; then echo "ok|"; else echo "none|"; fi;;
        gemini)
            body=$(_gc "https://gemini.google.com")
            if grep -q '45631641,null,true' <<<"$body"; then echo "ok|"; else echo "none|"; fi;;
    esac
}

# ---------- почта ----------
GC_MX=("Gmail:gmail-smtp-in.l.google.com" "Outlook:outlook-com.olc.protection.outlook.com" "Yahoo:mta5.am0.yahoodns.net"
       "iCloud:mx01.mail.icloud.com" "Mail.ru:mxs.mail.ru" "Yandex:mx.yandex.ru" "GMX:mx00.gmx.net")
GC_DNSBL=(zen.spamhaus.org bl.spamcop.net b.barracudacentral.org dnsbl.sorbs.net spam.dnsbl.sorbs.net
          cbl.abuseat.org psbl.surriel.com dnsbl-1.uceprotect.net dnsbl-2.uceprotect.net dnsbl-3.uceprotect.net
          ix.dnsbl.manitu.net bl.mailspike.net z.mailspike.net dnsbl.dronebl.org truncate.gbudb.net
          db.wpbl.info all.s5h.net bl.blocklist.de rbl.0spam.org spamrbl.imp.ch)

gc_fetch_mail() {   # dir ip
    local d="$1" ip="$2" m z rev
    mkdir -p "$d/mx" "$d/bl"
    for m in "${GC_MX[@]}"; do
        ( if timeout 6 bash -c "exec 3<>/dev/tcp/${m#*:}/25" 2>/dev/null; then echo ok; else echo bad; fi > "$d/mx/${m%%:*}" ) &
    done
    is_ipv4 "$ip" || return 0
    rev=$(awk -F. '{print $4"."$3"."$2"."$1}' <<<"$ip")
    for z in "${GC_DNSBL[@]}"; do
        ( a=$(getent ahostsv4 "$rev.$z" 2>/dev/null | awk 'NR==1{print $1}')
          if [[ -z "$a" ]]; then echo clean
          elif [[ "$a" == 127.255.255.* || "$a" == 127.0.0.255 ]]; then echo error   # резолвер отклонён (Spamhaus и др.)
          elif [[ "$a" == 127.* ]]; then echo listed
          else echo error; fi > "$d/bl/$z" ) &
    done
}

# ---------- отчёт ----------
ipquality_run() {
    local ip="${1:-}" self=no
    have jq || die "Нужен jq"
    local me; me=$(public_ip)
    [[ -z "$ip" ]] && ip="$me"
    [[ -n "$ip" ]] || die "Не удалось определить IP"
    [[ "$ip" == "$me" ]] && self=yes
    local tmp; tmp=$(mktemp -d); trap 'rm -rf "$tmp"' RETURN

    gc_fetch_dbs "$tmp" "$ip"
    local s
    if [[ "$self" == yes ]]; then
        for s in "${GC_SERVICES[@]}"; do ( gc_service "$s" > "$tmp/svc_$s" ) & done
        gc_fetch_mail "$tmp" "$ip"
    fi
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' i=0
    while [[ -n "$(jobs -rp)" ]]; do
        [[ -t 1 ]] && printf '\r  %s%s%s Опрашиваю базы и сервисы…' "$C_CYAN" "${spin:i++%10:1}" "$C_RESET"
        sleep 0.15
    done
    [[ -t 1 ]] && printf '\r\033[K'

    local -A G=(); gc_parse "$tmp" "$ip"
    local W=78 sharp eq
    sharp=$(printf '%*s' "$W" '' | tr ' ' '#'); eq=$(printf '%*s' "$W" '' | tr ' ' '=')

    # ===== шапка =====
    echo "$C_GRAY$sharp$C_RESET"
    printf '%*s%s\n' 22 "" "${C_BOLD}ОТЧЁТ О КАЧЕСТВЕ IP: ${C_CYAN}${ip}${C_RESET}"
    printf '%*s%s\n' 16 "" "${C_GRAY}fail2detect · по мотивам github.com/xykt/IPQuality${C_RESET}"
    printf '%*s%s\n' 20 "" "Время отчёта: $(date -u '+%Y-%m-%d %H:%M:%S') UTC"
    echo "$C_GRAY$sharp$C_RESET"

    # ===== 1. основное =====
    section "1. Основная информация"
    local cc="${G[ipinfo.cc]:-${G[ipregistry.cc]:-${G[dbip.cc]:-}}}"
    local country="${G[ipregistry.country]:-${G[dbip.country]:-}}"
    printf '  %s %s\n' "$(label "ASN:")" "${G[ipinfo.asn]:-—}"
    printf '  %s %s\n' "$(label "Организация:")" "${G[ipinfo.asname]:-${G[ipinfo.org]:-—}}"
    [[ -n "${G[ipinfo.host]:-}" ]] && printf '  %s %s\n' "$(label "Хост (rDNS):")" "${G[ipinfo.host]}"
    [[ -n "${G[ipinfo.route]:-}" ]] && printf '  %s %s\n' "$(label "Подсеть:")" "${G[ipinfo.route]}"
    if [[ -n "${G[ipinfo.loc]:-}" ]]; then
        printf '  %s %s\n' "$(label "Координаты:")" "${G[ipinfo.loc]}"
        printf '  %s %s%s%s\n' "$(label "Карта:")" "$C_GRAY" "https://www.google.com/maps?q=${G[ipinfo.loc]}" "$C_RESET"
    fi
    printf '  %s %s\n' "$(label "Город:")" "${G[ipinfo.city]:-—}${G[ipinfo.region]:+, ${G[ipinfo.region]}}"
    printf '  %s [%s] %s\n' "$(label "Фактический регион:")" "${cc:-?}" "$country"
    printf '  %s [%s]\n' "$(label "Регион регистрации:")" "${G[ipinfo.reg]:-?}"
    printf '  %s %s\n' "$(label "Часовой пояс:")" "${G[ipinfo.tz]:-—}"
    printf '  %s ' "$(label "Тип IP:")"
    if [[ -z "${G[ipinfo.reg]:-}" || -z "$cc" ]]; then badge none "нет данных"
    elif [[ "${G[ipinfo.reg]}" == "$cc" ]]; then badge ok "Нативный (регион совпадает)"
    else badge warn "Вещательный (зарегистрирован в ${G[ipinfo.reg]})"; fi
    echo

    # ===== 2. тип использования =====
    section "2. Тип IP (как его классифицируют базы)"
    local cw=14 db t k
    printf '  %s' "$(label "База:" 12)"
    for db in ipinfo ipregistry ipapi proxycheck; do colhead "${GC_DB_TITLE[$db]}" "$cw"; done; echo
    printf '  %s' "$(label "Сеть:" 12)"
    for db in ipinfo ipregistry ipapi proxycheck; do
        if [[ "$db" == proxycheck ]]; then t="${G[proxycheck.type]:-}"; else t="${G[$db.asntype]:-}"; fi
        read -r t k <<<"$(usage_ru "$t")"; badge "$k" "$t" "$cw"
    done; echo
    printf '  %s' "$(label "Компания:" 12)"
    for db in ipinfo ipregistry; do read -r t k <<<"$(usage_ru "${G[$db.comptype]:-}")"; badge "$k" "$t" "$cw"; done; echo

    # ===== 3. оценка риска =====
    section "3. Оценка риска"
    printf '  %s %s\n' "$(label "Шкала:" 14)" "$(risk_bar 100)"
    # подписи над зонами шкалы: 0–20 % / 20–60 % / 60–100 % от 40 символов
    printf '  %s %s%s%s%s%s%s%s%s%s\n' "$(label "" 14)" "$T_GREEN" "$(pad низкий 8)" "$C_RESET" "$T_YELLOW" "$(pad средний 16)" "$C_RESET" "$T_RED" "высокий" "$C_RESET"
    local src score
    for src in proxycheck scamalytics; do
        score="${G[$src.risk]:-}"
        read -r t k <<<"$(risk_level "$score")"
        printf '  %s %s %3s %s\n' "$(label "${GC_DB_TITLE[$src]}:" 14)" "$(risk_bar "${score:-0}")" "${score:-—}" "$(badge "$k" "${t//_/ }")"
    done

    # ===== 4. факторы риска =====
    section "4. Факторы риска"
    local fw=11 f
    printf '  %s' "$(label "База:" 10)"
    for db in "${GC_DBS[@]}"; do colhead "${GC_DB_SHORT[$db]}" "$fw"; done; echo
    printf '  %s' "$(label "Регион:" 10)"
    for db in "${GC_DBS[@]}"; do
        t="${G[$db.cc]:-}"
        if [[ -z "$t" ]]; then badge none "—" "$fw"
        elif [[ -n "$cc" && "$t" != "$cc" ]]; then badge warn "[$t]" "$fw"
        else badge ok "[$t]" "$fw"; fi
    done; echo
    for f in "proxy:Прокси" "tor:Tor" "vpn:VPN" "server:Сервер" "abuser:Абьюзер" "robot:Бот"; do
        k="${f%%:*}"; printf '  %s' "$(label "${f#*:}:" 10)"
        for db in "${GC_DBS[@]}"; do yn_badge "${G[$db.$k]:-}" "$fw"; done; echo
    done

    if [[ "$self" == yes ]]; then
        # ===== 5. сервисы =====
        section "5. Доступность медиа- и AI-сервисов"
        local sw=12 grp g r
        for grp in "tiktok netflix youtube prime" "reddit chatgpt claude gemini"; do
            printf '  %s' "$(label "Сервис:" 10)"
            for s in $grp; do colhead "${GC_SVC_TITLE[$s]}" "$sw"; done; echo
            printf '  %s' "$(label "Статус:" 10)"
            for s in $grp; do
                IFS='|' read -r g r < "$tmp/svc_$s"
                case "$g" in ok) badge ok "Да" "$sw";; warn) badge warn "Частично" "$sw";; bad) badge bad "Блок" "$sw";; *) badge none "?" "$sw";; esac
            done; echo
            printf '  %s' "$(label "Регион:" 10)"
            for s in $grp; do
                IFS='|' read -r g r < "$tmp/svc_$s"
                if [[ -z "$r" ]]; then badge none "" "$sw"
                elif [[ -n "$cc" && "$r" != "$cc" ]]; then badge warn "[$r]" "$sw"
                else badge ok "[$r]" "$sw"; fi
            done; echo
        done

        # ===== 6. почта =====
        section "6. Почта: порт 25 и чёрные списки"
        local m name ok25=0
        for m in "${GC_MX[@]}"; do [[ "$(cat "$tmp/mx/${m%%:*}" 2>/dev/null)" == ok ]] && ok25=1; done
        printf '  %s ' "$(label "Исходящий порт 25:" 20)"
        if (( ok25 )); then badge ok "открыт"; else badge bad "закрыт провайдером"; fi; echo
        printf '  %s ' "$(label "Подключение:" 20)"
        for m in "${GC_MX[@]}"; do
            name="${m%%:*}"
            if [[ "$(cat "$tmp/mx/$name" 2>/dev/null)" == ok ]]; then badge ok "$name"; else badge bad "$name"; fi
            printf ' '
        done; echo
        if [[ -d "$tmp/bl" ]] && is_ipv4 "$ip"; then
            local clean=0 listed=0 errs=0 lst=() z
            for z in "${GC_DNSBL[@]}"; do
                case "$(cat "$tmp/bl/$z" 2>/dev/null)" in
                    clean) clean=$((clean + 1));; listed) listed=$((listed + 1)); lst+=("$z");; *) errs=$((errs + 1));;
                esac
            done
            printf '  %s Проверено %s%d%s  Чисто %s%d%s  В списках %s%d%s  Нет данных %s%d%s\n' "$(label "DNSBL:" 20)" \
                "$C_BOLD" "${#GC_DNSBL[@]}" "$C_RESET" "$T_GREEN" "$clean" "$C_RESET" "$T_RED" "$listed" "$C_RESET" "$C_GRAY" "$errs" "$C_RESET"
            ((${#lst[@]})) && printf '  %s %s%s%s\n' "$(label "" 20)" "$T_RED" "${lst[*]}" "$C_RESET"
        fi
    else
        echo; info "Разделы 5–6 (сервисы и почта) проверяются только для IP этого сервера."
    fi
    echo "$C_GRAY$eq$C_RESET"

    # вывод для ноды VPN
    local flags=()
    for db in "${GC_DBS[@]}"; do
        [[ "${G[$db.vpn]:-}" == true || "${G[$db.proxy]:-}" == true ]] && flags+=("${GC_DB_TITLE[$db]}")
    done
    if ((${#flags[@]})); then
        warn "IP помечен как VPN/прокси: ${flags[*]}. Сервисы, которые опираются на эти базы, могут ограничивать клиентов ноды."
    else
        ok "Ни одна база не считает этот IP VPN/прокси."
    fi
}

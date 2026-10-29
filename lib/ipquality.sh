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
GC_DBS=(ipinfo ipregistry ipapi proxycheck scamalytics ip2loc abuseipdb dbip)
# короткие имена для узких колонок таблицы
declare -A GC_DB_SHORT=([ipinfo]=IPinfo [ipregistry]=ipregistry [ipapi]=ip-api [proxycheck]=proxycheck [scamalytics]=Scamalyt. [ip2loc]=IP2Loc [abuseipdb]=AbuseIPDB [dbip]=DB-IP)
declare -A GC_DB_TITLE=([ipinfo]=IPinfo [ipregistry]=ipregistry [ipapi]=ip-api [proxycheck]=proxycheck [scamalytics]=Scamalytics [ip2loc]=IP2Location [abuseipdb]=AbuseIPDB [dbip]=DB-IP)

_gc() { curl -4 -sS --max-time 12 -A "$UA_BROWSER" "$@" 2>/dev/null; }
_gcv() { local v="$1"; shift; curl "-$v" -sS --max-time 12 -A "$UA_BROWSER" "$@" 2>/dev/null; }   # через IPv4 или IPv6

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
gc_section() { printf '%s%s%s\n' "$C_BOLD$C_WHITE" "$1" "$C_RESET"; }

usage_ru() {   # тип сети -> "текст вид"
    # коды IP2Location: ISP MOB DCH COM ORG GOV MIL EDU LIB CDN SES RSV (бывают составные: ISP/MOB)
    case "${1^^}" in
        DCH) set -- hosting;; MOB|ISP/MOB) set -- mobile;; ISP|FIXED\ LINE\ ISP) set -- isp;; COM|COMMERCIAL) set -- business;;
        EDU|UNIVERSITY/COLLEGE/SCHOOL) set -- education;; GOV|GOVERNMENT|MIL|MILITARY) set -- government;;
        CDN|"CONTENT DELIVERY NETWORK") set -- cdn;; SES|"SEARCH ENGINE SPIDER") set -- robot;; "MOBILE ISP") set -- mobile;;
        "DATA CENTER/WEB HOSTING/TRANSIT") set -- hosting;; ORG|ORGANIZATION|LIB|LIBRARY) set -- organization;; RSV|RESERVED) set -- reserved;;
    esac
    case "${1,,}" in
        organization) echo "Организация ok";;
        robot) echo "Поисковик warn";;
        reserved) echo "Резерв warn";;
        nokey) echo "нужен_ключ none";;
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
    ( _gc -L "https://www.ip2location.com/$ip" > "$d/ip2loc" ) &
    if [[ -n "${ABUSEIPDB_KEY:-}" ]]; then
        ( _gc -G "https://api.abuseipdb.com/api/v2/check" --data-urlencode "ipAddress=$ip" -d maxAgeInDays=90 \
              -H "Key: $ABUSEIPDB_KEY" -H 'Accept: application/json' > "$d/abuseipdb" ) &
    fi
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
    j=""; [[ -f "$d/scamalytics" ]] && j=$(tr '\n' ' ' < "$d/scamalytics")
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
    # IP2Location: публичная страница (тип использования, тип прокси, fraud score)
    j=$(sed 's/<[^>]*>/ /g; s/&nbsp;/ /g' "$d/ip2loc" 2>/dev/null | tr -s ' \t\n' ' ')
    if [[ "$j" =~ Usage\ Type\ \(([A-Z/]+)\) ]]; then
        G[ip2loc.asntype]="${BASH_REMATCH[1]}"
        [[ "$j" =~ Country\ [^[]*\[([A-Z]{2})\] ]] && G[ip2loc.cc]="${BASH_REMATCH[1]}"
        [[ "$j" =~ Fraud\ Score\ ([0-9]+) ]] && G[ip2loc.risk]="${BASH_REMATCH[1]}"
        local pt=""; [[ "$j" =~ Proxy\ Type\ ([A-Z]{2,4}|-) ]] && pt="${BASH_REMATCH[1]}"
        G[ip2loc.vpn]=$([[ "$pt" == VPN ]] && echo true || echo false)
        G[ip2loc.tor]=$([[ "$pt" == TOR ]] && echo true || echo false)
        G[ip2loc.proxy]=$([[ "$pt" =~ ^(PUB|WEB|RES|CPN|EPN)$ ]] && echo true || echo false)
        G[ip2loc.server]=$([[ "$pt" == DCH || "${G[ip2loc.asntype]}" == DCH ]] && echo true || echo false)
        G[ip2loc.robot]=$([[ "$pt" == SES ]] && echo true || echo false)
    fi
    # AbuseIPDB: только с ключом (страница закрыта проверкой Cloudflare)
    if [[ -z "${ABUSEIPDB_KEY:-}" ]]; then
        G[abuseipdb.asntype]=nokey
    else
        j=$(cat "$d/abuseipdb" 2>/dev/null)
        if jq -e .data.ipAddress >/dev/null 2>&1 <<<"$j"; then
            eval "$(jq -r '.data | @sh "
                G[abuseipdb.cc]=\(.countryCode // "")
                G[abuseipdb.asntype]=\(.usageType // "")
                G[abuseipdb.risk]=\(.abuseConfidenceScore // "")
                G[abuseipdb.tor]=\(.isTor // false)
                G[abuseipdb.abuser]=\((.abuseConfidenceScore // 0) >= 25)
                G[abuseipdb.server]=\((.usageType // "") | test("Data Center|Hosting"))
                G[abuseipdb.robot]=\((.usageType // "") | test("Spider"))
                G[abuseipdb.reports]=\(.totalReports // 0)"' <<<"$j")"
        fi
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

gc_service() {   # сервис [4|6]
    local s="$1" v="${2:-4}" body code r
    case "$s" in
        tiktok)
            body=$(_gcv "$v" -L "https://www.tiktok.com/explore")
            r=$(grep -oE '"region":"[A-Z]{2}"' <<<"$body" | head -1 | cut -d'"' -f4)
            if [[ -n "$r" ]]; then echo "ok|$r"; elif [[ -n "$body" ]]; then echo "bad|"; else echo "none|"; fi;;
        netflix)
            local a b
            a=$(_gcv "$v" -L -o /dev/null -w '%{http_code} %{url_effective}' "https://www.netflix.com/title/81280792")
            b=$(_gcv "$v" -L -o /dev/null -w '%{http_code}' "https://www.netflix.com/title/70143836")
            r=$(grep -oE 'netflix\.com/[a-z]{2}(-[a-z]{2})?/' <<<"$a" | sed -E 's#netflix\.com/([a-z]{2}).*#\1#' | tr '[:lower:]' '[:upper:]')
            if [[ "${a%% *}" == 200 && "$b" == 200 ]]; then echo "ok|${r:-US}"
            elif [[ "${a%% *}" == 200 || "$b" == 200 ]]; then echo "warn|$r"
            elif [[ "${a%% *}" == 403 ]]; then echo "bad|"
            else echo "none|"; fi;;
        youtube)
            body=$(_gcv "$v" -L -H 'Accept-Language: en' -b 'SOCS=CAI; CONSENT=YES+' "https://www.youtube.com/premium")
            r=$(grep -oE '"GL":"[A-Z]{2}"' <<<"$body" | head -1 | cut -d'"' -f4)
            if [[ -z "$body" ]]; then echo "none|"
            elif grep -q 'www.google.cn' <<<"$body"; then echo "bad|CN"
            elif grep -qi 'Premium is not available in your country' <<<"$body"; then echo "bad|$r"
            else echo "ok|$r"; fi;;
        prime)
            body=$(_gcv "$v" -L "https://www.primevideo.com")
            r=$(grep -oE '"currentTerritory":"[A-Z]{2}"' <<<"$body" | head -1 | cut -d'"' -f4)
            if grep -q '"isServiceRestricted":true' <<<"$body"; then echo "bad|"
            elif [[ -n "$r" ]]; then echo "ok|$r"; else echo "none|"; fi;;
        reddit)
            code=$(_gcv "$v" -o /dev/null -w '%{http_code}' "https://www.reddit.com/")
            case "$code" in 200|301|302) echo "ok|";; 403|429) echo "bad|";; *) echo "none|";; esac;;
        chatgpt)
            local c i
            c=$(_gcv "$v" "https://api.openai.com/compliance/cookie_requirements")
            i=$(_gcv "$v" "https://ios.chat.openai.com/")
            r=$(_gcv "$v" "https://chat.openai.com/cdn-cgi/trace" | sed -n 's/^loc=//p')
            if [[ -z "$c$i" ]]; then echo "none|$r"
            elif grep -q 'unsupported_country' <<<"$c" || grep -q 'VPN' <<<"$i"; then echo "bad|$r"
            else echo "ok|$r"; fi;;
        claude)
            r=$(_gcv "$v" -o /dev/null -w '%{http_code} %{redirect_url}' "https://claude.ai/")
            if [[ "$r" == *unavailable* ]]; then echo "bad|"
            elif [[ "$r" == 2* || "$r" == 3* ]]; then echo "ok|"; else echo "none|"; fi;;
        gemini)
            body=$(_gcv "$v" "https://gemini.google.com")
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
# Разделы 1–4 для одного IP (данные — в G, объявленном вызывающим)
gc_report_ip() {   # ip метка
    local ip="$1" tag="$2" db t k
    local cc="${G[ipinfo.cc]:-${G[ipregistry.cc]:-${G[dbip.cc]:-}}}"
    local country="${G[ipregistry.country]:-${G[dbip.country]:-}}"
    GC_LAST_CC="$cc"
    printf '\n%s━━ %s: %s%s%s ━━%s\n' "$C_BOLD$C_MAGENTA" "$tag" "$C_CYAN" "$ip" "$C_BOLD$C_MAGENTA" "$C_RESET"

    # ===== 1. основное =====
    gc_section "1. Основная информация"
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
    gc_section "2. Тип IP (как его классифицируют базы)"
    local cw=12 types=(ipinfo ipregistry ipapi proxycheck ip2loc abuseipdb)
    printf '  %s' "$(label "База:" 10)"
    for db in "${types[@]}"; do colhead "${GC_DB_SHORT[$db]}" "$cw"; done; echo
    printf '  %s' "$(label "Сеть:" 10)"
    for db in "${types[@]}"; do
        if [[ "$db" == proxycheck ]]; then t="${G[proxycheck.type]:-}"; else t="${G[$db.asntype]:-}"; fi
        read -r t k <<<"$(usage_ru "$t")"; badge "$k" "${t//_/ }" "$cw"
    done; echo
    printf '  %s' "$(label "Компания:" 10)"
    for db in ipinfo ipregistry; do read -r t k <<<"$(usage_ru "${G[$db.comptype]:-}")"; badge "$k" "$t" "$cw"; done; echo

    # ===== 3. оценка риска =====
    gc_section "3. Оценка риска"
    printf '  %s %s\n' "$(label "Шкала:" 14)" "$(risk_bar 100)"
    printf '  %s %s%s%s%s%s%s%s%s%s\n' "$(label "" 14)" "$T_GREEN" "$(pad низкий 8)" "$C_RESET" "$T_YELLOW" "$(pad средний 16)" "$C_RESET" "$T_RED" "высокий" "$C_RESET"
    local src score
    for src in proxycheck scamalytics ip2loc abuseipdb; do
        score="${G[$src.risk]:-}"
        if [[ "$src" == abuseipdb && -z "${ABUSEIPDB_KEY:-}" ]]; then
            printf '  %s %sнужен бесплатный ключ: fail2detect config ABUSEIPDB_KEY <ключ>%s\n' "$(label "${GC_DB_TITLE[$src]}:" 14)" "$C_GRAY" "$C_RESET"
            continue
        fi
        read -r t k <<<"$(risk_level "$score")"
        local extra=""; [[ "$src" == abuseipdb && -n "${G[abuseipdb.reports]:-}" ]] && extra=" ${C_GRAY}жалоб: ${G[abuseipdb.reports]}${C_RESET}"
        printf '  %s %s %3s %s%s\n' "$(label "${GC_DB_TITLE[$src]}:" 14)" "$(risk_bar "${score:-0}")" "${score:-—}" "$(badge "$k" "${t//_/ }")" "$extra"
    done

    # ===== 4. факторы риска =====
    gc_section "4. Факторы риска"
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

    # кто считает IP VPN/прокси — копим для итога
    for db in "${GC_DBS[@]}"; do
        [[ "${G[$db.vpn]:-}" == true || "${G[$db.proxy]:-}" == true ]] && GC_FLAGS+=("${GC_DB_TITLE[$db]} ($tag)")
    done
    return 0
}

ipquality_run() {   # [ip]
    have jq || die "Нужен jq"
    local self=no targets=() tags=() v4 v6
    if [[ -n "${1:-}" ]]; then
        is_ip "$1" || die "Неверный IP: $1"
        targets=("$1"); tags=("$([[ "$1" == *:* ]] && echo IPv6 || echo IPv4)")
    else
        self=yes
        v4=$(curl -4 -sS --max-time 6 https://api.ipify.org 2>/dev/null)
        v6=$(curl -6 -sS --max-time 6 https://api6.ipify.org 2>/dev/null)
        is_ipv4 "$v4" && { targets+=("$v4"); tags+=(IPv4); }
        [[ "$v6" == *:* ]] && { targets+=("$v6"); tags+=(IPv6); }
        ((${#targets[@]})) || die "Не удалось определить IP сервера"
    fi
    local tmp; tmp=$(mktemp -d)
    _ipquality_report "$tmp" || true
    rm -rf "$tmp"
}

# отчёт по уже собранным целям (targets/tags — из ipquality_run); каталог — временный
_ipquality_report() {
    local tmp="$1"

    local i s vers=()
    for i in "${!targets[@]}"; do mkdir -p "$tmp/$i"; gc_fetch_dbs "$tmp/$i" "${targets[i]}"; done
    if [[ "$self" == yes ]]; then
        [[ -n "${v4:-}" ]] && is_ipv4 "$v4" && vers+=(4)
        [[ "${v6:-}" == *:* ]] && vers+=(6)
        for v in "${vers[@]}"; do
            for s in "${GC_SERVICES[@]}"; do ( gc_service "$s" "$v" > "$tmp/svc_${s}_$v" ) & done
        done
        is_ipv4 "${v4:-}" && gc_fetch_mail "$tmp" "$v4"
    fi
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' n=0
    while [[ -n "$(jobs -rp)" ]]; do
        [[ -t 1 ]] && printf '\r  %s%s%s Опрашиваю базы и сервисы…' "$C_CYAN" "${spin:n++%10:1}" "$C_RESET"
        sleep 0.15
    done
    [[ -t 1 ]] && printf '\r\033[K'

    local W=78 sharp eq
    sharp=$(printf '%*s' "$W" '' | tr ' ' '#'); eq=$(printf '%*s' "$W" '' | tr ' ' '=')
    echo "$C_GRAY$sharp$C_RESET"
    printf '%*s%s\n' 22 "" "${C_BOLD}ОТЧЁТ О КАЧЕСТВЕ IP${C_RESET}  ${C_CYAN}${targets[*]}${C_RESET}"
    printf '%*s%s\n' 16 "" "${C_GRAY}fail2detect · по мотивам github.com/xykt/IPQuality${C_RESET}"
    printf '%*s%s\n' 20 "" "Время отчёта: $(date -u '+%Y-%m-%d %H:%M:%S') UTC"
    echo "$C_GRAY$sharp$C_RESET"

    GC_FLAGS=()
    for i in "${!targets[@]}"; do
        local -A G=()
        gc_parse "$tmp/$i" "${targets[i]}"
        gc_report_ip "${targets[i]}" "${tags[i]}"
        unset G
    done

    if [[ "$self" == yes ]]; then
        # ===== 5. сервисы (по IPv4 и IPv6) =====
        printf '\n'; gc_section "5. Доступность медиа- и AI-сервисов"
        local sw=12 grp g r
        for grp in "tiktok netflix youtube prime" "reddit chatgpt claude gemini"; do
            printf '  %s' "$(label "Сервис:" 10)"
            for s in $grp; do colhead "${GC_SVC_TITLE[$s]}" "$sw"; done; echo
            for v in "${vers[@]}"; do
                printf '  %s' "$(label "IPv$v:" 10)"
                for s in $grp; do
                    IFS='|' read -r g r < "$tmp/svc_${s}_$v"
                    case "$g" in ok) badge ok "Да${r:+ $r}" "$sw";; warn) badge warn "Частично${r:+ $r}" "$sw";;
                                 bad) badge bad "Блок${r:+ $r}" "$sw";; *) badge none "?" "$sw";; esac
                done; echo
            done
        done

        # ===== 6. почта (IPv4) =====
        if is_ipv4 "${v4:-}"; then
            gc_section "6. Почта: порт 25 и чёрные списки (IPv4)"
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

    if ((${#GC_FLAGS[@]})); then
        warn "IP помечен как VPN/прокси: ${GC_FLAGS[*]}. Сервисы, которые опираются на эти базы, могут ограничивать клиентов ноды."
    else
        ok "Ни одна база не считает IP VPN/прокси."
    fi
    [[ -z "${ABUSEIPDB_KEY:-}" ]] && info "AbuseIPDB: бесплатный ключ — abuseipdb.com → Account → API, затем: fail2detect config ABUSEIPDB_KEY <ключ>"
}

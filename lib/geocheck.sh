#!/usr/bin/env bash
# fail2detect — GeoCheck: в какой стране этот IP видят сервисы, CDN и гео-базы.
#
# Каждый сервис сам решает, «откуда» пришёл клиент: у одних это MaxMind, у
# других своя база, у третьих — регион аккаунта или ближайший узел CDN. Если
# хоть один важный сервис видит не ту страну, что остальные, клиенты ноды
# получат чужой регион (каталог, цены, блокировки).
#
# Способы узнать регион у сервисов (публичные эндпоинты и публичные ключи
# веб-клиентов) взяты из ipregion — https://github.com/vernette/ipregion
# (MIT, © vernette). Код написан заново.

GR_UA="Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
GR_NA="N/A"; GR_DENIED="Отказано"; GR_RATE="Лимит"; GR_ERR="Ошибка"

# публичные ключи веб-клиентов сервисов (как в ipregion)
GR_SPOTIFY_KEY="142b583129b2df829de3656f9eb484e6"
GR_SPOTIFY_CLIENT="9a8d2f0ce77a4e248bb71fefcb557637"
GR_NETFLIX_TOKEN="YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm"
GR_TWITCH_CLIENT="kimne78kx3ncx6brgo4mv6wki5h1ko"
GR_CHATGPT_KEY="client-zUdXdSTygXJdzoE0sWTkP8GKTVsUMF2IRM7ShVO2JAG"
GR_REDDIT_BASIC="b2hYcG9xclpZdWIxa2c6"
GR_DISNEY_KEY="ZGlzbmV5JmFuZHJvaWQmMS4wLjA.bkeb0m230uUhv8qrAXuNu39tbE_mD5EEhM_NAcohjyA"
# shellcheck disable=SC2016  # $registerDevice — переменная GraphQL, не bash
GR_DISNEY_BODY='{"query":"mutation registerDevice($registerDevice: RegisterDeviceInput!) { registerDevice(registerDevice: $registerDevice) { __typename } }","variables":{"registerDevice":{"applicationRuntime":"android","attributes":{"operatingSystem":"Android","operatingSystemVersion":"13"},"deviceFamily":"android","deviceLanguage":"en","deviceProfile":"phone","devicePlatformId":"android"}},"operationName":"registerDevice"}'
GR_YT_SOCS="CAISNQgDEitib3FfaWRlbnRpdHlmcm9udGVuZHVpc2VydmVyXzIwMjUwNzMwLjA1X3AwGgJlbiACGgYIgPC_xAY"
GR_GEOAPIFY_KEY="b8568cb9afc64fad861a69edbddb2658"
GR_IPREGISTRY_KEY="sb69ksjcajfs4c"
GR_APC_AUTH="96dc04b3fb"

# ---------- HTTP ----------
# gr_req ipver [curl-аргументы…] -> тело ответа; при ошибке — маркер статуса
gr_req() {
    local v="$1"; shift
    local out code
    out=$(curl "-$v" -sS -L --max-time 10 --retry 1 -A "$GR_UA" -w $'\n%{http_code}' "$@" 2>/dev/null) || true
    code="${out##*$'\n'}"; out="${out%$'\n'*}"
    case "$code" in
        403) echo "@$GR_DENIED";;
        429) echo "@$GR_RATE";;
        5??) echo "@$GR_ERR";;
        000|"") echo "@";;
        *) printf '%s' "$out";;
    esac
}
# достать поле из JSON; маркеры статуса пропускаем как есть
gr_json() {   # фильтр
    local body; body=$(cat)
    [[ "$body" == @* ]] && { echo "$body"; return; }
    jq -r "$1 // empty" <<<"$body" 2>/dev/null | head -1
}
gr_grep() {   # регулярка perl с одной группой — печатает первую группу
    local body; body=$(cat)
    [[ "$body" == @* ]] && { echo "$body"; return; }
    perl -ne "if (/$1/) { print \"\$1\\n\"; exit }" <<<"$body" 2>/dev/null
}

# ---------- популярные сервисы: печатают код страны, Да/Нет или маркер ----------
GR_SERVICES=(google youtube twitch chatgpt netflix spotify reddit disney gemini reddit_guest youtube_premium
             google_captcha spotify_signup disney_access apple steam tiktok ookla jetbrains playstation microsoft)
declare -A GR_SERVICE_TITLE=([google]="Google" [youtube]="YouTube" [twitch]="Twitch" [chatgpt]="ChatGPT" [netflix]="Netflix"
    [spotify]="Spotify" [reddit]="Reddit" [disney]="Disney+" [gemini]="Gemini (доступен)" [reddit_guest]="Reddit (без входа)"
    [youtube_premium]="YouTube Premium" [google_captcha]="Google: капча" [spotify_signup]="Spotify: регистрация"
    [disney_access]="Disney+: доступ" [apple]="Apple" [steam]="Steam" [tiktok]="TikTok" [ookla]="Ookla Speedtest"
    [jetbrains]="JetBrains" [playstation]="PlayStation" [microsoft]="Microsoft")

gr_yes_no() { [[ "$1" == @* ]] && { echo "$1"; return; }; [[ "$1" == yes ]] && echo "Да" || echo "Нет"; }

gr_svc() {   # сервис ipver
    local s="$1" v="$2" r t
    case "$s" in
        google) gr_req "$v" "https://accounts.google.com/v3/signin/identifier?flowName=GlifSetupAndroid" | gr_grep 'name="region" value="([^"]*)"';;
        youtube) r=$(gr_req "$v" "https://www.youtube.com/sw.js_data"); [[ "$r" == @* ]] && echo "$r" || tail -n +3 <<<"$r" | gr_json '.[0][2][0][0][1]';;
        twitch) gr_req "$v" -X POST "https://gql.twitch.tv/gql" -H "Client-Id: $GR_TWITCH_CLIENT" -H 'Content-Type: application/json' \
                    --data '[{"operationName":"VerifyEmail_CurrentUser","variables":{},"extensions":{"persistedQuery":{"version":1,"sha256Hash":"f9e7dcdf7e99c314c82d8f7f725fab5f99d1df3d7359b53c9ae122deec590198"}}}]' \
                    | gr_json '.[0].data.requestInfo.countryCode';;
        chatgpt) gr_req "$v" -X POST "https://ab.chatgpt.com/v1/initialize" -H "Statsig-Api-Key: $GR_CHATGPT_KEY" | gr_json '.derived_fields.country';;
        netflix) gr_req "$v" "https://api.fast.com/netflix/speedtest/v2?https=true&token=$GR_NETFLIX_TOKEN&urlCount=1" | gr_json '.client.location.country';;
        spotify) gr_req "$v" "https://spclient.wg.spotify.com/signup/public/v1/account/?validate=1&key=$GR_SPOTIFY_KEY" -H "X-Client-Id: $GR_SPOTIFY_CLIENT" | gr_json '.country';;
        spotify_signup)
            r=$(gr_req "$v" "https://spclient.wg.spotify.com/signup/public/v1/account/?validate=1&key=$GR_SPOTIFY_KEY" -H "X-Client-Id: $GR_SPOTIFY_CLIENT")
            [[ "$r" == @* ]] && { echo "$r"; return; }
            t=$(jq -r '"\(.status)|\(.is_country_launched)"' <<<"$r" 2>/dev/null)
            [[ -z "$t" ]] && { echo "@"; return; }
            [[ "$t" =~ ^(120|320)\| || "$t" == *"|false" ]] && echo "Нет" || echo "Да";;
        reddit)
            local tok ua="Reddit/Version 2025.29.0/Build 2529021/Android 13"
            tok=$(gr_req "$v" -X POST "https://www.reddit.com/auth/v2/oauth/access-token/loid" -A "$ua" \
                -H "Authorization: Basic $GR_REDDIT_BASIC" -H 'Content-Type: application/json' --data '{"scopes":["email"]}' | gr_json '.access_token')
            [[ -z "$tok" || "$tok" == @* ]] && { echo "${tok:-@}"; return; }
            gr_req "$v" -X POST "https://gql-fed.reddit.com" -A "$ua" -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' \
                --data '{"operationName":"UserLocation","variables":{},"extensions":{"persistedQuery":{"version":1,"sha256Hash":"f07de258c54537e24d7856080f662c1b1268210251e5789c8c08f20d76cc8ab2"}}}' \
                | gr_json '.data.userLocation.countryCode';;
        reddit_guest) r=$(gr_req "$v" "https://www.reddit.com"); [[ "$r" == "@$GR_DENIED" ]] && echo "Нет" || { [[ "$r" == @ ]] && echo "@" || echo "Да"; };;
        disney) gr_req "$v" -X POST "https://disney.api.edge.bamgrid.com/graph/v1/device/graphql" -H "Authorization: Bearer $GR_DISNEY_KEY" \
                    -H 'Content-Type: application/json' --data "$GR_DISNEY_BODY" | gr_json '.extensions.sdk.session.location.countryCode';;
        disney_access)
            r=$(gr_req "$v" -X POST "https://disney.api.edge.bamgrid.com/graph/v1/device/graphql" -H "Authorization: Bearer $GR_DISNEY_KEY" \
                -H 'Content-Type: application/json' --data "$GR_DISNEY_BODY")
            [[ "$r" == @* ]] && { echo "$r"; return; }
            [[ "$(jq -r '((.errors // []) | length == 0) and (.extensions.sdk.session.inSupportedLocation == true)' <<<"$r" 2>/dev/null)" == true ]] && echo "Да" || echo "Нет";;
        gemini)
            local cc; cc=$(gr_svc google "$v")
            [[ -z "$cc" || "$cc" == @* ]] && { echo "${cc:-@}"; return; }
            gr_gemini_supported "$cc";;
        youtube_premium)
            r=$(gr_req "$v" "https://www.youtube.com/premium" -H "Cookie: SOCS=$GR_YT_SOCS" -H 'Accept-Language: en-US,en;q=0.9')
            [[ "$r" == @* ]] && { echo "$r"; return; }
            grep -qi 'youtube premium is not available in your country' <<<"$r" && echo "Нет" || echo "Да";;
        google_captcha)
            r=$(gr_req "$v" "https://www.google.com/search?q=cats" -H 'Accept-Language: en-US,en;q=0.9')
            [[ "$r" == @* ]] && { echo "$r"; return; }
            grep -qiE 'unusual traffic from|is blocked|unaddressed abuse' <<<"$r" && echo "Капча" || echo "Нет";;
        apple) r=$(gr_req "$v" "https://gspe1-ssl.ls.apple.com/pep/gcc"); [[ "$r" =~ ^[A-Z]{2}$ || "$r" == @* ]] && echo "$r";;
        steam) curl "-$v" -sS -I --max-time 10 -A "$GR_UA" "https://store.steampowered.com" 2>/dev/null | gr_grep 'steamCountry=([^%;]*)';;
        tiktok) gr_req "$v" "https://www.tiktok.com/api/v1/web-cookie-privacy/config?appId=1988" | gr_json '.body.appProps.region';;
        ookla) gr_req "$v" "https://www.speedtest.net/api/js/config-sdk" | gr_json '.location.countryCode';;
        jetbrains) gr_req "$v" "https://data.services.jetbrains.com/geo" | gr_json '.code';;
        playstation) curl "-$v" -sS -I --max-time 10 -A "$GR_UA" "https://www.playstation.com" 2>/dev/null | gr_grep 'country=([^;\s]*)';;
        microsoft) gr_req "$v" "https://login.live.com" | gr_grep '"sRequestCountry":"([^"]*)"';;
    esac
}

# Gemini: есть ли страна в официальном списке регионов Google AI
gr_gemini_supported() {   # cc
    local cc="$1" md names n
    md=$(curl -sS --max-time 10 "https://ai.google.dev/gemini-api/docs/available-regions.md.txt" 2>/dev/null)
    [[ -z "$md" ]] && { echo "@"; return; }
    names=$(curl -sS --max-time 10 "https://cdn.jsdelivr.net/npm/cldr-localenames-full/main/en/territories.json" 2>/dev/null \
        | jq -r --arg c "$cc" '.main.en.localeDisplayNames.territories | to_entries[] | select(.key | startswith($c)) | .value' 2>/dev/null)
    [[ -z "$names" ]] && { echo "@"; return; }
    while IFS= read -r n; do
        grep -qiF -- "- $n" <<<"$md" && { echo "Да"; return; }
    done <<<"$names"
    echo "Нет"
}

# ---------- CDN ----------
GR_CDN=(cloudflare youtube netflix)
declare -A GR_CDN_TITLE=([cloudflare]="Cloudflare CDN" [youtube]="YouTube CDN" [netflix]="Netflix CDN")

gr_iata_country() {   # IATA -> ISO страны (кэш на время отчёта)
    local iata="$1" f="$GR_TMP/iata_$1"
    [[ -s "$f" ]] && { cat "$f"; return; }
    curl -sS --max-time 10 -X POST "https://www.air-port-codes.com/api/v1/single" -H "APC-Auth: $GR_APC_AUTH" \
        -H 'Referer: https://www.air-port-codes.com/' --data "iata=$iata" 2>/dev/null | jq -r '.airport.country.iso // empty' | tee "$f"
}

gr_cdn() {   # cdn ipver
    local c="$1" v="$2" r iata cc
    case "$c" in
        cloudflare)
            r=$(gr_req "$v" "https://speed.cloudflare.com/meta" -H 'Referer: https://speed.cloudflare.com')
            [[ "$r" == @* ]] && { echo "$r"; return; }
            iata=$(jq -r '.colo.iata // .colo // empty' <<<"$r" 2>/dev/null); cc=$(jq -r '.colo.cca2 // empty' <<<"$r" 2>/dev/null)
            [[ -n "$iata" ]] && echo "${cc:-?} ($iata)";;
        youtube)
            r=$(gr_req "$v" "https://redirector.googlevideo.com/report_mapping?di=no")
            [[ "$r" == @* ]] && { echo "$r"; return; }
            iata=$(awk '{print $3}' <<<"$r" | cut -f2 -d'-' | cut -c1-3 | tr '[:lower:]' '[:upper:]')
            [[ "$iata" =~ ^[A-Z]{3}$ ]] && echo "$(gr_iata_country "$iata") ($iata)";;
        netflix) gr_req "$v" "https://api.fast.com/netflix/speedtest/v2?https=true&token=$GR_NETFLIX_TOKEN&urlCount=1" | gr_json '.targets[0].location.country';;
    esac
}

# ---------- гео-базы ----------
GR_GEOIP=(maxmind ripe ipinfo cloudflare ipregistry ipapi_co ifconfig ip2location iplocation country_is geoapify geojs ipapi_is ipbase ipquery ipwho ip_api)
declare -A GR_GEOIP_TITLE=([maxmind]="maxmind.com" [ripe]="rdap.db.ripe.net" [ipinfo]="ipinfo.io" [cloudflare]="cloudflare.com"
    [ipregistry]="ipregistry.co" [ipapi_co]="ipapi.co" [ifconfig]="ifconfig.co" [ip2location]="ip2location.io" [iplocation]="iplocation.com"
    [country_is]="country.is" [geoapify]="geoapify.com" [geojs]="geojs.io" [ipapi_is]="ipapi.is" [ipbase]="ipbase.com"
    [ipquery]="ipquery.io" [ipwho]="ipwho.is" [ip_api]="ip-api.com")

gr_geoip() {   # база ipver ip
    local g="$1" v="$2" ip="$3"
    case "$g" in
        maxmind) gr_req "$v" "https://geoip.maxmind.com/geoip/v2.1/city/me" -H 'Referer: https://www.maxmind.com' | gr_json '.country.iso_code';;
        ripe) gr_req "$v" "https://rdap.db.ripe.net/ip/$ip" | gr_json '.country';;
        ipinfo) gr_req "$v" "https://ipinfo.io/widget/demo/$ip" | gr_json '.data.country';;
        cloudflare) gr_req "$v" "https://speed.cloudflare.com/meta" -H 'Referer: https://speed.cloudflare.com' | gr_json '.country';;
        ipregistry) gr_req "$v" "https://api.ipregistry.co/$ip?hostname=true&key=$GR_IPREGISTRY_KEY" -H 'Origin: https://ipregistry.co' | gr_json '.location.country.code';;
        ipapi_co) gr_req "$v" "https://ipapi.co/$ip/json" | gr_json '.country';;
        ifconfig) local r; r=$(gr_req "$v" "https://ifconfig.co/country-iso?ip=$ip"); r="${r//[$'\r\n ']/}"; [[ "$r" =~ ^[A-Z]{2}$ || "$r" == @* ]] && echo "$r";;
        ip2location) gr_req "$v" "https://api.ip2location.io/?ip=$ip" | gr_json '.country_code';;
        iplocation) gr_req "$v" -X POST "https://iplocation.com" --data "ip=$ip" | gr_json '.country_code';;
        country_is) gr_req "$v" "https://api.country.is/$ip" | gr_json '.country';;
        geoapify) gr_req "$v" "https://api.geoapify.com/v1/ipinfo?&ip=$ip&apiKey=$GR_GEOAPIFY_KEY" | gr_json '.country.iso_code';;
        geojs) gr_req "$v" "https://get.geojs.io/v1/ip/country.json?ip=$ip" | gr_json '.[0].country // .country';;
        ipapi_is) gr_req "$v" "https://api.ipapi.is/?q=$ip" | gr_json '.location.country_code';;
        ipbase) gr_req "$v" "https://api.ipbase.com/v2/info?ip=$ip" | gr_json '.data.location.country.alpha2';;
        ipquery) gr_req "$v" "https://api.ipquery.io/$ip" | gr_json '.location.country_code';;
        ipwho) gr_req "$v" "https://ipwho.is/$ip" | gr_json '.country_code';;
        ip_api) gr_req "$v" "http://ip-api.com/json/$ip?fields=countryCode" | gr_json '.countryCode';;
    esac
}

# ---------- вывод ----------
gr_pad() { local t="$1" w="$2"; printf '%s%*s' "$t" $(( w > ${#t} ? w - ${#t} : 0 )) ""; }

# раскрасить значение ячейки; эталонная страна — белым, другая — жёлтым
gr_cell() {   # значение ширина эталон
    local val="$1" w="$2" ref="${3:-}" col="$C_BOLD"
    [[ -z "$val" || "$val" == "@" ]] && val="$GR_NA"
    val="${val#@}"
    case "$val" in
        "$GR_NA") col="$C_GRAY";;
        "$GR_DENIED"|"$GR_ERR"|Нет|Капча) col="$C_RED";;
        "$GR_RATE") col="$C_YELLOW";;
        Да) col="$C_GREEN";;
        *) [[ -n "$ref" && "${val:0:2}" != "$ref" && "$val" =~ ^[A-Z]{2} ]] && col="$C_YELLOW";;
    esac
    [[ "$val" == Нет && "$4" == inverse ]] && col="$C_GREEN"   # «капчи нет» — хорошо
    printf '%s%s%s' "$col" "$(gr_pad "$val" "$w")" "$C_RESET"
}

gr_mask() {   # 78.135.77.114 -> 78.135.*.*, 2a01:f900:11:5::1 -> 2a01:f900:11::
    local ip="$1" p
    if [[ "$ip" == *:* ]]; then IFS=: read -ra p <<<"$ip"; echo "${p[0]}:${p[1]}:${p[2]}::"
    else echo "${ip%.*.*}.*.*"; fi
}

# Временный каталог убираем явно: «trap … RETURN» оставался висеть и срабатывал
# при выходе из ВЫЗВАВШЕЙ функции (меню), удаляя чужие каталоги.
geocheck_run() {
    local rc=0
    GR_TMP=$(mktemp -d)
    _geocheck_run "$@" || rc=$?
    rm -rf "$GR_TMP"; GR_TMP=""
    return "$rc"
}

_geocheck_run() {
    have jq || die "Нужен jq"
    local show_full=no; [[ "${1:-}" == --full ]] && show_full=yes
    local ip4 ip6 vers=()
    ip4=$(curl -4 -sS --max-time 6 https://api.ipify.org 2>/dev/null)
    ip6=$(curl -6 -sS --max-time 6 https://api6.ipify.org 2>/dev/null)
    is_ipv4 "$ip4" && vers+=(4) || ip4=""
    [[ "$ip6" == *:* ]] && vers+=(6) || ip6=""
    ((${#vers[@]})) || die "Нет доступа в интернет"

    # всё параллельно, результат — файлы <тип>_<имя>_<версия>
    local v s ipv
    for v in "${vers[@]}"; do
        [[ $v == 4 ]] && ipv="$ip4" || ipv="$ip6"
        for s in "${GR_SERVICES[@]}"; do ( gr_svc "$s" "$v" > "$GR_TMP/svc_${s}_$v" ) & done
        for s in "${GR_CDN[@]}"; do ( gr_cdn "$s" "$v" > "$GR_TMP/cdn_${s}_$v" ) & done
        for s in "${GR_GEOIP[@]}"; do ( gr_geoip "$s" "$v" "$ipv" > "$GR_TMP/geo_${s}_$v" ) & done
    done
    ( curl -sS --max-time 10 "https://ipinfo.io/widget/demo/${ip4:-$ip6}" > "$GR_TMP/asn" 2>/dev/null ) &
    ( curl -sS --max-time 10 "https://rdap.db.ripe.net/ip/${ip4:-$ip6}" > "$GR_TMP/rdap4" 2>/dev/null ) &
    [[ -n "$ip6" ]] && ( curl -sS --max-time 10 "https://rdap.db.ripe.net/ip/$ip6" > "$GR_TMP/rdap6" 2>/dev/null ) &
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' i=0
    while [[ -n "$(jobs -rp)" ]]; do
        [[ -t 1 ]] && printf '\r  %s%s%s Спрашиваю сервисы, где они «видят» этот IP…' "$C_CYAN" "${spin:i++%10:1}" "$C_RESET"
        sleep 0.15
    done
    [[ -t 1 ]] && printf '\r\033[K'

    # шапка
    local reg4 reg6 asn
    reg4=$(jq -r '.country // empty' "$GR_TMP/rdap4" 2>/dev/null)
    reg6=$(jq -r '.country // empty' "$GR_TMP/rdap6" 2>/dev/null)
    asn=$(jq -r '.data.org // empty' "$GR_TMP/asn" 2>/dev/null)
    local s4="$ip4" s6="$ip6"
    [[ "$show_full" == no ]] && { [[ -n "$ip4" ]] && s4=$(gr_mask "$ip4"); [[ -n "$ip6" ]] && s6=$(gr_mask "$ip6"); }
    echo
    [[ -n "$ip4" ]] && printf '%sIPv4%s: %s%s%s, зарегистрирован в %s%s%s\n' "$C_CYAN" "$C_RESET" "$C_BOLD" "$s4" "$C_RESET" "$C_BOLD" "${reg4:-?}" "$C_RESET"
    [[ -n "$ip6" ]] && printf '%sIPv6%s: %s%s%s, зарегистрирован в %s%s%s\n' "$C_CYAN" "$C_RESET" "$C_BOLD" "$s6" "$C_RESET" "$C_BOLD" "${reg6:-?}" "$C_RESET"
    [[ -n "$ip6" ]] || printf '%sIPv6%s: %sнет%s\n' "$C_CYAN" "$C_RESET" "$C_GRAY" "$C_RESET"
    printf '%sASN%s: %s%s%s\n' "$C_CYAN" "$C_RESET" "$C_BOLD" "${asn:-?}" "$C_RESET"

    local ref="${reg4:-$reg6}" w1 w2=14
    gr_table() {   # заголовок префикс массив-имён массив-названий ширина_1
        local head="$1" pre="$2" w1="$5" name t val
        local -n names="$3" titles="$4"
        printf '\n%s%s%s\n\n' "$C_BOLD$C_CYAN" "$head" "$C_RESET"
        printf '%s%s%s%s%s\n' "$C_BOLD" "$(gr_pad "Сервис" "$w1")" "$(gr_pad IPv4 "$w2")" "IPv6" "$C_RESET"
        for name in "${names[@]}"; do
            t="${titles[$name]}"
            printf '%s%s%s' "$C_GREEN" "$(gr_pad "$t" "$w1")" "$C_RESET"
            for v in 4 6; do
                if [[ -f "$GR_TMP/${pre}_${name}_$v" ]]; then val=$(head -1 "$GR_TMP/${pre}_${name}_$v")
                else val="$GR_NA"; fi
                local inv=""; [[ "$name" == google_captcha ]] && inv=inverse
                gr_cell "$val" "$w2" "$ref" "$inv"
            done
            echo
        done
    }
    gr_table "Популярные сервисы" svc GR_SERVICES GR_SERVICE_TITLE 24
    gr_table "CDN" cdn GR_CDN GR_CDN_TITLE 24
    gr_table "Гео-базы (GeoIP)" geo GR_GEOIP GR_GEOIP_TITLE 24

    # итог: кто видит не ту страну
    local odd=() f val
    for f in "$GR_TMP"/svc_*_4 "$GR_TMP"/geo_*_4; do
        val=$(head -1 "$f" 2>/dev/null)
        [[ "$val" =~ ^[A-Z]{2}$ && -n "$ref" && "$val" != "$ref" ]] || continue
        f="${f##*/}"; f="${f#*_}"; f="${f%_4}"
        odd+=("${GR_SERVICE_TITLE[$f]:-${GR_GEOIP_TITLE[$f]:-$f}}=$val")
    done
    echo
    if ((${#odd[@]})); then
        warn "Видят другую страну (не $ref): ${odd[*]}"
    else
        ok "Все ответившие сервисы видят страну ${ref:-?}"
    fi
    printf '%sСпособы определения регионов — github.com/vernette/ipregion (MIT)%s\n' "$C_GRAY" "$C_RESET"
}

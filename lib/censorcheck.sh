#!/usr/bin/env bash
# fail2detect — CensorCheck: что режет DPI (ТСПУ) на этом сервере.
#
# Список сайтов и логика HTTP/HTTPS-проверок — по мотивам censorcheck
# (vernette, MIT, режим --mode dpi), код свой. Сверх оригинала:
#   * DNS-подмена: системный ответ сверяется с DoH (Cloudflare, Google);
#   * причина обрыва TLS: тот же IP без SNI — прошло, значит DPI по SNI;
#   * стоп-страницы провайдеров на HTTP;
#   * контрольные сайты — если не открываются они, сеть сломана целиком;
#   * «обрыв после 16 КБ» до зарубежных хостингов: так ТСПУ режет VPS.

CC_SITES=(
    youtube.com 'redirector.googlevideo.com/report_mapping?di=no' discord.com instagram.com facebook.com x.com
    linkedin.com rutracker.org digitalocean.com amnezia.org getoutline.org mailfence.com flibusta.is rezka.ag
    api.telegram.org play.google.com github.com raw.githubusercontent.com
    torproject.org protonvpn.com signal.org whatsapp.com
)
CC_CONTROL=(ya.ru vk.com)
# имя|URL файла не меньше 128 КБ (поддерживает Range)
CC_HOSTINGS=(
    'Hetzner · Фалькенштайн|https://fsn1-speed.hetzner.com/100MB.bin'
    'Hetzner · Хельсинки|https://hel1-speed.hetzner.com/100MB.bin'
    'DigitalOcean · Амстердам|https://speedtest-ams2.digitalocean.com/10mb.test'
    'DigitalOcean · Франкфурт|https://speedtest-fra1.digitalocean.com/10mb.test'
    'OVH · Рубе|https://proof.ovh.net/files/10Mb.dat'
    'Linode · Франкфурт|https://speedtest.frankfurt.linode.com/100MB-frankfurt.bin'
    'Vultr · Амстердам|https://ams-nl-ping.vultr.com/vultr.com.100MB.bin'
    'Vultr · Франкфурт|https://fra-de-ping.vultr.com/vultr.com.100MB.bin'
    'DataPacket · Амстердам|https://ams.download.datapacket.com/100mb.bin'
    'Cloudflare|https://speed.cloudflare.com/__down?bytes=262144'
)
CC_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:129.0) Gecko/20100101 Firefox/129.0"
CC_TIMEOUT=6
CC_16K_BYTES=131072
# стоп-страницы и заглушки российских провайдеров
CC_STUB_RE='warning\.rt\.ru|blocked\.|block\.|zapret|blacklist|eais\.rkn|rkn\.gov|lawfilter|stop\.|fz139|ertelecom\.ru/block|mts\.ru/block|beeline\.ru/block'

_cc_curl() { curl -s -A "$CC_UA" -H 'Accept-Language: ru,en;q=0.5' "$@"; }

# ---------------------------------------------------------------- DNS
cc_resolve_sys() {   # хост → первый IPv4
    local ip=""
    if have getent; then ip=$(getent ahostsv4 "$1" 2>/dev/null | awk '{print $1; exit}')
    elif have dig; then ip=$(dig +short +time=3 +tries=1 "$1" A 2>/dev/null | awk '/^[0-9.]+$/ {print; exit}'); fi
    echo "$ip"
}

cc_resolve_doh() {   # хост → IPv4 через DoH (по одному в строке)
    local u r
    for u in "https://1.1.1.1/dns-query?name=$1&type=A" "https://dns.google/resolve?name=$1&type=A"; do
        r=$(_cc_curl --max-time 5 -H 'accept: application/dns-json' "$u" 2>/dev/null | jq -r '.Answer[]? | select(.type == 1) | .data' 2>/dev/null)
        [[ -n "$r" ]] && { echo "$r"; return 0; }
    done
    return 1
}

# частный/служебный адрес — признак заглушки DNS
cc_bogus_ip() { [[ "$1" =~ ^(0\.|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|169\.254\.) ]]; }

# ---------------------------------------------------------------- сеть
cc_tcp() {   # ip порт → 0, если соединение установлено
    local t; t=$(curl -s -o /dev/null --connect-timeout 4 --max-time 5 -w '%{time_connect}' "http://$1:$2/" 2>/dev/null)
    awk -v t="${t:-0}" 'BEGIN{exit !(t > 0)}'
}

# запрос → "код|redirect|exit"
cc_req() {   # url host ip [extra curl args...]
    local url="$1" host="$2" ip="$3" out rc port=443; shift 3
    [[ "$url" == http://* ]] && port=80
    out=$(_cc_curl --compressed -o /dev/null --connect-timeout "$CC_TIMEOUT" --max-time $((CC_TIMEOUT * 2)) \
        --resolve "$host:$port:$ip" -w '%{http_code}|%{redirect_url}' "$@" "$url" 2>/dev/null); rc=$?
    echo "${out:-000|}|$rc"
}

# тот же IP без SNI (IP в URL — curl не шлёт SNI): прошёл ли TLS
cc_nosni() { _cc_curl -k -o /dev/null --connect-timeout "$CC_TIMEOUT" --max-time $((CC_TIMEOUT * 2)) "https://$1/" 2>/dev/null; local rc=$?; ((rc == 0 || rc == 22)); }

# ---------------------------------------------------------------- один сайт
# печатает JSON: {site, host, ip, dns, http:{...}, https:{...}, verdict, note}
cc_check_site() {   # сайт[/путь]
    local site="$1" host="${1%%/*}" ip doh dns=ok note=""
    ip=$(cc_resolve_sys "$host")
    doh=$(cc_resolve_doh "$host")
    if [[ -z "$ip" && -z "$doh" ]]; then
        jq -nc --arg s "$site" --arg h "$host" '{site: $s, host: $h, ip: null, dns: "nxdomain", verdict: "nodns", note: "нет в DNS"}'; return
    fi
    if [[ -z "$ip" ]]; then dns=empty; ip=$(head -1 <<<"$doh"); note="системный DNS не отвечает — IP из DoH"
    elif cc_bogus_ip "$ip"; then
        dns=spoofed; note="DNS подменён ($ip)"; ip=$(head -1 <<<"$doh")
    fi
    # 198.18.0.0/15 — fake-IP локального прокси (Clash, sing-box): это не цензор, но результат — через прокси
    [[ "$ip" =~ ^198\.1[89]\. ]] && note="fake-IP: проверка шла через локальный прокси"
    [[ -n "$ip" ]] || { jq -nc --arg s "$site" --arg h "$host" '{site: $s, host: $h, ip: null, dns: "spoofed", verdict: "dns", note: "DNS подменён, DoH недоступен"}'; return; }

    local t80=closed t443=closed
    cc_tcp "$ip" 80 && t80=open
    cc_tcp "$ip" 443 && t443=open
    # системный IP мёртв, а IP из DoH другой и живой — DNS ведёт в никуда
    if [[ "$t80$t443" == closedclosed && -n "$doh" ]] && ! grep -qxF "$ip" <<<"$doh"; then
        local alt; alt=$(head -1 <<<"$doh")
        if cc_tcp "$alt" 443; then dns=spoofed; note="DNS подменён ($ip)"; ip="$alt"; t443=open; cc_tcp "$ip" 80 && t80=open; fi
    fi
    if [[ "$t80" == closed && "$t443" == closed ]]; then
        jq -nc --arg s "$site" --arg h "$host" --arg ip "$ip" --arg d "$dns" --arg n "$note" \
            '{site: $s, host: $h, ip: $ip, dns: $d, verdict: "ip", note: (if $n == "" then null else $n end)}'; return
    fi
    local h=null s=null hc hr hx sc sr sx sni=null
    if [[ "$t80" == open ]]; then
        IFS='|' read -r hc hr hx <<<"$(cc_req "http://$site" "$host" "$ip")"
        h=$(jq -nc --arg c "$hc" --arg r "$hr" --arg x "$hx" '{code: ($c | tonumber), redirect: (if $r == "" then null else $r end), exit: ($x | tonumber)}')
    fi
    if [[ "$t443" == open ]]; then
        IFS='|' read -r sc sr sx <<<"$(cc_req "https://$site" "$host" "$ip" -L)"
        # повтор: обрыв мог быть случайным
        [[ "$sc" == 000 ]] && IFS='|' read -r sc sr sx <<<"$(cc_req "https://$site" "$host" "$ip" -L)"
        if [[ "$sc" == 000 ]]; then cc_nosni "$ip" && sni=true || sni=false; fi
        s=$(jq -nc --arg c "$sc" --arg r "$sr" --arg x "$sx" --argjson n "$sni" '{code: ($c | tonumber), redirect: (if $r == "" then null else $r end), exit: ($x | tonumber), nosni_ok: $n}')
    fi
    jq -nc --arg site "$site" --arg host "$host" --arg ip "$ip" --arg dns "$dns" --arg note "$note" --argjson h "$h" --argjson s "$s" \
        --arg t80 "$t80" --arg t443 "$t443" --arg stub "$CC_STUB_RE" '
        def verdict:
            if .https == null then (if .http.code == 0 then "tls" else "port443" end)
            elif .https.code == 451 then "451"
            elif .https.code >= 200 and .https.code < 600 and .https.code != 0 then "ok"
            elif .https.nosni_ok == true then "sni"
            else "tls" end;
        {site: $site, host: $host, ip: $ip, dns: $dns, tcp80: $t80, tcp443: $t443, http: $h, https: $s,
         note: (if $note == "" then null else $note end)}
        | .stub = ((.http.redirect // "") | test($stub; "i"))
        | .verdict = verdict
        | if .stub and .verdict == "ok" then .verdict = "stub_http" else . end'
}

# ---------------------------------------------------------------- 16 КБ
# сколько байт пришло из первых 128 КБ; печатает "байты код exit время"
cc_16k() {   # url
    local out rc
    out=$(_cc_curl -o /dev/null -r "0-$((CC_16K_BYTES - 1))" --connect-timeout "$CC_TIMEOUT" --max-time 10 \
        -w '%{size_download} %{http_code} %{time_total}' "$1" 2>/dev/null); rc=$?
    read -r by code tt <<<"${out:-0 000 0}"
    echo "${by:-0} ${code:-000} $rc ${tt:-0}"
}

# вердикт по числу байт
cc_16k_verdict() {   # байты код exit
    awk -v b="$1" -v c="$2" -v x="$3" -v full="$CC_16K_BYTES" 'BEGIN {
        if (b >= full || (x == 0 && b > 0)) print "ok"
        else if (c == "000" && b == 0) print (x == 28 ? "tls" : "conn")
        else if (b > 0 && b < 40000) print "cut"
        else if (b == 0) print "stall"
        else print "slow" }'
}

# ---------------------------------------------------------------- вывод
_cc_pad() { local t="$1" w="$2" p; ((${#t} > ${w#-})) && t="${t:0:${w#-}-1}…"; p=$((${w#-} - ${#t}))
    if [[ "$w" == -* ]]; then printf '%s%*s' "$t" "$p" ""; else printf '%*s%s' "$p" "" "$t"; fi; }

_cc_section() {
    local t=" $1 " w=86
    printf '\n %s━━%s%s%s%s%s\n' "$C_BLUE" "$C_RESET$C_BOLD" "$t" "$C_RESET$C_BLUE" "$(printf '━%.0s' $(seq 1 $((w - ${#t} - 2))))" "$C_RESET"
}

# вердикт → цвет и подпись
cc_verdict_label() {
    case "$1" in
        ok) printf '%s● доступен%s' "$C_GREEN" "$C_RESET";;
        stub_http) printf '%s● HTTPS работает%s %s(HTTP → стоп-страница)%s' "$C_YELLOW" "$C_RESET" "$C_GRAY" "$C_RESET";;
        sni) printf '%s✖ DPI по SNI%s' "$C_RED" "$C_RESET";;
        tls) printf '%s✖ TLS обрывается%s' "$C_RED" "$C_RESET";;
        ip) printf '%s✖ блок по IP%s' "$C_RED" "$C_RESET";;
        port443) printf '%s✖ порт 443 закрыт%s' "$C_RED" "$C_RESET";;
        451) printf '%s✖ 451 (по закону)%s' "$C_RED" "$C_RESET";;
        dns) printf '%s✖ DNS-подмена%s' "$C_RED" "$C_RESET";;
        nodns) printf '%s○ нет в DNS%s' "$C_GRAY" "$C_RESET";;
        *) printf '%s? %s%s' "$C_YELLOW" "$1" "$C_RESET";;
    esac
}

_cc_http_cell() {   # json объекта http/https → коротко
    jq -r --arg stub "$CC_STUB_RE" 'if . == null then "—"
        elif .code == 0 then (if .exit == 28 then "таймаут" elif .exit == 35 then "TLS сброс" elif .exit == 56 or .exit == 52 then "сброс" else "ошибка \(.exit)" end)
        elif (.redirect // "") != "" then (if ((.redirect // "") | test($stub; "i")) then "\(.code) → стоп-стр." else "\(.code) → " + (.redirect | sub("^https?://"; "") | split("/")[0]) end)
        else (.code | tostring) end' <<<"$1"
}

cc_row() {   # json
    local j="$1" site ip v http https note
    IFS=$'\037' read -r site ip v note < <(jq -r '[.site, (.ip // "—"), .verdict, (.note // "")] | join("\u001f")' <<<"$j")
    http=$(_cc_http_cell "$(jq -c '.http // null' <<<"$j")"); https=$(_cc_http_cell "$(jq -c '.https // null' <<<"$j")")
    printf '  %s %s%s%s  %s%s%s  %s  %s' "$(_cc_pad "${site%%/*}" -24)" "$C_GRAY" "$(_cc_pad "$ip" -15)" "$C_RESET" "$C_GRAY" "$(_cc_pad "$http" -16)" "$C_RESET" "$(_cc_pad "$https" -10)" "$(cc_verdict_label "$v")"
    [[ -n "$note" ]] && printf ' %s%s%s' "$C_YELLOW" "$note" "$C_RESET"
    printf '\n'
}

cc_16k_row() {   # имя байты код exit
    local name="$1" by="$2" v kb w=16 n i bar=""
    v=$(cc_16k_verdict "$2" "$3" "$4")
    kb=$(awk -v b="$by" 'BEGIN{printf "%.0f", b / 1024}')
    n=$(awk -v b="$by" -v f="$CC_16K_BYTES" -v w="$w" 'BEGIN{n = int(b / f * w + 0.5); if (b > 0 && n < 1) n = 1; print (n > w ? w : n)}')
    local col="$C_GREEN"; [[ "$v" != ok ]] && col="$C_RED"; [[ "$v" == slow ]] && col="$C_YELLOW"
    for ((i = 0; i < w; i++)); do ((i < n)) && bar+="▰" || bar+="▱"; done
    printf '  %s %s%s%s %s  ' "$(_cc_pad "$name" -26)" "$col" "$bar" "$C_RESET" "$(_cc_pad "$kb КБ" 7)"
    case "$v" in
        ok) printf '%s● без обрыва%s\n' "$C_GREEN" "$C_RESET";;
        cut) printf '%s✖ обрыв после %s КБ — режет ТСПУ%s\n' "$C_RED" "$kb" "$C_RESET";;
        stall) printf '%s✖ ответ есть, данные не идут%s\n' "$C_RED" "$C_RESET";;
        tls) printf '%s✖ TLS не установлен (таймаут)%s\n' "$C_RED" "$C_RESET";;
        conn) printf '%s✖ нет соединения%s\n' "$C_RED" "$C_RESET";;
        slow) printf '%s! медленно, %s КБ за 10 с%s\n' "$C_YELLOW" "$kb" "$C_RESET";;
    esac
}

# ---------------------------------------------------------------- запуск
censorcheck_run() {   # [сайт...] [--no-hosting] [--json]
    local json="" hosting=yes sites=() a
    for a in "$@"; do case "$a" in --json) json=1;; --no-hosting|--sites-only) hosting=no;; --hosting-only) sites=(-);; -*) ;; *) sites+=("$a");; esac; done
    have curl || die "Нужен curl"; have jq || die "Нужен jq"
    ((${#sites[@]})) || sites=("${CC_SITES[@]}")
    [[ "${sites[0]}" == - ]] && sites=()
    local tmp; tmp=$(mktemp -d)
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'; printf '\033[?25h'; trap - INT TERM; exit 130" INT TERM
    [[ -n "$json" ]] && exec 3>&1 1>/dev/null

    local me; me=$(curl -fsS --max-time 5 https://speed.cloudflare.com/meta 2>/dev/null)
    printf '\n %s⛨ CensorCheck%s %sчто режет DPI на этом сервере · fail2detect v%s%s\n' "$C_BOLD$C_MAGENTA" "$C_RESET" "$C_GRAY" "$F2D_VERSION" "$C_RESET"
    jq -e .clientIp >/dev/null 2>&1 <<<"$me" && printf ' %s%s · AS%s %s · %s%s\n' "$C_GRAY" "$(jq -r .clientIp <<<"$me")" "$(jq -r .asn <<<"$me")" "$(jq -r .asOrganization <<<"$me")" "$(jq -r '.country // "?"' <<<"$me")" "$C_RESET"
    [[ "$(jq -r '.country // ""' <<<"$me" 2>/dev/null)" != RU ]] && [[ -n "$me" ]] && \
        printf ' %s! Сервер не в России — блокировок ТСПУ здесь быть не должно; проверка покажет фильтры этой сети%s\n' "$C_YELLOW" "$C_RESET"
    printf '\033[?25l'

    # параллельно, по 6 сайтов; печать — по порядку
    _cc_batch() {   # префикс сайты...
        local pre="$1" i=0 s running=0; shift
        for s in "$@"; do
            cc_check_site "$s" > "$tmp/$pre.$i" 2>/dev/null &
            i=$((i + 1)); running=$((running + 1))
            ((running >= 6)) && { wait -n 2>/dev/null; running=$((running - 1)); }
        done
        local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' k=0
        while (( $(jobs -rp | wc -l) > 0 )); do printf '\r  %s проверяю %s…\033[K' "$C_CYAN${spin:k++%10:1}$C_RESET" "$pre"; sleep 0.15; done
        printf '\r\033[K'
    }

    _cc_section "Контроль"
    _cc_batch control "${CC_CONTROL[@]}"
    local i ctrl_ok=0
    for ((i = 0; i < ${#CC_CONTROL[@]}; i++)); do
        cc_row "$(cat "$tmp/control.$i")"
        [[ "$(jq -r .verdict "$tmp/control.$i")" == ok ]] && ctrl_ok=$((ctrl_ok + 1))
    done
    ((ctrl_ok == 0)) && printf '  %s✖ Контрольные сайты не открываются — проблема в сети сервера, а не в DPI. Итог ниже недостоверен.%s\n' "$C_RED" "$C_RESET"

    if ((${#sites[@]})); then
        _cc_section "Сайты"
        printf '  %s%s %s  %s  %s  %s%s\n' "$C_GRAY" "$(_cc_pad Сайт -24)" "$(_cc_pad IP -15)" "$(_cc_pad HTTP -16)" "$(_cc_pad HTTPS -10)" "Итог" "$C_RESET"
        _cc_batch site "${sites[@]}"
        for ((i = 0; i < ${#sites[@]}; i++)); do cc_row "$(cat "$tmp/site.$i")"; cat "$tmp/site.$i" >> "$tmp/all.jsonl"; echo >> "$tmp/all.jsonl"; done
    fi

    if [[ "$hosting" == yes ]]; then
        _cc_section "Зарубежные хостинги · обрыв после 16 КБ"
        printf '  %sТСПУ пропускает начало соединения с VPS (~16 КБ) и обрывает его — так ломаются VPN и прокси%s\n' "$C_GRAY" "$C_RESET"
        local h name url
        i=0
        for h in "${CC_HOSTINGS[@]}"; do cc_16k "${h#*|}" > "$tmp/h.$i" & i=$((i + 1)); done
        local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' k=0
        while (( $(jobs -rp | wc -l) > 0 )); do printf '\r  %s качаю по 128 КБ…\033[K' "$C_CYAN${spin:k++%10:1}$C_RESET"; sleep 0.15; done
        printf '\r\033[K'
        i=0
        for h in "${CC_HOSTINGS[@]}"; do
            name="${h%%|*}"; url="${h#*|}"
            local by code rc tt
            read -r by code rc tt < "$tmp/h.$i"
            cc_16k_row "$name" "$by" "$code" "$rc"
            jq -nc --arg n "$name" --arg u "$url" --argjson b "${by:-0}" --arg c "$code" --argjson x "${rc:-0}" --arg v "$(cc_16k_verdict "$by" "$code" "$rc")" \
                '{hosting: $n, url: $u, bytes: $b, code: $c, exit: $x, verdict: $v}' >> "$tmp/hosting.jsonl"
            i=$((i + 1))
        done
    fi

    # итог
    _cc_section "Итог"
    if [[ -s "$tmp/all.jsonl" ]]; then
        local sum; sum=$(jq -rs 'map(select(type == "object")) | group_by(.verdict) | map("\(.[0].verdict)=\(length)") | join(" ")' "$tmp/all.jsonl")
        local total ok blocked
        total=$(jq -s 'map(select(type == "object")) | length' "$tmp/all.jsonl")
        ok=$(jq -s 'map(select(type == "object" and (.verdict == "ok" or .verdict == "stub_http"))) | length' "$tmp/all.jsonl")
        blocked=$((total - ok - $(jq -s 'map(select(type == "object" and .verdict == "nodns")) | length' "$tmp/all.jsonl")))
        printf '  %sСайты%s      %s%s доступно%s · %s%s заблокировано%s из %s' "$C_BOLD" "$C_RESET" "$C_GREEN" "$ok" "$C_RESET" "$([[ $blocked -gt 0 ]] && echo "$C_RED" || echo "$C_GREEN")" "$blocked" "$C_RESET" "$total"
        local part v c
        for part in $sum; do
            v="${part%%=*}"; c="${part#*=}"
            case "$v" in ok|stub_http|nodns) continue;; esac
            printf '   %s %s' "$(cc_verdict_label "$v")" "$c"
        done
        printf '\n'
    fi
    if [[ -s "$tmp/hosting.jsonl" ]]; then
        local hb ht
        ht=$(jq -s 'length' "$tmp/hosting.jsonl"); hb=$(jq -s 'map(select(.verdict != "ok")) | length' "$tmp/hosting.jsonl")
        printf '  %sХостинги%s   %s%s режутся%s из %s' "$C_BOLD" "$C_RESET" "$([[ $hb -gt 0 ]] && echo "$C_RED" || echo "$C_GREEN")" "$hb" "$C_RESET" "$ht"
        ((hb > 0)) && printf '  %s— VPN-ноды у этих хостингов отсюда будут рваться%s' "$C_GRAY" "$C_RESET"
        printf '\n'
    fi
    printf '\033[?25h\n'
    if [[ -n "$json" ]]; then
        exec 1>&3 3>&-
        jq -n --slurpfile s <(jq -c 'select(type == "object")' "$tmp/all.jsonl" 2>/dev/null) --slurpfile h <(cat "$tmp/hosting.jsonl" 2>/dev/null) '{sites: $s, hostings: $h}'
    fi
    rm -rf "$tmp"; trap - INT TERM
}

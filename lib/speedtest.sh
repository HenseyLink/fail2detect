#!/usr/bin/env bash
# fail2detect — Cloudflare Speedtest в терминале (speed.cloudflare.com).

CF_SPEED="https://speed.cloudflare.com"
SPARK=(▁ ▂ ▃ ▄ ▅ ▆ ▇ █)

_cf_curl() { curl -sS -H 'Referer: https://speed.cloudflare.com/' -A 'Mozilla/5.0 fail2detect' "$@"; }

# число с плавающей точкой через awk
_calc() { awk "BEGIN{ printf \"%.${2:-2}f\", $1 }"; }

sparkline() {   # значения...
    local max=0 v out=""
    for v in "$@"; do awk -v a="$v" -v b="$max" 'BEGIN{exit !(a>b)}' && max=$v; done
    for v in "$@"; do
        local i; i=$(awk -v a="$v" -v m="$max" 'BEGIN{ if (m<=0) print 0; else { x=int(a/m*7+0.5); print (x>7?7:x) } }')
        out+="${SPARK[i]}"
    done
    printf '%s' "$out"
}

bar() {   # value max width color
    local w="${3:-30}" fill i out=""
    fill=$(awk -v v="$1" -v m="$2" -v w="$w" 'BEGIN{ if (m<=0) print 0; else { x=int(v/m*w+0.5); print (x>w?w:x) } }')
    for ((i = 0; i < fill; i++)); do out+="█"; done
    out+="$C_GRAY"
    for ((; i < w; i++)); do out+="░"; done
    printf '%s%s%s' "${4:-$C_GREEN}" "$out" "$C_RESET"
}

# крутилка, пока жив процесс
_spin() {   # pid label
    local pid="$1" label="$2" s='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf '\r  %s%s%s %s' "$C_CYAN" "${s:i++%10:1}" "$C_RESET" "$label"
        sleep 0.1
    done
    printf '\r\033[K'
}

_box() {
    local w=62 line
    printf '%s╭%s╮%s\n' "$C_MAGENTA" "$(printf '─%.0s' $(seq 1 $w))" "$C_RESET"
    for line in "$@"; do
        local plain; plain=$(sed 's/\x1b\[[0-9;]*m//g' <<<"$line")
        printf '%s│%s %s%*s%s│%s\n' "$C_MAGENTA" "$C_RESET" "$line" $((w - 1 - ${#plain})) "" "$C_MAGENTA" "$C_RESET"
    done
    printf '%s╰%s╯%s\n' "$C_MAGENTA" "$(printf '─%.0s' $(seq 1 $w))" "$C_RESET"
}

speedtest_run() {
    local quick="${1:-}"
    have curl || die "Нужен curl"
    local tmp; tmp=$(mktemp -d); trap 'rm -rf "$tmp"' RETURN

    # --- метаданные ---
    local meta ip asn org city country colo
    meta=$(_cf_curl --max-time 8 "$CF_SPEED/meta" 2>/dev/null)
    if jq -e .clientIp >/dev/null 2>&1 <<<"$meta"; then
        ip=$(jq -r .clientIp <<<"$meta"); asn=$(jq -r .asn <<<"$meta"); org=$(jq -r .asOrganization <<<"$meta")
        city=$(jq -r '.city // "?"' <<<"$meta"); country=$(jq -r .country <<<"$meta")
        colo="$(jq -r '.colo.iata // .colo' <<<"$meta") ($(jq -r '.colo.city // "?"' <<<"$meta"))"
    else
        local tr; tr=$(_cf_curl --max-time 8 "$CF_SPEED/cdn-cgi/trace")
        ip=$(awk -F= '$1=="ip"{print $2}' <<<"$tr"); country=$(awk -F= '$1=="loc"{print $2}' <<<"$tr")
        colo=$(awk -F= '$1=="colo"{print $2}' <<<"$tr"); asn="?"; org="?"; city="?"
    fi
    echo
    _box "${C_BOLD}☁  Cloudflare Speedtest${C_RESET}  ${C_GRAY}fail2detect${C_RESET}" \
         "IP:      ${C_WHITE}$ip${C_RESET}  ${C_GRAY}AS$asn $org${C_RESET}" \
         "Сервер:  $city, $country   →   Cloudflare ${C_CYAN}$colo${C_RESET}"

    # --- задержка ---
    local lat=() i n=20; [[ "$quick" == --quick ]] && n=10
    for ((i = 1; i <= n; i++)); do
        local t; t=$(_cf_curl -o /dev/null --max-time 5 -w '%{time_connect} %{time_appconnect} %{time_starttransfer}' "$CF_SPEED/__down?bytes=0" 2>/dev/null) || continue
        # RTT ≈ TTFB − TLS-рукопожатие (один круг до сервера)
        lat+=("$(awk '{ printf "%.1f", ($3-$2)*1000 }' <<<"$t")")
        printf '\r  %sЗадержка%s  %d/%d  %s' "$C_CYAN" "$C_RESET" "$i" "$n" "$(sparkline "${lat[@]}")"
    done
    printf '\r\033[K'
    local lat_stats
    lat_stats=$(printf '%s\n' "${lat[@]}" | sort -n | awk '{a[NR]=$1; s+=$1} END{ if(!NR){print "0 0 0 0"; exit} printf "%.1f %.1f %.1f", a[1], a[int((NR+1)/2)], s/NR }')
    local jitter
    jitter=$(printf '%s\n' "${lat[@]}" | awk 'NR>1{d=$1-p; if(d<0)d=-d; s+=d; c++} {p=$1} END{printf "%.1f", c?s/c:0}')
    read -r lmin lmed lavg <<<"$lat_stats"

    # --- скачивание ---
    local sizes=(100000 1000000 10000000 25000000 100000000)
    [[ "$quick" == --quick ]] && sizes=(100000 1000000 10000000 25000000)
    local dl=() s
    for s in "${sizes[@]}"; do
        ( _cf_curl -o /dev/null --max-time 30 -w '%{speed_download}' "$CF_SPEED/__down?bytes=$s" > "$tmp/d" 2>/dev/null ) &
        _spin $! "Скачивание $(numfmt --to=si "$s" 2>/dev/null || echo "$s")Б…"
        local bps; bps=$(<"$tmp/d"); [[ -n "$bps" ]] && dl+=("$(_calc "$bps*8/1000000" 2)")
    done
    # параллельные потоки — честнее для каналов с большим RTT
    for i in 1 2 3 4; do ( _cf_curl -o /dev/null --max-time 30 -w '%{speed_download}' "$CF_SPEED/__down?bytes=25000000" > "$tmp/p$i" 2>/dev/null ) & done
    _spin "$!" "Скачивание, 4 потока…"; wait
    local par=0; for i in 1 2 3 4; do par=$(_calc "$par + $(cat "$tmp/p$i" 2>/dev/null || echo 0)*8/1000000" 2); done
    dl+=("$par")

    # --- загрузка ---
    local ul=(); local usizes=(100000 1000000 10000000 25000000)
    [[ "$quick" == --quick ]] && usizes=(100000 1000000 10000000)
    for s in "${usizes[@]}"; do
        head -c "$s" /dev/urandom > "$tmp/u"
        ( _cf_curl -o /dev/null --max-time 30 -w '%{speed_upload}' -X POST --data-binary @"$tmp/u" "$CF_SPEED/__up" > "$tmp/r" 2>/dev/null ) &
        _spin $! "Загрузка $(numfmt --to=si "$s" 2>/dev/null || echo "$s")Б…"
        local bps; bps=$(<"$tmp/r"); [[ -n "$bps" ]] && ul+=("$(_calc "$bps*8/1000000" 2)")
    done

    # итог: 90-й перцентиль, как на speed.cloudflare.com
    local dmax umax
    dmax=$(printf '%s\n' "${dl[@]}" | sort -n | awk '{a[NR]=$1} END{i=int(NR*0.9+0.5); if(i<1)i=1; print a[i]+0}')
    umax=$(printf '%s\n' "${ul[@]}" | sort -n | awk '{a[NR]=$1} END{i=int(NR*0.9+0.5); if(i<1)i=1; print a[i]+0}')
    local scale; scale=$(awk -v a="$dmax" -v b="$umax" 'BEGIN{m=(a>b?a:b); print (m<1?1:m)}')

    echo
    _box \
        "${C_BOLD}↓ Скачивание${C_RESET}  $(printf '%9s' "$dmax") Мбит/с  $(bar "$dmax" "$scale" 22 "$C_GREEN")" \
        "               ${C_GRAY}$(sparkline "${dl[@]}")${C_RESET}" \
        "${C_BOLD}↑ Загрузка${C_RESET}    $(printf '%9s' "$umax") Мбит/с  $(bar "$umax" "$scale" 22 "$C_BLUE")" \
        "               ${C_GRAY}$(sparkline "${ul[@]}")${C_RESET}" \
        "${C_BOLD}◷ Задержка${C_RESET}    мин ${lmin} / мед ${C_WHITE}${lmed}${C_RESET} / ср ${lavg} мс" \
        "${C_BOLD}≈ Джиттер${C_RESET}     ${jitter} мс   $(sparkline "${lat[@]}")"
    echo
}

# полноэкранный TUI от kavehtehrani, если пользователь хочет
speedtest_tui() {
    local bin; bin=$(command -v cloudflare-speed-cli || echo "$HOME/.local/bin/cloudflare-speed-cli")
    if [[ ! -x "$bin" ]]; then
        info "cloudflare-speed-cli (TUI) — https://github.com/kavehtehrani/cloudflare-speed-cli"
        confirm "Установить его официальным скриптом автора?" n || return 0
        curl -fsSL https://raw.githubusercontent.com/kavehtehrani/cloudflare-speed-cli/main/install.sh | sh || return 1
        bin="$HOME/.local/bin/cloudflare-speed-cli"
    fi
    "$bin"
}

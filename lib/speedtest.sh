#!/usr/bin/env bash
# fail2detect — Cloudflare Speedtest с живым дашбордом (speed.cloudflare.com).
#
# Методика — как у cloudflare-speed-cli (kavehtehrani), переписана на bash:
#   * задержка в простое: запросы __down?bytes=0 каждые 250 мс;
#   * скачивание и отдача: 6 потоков, keep-alive, фаза 10 с; размер запроса
#     каждый поток подгоняет под свою скорость (запрос ≈ 0.6 с); рядом — замеры
#     задержки под нагрузкой (during=download|upload);
#   * скорость — по окнам 250 мс; первые 20% фазы (не меньше 1 с) — разгон TCP,
#     в итог не идут;
#   * перцентили с интерполяцией, джиттер — стандартное отклонение;
#   * потери: 50 STUN binding request'ов на stun.cloudflare.com:3478,
#     MOS — упрощённая E-модель ITU-T G.107;
#   * Bufferbloat = рост медианы задержки под нагрузкой, стабильность —
#     коэффициент вариации скорости.

CF_SPEED="https://speed.cloudflare.com"
ST_STUN_HOST="stun.cloudflare.com"
ST_STUN_PORT=3478
ST_BUCKET=0.25            # окно расчёта скорости, с
ST_WORKERS=6
ST_HISTORY_DIR="${F2D_STATE_DIR}/speedtest"

_cf_curl() { curl -sS -H 'Referer: https://speed.cloudflare.com/' -A 'Mozilla/5.0 fail2detect' "$@"; }
_st_now() { local t="$EPOCHREALTIME"; echo "${t/,/.}"; }

# ---------------------------------------------------------------- статистика
# значения по одному в строке → "n mean med p25 p75 p95 min max sd" (пусто, если n=0)
st_stats() {
    sort -g | awk '
        function pct(p,   pos, lo, hi) { pos = p * (n - 1); lo = int(pos); hi = (pos > lo) ? lo + 1 : lo
            return v[lo] + (pos - lo) * (v[hi] - v[lo]) }
        $1 != "" { v[n++] = $1 + 0; s += $1 }
        END {
            if (!n) exit
            m = s / n; for (i = 0; i < n; i++) q += (v[i] - m) ^ 2
            sd = (n > 1) ? sqrt(q / (n - 1)) : 0
            if (n == 1) printf "%d %.2f %.2f %.2f %.2f %.2f %.2f %.2f %.2f\n", n, m, m, m, m, m, m, m, 0
            else printf "%d %.2f %.2f %.2f %.2f %.2f %.2f %.2f %.2f\n", n, m, pct(.5), pct(.25), pct(.75), pct(.95), v[0], v[n-1], sd
        }'
}

# коэффициент вариации, % (нужно ≥3 значений)
st_cv() {
    awk '$1 != "" { v[n++] = $1; s += $1 } END { if (n < 3) exit; m = s / n; if (m == 0) exit
        for (i = 0; i < n; i++) q += (v[i] - m) ^ 2; printf "%.1f\n", sqrt(q / (n - 1)) / m * 100 }'
}

# MOS (1…5): rtt, jitter (мс), потери (%)
st_mos() {
    awk -v r="$1" -v j="$2" -v l="$3" 'BEGIN {
        d = r / 2 + 2 * j; if (d > 177.3) d = 177.3
        R = 93.2 - d / 40 - 30 * ((l / 100 > 1) ? 1 : l / 100)
        if (R < 0) R = 0; if (R > 100) R = 100
        m = 1 + 0.035 * R + 7e-6 * R * (R - 60) * (100 - R)
        if (m < 1) m = 1; if (m > 5) m = 5; printf "%.1f\n", m }'
}

st_loss_label() {
    awk -v l="$1" 'BEGIN { if (l == 0) print "Отлично"; else if (l < 1) print "Хорошо"; else if (l < 2.5) print "Приемлемо"
        else if (l < 5) print "Плохо"; else print "Очень плохо" }'
}

st_bloat_grade() {
    awk -v v="$1" 'BEGIN { if (v < 0) v = 0; if (v <= 5) print "A+"; else if (v <= 30) print "A"; else if (v <= 60) print "B"
        else if (v <= 200) print "C"; else if (v <= 400) print "D"; else print "F" }'
}

st_stab_grade() {
    awk -v v="$1" 'BEGIN { if (v <= 5) print "A"; else if (v <= 10) print "B"; else if (v <= 20) print "C"; else if (v <= 35) print "D"; else print "F" }'
}

# события передач ("начало конец байты") → Мбит/с по окнам с начала фазы
st_series() {   # файл t0 длительность сейчас [отставание]
    [[ -s "$1" ]] || return 0
    awk -v t0="$2" -v dur="$3" -v now="$4" -v lag="${5:-0}" -v b="$ST_BUCKET" '
        { s = $1 - t0; e = $2 - t0; by = $3; if (e <= s) { s = e - 0.001 }
          len = e - s
          for (i = int((s > 0 ? s : 0) / b); i * b < e && i * b < dur; i++) {
              lo = (i * b > s) ? i * b : s; hi = ((i + 1) * b < e) ? (i + 1) * b : e
              if (hi > lo) acc[i] += by * (hi - lo) / len
          } }
        END {
            lim = now - t0 - lag; if (lim > dur) lim = dur
            nb = int(lim / b + 1e-9)
            for (i = 0; i < nb; i++) printf "%.2f\n", acc[i] * 8 / b / 1e6
        }' "$1"
}

# без разгона: первые 20% фазы, но не меньше 1 с
st_steady() {   # длительность фазы
    awk -v dur="$1" -v b="$ST_BUCKET" 'BEGIN { c = dur * 0.2; if (c < 1) c = 1; skip = int(c / b + 0.5) } NR > skip'
}

# ---------------------------------------------------------------- рисование
_st_vis() {   # видимая длина строки (без ANSI)
    local s="$1"
    shopt -s extglob
    s="${s//$'\e'\[*([0-9;])m/}"
    echo "${#s}"
}

# рамка: печатает строки ровно шириной w
_st_box() {   # w цвет "заголовок" строки...
    local w="$1" col="$2" title="$3" line pad tv; shift 3
    tv=$(_st_vis "$title")
    pad=$((w - 5 - tv)); ((pad < 0)) && pad=0
    printf '%s╭─ %s%s %s%s╮%s\n' "$col" "$C_RESET$title" "$col" "$(_st_rep ─ "$pad")" "" "$C_RESET"
    for line in "$@"; do
        tv=$(_st_vis "$line"); pad=$((w - 4 - tv)); ((pad < 0)) && pad=0
        printf '%s│%s %s%*s %s│%s\n' "$col" "$C_RESET" "$line" "$pad" "" "$col" "$C_RESET"
    done
    printf '%s╰%s╯%s\n' "$col" "$(_st_rep ─ $((w - 2)))" "$C_RESET"
}

# обрезать простую строку (без ANSI) до n символов
_st_cut() { local s="$1" n="$2"; ((${#s} > n)) && s="${s:0:n-1}…"; printf '%s' "$s"; }

_st_rep() { local s="" i; for ((i = 0; i < $2; i++)); do s+="$1"; done; printf '%s' "$s"; }

# столбики из 1/8 блоков: значения на stdin → h строк шириной w
st_chart() {   # w h max цвет
    awk -v w="$1" -v h="$2" -v mx="$3" -v col="$4" -v rst="$C_RESET" -v gray="$C_GRAY" '
        # глифы по одному: mawk/BSD awk режут UTF-8 по байтам
        BEGIN { g[1] = "▁"; g[2] = "▂"; g[3] = "▃"; g[4] = "▄"; g[5] = "▅"; g[6] = "▆"; g[7] = "▇"; g[8] = "█" }
        { v[n++] = $1 }
        END {
            for (c = 0; c < w; c++) {
                if (!n) { y[c] = -1; continue }
                # последние w окон; если окон меньше — растягиваем
                if (n >= w) idx = n - w + c; else idx = int(c * n / w)
                y[c] = (mx > 0) ? v[idx] / mx * h : 0
            }
            for (r = h - 1; r >= 0; r--) {
                line = col
                for (c = 0; c < w; c++) {
                    if (y[c] < 0) { line = line gray (r == 0 ? "·" : " ") col; continue }
                    f = y[c] - r; if (f >= 1) ch = "█"; else if (f <= 0) ch = (r == 0 ? "▁" : " ")
                    else { k = int(f * 8 + 0.5); ch = (k < 1) ? (r == 0 ? "▁" : " ") : g[k] }
                    line = line ch
                }
                print line rst
            }
        }'
}

# полоса задержки: ├──▓▓▓┃▓▓──┤ в масштабе [0, scale]
st_strip() {   # w min p25 med p75 max "lo hi" цвет
    local lo="${7% *}" hi="${7#* }"
    awk -v w="$1" -v mn="$2" -v a="$3" -v md="$4" -v b="$5" -v mx="$6" -v lo="$lo" -v hi="$hi" -v col="$8" -v rst="$C_RESET" -v gray="$C_GRAY" '
        function x(v) { p = int((v - lo) / (hi - lo) * (w - 1) + 0.5); return p < 0 ? 0 : (p > w - 1 ? w - 1 : p) }
        BEGIN {
            if (hi <= lo) hi = lo + 1
            i0 = x(mn); i1 = x(a); i2 = x(md); i3 = x(b); i4 = x(mx)
            out = ""
            for (i = 0; i < w; i++) {
                if (i == i2) ch = rst "\033[1m┃" col
                else if (i >= i1 && i <= i3) ch = "▓"
                else if (i == i0) ch = "├"
                else if (i == i4) ch = "┤"
                else if (i > i0 && i < i4) ch = "─"
                else ch = gray "·" col
                out = out ch
            }
            print col out rst
        }'
}

_st_fmt() { awk -v v="${1:-}" 'BEGIN { if (v == "") print "—"; else if (v >= 100) printf "%.0f", v; else if (v >= 10) printf "%.1f", v; else printf "%.2f", v }'; }

_st_grade_col() {
    case "$1" in A+|A) printf '%s' "$C_GREEN";; B) printf '%s' "$C_CYAN";; C) printf '%s' "$C_YELLOW";; -) printf '%s' "$C_GRAY";; *) printf '%s' "$C_RED";; esac
}

# ---------------------------------------------------------------- измерения
# задержка одного запроса: TTFB без TCP/TLS-рукопожатия (один круг до сервера)
_st_probe() {   # [during]
    local q="bytes=0"; [[ -n "${1:-}" ]] && q+="&during=$1"
    _cf_curl -o /dev/null --max-time 2 -w '%{time_appconnect} %{time_starttransfer}' "$CF_SPEED/__down?$q" 2>/dev/null \
        | awk '$2 > 0 { printf "%.1f\n", ($2 - $1) * 1000 }'
}

_st_probe_loop() {   # файл длительность [during]
    local end; end=$(awk -v a="$(_st_now)" -v d="$2" 'BEGIN{printf "%.3f", a + d}')
    while awk -v a="$(_st_now)" -v e="$end" 'BEGIN{exit !(a < e)}'; do
        _st_probe "${3:-}" >> "$1"
        sleep 0.25
    done
}

# поток до конца фазы, каждое завершение запроса — "начало конец байты" в файл
# событий. Сначала короткая пачка (2 запроса) — узнать скорость потока, затем
# одно keep-alive соединение до конца фазы с запросами по ≈ ST_REQ_SEC: у мелких
# запросов ожидание ответа сервера (десятки мс) съедает заметную долю скорости,
# а новое соединение — это заново разгон TCP.
ST_REQ_SEC=0.6
_st_chunk() {   # байт/с down|up → размер запроса (степень двойки: меньше разных тел отдачи)
    awk -v r="$1" -v d="$2" -v t="$ST_REQ_SEC" 'BEGIN { c = r * t; mx = (d == "down") ? 2^26 : 2^24
        p = 2^18; while (p * 1.5 < c && p < mx) p *= 2; printf "%d", p }'
}

_st_worker() {   # down|up начальный_размер конец_фазы файл_событий номер
    local dir="$1" chunk="$2" end="$3" ev="$4" rf="$ST_T/$1.rate$5" i k=2 r body args buf=()
    command -v stdbuf >/dev/null && buf=(stdbuf -oL)
    while awk -v a="$(_st_now)" -v e="$end" 'BEGIN{exit !(a < e)}'; do
        args=()
        if [[ "$dir" == down ]]; then
            for ((i = 0; i < k; i++)); do args+=(-o /dev/null "$CF_SPEED/__down?bytes=$chunk"); done
            args+=(-w '%{time_pretransfer} %{time_starttransfer} %{time_total} %{size_download}\n')
        else
            # тело одного размера на все потоки: создаём один раз, без гонки
            body="$ST_T/up-$chunk.bin"
            [[ -s "$body" ]] || { head -c "$chunk" /dev/urandom > "$body.$5" && mv -f "$body.$5" "$body"; }
            for ((i = 0; i < k; i++)); do args+=(-o /dev/null "$CF_SPEED/__up"); done
            args+=(-H 'Content-Type: application/octet-stream' --data-binary "@$body"
                   -w '%{time_pretransfer} %{time_starttransfer} %{time_total} %{size_upload}\n')
        fi
        "${buf[@]}" curl -sS -H 'Referer: https://speed.cloudflare.com/' -A 'Mozilla/5.0 fail2detect' "${args[@]}" 2>/dev/null \
        | while read -r pre st tot by; do
            # скачивание: байты идут от первого байта ответа до конца;
            # отдача: от конца рукопожатия до первого байта ответа
            awk -v n="$(_st_now)" -v pre="$pre" -v st="$st" -v tot="$tot" -v by="$by" -v d="$dir" -v ev="$ev" -v rf="$rf" 'BEGIN {
                b = n - tot
                if (d == "down") { printf "%.4f %.4f %s\n", b + st, n, by >> ev; dt = tot - st }
                else { printf "%.4f %.4f %s\n", b + pre, b + st, by >> ev; dt = st - pre }
                if (dt > 0.02 && by > 0) printf "%d\n", by / dt > rf }'
        done
        r=$(cat "$rf" 2>/dev/null); [[ -n "$r" ]] && chunk=$(_st_chunk "$r" "$dir")
        # запросов — с запасом на остаток фазы (лишние оборвёт конец фазы)
        k=$(awk -v a="$(_st_now)" -v e="$end" -v c="$chunk" -v r="${r:-0}" 'BEGIN { t = (r > 0) ? c / r : 0.3
            if (t < 0.05) t = 0.05; k = int((e - a) / t * 2) + 2; if (k > 300) k = 300; print k }')
    done
}

# остановить процесс со всеми потомками (curl внутри конвейеров потоков —
# внуки движка: без этого они качают дальше и пишут в удалённый каталог)
_st_kill_tree() {
    local c
    kill -STOP "$1" 2>/dev/null   # замороженный поток не запустит новую пачку, пока гасим его детей
    for c in $(pgrep -P "$1" 2>/dev/null); do _st_kill_tree "$c"; done
    kill -TERM "$1" 2>/dev/null; kill -CONT "$1" 2>/dev/null
}

# фаза скачивания/отдачи: потоки + задержка под нагрузкой
_st_phase() {   # down|up длительность
    local dir="$1" dur="$2" ev lat chunk i pids=() t0 rate end
    ev="$ST_T/$dir.ev"; lat="$ST_T/$dir.lat"; : > "$ev"; : > "$lat"
    # начальный размер запроса — по грубой оценке на поток; дальше каждый поток подстраивает свой
    rate=$(cat "$ST_T/$dir.est" 2>/dev/null); [[ -n "$rate" ]] || rate=1000000
    chunk=$(_st_chunk "$(awk -v r="$rate" -v w="$ST_WORKERS" 'BEGIN{printf "%d", r * 1.5 / w}')" "$dir")
    t0=$(_st_now); echo "$t0" > "$ST_T/$dir.t0"
    end=$(awk -v a="$t0" -v d="$dur" 'BEGIN{printf "%.3f", a + d}')
    for ((i = 0; i < ST_WORKERS; i++)); do _st_worker "$dir" "$chunk" "$end" "$ev" "$i" & pids+=($!); done
    _st_probe_loop "$lat" "$dur" "$([[ $dir == down ]] && echo download || echo upload)" &
    local lp=$!
    sleep "$dur"; wait "$lp" 2>/dev/null
    # дать завершиться запросам в полёте, затем остановить
    sleep 1.5
    for i in "${pids[@]}"; do _st_kill_tree "$i"; done
    wait "${pids[@]}" 2>/dev/null
    return 0
}

# STUN binding request'ы через /dev/udp; строки "ok мс" или "lost"
_st_udp() {   # количество
    local n="$1" fd i tid t1 t2 got lost_streak=0 recv=0
    : > "$ST_T/udp"
    exec {fd}<>"/dev/udp/$ST_STUN_HOST/$ST_STUN_PORT" 2>/dev/null || { echo unreachable > "$ST_T/udp.state"; return 0; }
    for ((i = 1; i <= n; i++)); do
        while read -r -t 0.001 -N 1 -u "$fd" _ 2>/dev/null; do :; done   # опоздавшие ответы
        tid=$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n' | sed 's/../\\x&/g')
        t1=$(_st_now)
        # shellcheck disable=SC2059
        { printf "\x00\x01\x00\x00\x21\x12\xa4\x42$tid" >&"$fd"; } 2>/dev/null
        got=no
        if read -r -t 0.6 -N 1 -u "$fd" _ 2>/dev/null; then got=yes; fi
        t2=$(_st_now)
        if [[ "$got" == yes ]]; then
            recv=$((recv + 1)); lost_streak=0
            awk -v a="$t1" -v b="$t2" 'BEGIN{printf "ok %.1f\n", (b - a) * 1000}' >> "$ST_T/udp"
        else
            echo lost >> "$ST_T/udp"; lost_streak=$((lost_streak + 1))
            if ((recv == 0 && lost_streak >= 10)); then echo unreachable > "$ST_T/udp.state"; break; fi
        fi
        sleep 0.08
    done
    exec {fd}>&-
    return 0
}

_st_net_info() {
    local out ip w
    out=$(_cf_curl --max-time 6 -w '\n%{time_namelookup} %{time_connect} %{time_appconnect}' "$CF_SPEED/meta" 2>/dev/null)
    w=$(tail -1 <<<"$out"); out=$(sed '$d' <<<"$out")
    if jq -e .clientIp >/dev/null 2>&1 <<<"$out"; then
        jq -c '{ip: .clientIp, asn: .asn, org: .asOrganization, colo: (.colo.iata // .colo), colo_city: (.colo.city // ""), city: (.city // ""), country: (.country // "")}' <<<"$out" > "$ST_T/meta.json"
    else
        local tr; tr=$(_cf_curl --max-time 6 "$CF_SPEED/cdn-cgi/trace" 2>/dev/null)
        jq -nc --arg ip "$(awk -F= '$1=="ip"{print $2}' <<<"$tr")" --arg colo "$(awk -F= '$1=="colo"{print $2}' <<<"$tr")" \
            --arg c "$(awk -F= '$1=="loc"{print $2}' <<<"$tr")" '{ip: $ip, asn: "", org: "", colo: $colo, colo_city: "", city: "", country: $c}' > "$ST_T/meta.json"
    fi
    ip=$(jq -r .ip "$ST_T/meta.json")
    local tls; tls=$(curl -sv -o /dev/null --max-time 6 "$CF_SPEED/__down?bytes=0" 2>&1 | grep -oE 'TLSv1\.[0-3]' | head -1)
    local dev; dev=$(ip route get "$([[ "$ip" == *:* ]] && echo 2606:4700:4700::1111 || echo 1.1.1.1)" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1)
    {
        echo "family=$([[ "$ip" == *:* ]] && echo IPv6 || echo IPv4)"
        echo "iface=${dev:-?}"
        awk '{printf "dns=%.2f\ntls_ms=%.2f\n", $1 * 1000, ($3 - $2) * 1000}' <<<"$w"
        echo "tls=${tls:-?}"
    } > "$ST_T/net"
}

# грубая оценка скорости (байт/с) — подобрать размер запросов
_st_estimate() {   # down|up
    if [[ "$1" == down ]]; then
        _cf_curl -o /dev/null --max-time 8 -w '%{speed_download}' "$CF_SPEED/__down?bytes=4000000" 2>/dev/null
    else
        head -c 1000000 /dev/urandom > "$ST_T/est.bin"
        _cf_curl -o /dev/null --max-time 8 -w '%{speed_upload}' --data-binary "@$ST_T/est.bin" "$CF_SPEED/__up" 2>/dev/null
    fi
}

_st_engine() {   # idle dl ul udp_n
    _st_set() { echo "$1" > "$ST_T/phase"; }
    _st_set "Сеть"; _st_net_info
    _st_set "Простой"; _st_probe_loop "$ST_T/idle.lat" "$1"
    _st_estimate down > "$ST_T/down.est"
    _st_set "Скачивание"; _st_phase down "$2"
    _st_estimate up > "$ST_T/up.est"
    _st_set "Отдача"; _st_phase up "$3"
    _st_set "Потери"; _st_udp "$4"
    _st_set "Итог"; touch "$ST_T/done"
}

# ---------------------------------------------------------------- итоги
# всё посчитанное — в JSON (для экрана, истории и --json)
st_result_json() {   # durations: dl ul
    local dl_d="$1" ul_d="$2" now
    now=$(_st_now)
    local dls uls il dll ull dl_cv ul_cv
    _st_lat_json() { [[ -s "$1" ]] && st_stats < "$1" | awk '{printf "{\"n\":%d,\"mean\":%s,\"med\":%s,\"p25\":%s,\"p75\":%s,\"p95\":%s,\"min\":%s,\"max\":%s,\"jitter\":%s}", $1,$2,$3,$4,$5,$6,$7,$8,$9}'; }
    _st_tp_json() {   # dir dur
        local t0; t0=$(cat "$ST_T/$1.t0" 2>/dev/null) || return 0
        st_series "$ST_T/$1.ev" "$t0" "$2" "$now" | st_steady "$2" | st_stats | awk '{printf "{\"mean\":%s,\"med\":%s,\"p25\":%s,\"p75\":%s,\"p95\":%s,\"max\":%s}", $2,$3,$4,$5,$6,$8}'
    }
    dls=$(_st_tp_json down "$dl_d"); uls=$(_st_tp_json up "$ul_d")
    il=$(_st_lat_json "$ST_T/idle.lat"); dll=$(_st_lat_json "$ST_T/down.lat"); ull=$(_st_lat_json "$ST_T/up.lat")
    dl_cv=$( [[ -f "$ST_T/down.t0" ]] && st_series "$ST_T/down.ev" "$(<"$ST_T/down.t0")" "$dl_d" "$now" | st_steady "$dl_d" | st_cv)
    ul_cv=$( [[ -f "$ST_T/up.t0" ]] && st_series "$ST_T/up.ev" "$(<"$ST_T/up.t0")" "$ul_d" "$now" | st_steady "$ul_d" | st_cv)
    # UDP
    local udp="null"
    if [[ -s "$ST_T/udp" ]]; then
        local sent recv loss rtts rs mos
        sent=$(wc -l < "$ST_T/udp" | tr -d ' '); recv=$(grep -c '^ok' "$ST_T/udp")
        loss=$(awk -v s="$sent" -v r="$recv" 'BEGIN{printf "%.1f", (s - r) * 100 / s}')
        rtts=$(awk '$1=="ok"{print $2}' "$ST_T/udp" | st_stats)
        if [[ -n "$rtts" ]]; then
            read -r _ _ rmed _ _ _ _ _ rsd <<<"$rtts"
            mos=$(st_mos "$rmed" "$rsd" "$loss")
            udp=$(jq -nc --argjson s "$sent" --argjson r "$recv" --argjson l "$loss" --argjson rtt "$rmed" --argjson j "$rsd" --argjson m "$mos" --arg q "$(st_loss_label "$loss")" \
                '{sent: $s, recv: $r, loss: $l, rtt: $rtt, jitter: $j, mos: $m, label: $q}')
        fi
    fi
    [[ "$(cat "$ST_T/udp.state" 2>/dev/null)" == unreachable && "$udp" == null ]] && udp='{"unreachable":true}'
    jq -nc --argjson meta "$(cat "$ST_T/meta.json" 2>/dev/null || echo '{}')" --arg net "$(cat "$ST_T/net" 2>/dev/null)" \
        --argjson dl "${dls:-null}" --argjson ul "${uls:-null}" --argjson il "${il:-null}" --argjson dll "${dll:-null}" --argjson ull "${ull:-null}" \
        --arg dcv "$dl_cv" --arg ucv "$ul_cv" --argjson udp "$udp" --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '
        ($net | split("\n") | map(select(contains("=")) | split("=") | {(.[0]): (.[1:] | join("="))}) | add // {}) as $n
        | {time: $ts, meta: $meta, net: $n, download: $dl, upload: $ul, idle_latency: $il,
           loaded_latency_download: $dll, loaded_latency_upload: $ull, udp: $udp,
           cv_download: ($dcv | tonumber? // null), cv_upload: ($ucv | tonumber? // null)}
        | .bufferbloat_ms = (if .idle_latency.med == null then null else
              ([.loaded_latency_download.med, .loaded_latency_upload.med] | map(select(. != null) | . - $il.med) | if length == 0 then null else (max | if . < 0 then 0 else . end) end) end)
        | .cv_worst = ([.cv_download, .cv_upload] | map(select(. != null)) | if length == 0 then null else max end)'
}

# ---------------------------------------------------------------- экран
_st_tp_box() {   # w dir title color dur now live
    local w="$1" dir="$2" title="$3" col="$4" dur="$5" now="$6" live="$7"
    local t0 vals inst stats mx head foot cw=$((w - 4)) ch=7
    t0=$(cat "$ST_T/$dir.t0" 2>/dev/null)
    if [[ -n "$t0" ]]; then vals=$(st_series "$ST_T/$dir.ev" "$t0" "$dur" "$now" "$([[ $live == yes ]] && echo 0.6 || echo 0)"); fi
    inst=$(tail -1 <<<"$vals")
    stats=$(st_steady "$dur" <<<"$vals" | st_stats); [[ -n "$stats" ]] || stats=$(st_stats <<<"$vals")
    local n mean med p25 p75 p95 mn mxv _sd
    read -r n mean med p25 p75 p95 mn mxv _sd <<<"$stats"
    mx=$(awk -v m="${mxv:-0}" 'BEGIN{ if (m <= 0) { print 1; exit } e = 10 ^ int(log(m) / log(10)); s = m / e
        print (s <= 1 ? 1 : s <= 2 ? 2 : s <= 5 ? 5 : 10) * e }')
    if [[ "$live" == yes ]]; then head="$C_BOLD$title$C_RESET  $col$C_BOLD$(_st_fmt "$inst")$C_RESET ${C_GRAY}Мбит/с сейчас$C_RESET"
    else head="$C_BOLD$title$C_RESET  $col$C_BOLD$(_st_fmt "$med")$C_RESET ${C_GRAY}Мбит/с (медиана)$C_RESET"; fi
    local lines=() l
    while IFS= read -r l; do lines+=("$l"); done < <(st_chart "$cw" "$ch" "$mx" "$col" <<<"$vals")
    foot="${C_GRAY}ср$C_RESET $(_st_fmt "$mean") ${C_GRAY}мед$C_RESET $col$(_st_fmt "$med")$C_RESET ${C_GRAY}p25$C_RESET $(_st_fmt "$p25") ${C_GRAY}p75$C_RESET $(_st_fmt "$p75")"
    local fs=" ${C_GRAY}│ шкала $(_st_fmt "$mx")${C_RESET}"
    (( $(_st_vis "$foot$fs") <= cw )) && foot+="$fs"
    _st_box "$w" "$col" "$head" "${lines[@]}" "$foot"
}

_st_lat_box() {   # w файл title color scale
    local w="$1" f="$2" title="$3" col="$4" sc="$5" stats n mean med p25 p75 p95 mn mx sd
    # файла ещё нет (фаза не началась): редирект упал бы с ошибкой прямо на экран
    [[ -s "$f" ]] && stats=$(st_stats < "$f")
    read -r n mean med p25 p75 p95 mn mx sd <<<"$stats"
    local strip foot
    if [[ -n "$stats" ]]; then
        strip=$(st_strip $((w - 4)) "$mn" "$p25" "$med" "$p75" "$mx" "$sc" "$col")
        foot="${C_GRAY}p25$C_RESET $(_st_fmt "$p25") ${C_GRAY}p75$C_RESET $(_st_fmt "$p75") ${C_GRAY}джиттер$C_RESET $(_st_fmt "$sd")"
    else
        strip="$C_GRAY$(_st_rep · $((w - 4)))$C_RESET"; foot="${C_GRAY}ждёт…$C_RESET"
    fi
    _st_box "$w" "$col" "$C_BOLD$title$C_RESET $col$(_st_fmt "$med")$C_RESET ${C_GRAY}мс$C_RESET" "$strip" "$foot"
}

# склеить колонки (каждая — вывод _st_box) в строки
_st_side() {   # gap колонка1 колонка2 [колонка3]
    local gap="$1"; shift
    local -a a=() b=() c=(); mapfile -t a <<<"$1"; mapfile -t b <<<"$2"; [[ -n "${3:-}" ]] && mapfile -t c <<<"$3"
    local n=${#a[@]} i; ((${#b[@]} > n)) && n=${#b[@]}; ((${#c[@]} > n)) && n=${#c[@]}
    for ((i = 0; i < n; i++)); do
        printf '%s%*s%s' "${a[i]:-}" "$gap" "" "${b[i]:-}"
        [[ -n "${3:-}" ]] && printf '%*s%s' "$gap" "" "${c[i]:-}"
        printf '\n'
    done
}

st_render() {   # dl_dur ul_dur final(yes|no)
    local cols W live=yes now phase
    cols="${COLUMNS:-}"; [[ "$cols" =~ ^[0-9]+$ ]] || cols=$(tput cols 2>/dev/null || echo 100)
    W=$((cols > 150 ? 150 : cols)); ((W < 60)) && W=60
    [[ "$3" == yes ]] && live=no
    now=$(_st_now); phase=$(cat "$ST_T/phase" 2>/dev/null)
    local m_ip m_asn m_org m_colo m_city
    if [[ -s "$ST_T/meta.json" ]]; then
        IFS=$'\037' read -r m_ip m_asn m_org m_colo m_city < <(jq -r '[.ip, (.asn|tostring), .org, .colo, .colo_city] | join("\u001f")' "$ST_T/meta.json")
    fi
    # шапка: фазы
    local ph p mark steps=""
    for p in Простой Скачивание Отдача Потери; do
        if [[ "$phase" == "$p" ]]; then mark="${C_YELLOW}◉ $C_BOLD$p$C_RESET"
        elif [[ -f "$ST_T/done" ]] || { [[ "$p" == Простой && "$phase" =~ ^(Скачивание|Отдача|Потери|Итог)$ ]]; } \
            || { [[ "$p" == Скачивание && "$phase" =~ ^(Отдача|Потери|Итог)$ ]]; } || { [[ "$p" == Отдача && "$phase" =~ ^(Потери|Итог)$ ]]; }; then mark="${C_GREEN}● $p$C_RESET"
        else mark="${C_GRAY}○ $p$C_RESET"; fi
        steps+="$mark  "
    done
    ph="$C_BOLD${C_MAGENTA}☁ Cloudflare Speedtest$C_RESET ${C_GRAY}fail2detect v$F2D_VERSION$C_RESET"
    printf ' %s   %s\n' "$ph" "$steps"
    printf ' %s\n' "$C_GRAY${m_colo:+Cloudflare $m_colo${m_city:+ ($m_city)}}${m_asn:+ · AS$m_asn $m_org}${m_ip:+ · $m_ip}$C_RESET"

    # скорость
    if ((W >= 100)); then
        local hw=$(((W - 1) / 2))
        _st_side 1 "$(_st_tp_box "$hw" down "↓ Скачивание" "$C_GREEN" "$1" "$now" "$live")" "$(_st_tp_box $((W - 1 - hw)) up "↑ Отдача" "$C_MAGENTA" "$2" "$now" "$live")"
    else
        _st_tp_box "$W" down "↓ Скачивание" "$C_GREEN" "$1" "$now" "$live"
        _st_tp_box "$W" up "↑ Отдача" "$C_MAGENTA" "$2" "$now" "$live"
    fi
    # задержка — общая шкала для трёх полос
    # общая шкала трёх полос: от минимума до p95 с запасом (редкие выбросы не сжимают картину)
    local sc; sc=$(cat "$ST_T/idle.lat" "$ST_T/down.lat" "$ST_T/up.lat" 2>/dev/null | st_stats \
        | awk '{lo = $7; hi = $6 * 1.15; if (hi > $8 || hi <= lo) hi = $8; pad = (hi - lo) * 0.08 + 1; lo -= pad; if (lo < 0) lo = 0; printf "%.1f %.1f", lo, hi + pad}')
    [[ -n "$sc" ]] || sc="0 1"
    if ((W >= 100)); then
        local tw=$(((W - 2) / 3))
        _st_side 1 "$(_st_lat_box "$tw" "$ST_T/idle.lat" "◷ Простой" "$C_CYAN" "$sc")" \
            "$(_st_lat_box "$tw" "$ST_T/down.lat" "◷ При скачивании" "$C_GREEN" "$sc")" \
            "$(_st_lat_box $((W - 2 - 2 * tw)) "$ST_T/up.lat" "◷ При отдаче" "$C_MAGENTA" "$sc")"
    else
        _st_lat_box "$W" "$ST_T/idle.lat" "◷ Простой" "$C_CYAN" "$sc"
        _st_lat_box "$W" "$ST_T/down.lat" "◷ При скачивании" "$C_GREEN" "$sc"
        _st_lat_box "$W" "$ST_T/up.lat" "◷ При отдаче" "$C_MAGENTA" "$sc"
    fi
    # потери (UDP/STUN)
    local udp_line gauge=""
    if [[ "$(cat "$ST_T/udp.state" 2>/dev/null)" == unreachable ]]; then
        udp_line="${C_RED}STUN недоступен$C_RESET ${C_GRAY}(UDP 3478 закрыт по пути)$C_RESET"
    elif [[ -s "$ST_T/udp" ]]; then
        local sent recv loss rr
        sent=$(wc -l < "$ST_T/udp" | tr -d ' '); recv=$(grep -c '^ok' "$ST_T/udp")
        loss=$(awk -v s="$sent" -v r="$recv" 'BEGIN{printf "%.1f", (s - r) * 100 / s}')
        rr=$(awk '$1=="ok"{print $2}' "$ST_T/udp" | st_stats)
        local _n _m rmed _a _b _c _d _e rsd lab lc mos
        read -r _n _m rmed _a _b _c _d _e rsd <<<"$rr"
        lab=$(st_loss_label "$loss"); mos=$( [[ -n "$rmed" ]] && st_mos "$rmed" "$rsd" "$loss")
        case "$lab" in Отлично|Хорошо) lc="$C_GREEN";; Приемлемо) lc="$C_YELLOW";; *) lc="$C_RED";; esac
        udp_line="$lc$C_BOLD$lab$C_RESET  ${C_GRAY}MOS$C_RESET ${mos:-—}  ${C_GRAY}потери$C_RESET $lc$loss%$C_RESET  ${C_GRAY}RTT$C_RESET $(_st_fmt "$rmed") мс  ${C_GRAY}джиттер$C_RESET $(_st_fmt "$rsd") мс  ${C_GRAY}пакетов$C_RESET $recv/$sent"
        local gw=$((W - 4)) okw
        okw=$(awk -v r="$recv" -v s="$sent" -v w="$gw" 'BEGIN{print int(r / s * w + 0.5)}')
        gauge="$C_GREEN$(_st_rep ▰ "$okw")$C_RED$(_st_rep ▱ $((gw - okw)))$C_RESET"
    else
        udp_line="${C_GRAY}ждёт…$C_RESET"
    fi
    if [[ -n "$gauge" ]]; then _st_box "$W" "$C_BLUE" "${C_BOLD}≋ Потери пакетов$C_RESET ${C_GRAY}UDP/STUN$C_RESET" "$udp_line" "$gauge"
    else _st_box "$W" "$C_BLUE" "${C_BOLD}≋ Потери пакетов$C_RESET ${C_GRAY}UDP/STUN$C_RESET" "$udp_line"; fi

    # итог
    if [[ "$3" == yes && -s "$ST_T/result.json" ]]; then
        local r bb bg cv sg fam iface dns tlsm tls
        r=$(<"$ST_T/result.json")
        bb=$(jq -r '.bufferbloat_ms // empty' <<<"$r"); cv=$(jq -r '.cv_worst // empty' <<<"$r")
        bg=$( [[ -n "$bb" ]] && st_bloat_grade "$bb" || echo -); sg=$( [[ -n "$cv" ]] && st_stab_grade "$cv" || echo -)
        IFS=$'\037' read -r fam iface dns tlsm tls < <(jq -r '[.net.family, .net.iface, .net.dns, .net.tls_ms, .net.tls] | map(. // "?") | join("\u001f")' <<<"$r")
        local left right lw rw
        if ((W >= 100)); then lw=$(((W - 1) / 2)); rw=$((W - 1 - lw)); else lw=$W; rw=$W; fi
        local conn="$fam"; [[ "$iface" != "?" ]] && conn+=" · $iface"
        left=$(_st_box "$lw" "$C_GRAY" "${C_BOLD}Сеть$C_RESET" \
            "${C_GRAY}Подключение$C_RESET  $conn" \
            "${C_GRAY}Провайдер$C_RESET    $(_st_cut "${m_org:-?}" $((lw - 27))) ${C_GRAY}AS${m_asn:-?}$C_RESET" \
            "${C_GRAY}DNS$C_RESET          $(_st_fmt "$dns") мс   ${C_GRAY}TLS$C_RESET $(_st_fmt "$tlsm") мс $tls")
        right=$(_st_box "$rw" "$C_GRAY" "${C_BOLD}Оценка$C_RESET" \
            "${C_GRAY}Bufferbloat$C_RESET   $(_st_grade_col "$bg")$C_BOLD$bg$C_RESET ${C_GRAY}+$(_st_fmt "$bb") мс под нагрузкой$C_RESET" \
            "${C_GRAY}Стабильность$C_RESET  $(_st_grade_col "$sg")$C_BOLD$sg$C_RESET ${C_GRAY}разброс ↓$(_st_fmt "$(jq -r '.cv_download // empty' <<<"$r")")% ↑$(_st_fmt "$(jq -r '.cv_upload // empty' <<<"$r")")%$C_RESET" \
            "${C_GRAY}История$C_RESET       $([[ -n "${ST_SAVED:-}" ]] && echo "сохранено · f2d speed history" || echo "не сохранено")")
        if ((W >= 100)); then _st_side 1 "$left" "$right"; else echo "$left"; echo "$right"; fi
    fi
}

# ---------------------------------------------------------------- запуск
# клавиша дашборда → действие (английская и русская раскладка на тех же клавишах)
_st_key_action() {
    case "$1" in
        q|Q|й|Й) echo quit;; r|R|к|К) echo restart;; h|H|р|Р) echo history;;
        a|A|ф|Ф) echo autosave;; "") echo enter;; *) echo none;;
    esac
}

_st_keys_line() {   # итог показан?
    local sv="${C_GREEN}вкл${C_RESET}"; [[ "${SPEEDTEST_SAVE:-yes}" == yes ]] || sv="${C_RED}выкл${C_RESET}"
    local st=""
    if [[ "$1" == yes ]]; then
        if [[ -n "${ST_SAVED:-}" ]]; then st=" ${C_GRAY}(замер сохранён)${C_RESET}"; else st=" ${C_GRAY}(замер не сохранён)${C_RESET}"; fi
    fi
    printf ' %sA%s автосохранение: %s%s   %sR%s заново   %sH%s история   %sQ%s выход' \
        "$C_BOLD$C_YELLOW" "$C_RESET" "$sv" "$st" "$C_BOLD$C_YELLOW" "$C_RESET" "$C_BOLD$C_YELLOW" "$C_RESET" "$C_BOLD$C_YELLOW" "$C_RESET"
}

_st_save() {
    [[ -s "$ST_T/result.json" ]] && mkdir -p "$ST_HISTORY_DIR" 2>/dev/null || return 1
    ST_SAVED="$ST_HISTORY_DIR/$(date +%Y%m%d-%H%M%S).json"
    cp "$ST_T/result.json" "$ST_SAVED" 2>/dev/null || { ST_SAVED=""; return 1; }
    # имена — время замера, по ним и сортируем; храним 100 последних
    local old=("$ST_HISTORY_DIR"/*.json)
    ((${#old[@]} > 100)) && rm -f "${old[@]:0:${#old[@]}-100}"
    return 0
}

# A: переключить автосохранение; на итоговом экране — сразу сохранить/убрать этот замер
_st_toggle_save() {   # итог показан?
    if [[ "${SPEEDTEST_SAVE:-yes}" == yes ]]; then
        SPEEDTEST_SAVE=no; [[ $EUID -eq 0 ]] && config_set SPEEDTEST_SAVE no >/dev/null 2>&1
        [[ "$1" == yes && -n "${ST_SAVED:-}" ]] && { rm -f "$ST_SAVED"; ST_SAVED=""; }
    else
        SPEEDTEST_SAVE=yes; [[ $EUID -eq 0 ]] && config_set SPEEDTEST_SAVE yes >/dev/null 2>&1
        [[ "$1" == yes && -z "${ST_SAVED:-}" ]] && _st_save
    fi
}

_st_frame() {   # dl ul final
    local frame; frame=$(st_render "$@"; echo; _st_keys_line "$3")
    printf '\033[H%s\033[J' "${frame//$'\n'/$'\033[K\n'}"
}

# H: история поверх дашборда
_st_history_screen() {
    local frame; frame=$(speedtest_history; echo; printf ' %sлюбая клавиша — назад%s' "$C_GRAY" "$C_RESET")
    printf '\033[H%s\033[J' "${frame//$'\n'/$'\033[K\n'}"
    read -rsn1 _ </dev/tty 2>/dev/null
}

_st_stop_engine() { _st_kill_tree "$1"; wait "$1" 2>/dev/null; }

# ---------------------------------------------------------------- движок на Rust
# f2d-speed (каталог speed/ репозитория): точнее bash-версии — байты считает по
# мере прихода, у каждого потока своё соединение. Бинарник берётся из релиза
# fail2detect той же версии (sha256 проверяется); нет его — работает bash-версия.
# SPEEDTEST_ENGINE=bash — всегда bash; F2D_SPEED_BIN — свой бинарник.
ST_BIN_URL="https://github.com/${F2D_REPO}/releases/download"

_st_bin_dir() {
    if [[ -w "$F2D_STATE_DIR" ]] || { [[ $EUID -eq 0 ]] && mkdir -p "$F2D_STATE_DIR" 2>/dev/null; }; then echo "$F2D_STATE_DIR/bin"
    else echo "${XDG_CACHE_HOME:-$HOME/.cache}/fail2detect"; fi
}

speedtest_bin() {
    [[ -n "${F2D_SPEED_BIN:-}" ]] && { [[ -x "$F2D_SPEED_BIN" ]] && echo "$F2D_SPEED_BIN"; return; }
    [[ "$(uname -s)" == Linux ]] || return 1
    local arch dir bin miss tmp url sum
    case "$(uname -m)" in x86_64|amd64) arch=x86_64;; aarch64|arm64) arch=aarch64;; *) return 1;; esac
    dir=$(_st_bin_dir); bin="$dir/f2d-speed"; miss="$dir/.miss-$F2D_VERSION"
    [[ -x "$bin" && "$("$bin" --version 2>/dev/null)" == "$F2D_VERSION" ]] && { echo "$bin"; return 0; }
    # релиза этой версии нет или GitHub недоступен — не пробуем чаще раза в сутки
    [[ -f "$miss" ]] && (( $(date +%s) - $(stat -c %Y "$miss" 2>/dev/null || echo 0) < 86400 )) && return 1
    mkdir -p "$dir" 2>/dev/null || return 1
    url="$ST_BIN_URL/v$F2D_VERSION/f2d-speed-$arch-linux.tar.gz"
    tmp=$(mktemp -d)
    [[ -t 2 ]] && printf '  %s➜%s загружаю движок спидтеста (f2d-speed %s)…\r' "$C_CYAN" "$C_RESET" "$F2D_VERSION" >&2
    if curl -fsSL --connect-timeout 5 --max-time 60 -o "$tmp/a.tgz" "$url" 2>/dev/null \
        && sum=$(curl -fsSL --connect-timeout 5 --max-time 15 "$url.sha256" 2>/dev/null | awk '{print $1}') \
        && [[ "$(sha256sum "$tmp/a.tgz" | awk '{print $1}')" == "$sum" ]] \
        && tar -xzf "$tmp/a.tgz" -C "$tmp" f2d-speed 2>/dev/null \
        && [[ "$("$tmp/f2d-speed" --version 2>/dev/null)" == "$F2D_VERSION" ]]; then
        install -m 755 "$tmp/f2d-speed" "$bin"; rm -rf "$tmp"; rm -f "$dir"/.miss-*
        [[ -t 2 ]] && printf '\033[K' >&2
        echo "$bin"; return 0
    fi
    rm -rf "$tmp"; : > "$miss"
    [[ -t 2 ]] && printf '\033[K' >&2
    return 1
}

# запуск f2d-speed; переключатель автосохранения (A) сохраняется в конфиг, как у bash-версии
_st_run_bin() {   # бинарник аргументы…
    local bin="$1" a args=() so rc save0="${SPEEDTEST_SAVE:-yes}" save1; shift
    for a in "$@"; do case "$a" in --quick|--plain|--json|--no-save) args+=("$a");; esac; done
    [[ "$save0" == yes ]] || args+=(--no-save)
    so=$(mktemp)
    "$bin" --history-dir "$ST_HISTORY_DIR" --f2d-version "$F2D_VERSION" --state-out "$so" "${args[@]}"; rc=$?
    save1=$(sed -n 's/^SPEEDTEST_SAVE=//p' "$so" 2>/dev/null); rm -f "$so"
    if [[ -n "$save1" && "$save1" != "$save0" && " $* " != *" --no-save "* ]]; then
        SPEEDTEST_SAVE="$save1"; [[ $EUID -eq 0 ]] && config_set SPEEDTEST_SAVE "$save1" >/dev/null 2>&1
    fi
    return "$rc"
}

speedtest_run() {   # [--quick] [--plain] [--json] [--no-save]
    local bin
    if [[ "${SPEEDTEST_ENGINE:-auto}" != bash ]] && bin=$(speedtest_bin); then
        _st_run_bin "$bin" "$@"; return
    fi
    have curl || die "Нужен curl"; have jq || die "Нужен jq"
    ((BASH_VERSINFO[0] >= 5)) || die "Нужен bash 5+"
    local quick="" plain="" json="" a
    for a in "$@"; do case "$a" in --quick) quick=1;; --plain) plain=1;; --json) json=1;; --no-save) SPEEDTEST_SAVE=no;; --tui) ;; esac; done
    [[ -t 1 ]] || plain=1
    [[ -n "$json" ]] && plain=1
    local idle=2 dl=10 ul=10 udp=50
    [[ -n "$quick" ]] && { dl=5; ul=5; udp=25; }

    local eng key act
    # shellcheck disable=SC2064
    trap '[[ -n "${eng:-}" ]] && _st_stop_engine "$eng"; printf "\033[?25h\033[?1049l"; rm -rf "${ST_T:-/nonexistent}"; trap - INT TERM; exit 130' INT TERM
    [[ -z "$plain" ]] && printf '\033[?1049h\033[?25l'
    while true; do
        ST_T=$(mktemp -d); ST_SAVED=""; act=""
        _st_engine "$idle" "$dl" "$ul" "$udp" &
        eng=$!
        if [[ -z "$plain" ]]; then
            while [[ ! -f "$ST_T/done" ]] && kill -0 "$eng" 2>/dev/null; do
                _st_frame "$dl" "$ul" no
                read -rsn1 -t 0.3 key </dev/tty 2>/dev/null || continue
                case "$(_st_key_action "$key")" in
                    quit) act=quit; break;;
                    restart) act=restart; break;;
                    autosave) _st_toggle_save no;;
                    history) _st_history_screen;;
                esac
            done
        else
            local s='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' i=0
            while [[ ! -f "$ST_T/done" ]] && kill -0 "$eng" 2>/dev/null; do
                [[ -z "$json" && -t 2 ]] && printf '\r  %s %s…\033[K' "${s:i++%10:1}" "$(cat "$ST_T/phase" 2>/dev/null)" >&2
                sleep 0.3
            done
            [[ -z "$json" && -t 2 ]] && printf '\r\033[K' >&2
        fi
        if [[ -n "$act" ]]; then
            _st_stop_engine "$eng"; rm -rf "$ST_T"
            [[ "$act" == restart ]] && continue
            printf '\033[?25h\033[?1049l'; trap - INT TERM; return 0
        fi
        wait "$eng" 2>/dev/null; eng=""

        st_result_json "$dl" "$ul" > "$ST_T/result.json" 2>/dev/null
        [[ "${SPEEDTEST_SAVE:-yes}" == yes ]] && _st_save

        if [[ -n "$json" ]]; then cat "$ST_T/result.json"; break
        elif [[ -n "$plain" ]]; then st_render "$dl" "$ul" yes; break; fi

        # итоговый экран: ждём клавишу
        while true; do
            _st_frame "$dl" "$ul" yes
            read -rsn1 key </dev/tty 2>/dev/null || { act=quit; break; }
            act=$(_st_key_action "$key")
            case "$act" in
                quit|enter|restart) break;;
                autosave) _st_toggle_save yes;;
                history) _st_history_screen;;
            esac
        done
        if [[ "$act" == restart ]]; then rm -rf "$ST_T"; continue; fi
        printf '\033[?25h\033[?1049l'
        st_render "$dl" "$ul" yes
        break
    done
    trap - INT TERM
    rm -rf "$ST_T"
}

# история замеров
speedtest_history() {
    local f n=0
    title "История замеров (Cloudflare)"
    # printf считает ширину в байтах — кириллицу выравниваем по символам сами
    _st_pad() { local t="$1" w="$2" p; p=$((${w#-} - ${#t})); ((p < 0)) && p=0
        if [[ "$w" == -* ]]; then printf '%s%*s' "$t" "$p" ""; else printf '%*s%s' "$p" "" "$t"; fi; }
    printf '  %s%s %s %s %s %s %s %s %s %s%s\n' "$C_BOLD" "$(_st_pad Время -17)" "$(_st_pad Точка -6)" "$(_st_pad "↓ Мбит/с" 10)" "$(_st_pad "↑ Мбит/с" 10)" \
        "$(_st_pad Простой 9)" "$(_st_pad Нагрузка 9)" "$(_st_pad Потери 6)" "$(_st_pad BB 4)" "$(_st_pad Стб 4)" "$C_RESET"
    local all=("$ST_HISTORY_DIR"/*.json) i
    for ((i = ${#all[@]} - 1; i >= 0 && i >= ${#all[@]} - 20; i--)); do
        f="${all[i]}"; [[ -f "$f" ]] || continue
        n=$((n + 1))
        jq -r '[(.time | sub("T"; " ") | sub(":[0-9]+Z$"; "")), (.meta.colo // "?"),
            (.download.med // 0 | floor | tostring), (.upload.med // 0 | floor | tostring),
            ((.idle_latency.med // 0) | floor | tostring), ([.loaded_latency_download.med, .loaded_latency_upload.med] | map(. // 0) | max | floor | tostring),
            (if .udp.loss == null then "—" else (.udp.loss | tostring) + "%" end),
            (.bufferbloat_ms // -1 | tostring), (.cv_worst // -1 | tostring)] | join("\u001f")' "$f" 2>/dev/null \
        | while IFS=$'\037' read -r t c d u il ll lo bb cv; do
            local bg sg
            bg=$( [[ "$bb" != -1 ]] && st_bloat_grade "$bb" || echo -); sg=$( [[ "$cv" != -1 ]] && st_stab_grade "$cv" || echo -)
            printf '  %-17s %-6s %s%10s%s %s%10s%s %6s мс %6s мс %6s %s%4s%s %s%4s%s\n' "$t" "$c" "$C_GREEN" "$d" "$C_RESET" "$C_MAGENTA" "$u" "$C_RESET" "$il" "$ll" "$lo" \
                "$(_st_grade_col "$bg")" "$bg" "$C_RESET" "$(_st_grade_col "$sg")" "$sg" "$C_RESET"
        done
    done
    ((n)) || info "Замеров ещё нет: f2d speed"
}

speedtest_cli() {
    case "${1:-}" in
        history|hist) speedtest_history;;
        *) speedtest_run "$@";;
    esac
}

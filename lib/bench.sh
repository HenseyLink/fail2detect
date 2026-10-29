#!/usr/bin/env bash
# fail2detect — бенчмарк сети: скорость и пинг до российских и зарубежных провайдеров.
#
# Россия — iperf3 до публичных серверов провайдеров (список — как в bench.gig.ovh).
# Зарубеж — Ookla Speedtest CLI по ID серверов (список — как в bench.sh); CLI
# скачивается с install.speedtest.net только с согласия на лицензию Ookla.
# Без него — iperf3 до зарубежных серверов.
# Пинг — ICMP (5 пакетов); если ICMP закрыт — время TCP-подключения.

# хост:порт:город:провайдер
BENCH_RU=(
    'spd-rudp.hostkey.ru:5201:Москва:Hostkey'
    'st.spb.ertelecom.ru:5201:Санкт-Петербург:Дом.ру'
    'st.bryansk.ertelecom.ru:5201:Брянск:Дом.ру'
    'voronezh-speedtest.corbina.net:5201:Воронеж:Билайн'
    'st.rostov.ertelecom.ru:5201:Ростов-на-Дону:Дом.ру'
    'st.volgograd.ertelecom.ru:5201:Волгоград:Дом.ру'
    'st.nn.ertelecom.ru:5201:Нижний Новгород:Дом.ру'
    'st.kzn.ertelecom.ru:5201:Казань:Дом.ру'
    'st.samara.ertelecom.ru:5201:Самара:Дом.ру'
    'st.ekat.ertelecom.ru:5201:Екатеринбург:Дом.ру'
    'st.chel.ertelecom.ru:5201:Челябинск:Дом.ру'
    'st.krsk.ertelecom.ru:5202:Красноярск:Дом.ру'
    'st.irkutsk.ertelecom.ru:5201:Иркутск:Дом.ру'
)
BENCH_WORLD_IPERF=(
    'iperf-ams-nl.eranium.net:5201:Амстердам, NL:Eranium'
    'iperf3.moji.fr:5200:Париж, FR:Moji'
    'a208.speedtest.wobcom.de:5201:Дюссельдорф, DE:WOBCOM'
    'speedtest.fra1.de.leaseweb.net:5201:Франкфурт, DE:Leaseweb'
    'spd-fisrv.hostkey.com:5201:Хельсинки, FI:Hostkey'
    'speedtest.nyc1.us.leaseweb.net:5201:Нью-Йорк, US:Leaseweb'
)
# id:город (пустой id — ближайший сервер Ookla)
BENCH_WORLD_OOKLA=(
    ':Ближайший'
    '7190:Лос-Анджелес, US'
    '22288:Даллас, US'
    '64420:Монреаль, CA'
    '61933:Париж, FR'
    '41423:Амстердам, NL'
    '32155:Гонконг, HK'
    '13623:Сингапур, SG'
    '48463:Токио, JP'
)

BENCH_OOKLA_VER="1.2.0"
BENCH_OOKLA_DIR="${F2D_STATE_DIR}/ookla"

# ---------------------------------------------------------------- разбор
# вывод ping → "среднее потери%" (iputils, busybox, BSD)
bench_parse_ping() {
    awk '/packet loss/ { for (i = 1; i <= NF; i++) if ($i ~ /%$/) { l = $i; sub(/%/, "", l) } }
         /min\/avg\/max/ { split($0, a, "="); split(a[2], v, "/"); gsub(/ /, "", v[2]); avg = v[2] }
         END { if (l == "") exit; printf "%s %s\n", (avg == "" ? "-" : avg), l }'
}

# JSON iperf3 → Мбит/с (или "ERR текст")
bench_parse_iperf() {
    jq -r 'if (.error // "") != "" then "ERR " + .error
           else ((.end.sum_received.bits_per_second // .end.sum.bits_per_second // 0) / 1e6 * 100 | round / 100 | tostring) end' 2>/dev/null
}

# JSON Ookla → "пинг ↓ ↑ сервер" (Мбит/с)
bench_parse_ookla() {
    jq -r 'select(.type == "result") | [(.ping.latency * 10 | round / 10), (.download.bandwidth * 8 / 1e6 * 100 | round / 100),
        (.upload.bandwidth * 8 / 1e6 * 100 | round / 100), ((.server.location // "") + " · " + (.server.name // ""))] | join("\u001f")' 2>/dev/null
}

# ---------------------------------------------------------------- рисование
# логарифмическая шкала 1…10000 Мбит/с в 12 делениях: видно и 5, и 5000
bench_bar() {   # мбит цвет
    awk -v v="$1" -v col="$2" -v rst="$C_RESET" -v gray="$C_GRAY" 'BEGIN {
        w = 12; n = (v >= 1) ? int(log(v) / log(10) / 4 * w + 0.5) : 0; if (v > 0 && n < 1) n = 1; if (n > w) n = w
        s = col; for (i = 0; i < n; i++) s = s "▰"; s = s gray; for (; i < w; i++) s = s "▱"; print s rst }'
}

bench_ping_col() {
    awk -v p="$1" -v g="$C_GREEN" -v y="$C_YELLOW" -v r="$C_RED" -v gr="$C_GRAY" 'BEGIN {
        if (p == "" || p == "-") printf "%s", gr; else if (p < 50) printf "%s", g; else if (p < 150) printf "%s", y; else printf "%s", r }'
}

_bench_fmt() { awk -v v="${1:-}" 'BEGIN { if (v == "" || v == "-") print "—"; else if (v >= 100) printf "%.0f", v; else if (v >= 10) printf "%.1f", v; else printf "%.2f", v }'; }

# выравнивание по символам (printf считает байты)
_bench_pad() { local t="$1" w="$2" p; ((${#t} > ${w#-})) && t="${t:0:${w#-}-1}…"; p=$((${w#-} - ${#t}))
    if [[ "$w" == -* ]]; then printf '%s%*s' "$t" "$p" ""; else printf '%*s%s' "$p" "" "$t"; fi; }

bench_row() {   # город провайдер пинг потери ↓ ↑ [ошибка]
    local city="$1" prov="$2" ping="$3" loss="$4" dl="$5" ul="$6" e="${7:-}"
    local pc tcp=" "; pc=$(bench_ping_col "${ping#≈}")
    [[ "$ping" == ≈* ]] && { tcp="≈"; ping="${ping#≈}"; }   # ICMP закрыт — время TCP-подключения
    printf '  %s %s%s%s %s%s%s%s' "$(_bench_pad "$city" -16)" "$C_GRAY" "$(_bench_pad "$prov" -10)" "$C_RESET" "$C_GRAY$tcp" "$pc" "$(_bench_pad "$(_bench_fmt "$ping") мс" 8)" "$C_RESET"
    if awk -v l="${loss:-0}" 'BEGIN{exit !(l + 0 > 0)}' 2>/dev/null; then printf ' %s%s%s' "$C_RED" "$(_bench_pad "$(_bench_fmt "$loss")%" 5)" "$C_RESET"; else printf '      '; fi
    if [[ -n "$e" ]]; then printf '  %s%s%s\n' "$C_RED" "$e" "$C_RESET"; return; fi
    if [[ -z "$dl$ul" ]]; then printf '\n'; return; fi
    printf '  %s↓%s %s %s  %s↑%s %s %s\n' "$C_GREEN" "$C_RESET" "$(bench_bar "$dl" "$C_GREEN")" "$(_bench_pad "$(_bench_fmt "$dl")" 6)" \
        "$C_MAGENTA" "$C_RESET" "$(bench_bar "$ul" "$C_MAGENTA")" "$(_bench_pad "$(_bench_fmt "$ul")" 6)"
}

bench_section() {   # заголовок
    local t=" $1 " w=78
    printf '\n %s━━%s%s%s%s%s\n' "$C_BLUE" "$C_RESET$C_BOLD" "$t" "$C_RESET$C_BLUE" "$(printf '━%.0s' $(seq 1 $((w - ${#t} - 2))))" "$C_RESET"
}

# ---------------------------------------------------------------- замеры
bench_ping() {   # хост [порт] → "мс потери" (мс с ≈ — по TCP)
    local out r
    if have ping; then
        out=$(LC_ALL=C ping -c 5 -i 0.2 -W 2 "$1" 2>/dev/null || LC_ALL=C ping -c 5 -W 2 "$1" 2>/dev/null)
        r=$(bench_parse_ping <<<"$out")
        if [[ -n "$r" && "${r%% *}" != "-" ]]; then echo "$r"; return; fi
    fi
    # ICMP закрыт — время TCP-подключения к порту iperf3/443
    local t; t=$(curl -s -o /dev/null --max-time 3 -w '%{time_connect}' "telnet://$1:${2:-443}" </dev/null 2>/dev/null)
    awk -v t="$t" 'BEGIN { if (t > 0) printf "≈%.1f 0\n", t * 1000; else print "- 100" }'
}

# iperf3 с повтором, если сервер занят чужим тестом; печатает Мбит/с или "ERR …"
bench_iperf() {   # хост порт reverse(yes|no)
    local h="$1" p="$2" try port r args=(-c "$1" -P "$BENCH_THREADS" -t "$BENCH_DUR" -O 2 -J)
    [[ "$3" == yes ]] && args+=(-R)
    iperf3 --help 2>&1 | grep -q -- '--connect-timeout' && args+=(--connect-timeout 4000)
    for try in 1 2 3; do
        # у многих публичных серверов несколько портов подряд
        for port in "$p" $((p + 1)) $((p + 2)); do
            r=$(timeout $((BENCH_DUR + 15)) iperf3 "${args[@]}" -p "$port" 2>/dev/null | bench_parse_iperf)
            [[ -z "$r" ]] && r="ERR нет ответа"
            [[ "$r" != ERR* ]] && { echo "$r"; return 0; }
            [[ "$r" == *busy* ]] || break
        done
        [[ "$r" == *busy* ]] || break
        sleep 3
    done
    echo "$r"
}

_bench_err_ru() {
    case "$1" in
        *busy*) echo "сервер занят";;
        *refused*|*"unable to connect"*|*"No route"*|*unreachable*) echo "недоступен";;
        *timeout*|*"timed out"*|*"нет ответа"*) echo "нет ответа";;
        *) echo "ошибка: ${1#ERR }";;
    esac
}

_bench_spin_row() {   # pid город провайдер стадия
    local s='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' i=0
    while kill -0 "$1" 2>/dev/null; do
        printf '\r  %s %s%s%s %s…\033[K' "$(_bench_pad "$2" -16)" "$C_GRAY" "$(_bench_pad "$3" -10)" "$C_RESET" "$C_CYAN${s:i++%10:1}$C_RESET $4"
        sleep 0.15
    done
    printf '\r\033[K'
}

# один iperf3-сервер: строка + запись в $BENCH_OUT
bench_iperf_server() {   # группа "хост:порт:город:провайдер"
    local grp="$1" h p city prov ping="" loss="" dl="" ul="" tmp e=""
    IFS=: read -r h p city prov <<<"$2"
    tmp=$(mktemp)
    { bench_ping "$h" "$p" > "$tmp"; } & _bench_spin_row $! "$city" "$prov" "пинг"
    read -r ping loss < "$tmp"
    if [[ "$loss" == 100 && "$ping" == "-" ]]; then
        e="недоступен"
    elif [[ -z "${BENCH_PING_ONLY:-}" ]]; then
        { bench_iperf "$h" "$p" yes > "$tmp"; } & _bench_spin_row $! "$city" "$prov" "скачивание ($BENCH_DUR с)"
        dl=$(<"$tmp")
        if [[ "$dl" == ERR* ]]; then e=$(_bench_err_ru "$dl"); dl=""
        else
            { bench_iperf "$h" "$p" no > "$tmp"; } & _bench_spin_row $! "$city" "$prov" "отдача ($BENCH_DUR с)"
            ul=$(<"$tmp"); [[ "$ul" == ERR* ]] && { e=$(_bench_err_ru "$ul"); ul=""; }
        fi
    fi
    rm -f "$tmp"
    [[ -n "$e" && -n "$dl" ]] && e="↓ $(_bench_fmt "$dl") · ↑ $e"
    bench_row "$city" "$prov" "$ping" "$loss" "$dl" "$ul" "$e"
    jq -nc --arg g "$grp" --arg c "$city" --arg pr "$prov" --arg h "$h" --arg ping "${ping#≈}" --arg loss "$loss" --arg dl "$dl" --arg ul "$ul" --arg e "$e" \
        '{group: $g, city: $c, provider: $pr, host: $h, ping: ($ping | tonumber? // null), loss: ($loss | tonumber? // null),
          download: ($dl | tonumber? // null), upload: ($ul | tonumber? // null), error: (if $e == "" then null else $e end)}' >> "$BENCH_OUT"
}

# ---------------------------------------------------------------- Ookla
bench_ookla_bin() { [[ -x "$BENCH_OOKLA_DIR/speedtest" ]] && echo "$BENCH_OOKLA_DIR/speedtest"; }

# скачать Ookla Speedtest CLI — только после согласия с лицензией
bench_ookla_install() {
    [[ -n "$(bench_ookla_bin)" ]] && return 0
    local arch
    case "$(uname -m)" in x86_64|amd64) arch=x86_64;; aarch64|arm64) arch=aarch64;; armv7*|armhf) arch=armhf;; i?86) arch=i386;; *) return 1;; esac
    echo
    info "Зарубежные замеры (как в bench.sh) идут через Ookla Speedtest CLI $BENCH_OOKLA_VER."
    echo "  Его нужно скачать с install.speedtest.net и принять условия Ookla:"
    echo "    https://www.speedtest.net/about/eula · https://www.speedtest.net/about/privacy"
    echo "  Без него зарубеж меряется через iperf3 (Европа и США)."
    confirm "Скачать Ookla Speedtest CLI и принять его условия?" n || { [[ $EUID -eq 0 ]] && config_set BENCH_OOKLA no >/dev/null; return 1; }
    mkdir -p "$BENCH_OOKLA_DIR"
    local tgz; tgz=$(mktemp)
    if curl -fsSL --max-time 60 -o "$tgz" "https://install.speedtest.net/app/cli/ookla-speedtest-${BENCH_OOKLA_VER}-linux-${arch}.tgz" \
        && tar -xzf "$tgz" -C "$BENCH_OOKLA_DIR" speedtest 2>/dev/null; then
        chmod 755 "$BENCH_OOKLA_DIR/speedtest"; rm -f "$tgz"
        [[ $EUID -eq 0 ]] && config_set BENCH_OOKLA yes >/dev/null
        ok "Ookla Speedtest CLI: $BENCH_OOKLA_DIR/speedtest"
        return 0
    fi
    rm -f "$tgz"; err "Не удалось скачать Ookla Speedtest CLI — меряю через iperf3"; return 1
}

bench_ookla_server() {   # "id:город"
    local id="${1%%:*}" city="${1#*:}" tmp r ping="" dl="" ul="" srv="" e="" args=(--accept-license --accept-gdpr -f json -p no)
    [[ -n "$id" ]] && args+=(-s "$id")
    tmp=$(mktemp)
    { timeout 90 "$(bench_ookla_bin)" "${args[@]}" > "$tmp" 2>/dev/null; } & _bench_spin_row $! "$city" "Ookla" "замер"
    r=$(bench_parse_ookla < "$tmp"); rm -f "$tmp"
    if [[ -n "$r" ]]; then
        IFS=$'\037' read -r ping dl ul srv <<<"$r"
    else
        e="замер не удался"
    fi
    # у ближайшего — показать, какой сервер выбран
    local prov="Ookla"; [[ -z "$id" && -n "${srv:-}" ]] && prov="${srv%% ·*}"
    bench_row "$city" "$prov" "${ping:-}" "" "${dl:-}" "${ul:-}" "$e"
    jq -nc --arg c "$city" --arg pr "${srv:-Ookla}" --arg h "ookla:$id" --arg ping "${ping:-}" --arg dl "${dl:-}" --arg ul "${ul:-}" --arg e "$e" \
        '{group: "world", city: $c, provider: $pr, host: $h, ping: ($ping | tonumber? // null), loss: null,
          download: ($dl | tonumber? // null), upload: ($ul | tonumber? // null), error: (if $e == "" then null else $e end)}' >> "$BENCH_OUT"
}

# ---------------------------------------------------------------- итог
bench_summary() {   # файл результатов
    bench_section "Итог"
    local g label n ok_n pm dm um
    for g in ru world; do
        [[ "$g" == ru ]] && label="Россия" || label="Зарубеж"
        n=$(jq -s --arg g "$g" 'map(select(.group == $g)) | length' "$1")
        ((n)) || continue
        read -r ok_n pm dm um < <(jq -rs --arg g "$g" '
            def med: sort | if length == 0 then null elif length % 2 == 1 then .[length / 2 | floor] else (.[length / 2 - 1] + .[length / 2]) / 2 end;
            map(select(.group == $g)) as $a
            | [($a | map(select(.error == null)) | length), ($a | map(.ping) | map(select(. != null)) | med), ($a | map(.download) | map(select(. != null)) | med),
               ($a | map(.upload) | map(select(. != null)) | med)] | map(if . == null then "-" else tostring end) | join(" ")' "$1")
        printf '  %s%s%s  %sпинг%s %s%s мс%s' "$C_BOLD" "$(_bench_pad "$label" -8)" "$C_RESET" "$C_GRAY" "$C_RESET" "$(bench_ping_col "$pm")" "$(_bench_pad "$(_bench_fmt "$pm")" 5)" "$C_RESET"
        [[ "$dm$um" != "--" ]] && printf '  %s↓%s %s  %s↑%s %s Мбит/с' "$C_GREEN" "$C_RESET" "$(_bench_fmt "$dm")" "$C_MAGENTA" "$C_RESET" "$(_bench_fmt "$um")"
        printf '  %sответили %s/%s%s\n' "$C_GRAY" "$ok_n" "$n" "$C_RESET"
    done
    local best worst
    best=$(jq -rs 'map(select(.download != null)) | max_by(.download) // empty | "\(.city) (\(.provider)) — ↓ \(.download | round)"' "$1")
    worst=$(jq -rs 'map(select(.ping != null)) | max_by(.ping) // empty | "\(.city) (\(.provider)) — \(.ping | . * 10 | round / 10) мс"' "$1")
    local near; near=$(jq -rs 'map(select(.ping != null)) | min_by(.ping) // empty | "\(.city) (\(.provider)) — \(.ping | . * 10 | round / 10) мс"' "$1")
    [[ -n "$near" ]] && printf '  %sБлиже всего%s    %s\n' "$C_GRAY" "$C_RESET" "$near"
    [[ -n "$best" ]] && printf '  %sБыстрее всего%s  %s Мбит/с\n' "$C_GRAY" "$C_RESET" "$best"
    [[ -n "$worst" ]] && printf '  %sДальше всего%s   %s\n' "$C_GRAY" "$C_RESET" "$worst"
}

# ---------------------------------------------------------------- запуск
bench_run() {   # [ru|world|all] [--ping] [--quick] [--threads N] [--ookla|--iperf] [--json]
    local what=all json="" engine="${BENCH_OOKLA:-}" a
    BENCH_THREADS=8; BENCH_DUR=8; BENCH_PING_ONLY=""
    while (($#)); do
        case "$1" in
            ru|russia|россия) what=ru;; world|intl|зарубеж) what=world;; all) what=all;;
            --ping) BENCH_PING_ONLY=1;; --quick) BENCH_DUR=4;;
            --threads|-P) BENCH_THREADS="${2:?число потоков}"; shift;;
            --single) BENCH_THREADS=1;;
            --ookla) engine=yes;; --iperf) engine=no;;
            --json) json=1;;
            *) die "bench [ru|world|all] [--ping] [--quick] [--threads N] [--single] [--ookla|--iperf] [--json]";;
        esac
        shift
    done
    have jq || die "Нужен jq"
    if [[ -z "$BENCH_PING_ONLY" ]] && ! have iperf3; then
        info "Нужен iperf3 — устанавливаю"
        require_root
        { have apt-get && apt-get update -qq >/dev/null 2>&1; pkg_install iperf3; } || die "Не удалось установить iperf3"
    fi
    BENCH_OUT=$(mktemp)
    # shellcheck disable=SC2064
    trap "rm -f '$BENCH_OUT'; printf '\033[?25h'; trap - INT TERM; exit 130" INT TERM
    [[ -n "$json" ]] && exec 3>&1 1>/dev/null

    local me; me=$(curl -fsS --max-time 5 https://speed.cloudflare.com/meta 2>/dev/null)
    printf '\n %s⚡ Бенчмарк сети%s %sfail2detect v%s%s\n' "$C_BOLD$C_MAGENTA" "$C_RESET" "$C_GRAY" "$F2D_VERSION" "$C_RESET"
    if jq -e .clientIp >/dev/null 2>&1 <<<"$me"; then
        printf ' %s%s · AS%s %s · %s%s\n' "$C_GRAY" "$(jq -r .clientIp <<<"$me")" "$(jq -r .asn <<<"$me")" "$(jq -r .asOrganization <<<"$me")" "$(jq -r '.country // "?"' <<<"$me")" "$C_RESET"
    fi
    if [[ -n "$BENCH_PING_ONLY" ]]; then printf ' %sтолько пинг%s\n' "$C_GRAY" "$C_RESET"
    else printf ' %siperf3: %s потоков, по %s с в каждую сторону · шкала ▰ логарифмическая, 1…10 000 Мбит/с%s\n' "$C_GRAY" "$BENCH_THREADS" "$BENCH_DUR" "$C_RESET"; fi
    printf '\033[?25l'

    local s
    if [[ "$what" != world ]]; then
        bench_section "Россия"
        for s in "${BENCH_RU[@]}"; do bench_iperf_server ru "$s"; done
    fi
    if [[ "$what" != ru ]]; then
        # зарубеж: Ookla (как bench.sh) — если согласились; иначе iperf3
        local use_ookla=no
        if [[ -z "$BENCH_PING_ONLY" && "$engine" != no ]]; then
            if [[ -n "$(bench_ookla_bin)" ]]; then use_ookla=yes
            elif [[ "$engine" == yes || ( -z "$engine" && -t 0 && -z "$json" ) ]]; then
                printf '\033[?25h'; bench_ookla_install && use_ookla=yes; printf '\033[?25l'
            fi
        fi
        if [[ "$use_ookla" == yes ]]; then
            bench_section "Зарубеж · Ookla Speedtest"
            for s in "${BENCH_WORLD_OOKLA[@]}"; do bench_ookla_server "$s"; done
        else
            bench_section "Зарубеж"
            for s in "${BENCH_WORLD_IPERF[@]}"; do bench_iperf_server world "$s"; done
        fi
    fi
    bench_summary "$BENCH_OUT"
    printf '\033[?25h\n'
    if [[ -n "$json" ]]; then exec 1>&3 3>&-; jq -s '.' "$BENCH_OUT"; fi
    rm -f "$BENCH_OUT"; trap - INT TERM
}

#!/usr/bin/env bash
# fail2detect — бан-движок по принципу fail2ban и журнал аудита.
#
# Jail = источник логов + регулярки + пороги. Демон читает источники
# потоково, считает «неудачи» по IP в окне FINDTIME и, набрав MAXRETRY,
# добавляет IP в набор nftables с таймаутом (снимается ядром само).
# Каждое действие пишется в журнал аудита, чтобы чистый IP можно было
# найти и разбанить.

F2D_LOCK="${F2D_STATE_DIR}/bans.lock"
F2D_GEO_CACHE="${F2D_STATE_DIR}/geo.cache"

# ---------- журнал аудита ----------
# Формат TSV: время  действие  ip  jail  срок  страна  подробности
audit_write() {   # action ip jail duration details
    local action="$1" ip="${2:--}" jail="${3:--}" dur="${4:--}" details="${5:-}" cc="-"
    [[ "$ip" != - && "$action" == BAN ]] && cc=$(geo_country "$ip")
    mkdir -p "$F2D_LOG_DIR"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(iso_now)" "$action" "$ip" "$jail" "$dur" "$cc" "${details//$'\t'/ }" >> "$F2D_AUDIT_LOG"
}

geo_country() {
    [[ "$GEO_LOOKUP" == yes ]] || { echo "-"; return; }
    local ip="$1" cc
    cc=$(awk -v ip="$ip" '$1==ip{print $2; exit}' "$F2D_GEO_CACHE" 2>/dev/null)
    if [[ -z "$cc" ]]; then
        cc=$(curl -fsS --max-time 3 "http://ip-api.com/line/${ip}?fields=countryCode" 2>/dev/null | head -1)
        [[ "$cc" =~ ^[A-Z]{2}$ ]] || cc="??"
        [[ "$cc" != "??" ]] && echo "$ip $cc" >> "$F2D_GEO_CACHE"
    fi
    echo "$cc"
}

# audit_show [-n N] [--ip IP] [--jail J] [--action A] [--today]
audit_show() {
    local n=50 ip="" jail="" action="" day=""
    while (($#)); do
        case "$1" in
            -n) n="$2"; shift;; --ip) ip="$2"; shift;; --jail) jail="$2"; shift;;
            --action) action="${2^^}"; shift;; --today) day=$(date +%F);;
            *) ip="$1";;
        esac; shift
    done
    [[ -s "$F2D_AUDIT_LOG" ]] || { info "Журнал аудита пуст"; return; }
    title "Журнал аудита ($F2D_AUDIT_LOG)"
    printf '%s%-19s  %-10s %-39s %-10s %-8s %-3s %s%s\n' "$C_BOLD" "ВРЕМЯ" "ДЕЙСТВИЕ" "IP" "JAIL" "СРОК" "CC" "ПОДРОБНОСТИ" "$C_RESET"
    awk -F'\t' -v ip="$ip" -v jail="$jail" -v act="$action" -v day="$day" '
        (ip=="" || $3==ip) && (jail=="" || $4==jail) && (act=="" || $2==act) && (day=="" || index($1,day)==1)
    ' "$F2D_AUDIT_LOG" | tail -n "$n" | while IFS=$'\t' read -r t a i j d c rest; do
        local col="$C_RESET"
        case "$a" in BAN) col="$C_RED";; UNBAN|TRUST) col="$C_GREEN";; RECORD) col="$C_YELLOW";; *) col="$C_CYAN";; esac
        printf '%-19s  %s%-10s%s %-39s %-10s %-8s %-3s %s%s%s\n' "$t" "$col" "$a" "$C_RESET" "$i" "$j" "$d" "$c" "$C_GRAY" "$rest" "$C_RESET"
    done
}

audit_stats() {
    [[ -s "$F2D_AUDIT_LOG" ]] || { info "Журнал аудита пуст"; return; }
    title "Статистика банов"
    printf '  %-28s %s\n' "Всего банов:" "$(awk -F'\t' '$2=="BAN"' "$F2D_AUDIT_LOG" | wc -l)"
    printf '  %-28s %s\n' "За сегодня:" "$(awk -F'\t' -v d="$(date +%F)" '$2=="BAN" && index($1,d)==1' "$F2D_AUDIT_LOG" | wc -l)"
    echo; echo "  ${C_BOLD}По jail:${C_RESET}"
    awk -F'\t' '$2=="BAN"{c[$4]++} END{for(k in c) printf "    %-20s %d\n", k, c[k]}' "$F2D_AUDIT_LOG" | sort -k2 -nr
    echo; echo "  ${C_BOLD}Топ стран:${C_RESET}"
    awk -F'\t' '$2=="BAN"{c[$6]++} END{for(k in c) printf "    %-20s %d\n", k, c[k]}' "$F2D_AUDIT_LOG" | sort -k2 -nr | head -10
    echo; echo "  ${C_BOLD}Топ подсетей /24:${C_RESET}"
    awk -F'\t' '$2=="BAN" && $3 ~ /^[0-9.]+$/ {split($3,o,"."); c[o[1]"."o[2]"."o[3]".0/24"]++} END{for(k in c) printf "    %-20s %d\n", k, c[k]}' "$F2D_AUDIT_LOG" | sort -k2 -nr | head -10
}

# ---------- баны ----------
# shellcheck disable=SC2086  # разбиение по точкам — намеренно
_ip_to_int() { local IFS=.; set -- $1; echo $(( ($1<<24) + ($2<<16) + ($3<<8) + $4 )); }
ip_in_list() {   # ip "список ip/cidr"
    local ip="$1" x
    for x in $2; do
        [[ "$x" == "$ip" ]] && return 0
        if [[ "$x" == */* ]] && is_ipv4 "$ip" && is_ipv4 "$x"; then
            local m="${x#*/}" mask
            mask=$(( m == 0 ? 0 : (0xFFFFFFFF << (32 - m)) & 0xFFFFFFFF ))
            (( ($(_ip_to_int "$ip") & mask) == ($(_ip_to_int "${x%/*}") & mask) )) && return 0
        fi
    done
    return 1
}

ban_ignored() {   # почему этот IP банить нельзя (пусто — можно)
    local ip="$1"
    is_private_ip "$ip" && { echo "частный адрес"; return; }
    ip_in_list "$ip" "$TRUSTED_IPS" && { echo "в белом списке"; return; }
    ip_in_list "$ip" "$(detect_panel_ips)" && { echo "IP панели"; return; }
    [[ -n "${F2D_SELF_IP:-}" && "$ip" == "$F2D_SELF_IP" ]] && { echo "собственный IP"; return; }
    # адрес текущей SSH-сессии администратора
    [[ -n "${SSH_CLIENT:-}" && "$ip" == "${SSH_CLIENT%% *}" ]] && { echo "ваша SSH-сессия"; return; }
    return 0
}

_with_lock() { mkdir -p "$F2D_STATE_DIR"; ( flock -w 10 9; "$@" ) 9>"$F2D_LOCK"; }

_db_put() {   # ip until jail reason
    local tmp; tmp=$(mktemp)
    awk -F'\t' -v ip="$1" '$1!=ip' "$F2D_BANS_DB" > "$tmp" 2>/dev/null
    printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "${4//$'\t'/ }" >> "$tmp"
    cat "$tmp" > "$F2D_BANS_DB"; rm -f "$tmp"
}
_db_del() {
    local tmp; tmp=$(mktemp)
    awk -F'\t' -v ip="$1" '$1!=ip' "$F2D_BANS_DB" > "$tmp" 2>/dev/null
    cat "$tmp" > "$F2D_BANS_DB"; rm -f "$tmp"
}

_set_of() { [[ "$1" == *:* ]] && echo banned6 || echo banned4; }

# ban_add ip seconds(0=навсегда) jail reason [record]
#   record — IP уже забанен ядром (анти-флуд), только фиксируем в журнале
ban_add() {
    local ip="$1" secs="$2" jail="${3:-manual}" reason="${4:-}" mode="${5:-}"
    is_ip "$ip" || { err "Неверный IP: $ip"; return 1; }
    local why; why=$(ban_ignored "$ip")
    if [[ -n "$why" ]]; then
        audit_write IGNORE "$ip" "$jail" - "не забанен: $why; $reason"
        return 0
    fi
    # уже забанен (несколько строк лога об одном и том же) — не дублируем
    if [[ "$mode" == record ]] && awk -F'\t' -v ip="$ip" -v t="$(now)" '$1==ip && ($2==0 || $2>t){f=1} END{exit !f}' "$F2D_BANS_DB" 2>/dev/null; then
        return 0
    fi
    # повторные баны — дольше (как bantime.increment в fail2ban)
    if [[ "$BANTIME_INCREMENT" == yes && "$secs" -gt 0 && "$mode" != record ]]; then
        local prev max
        prev=$(awk -F'\t' -v ip="$ip" '$2=="BAN" && $3==ip' "$F2D_AUDIT_LOG" 2>/dev/null | wc -l)
        max=$(to_seconds "$BANTIME_MAX")
        (( prev > 10 )) && prev=10
        secs=$(( secs << prev )); (( secs > max )) && secs=$max
    fi
    local until=0; (( secs > 0 )) && until=$(( $(now) + secs ))
    if [[ "$mode" != record ]]; then
        local el="$ip"; (( secs > 0 )) && el="$ip timeout ${secs}s"
        nft add element inet "$F2D_NFT_TABLE" "$(_set_of "$ip")" "{ $el }" 2>/dev/null \
            || nft add element inet "$F2D_NFT_TABLE" "$(_set_of "$ip")" "{ $el }" 2>&1 | grep -v 'File exists' >&2
    fi
    _with_lock _db_put "$ip" "$until" "$jail" "$reason"
    audit_write BAN "$ip" "$jail" "$(human_duration "$secs")" "$reason"
    notify "🚫 fail2detect $(hostname): бан $ip [$jail] на $(human_duration "$secs") — $reason"
}

ban_remove() {   # ip [quiet]
    local ip="$1"
    nft delete element inet "$F2D_NFT_TABLE" "$(_set_of "$ip")" "{ $ip }" 2>/dev/null
    local was; was=$(awk -F'\t' -v ip="$ip" '$1==ip' "$F2D_BANS_DB" 2>/dev/null)
    _with_lock _db_del "$ip"
    if [[ -n "$was" ]]; then
        audit_write UNBAN "$ip" "$(cut -f3 <<<"$was")" - "разбанен вручную"
        [[ "${2:-}" == quiet ]] || ok "$ip разбанен"
    else
        [[ "${2:-}" == quiet ]] || info "$ip не был в списке банов (удалён из nft на всякий случай)"
    fi
}

ban_list() {
    title "Активные баны"
    local t; t=$(now)
    # синхронизация с ядром: баны, которые уже истекли, убираем из базы
    local live; live=$( { nft -j list set inet "$F2D_NFT_TABLE" banned4; nft -j list set inet "$F2D_NFT_TABLE" banned6; } 2>/dev/null \
        | jq -r '.nftables[].set.elem // empty | .[] | if type=="object" then .elem.val else . end' 2>/dev/null)
    local rows=0
    printf '%s%-39s %-12s %-12s %s%s\n' "$C_BOLD" "IP" "JAIL" "ОСТАЛОСЬ" "ПРИЧИНА" "$C_RESET"
    while IFS=$'\t' read -r ip until jail reason; do
        [[ -z "$ip" ]] && continue
        (( until != 0 && until <= t )) && continue
        [[ -n "$live" ]] && ! grep -qxF "$ip" <<<"$live" && continue
        local left="навсегда"; (( until > 0 )) && left=$(human_duration $(( until - t )))
        printf '%s%-39s%s %-12s %-12s %s%s%s\n' "$C_RED" "$ip" "$C_RESET" "$jail" "$left" "$C_GRAY" "$reason" "$C_RESET"
        rows=$((rows + 1))
    done < "$F2D_BANS_DB"
    # баны, которых нет в базе (например, добавлены вручную через nft)
    local ip
    for ip in $live; do
        grep -q "^${ip}"$'\t' "$F2D_BANS_DB" 2>/dev/null && continue
        printf '%s%-39s%s %-12s %-12s %s\n' "$C_RED" "$ip" "$C_RESET" "?" "?" "нет в базе fail2detect"
        rows=$((rows + 1))
    done
    ((rows)) || info "Банов нет"
}

ban_prune() {   # убрать истёкшие записи из базы
    local t tmp; t=$(now); tmp=$(mktemp)
    awk -F'\t' -v t="$t" '$1!="" && ($2==0 || $2>t)' "$F2D_BANS_DB" > "$tmp" 2>/dev/null
    cat "$tmp" > "$F2D_BANS_DB"; rm -f "$tmp"
}

# ---------- jail'ы ----------
jail_names() {
    local f
    for f in "$F2D_JAIL_DIR"/*.conf; do [[ -f "$f" ]] && basename "$f" .conf; done
}

# загрузить jail в переменные J_*
jail_load() {
    local name="$1" f="$F2D_JAIL_DIR/$1.conf"
    [[ -f "$f" ]] || return 1
    ENABLED=no; SOURCE=""; FILTERS=(); IGNOREREGEX=""; MAXRETRY=5; FINDTIME=10m; BANTIME=1h; ACTION=ban; DESCRIPTION=""
    # shellcheck disable=SC1090
    source "$f"
    J_NAME="$name"; J_ENABLED="$ENABLED"; J_SOURCE="$SOURCE"; J_FILTERS=("${FILTERS[@]}")
    J_IGNORE="$IGNOREREGEX"; J_MAXRETRY="$MAXRETRY"; J_FINDTIME=$(to_seconds "$FINDTIME")
    J_BANTIME=$(to_seconds "$BANTIME"); J_ACTION="$ACTION"; J_DESC="$DESCRIPTION"
}

jail_set_enabled() {   # name yes|no
    local f="$F2D_JAIL_DIR/$1.conf"
    [[ -f "$f" ]] || die "Нет jail '$1'. Доступные: $(jail_names | xargs)"
    sed -i "s/^ENABLED=.*/ENABLED=$2/" "$f"
    audit_write JAIL - "$1" - "ENABLED=$2"
    ok "jail $1: ENABLED=$2"
    systemctl is-active --quiet fail2detect 2>/dev/null && systemctl restart fail2detect && info "Демон перезапущен"
}

# команда, которая выдаёт поток строк из источника
jail_source_cmd() {
    local src="$1"
    case "$src" in
        kernel)
            if have journalctl; then echo "journalctl -k -f -n0 -o cat"
            else echo "tail -F -n0 /var/log/kern.log"; fi;;
        journal-tag:*)
            local tags="${src#journal-tag:}" a="" t
            for t in ${tags//,/ }; do a+=" -t $t"; done
            echo "journalctl -f -n0 -o cat$a";;
        journal-unit:*)
            local units="${src#journal-unit:}" a="" u
            for u in ${units//,/ }; do a+=" -u $u"; done
            echo "journalctl -f -n0 -o cat$a";;
        file:*)   echo "tail -F -n0 ${src#file:}";;
        docker:*) echo "docker logs -f --since 0s --tail 0 ${src#docker:}";;
        *) return 1;;
    esac
}

# главный цикл одного jail: stdin — строки лога
jail_loop() {
    local name="$1"
    jail_load "$name" || return 1
    local -A hits=()
    local re=() f
    for f in "${J_FILTERS[@]}"; do re+=("${f//<HOST>/([0-9a-fA-F:.]+[0-9a-fA-F])}"); done
    local line t ip r i cnt kept ts
    while IFS= read -r line; do
        [[ -n "$J_IGNORE" && "$line" =~ $J_IGNORE ]] && continue
        ip=""
        for r in "${re[@]}"; do
            if [[ "$line" =~ $r ]]; then
                local g=("${BASH_REMATCH[@]}")   # is_ip сам затирает BASH_REMATCH
                for ((i = 1; i < ${#g[@]}; i++)); do
                    is_ip "${g[i]:-}" && { ip="${g[i]}"; break; }
                done
                [[ -n "$ip" ]] && break
            fi
        done
        [[ -z "$ip" ]] && continue
        printf -v t '%(%s)T' -1
        # окно FINDTIME
        kept=""; cnt=0
        for ts in ${hits[$ip]:-}; do (( ts > t - J_FINDTIME )) && { kept+="$ts "; cnt=$((cnt + 1)); }; done
        kept+="$t"; cnt=$((cnt + 1))
        if (( cnt >= J_MAXRETRY )); then
            unset 'hits[$ip]'
            local reason="${cnt} совп. за $(human_duration "$J_FINDTIME"): ${line:0:160}"
            if [[ "$J_ACTION" == record ]]; then
                ban_add "$ip" "$J_BANTIME" "$name" "$reason" record
            else
                ban_add "$ip" "$J_BANTIME" "$name" "$reason"
            fi
        else
            hits[$ip]="$kept"
        fi
        # не даём памяти расти бесконечно
        (( ${#hits[@]} > 20000 )) && hits=()
    done
}

jail_run() {   # бесконечно: источник | jail_loop (с переподключением)
    local name="$1"
    jail_load "$name" || return 1
    local cmd; cmd=$(jail_source_cmd "$J_SOURCE") || { err "jail $name: неизвестный SOURCE=$J_SOURCE"; return 1; }
    while true; do
        # shellcheck disable=SC2086
        stdbuf -oL $cmd 2>&1 | jail_loop "$name"
        sleep 5
    done
}

# ---------- демон ----------
daemon_run() {
    require_root
    ensure_dirs
    F2D_SELF_IP=$(public_ip 2>/dev/null || true); export F2D_SELF_IP
    nft list table inet "$F2D_NFT_TABLE" >/dev/null 2>&1 || fw_apply
    local name pids=()
    for name in $(jail_names); do
        jail_load "$name" || continue
        [[ "$J_ENABLED" == yes ]] || continue
        if ! jail_source_cmd "$J_SOURCE" >/dev/null; then warn "jail $name: плохой SOURCE"; continue; fi
        case "$J_SOURCE" in
            file:*) [[ -e "${J_SOURCE#file:}" ]] || warn "jail $name: файла ${J_SOURCE#file:} пока нет — жду";;
            docker:*) have docker || { warn "jail $name: docker не найден — пропуск"; continue; };;
        esac
        jail_run "$name" & pids+=($!)
        info "jail $name запущен (${J_SOURCE}, ${J_MAXRETRY} за $(human_duration "$J_FINDTIME") → бан $(human_duration "$J_BANTIME"))"
    done
    ((${#pids[@]})) || warn "Нет включённых jail — работают только фаервол и блок-листы"
    audit_write START - - - "демон запущен, jail: $(jail_names | xargs)"
    trap 'audit_write STOP - - - "демон остановлен"; kill 0 2>/dev/null; exit 0' TERM INT
    while true; do
        sleep 600 & wait $!
        _with_lock ban_prune
    done
}

jail_status() {
    title "Jail'ы"
    local name
    printf '%s%-12s %-4s %-34s %-6s %-8s %-8s %s%s\n' "$C_BOLD" "JAIL" "ВКЛ" "ИСТОЧНИК" "ПОРОГ" "ОКНО" "БАН" "БАНОВ" "$C_RESET"
    for name in $(jail_names); do
        jail_load "$name" || continue
        local n; n=$(awk -F'\t' -v j="$name" '$2=="BAN" && $4==j' "$F2D_AUDIT_LOG" 2>/dev/null | wc -l)
        local on="${C_GRAY}нет${C_RESET} "; [[ "$J_ENABLED" == yes ]] && on="${C_GREEN}да${C_RESET}  "
        printf '%-12s %s %-34s %-6s %-8s %-8s %s\n' "$name" "$on" "${J_SOURCE:0:34}" "$J_MAXRETRY" "$(human_duration "$J_FINDTIME")" "$(human_duration "$J_BANTIME")" "$n"
        [[ -n "$J_DESC" ]] && printf '  %s%s%s\n' "$C_GRAY" "$J_DESC" "$C_RESET"
    done
    echo
    if systemctl is-active --quiet fail2detect 2>/dev/null; then ok "Демон fail2detect работает"
    else warn "Демон fail2detect не запущен (systemctl start fail2detect)"; fi
}

# проверить регулярки jail на файле/строке: fail2detect jail test sshd /var/log/auth.log
jail_test() {
    local name="$1" src="${2:-}"
    jail_load "$name" || die "Нет jail $name"
    local re=() f line ip="" n=0 m=0
    for f in "${J_FILTERS[@]}"; do re+=("${f//<HOST>/([0-9a-fA-F:.]+[0-9a-fA-F])}"); done
    local input
    if [[ -z "$src" ]]; then
        local cmd; cmd=$(jail_source_cmd "$J_SOURCE"); cmd="${cmd/ -f -n0/ -n 5000 --no-pager}"; cmd="${cmd/tail -F -n0/tail -n 5000}"; cmd="${cmd/ -f --since 0s --tail 0/ --tail 5000}"
        input=$(eval "$cmd" 2>&1)
    elif [[ -f "$src" ]]; then input=$(tail -n 20000 "$src")
    else input="$src"; fi
    local -A per=()
    while IFS= read -r line; do
        n=$((n + 1))
        for f in "${re[@]}"; do
            if [[ "$line" =~ $f ]]; then
                ip=""
                local i g=("${BASH_REMATCH[@]}")
                for ((i = 1; i < ${#g[@]}; i++)); do is_ip "${g[i]:-}" && { ip="${g[i]}"; break; }; done
                [[ -z "$ip" ]] && continue
                m=$((m + 1)); per[$ip]=$(( ${per[$ip]:-0} + 1 )); break
            fi
        done
    done <<<"$input"
    info "Строк: $n, совпадений: $m, уникальных IP: ${#per[@]}"
    for ip in "${!per[@]}"; do echo "${per[$ip]} $ip"; done | sort -nr | head -15 | awk '{printf "  %6d  %s\n", $1, $2}'
}

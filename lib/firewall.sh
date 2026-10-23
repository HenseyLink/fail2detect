#!/usr/bin/env bash
# fail2detect — фаервол на nftables.
#
# Своя таблица `inet fail2detect` с приоритетом раньше UFW/Docker. В ней только
# запреты (баны, блок-листы, порты) — разрешение пакета в нашей таблице не
# отменяет правил UFW, поэтому с UFW от скрипта eGames мы не конфликтуем.
#
# Режимы:
#   ufw — политику портов держит UFW (как настроил eGames), fail2detect
#         добавляет баны, блок-листы, защиту API ноды и docker-портов;
#   nft — UFW нет: fail2detect сам закрывает всё, кроме разрешённых портов.

F2D_NFT_PREV="${F2D_STATE_DIR}/fail2detect.prev.nft"
F2D_ROLLBACK_PID="${F2D_STATE_DIR}/rollback.pid"

# ---------- UFW ----------
# TCP/UDP-порты, открытые в UFW для всех: печатает "proto port|range"
ufw_open_ports() {
    ufw_active || return 0
    ufw status 2>/dev/null | awk '
        $0 ~ /ALLOW/ && $0 ~ /Anywhere/ && $0 !~ /ALLOW OUT/ {
            spec=$1
            if (spec ~ /^[0-9]/) {
                proto="any"
                if (spec ~ /\//) { split(spec, p, "/"); spec=p[1]; proto=p[2] }
                n=split(spec, list, ",")
                for (i=1;i<=n;i++) { r=list[i]; gsub(":", "-", r)
                    if (proto=="any" || proto=="tcp") print "tcp", r
                    if (proto=="any" || proto=="udp") print "udp", r }
            }
        }' | sort -u
}

ufw_allow() {   # port proto [from] [comment]
    ufw_active || return 0
    local port="$1" proto="${2:-tcp}" from="${3:-}" comment="${4:-fail2detect}"
    if [[ -n "$from" ]]; then
        ufw allow proto "$proto" from "$from" to any port "$port" comment "$comment" >/dev/null
    else
        ufw allow "$port/$proto" comment "$comment" >/dev/null
    fi
}
ufw_delete_allow() {   # port proto
    ufw_active || return 0
    ufw --force delete allow "$1/${2:-tcp}" >/dev/null 2>&1 || true
}

# ---------- состав портов ----------
fw_public_tcp() {
    local p=() x
    for x in $(detect_ssh_ports); do p+=("$x"); done
    has_node && for x in $(detect_xray_ports); do p+=("$x"); done
    for x in $PUBLIC_TCP; do p+=("$x"); done
    if [[ "$(fw_mode)" == ufw ]]; then
        while read -r proto x; do [[ "$proto" == tcp ]] && p+=("$x"); done < <(ufw_open_ports)
    elif has_panel || has_sub_page || { has_node && [[ -z "$(detect_xray_ports)" ]]; }; then
        p+=(443)   # веб-сервер панели/подписки или Xray, который ещё не поднялся
    fi
    # API ноды никогда не публичный
    local api; api=$(has_node && detect_node_api_port)
    printf '%s\n' "${p[@]}" | grep -vx "${api:-__none__}" | sort -un | xargs
}

fw_public_udp() {
    local p=() x
    for x in $PUBLIC_UDP; do p+=("$x"); done
    has_node && for x in $(detect_xray_udp_ports); do p+=("$x"); done
    if [[ "$(fw_mode)" == ufw ]]; then
        while read -r proto x; do [[ "$proto" == udp ]] && p+=("$x"); done < <(ufw_open_ports)
    fi
    ((${#p[@]})) && printf '%s\n' "${p[@]}" | sort -un | xargs
}

# элементы набора через запятую, отдельно v4/v6
_join() { local IFS=,; echo "$*"; }
_ips() {   # family list...
    local fam="$1"; shift; local out=() x
    for x in "$@"; do
        if [[ "$fam" == 4 ]]; then is_ipv4 "$x" && out+=("$x"); else is_ipv6 "$x" && out+=("$x"); fi
    done
    _join "${out[@]}"
}
_elements() { [[ -n "$1" ]] && printf ' elements = { %s };' "$1"; }

# ---------- генерация правил ----------
fw_render() {
    local mode tcp udp api wan trusted4 trusted6 panel4 panel6
    mode=$(fw_mode)
    tcp=$(fw_public_tcp | tr ' ' ',')
    udp=$(fw_public_udp | tr ' ' ',')
    api=""; has_node && api=$(detect_node_api_port)
    wan=$(wan_iface)
    local panels; panels=$(detect_panel_ips)
    # shellcheck disable=SC2086  # списки через пробел — разбиваем намеренно
    trusted4=$(_ips 4 $TRUSTED_IPS)
    # shellcheck disable=SC2086
    trusted6=$(_ips 6 $TRUSTED_IPS)
    # shellcheck disable=SC2086
    panel4=$(_ips 4 $panels)
    # shellcheck disable=SC2086
    panel6=$(_ips 6 $panels)

    local drop_log='limit rate 20/second burst 50 packets log prefix "f2d-drop: " level info'

    cat <<EOF
# Сгенерировано fail2detect $F2D_VERSION — $(iso_now). Не редактируйте вручную:
# правьте $F2D_CONF и выполните \`fail2detect fw apply\`.
table inet $F2D_NFT_TABLE
delete table inet $F2D_NFT_TABLE
table inet $F2D_NFT_TABLE {
    set trusted4 { type ipv4_addr; flags interval; auto-merge;$(_elements "$trusted4") }
    set trusted6 { type ipv6_addr; flags interval; auto-merge;$(_elements "$trusted6") }
    set panel4   { type ipv4_addr; flags interval; auto-merge;$(_elements "$panel4") }
    set panel6   { type ipv6_addr; flags interval; auto-merge;$(_elements "$panel6") }
    set banned4  { type ipv4_addr; flags dynamic, timeout; }
    set banned6  { type ipv6_addr; flags dynamic, timeout; }
    set block4   { type ipv4_addr; flags interval; auto-merge; }
    set block6   { type ipv6_addr; flags interval; auto-merge; }
    set pub_tcp  { type inet_service; flags interval;$(_elements "$tcp") }
    set pub_udp  { type inet_service; flags interval;$(_elements "$udp") }
    set node_api { type inet_service;$(_elements "$api") }
    set flood4   { type ipv4_addr; flags dynamic, timeout; timeout 1m; }
    set flood6   { type ipv6_addr; flags dynamic, timeout; timeout 1m; }

    chain input {
        type filter hook input priority filter - 10; policy accept;
        iif "lo" accept
        ip  saddr @trusted4 accept
        ip6 saddr @trusted6 accept
        ip  saddr @banned4 drop
        ip6 saddr @banned6 drop
        ip  saddr @block4 drop
        ip6 saddr @block6 drop
        ct state established,related accept
        ct state invalid drop

        # API ноды (NODE_PORT) — только с IP панели: сканер не должен его видеть.
        # С внутренних интерфейсов (docker-мост панели, NetBird/WireGuard) — можно.
$( [[ -n "$wan" ]] && echo "        iifname != \"$wan\" tcp dport @node_api accept" )
        tcp dport @node_api ip  saddr @panel4 accept
        tcp dport @node_api ip6 saddr @panel6 accept
        tcp dport @node_api $drop_log
        tcp dport @node_api drop
EOF
    if [[ "$FLOOD_GUARD" == yes ]]; then
        local bt; bt=$(to_seconds "$FLOOD_BANTIME")
        cat <<EOF

        # шквал новых соединений с одного IP -> временный бан
        ct state new tcp dport @pub_tcp update @flood4 { ip  saddr limit rate over $FLOOD_RATE } add @banned4 { ip  saddr timeout ${bt}s } log prefix "f2d-flood: " level info drop
        ct state new tcp dport @pub_tcp update @flood6 { ip6 saddr limit rate over $FLOOD_RATE } add @banned6 { ip6 saddr timeout ${bt}s } log prefix "f2d-flood: " level info drop
EOF
    fi
    if [[ "$STEALTH_ICMP" == yes ]]; then
        cat <<'EOF'

        # не отвечаем на ping — сервер не «светится» при массовом сканировании
        icmp type echo-request drop
        icmpv6 type echo-request drop
EOF
    fi
    if [[ "$mode" == nft ]]; then
        cat <<EOF

        # ICMP, без которого ломается сеть
        icmp type { echo-request, destination-unreachable, time-exceeded, parameter-problem } accept
        icmpv6 type { echo-request, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
        udp sport 67 udp dport 68 accept
        udp dport 546 accept

        tcp dport @pub_tcp accept
        udp dport @pub_udp accept
        meta pkttype { broadcast, multicast } drop

        # всё остальное закрыто; попытки пишем в журнал (их ловит jail portscan)
        tcp flags & (syn | ack) == syn $drop_log
        meta l4proto udp $drop_log
        drop
EOF
    fi
    cat <<EOF
    }

    chain forward {
        type filter hook forward priority filter - 10; policy accept;
        ip  saddr @banned4 drop
        ip6 saddr @banned6 drop
        ip  saddr @block4 drop
        ip6 saddr @block6 drop
EOF
    if [[ "$DOCKER_GUARD" == yes && -n "$wan" ]]; then
        cat <<EOF

        # Docker публикует порты в обход UFW. Пускаем снаружи только в открытые.
        iifname "$wan" ct state new ct status dnat meta l4proto tcp ct original proto-dst @pub_tcp accept
        iifname "$wan" ct state new ct status dnat meta l4proto udp ct original proto-dst @pub_udp accept
        iifname "$wan" ct state new ct status dnat $drop_log
        iifname "$wan" ct state new ct status dnat drop
EOF
    fi
    cat <<EOF
    }
}
EOF
    fw_render_elements
}

# активные баны и блок-листы — в тот же файл, чтобы применить атомарно
fw_render_elements() {
    local t; t=$(now)
    if [[ -s "$F2D_BANS_DB" ]]; then
        awk -F'\t' -v t="$t" -v tb="$F2D_NFT_TABLE" '
            $1=="" {next}
            { fam = ($1 ~ /:/) ? 6 : 4 }
            $2==0     { printf "add element inet %s banned%s { %s }\n", tb, fam, $1; next }
            $2>t+1    { printf "add element inet %s banned%s { %s timeout %ds }\n", tb, fam, $1, $2-t }
        ' "$F2D_BANS_DB"
    fi
    local f
    for f in 4 6; do
        [[ -s "$F2D_STATE_DIR/blocklist$f.txt" ]] || continue
        # пачками по 500 элементов
        awk -v tb="$F2D_NFT_TABLE" -v f="$f" '
            { buf = buf (n ? ", " : "") $1; n++ }
            n==500 { printf "add element inet %s block%s { %s }\n", tb, f, buf; buf=""; n=0 }
            END { if (n) printf "add element inet %s block%s { %s }\n", tb, f, buf }
        ' "$F2D_STATE_DIR/blocklist$f.txt"
    done
}

# ---------- применение ----------
fw_apply() {   # [--safe]
    local safe="${1:-}"
    ensure_dirs
    local new="$F2D_NFT_FILE.new"
    fw_render > "$new"
    if ! nft -c -f "$new" 2>"$new.err"; then
        err "Ошибка в сгенерированных правилах:"; cat "$new.err" >&2
        return 1
    fi
    nft list table inet "$F2D_NFT_TABLE" > "$F2D_NFT_PREV" 2>/dev/null || rm -f "$F2D_NFT_PREV"
    nft -f "$new" || { err "nft не смог применить правила"; return 1; }
    mv -f "$new" "$F2D_NFT_FILE"; rm -f "$new.err"
    [[ "$(fw_mode)" == ufw ]] && ufw logging low >/dev/null 2>&1
    ok "Правила fail2detect применены (режим: $(fw_mode))"

    if [[ "$safe" == --safe && -t 0 ]]; then
        fw_confirm_or_rollback 60
    fi
}

# Защита от «отрезал себе SSH»: откат, если не подтвердили
fw_confirm_or_rollback() {
    local t="${1:-60}" self; self=$(readlink -f "$F2D_BIN")
    setsid bash -c "sleep $t; '$self' fw rollback --auto" >/dev/null 2>&1 < /dev/null &
    echo $! > "$F2D_ROLLBACK_PID"
    warn "Если SSH-доступ пропал, правила откатятся сами через ${t}с."
    printf '%s?%s Откройте НОВУЮ SSH-сессию и проверьте вход. Всё работает? [y/N]: ' "$C_YELLOW" "$C_RESET"
    local a=""
    read -r -t "$t" a || true
    if [[ "$a" =~ ^([yYдД]|yes|да)$ ]]; then
        kill "$(cat "$F2D_ROLLBACK_PID")" 2>/dev/null; rm -f "$F2D_ROLLBACK_PID"
        ok "Подтверждено, правила сохранены"
    else
        kill "$(cat "$F2D_ROLLBACK_PID")" 2>/dev/null; rm -f "$F2D_ROLLBACK_PID"
        fw_rollback
    fi
}

fw_rollback() {
    if [[ -s "$F2D_NFT_PREV" ]]; then
        { echo "table inet $F2D_NFT_TABLE"; echo "delete table inet $F2D_NFT_TABLE"; cat "$F2D_NFT_PREV"; } | nft -f - \
            && warn "Правила откатены к предыдущей версии"
    else
        nft delete table inet "$F2D_NFT_TABLE" 2>/dev/null; warn "Таблица fail2detect удалена (откат)"
    fi
    audit_write ROLLBACK - fw - "откат правил фаервола"
}

fw_disable() {
    nft delete table inet "$F2D_NFT_TABLE" 2>/dev/null && ok "Фаервол fail2detect отключён (UFW не тронут)"
}

fw_status() {
    title "Фаервол"
    if ! nft list table inet "$F2D_NFT_TABLE" >/dev/null 2>&1; then
        warn "Таблица fail2detect не загружена — выполните: fail2detect fw apply"; return
    fi
    local b4 b6 bl4 bl6
    b4=$(nft -j list set inet "$F2D_NFT_TABLE" banned4 2>/dev/null | jq '[.nftables[].set.elem // empty | .[]] | length')
    b6=$(nft -j list set inet "$F2D_NFT_TABLE" banned6 2>/dev/null | jq '[.nftables[].set.elem // empty | .[]] | length')
    bl4=$(nft -j list set inet "$F2D_NFT_TABLE" block4 2>/dev/null | jq '[.nftables[].set.elem // empty | .[]] | length')
    bl6=$(nft -j list set inet "$F2D_NFT_TABLE" block6 2>/dev/null | jq '[.nftables[].set.elem // empty | .[]] | length')
    printf '  %-26s %s\n' "Режим:" "$(fw_mode)"
    printf '  %-26s %s\n' "Открытые TCP:" "$(fw_public_tcp)"
    printf '  %-26s %s\n' "Открытые UDP:" "$(fw_public_udp)"
    has_node && printf '  %-26s %s (только с: %s)\n' "API ноды:" "$(detect_node_api_port)" "$(detect_panel_ips || true)"
    printf '  %-26s %s\n' "Белый список:" "${TRUSTED_IPS:-—}"
    printf '  %-26s %s\n' "Забанено сейчас:" "$(( ${b4:-0} + ${b6:-0} ))"
    printf '  %-26s %s сетей (%s)\n' "В блок-листах:" "$(( ${bl4:-0} + ${bl6:-0} ))" "${BLOCKLISTS:-—}"
    printf '  %-26s %s\n' "Скрытие от ping:" "$STEALTH_ICMP"
    printf '  %-26s %s\n' "Защита docker-портов:" "$DOCKER_GUARD"
    printf '  %-26s %s\n' "Анти-флуд:" "$FLOOD_GUARD$( [[ $FLOOD_GUARD == yes ]] && echo " ($FLOOD_RATE)")"
}

# ---------- порты ----------
fw_port_open() {   # port [proto]
    local port="$1" proto="${2:-tcp}"
    is_port "$port" || die "Неверный порт: $port"
    if [[ "$proto" == udp ]]; then list_add PUBLIC_UDP "$port"; else list_add PUBLIC_TCP "$port"; fi
    ufw_allow "$port" "$proto"
    audit_write PORT_OPEN - fw - "$port/$proto"
    fw_apply
}

fw_port_close() {   # port [proto]
    local port="$1" proto="${2:-tcp}"
    is_port "$port" || die "Неверный порт: $port"
    if [[ "$proto" == tcp && " $(detect_ssh_ports) " == *" $port "* ]]; then
        die "Порт $port — это SSH. Закрывать его нельзя, иначе потеряете доступ."
    fi
    if [[ "$proto" == udp ]]; then list_del PUBLIC_UDP "$port"; else list_del PUBLIC_TCP "$port"; fi
    ufw_delete_allow "$port" "$proto"
    audit_write PORT_CLOSE - fw - "$port/$proto"
    fw_apply --safe
}

# ---------- белый список ----------
trust_add() {
    is_ip "$1" || die "Неверный IP/подсеть: $1"
    list_add TRUSTED_IPS "$1"
    ban_remove "$1" quiet
    audit_write TRUST "$1" - - "добавлен в белый список"
    fw_apply
}
trust_del() { list_del TRUSTED_IPS "$1"; audit_write UNTRUST "$1" - - "удалён из белого списка"; fw_apply; }

# ---------- блок-листы сканеров ----------
blocklist_update() {
    ensure_dirs
    local name url tmp4 tmp6 total=0
    tmp4=$(mktemp); tmp6=$(mktemp)
    for name in $BLOCKLISTS; do
        url="BLOCKLIST_URL_${name}"; url="${!url:-}"
        [[ -n "$url" ]] || { warn "Блок-лист $name: нет URL (BLOCKLIST_URL_$name)"; continue; }
        local raw; raw=$(curl -fsSL --max-time 30 "$url" 2>/dev/null) || { warn "Блок-лист $name: не скачался"; continue; }
        local n4 n6
        # только строки, похожие на IP/CIDR; комментарии и мусор отбрасываем
        n4=$(printf '%s\n' "$raw" | sed 's/#.*//' | grep -oE '^[[:space:]]*[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?' | tr -d ' \t' | tee -a "$tmp4" | wc -l)
        n6=$(printf '%s\n' "$raw" | sed 's/#.*//' | grep -oE '^[[:space:]]*[0-9a-fA-F]*:[0-9a-fA-F:]+(/[0-9]{1,3})?' | tr -d ' \t' | tee -a "$tmp6" | wc -l)
        ok "Блок-лист ${name}: $((n4 + n6)) сетей"
        total=$((total + n4 + n6))
    done
    # никогда не блокируем себя, доверенных и панель
    local keep=" $TRUSTED_IPS $(detect_panel_ips) "
    sort -u "$tmp4" | while read -r c; do is_ipv4 "$c" && [[ "$keep" != *" ${c%/32} "* ]] && echo "$c"; done > "$F2D_STATE_DIR/blocklist4.txt"
    sort -u "$tmp6" > "$F2D_STATE_DIR/blocklist6.txt"
    rm -f "$tmp4" "$tmp6"
    audit_write BLOCKLIST - - - "обновлено: $total сетей ($BLOCKLISTS)"
    nft list table inet "$F2D_NFT_TABLE" >/dev/null 2>&1 && fw_apply >/dev/null && ok "Блок-листы загружены в фаервол"
}

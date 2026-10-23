#!/usr/bin/env bash
# fail2detect — автоопределение окружения (Remnawave, порты, панель).

compose_has_service() { [[ -f "$1/docker-compose.yml" ]] && grep -qE "^[[:space:]]*$2:" "$1/docker-compose.yml"; }

has_panel()  { compose_has_service "$RW_PANEL_DIR" remnawave; }
has_node()   { compose_has_service "$RW_NODE_DIR" remnanode || compose_has_service "$RW_PANEL_DIR" remnanode; }
has_sub_page() { [[ -f /opt/subscription/docker-compose.yml ]] || compose_has_service "$RW_PANEL_DIR" remnawave-subscription-page; }

# каталог, где лежит compose с remnanode
node_dir() {
    if compose_has_service "$RW_NODE_DIR" remnanode; then echo "$RW_NODE_DIR"
    elif compose_has_service "$RW_PANEL_DIR" remnanode; then echo "$RW_PANEL_DIR"; fi
}

server_role() {
    local r=()
    has_panel && r+=("панель")
    has_node && r+=("нода")
    has_sub_page && r+=("подписка")
    ((${#r[@]})) && (IFS=+; echo "${r[*]}") || echo "не найдено"
}

# NODE_PORT (API ноды, по умолчанию 2222); старые версии — APP_PORT
detect_node_api_port() {
    [[ -n "$NODE_API_PORT" ]] && { echo "$NODE_API_PORT"; return; }
    local d; d=$(node_dir); [[ -n "$d" ]] || return 1
    local p
    p=$(grep -oE '(NODE_PORT|APP_PORT)[=:][[:space:]]*"?[0-9]+' "$d/docker-compose.yml" "$d/.env" 2>/dev/null | grep -oE '[0-9]+$' | head -1)
    echo "${p:-2222}"
}

detect_ssh_ports() {
    [[ -n "$SSH_PORTS" ]] && { echo "$SSH_PORTS"; return; }
    local p=""
    have sshd && p=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' | sort -u | xargs)
    [[ -z "$p" ]] && p=$(ss -H -tlnp 2>/dev/null | awk '/"sshd"/{n=split($4,a,":"); print a[n]}' | sort -u | xargs)
    echo "${p:-22}"
}

# порты, которые слушает xray (rw-core/xray) снаружи
detect_xray_ports() {
    [[ -n "$XRAY_PORTS" ]] && { echo "$XRAY_PORTS"; return; }
    ss -H -tlnp 2>/dev/null | awk '/"(xray|rw-core)"/{n=split($4,a,":"); if ($4 !~ /^127\.|^\[::1\]/) print a[n]}' | sort -un | xargs
}

# UDP-порты Xray (Hysteria 2)
detect_xray_udp_ports() {
    ss -H -ulnp 2>/dev/null | awk '/"(xray|rw-core)"/{n=split($4,a,":"); if ($4 !~ /^127\.|^\[::1\]/) print a[n]}' | sort -un | xargs
}

# IP панели: из конфига, иначе из правил UFW для порта ноды (так их задают установщики)
detect_panel_ips() {
    [[ -n "$PANEL_IPS" ]] && { echo "$PANEL_IPS"; return; }
    local port; port=$(detect_node_api_port) || return 0
    have ufw || return 0
    ufw status 2>/dev/null | awk -v p="$port" '$1==p || $1==p"/tcp" {for(i=2;i<=NF;i++) if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/) print $i}' | sort -u | xargs
}

ufw_active() { have ufw && ufw status 2>/dev/null | grep -q '^Status: active'; }

# итоговый режим фаервола
fw_mode() {
    case "$FW_MODE" in
        ufw|nft) echo "$FW_MODE";;
        *) ufw_active && echo ufw || echo nft;;
    esac
}

# Все TCP-сокеты, слушающие не на localhost: "порт процесс"
listening_public_tcp() {
    ss -H -tlnp 2>/dev/null | awk '{
        addr=$4; n=split(addr,a,":"); port=a[n];
        if (addr ~ /^127\.|^\[::1\]|^\[::ffff:127\./) next;
        proc="?"; if (match($0, /"[^"]+"/)) proc=substr($0, RSTART+1, RLENGTH-2);
        print port, proc }' | sort -un -k1,1
}

# интерфейс в интернет
wan_iface() { ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}'; }

print_env_summary() {
    title "Окружение"
    printf '  %-22s %s\n' "Роль сервера:" "$(server_role)"
    printf '  %-22s %s\n' "Режим фаервола:" "$(fw_mode)$(ufw_active && echo ' (UFW активен)')"
    printf '  %-22s %s\n' "SSH-порты:" "$(detect_ssh_ports)"
    has_node && printf '  %-22s %s\n' "Порты Xray:" "$(detect_xray_ports || true)"
    has_node && printf '  %-22s %s\n' "API ноды (NODE_PORT):" "$(detect_node_api_port)"
    has_node && printf '  %-22s %s\n' "IP панели:" "$(detect_panel_ips || true)"
    printf '  %-22s %s\n' "WAN-интерфейс:" "$(wan_iface)"
}

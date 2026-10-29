#!/usr/bin/env bash
# fail2detect — автоопределение окружения (Remnawave, порты, панель).

# compose-файл каталога: у установщиков и версий docker compose имена разные
compose_file() {   # каталог → путь (если файла нет — docker-compose.yml)
    local f
    for f in docker-compose.yml docker-compose.yaml compose.yml compose.yaml; do
        [[ -f "$1/$f" ]] && { echo "$1/$f"; return 0; }
    done
    echo "$1/docker-compose.yml"; return 1
}

# сервис есть в compose: по имени или по образу (имя сервиса установщики меняют)
compose_has_service() {   # каталог сервис [шаблон_образа]
    local f; f=$(compose_file "$1") || return 1
    grep -qE "^[[:space:]]*$2:" "$f" && return 0
    [[ -n "${3:-}" ]] && grep -qE "^[[:space:]]*image:[[:space:]]*[\"']?([^/]+/)?$3([:@\"' ]|$)" "$f"
}

# контейнеры Remnawave: имя<TAB>образ<TAB>каталог compose<TAB>состояние (кэш на запуск)
_rw_containers() {
    if [[ -z "${_RW_CT_DONE:-}" ]]; then
        _RW_CT=$(docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Label "com.docker.compose.project.working_dir"}}\t{{.State}}' 2>/dev/null | grep -E $'\tremnawave/' || true)
        _RW_CT_DONE=1
    fi
    [[ -n "$_RW_CT" ]] && printf '%s\n' "$_RW_CT"
}
_rw_ct_dir() { _rw_containers | awk -F'\t' -v i="$1" '$2 ~ "^remnawave/" i "(:|@|$)" && $3 != "" {print $3; exit}'; }
_rw_ct_has() { _rw_containers | awk -F'\t' -v i="$1" '$2 ~ "^remnawave/" i "(:|@|$)" {f = 1} END {exit !f}'; }

# найти каталоги панели/ноды/подписки, если они не там, где ждём
rw_locate() {
    local d
    if ! compose_has_service "$RW_PANEL_DIR" remnawave 'remnawave/backend'; then
        d=$(_rw_ct_dir backend); [[ -n "$d" ]] && compose_has_service "$d" remnawave 'remnawave/backend' && RW_PANEL_DIR="$d"
    fi
    if ! compose_has_service "$RW_NODE_DIR" remnanode 'remnawave/node' && ! compose_has_service "$RW_PANEL_DIR" remnanode 'remnawave/node'; then
        d=$(_rw_ct_dir node); [[ -n "$d" && "$d" != "$RW_PANEL_DIR" ]] && compose_has_service "$d" remnanode 'remnawave/node' && RW_NODE_DIR="$d"
    fi
    if [[ ! -f "$(compose_file "$RW_SUB_DIR")" ]]; then
        d=$(_rw_ct_dir subscription-page); [[ -n "$d" && "$d" != "$RW_PANEL_DIR" ]] && RW_SUB_DIR="$d"
    fi
    return 0
}

has_panel()  { compose_has_service "$RW_PANEL_DIR" remnawave 'remnawave/backend' || _rw_ct_has backend; }
has_node()   { compose_has_service "$RW_NODE_DIR" remnanode 'remnawave/node' || compose_has_service "$RW_PANEL_DIR" remnanode 'remnawave/node' || _rw_ct_has node; }
has_sub_page() { compose_file "$RW_SUB_DIR" >/dev/null || compose_has_service "$RW_PANEL_DIR" remnawave-subscription-page 'remnawave/subscription-page' || _rw_ct_has subscription-page; }

# каталог, где лежит compose с remnanode
node_dir() {
    if compose_has_service "$RW_NODE_DIR" remnanode 'remnawave/node'; then echo "$RW_NODE_DIR"
    elif compose_has_service "$RW_PANEL_DIR" remnanode 'remnawave/node'; then echo "$RW_PANEL_DIR"; fi
}

server_role() {
    local r=()
    has_panel && r+=("панель")
    has_node && r+=("нода")
    has_sub_page && r+=("подписка")
    ((${#r[@]})) && (IFS=+; echo "${r[*]}") || echo "не найдено"
}

# что и где найдено — для разбора «роль: не найдено»
rw_detect_report() {
    title "Что fail2detect видит на сервере"
    local name dir svc img f
    for name in "Панель|$RW_PANEL_DIR|remnawave|backend" "Нода|$RW_NODE_DIR|remnanode|node" "Подписка|$RW_SUB_DIR|remnawave-subscription-page|subscription-page"; do
        IFS='|' read -r name dir svc img <<<"$name"
        f=$(compose_file "$dir") || f=""
        if [[ -n "$f" ]] && compose_has_service "$dir" "$svc" "remnawave/$img"; then
            ok "$name: $f (сервис $svc / образ remnawave/$img)"
        elif [[ -n "$f" ]]; then
            warn "$name: в $f нет сервиса $svc и образа remnawave/$img"
        else
            info "$name: в $dir compose-файла нет"
        fi
    done
    echo
    if have docker; then
        local ct; ct=$(_rw_containers)
        if [[ -n "$ct" ]]; then
            echo "  ${C_BOLD}Контейнеры Remnawave${C_RESET}"
            local n i w st
            while IFS=$'\t' read -r n i w st; do printf '    %-28s %-36s %-9s %s\n' "$n" "$i" "$st" "${w:-—}"; done <<<"$ct"
        else
            warn "Контейнеров с образами remnawave/* нет (docker ps -a)"
        fi
    else
        warn "Docker не установлен"
    fi
    echo
    echo "  Роль: $(server_role)"
    echo
    if systemctl is-active --quiet fail2detect 2>/dev/null; then ok "Демон fail2detect работает"
    else
        warn "Демон fail2detect остановлен ($(systemctl is-enabled fail2detect 2>/dev/null || echo "не установлен"))"
        journalctl -u fail2detect -n 8 --no-pager 2>/dev/null | sed 's/^/    /'
        echo "    Запустить: systemctl enable --now fail2detect   (или fail2detect setup)"
    fi
    echo
    echo "  Каталог не тот? Задайте явно: fail2detect config RW_PANEL_DIR /путь  (или RW_NODE_DIR)"
}

# NODE_PORT (API ноды, по умолчанию 2222); старые версии — APP_PORT
detect_node_api_port() {
    [[ -n "$NODE_API_PORT" ]] && { echo "$NODE_API_PORT"; return; }
    local d p="" ct f; d=$(node_dir); [[ -n "$d" ]] || return 1
    # 1) как запущена нода на самом деле — переменная NODE_PORT контейнера
    ct=$(_rw_containers | awk -F'\t' '$2 ~ /^remnawave\/node/ && $4 == "running" {print $1; exit}')
    [[ -n "$ct" ]] && p=$(docker inspect "$ct" -f '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | sed -nE 's/^(NODE_PORT|APP_PORT)=([0-9]+).*/\2/p' | head -1)
    # 2) блок сервиса ноды в compose. Весь файл не годится: у панели «всё в одном»
    #    выше стоят APP_PORT=3000/3010 панели и подписки — их и брали за порт ноды.
    if [[ -z "$p" ]] && f=$(compose_file "$d"); then
        p=$(compose_service_block "$f" remnanode 'remnawave/node' | grep -oE '(NODE_PORT|APP_PORT)[=:][[:space:]]*"?[0-9]+' | grep -oE '[0-9]+$' | head -1)
    fi
    # 3) .env ноды — только если это её собственный каталог (у панели там APP_PORT панели)
    if [[ -z "$p" && "$d" != "$RW_PANEL_DIR" && -f "$d/.env" ]]; then
        p=$(grep -oE '^(NODE_PORT|APP_PORT)=[[:space:]]*"?[0-9]+' "$d/.env" | grep -oE '[0-9]+$' | head -1)
    fi
    echo "${p:-2222}"
}

# строки одного сервиса из compose (по имени или по образу)
compose_service_block() {   # файл сервис [образ]
    awk -v svc="$2" -v img="${3:-}" '
        function ind(s) { match(s, /^ */); return RLENGTH }
        /^[^[:space:]#]/ { if (inb) flush(); top = ($0 ~ /^services:/); inb = 0; next }
        top && /^[[:space:]]+[A-Za-z0-9_.-]+:[[:space:]]*$/ && (sind == "" || ind($0) == sind) {
            sind = ind($0); name = $0; gsub(/[[:space:]:]/, "", name)
            if (inb) flush(); inb = 1; buf = ""; cur = name; next
        }
        inb { buf = buf $0 "\n" }
        function flush() { if (!done && (cur == svc || (img != "" && buf ~ ("image:[[:space:]]*[\"'\'']?" img)))) { printf "%s", buf; done = 1 } }
        END { if (inb && !done) flush() }
    ' "$1" | awk 'NF'   # без пустых строк
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

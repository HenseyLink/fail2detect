#!/usr/bin/env bash
# fail2detect — мастер настройки и аудит безопасности.

F2D_SHARE="${F2D_SHARE:-/opt/fail2detect}"

install_default_jails() {
    ensure_dirs
    local f
    for f in "$F2D_SHARE"/conf/jail.d/*.conf; do
        [[ -f "$f" ]] || continue
        [[ -f "$F2D_JAIL_DIR/$(basename "$f")" ]] || install -m 644 "$f" "$F2D_JAIL_DIR/"
    done
    # панельный jail имеет смысл только там, где есть панель с прямым 443
    if has_panel && ! compose_has_service "$RW_PANEL_DIR" remnanode; then
        sed -i 's/^ENABLED=.*/ENABLED=yes/' "$F2D_JAIL_DIR/panel.conf" 2>/dev/null
    fi
}

install_services() {
    local u
    for u in fail2detect.service fail2detect-blocklist.service fail2detect-blocklist.timer; do
        install -m 644 "$F2D_SHARE/systemd/$u" "/etc/systemd/system/$u"
    done
    systemctl daemon-reload
    systemctl enable fail2detect.service fail2detect-blocklist.timer >/dev/null 2>&1
    # один запуск службы (а не enable --now + restart), таймер — после неё
    systemctl restart fail2detect.service || warn "Служба не стартовала: journalctl -u fail2detect -n 30"
    systemctl start fail2detect-blocklist.timer >/dev/null 2>&1
    ok "Службы fail2detect включены (демон + обновление блок-листов раз в сутки)"
}

# UFW после установщика: API ноды открыт только для панели, по умолчанию deny
ufw_harden() {
    ufw_active || return 0
    ufw default deny incoming >/dev/null
    ufw logging low >/dev/null
    if has_node; then
        local api panels ip; api=$(detect_node_api_port); panels=$(detect_panel_ips)
        if ufw status | grep -qE "^${api}(/tcp)?[[:space:]]+ALLOW( IN)?[[:space:]]+Anywhere"; then
            if [[ -n "$panels" ]]; then
                ufw --force delete allow "$api/tcp" >/dev/null 2>&1; ufw --force delete allow "$api" >/dev/null 2>&1
                for ip in $panels; do ufw_allow "$api" tcp "$ip" "Remnawave panel"; done
                ok "UFW: порт API ноды $api закрыт для всех, кроме панели"
            else
                warn "UFW: порт $api открыт всему интернету, а IP панели неизвестен — закройте вручную"
            fi
        fi
    fi
}

setup_wizard() {
    require_root
    ensure_deps
    ensure_dirs
    install_default_jails
    load_config
    print_env_summary

    if has_panel || has_node; then
        rw_setup_interactive
        load_config
    fi

    title "Настройка защиты"
    if has_node && [[ -z "$(detect_panel_ips)" ]]; then
        if has_panel; then
            info "Панель на этом же сервере — API ноды доступен ей через внутренний интерфейс"
        else
            ask "IP панели Remnawave (ей одной разрешён API ноды)" ""
            is_ip "$REPLY" && config_set PANEL_IPS "$REPLY"
        fi
    fi

    local me="${SSH_CLIENT%% *}"
    if [[ -n "$me" ]] && ! ip_in_list "$me" "$TRUSTED_IPS"; then
        info "Ваш текущий IP: $me. Если он постоянный — добавьте в белый список."
        info "Если IP динамический (мобильный интернет) — не добавляйте."
        confirm "Добавить $me в белый список?" n && list_add TRUSTED_IPS "$me"
    fi

    if confirm "Подключить блок-листы сканеров РКН/«Скипа» (antiscanner, skipa)?" y; then
        config_set BLOCKLISTS "antiscanner skipa"
    else config_set BLOCKLISTS ""; fi
    if confirm "Также блокировать государственные сети РФ (~12 тыс. подсетей)?" n; then
        list_add BLOCKLISTS government
    fi
    if confirm "Не отвечать на ping (скрыть сервер от массовых сканеров)?" y; then
        config_set STEALTH_ICMP yes
    else config_set STEALTH_ICMP no; fi
    if confirm "Анти-флуд (бан IP за шквал соединений)? Осторожно с мобильным CGNAT" n; then
        config_set FLOOD_GUARD yes
    else config_set FLOOD_GUARD no; fi

    [[ "$(fw_mode)" == ufw ]] && ufw_harden
    [[ -n "$BLOCKLISTS" ]] && blocklist_update
    if ! fw_apply --safe; then
        err "Правила откачены — службы fail2detect НЕ включены. Проверьте доступ и запустите мастер снова."
        return 1
    fi
    install_services
    audit_write SETUP - - - "мастер настройки завершён"
    echo
    ok "Готово. Проверить итог: ${C_BOLD}fail2detect doctor${C_RESET}"
}

# ---------- аудит безопасности ----------
_chk() {   # level text
    case "$1" in
        ok)   printf '  %s✔%s %s\n' "$C_GREEN" "$C_RESET" "$2";;
        warn) printf '  %s!%s %s\n' "$C_YELLOW" "$C_RESET" "$2"; DOC_WARN=$((DOC_WARN + 1));;
        bad)  printf '  %s✘%s %s\n' "$C_RED" "$C_RESET" "$2"; DOC_BAD=$((DOC_BAD + 1));;
    esac
    [[ -n "${3:-}" ]] && printf '      %s%s%s\n' "$C_GRAY" "$3" "$C_RESET"
    return 0
}

doctor() {
    require_root
    DOC_WARN=0; DOC_BAD=0
    print_env_summary

    title "Фаервол"
    if nft list table inet "$F2D_NFT_TABLE" >/dev/null 2>&1; then _chk ok "Таблица fail2detect загружена"
    else _chk bad "Таблица fail2detect не загружена" "fail2detect fw apply"; fi
    systemctl is-active --quiet fail2detect 2>/dev/null && _chk ok "Демон банов работает" || _chk bad "Демон банов не запущен" "systemctl enable --now fail2detect"
    if [[ "$(fw_mode)" == ufw ]]; then
        ufw status verbose 2>/dev/null | grep -q 'deny (incoming)' && _chk ok "UFW: входящие по умолчанию запрещены" || _chk bad "UFW пропускает входящие по умолчанию" "ufw default deny incoming"
        ufw status verbose 2>/dev/null | grep -qE '^Logging: on' && _chk ok "UFW логирует блокировки (нужно jail portscan)" || _chk warn "UFW не логирует блокировки — jail portscan слеп" "ufw logging low"
    fi
    [[ -s "$F2D_STATE_DIR/blocklist4.txt" ]] && _chk ok "Блок-листы сканеров: $(wc -l < "$F2D_STATE_DIR/blocklist4.txt") сетей" || _chk warn "Блок-листы сканеров не загружены" "fail2detect blocklist update"
    [[ "$STEALTH_ICMP" == yes ]] && _chk ok "Сервер не отвечает на ping" || _chk warn "Сервер отвечает на ping"

    title "Открытые порты"
    local pub; pub=" $(fw_public_tcp) "
    local api=""; has_node && api=$(detect_node_api_port)
    local port proc
    while read -r port proc; do
        [[ -z "$port" ]] && continue
        if [[ "$port" == "$api" ]]; then
            _chk ok "$port ($proc) — API ноды, доступен только панели"
        elif [[ "$pub" == *" $port "* ]]; then
            _chk ok "$port ($proc) — открыт намеренно"
        else
            case "$port" in
                3000|3001|3010|5432|6767|6379) _chk bad "$port ($proc) слушает наружу — это внутренний порт панели" "закрыт фаерволом, но лучше привязать к 127.0.0.1 в docker-compose";;
                *) _chk ok "$port ($proc) — слушает, но закрыт фаерволом";;
            esac
        fi
    done < <(listening_public_tcp)
    if have docker; then
        local dp; dp=$(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep -oE '^[^ ]+|0\.0\.0\.0:[0-9]+|\[::\]:[0-9]+' | paste -sd' ' -)
        if grep -qE '0\.0\.0\.0:|\[::\]:' <<<"$dp"; then
            [[ "$DOCKER_GUARD" == yes ]] && _chk ok "Docker публикует порты наружу, но docker-guard их прикрывает" \
                || _chk bad "Docker публикует порты в обход UFW" "включите DOCKER_GUARD=yes"
        fi
    fi

    title "SSH"
    local sshcfg; sshcfg=$(sshd -T 2>/dev/null)
    grep -q '^passwordauthentication yes' <<<"$sshcfg" && _chk warn "Вход по паролю разрешён" "лучше только ключи: PasswordAuthentication no" || _chk ok "Вход только по ключам"
    grep -q '^permitrootlogin yes' <<<"$sshcfg" && _chk warn "root может входить по паролю" "PermitRootLogin prohibit-password"
    [[ "$(detect_ssh_ports)" == 22 ]] && _chk warn "SSH на стандартном порту 22" "смена порта снижает шум сканеров (не забудьте fail2detect port open)" || _chk ok "SSH на нестандартном порту $(detect_ssh_ports)"
    have fail2ban-server && systemctl is-active --quiet fail2ban && _chk warn "Работает и fail2ban" "совместимо, но SSH лучше банить чем-то одним: fail2detect jail disable sshd"

    if has_node || has_panel; then
        title "Remnawave / Xray"
        rw_normalize_url
        if [[ "$RW_API_URL" == http://127.0.0.1:3000 ]] && ! has_panel; then
            _chk warn "Панель на другом сервере — inbound'ы проверяются на сервере панели" "или: fail2detect config RW_API_URL https://панель + токен"
        elif ! F2D_NO_PROMPT=1 rw_token >/dev/null 2>&1; then
            _chk warn "API-токен панели не задан — проверка inbound'ов пропущена" "fail2detect setup или fail2detect config RW_API_TOKEN <токен>"
        elif info "Проверяю API панели ($RW_API_URL, до 15 с)…" && \
             IFS='|' read -r _pc _ <<<"$(rw_probe)" && [[ "$_pc" != 200 ]]; then
            _chk warn "API панели: $(rw_probe_explain "$_pc")" "адрес: $RW_API_URL; исправить: fail2detect setup"
        else
            local tag port tr
            while IFS=$'\t' read -r _ _ tag port _ tr; do
                case "$tr" in
                    tcp/reality|raw/reality) _chk ok "$tag :$port — $tr" "Vision (xtls-rprx-vision) Remnawave включает сам — TLS-in-TLS не виден";;
                    hysteria/*) _chk warn "$tag :$port — Hysteria 2 (QUIC/UDP)" "UDP/QUIC в РФ часто режут или замедляют — держите запасной TCP-транспорт";;
                    xhttp/reality|xhttp/tls|grpc/reality|grpc/tls) _chk warn "$tag :$port — $tr" "без Vision внутренний TLS клиента виден по размерам/таймингам пакетов (TLS-in-TLS); XHTTP маскируется лучше gRPC";;
                    *) _chk bad "$tag :$port — $tr (без шифрования транспорта)" "такой inbound легко детектируется";;
                esac
                [[ "$port" == 443 ]] || _chk ok "$tag на нестандартном порту $port"
            done < <(F2D_NO_PROMPT=1 F2D_API_CONNECT_TIMEOUT=5 F2D_API_MAX_TIME=10 rw_inbounds 2>/dev/null </dev/null)
        fi
        has_node && ! has_panel && [[ -z "$(detect_panel_ips)" ]] && _chk bad "IP панели неизвестен — API ноды некому разрешить" "fail2detect config PANEL_IPS <ip>"
    fi

    title "Итог"
    if (( DOC_BAD == 0 && DOC_WARN == 0 )); then ok "Замечаний нет"
    else printf '  %sкритичных: %d%s, %sпредупреждений: %d%s\n' "$C_RED" "$DOC_BAD" "$C_RESET" "$C_YELLOW" "$DOC_WARN" "$C_RESET"; fi
}

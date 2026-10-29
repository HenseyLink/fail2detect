#!/usr/bin/env bash
# fail2detect — удаление и переустановка ноды и панели.
#
# Всегда сначала резервная копия (/var/lib/fail2detect/backup): файлы ноды,
# у панели — ещё и дамп базы. База панели удаляется только после ввода слова
# «удалить»: в ней пользователи и подписки. В панели нода удаляется через API
# только с подтверждения; профиль — только если его создал fail2detect (f2d-…)
# и им больше никто не пользуется.

F2D_BACKUP_DIR="${F2D_STATE_DIR}/backup"

# rm -rf только для известных каталогов Remnawave/fail2detect
_safe_rmdir() {
    case "$1" in
        /opt/remnanode|/opt/remnawave|/opt/subscription|/opt/fail2detect-web) rm -rf -- "$1";;
        *) err "Отказ удалять «$1»: это не каталог Remnawave"; return 1;;
    esac
}

_backup_dir() {   # каталог метка -> печатает путь архива
    [[ -d "$1" ]] || return 0
    install -d -m 700 "$F2D_BACKUP_DIR"
    local f; f="$F2D_BACKUP_DIR/$2-$(date +%Y%m%d-%H%M%S).tgz"
    tar -czf "$f" -C "$(dirname "$1")" "$(basename "$1")" 2>/dev/null && chmod 600 "$f" && echo "$f"
}

_close_port() {   # порт/протокол
    local p="${1%/*}" l4="${1#*/}"
    [[ " $(detect_ssh_ports) " == *" $p "* ]] && return 0   # SSH не трогаем никогда
    list_del "PUBLIC_$( [[ $l4 == udp ]] && echo UDP || echo TCP )" "$p"
    ufw_delete_allow "$p" "$l4"
}

# ---------- нода ----------
remove_node() {   # [--reinstall]
    require_root; load_config
    local reinstall=no; [[ "${1:-}" == --reinstall ]] && reinstall=yes
    local d; d=$(node_dir)
    [[ -z "$d" ]] && compose_file "$RW_NODE_DIR" >/dev/null && d="$RW_NODE_DIR"
    [[ -n "$d" ]] || { info "Ноды на этом сервере нет"; return 0; }
    if [[ "$d" == "$RW_PANEL_DIR" ]]; then
        die "Нода в одном docker-compose с панелью ($d). Удалите её из compose вручную или удалите панель целиком: fail2detect remove panel"
    fi

    # что ещё живёт в этом compose (например, сайт-заглушка установщика)
    local others; others=$(awk '/^services:/{f=1;next} f&&/^[^ ]/{f=0} f&&/^ +[A-Za-z0-9_-]+:[ \t]*$/{gsub(/[ :]/,""); print}' "$(compose_file "$d")" | grep -vx remnanode | xargs)
    local xp=(); read -ra xp <<<"$NODE_XRAY_PORTS"
    local ports; ports=$( { ((${#xp[@]})) && printf '%s\n' "${xp[@]}"
        for p in $(detect_xray_ports); do echo "$p/tcp"; done
        for p in $(detect_xray_udp_ports); do echo "$p/udp"; done; } | grep . | sort -u | xargs)
    local api; api=$(detect_node_api_port 2>/dev/null)

    title "$([[ $reinstall == yes ]] && echo "Переустановка" || echo "Удаление") ноды Remnawave"
    echo "  Каталог:        $d (будет сохранён в архив)"
    [[ -n "$others" ]] && echo "  Вместе с ней:   $others (из того же docker-compose)"
    echo "  Закрою порты:   ${ports:-—}${api:+  + API ноды $api}"
    confirm "Удалить ноду с этого сервера?" n || return 1

    # панель: удалить ноду и там? (решаем до остановки — пока знаем адрес)
    local panel_cleanup=no
    if [[ -t 0 ]] && confirm "Удалить эту ноду и в панели (нода, её хосты, профиль f2d-…)?" "$([[ $reinstall == yes ]] && echo y || echo n)"; then
        panel_cleanup=yes
    fi

    local bk; bk=$(_backup_dir "$d" remnanode) && [[ -n "$bk" ]] && ok "Резервная копия: $bk"
    (cd "$d" && docker compose down --remove-orphans >/dev/null 2>&1) || docker rm -f remnanode >/dev/null 2>&1
    ok "Контейнеры ноды остановлены и удалены"
    _safe_rmdir "$d" && ok "Каталог $d удалён"

    local pp ip
    for pp in $ports; do _close_port "$pp"; done
    if [[ -n "$api" ]]; then
        for ip in $(detect_panel_ips); do
            ufw_active && ufw --force delete allow proto tcp from "$ip" to any port "$api" >/dev/null 2>&1
        done
    fi
    # свой nginx нужен был только для сайта-заглушки — убрать, если на нём нет панели/подписки
    if web_installed; then
        web_load
        if [[ -z "$PANEL_DOMAIN" && -z "$SUB_DOMAIN" ]]; then
            (cd "$F2D_WEB_DIR" && docker compose down >/dev/null 2>&1)
            _safe_rmdir "$F2D_WEB_DIR"; web_set SELFSTEAL_DOMAIN ""
            ok "Сайт-заглушка (nginx fail2detect) удалён"
        fi
    fi
    config_set NODE_XRAY_PORTS ""; config_set NODE_TLS_DOMAIN ""; config_set NODE_API_PORT ""
    fw_apply >/dev/null 2>&1 && ok "Фаервол: порты ноды закрыты"
    audit_write REMOVE - node - "нода удалена${bk:+, архив $bk}"

    [[ "$panel_cleanup" == yes ]] && panel_forget_node
    ok "Нода удалена.$([[ $reinstall == yes ]] || echo " Поставить заново: fail2detect install node")"
}

# удалить ноду этого сервера в панели (нода, хосты, профиль f2d-…)
panel_forget_node() {
    rw_need_api || { warn "Панель недоступна — удалите ноду в панели вручную"; return 0; }
    local me nodes; me=$(public_ip)
    nodes=$(rw_api GET /api/nodes | jq -c --arg a "$me" --arg d "${T_DOMAIN:-}" \
        '[.response[] | select(.address == $a or ($d != "" and .address == $d))]')
    if [[ "$(jq length <<<"$nodes")" == 0 ]]; then
        warn "В панели нет ноды с адресом $me — если она там есть под другим адресом, удалите её вручную"
        return 0
    fi
    local n uuid name puuid
    while read -r n; do
        uuid=$(jq -r .uuid <<<"$n"); name=$(jq -r .name <<<"$n")
        puuid=$(jq -r '.configProfile.activeConfigProfileUuid // empty' <<<"$n")
        confirm "Удалить в панели ноду «${name}» ($me)?" y || continue
        rw_api DELETE "/api/nodes/$uuid" >/dev/null && ok "Нода «${name}» удалена из панели"
        [[ -n "$puuid" ]] || continue
        local prof pname users
        prof=$(rw_api GET "/api/config-profiles/$puuid")
        pname=$(jq -r '.response.name // empty' <<<"$prof")
        users=$(rw_api GET /api/nodes | jq --arg p "$puuid" '[.response[] | select(.configProfile.activeConfigProfileUuid == $p)] | length')
        if [[ "$pname" == f2d-* && "$users" == 0 ]]; then
            local h
            for h in $(rw_api GET /api/hosts | jq -r --arg p "$puuid" '.response[] | select(.inbound.configProfileUuid == $p) | .uuid'); do
                rw_api DELETE "/api/hosts/$h" >/dev/null
            done
            rw_api DELETE "/api/config-profiles/$puuid" >/dev/null && ok "Профиль «${pname}» и его хосты удалены"
        elif [[ -n "$pname" ]]; then
            info "Профиль «${pname}» оставлен: $([[ "$pname" != f2d-* ]] && echo "его создал не fail2detect" || echo "им пользуются другие ноды")"
        fi
    done < <(jq -c '.[]' <<<"$nodes")
    audit_write REMOVE - panel - "нода $me удалена из панели"
}

reinstall_node() {
    remove_node --reinstall || return 1
    install_node "$@"
}

# ---------- панель ----------
remove_panel() {   # [--reinstall]
    require_root; load_config
    has_panel || compose_file "$RW_PANEL_DIR" >/dev/null || { info "Панели на этом сервере нет"; return 0; }
    title "Удаление панели Remnawave"
    echo "  Каталоги:  $RW_PANEL_DIR$([[ -d $RW_SUB_DIR ]] && echo " и $RW_SUB_DIR") (будут сохранены в архив)"
    echo "  База:      дамп в $F2D_BACKUP_DIR; удалять ли сам том с базой — спрошу отдельно"
    compose_has_service "$RW_PANEL_DIR" remnanode && warn "В том же compose работает нода — она тоже будет удалена"
    confirm "Удалить панель с этого сервера?" n || return 1

    install -d -m 700 "$F2D_BACKUP_DIR"
    local ts dump; ts=$(date +%Y%m%d-%H%M%S); dump="$F2D_BACKUP_DIR/remnawave-db-$ts.sql.gz"
    if docker ps --format '{{.Names}}' | grep -qx remnawave-db; then
        if bk_dump_db "$dump"; then
            chmod 600 "$dump"; ok "Дамп базы: $dump"
        else
            rm -f "$dump"; err "Дамп базы не получился"
            confirm "Продолжить удаление БЕЗ дампа базы?" n || return 1
        fi
    else
        warn "Контейнер базы не запущен — дамп пропущен (том с базой можно оставить)"
    fi
    local bk
    bk=$(_backup_dir "$RW_PANEL_DIR" remnawave) && [[ -n "$bk" ]] && ok "Архив панели: $bk"
    [[ -d "$RW_SUB_DIR" ]] && bk=$(_backup_dir "$RW_SUB_DIR" subscription) && [[ -n "$bk" ]] && ok "Архив подписки: $bk"

    local drop_db=no
    echo
    warn "Том с базой содержит ВСЕХ пользователей и подписки."
    ask "Удалить и том с базой? Введите «удалить», иначе том останется" ""
    [[ "$REPLY" == удалить ]] && drop_db=yes

    [[ -d "$RW_SUB_DIR" ]] && { (cd "$RW_SUB_DIR" && docker compose down >/dev/null 2>&1); _safe_rmdir "$RW_SUB_DIR"; }
    if [[ "$drop_db" == yes ]]; then
        (cd "$RW_PANEL_DIR" && docker compose down -v --remove-orphans >/dev/null 2>&1) && ok "Панель и том с базой удалены"
    else
        (cd "$RW_PANEL_DIR" && docker compose down --remove-orphans >/dev/null 2>&1) && ok "Панель остановлена, том с базой сохранён"
    fi
    _safe_rmdir "$RW_PANEL_DIR"

    # nginx: убрать панель/подписку; если остался сайт-заглушка ноды — пересобрать
    if web_installed; then
        web_set PANEL_DOMAIN ""; web_set SUB_DOMAIN ""; web_load
        if [[ -n "$SELFSTEAL_DOMAIN" ]] && has_node; then web_apply >/dev/null
        else (cd "$F2D_WEB_DIR" && docker compose down >/dev/null 2>&1); _safe_rmdir "$F2D_WEB_DIR"; fi
    fi
    rm -f "$RW_TOKEN_FILE" "$F2D_CONF_DIR/panel-admin.txt"
    config_set RW_API_URL "http://127.0.0.1:3000"; config_set RW_API_TOKEN ""; config_set RW_API_COOKIE ""
    fw_apply >/dev/null 2>&1
    audit_write REMOVE - panel - "панель удалена (база: $([[ $drop_db == yes ]] && echo удалена || echo сохранена))"
    ok "Панель удалена.$([[ "${1:-}" == --reinstall ]] || echo " Поставить заново: fail2detect install panel")"
    [[ "$drop_db" == no ]] && info "Том с базой сохранён: при новой установке с тем же паролем БД данные вернутся (пароль — в архиве .env)."
}

reinstall_panel() {
    remove_panel --reinstall || return 1
    install_panel
}

remove_cli() {   # node|panel
    case "${1:-}" in
        node) remove_node;; panel) remove_panel;;
        *) die "remove node|panel";;
    esac
}
reinstall_cli() {
    case "${1:-}" in
        node) shift; reinstall_node "$@";; panel) reinstall_panel;;
        *) die "reinstall node|panel";;
    esac
}

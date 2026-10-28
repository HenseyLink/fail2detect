#!/usr/bin/env bash
# fail2detect — установка Remnawave: панель, нода, страница подписки.
#
# compose и .env панели и страницы подписки берутся из официальных
# репозиториев Remnawave в момент установки, fail2detect только подставляет
# секреты и домены. Возможности:
#   * любой порт ноды (а не только 443);
#   * транспорты: TCP/XHTTP/gRPC + Reality, XHTTP/gRPC + TLS, Hysteria 2;
#   * сразу с защитой fail2detect (фаервол, баны, скрытая панель).

RW_RAW_BACKEND="https://raw.githubusercontent.com/remnawave/backend/refs/heads/main"
RW_RAW_SUBPAGE="https://raw.githubusercontent.com/remnawave/subscription-page/refs/heads/main"
RW_SUB_DIR="/opt/subscription"

require_docker() {
    if have docker && docker compose version >/dev/null 2>&1; then return 0; fi
    info "Docker не найден — ставлю официальным скриптом get.docker.com"
    curl -fsSL https://get.docker.com | sh >/dev/null 2>&1 || die "Не удалось установить Docker"
    systemctl enable --now docker >/dev/null 2>&1
    docker compose version >/dev/null 2>&1 || die "Нет docker compose"
}

rand_alnum() { tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "${1:-32}"; }
# пароль под требования панели: ≥24, есть A-Z, a-z, 0-9
rand_password() { echo "$(rand_alnum 26)Aa1"; }

ask_domain() {   # prompt -> REPLY
    while true; do
        ask "$1" "${2:-}"
        [[ "$REPLY" =~ ^([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$ ]] || { warn "Это не похоже на домен"; continue; }
        local me ip; me=$(public_ip); ip=$(getent ahostsv4 "$REPLY" 2>/dev/null | awk 'NR==1{print $1}')
        if [[ -n "$me" && "$ip" != "$me" ]]; then
            warn "$REPLY указывает на ${ip:-ничего}, а IP сервера $me"
            confirm "Продолжить всё равно (например, домен за Cloudflare)?" n || continue
        fi
        return 0
    done
}

ask_port() {   # prompt default l4 -> REPLY
    while true; do
        ask "$1" "$2"
        is_port "$REPLY" || { warn "Порт 1–65535"; continue; }
        # ASK_PORT_NOCHECK — порт на другом сервере; ASK_PORT_ALLOW — его занимает сам меняемый inbound
        if [[ -z "${ASK_PORT_NOCHECK:-}" && "$REPLY" != "${ASK_PORT_ALLOW:-}" ]]; then
            local f=-tln; [[ "${3:-tcp}" == udp ]] && f=-uln
            if ss -H $f "( sport = :$REPLY )" 2>/dev/null | grep -q .; then warn "Порт $REPLY/${3:-tcp} занят"; continue; fi
        fi
        return 0
    done
}

# ---------- панель ----------
panel_wait_api() {
    local i
    for i in $(seq 1 60); do
        curl -fsS --max-time 3 -o /dev/null http://127.0.0.1:3000/api/auth/status \
            -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Forwarded-Proto: https' 2>/dev/null && return 0
        sleep 3
    done
    return 1
}

# регистрация первого админа и токен для fail2detect
panel_bootstrap() {
    local user pass jwt r tok
    user="admin_$(rand_alnum 6 | tr '[:upper:]' '[:lower:]')"; pass=$(rand_password)
    r=$(curl -sS --max-time 20 -X POST http://127.0.0.1:3000/api/auth/register \
        -H 'Content-Type: application/json' -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Forwarded-Proto: https' \
        --data-binary @- <<<"$(jq -n --arg u "$user" --arg p "$pass" '{username:$u, password:$p}')")
    jwt=$(jq -r '.response.accessToken // empty' <<<"$r")
    [[ -n "$jwt" ]] || { err "Не удалось создать администратора: $r"; return 1; }
    _RW_TOKEN="$jwt"
    r=$(rw_api POST /api/tokens '{"name":"fail2detect","expiresInDays":3650,"scopes":["*"]}')
    tok=$(jq -r '.response.token // empty' <<<"$r")
    if [[ -n "$tok" ]]; then
        install -m 600 /dev/null "$RW_TOKEN_FILE"; printf '%s' "$tok" > "$RW_TOKEN_FILE"; _RW_TOKEN="$tok"
    else
        warn "API-токен не создан ($r) — fail2detect будет использовать сессию админа"
        install -m 600 /dev/null "$RW_TOKEN_FILE"; printf '%s' "$jwt" > "$RW_TOKEN_FILE"
    fi
    install -m 600 /dev/null "$F2D_CONF_DIR/panel-admin.txt"
    printf 'login=%s\npassword=%s\n' "$user" "$pass" > "$F2D_CONF_DIR/panel-admin.txt"
    PANEL_ADMIN_USER="$user"; PANEL_ADMIN_PASS="$pass"
}

install_panel() {
    require_root; ensure_deps; ensure_dirs; require_docker; load_config
    if has_panel; then
        warn "Панель уже установлена в $RW_PANEL_DIR."
        confirm "Переустановить (удалить с резервной копией и поставить заново)?" n || return 1
        remove_panel --reinstall || return 1
        load_config
    fi
    title "Установка панели Remnawave"
    ask_domain "Домен панели (A-запись на этот сервер)"; local pdomain="$REPLY"
    local sdomain=""
    if confirm "Ставить страницу подписки на этом сервере (отдельный домен)?" y; then
        ask_domain "Домен страницы подписки"; sdomain="$REPLY"
    fi
    local with_node=no
    confirm "Ставить ноду на этот же сервер?" n && with_node=yes

    cert_ask_method
    cert_ensure "$pdomain" || return 1
    [[ -n "$sdomain" ]] && { cert_ensure "$sdomain" || return 1; }

    # официальные файлы Remnawave
    mkdir -p "$RW_PANEL_DIR"; cd "$RW_PANEL_DIR" || return 1
    curl -fsSL "$RW_RAW_BACKEND/docker-compose-prod.yml" -o docker-compose.yml || die "Не скачался docker-compose панели"
    curl -fsSL "$RW_RAW_BACKEND/.env.sample" -o .env || die "Не скачался .env панели"
    # том с базой от прошлой установки: новый пароль к нему не подойдёт
    local reuse=no
    if docker volume inspect remnawave-db-data >/dev/null 2>&1; then
        # архивы именуются remnawave-ГГГГММДД-ЧЧММСС.tgz — последний по имени и есть свежий
        local last="" f; for f in "$F2D_BACKUP_DIR"/remnawave-2*.tgz; do [[ -f "$f" ]] && last="$f"; done
        warn "Найдена база от прошлой установки (docker-том remnawave-db-data)."
        echo "  1. Использовать её — пользователи и подписки сохранятся (пароли возьму из архива${last:+ $last})"
        echo "  2. Удалить её и начать с чистой базы"
        ask "Вариант" "1"
        if [[ "$REPLY" == 2 ]]; then
            ask "Чтобы удалить базу, введите «удалить»" ""
            [[ "$REPLY" == удалить ]] || die "Отменено"
            docker volume rm remnawave-db-data >/dev/null && ok "Старая база удалена"
        else
            [[ -n "$last" ]] || die "Нет архива с паролями старой базы. Удалите том (docker volume rm remnawave-db-data) или положите прежний .env в $RW_PANEL_DIR"
            local old; old=$(tar -xzOf "$last" remnawave/.env 2>/dev/null) || die "В архиве $last нет .env"
            local key val
            for key in APP_SECRET POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB DATABASE_URL METRICS_USER METRICS_PASS WEBHOOK_SECRET_HEADER; do
                val=$(grep -m1 "^$key=" <<<"$old" | cut -d= -f2-) || continue
                [[ -n "$val" ]] && { grep -v "^$key=" .env > .env.new; printf '%s=%s\n' "$key" "$val" >> .env.new; mv .env.new .env; }
            done
            reuse=yes; ok "Пароли и секреты старой установки восстановлены из $last"
        fi
    fi
    local dbpass; dbpass=$(rand_alnum 32)
    [[ "$reuse" == yes ]] && sed -i \
        -e "s|^PANEL_DOMAIN=.*|PANEL_DOMAIN=$pdomain|" \
        -e "s|^SUB_PUBLIC_DOMAIN=.*|SUB_PUBLIC_DOMAIN=${sdomain:-$pdomain/api/sub}|" .env
    [[ "$reuse" == yes ]] || sed -i \
        -e "s|^APP_SECRET=.*|APP_SECRET=$(rand_alnum 64)|" \
        -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$dbpass|" \
        -e "s|^DATABASE_URL=.*|DATABASE_URL=\"postgresql://postgres:${dbpass}@remnawave-db:5432/postgres\"|" \
        -e "s|^METRICS_PASS=.*|METRICS_PASS=$(rand_alnum 24)|" \
        -e "s|^WEBHOOK_SECRET_HEADER=.*|WEBHOOK_SECRET_HEADER=$(rand_alnum 64)|" \
        -e "s|^PANEL_DOMAIN=.*|PANEL_DOMAIN=$pdomain|" \
        -e "s|^SUB_PUBLIC_DOMAIN=.*|SUB_PUBLIC_DOMAIN=${sdomain:-$pdomain/api/sub}|" \
        .env
    chmod 600 .env
    info "Запускаю панель…"
    docker compose up -d >/dev/null 2>&1 || die "docker compose up не удался (см. docker compose logs в $RW_PANEL_DIR)"
    panel_wait_api || die "Панель не отвечает на 127.0.0.1:3000 (docker compose logs -f remnawave)"
    ok "Панель запущена"
    if [[ "$reuse" == yes ]]; then
        info "База прежняя — администратор и API-токены тоже. Нужен API-токен панели."
        config_set RW_API_URL "http://127.0.0.1:3000"
        rw_setup_interactive || warn "Без токена не получится создать ноду и страницу подписки автоматически"
        PANEL_ADMIN_USER="(прежний)"; PANEL_ADMIN_PASS="(прежний)"
    else
        panel_bootstrap || return 1
    fi

    # nginx: если нода будет здесь же на 443 через Reality — панель доступна
    # через неё (selfsteal-сокет), иначе nginx сам слушает 443
    web_set PANEL_DOMAIN "$pdomain"
    web_set PANEL_KEY_NAME "$(rand_alnum 8 | tr '[:upper:]' '[:lower:]')"
    web_set PANEL_KEY_VALUE "$(rand_alnum 16)"
    web_set WEB_PORT 443
    [[ -n "$sdomain" ]] && web_set SUB_DOMAIN "$sdomain"
    if [[ -n "$sdomain" ]]; then install_sub_local "$sdomain" || warn "Страница подписки не установлена"; fi

    if [[ "$with_node" == yes ]]; then
        node_add_local || warn "Нода не добавлена — позже: fail2detect node add"
    fi
    web_load
    web_apply || return 1
    if [[ -n "$WEB_PORT" ]]; then list_add PUBLIC_TCP "$WEB_PORT"; ufw_allow "$WEB_PORT" tcp "" "Remnawave panel"; fi
    audit_write INSTALL - - - "панель $pdomain"

    title "Панель готова"
    echo "  Вход:   ${C_BOLD}$(panel_login_url)${C_RESET}"
    echo "  Логин:  $PANEL_ADMIN_USER"
    echo "  Пароль: $PANEL_ADMIN_PASS"
    echo "  ${C_GRAY}(сохранено в $F2D_CONF_DIR/panel-admin.txt; без ключа в ссылке панель не откроется)${C_RESET}"
    echo
    confirm "Настроить защиту fail2detect сейчас?" y && setup_wizard
}

# ---------- страница подписки ----------
# на сервере панели
install_sub_local() {   # sub_domain
    local sdomain="$1" tok
    mkdir -p "$RW_SUB_DIR"; cd "$RW_SUB_DIR" || return 1
    curl -fsSL "$RW_RAW_SUBPAGE/docker-compose-prod.yml" -o docker-compose.yml || return 1
    curl -fsSL "$RW_RAW_SUBPAGE/.env.sample" -o .env || return 1
    tok=$(rw_api POST /api/tokens '{"name":"subscription-page","expiresInDays":3650,"scopes":["*"]}' | jq -r '.response.token // empty')
    [[ -n "$tok" ]] || { err "Не удалось выпустить токен для страницы подписки"; return 1; }
    sed -i -e "s|^REMNAWAVE_PANEL_URL=.*|REMNAWAVE_PANEL_URL=http://remnawave:3000|" \
           -e "s|^REMNAWAVE_API_TOKEN=.*|REMNAWAVE_API_TOKEN=$tok|" .env
    chmod 600 .env
    docker compose up -d >/dev/null 2>&1 && ok "Страница подписки запущена (https://$sdomain)"
}

# отдельный сервер подписки
install_sub() {
    require_root; ensure_deps; ensure_dirs; require_docker; load_config
    if has_panel; then
        ask_domain "Домен страницы подписки"; local sdomain="$REPLY"
        cert_ensure "$sdomain" || return 1
        install_sub_local "$sdomain" || return 1
        sed -i "s|^SUB_PUBLIC_DOMAIN=.*|SUB_PUBLIC_DOMAIN=$sdomain|" "$RW_PANEL_DIR/.env"
        (cd "$RW_PANEL_DIR" && docker compose up -d >/dev/null 2>&1)
        web_set SUB_DOMAIN "$sdomain"; web_load
        [[ -z "$WEB_PORT" ]] && web_set WEB_PORT 443
        web_apply; return
    fi
    title "Страница подписки на отдельном сервере"
    ask_domain "Домен страницы подписки"; local sdomain="$REPLY"
    ask "URL панели (https://panel.example.com)"; local purl="${REPLY%/}"
    local tok; read_secret "API-токен панели (Настройки → API токены)"; tok="$REPLY"
    cert_ensure "$sdomain" || return 1
    mkdir -p "$RW_SUB_DIR"; cd "$RW_SUB_DIR" || return 1
    curl -fsSL "$RW_RAW_SUBPAGE/docker-compose-prod.yml" -o docker-compose.yml || return 1
    curl -fsSL "$RW_RAW_SUBPAGE/.env.sample" -o .env || return 1
    sed -i -e "s|^REMNAWAVE_PANEL_URL=.*|REMNAWAVE_PANEL_URL=$purl|" -e "s|^REMNAWAVE_API_TOKEN=.*|REMNAWAVE_API_TOKEN=$tok|" .env
    chmod 600 .env
    docker network inspect remnawave-network >/dev/null 2>&1 || docker network create remnawave-network >/dev/null
    docker compose up -d >/dev/null 2>&1 || die "Страница подписки не запустилась"
    web_set SUB_DOMAIN "$sdomain"; web_set WEB_PORT 443
    web_apply || return 1
    list_add PUBLIC_TCP 443; ufw_allow 443 tcp "" "Subscription page"; fw_apply >/dev/null
    ok "Страница подписки: https://$sdomain"
    warn "В .env панели укажите SUB_PUBLIC_DOMAIN=$sdomain и перезапустите панель"
}

# ---------- нода ----------
# Спросить параметры транспорта. Результат в переменных T_*.
ask_transport_params() {   # [default_transport] [default_port] [default_domain]
    choose_transport "${1:-}"; T_TRANSPORT="$REPLY"
    local l4; l4=$(transport_l4 "$T_TRANSPORT")
    local defport="${2:-443}"
    if [[ -z "${2:-}" ]]; then
        [[ "$T_TRANSPORT" == hysteria2 ]] && defport=443 || defport=$(( 8443 + RANDOM % 1000 ))
    fi
    ask_port "Порт ($l4)" "$defport" "$l4"; T_PORT="$REPLY"
    T_TARGET=""; T_DOMAIN="${3:-}"; T_OBFS=""
    if transport_reality "$T_TRANSPORT"; then
        echo "  Reality отдаёт сканерам чужой «настоящий» сайт:"
        echo "   1. свой сайт-заглушка на домене ноды (selfsteal, рекомендуется)"
        echo "   2. чужой сайт (например www.microsoft.com:443) — домен не нужен"
        ask "Вариант" "1"
        if [[ "$REPLY" == 2 ]]; then
            ask "target (хост:порт)" "www.microsoft.com:443"; T_TARGET="$REPLY"
            [[ "$T_TARGET" == *:* ]] || T_TARGET="$T_TARGET:443"
        else
            ask_domain "Домен ноды (selfsteal)" "$T_DOMAIN"; T_DOMAIN="$REPLY"
        fi
    else
        ask_domain "Домен ноды (для TLS-сертификата)" "$T_DOMAIN"; T_DOMAIN="$REPLY"
    fi
    if [[ "$T_TRANSPORT" == hysteria2 ]] && confirm "Включить обфускацию Salamander (клиент тоже должен её поддерживать)?" n; then
        T_OBFS=$(rand_alnum 20)
    fi
}

write_node_compose() {   # dir node_port secret
    local d="$1"
    mkdir -p "$d/certs" /var/log/remnanode
    install -m 600 /dev/null "$d/.env"
    printf 'NODE_PORT=%s\nSECRET_KEY=%s\n' "$2" "$3" > "$d/.env"
    cat > "$d/docker-compose.yml" <<EOF
services:
  remnanode:
    image: remnawave/node:latest
    container_name: remnanode
    hostname: remnanode
    restart: always
    network_mode: host
    cap_add:
      - NET_ADMIN
    ulimits:
      nofile: { soft: 1048576, hard: 1048576 }
    env_file: .env
    volumes:
      - /dev/shm:/dev/shm:rw
      - /var/log/remnanode:/var/log/remnanode
      - ./certs:${XRAY_CERT_DIR}:ro
    logging:
      driver: json-file
      options: { max-size: 50m, max-file: "3" }
EOF
}

# ---------- несколько транспортов на одной ноде ----------
# Выбор пользователя: T_LIST (транспорты), T_PORTS[транспорт]=порт,
# T_DOMAIN, T_TARGET (чужой сайт для Reality), T_OBFS (Salamander).
# Запасные транспорты нужны на случай, если основной глушат (например, UDP
# для Hysteria 2): клиент переключится на другой хост в подписке.
NODE_TRANSPORT_SET=(tcp-reality hysteria2 grpc-reality xhttp-reality)

ask_transports() {   # [домен по умолчанию]
    local i=0 t
    echo "  Транспорты ноды — можно несколько (запасные, если основной глушат):"
    for t in "${TRANSPORTS[@]}"; do
        i=$((i + 1))
        printf '  %s%d.%s %-14s %s%-26s%s %s\n' "$C_YELLOW" "$i" "$C_RESET" "$t" "$C_GRAY" "$(transport_title "$t")" "$C_RESET" \
            "$(transport_default_port "$t")/$(transport_l4 "$t")"
    done
    printf '  %s%d.%s %sНабор: Reality 443/tcp + Hysteria2 443/udp + gRPC 8443 + XHTTP 4443%s\n' "$C_YELLOW" $((i + 1)) "$C_RESET" "$C_BOLD" "$C_RESET"
    local preset=$((i + 1)) sel n
    while true; do
        ask "Номера через пробел или запятую" "1"
        T_LIST=()
        for n in ${REPLY//,/ }; do
            if [[ "$n" == "$preset" ]]; then T_LIST+=("${NODE_TRANSPORT_SET[@]}")
            elif [[ "$n" =~ ^[0-9]+$ ]] && (( n >= 1 && n <= ${#TRANSPORTS[@]} )); then T_LIST+=("${TRANSPORTS[n - 1]}")
            elif transport_valid "$n"; then T_LIST+=("$n")
            else warn "Нет такого варианта: $n"; T_LIST=(); break; fi
        done
        # без повторов, порядок сохраняем
        local -A seen=(); sel=()
        for t in "${T_LIST[@]}"; do [[ -n "${seen[$t]:-}" ]] || { sel+=("$t"); seen[$t]=1; }; done
        T_LIST=("${sel[@]}")
        ((${#T_LIST[@]})) && break
    done

    # порты: свой у каждого транспорта, TCP/UDP не пересекаются внутри протокола
    declare -gA T_PORTS=(); local -A used=()
    for t in "${T_LIST[@]}"; do
        local l4; l4=$(transport_l4 "$t")
        while true; do
            ask_port "Порт для $(transport_label "$t") ($l4)" "$(transport_default_port "$t")" "$l4"
            [[ -n "${used[$REPLY/$l4]:-}" ]] && { warn "$REPLY/$l4 уже занят транспортом ${used[$REPLY/$l4]}"; continue; }
            break
        done
        T_PORTS[$t]="$REPLY"; used[$REPLY/$l4]="$t"
    done

    # домен и сайт для Reality — один на все транспорты
    T_DOMAIN="${1:-}"; T_TARGET=""; T_OBFS=""
    local need_domain=no has_reality=no
    for t in "${T_LIST[@]}"; do
        transport_tls "$t" && need_domain=yes
        transport_reality "$t" && has_reality=yes
    done
    if [[ "$has_reality" == yes ]]; then
        echo "  Reality отдаёт сканерам «настоящий» сайт:"
        echo "   1. свой сайт-заглушка на домене ноды (selfsteal, рекомендуется)"
        echo "   2. чужой сайт (например www.microsoft.com:443)"
        ask "Вариант" "1"
        if [[ "$REPLY" == 2 ]]; then
            ask "target (хост:порт)" "www.microsoft.com:443"; T_TARGET="$REPLY"
            [[ "$T_TARGET" == *:* ]] || T_TARGET="$T_TARGET:443"
        else
            need_domain=yes
        fi
    fi
    if [[ "$need_domain" == yes ]]; then ask_domain "Домен ноды (A-запись на её IP)" "$T_DOMAIN"; T_DOMAIN="$REPLY"; fi
    if [[ " ${T_LIST[*]} " == *" hysteria2 "* ]] && confirm "Hysteria 2: включить обфускацию Salamander (клиент тоже должен её поддерживать)?" n; then
        T_OBFS=$(rand_alnum 20)
    fi
    # совместимость со старым кодом: «основной» транспорт
    T_TRANSPORT="${T_LIST[0]}"; T_PORT="${T_PORTS[$T_TRANSPORT]}"
    echo
    for t in "${T_LIST[@]}"; do printf '  %s✔%s %-10s %s/%s\n' "$C_GREEN" "$C_RESET" "$(transport_label "$t")" "${T_PORTS[$t]}" "$(transport_l4 "$t")"; done
}

# разбор --transports tcp-reality:443,hysteria2:443 (и старых --transport/--port)
parse_transports_arg() {   # "t:p,t:p"
    local item t p
    T_LIST=(); declare -gA T_PORTS=()
    for item in ${1//,/ }; do
        t="${item%%:*}"; p="${item#*:}"; [[ "$item" == *:* ]] || p=$(transport_default_port "$t")
        transport_valid "$t" || die "Неизвестный транспорт: $t"
        is_port "$p" || die "Неверный порт для $t: $p"
        T_LIST+=("$t"); T_PORTS[$t]="$p"
    done
    ((${#T_LIST[@]})) || die "Не задан ни один транспорт"
    T_TRANSPORT="${T_LIST[0]}"; T_PORT="${T_PORTS[$T_TRANSPORT]}"
}
transports_arg() { local t out=(); for t in "${T_LIST[@]}"; do out+=("$t:${T_PORTS[$t]}"); done; local IFS=,; echo "${out[*]}"; }

# inbound'ы для всех выбранных транспортов; ключи Reality — общие
build_inbounds() {   # префикс_тега [priv] [sid]
    local prefix="$1" priv="${2:-}" sid="${3:-}" t arr="[]" inb dom
    if [[ -z "$priv" ]]; then priv=$(x25519_keys | cut -d' ' -f1); sid=$(rand_hex 8); fi
    for t in "${T_LIST[@]}"; do
        dom="$T_DOMAIN"
        # Reality с чужим сайтом: serverNames — домен этого сайта, а не наш
        transport_reality "$t" && [[ -n "$T_TARGET" ]] && dom=""
        inb=$(inbound_build "$t" "${prefix}_$(transport_label "$t" | tr '[:lower:]' '[:upper:]' | tr ' ' '_')" "${T_PORTS[$t]}" "$dom" "$T_TARGET" "" "$priv" "$sid" \
              "$([[ "$t" == hysteria2 ]] && echo "$T_OBFS")") || return 1
        arr=$(jq -c --argjson i "$inb" '. + [$i]' <<<"$arr")
    done
    echo "$arr"
}

# подготовить сервер ноды под все выбранные транспорты
node_prepare_all() {
    local t dom
    for t in "${T_LIST[@]}"; do
        dom="$T_DOMAIN"; transport_reality "$t" && [[ -n "$T_TARGET" ]] && dom=""
        node_prepare "$t" "${T_PORTS[$t]}" "$dom" "$T_TARGET" || return 1
    done
}

tag_prefix() { local n; n=$(tr -cd 'A-Za-z0-9_' <<<"${1// /_}" | tr '[:lower:]' '[:upper:]'); echo "${n:0:16}_$(rand_alnum 3 | tr '[:lower:]' '[:upper:]')"; }

# Нода уже стоит? compose без контейнера — это незавершённая установка,
# её можно продолжить (раньше после ошибки на сертификате ставить было нельзя).
node_install_state() {   # -> none | unfinished | installed
    if ! compose_has_service "$RW_NODE_DIR" remnanode && ! compose_has_service "$RW_PANEL_DIR" remnanode; then echo none; return; fi
    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx remnanode; then echo installed; else echo unfinished; fi
}

# Установка ноды на ЭТОМ сервере.
#   Автоматически — fail2detect сам создаёт в панели профиль (со всеми
#     транспортами), ноду, хосты и берёт SECRET_KEY через API.
#   Вручную — вы создаёте ноду в панели и вставляете SECRET_KEY.
# Неинтерактивно (команда из `fail2detect node add`):
#   fail2detect install node --panel-ip IP --secret KEY --transports t:p[,t:p…] [--domain D] [--target host:port]
install_node() {
    require_root; ensure_deps; ensure_dirs; require_docker; load_config
    local panel_ip="" secret="" napi=2222 targ="" mode=""
    T_DOMAIN=""; T_TARGET=""; T_OBFS=""; T_LIST=()
    local one_t="" one_p=""
    while (($#)); do
        case "$1" in
            --panel-ip) panel_ip="$2"; shift;; --secret) secret="$2"; shift;;
            --transports) targ="$2"; shift;; --transport) one_t="$2"; shift;; --port) one_p="$2"; shift;;
            --domain) T_DOMAIN="$2"; shift;; --target) T_TARGET="$2"; shift;;
            --obfs) T_OBFS="$2"; shift;; --node-port) napi="$2"; shift;;
            *) die "Неизвестный параметр: $1";;
        esac; shift
    done
    [[ -n "$one_t" ]] && targ="$one_t:${one_p:-$(transport_default_port "$one_t")}"

    case "$(node_install_state)" in
        installed)
            warn "Нода уже установлена ($(node_dir))."
            echo "  Сменить транспорт: fail2detect node transport · добавить запасной: fail2detect node add-transport"
            confirm "Переустановить ноду (удалить с резервной копией и поставить заново)?" n || return 1
            remove_node --reinstall || return 1
            load_config;;
        unfinished)
            warn "Найдена незавершённая установка ноды ($RW_NODE_DIR, контейнер не создан)."
            confirm "Начать установку заново (файлы ноды будут перезаписаны)?" y || return 1;;
    esac
    title "Установка ноды Remnawave"

    if [[ -n "$secret" ]]; then
        mode=manual
        [[ -n "$targ" ]] || die "Нужен --transports (например tcp-reality:443,hysteria2:443)"
        parse_transports_arg "$targ"
    else
        echo "  1. Автоматически — fail2detect сам создаст в панели профиль, ноду и хосты"
        echo "     и возьмёт SECRET_KEY (нужны адрес панели и API-токен)"
        echo "  2. Вручную — вы создаёте ноду в панели и вставляете SECRET_KEY"
        ask "Способ" "1"; [[ "$REPLY" == 2 ]] && mode=manual || mode=auto
    fi

    if [[ "$mode" == auto ]]; then
        rw_need_api || { warn "Без доступа к панели — переходим к ручной установке"; mode=manual; }
    fi

    if [[ "$mode" == auto ]]; then
        local me name cc ph
        me=$(public_ip)
        ask "Имя ноды в панели" "$(hostname -s)"; name="$REPLY"
        cc=$(curl -sS --max-time 6 "https://ipinfo.io/widget/demo/$me" 2>/dev/null | jq -r '.data.country // empty' 2>/dev/null)
        ask "Код страны (2 буквы)" "${cc:-XX}"; cc="${REPLY^^}"
        ask "Адрес ноды для панели (IP или домен)" "$me"; local addr="$REPLY"
        ask_transports
        ph=$(sed -E 's#^https?://([^/:]+).*#\1#' <<<"$RW_API_URL")
        panel_ip=$(getent ahostsv4 "$ph" 2>/dev/null | awk 'NR==1{print $1}')
        [[ "$ph" == 127.0.0.1 ]] && panel_ip=127.0.0.1
        info "С какого IP панель подключается к ноде? (домен за Cloudflare даст не тот адрес)"
        while true; do ask "IP сервера панели" "$panel_ip"; is_ip "$REPLY" && break; done; panel_ip="$REPLY"
        node_add_api "$name" "$addr" "$cc" "${T_DOMAIN:-$addr}" || return 1
        secret="$NODE_SECRET"
    elif [[ -z "$secret" ]]; then
        if [[ -z "$panel_ip" ]] && ! has_panel; then
            while true; do ask "IP сервера панели"; is_ip "$REPLY" && break; done; panel_ip="$REPLY"
        fi
        info "SECRET_KEY: Панель → Ноды → Создать ноду → скопировать SECRET_KEY"
        read_secret "SECRET_KEY ноды (вставьте)"; secret="$REPLY"
        [[ -n "$secret" ]] || die "Нужен SECRET_KEY"
        ask_transports
    fi

    write_node_compose "$RW_NODE_DIR" "$napi" "$secret"
    [[ -n "$panel_ip" ]] && config_set PANEL_IPS "$panel_ip"
    config_set NODE_API_PORT "$napi"
    [[ -n "$panel_ip" ]] && ufw_allow "$napi" tcp "$panel_ip" "Remnawave panel"

    node_prepare_all || return 1
    (cd "$RW_NODE_DIR" && docker compose up -d >/dev/null 2>&1) || die "Нода не запустилась: cd $RW_NODE_DIR && docker compose logs"
    ok "Контейнер ноды запущен (API ноды $napi — только для ${panel_ip:-панели})"
    audit_write INSTALL - - - "нода ($mode) $(transports_arg) ${T_DOMAIN:-$T_TARGET}"

    if [[ "$mode" == auto && -n "${NODE_UUID:-}" ]]; then
        info "Жду, пока панель подключится к ноде и пришлёт конфиг…"
        local i st=""
        for i in $(seq 1 30); do
            st=$(rw_api GET "/api/nodes/$NODE_UUID" | jq -r '.response.isConnected // empty' 2>/dev/null)
            [[ "$st" == true ]] && break; sleep 3
        done
        [[ "$st" == true ]] && ok "Панель видит ноду: подключена" || warn "Панель пока не подключилась к ноде — проверьте IP панели ($panel_ip) и фаервол"
    fi
    local t
    for t in "${T_LIST[@]}"; do
        if node_wait_port "${T_PORTS[$t]}" "$(transport_l4 "$t")"; then ok "$(transport_label "$t"): слушает ${T_PORTS[$t]}/$(transport_l4 "$t")"
        else warn "$(transport_label "$t"): ${T_PORTS[$t]}/$(transport_l4 "$t") пока не слушается (Xray поднимется, когда панель пришлёт конфиг)"; fi
    done
    if [[ "$mode" == manual ]]; then
        echo
        info "Создайте в панели профиль с этими inbound'ами (или используйте автоматический режим):"
        for t in "${T_LIST[@]}"; do echo "    fail2detect node inbound-json $t ${T_PORTS[$t]} ${T_DOMAIN:-\"\"} ${T_TARGET}"; done
    fi
    [[ "$mode" == auto && -n "${NODE_UUID:-}" ]] && balancer_offer "$name"
    echo
    confirm "Настроить защиту fail2detect сейчас?" y && setup_wizard
}

# ---------- добавление ноды в панель (на сервере панели) ----------
# Профиль со всеми транспортами + нода + хосты + squad. Печатает команду для ноды.
node_add() {   # [address]
    require_root; load_config; rw_need_api || return 1
    title "Новая нода в панели"
    ask "Имя ноды" "node-$(rand_alnum 4 | tr '[:upper:]' '[:lower:]')"; local name="$REPLY"
    ask "Адрес ноды (IP или домен, к нему подключается панель)" "${1:-}"; local addr="$REPLY"
    ask "Код страны (2 буквы)" "XX"; local cc="${REPLY^^}"
    ASK_PORT_NOCHECK=1 ask_transports
    node_add_api "$name" "$addr" "$cc" "${T_DOMAIN:-$addr}" || return 1
    title "Дальше — на сервере ноды"
    echo "  bash <(curl -fsSL https://raw.githubusercontent.com/${F2D_REPO}/main/install.sh)"
    printf '  fail2detect install node --panel-ip %s --secret %q --transports %s' "$(public_ip)" "$NODE_SECRET" "$(transports_arg)"
    [[ -n "$T_DOMAIN" ]] && printf ' --domain %s' "$T_DOMAIN"
    [[ -n "$T_TARGET" ]] && printf ' --target %s' "$T_TARGET"
    [[ -n "$T_OBFS" ]] && printf ' --obfs %s' "$T_OBFS"
    echo
    balancer_offer "$name"
}

# нода на сервере панели (вызывается из install_panel)
node_add_local() {
    info "Нода на этом же сервере"
    ask_transports
    local gw; gw=$(docker network inspect remnawave-network -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null)
    [[ -n "$gw" ]] || gw="172.17.0.1"
    node_add_api "local" "$gw" "XX" "${T_DOMAIN:-$(public_ip)}" || return 1
    # если Xray занял порт nginx (443/tcp), nginx уходит на unix-сокет (панель — через Reality)
    local t
    for t in "${T_LIST[@]}"; do
        [[ "$(transport_l4 "$t")" == tcp && "${T_PORTS[$t]}" == "$WEB_PORT" ]] || continue
        if [[ "$t" == tcp-reality && -z "$T_TARGET" ]]; then
            web_set WEB_PORT ""; info "Панель будет доступна через Reality-порт ${T_PORTS[$t]} (selfsteal)"
        else
            web_set WEB_PORT 8443; warn "${T_PORTS[$t]} занят Xray — панель переезжает на 8443"
        fi
    done
    write_node_compose "$RW_NODE_DIR" 2222 "$NODE_SECRET"
    config_set NODE_API_PORT 2222
    [[ -n "$T_DOMAIN" ]] && { cert_ensure "$T_DOMAIN" || return 1; }
    [[ " ${T_LIST[*]} " == *-reality* && -z "$T_TARGET" ]] && web_set SELFSTEAL_DOMAIN "$T_DOMAIN"
    web_load; web_apply || return 1
    node_prepare_all || return 1
    (cd "$RW_NODE_DIR" && docker compose up -d >/dev/null 2>&1) && ok "Нода запущена"
}

# общая часть: профиль (все транспорты), нода, хосты, squad. Выставляет NODE_SECRET, NODE_UUID.
node_add_api() {   # name address country host_address
    local name="$1" addr="$2" cc="$3" haddr="$4" inbs cfg r puuid nuuid prefix
    prefix=$(tag_prefix "$name")
    inbs=$(build_inbounds "$prefix") || return 1
    cfg=$(profile_config "$inbs")
    r=$(rw_api POST /api/config-profiles "$(jq -n --arg n "f2d-${name:0:20}" --argjson c "$cfg" '{name:$n, config:$c}')")
    puuid=$(jq -r '.response.uuid // empty' <<<"$r")
    [[ -n "$puuid" ]] || { err "Профиль не создан: $(jq -c '.message // .' <<<"$r" 2>/dev/null)"; return 1; }
    local -A uuid_of=(); local tag u
    while IFS=$'\t' read -r tag u; do uuid_of[$tag]="$u"; done < <(jq -r '.response.inbounds[] | [.tag, .uuid] | @tsv' <<<"$r")
    local all; all=$(jq -c '[.response.inbounds[].uuid]' <<<"$r")
    ok "Профиль f2d-$name: $(for t in "${T_LIST[@]}"; do printf '%s %s/%s  ' "$(transport_label "$t")" "${T_PORTS[$t]}" "$(transport_l4 "$t")"; done)"

    r=$(rw_api POST /api/nodes "$(jq -n --arg n "$name" --arg a "$addr" --arg cc "$cc" --arg p "$puuid" --argjson i "$all" \
        '{name:$n, address:$a, port:2222, countryCode:$cc, isTrafficTrackingActive:false, configProfile:{activeConfigProfileUuid:$p, activeInbounds:$i}}')")
    NODE_UUID=$(jq -r '.response.uuid // empty' <<<"$r")
    [[ -n "$NODE_UUID" ]] || { err "Нода не создана: $(jq -c '.message // .' <<<"$r" 2>/dev/null)"; return 1; }
    ok "Нода $name ($addr)"

    # хост на каждый транспорт: «Имя · Reality», «Имя · Hysteria2», …
    local inb hf label
    while read -r inb; do
        tag=$(jq -r .tag <<<"$inb"); u="${uuid_of[$tag]:-}"
        [[ -n "$u" ]] || continue
        label=$(transport_label "$(transport_of_inbound <<<"$inb")")
        hf=$(host_fields "$inb" "$haddr")
        r=$(rw_api POST /api/hosts "$(jq -n --argjson h "$hf" --arg p "$puuid" --arg i "$u" --arg rem "$name · $label" \
            '$h + {remark:$rem, inbound:{configProfileUuid:$p, configProfileInboundUuid:$i}} | with_entries(select(.value != null))')")
        if jq -e '.response.uuid' >/dev/null <<<"$r"; then ok "Хост «$name · ${label}»"; else warn "Хост «$name · ${label}» не создан: $(jq -c '.message // .' <<<"$r" 2>/dev/null)"; fi
        squad_add_inbound "$u" >/dev/null
    done < <(jq -c '.[]' <<<"$inbs")
    ok "Inbound'ы добавлены в squad (пользователи их получат)"
    NODE_SECRET=$(rw_api GET /api/keygen | jq -r '.response.secretKey // .response.pubKey // empty')
    [[ -n "$NODE_SECRET" ]] || { err "Не удалось получить SECRET_KEY ноды"; return 1; }
    audit_write NODE_ADD - "$prefix" - "$name $addr $(transports_arg)"
}

squad_add_inbound() {   # inbound_uuid [old_uuid]
    local new="$1" old="${2:-}" sq u cur
    sq=$(rw_api GET /api/internal-squads | jq -c '.response.internalSquads // []')
    [[ "$(jq length <<<"$sq")" -gt 0 ]] || { warn "Нет internal squad — добавьте inbound в squad вручную"; return 0; }
    while read -r u; do
        cur=$(jq -c --arg u "$u" '.[] | select(.uuid == $u) | [.inbounds[]? | (.uuid // .)]' <<<"$sq")
        # при замене inbound'а — только в те squad'ы, где был старый; новый — в первый
        if [[ -n "$old" ]]; then jq -e --arg o "$old" 'index($o)' <<<"$cur" >/dev/null || continue; fi
        cur=$(jq -c --arg n "$new" --arg o "$old" 'map(select(. != $o)) + [$n] | unique' <<<"$cur")
        rw_api PATCH /api/internal-squads "$(jq -n --arg u "$u" --argjson i "$cur" '{uuid:$u, inbounds:$i}')" >/dev/null
        [[ -z "$old" ]] && break
    done < <(jq -r '.[].uuid' <<<"$sq")
    ok "Inbound добавлен в squad (пользователи его получат)"
}

# JSON inbound'а для ручной вставки в профиль (нода, созданная вручную или другим установщиком)
node_inbound_json() {   # transport port [domain] [target]
    transport_valid "${1:-}" || die "fail2detect node inbound-json <транспорт> <порт> [домен] [target]"
    local keys priv pub; keys=$(x25519_keys); priv="${keys% *}"; pub="${keys#* }"
    inbound_build "$1" "$(echo "$1" | tr '[:lower:]' '[:upper:]' | tr '-' '_')" "$2" "${3:-}" "${4:-}" "" "$priv"
    transport_reality "$1" && info "publicKey для клиентов (Remnawave посчитает сам): $pub" >&2
}

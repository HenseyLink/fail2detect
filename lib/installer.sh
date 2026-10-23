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
    has_panel && die "Панель уже установлена в $RW_PANEL_DIR"
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
    local dbpass; dbpass=$(rand_alnum 32)
    sed -i \
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
    panel_bootstrap || return 1

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

# Нода на сервере ноды. Профиль/хост в панели создаёт `fail2detect node add`
# на сервере панели (он же печатает готовую команду для этого шага).
#   fail2detect install node [--panel-ip IP] [--secret KEY] [--transport T]
#        [--port P] [--domain D] [--target host:port] [--node-port 2222]
install_node() {
    require_root; ensure_deps; ensure_dirs; require_docker; load_config
    local panel_ip="" secret="" napi=2222
    T_TRANSPORT=""; T_PORT=""; T_DOMAIN=""; T_TARGET=""
    while (($#)); do
        case "$1" in
            --panel-ip) panel_ip="$2"; shift;; --secret) secret="$2"; shift;;
            --transport) T_TRANSPORT="$2"; shift;; --port) T_PORT="$2"; shift;;
            --domain) T_DOMAIN="$2"; shift;; --target) T_TARGET="$2"; shift;;
            --node-port) napi="$2"; shift;;
            *) die "Неизвестный параметр: $1";;
        esac; shift
    done
    { compose_has_service "$RW_NODE_DIR" remnanode || compose_has_service "$RW_PANEL_DIR" remnanode; } \
        && die "Нода уже установлена. Сменить порт/транспорт: fail2detect node transport"
    title "Установка ноды Remnawave"
    if [[ -z "$panel_ip" ]] && ! has_panel; then
        while true; do ask "IP панели"; is_ip "$REPLY" && break; done; panel_ip="$REPLY"
    fi
    if [[ -z "$secret" ]]; then
        info "SECRET_KEY: Панель → Ноды → Добавить ноду → скопировать, или вывод \`fail2detect node add\`"
        read -r -p "SECRET_KEY: " secret
    fi
    [[ -n "$secret" ]] || die "Нужен SECRET_KEY"
    if [[ -z "$T_TRANSPORT" ]]; then
        ask_transport_params
    else
        transport_valid "$T_TRANSPORT" || die "Неизвестный транспорт: $T_TRANSPORT"
        is_port "${T_PORT:-}" || die "Нужен --port"
    fi

    write_node_compose "$RW_NODE_DIR" "$napi" "$secret"
    [[ -n "$panel_ip" ]] && config_set PANEL_IPS "$panel_ip"
    config_set NODE_API_PORT "$napi"
    [[ -n "$panel_ip" ]] && ufw_allow "$napi" tcp "$panel_ip" "Remnawave panel"

    node_prepare "$T_TRANSPORT" "$T_PORT" "$T_DOMAIN" "$T_TARGET" || return 1
    (cd "$RW_NODE_DIR" && docker compose up -d >/dev/null 2>&1) || die "Нода не запустилась"
    ok "Нода запущена (API на $napi только для ${panel_ip:-панели})"
    audit_write INSTALL - - - "нода $T_TRANSPORT $T_PORT ${T_DOMAIN:-$T_TARGET}"
    if [[ -n "$panel_ip" ]] && ! ss -H -tln "( sport = :$T_PORT )" | grep -q . && [[ "$(transport_l4 "$T_TRANSPORT")" == tcp ]]; then
        info "Xray поднимется, когда панель пришлёт конфиг (нода → «Подключена» в панели)."
    fi
    echo
    info "Если ноду в панели вы создавали вручную, вставьте в её профиль inbound:"
    echo "    fail2detect node inbound-json $T_TRANSPORT $T_PORT ${T_DOMAIN:-\"\"} ${T_TARGET}"
    echo
    confirm "Настроить защиту fail2detect сейчас?" y && setup_wizard
}

# ---------- добавление ноды в панель (на сервере панели) ----------
# Профиль конфигурации + нода + хост + inbound в squad. Печатает команду для ноды.
node_add() {   # [address]
    require_root; load_config; rw_need_api || return 1
    title "Новая нода в панели"
    ask "Имя ноды" "node-$(rand_alnum 4 | tr '[:upper:]' '[:lower:]')"; local name="$REPLY"
    ask "Адрес ноды (IP или домен, к нему подключается панель)" "${1:-}"; local addr="$REPLY"
    ask "Код страны (2 буквы)" "XX"; local cc="${REPLY^^}"
    ASK_PORT_NOCHECK=1 ask_transport_params
    node_add_api "$name" "$addr" "$cc" "${T_DOMAIN:-$addr}" || return 1
    title "Дальше — на сервере ноды"
    echo "  bash <(curl -fsSL https://raw.githubusercontent.com/${F2D_REPO}/main/install.sh)"
    printf '  fail2detect install node --panel-ip %s --secret %q --transport %s --port %s' \
        "$(public_ip)" "$NODE_SECRET" "$T_TRANSPORT" "$T_PORT"
    [[ -n "$T_DOMAIN" ]] && printf ' --domain %s' "$T_DOMAIN"
    [[ -n "$T_TARGET" ]] && printf ' --target %s' "$T_TARGET"
    echo
}

# нода на сервере панели (вызывается из install_panel)
node_add_local() {
    info "Нода на этом же сервере"
    ask_transport_params
    local gw; gw=$(docker network inspect remnawave-network -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null)
    [[ -n "$gw" ]] || gw="172.17.0.1"
    node_add_api "local" "$gw" "XX" "${T_DOMAIN:-$(public_ip)}" || return 1
    # если Xray занял 443/tcp, nginx уходит только на unix-сокет (панель — через Reality)
    if [[ "$(transport_l4 "$T_TRANSPORT")" == tcp && "$T_PORT" == "$WEB_PORT" ]]; then
        if transport_reality "$T_TRANSPORT" && [[ -z "$T_TARGET" ]]; then
            web_set WEB_PORT ""; info "Панель будет доступна через Reality-порт $T_PORT (selfsteal)"
        else
            web_set WEB_PORT 8443; warn "443 занят Xray — панель переезжает на 8443"
        fi
    fi
    write_node_compose "$RW_NODE_DIR" 2222 "$NODE_SECRET"
    config_set NODE_API_PORT 2222
    [[ -n "$T_DOMAIN" ]] && { cert_ensure "$T_DOMAIN" || return 1; }
    if transport_reality "$T_TRANSPORT" && [[ -z "$T_TARGET" ]]; then web_set SELFSTEAL_DOMAIN "$T_DOMAIN"; fi
    web_load; web_apply || return 1
    node_prepare "$T_TRANSPORT" "$T_PORT" "$T_DOMAIN" "$T_TARGET" || return 1
    (cd "$RW_NODE_DIR" && docker compose up -d >/dev/null 2>&1) && ok "Нода запущена"
}

# общая часть: профиль, нода, хост, squad. Выставляет NODE_SECRET.
node_add_api() {   # name address country host_address
    local name="$1" addr="$2" cc="$3" haddr="$4" tag inb cfg r puuid iuuid nuuid
    tag="$(echo "${T_TRANSPORT}" | tr '[:lower:]' '[:upper:]' | tr '-' '_')_$(rand_alnum 4 | tr '[:lower:]' '[:upper:]')"
    inb=$(inbound_build "$T_TRANSPORT" "$tag" "$T_PORT" "$T_DOMAIN" "$T_TARGET" "" "" "" "$T_OBFS") || return 1
    cfg=$(profile_config "$inb")
    r=$(rw_api POST /api/config-profiles "$(jq -n --arg n "f2d-${name:0:20}" --argjson c "$cfg" '{name:$n, config:$c}')")
    puuid=$(jq -r '.response.uuid // empty' <<<"$r"); iuuid=$(jq -r '.response.inbounds[0].uuid // empty' <<<"$r")
    [[ -n "$puuid" && -n "$iuuid" ]] || { err "Профиль не создан: $(jq -c '.message // .' <<<"$r" 2>/dev/null)"; return 1; }
    ok "Профиль f2d-$name ($(transport_title "$T_TRANSPORT"), порт $T_PORT)"

    r=$(rw_api POST /api/nodes "$(jq -n --arg n "$name" --arg a "$addr" --arg cc "$cc" --arg p "$puuid" --arg i "$iuuid" \
        '{name:$n, address:$a, port:2222, countryCode:$cc, isTrafficTrackingActive:false, configProfile:{activeConfigProfileUuid:$p, activeInbounds:[$i]}}')")
    nuuid=$(jq -r '.response.uuid // empty' <<<"$r")
    [[ -n "$nuuid" ]] || { err "Нода не создана: $(jq -c '.message // .' <<<"$r" 2>/dev/null)"; return 1; }
    ok "Нода $name ($addr)"

    local hf; hf=$(host_fields "$inb" "$haddr")
    r=$(rw_api POST /api/hosts "$(jq -n --argjson h "$hf" --arg p "$puuid" --arg i "$iuuid" --arg rem "$name" \
        '$h + {remark:$rem, inbound:{configProfileUuid:$p, configProfileInboundUuid:$i}} | with_entries(select(.value != null))')")
    jq -e '.response.uuid' >/dev/null <<<"$r" && ok "Хост для подписки" || warn "Хост не создан: $(jq -c '.message // .' <<<"$r" 2>/dev/null)"

    squad_add_inbound "$iuuid"
    NODE_SECRET=$(rw_api GET /api/keygen | jq -r '.response.secretKey // .response.pubKey // empty')
    [[ -n "$NODE_SECRET" ]] || { err "Не удалось получить SECRET_KEY ноды"; return 1; }
    audit_write NODE_ADD - "$tag" - "$name $addr $T_TRANSPORT:$T_PORT"
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

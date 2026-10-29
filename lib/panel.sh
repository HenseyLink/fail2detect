#!/usr/bin/env bash
# fail2detect — доступ к панели: ссылка входа, учётные данные, проверка «почему не открывается».

panel_domain() { _bk_env_get "$RW_PANEL_DIR/.env" PANEL_DOMAIN 2>/dev/null; }

# ссылка входа с секретным ключом: наш nginx (web.env) или nginx/Caddy установщика remnawave-reverse-proxy
panel_login_link() {
    local u; u=$(panel_login_url 2>/dev/null) && [[ -n "$u" ]] && { echo "$u"; return 0; }
    local dom kv="" f; dom=$(panel_domain); [[ -n "$dom" ]] || return 1
    for f in "$RW_PANEL_DIR/nginx.conf" "$RW_PANEL_DIR"/nginx/*.conf; do
        [[ -f "$f" ]] || continue
        kv=$(grep -oE '"~\*[A-Za-z0-9_]+=[A-Za-z0-9_]+"' "$f" | head -1 | tr -d '"~*')
        [[ -n "$kv" ]] && break
    done
    if [[ -z "$kv" ]]; then
        for f in "$RW_PANEL_DIR/Caddyfile" "$RW_PANEL_DIR"/caddy/Caddyfile; do
            [[ -f "$f" ]] || continue
            kv=$(grep -oE '^[[:space:]]*query[[:space:]]+[A-Za-z0-9_]+=[A-Za-z0-9_]+' "$f" | head -1 | awk '{print $2}')
            [[ -n "$kv" ]] && break
        done
    fi
    if [[ -n "$kv" ]]; then echo "https://$dom/auth/login?$kv"; else echo "https://$dom/"; fi
}

# что показать после установки/восстановления/переноса
panel_access_info() {   # [restored]
    local link; link=$(panel_login_link) || return 0
    title "Вход в панель"
    echo "  Ссылка: ${C_BOLD}$link${C_RESET}"
    [[ "$link" != *auth/login\?* ]] && echo "  ${C_GRAY}(секретного ключа в конфиге не нашлось — панель открывается без него)${C_RESET}"
    if [[ -s "$F2D_CONF_DIR/panel-admin.txt" ]]; then
        local l p
        l=$(_bk_env_get "$F2D_CONF_DIR/panel-admin.txt" login); p=$(_bk_env_get "$F2D_CONF_DIR/panel-admin.txt" password)
        echo "  Логин:  $l"
        echo "  Пароль: $p"
    else
        echo "  Логин и пароль: ${C_BOLD}прежние${C_RESET} — те же, что были на старой панели"
    fi
    [[ "${1:-}" == restored ]] && echo "  ${C_GRAY}При переносе логин, пароль и ключ ссылки не меняются: они лежат в базе и конфиге панели.${C_RESET}"
    return 0
}

# шлюз docker-сети, в которой работает контейнер панели (с него панель ходит к ноде на этом же сервере)
panel_docker_gateway() {
    docker inspect remnawave -f '{{range $k, $v := .NetworkSettings.Networks}}{{$v.Gateway}} {{$v.IPAddress}}{{"\n"}}{{end}}' 2>/dev/null | awk 'NF {print $1; exit}'
}

_is_private_ip() { [[ "$1" =~ ^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.) ]]; }

# Нода на этом же сервере записана в панели адресом шлюза docker-сети. После переноса
# шлюз может быть другим, а правила UFW «сеть docker → API ноды» не переезжают —
# панель не достучится до ноды, Xray не получит конфиг, и 443 (Reality) не поднимется.
panel_fix_local_node() {
    has_node || return 0
    local gw sub napi nodes u name addr port fixed=0
    gw=$(panel_docker_gateway); [[ -n "$gw" ]] || return 0
    napi="${NODE_API_PORT:-$(detect_node_api_port)}"
    sub=$(docker inspect remnawave -f '{{range $k, $v := .NetworkSettings.Networks}}{{$v.IPAddress}}/{{$v.IPPrefixLen}}{{"\n"}}{{end}}' 2>/dev/null | awk 'NF {print; exit}')
    # API ноды — из docker-сети панели
    if ufw_active && [[ -n "$sub" ]]; then
        local net; net=$(docker network inspect "$(docker inspect remnawave -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' 2>/dev/null)" -f '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null)
        [[ -n "$net" ]] && ufw_allow "$napi" tcp "$net" "Remnawave panel (docker)" && ok "UFW: API ноды ($napi) открыт для docker-сети панели $net"
    fi
    nodes=$(F2D_NO_PROMPT=1 rw_api GET /api/nodes 2>/dev/null | jq -r '.response[]? | [.uuid, .name, .address, (.port // 0 | tostring)] | @tsv' 2>/dev/null) || return 0
    while IFS=$'\t' read -r u name addr port; do
        [[ -n "$u" ]] || continue
        _is_private_ip "$addr" || continue
        [[ "$port" == "$napi" || "$port" == 0 ]] || continue
        if [[ "$addr" != "$gw" ]]; then
            local r; r=$(rw_api PATCH /api/nodes "$(jq -nc --arg u "$u" --arg a "$gw" '{uuid: $u, address: $a}')" 2>/dev/null)
            if jq -e '.response.uuid' >/dev/null 2>&1 <<<"$r"; then ok "Нода «${name}»: адрес $addr → $gw (шлюз docker на этом сервере)"; fixed=1
            else warn "Нода «${name}»: адрес $addr не обновлён ($(jq -c '.message // .' <<<"$r" 2>/dev/null))"; fi
        fi
        # дождаться, пока панель подключится и раздаст конфиг
        local i st=""
        for i in $(seq 1 20); do
            st=$(rw_api GET "/api/nodes/$u" 2>/dev/null | jq -r '.response.isConnected // empty' 2>/dev/null)
            [[ "$st" == true ]] && break; sleep 3
        done
        [[ "$st" == true ]] && ok "Нода «${name}» подключена к панели" || warn "Нода «${name}» пока не подключена — fail2detect panel check"
    done <<<"$nodes"
    return 0
}

# ---------- «почему панель не открывается» ----------
panel_check() {
    require_root
    has_panel || { err "Панели на этом сервере нет (fail2detect detect)"; return 1; }
    local dom bad=0; dom=$(panel_domain)
    title "Проверка панели${dom:+ $dom}"
    # 1) контейнеры
    local ct; ct=$(cd "$RW_PANEL_DIR" && docker compose ps -a --format '{{.Name}}\t{{.State}}' 2>/dev/null)
    if [[ -n "$ct" ]]; then
        local n s
        while IFS=$'\t' read -r n s; do
            if [[ "$s" == running ]]; then ok "Контейнер $n работает"
            else err "Контейнер $n: $s (cd $RW_PANEL_DIR && docker compose logs $n)"; bad=1; fi
        done <<<"$ct"
    else
        err "Контейнеры панели не запущены (cd $RW_PANEL_DIR && docker compose up -d)"; bad=1
    fi
    # 2) API
    if curl -fsS --max-time 4 -o /dev/null http://127.0.0.1:3000/api/auth/status -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Forwarded-Proto: https' 2>/dev/null; then
        ok "API панели отвечает (127.0.0.1:3000)"
    else
        err "API панели не отвечает на 127.0.0.1:3000 (docker compose logs -f remnawave)"; bad=1
    fi
    # 3) кто слушает 443
    local who; who=$(ss -H -tlnp '( sport = :443 )' 2>/dev/null | grep -o 'users:(("[^"]*' | cut -d'"' -f2 | sort -u | paste -sd, -)
    if [[ -z "$who" ]]; then
        err "Порт 443 никто не слушает"
        if has_node; then
            echo "    Панель открывается через Reality ноды на этом сервере, а нода ещё не получила конфиг от панели."
            echo "    Исправить: fail2detect panel fix   (адрес ноды и доступ панели к её API)"
        fi
        bad=1
    else
        ok "443 слушает: $who"
    fi
    # 4) DNS
    if [[ -n "$dom" ]]; then
        local me ips
        me=$(curl -fsS4 --max-time 5 https://api.ipify.org 2>/dev/null)
        ips=$(curl -fsS --max-time 5 -H 'accept: application/dns-json' "https://1.1.1.1/dns-query?name=$dom&type=A" 2>/dev/null | jq -r '.Answer[]? | select(.type == 1) | .data' 2>/dev/null | paste -sd' ' -)
        if [[ -z "$ips" ]]; then warn "DNS: у $dom нет A-записи"; bad=1
        elif [[ -n "$me" && " $ips " != *" $me "* ]]; then
            if [[ " $ips " == *" 104."* || " $ips " == *" 172.6"* || " $ips " == *" 188.114."* ]]; then
                info "DNS: $dom → $ips (похоже на Cloudflare-прокси — проверьте, что в Cloudflare указан $me)"
            else
                err "DNS: $dom → $ips, а этот сервер — $me. Переключите A-запись на $me"; bad=1
            fi
        else
            ok "DNS: $dom → $me"
        fi
    fi
    # 5) сама страница входа, как её откроет браузер (через этот сервер)
    if [[ -n "$dom" && -n "$who" ]]; then
        local link code; link=$(panel_login_link)
        code=$(curl -s -o /dev/null --max-time 8 --resolve "$dom:443:127.0.0.1" -w '%{http_code}' "$link" 2>/dev/null); local rc=$?
        case "$code" in
            200|301|302|307|308) ok "Страница входа отвечает ($code) — $link";;
            000) if ((rc == 60)); then err "Сертификат не подходит к $dom (fail2detect cert list)"; else err "Страница входа не отвечает (TLS/соединение, код curl $rc)"; fi; bad=1;;
            *) warn "Страница входа ответила $code";;
        esac
    fi
    # 6) нода на этом сервере
    if has_node; then
        local st; st=$(F2D_NO_PROMPT=1 rw_api GET /api/nodes 2>/dev/null | jq -r --arg gw "$(panel_docker_gateway)" '.response[]? | select(.address == $gw or (.address | test("^(127\\.|10\\.|172\\.|192\\.168\\.)"))) | "\(.name)\t\(.address)\t\(.isConnected)"' 2>/dev/null)
        if [[ -n "$st" ]]; then
            local n a c
            while IFS=$'\t' read -r n a c; do
                [[ "$c" == true ]] && ok "Нода «${n}» ($a) подключена" || { err "Нода «${n}» ($a) не подключена к панели — fail2detect panel fix"; bad=1; }
            done <<<"$st"
        fi
    fi
    echo
    ((bad == 0)) && ok "Панель в порядке" || warn "Есть проблемы — см. выше"
    ((bad == 0))
}

panel_fix() {
    require_root
    load_config; config_set RW_API_URL "http://127.0.0.1:3000" >/dev/null
    panel_fix_local_node
    panel_check
}

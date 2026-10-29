#!/usr/bin/env bash
# fail2detect — работа с Remnawave: API, смена порта/транспорта ноды, логи Xray.
#
# Почему нода от популярных установщиков «не встаёт» на 8443: они жёстко прописывают 443
# в трёх местах — правило UFW, inbound в профиле конфигурации и порт хоста
# (то, что уходит клиентам в подписку), а в конце проверяет ноду запросом
# на https://домен (то есть на 443). Если поменять порт только в одном месте,
# проверка падает и установка обрывается. Правильный путь — поставить ноду
# на 443, а потом согласованно перенести порт: профиль + хосты + фаервол.

RW_TOKEN_FILE="${F2D_CONF_DIR}/api_token"

# В RW_API_URL часто вставляют ссылку входа в панель целиком:
#   https://panel.example.com/auth/login?abcd=EFGH
# Нужен только адрес (https://panel.example.com), а ?abcd=EFGH — это cookie.
# Печатает "url<TAB>cookie" (cookie пустой, если его в ссылке не было).
rw_parse_url() {
    local u="${1%/}" base q cookie=""
    base=$(sed -E 's#^(https?://[^/?]+).*#\1#' <<<"$u")
    [[ "$u" == *\?* ]] && q="${u#*\?}" && [[ "$q" =~ ^([A-Za-z0-9_-]+)=([A-Za-z0-9_-]+)$ ]] && cookie="$q"
    printf '%s\t%s\n' "$base" "$cookie"
}

# привести RW_API_URL/RW_API_COOKIE в порядок (и сохранить, если поменялись)
rw_normalize_url() {
    [[ -n "${RW_API_URL:-}" ]] || return 0
    local base cookie; IFS=$'\t' read -r base cookie < <(rw_parse_url "$RW_API_URL")
    if [[ "$base" != "$RW_API_URL" ]]; then
        [[ -w "$F2D_CONF" ]] && config_set RW_API_URL "$base" || RW_API_URL="$base"
        [[ -n "$cookie" && -z "${RW_API_COOKIE:-}" ]] && { [[ -w "$F2D_CONF" ]] && config_set RW_API_COOKIE "$cookie" || RW_API_COOKIE="$cookie"; }
        info "RW_API_URL исправлен на $base${cookie:+ (ключ входа сохранён как RW_API_COOKIE)}" >&2
    fi
}

rw_token() {
    [[ -n "${_RW_TOKEN:-}" ]] && { echo "$_RW_TOKEN"; return; }
    local t="$RW_API_TOKEN"
    [[ -z "$t" && -s "$RW_TOKEN_FILE" ]] && t=$(<"$RW_TOKEN_FILE")
    [[ -z "$t" && -s "$RP_DIR/token" ]] && t=$(<"$RP_DIR/token")
    # без терминала (или в doctor) не спрашиваем — иначе «зависание» на скрытом вопросе
    if [[ -z "$t" && ( -n "${F2D_NO_PROMPT:-}" || ! -t 0 ) ]]; then return 1; fi
    if [[ -z "$t" ]]; then
        warn "Нужен API-токен панели (Панель → Настройки → API токены)."
        read_secret "Вставьте API-токен панели"; t="$REPLY"
        [[ -n "$t" ]] || return 1
        install -m 600 /dev/null "$RW_TOKEN_FILE"; printf '%s' "$t" > "$RW_TOKEN_FILE"
    fi
    _RW_TOKEN="$t"; echo "$t"
}

# rw_api METHOD /api/path [json] — тело ответа в stdout
# тело PATCH /api/config-profiles: конфиг читается из stdin — с правилами RIPE он
# больше 128 КБ и не помещается в аргумент jq (Linux: «Argument list too long»)
rw_profile_body() { jq -c --arg u "$1" '{uuid: $u, config: .}'; }

rw_api() {
    local method="$1" path="$2" data="${3:-}" token hdr
    token=$(rw_token) || return 1
    rw_normalize_url
    hdr=$(printf 'Authorization: Bearer %s\nContent-Type: application/json\nX-Forwarded-For: 127.0.0.1\nX-Forwarded-Proto: https\n' "$token")
    [[ -n "${RW_API_COOKIE:-}" ]] && hdr+=$'\n'"Cookie: ${RW_API_COOKIE}"
    local ct="${F2D_API_CONNECT_TIMEOUT:-10}" mt="${F2D_API_MAX_TIME:-60}"
    if [[ -n "$data" ]]; then
        printf '%s' "$data" | curl -sS --connect-timeout "$ct" --max-time "$mt" -X "$method" "${RW_API_URL%/}$path" -H @<(printf '%s' "$hdr") --data-binary @-
    else
        curl -sS --connect-timeout "$ct" --max-time "$mt" -X "$method" "${RW_API_URL%/}$path" -H @<(printf '%s' "$hdr") </dev/null
    fi
}

# Проверка API с диагнозом: печатает "код|число_профилей" (код 000 — нет соединения)
rw_probe() {
    local token hdr out code
    token=$(F2D_NO_PROMPT=1 rw_token) || { echo "notoken|0"; return; }
    hdr=$(printf 'Authorization: Bearer %s\nX-Forwarded-For: 127.0.0.1\nX-Forwarded-Proto: https\n' "$token")
    [[ -n "${RW_API_COOKIE:-}" ]] && hdr+=$'\n'"Cookie: ${RW_API_COOKIE}"
    out=$(mktemp)
    local rc=0
    code=$(curl -sS -o "$out" -w '%{http_code}' --connect-timeout 5 --max-time 15 \
        "${RW_API_URL%/}/api/config-profiles" -H @<(printf '%s' "$hdr") </dev/null 2>/dev/null) || rc=$?
    if [[ -z "$code" || "$code" == 000 ]]; then
        case "$rc" in
            52|56) code=444;;   # соединение закрыто без ответа — так nginx панели отвечает без ключа входа
            6) code=dns;; 28) code=timeout;; *) code=000;;
        esac
    fi
    local n; n=$(jq -r '.response.configProfiles | length' "$out" 2>/dev/null)
    echo "$code|${n:-0}"
    rm -f "$out"
}

rw_probe_explain() {   # код -> человеческое объяснение
    case "$1" in
        200) echo "подключено";;
        notoken) echo "токен не задан";;
        000) echo "нет соединения с $RW_API_URL — сервер недоступен или порт закрыт";;
        dns) echo "домен из $RW_API_URL не резолвится — проверьте адрес";;
        timeout) echo "панель не ответила за 15 с — фаервол панели или неверный адрес";;
        401|403) echo "панель отвергла токен (HTTP $1) — проверьте API-токен";;
        444|400|"") echo "nginx панели закрыл соединение — нужен ключ входа (вставьте ссылку входа целиком)";;
        404) echo "по этому адресу нет API Remnawave (HTTP 404) — нужен адрес панели";;
        5*) echo "панель ответила ошибкой HTTP $1";;
        *) echo "неожиданный ответ HTTP $1";;
    esac
}

# Шаг мастера: адрес/ссылка панели + API-токен, с проверкой
rw_setup_interactive() {
    title "Подключение к панели Remnawave"
    echo "  Нужно для смены порта и транспорта нод и проверки inbound'ов в doctor."
    echo "  Токен: Панель → Настройки → API токены → создать."
    if has_panel; then
        config_set RW_API_URL "http://127.0.0.1:3000"
        info "Панель на этом сервере — API: http://127.0.0.1:3000"
    else
        local cur=""; [[ "$RW_API_URL" != http://127.0.0.1:3000 ]] && cur="$RW_API_URL"
        echo "  Вставьте адрес панели (https://panel.example.com) или, если панель ставил"
        echo "  установщик с секретным ключом, ссылку входа ЦЕЛИКОМ — с ?ключом=значением на конце."
        ask "Панель (пусто — пропустить)" "$cur"
        [[ -z "$REPLY" ]] && { info "Пропущено. Позже: fail2detect config RW_API_URL <ссылка>"; return 1; }
        [[ "$REPLY" =~ ^https?:// ]] || REPLY="https://$REPLY"
        config_set RW_API_URL "$REPLY"; rw_normalize_url
        [[ -n "${RW_API_COOKIE:-}" ]] && ok "Ключ входа сохранён (RW_API_COOKIE)"
    fi
    local try code n need_token=no
    F2D_NO_PROMPT=1 rw_token >/dev/null 2>&1 || need_token=yes
    for try in 1 2 3; do
        if [[ "$need_token" == yes ]]; then
            local t; read_secret "API-токен панели (вставьте; пусто — пропустить)"; t="$REPLY"
            [[ -z "$t" ]] && { info "Пропущено. Позже: fail2detect config RW_API_TOKEN <токен>"; return 1; }
            install -m 600 /dev/null "$RW_TOKEN_FILE"; printf '%s' "$t" > "$RW_TOKEN_FILE"
            config_set RW_API_TOKEN ""; RW_API_TOKEN=""; _RW_TOKEN=""
        fi
        info "Проверяю API…"
        IFS='|' read -r code n <<<"$(rw_probe)"
        if [[ "$code" == 200 ]]; then
            ok "Панель подключена: профилей конфигурации — $n"
            audit_write PANEL - - - "подключена панель $RW_API_URL"
            return 0
        fi
        warn "$(rw_probe_explain "$code")"
        [[ "$code" =~ ^(401|403|notoken)$ ]] && need_token=yes || need_token=no
        if [[ "$code" =~ ^(444|400)$ && -z "${RW_API_COOKIE:-}" ]] && ! has_panel; then
            ask "Ключ входа name=value (или ссылка входа целиком; пусто — нет ключа)" ""
            if [[ "$REPLY" == http* ]]; then config_set RW_API_URL "$REPLY"; rw_normalize_url
            elif [[ -n "$REPLY" ]]; then config_set RW_API_COOKIE "$REPLY"; fi
        fi
        confirm "Попробовать ещё раз?" y || break
    done
    warn "Панель не подключена — fail2detect работает и без неё (кроме смены порта/транспорта)."
    return 1
}

rw_api_ok() {   # проверка доступа к API
    local r; r=$(rw_api GET /api/config-profiles 2>/dev/null)
    jq -e '.response.configProfiles' >/dev/null 2>&1 <<<"$r"
}

rw_need_api() {
    # Адрес и токен спрашиваем ЯВНО и заранее: дальше API зовётся в $(…) с
    # заглушённым stderr, и скрытый вопрос о токене выглядел как зависание.
    if { [[ "$RW_API_URL" == http://127.0.0.1:3000 ]] && ! has_panel; } || ! F2D_NO_PROMPT=1 rw_token >/dev/null 2>&1; then
        [[ -t 0 ]] || { err "Панель не настроена: fail2detect setup или fail2detect config RW_API_URL/RW_API_TOKEN"; return 1; }
        rw_setup_interactive || return 1
        load_config; _RW_TOKEN=""
        return 0
    fi
    local code
    IFS='|' read -r code _ <<<"$(rw_probe)"
    [[ "$code" == 200 ]] && return 0
    err "API панели: $(rw_probe_explain "$code")"
    if [[ -t 0 ]] && confirm "Ввести адрес/токен панели заново?" y; then
        rw_setup_interactive || return 1
        load_config; _RW_TOKEN=""
        return 0
    fi
    return 1
}

# таблица inbound'ов: profile_uuid inbound_uuid tag port profile_name
rw_inbounds() {
    rw_api GET /api/config-profiles | jq -r '
        .response.configProfiles[] as $p
        | ($p.config.inbounds // [])[] as $i
        | [$p.uuid, ((($p.inbounds // []) | map(select(.tag == $i.tag)) | .[0].uuid) // "-"), $i.tag, ($i.port|tostring), $p.name,
           (($i.streamSettings.network // "tcp") + "/" + ($i.streamSettings.security // "none"))] | @tsv'
}

rw_show_inbounds() {
    rw_need_api || return 1
    title "Inbound'ы в профилях конфигурации"
    printf '%s%-4s %-20s %-7s %-16s %s%s\n' "$C_BOLD" "№" "TAG" "ПОРТ" "ТРАНСПОРТ" "ПРОФИЛЬ" "$C_RESET"
    local i=0
    while IFS=$'\t' read -r _ _ tag port name tr; do
        i=$((i + 1)); printf '%-4s %-20s %-7s %-16s %s\n' "$i" "$tag" "$port" "$tr" "$name"
    done < <(rw_inbounds)
}

# выбрать inbound -> SEL_PUUID SEL_IUUID SEL_TAG SEL_PORT SEL_PNAME
rw_pick_inbound() {   # [tag] [вопрос]
    local want="${1:-}" q="Номер inbound’а" rows sel
    [[ -n "${2:-}" ]] && q="$2"
    rows=$(rw_inbounds); [[ -n "$rows" ]] || die "В панели нет inbound'ов"
    if [[ -n "$want" ]]; then sel=$(awk -F'\t' -v t="$want" '$3==t' <<<"$rows" | head -1)
    elif (( $(wc -l <<<"$rows") == 1 )); then sel="$rows"
    else rw_show_inbounds; ask "$q" "1"; sel=$(sed -n "${REPLY}p" <<<"$rows"); fi
    [[ -n "$sel" ]] || die "Inbound не найден"
    IFS=$'\t' read -r SEL_PUUID SEL_IUUID SEL_TAG SEL_PORT SEL_PNAME _ <<<"$sel"
}

rw_inbound_json() {   # profile_uuid tag
    rw_api GET "/api/config-profiles/$1" | jq -c --arg t "$2" '.response.config.inbounds[] | select(.tag == $t)'
}

# хосты inbound'а: uuid remark port address
rw_hosts_of() { rw_api GET /api/hosts | jq -r --arg i "$1" '.response[] | select(.inbound.configProfileInboundUuid == $i) | [.uuid, .remark, (.port|tostring), .address] | @tsv'; }

# ---------- смена порта Xray (inbound) ----------
node_port_change() {   # new_port [tag]
    local new="$1"
    is_port "$new" || die "Неверный порт: $new"
    (( new == $(detect_node_api_port 2>/dev/null || echo 0) )) && die "Порт $new занят API ноды (NODE_PORT)"
    rw_need_api || return 1
    rw_pick_inbound "${2:-}" "Номер inbound'а, у которого меняем порт"
    local puuid="$SEL_PUUID" iuuid="$SEL_IUUID" tag="$SEL_TAG" old="$SEL_PORT" pname="$SEL_PNAME"
    [[ "$old" == "$new" ]] && { info "Порт уже $new"; return 0; }
    local l4; l4=$(transport_l4 "$(rw_inbound_json "$puuid" "$tag" | transport_of_inbound)")
    local f=-tln; [[ "$l4" == udp ]] && f=-uln
    if has_node && ss -H $f "( sport = :$new )" 2>/dev/null | grep -q .; then die "Порт $new/$l4 уже занят"; fi

    title "Смена порта: $tag ($pname) $old → $new/$l4"
    local hosts; hosts=$(rw_hosts_of "$iuuid")
    echo "  Хостов, где порт поменяется: $(awk -F'\t' -v o="$old" '$3==o' <<<"$hosts" | grep -c .)"
    has_node && echo "  Фаервол этого сервера: открою $new/$l4"
    confirm "Применить?" y || return 1

    # фаервол — до того, как панель разошлёт новый конфиг
    if has_node; then list_add "PUBLIC_${l4^^}" "$new"; ufw_allow "$new" "$l4" "" "Xray $tag"; fw_apply >/dev/null; fi

    local cfg r; cfg=$(rw_api GET "/api/config-profiles/$puuid" | jq --arg t "$tag" --argjson n "$new" '
        .response.config | .inbounds |= map(if .tag == $t then .port = $n else . end)')
    [[ -n "$cfg" && "$cfg" != null ]] || die "Не удалось получить конфиг профиля"
    r=$(rw_api PATCH /api/config-profiles "$(rw_profile_body "$puuid" <<<"$cfg")")
    jq -e '.response.uuid' >/dev/null <<<"$r" || die "Панель не приняла профиль: $(jq -c '.message // .' <<<"$r" 2>/dev/null || echo "$r")"
    ok "Профиль обновлён — панель разошлёт конфиг на ноды"

    local hu hr hp
    while IFS=$'\t' read -r hu hr hp _; do
        [[ -z "$hu" || "$hp" != "$old" ]] && continue
        r=$(rw_api PATCH /api/hosts "$(jq -n --arg u "$hu" --argjson p "$new" '{uuid:$u, port:$p}')")
        if jq -e '.response.uuid' >/dev/null <<<"$r"; then ok "Хост «${hr}»: порт $new"; else warn "Хост «${hr}» не обновлён: $r"; fi
    done <<<"$hosts"

    if has_node; then
        info "Жду, пока Xray поднимется на $new/${l4}…"
        if node_wait_port "$new" "$l4"; then ok "Xray слушает $new/$l4"
        else warn "Xray пока не слушает $new — проверьте ноду в панели (Ноды → статус)"; fi
        if [[ " $(detect_ssh_ports) " != *" $old "* ]] && confirm "Закрыть старый порт $old/$l4?" y; then
            list_del "PUBLIC_${l4^^}" "$old"; ufw_delete_allow "$old" "$l4"; fw_apply >/dev/null; ok "Порт $old закрыт"
        fi
    else
        warn "Нода на другом сервере. Выполните там:"
        echo "    fail2detect port open $new $l4 && fail2detect port close $old $l4"
    fi
    audit_write NODE_PORT - "$tag" - "$old → $new/$l4 (профиль $pname)"
    warn "Клиентам нужно обновить подписку, чтобы получить новый порт."
}

# ---------- смена транспорта (и порта) у работающей ноды ----------
# Inbound пересобирается с тем же tag: ключи Reality и path сохраняются, где
# это возможно; хосты, ноды и squad'ы перепривязываются, если панель выдала
# inbound'у новый uuid. Подходит для нод от любых установщиков и ручных.
node_transport_change() {   # [tag]
    require_root; rw_need_api || return 1
    rw_pick_inbound "${1:-}" "Номер inbound'а, у которого меняем транспорт"
    local puuid="$SEL_PUUID" iuuid="$SEL_IUUID" tag="$SEL_TAG" oport="$SEL_PORT" pname="$SEL_PNAME"
    local old ot odomain otarget opriv osid opath ol4
    old=$(rw_inbound_json "$puuid" "$tag"); ot=$(transport_of_inbound <<<"$old")
    odomain=$(jq -r '.streamSettings | (.realitySettings.serverNames[0] // .tlsSettings.serverName // "")' <<<"$old")
    otarget=$(jq -r '.streamSettings.realitySettings | (.target // .dest // "")' <<<"$old")
    opriv=$(jq -r '.streamSettings.realitySettings.privateKey // ""' <<<"$old")
    osid=$(jq -r '.streamSettings.realitySettings.shortIds[0] // ""' <<<"$old")
    opath=$(jq -r '.streamSettings | (.xhttpSettings.path // .grpcSettings.serviceName // "")' <<<"$old")
    ol4=$(transport_l4 "$ot")
    title "Сейчас: $tag — $(transport_title "$ot") на $oport/$ol4 (профиль $pname)"

    ASK_PORT_ALLOW="$oport"
    local i=1 t; for t in "${TRANSPORTS[@]}"; do [[ "$t" == "$ot" ]] && break; i=$((i + 1)); done
    ask_transport_params "$i" "$oport" "$odomain"
    unset ASK_PORT_ALLOW
    local path=""; [[ "${ot%%-*}" == "${T_TRANSPORT%%-*}" ]] && path="$opath"
    local new; new=$(inbound_build "$T_TRANSPORT" "$tag" "$T_PORT" "$T_DOMAIN" "$T_TARGET" "$path" "$opriv" "$osid" "$T_OBFS") || return 1
    local nl4; nl4=$(transport_l4 "$T_TRANSPORT")

    echo
    echo "  Было:  $(transport_title "$ot") · $oport/$ol4 · ${odomain:-$otarget}"
    echo "  Стало: $(transport_title "$T_TRANSPORT") · $T_PORT/$nl4 · ${T_DOMAIN:-$T_TARGET}"
    confirm "Применить?" y || return 1

    # 1) нода: сертификат, selfsteal, фаервол — ДО того, как Xray получит конфиг
    local here=no
    if has_node && confirm "Нода с этим профилем работает на этом сервере?" y; then here=yes; fi
    if [[ "$here" == yes ]]; then
        node_prepare "$T_TRANSPORT" "$T_PORT" "$T_DOMAIN" "$T_TARGET" "$oport/$ol4" || return 1
    else
        warn "Сначала подготовьте ноду. На её сервере выполните:"
        printf '    fail2detect node prepare --transport %s --port %s' "$T_TRANSPORT" "$T_PORT"
        [[ -n "$T_DOMAIN" ]] && printf ' --domain %s' "$T_DOMAIN"
        [[ -n "$T_TARGET" ]] && printf ' --target %s' "$T_TARGET"
        printf ' --close %s/%s\n' "$oport" "$ol4"
        echo "    (подходит для нод от любого установщика — сначала установите fail2detect на ноду)"
        confirm "Нода подготовлена?" n || { info "Отменено, панель не изменена"; return 1; }
    fi

    # 2) профиль
    local cfg r; cfg=$(rw_api GET "/api/config-profiles/$puuid" | jq --arg t "$tag" --argjson n "$new" '
        .response.config | .inbounds |= map(if .tag == $t then $n else . end)')
    r=$(rw_api PATCH /api/config-profiles "$(rw_profile_body "$puuid" <<<"$cfg")")
    jq -e '.response.uuid' >/dev/null <<<"$r" || die "Панель не приняла профиль: $(jq -c '.message // .' <<<"$r" 2>/dev/null || echo "$r")"
    ok "Профиль обновлён"

    # 3) если uuid inbound'а сменился — перепривязать ноды, хосты и squad'ы
    local niuuid; niuuid=$(jq -r --arg t "$tag" '.response.inbounds[] | select(.tag == $t) | .uuid' <<<"$r")
    [[ -z "$niuuid" ]] && niuuid=$(rw_api GET "/api/config-profiles/$puuid" | jq -r --arg t "$tag" '.response.inbounds[] | select(.tag == $t) | .uuid')
    if [[ -n "$niuuid" && "$niuuid" != "$iuuid" ]]; then
        info "Панель пересоздала inbound — перепривязываю"
        local nu ai
        while IFS=$'\t' read -r nu ai; do
            rw_api PATCH /api/nodes "$(jq -n --arg u "$nu" --arg p "$puuid" --argjson a "$ai" --arg o "$iuuid" --arg n "$niuuid" \
                '{uuid:$u, configProfile:{activeConfigProfileUuid:$p, activeInbounds:($a | map(if . == $o then $n else . end))}}')" >/dev/null && ok "Нода $nu перепривязана"
        done < <(rw_api GET /api/nodes | jq -r --arg o "$iuuid" '.response[] | select(.configProfile.activeInbounds // [] | map(.uuid // .) | index($o)) | [.uuid, (.configProfile.activeInbounds | map(.uuid // .) | tojson)] | @tsv')
        squad_add_inbound "$niuuid" "$iuuid"
    fi
    iuuid="${niuuid:-$iuuid}"

    # 4) хосты: порт, SNI, path, ALPN под новый транспорт (адрес не трогаем)
    local hu hr hp ha hf
    while IFS=$'\t' read -r hu hr hp ha; do
        [[ -z "$hu" ]] && continue
        hf=$(host_fields "$new" "$ha")
        r=$(rw_api PATCH /api/hosts "$(jq -n --arg u "$hu" --argjson h "$hf" --arg p "$puuid" --arg i "$iuuid" \
            '$h + {uuid:$u, inbound:{configProfileUuid:$p, configProfileInboundUuid:$i}}')")
        if jq -e '.response.uuid' >/dev/null <<<"$r"; then ok "Хост «${hr}» обновлён"; else warn "Хост «${hr}»: $(jq -c '.message // .' <<<"$r" 2>/dev/null)"; fi
    done < <(rw_api GET /api/hosts | jq -r --arg a "$SEL_IUUID" --arg b "$iuuid" '.response[] | select(.inbound.configProfileInboundUuid == $a or .inbound.configProfileInboundUuid == $b) | [.uuid, .remark, (.port|tostring), .address] | @tsv')

    if [[ "$here" == yes ]]; then
        info "Жду, пока Xray поднимется на $T_PORT/${nl4}…"
        node_wait_port "$T_PORT" "$nl4" && ok "Xray слушает $T_PORT/$nl4" || warn "Xray пока не слушает — смотрите статус ноды в панели и docker logs remnanode"
    fi
    audit_write NODE_TRANSPORT - "$tag" - "$ot:$oport → $T_TRANSPORT:$T_PORT"
    warn "Клиентам нужно обновить подписку."
}

# ---------- запасные транспорты к работающей ноде ----------
# Берём существующий inbound как образец (домен, ключи Reality, адрес хоста),
# добавляем в тот же профиль новые inbound'ы и по хосту на каждый, включаем
# их у нод с этим профилем и в тех же squad'ах. Старый транспорт не трогаем.
node_transport_add() {   # [tag-образца]
    require_root; rw_need_api || return 1
    rw_pick_inbound "${1:-}" "Номер inbound'а ноды, к которой добавить транспорт"
    local puuid="$SEL_PUUID" ruuid="$SEL_IUUID" rtag="$SEL_TAG" pname="$SEL_PNAME"
    local ref ot odomain otarget opriv osid
    ref=$(rw_inbound_json "$puuid" "$rtag"); ot=$(transport_of_inbound <<<"$ref")
    odomain=$(jq -r '.streamSettings | (.realitySettings.serverNames[0] // .tlsSettings.serverName // "")' <<<"$ref")
    otarget=$(jq -r '.streamSettings.realitySettings | (.target // .dest // "")' <<<"$ref")
    opriv=$(jq -r '.streamSettings.realitySettings.privateKey // ""' <<<"$ref")
    osid=$(jq -r '.streamSettings.realitySettings.shortIds[0] // ""' <<<"$ref")
    [[ "$otarget" == "$NGINX_SOCK" ]] && otarget=""
    title "Запасные транспорты для профиля «${pname}» (сейчас: $(transport_label "$ot") :$SEL_PORT)"

    # занятые в профиле порты, чтобы не предложить конфликт
    local busy; busy=$(rw_api GET "/api/config-profiles/$puuid" | jq -r '.response.config.inbounds[] | "\(.port)/\(if .protocol == "hysteria" then "udp" else "tcp" end)"')
    local here=no
    if has_node && confirm "Нода с этим профилем работает на этом сервере?" y; then here=yes; fi
    [[ "$here" == yes ]] || ASK_PORT_NOCHECK=1
    ask_transports "$odomain"
    unset ASK_PORT_NOCHECK
    [[ -n "$otarget" && -z "$T_TARGET" ]] && T_TARGET="$otarget"
    local t
    for t in "${T_LIST[@]}"; do
        grep -qx "${T_PORTS[$t]}/$(transport_l4 "$t")" <<<"$busy" && die "${T_PORTS[$t]}/$(transport_l4 "$t") уже занят в этом профиле — выберите другой порт"
    done
    confirm "Добавить: $(for t in "${T_LIST[@]}"; do printf '%s %s/%s  ' "$(transport_label "$t")" "${T_PORTS[$t]}" "$(transport_l4 "$t")"; done)?" y || return 1

    # 1) нода: сертификат, сайт, фаервол — до того, как Xray получит конфиг
    if [[ "$here" == yes ]]; then
        node_prepare_all || return 1
    else
        warn "Сначала подготовьте ноду. На её сервере выполните:"
        for t in "${T_LIST[@]}"; do
            printf '    fail2detect node prepare --transport %s --port %s' "$t" "${T_PORTS[$t]}"
            [[ -n "$T_DOMAIN" ]] && printf ' --domain %s' "$T_DOMAIN"
            [[ -n "$T_TARGET" ]] && transport_reality "$t" && printf ' --target %s' "$T_TARGET"
            echo
        done
        confirm "Нода подготовлена?" n || { info "Отменено, панель не изменена"; return 1; }
    fi

    # 2) профиль: + новые inbound'ы (ключи Reality — как у образца)
    local prefix inbs cfg r
    prefix=$(tag_prefix "${rtag%%_*}")
    inbs=$(build_inbounds "$prefix" "$opriv" "$osid") || return 1
    cfg=$(rw_api GET "/api/config-profiles/$puuid" | jq --argjson n "$inbs" '.response.config | .inbounds += $n')
    r=$(rw_api PATCH /api/config-profiles "$(rw_profile_body "$puuid" <<<"$cfg")")
    jq -e '.response.uuid' >/dev/null <<<"$r" || die "Панель не приняла профиль: $(jq -c '.message // .' <<<"$r" 2>/dev/null)"
    ok "Профиль обновлён"
    local -A uuid_of=(); local tag u
    while IFS=$'\t' read -r tag u; do uuid_of[$tag]="$u"; done < <(jq -r '.response.inbounds[] | [.tag, .uuid] | @tsv' <<<"$r")
    local added=(); while read -r tag; do [[ -n "${uuid_of[$tag]:-}" ]] && added+=("${uuid_of[$tag]}"); done < <(jq -r '.[].tag' <<<"$inbs")
    local newj; newj=$(printf '%s\n' "${added[@]}" | jq -R . | jq -sc .)

    # 3) ноды с этим профилем и образцом — включить новые inbound'ы
    local nu ai
    while IFS=$'\t' read -r nu ai; do
        rw_api PATCH /api/nodes "$(jq -n --arg u "$nu" --arg p "$puuid" --argjson a "$ai" --argjson n "$newj" \
            '{uuid:$u, configProfile:{activeConfigProfileUuid:$p, activeInbounds:(($a + $n) | unique)}}')" >/dev/null && ok "Нода $nu: транспорты включены"
    done < <(rw_api GET /api/nodes | jq -r --arg o "$ruuid" '.response[] | select(.configProfile.activeInbounds // [] | map(.uuid // .) | index($o)) | [.uuid, (.configProfile.activeInbounds | map(.uuid // .) | tojson)] | @tsv')

    # 4) хосты по образцу: тот же адрес, имя «<имя образца> · <транспорт>»
    local rhost raddr rrem inb hf label
    rhost=$(rw_hosts_of "$ruuid" | head -1)
    IFS=$'\t' read -r _ rrem _ raddr <<<"$rhost"
    rrem="${rrem% · *}"; [[ -n "$rrem" ]] || rrem="$pname"
    [[ -n "$raddr" ]] || raddr="${T_DOMAIN:-$(public_ip)}"
    while read -r inb; do
        tag=$(jq -r .tag <<<"$inb"); u="${uuid_of[$tag]:-}"; [[ -n "$u" ]] || continue
        label=$(transport_label "$(transport_of_inbound <<<"$inb")")
        hf=$(host_fields "$inb" "$raddr")
        r=$(rw_api POST /api/hosts "$(jq -n --argjson h "$hf" --arg p "$puuid" --arg i "$u" --arg rem "$rrem · $label" \
            '$h + {remark:$rem, inbound:{configProfileUuid:$p, configProfileInboundUuid:$i}} | with_entries(select(.value != null))')")
        if jq -e '.response.uuid' >/dev/null <<<"$r"; then ok "Хост «$rrem · ${label}»"; else warn "Хост «$rrem · ${label}»: $(jq -c '.message // .' <<<"$r" 2>/dev/null)"; fi
        squad_link_like "$u" "$ruuid"
    done < <(jq -c '.[]' <<<"$inbs")

    if [[ "$here" == yes ]]; then
        for t in "${T_LIST[@]}"; do
            node_wait_port "${T_PORTS[$t]}" "$(transport_l4 "$t")" && ok "$(transport_label "$t"): слушает ${T_PORTS[$t]}/$(transport_l4 "$t")" \
                || warn "$(transport_label "$t"): ${T_PORTS[$t]}/$(transport_l4 "$t") пока не слушается — docker logs remnanode"
        done
    fi
    audit_write NODE_TRANSPORT_ADD - "$rtag" - "$(transports_arg)"
    warn "Клиентам нужно обновить подписку, чтобы получить новые транспорты."
}

# добавить inbound во все squad'ы, где есть образец (ничего не удаляя)
squad_link_like() {   # new_uuid ref_uuid
    local sq u cur
    sq=$(rw_api GET /api/internal-squads | jq -c '.response.internalSquads // []')
    while read -r u; do
        [[ -n "$u" ]] || continue
        cur=$(jq -c --arg u "$u" '.[] | select(.uuid == $u) | [.inbounds[]? | (.uuid // .)]' <<<"$sq")
        jq -e --arg o "$2" 'index($o)' <<<"$cur" >/dev/null || continue
        rw_api PATCH /api/internal-squads "$(jq -n --arg u "$u" --argjson i "$(jq -c --arg n "$1" '. + [$n] | unique' <<<"$cur")" '{uuid:$u, inbounds:$i}')" >/dev/null
    done < <(jq -r '.[].uuid' <<<"$sq")
}

# подготовка ноды из CLI: fail2detect node prepare --transport T --port P [--domain D] [--target T] [--close P/proto]
node_prepare_cli() {
    local t="" p="" d="" tg="" close=""
    while (($#)); do
        case "$1" in
            --transport) t="$2"; shift;; --port) p="$2"; shift;; --domain) d="$2"; shift;;
            --target) tg="$2"; shift;; --close) close="$2"; shift;; *) die "Неизвестный параметр: $1";;
        esac; shift
    done
    node_prepare "$t" "$p" "$d" "$tg" "$close"
}

# ---------- смена NODE_PORT (API ноды, по умолчанию 2222) ----------
node_api_port_change() {   # new_port
    local new="$1" d old
    is_port "$new" || die "Неверный порт: $new"
    d=$(node_dir); [[ -n "$d" ]] || die "Нода на этом сервере не найдена"
    old=$(detect_node_api_port)
    [[ "$old" == "$new" ]] && { info "NODE_PORT уже $new"; return 0; }
    ss -H -tln "( sport = :$new )" | grep -q . && die "Порт $new занят"
    local panels; panels=$(detect_panel_ips)
    title "Смена API-порта ноды: $old → $new"
    [[ -n "$panels" ]] || warn "IP панели не найден — укажите его: fail2detect config PANEL_IPS <ip>"
    confirm "Нода перезапустится (клиенты отключатся на ~10 c). Продолжить?" y || return 1

    local cf; cf=$(compose_file "$d")
    cp -a "$cf" "$cf.f2d.bak"
    sed -i -E "s/(NODE_PORT|APP_PORT)([=:][[:space:]]*\"?)$old/\1\2$new/" "$cf"
    [[ -f "$d/.env" ]] && sed -i -E "s/^(NODE_PORT|APP_PORT)=$old$/\1=$new/" "$d/.env"
    config_set NODE_API_PORT "$new"

    local ip
    for ip in $panels; do
        ufw_allow "$new" tcp "$ip" "Remnawave panel"
        ufw_active && ufw --force delete allow proto tcp from "$ip" to any port "$old" >/dev/null 2>&1
    done
    fw_apply >/dev/null
    (cd "$d" && docker compose up -d remnanode >/dev/null 2>&1) && ok "Нода перезапущена с NODE_PORT=$new"

    # обновить порт ноды в панели
    if { has_panel || [[ "$RW_API_URL" != http://127.0.0.1:3000 ]]; } && rw_api_ok; then
        local me nodes nu
        me=$(public_ip)
        nodes=$(rw_api GET /api/nodes)
        nu=$(jq -r --arg a "$me" --argjson o "$old" '.response[] | select((.address == $a or .address == "127.0.0.1" or .address == "172.30.0.1") and .port == $o) | .uuid' <<<"$nodes" | head -1)
        if [[ -n "$nu" ]]; then
            rw_api PATCH /api/nodes "$(jq -n --arg u "$nu" --argjson p "$new" '{uuid:$u, port:$p}')" | jq -e '.response.uuid' >/dev/null \
                && ok "Порт ноды в панели обновлён"
        else
            warn "Не нашёл эту ноду в панели — поменяйте порт вручную: Ноды → нода → Порт = $new"
        fi
    else
        warn "Поменяйте порт в панели: Ноды → эта нода → Порт = $new"
    fi
    audit_write NODE_API_PORT - - - "$old → $new"
}

# ---------- лог Xray для jail reality ----------
node_logs_enable() {
    rw_need_api || return 1
    local profiles puuid
    profiles=$(rw_api GET /api/config-profiles | jq -r '.response.configProfiles[] | [.uuid, .name] | @tsv')
    if (( $(wc -l <<<"$profiles") > 1 )); then
        local i=0 n
        while IFS=$'\t' read -r _ n; do i=$((i + 1)); echo "  $i. $n"; done <<<"$profiles"
        ask "Номер профиля" "1"; profiles=$(sed -n "${REPLY}p" <<<"$profiles")
    fi
    puuid=$(cut -f1 <<<"$profiles" | head -1)
    [[ -n "$puuid" ]] || die "Профиль не выбран"
    local cfg r
    cfg=$(rw_api GET "/api/config-profiles/$puuid" | jq '.response.config | .log = ((.log // {}) + {loglevel:"info", error:"/var/log/remnanode/error.log", access:"none"})')
    r=$(rw_api PATCH /api/config-profiles "$(rw_profile_body "$puuid" <<<"$cfg")")
    jq -e '.response.uuid' >/dev/null <<<"$r" || die "Панель не приняла профиль: $r"
    ok "Xray пишет ошибки в /var/log/remnanode/error.log"
    if has_node; then
        mkdir -p /var/log/remnanode
        cat > /etc/logrotate.d/remnanode-f2d <<'EOF'
/var/log/remnanode/*.log {
    daily
    rotate 3
    size 50M
    missingok
    notifempty
    compress
    copytruncate
}
EOF
        jail_set_enabled reality yes
    else
        info "На нодах включите jail: fail2detect jail enable reality"
    fi
}

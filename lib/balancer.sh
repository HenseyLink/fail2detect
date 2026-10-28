#!/usr/bin/env bash
# fail2detect — клиентский балансировщик (подписка Xray JSON).
#
# В подписке появляется одна запись «⚡ Авто». Для неё панель собирает конфиг
# Xray, в который подставлены все ноды пула: клиент сам пингует их
# (burstObservatory) и держит трафик на лучших (leastLoad — случайно среди
# двух самых быстрых).
#
# Пул — хосты с тегом F2D_BAL. Новая нода с этим тегом попадает в
# балансировщик сама, без перенастройки.
#
# Белые списки — хосты с тегом F2D_WL (например, мост на сервере в
# разрешённой сети). Через них трафик не идёт, пока основной пул отвечает.
# Когда оператор включает белые списки, зарубежные ноды перестают отвечать
# на пинг — балансировщик переключается на мост; списки сняли — обратно.
#
# Всё штатными средствами Remnawave: шаблон XRAY_JSON с блоком
# remnawave.injectHosts (подстановка хостов по тегу) и хост-обёртка,
# видимая только в подписке Xray JSON.

BAL_TAG="F2D_BAL"
BAL_WL_TAG="F2D_WL"
BAL_TEMPLATE_NAME="fail2detect Auto"
BAL_PROBE_URL="https://www.gstatic.com/generate_204"
BAL_NOT_JSON='["XRAY_BASE64","MIHOMO","STASH","CLASH","SINGBOX"]'

# ---------- шаблон ----------
# Собирается поверх шаблона XRAY_JSON «Default» панели: его dns, inbounds и
# правила маршрутизации сохраняются; голое правило «всё → прокси» заменяется
# правилом «всё → балансировщик».
balancer_template_json() {   # default_json has_wl(yes|no)
    local def="${1:-}"; [[ -n "$def" ]] || def='{}'
    jq -n --argjson def "$def" --arg wl "${2:-no}" --arg bal "$BAL_TAG" --arg wltag "$BAL_WL_TAG" --arg probe "$BAL_PROBE_URL" '
        ($def | {
            dns: (.dns // {servers: ["1.1.1.1", "8.8.8.8"], queryStrategy: "UseIP"}),
            inbounds: (.inbounds // [
                {tag: "socks", port: 10808, listen: "127.0.0.1", protocol: "socks",
                 settings: {udp: true, auth: "noauth"},
                 sniffing: {enabled: true, destOverride: ["http", "tls", "quic"]}},
                {tag: "http", port: 10809, listen: "127.0.0.1", protocol: "http",
                 sniffing: {enabled: true, destOverride: ["http", "tls", "quic"]}}]),
            # теги proxy*/wl* займут подставленные хосты
            outbounds: ((.outbounds // [{tag: "direct", protocol: "freedom"}, {tag: "block", protocol: "blackhole"}])
                | map(select((.tag // "") | test("^(proxy|wl)") | not))),
            routing: (.routing // {})
        }) as $b
        # правила, которые что-то реально отбирают (домены, IP, порты, протоколы);
        # «голое» {network, outboundTag} съело бы всё раньше балансировщика
        | ([($b.routing.rules // [])[]
            | select([keys_unsorted[] | select(. != "type" and . != "network" and . != "outboundTag" and . != "balancerTag")] | length > 0)]) as $rules
        | ($wl == "yes") as $has_wl
        | $b + {
            remnawave: {
                injectHosts: ([{selector: {type: "tagRegex", pattern: ("^" + $bal + "$")}, selectFrom: "ALL", tagPrefix: "proxy"}]
                    + (if $has_wl then [{selector: {type: "tagRegex", pattern: ("^" + $wltag + "$")}, selectFrom: "ALL", tagPrefix: "wl"}] else [] end))
            },
            burstObservatory: {
                subjectSelector: (["proxy"] + (if $has_wl then ["wl"] else [] end)),
                pingConfig: {destination: $probe, connectivity: "", interval: "30s", sampling: 2, timeout: "5s"}
            },
            routing: ($b.routing + {
                domainStrategy: ($b.routing.domainStrategy // "IPIfNonMatch"),
                balancers: [{
                    tag: "auto",
                    selector: ["proxy"],
                    strategy: {type: "leastLoad", settings: {expected: 2, maxRTT: "1s", tolerance: 0.01, baselines: ["1s"]}},
                    # все основные ноды молчат (белые списки) → мост; без мостов — первая нода
                    fallbackTag: (if $has_wl then "wl" else "proxy" end)
                }],
                rules: ($rules + [{network: "tcp,udp", balancerTag: "auto"}])
            })
        }'
}

# ---------- хосты ----------
# uuid remark address port tags(через запятую) hidden template_uuid profile inbound
bal_hosts() {
    rw_api GET /api/hosts | jq -r '.response[] | [.uuid, .remark, (.address // ""), ((.port // 0) | tostring),
        ((.tags // []) | join(",")), (if .isHidden then "hidden" else "" end), (.xrayJsonTemplateUuid // ""),
        (.inbound.configProfileUuid // ""), (.inbound.configProfileInboundUuid // "")] | @tsv'
}

bal_set_tag() {   # host_uuid tag add|del
    local cur new r
    cur=$(rw_api GET /api/hosts | jq -c --arg u "$1" '.response[] | select(.uuid == $u) | (.tags // [])')
    [[ -n "$cur" ]] || return 1
    if [[ "$3" == add ]]; then new=$(jq -c --arg t "$2" '. + [$t] | unique' <<<"$cur")
    else new=$(jq -c --arg t "$2" 'map(select(. != $t))' <<<"$cur"); fi
    [[ "$new" == "$cur" ]] && return 0
    r=$(rw_api PATCH /api/hosts "$(jq -nc --arg u "$1" --argjson t "$new" '{uuid: $u, tags: $t}')")
    jq -e '.response.uuid' >/dev/null <<<"$r"
}

bal_template_uuid() {   # uuid нашего шаблона, если есть
    rw_api GET /api/subscription-templates | jq -r --arg n "$BAL_TEMPLATE_NAME" \
        '.response.templates[]? | select(.templateType == "XRAY_JSON" and .name == $n) | .uuid' | head -1
}

bal_default_json() {
    local u; u=$(rw_api GET /api/subscription-templates | jq -r '.response.templates[]? | select(.templateType == "XRAY_JSON" and .name == "Default") | .uuid' | head -1)
    [[ -n "$u" ]] || { echo "{}"; return; }
    rw_api GET "/api/subscription-templates/$u" | jq -c '.response.templateJson // {}'
}

# записать шаблон (создать при необходимости); печатает uuid
bal_write_template() {   # has_wl
    local uuid json r
    json=$(balancer_template_json "$(bal_default_json)" "$1") || return 1
    uuid=$(bal_template_uuid)
    if [[ -z "$uuid" ]]; then
        r=$(rw_api POST /api/subscription-templates "$(jq -n --arg n "$BAL_TEMPLATE_NAME" '{name: $n, templateType: "XRAY_JSON"}')")
        uuid=$(jq -r '.response.uuid // empty' <<<"$r")
        [[ -n "$uuid" ]] || { err "Шаблон не создан: $(jq -c '.message // .' <<<"$r" 2>/dev/null)"; return 1; }
    fi
    r=$(rw_api PATCH /api/subscription-templates "$(jq -n --arg u "$uuid" --argjson j "$json" '{uuid: $u, templateJson: $j}')")
    jq -e '.response.uuid' >/dev/null <<<"$r" || { err "Шаблон не сохранён: $(jq -c '.message // .' <<<"$r" 2>/dev/null)"; return 1; }
    echo "$uuid"
}

# ---------- команды ----------
balancer_status() {
    rw_need_api || return 1
    title "Балансировщик (подписка Xray JSON)"
    local tpl; tpl=$(bal_template_uuid)
    local u rem addr port tags hid tu _p _i n=0 w=0 wrap=""
    while IFS=$'\t' read -r u rem addr port tags hid tu _p _i; do
        [[ -n "$tu" && "$tu" == "$tpl" ]] && { wrap="$rem"; continue; }
        if [[ ",$tags," == *",$BAL_TAG,"* ]]; then n=$((n + 1)); printf '  %s●%s %-30s %s:%s\n' "$C_GREEN" "$C_RESET" "$rem" "$addr" "$port"; fi
        if [[ ",$tags," == *",$BAL_WL_TAG,"* ]]; then w=$((w + 1)); printf '  %s◆%s %-30s %s:%s  %s(белые списки)%s\n' "$C_YELLOW" "$C_RESET" "$rem" "$addr" "$port" "$C_GRAY" "$C_RESET"; fi
    done < <(bal_hosts)
    echo
    if [[ -n "$tpl" && -n "$wrap" ]]; then
        ok "Работает: запись «${wrap}», нод в пуле — $n, мостов для белых списков — $w"
    elif [[ -n "$tpl" ]]; then
        warn "Шаблон есть, но записи в подписке нет — запустите: f2d balancer setup"
    else
        info "Балансировщик не настроен: f2d balancer setup"
    fi
}

# выбрать хосты номерами; печатает uuid'ы
_bal_pick() {   # "вопрос" "по умолчанию" файл_со_списком
    local list="$3" i=0 u rem addr port tags hid tu _p _i
    while IFS=$'\t' read -r u rem addr port tags hid tu _p _i; do
        i=$((i + 1))
        printf '  %s%2d.%s %-30s %s:%s %s%s%s\n' "$C_YELLOW" "$i" "$C_RESET" "${rem:0:30}" "$addr" "$port" "$C_GRAY" \
            "$( [[ ",$tags," == *",$BAL_TAG,"* ]] && echo "[в пуле]")$( [[ ",$tags," == *",$BAL_WL_TAG,"* ]] && echo "[белые списки]")$( [[ -n "$hid" ]] && echo "[скрыт]")" "$C_RESET" >&2
    done < "$list"
    ask "$1" "$2"
    local n out=()
    for n in ${REPLY//,/ }; do
        [[ "$n" == all || "$n" == все ]] && { cut -f1 "$list"; return; }
        [[ "$n" == "-" || "$n" == нет ]] && return 0
        [[ "$n" =~ ^[0-9]+$ ]] && (( n >= 1 && n <= i )) && out+=("$(sed -n "${n}p" "$list" | cut -f1)")
    done
    ((${#out[@]})) && printf '%s\n' "${out[@]}"
}

balancer_setup() {
    require_root; rw_need_api || return 1
    title "Клиентский балансировщик"
    echo "  В подписке появится запись «⚡ Авто»: клиент сам пингует ноды пула и"
    echo "  держит трафик на лучших. Работает в клиентах с подпиской Xray JSON"
    echo "  (v2rayNG, Happ, Streisand…); остальным эта запись не показывается."
    echo
    local tpl; tpl=$(bal_template_uuid)
    local list; list=$(mktemp)
    # кандидаты: все хосты, кроме самой обёртки балансировщика
    bal_hosts | awk -F'\t' -v t="$tpl" '!(t != "" && $7 == t)' > "$list"
    [[ -s "$list" ]] || { rm -f "$list"; err "В панели нет хостов"; return 1; }

    echo "  ${C_BOLD}1. Ноды пула${C_RESET} (номера через пробел, «all» — все):"
    local pool; pool=$(_bal_pick "Ноды пула" "all" "$list")
    [[ -n "$pool" ]] || { rm -f "$list"; err "Пул пуст"; return 1; }
    echo
    echo "  ${C_BOLD}2. Мосты для белых списков${C_RESET} — хосты, доступные, когда оператор"
    echo "     включает белые списки (сервер в разрешённой сети). «-» — без них."
    local wl; wl=$(_bal_pick "Мосты для белых списков" "-" "$list")

    # теги: в пул — F2D_BAL, мосты — F2D_WL (и не в пуле, чтобы не тянуть трафик в обычное время)
    local u rem addr port tags hid tu _p _i
    while IFS=$'\t' read -r u rem addr port tags hid tu _p _i; do
        if grep -qx "$u" <<<"$wl"; then
            bal_set_tag "$u" "$BAL_WL_TAG" add; bal_set_tag "$u" "$BAL_TAG" del
        elif grep -qx "$u" <<<"$pool"; then
            bal_set_tag "$u" "$BAL_TAG" add; bal_set_tag "$u" "$BAL_WL_TAG" del
        else
            bal_set_tag "$u" "$BAL_TAG" del; bal_set_tag "$u" "$BAL_WL_TAG" del
        fi
    done < "$list"
    ok "Пул: $(wc -l <<<"$pool" | tr -d ' ') нод(ы)$([[ -n "$wl" ]] && echo ", мостов: $(wc -l <<<"$wl" | tr -d ' ')")"

    tpl=$(bal_write_template "$([[ -n "$wl" ]] && echo yes || echo no)") || { rm -f "$list"; return 1; }
    config_set BALANCER_TEMPLATE_UUID "$tpl"
    ok "Шаблон Xray JSON «${BAL_TEMPLATE_NAME}»"

    # обёртка — видимая только в подписке Xray JSON запись; inbound — как у
    # первой ноды пула, чтобы её видели пользователи этой ноды
    local first; first=$(head -1 <<<"$pool")
    local wrap; wrap=$(awk -F'\t' -v t="$tpl" '$7 == t {print $1; exit}' <(bal_hosts))
    local f; f=$(awk -F'\t' -v u="$first" '$1 == u' "$list")
    IFS=$'\t' read -r u rem addr port tags hid tu _p _i <<<"$f"
    ask "Название записи в подписке" "⚡ Авто (лучшая нода)"; local remark="$REPLY"
    local body r
    body=$(jq -n --arg rem "$remark" --arg a "$addr" --argjson p "${port:-443}" --arg t "$tpl" --arg pu "$_p" --arg iu "$_i" --argjson ex "$BAL_NOT_JSON" \
        '{remark: $rem, address: $a, port: $p, xrayJsonTemplateUuid: $t, excludeFromSubscriptionTypes: $ex,
          isDisabled: false, isHidden: false, tags: ["F2D_AUTO"], inbound: {configProfileUuid: $pu, configProfileInboundUuid: $iu}}')
    if [[ -n "$wrap" ]]; then
        r=$(rw_api PATCH /api/hosts "$(jq --arg u "$wrap" '. + {uuid: $u}' <<<"$body")")
    else
        r=$(rw_api POST /api/hosts "$body")
    fi
    rm -f "$list"
    jq -e '.response.uuid' >/dev/null <<<"$r" || { err "Запись «${remark}» не создана: $(jq -c '.message // .' <<<"$r" 2>/dev/null)"; return 1; }
    config_set BALANCER_HOST_UUID "$(jq -r '.response.uuid' <<<"$r")"
    ok "Запись «${remark}» — в подписке Xray JSON"
    audit_write BALANCER - - - "настроен: пул $(wc -l <<<"$pool" | tr -d ' '), мостов $([[ -n "$wl" ]] && wc -l <<<"$wl" | tr -d ' ' || echo 0)"
    echo
    info "Клиентам нужно обновить подписку. Новые ноды: f2d balancer add (или тег $BAL_TAG в панели)."
    [[ -n "$wl" ]] && info "Белые списки: пока ноды пула отвечают, мосты не используются; перестали — трафик уйдёт на мост."
    return 0
}

# добавить хост(ы) в пул или в мосты, не пересобирая балансировщик
balancer_add() {   # [wl]
    require_root; rw_need_api || return 1
    local tag="$BAL_TAG" what="пул"; [[ "${1:-}" == wl ]] && { tag="$BAL_WL_TAG"; what="мосты для белых списков"; }
    local tpl; tpl=$(bal_template_uuid)
    [[ -n "$tpl" ]] || { warn "Балансировщик ещё не настроен"; balancer_setup; return; }
    local list; list=$(mktemp)
    bal_hosts | awk -F'\t' -v t="$tpl" '$7 != t' > "$list"
    local sel u; sel=$(_bal_pick "Добавить в $what" "" "$list"); rm -f "$list"
    for u in $sel; do bal_set_tag "$u" "$tag" add && ok "Хост $u → $what"; done
    # первый мост — нужно пересобрать шаблон (появляется fallback на «wl»)
    if [[ "$tag" == "$BAL_WL_TAG" && -n "$sel" ]]; then bal_write_template yes >/dev/null && ok "Шаблон обновлён (с мостами)"; fi
}

# пометить хосты этой ноды тегом пула (из install node)
balancer_tag_node_hosts() {   # node_name
    local u rem
    while IFS=$'\t' read -r u rem _; do
        [[ "$rem" == "$1 · "* ]] && bal_set_tag "$u" "$BAL_TAG" add && ok "«${rem}» → в балансировщике"
    done < <(bal_hosts)
}

# после создания ноды через API: включить её в балансировщик или предложить его
balancer_offer() {   # node_name
    echo
    if [[ -n "$(bal_template_uuid)" ]]; then
        confirm "Добавить ноду в балансировщик «Авто»?" y && balancer_tag_node_hosts "$1"
    else
        info "Балансировщик: одна запись «⚡ Авто» в подписке, клиент сам выбирает лучшую по пингу ноду"
        info "и уходит на мост, если оператор включил белые списки (клиенты с подпиской Xray JSON)."
        confirm "Настроить балансировщик сейчас?" n && { balancer_setup || warn "Балансировщик не настроен — позже: f2d balancer setup"; }
    fi
    return 0
}

balancer_remove() {
    require_root; rw_need_api || return 1
    confirm "Убрать балансировщик (запись «Авто», шаблон и теги)? Ноды и хосты останутся" n || return 1
    local tpl; tpl=$(bal_template_uuid)
    local u rem addr port tags hid tu _p _i
    while IFS=$'\t' read -r u rem addr port tags hid tu _p _i; do
        if [[ -n "$tpl" && "$tu" == "$tpl" ]]; then rw_api DELETE "/api/hosts/$u" >/dev/null && ok "Запись «${rem}» удалена"; continue; fi
        [[ ",$tags," == *",$BAL_TAG,"* ]] && bal_set_tag "$u" "$BAL_TAG" del
        [[ ",$tags," == *",$BAL_WL_TAG,"* ]] && bal_set_tag "$u" "$BAL_WL_TAG" del
    done < <(bal_hosts)
    [[ -n "$tpl" ]] && rw_api DELETE "/api/subscription-templates/$tpl" >/dev/null && ok "Шаблон удалён"
    config_set BALANCER_TEMPLATE_UUID ""; config_set BALANCER_HOST_UUID ""
    audit_write BALANCER - - - "удалён"
}

balancer_cli() {
    case "${1:-status}" in
        setup) balancer_setup;; add) balancer_add;; add-wl|wl) balancer_add wl;;
        status) balancer_status;; remove|rm) balancer_remove;;
        *) die "balancer setup|add|add-wl|status|remove";;
    esac
}

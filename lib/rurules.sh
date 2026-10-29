#!/usr/bin/env bash
# fail2detect — российский трафик на ноде: блокировать или явно напрямую.
#
# Обычно Россию «мимо VPN» ведёт маршрутизация клиента. Но она держится на
# гео-базах с GitHub, а их могут изменить или удалить, и тогда российский трафик
# пойдёт через ноду — российские сервисы увидят её IP. Правило на самой ноде
# закрывает это с серверной стороны:
#   block   — ноду российские сайты не видят вовсе (рекомендуется для зарубежных нод)
#   direct  — явно напрямую, мимо любых других правил/цепочек профиля
#   off     — не трогать
#
# Чтобы правило не зависело от одной базы, оно собрано из нескольких слоёв:
#   * российские зоны (.ru .su .рф …) — работает без всяких баз;
#   * крупные российские сервисы на иностранных доменах (yandex.net, vk.com …);
#   * geosite:category-ru и geoip:ru — из баз, вшитых в образ ноды;
#   * по желанию — все IP-сети России прямо из реестра RIPE NCC (не GitHub).

RU_TLDS=(ru su xn--p1ai xn--p1acf xn--d1acj3b xn--80asehdb xn--80aswg xn--c1avg xn--80adxhks moscow tatar)
RU_SERVICES=(
    yandex.net yandex.com yastatic.net yandexcloud.net yandex.cloud ya.cc
    vk.com vk.me vk.cc vkontakte.com userapi.com vk-cdn.net vkuser.net vkuseraudio.net vkuservideo.net
    mycdn.me mradx.net sberbank.com 2gis.com avito.st wbstatic.net okko.tv
)
RU_RIPE_URL="https://stat.ripe.net/data/country-resource-list/data.json?resource=RU&v4_format=prefix"
RU_RIPE_CACHE="${F2D_STATE_DIR}/ru-prefixes.txt"

ru_policy_label() {
    case "$1" in
        block) echo "блокировать на ноде (российские сайты не видят IP ноды)";;
        direct) echo "напрямую с ноды (сайт видит IP ноды; мимо WARP/каскада)";;
        bypass) echo "обход: мимо VPN на устройстве (в подписке JSON)";;
        off|"") echo "не трогать";;
        *) echo "$1";;
    esac
}

# ---------- IP-сети России из RIPE ----------
# IPv4: склеить соседние и вложенные префиксы (~11 тыс. → заметно меньше)
ru_aggregate_v4() {
    awk -F'[./]' 'NF == 5 { s = (($1 * 256 + $2) * 256 + $3) * 256 + $4; printf "%.0f %.0f\n", s, s + 2 ^ (32 - $5) - 1 }' \
    | sort -n -k1,1 \
    | awk '
        function ip(n,   a, b, c) { a = int(n / 16777216); n -= a * 16777216; b = int(n / 65536); n -= b * 65536; c = int(n / 256); return a "." b "." c "." (n - c * 256) }
        function emit(s, e,   len, size) {   # диапазон → минимальный набор CIDR
            while (s <= e) {
                len = 32
                while (len > 0) {
                    size = 2 ^ (33 - len)
                    if (s % size != 0 || s + size - 1 > e) break
                    len--
                }
                print ip(s) "/" len
                s += 2 ^ (32 - len)
            }
        }
        { if (NR == 1) { cs = $1; ce = $2; next }
          if ($1 <= ce + 1) { if ($2 > ce) ce = $2 } else { emit(cs, ce); cs = $1; ce = $2 } }
        END { if (NR) emit(cs, ce) }'
}

# свежий список (v4 склеен, v6 как есть); при недоступности RIPE — прошлый из кэша
ru_ripe_prefixes() {
    local j v4 v6
    j=$(curl -fsS --max-time 40 "$RU_RIPE_URL" 2>/dev/null)
    # правдоподобность — по исходному числу префиксов (у России их ~11 тыс.)
    local raw; raw=$(jq -r '.data.resources.ipv4 | length' <<<"$j" 2>/dev/null)
    v4=$(jq -r '.data.resources.ipv4[]?' <<<"$j" 2>/dev/null | ru_aggregate_v4)
    v6=$(jq -r '.data.resources.ipv6[]?' <<<"$j" 2>/dev/null)
    if [[ "${raw:-0}" =~ ^[0-9]+$ ]] && ((raw > 1000)) && [[ -n "$v4" ]]; then
        mkdir -p "$(dirname "$RU_RIPE_CACHE")" 2>/dev/null
        { echo "$v4"; [[ -n "$v6" ]] && echo "$v6"; } > "$RU_RIPE_CACHE" 2>/dev/null
        { echo "$v4"; [[ -n "$v6" ]] && echo "$v6"; }
        return 0
    fi
    [[ -s "$RU_RIPE_CACHE" ]] && { warn "RIPE недоступен — беру прошлый список ($(date -r "$RU_RIPE_CACHE" +%F 2>/dev/null))"; cat "$RU_RIPE_CACHE"; return 0; }
    return 1
}

# ---------- правила Xray ----------
# JSON-массив правил (пустой для off). ripe: yes|no
ru_rules_json() {   # политика ripe [файл_префиксов]
    local pol="$1" ripe="${2:-no}" pfx="${3:-}" tag
    case "$pol" in block) tag=BLOCK;; direct) tag=DIRECT;; *) echo '[]'; return 0;; esac
    # Список сетей RIPE (~190 КБ) идёт в jq только через stdin: аргумент команды
    # в Linux ограничен 128 КБ («Argument list too long»).
    local doms; doms=$( { echo "geosite:category-ru"; printf 'domain:%s\n' "${RU_TLDS[@]}" "${RU_SERVICES[@]}"; } | jq -R . | jq -sc .)
    {
        echo "geoip:ru"
        [[ "$ripe" == yes && -n "$pfx" && -s "$pfx" ]] && cat "$pfx"
    } | jq -R . | jq -sc --arg t "$tag" --argjson d "$doms" \
        'map(select(. != "")) as $i | [{ruleTag: "f2d-ru-domains", domain: $d, outboundTag: $t}, {ruleTag: "f2d-ru-ip", ip: $i, outboundTag: $t}]'
}

# вставить правила в конфиг профиля: старые f2d-ru-* убрать, новые — сразу после
# блокировки частных сетей (до остальных правил, чтобы их не обходили)
ru_apply_to_config() {   # config_json rules_json
    # правила — через файловый дескриптор (могут быть больше 128 КБ)
    jq -c --slurpfile rr <(printf '%s' "$2") '$rr[0] as $r
        | .routing = (.routing // {})
        | .routing.rules = ((.routing.rules // []) | map(select((.ruleTag // "") | startswith("f2d-ru-") | not)))
        | (.routing.rules | map((.ip // []) | index("geoip:private") != null) | index(true)) as $p
        | .routing.rules = (if $p == null then $r + .routing.rules else .routing.rules[:$p + 1] + $r + .routing.rules[$p + 1:] end)
        | .outbounds = ((.outbounds // []) as $o
            | $o + ([{tag: "DIRECT", protocol: "freedom"}, {tag: "BLOCK", protocol: "blackhole"}]
                    | map(select(.tag as $t | $o | map(.tag) | index($t) | not))))' <<<"$1"
}

# текущая политика в конфиге профиля
ru_policy_of() {   # config_json → "block ripe" / "direct" / "off"
    jq -r '[.routing.rules[]? | select((.ruleTag // "") | startswith("f2d-ru-"))] as $r
        | if ($r | length) == 0 then "off"
          else (($r[0].outboundTag | ascii_downcase) + (if ([$r[] | .ip // [] | length] | max) > 100 then " ripe" else "" end)) end' <<<"$1"
}

# выбор при установке: зарубежной ноде — блок, российской (мост для белых списков) — не трогать
ask_ru_policy() {   # [код_страны]
    local def=1; [[ "${1:-}" == RU ]] && def=3
    [[ -n "${NODE_RU_POLICY_SET:-}" ]] && return 0
    echo
    echo "  ${C_BOLD}Российский трафик через ноду${C_RESET}"
    echo "  Если у клиента сломается маршрутизация (гео-базы на GitHub изменят или удалят),"
    echo "  российские сайты пойдут через ноду и увидят её IP. Правило на ноде это закрывает."
    echo "   1. блокировать (рекомендуется для зарубежной ноды: российские сайты не увидят её IP)"
    echo "   2. напрямую с ноды (сайт увидит IP ноды — только против WARP/каскада в профиле)"
    echo "   3. не трогать${def:+$([[ $def == 3 ]] && echo " (нода в России — например, мост для белых списков)")}"
    ask "Вариант" "$def"
    case "$REPLY" in 1) NODE_RU_POLICY=block;; 2) NODE_RU_POLICY=direct;; *) NODE_RU_POLICY=off;; esac
    NODE_RU_RIPE=no
    if [[ "$NODE_RU_POLICY" != off ]]; then
        confirm "Добавить все IP-сети России из реестра RIPE (не зависит от гео-баз GitHub)?" y && NODE_RU_RIPE=yes
    fi
    [[ "$NODE_RU_POLICY" == block ]] && info "Чтобы российское шло мимо VPN с домашнего IP пользователя — обход в подписке: f2d node ru-traffic bypass"
    NODE_RU_POLICY_SET=1
    config_set NODE_RU_POLICY "$NODE_RU_POLICY" >/dev/null 2>&1
    config_set NODE_RU_RIPE "$NODE_RU_RIPE" >/dev/null 2>&1
}

# правила для нового профиля (profile_config): по выбору NODE_RU_POLICY/NODE_RU_RIPE
ru_rules_for_profile() {
    local pfx=""
    if [[ "${NODE_RU_RIPE:-no}" == yes && "${NODE_RU_POLICY:-off}" != off ]]; then
        pfx=$(mktemp); ru_ripe_prefixes > "$pfx" 2>/dev/null || { warn "Список RIPE не получен — только geoip:ru и домены"; : > "$pfx"; }
    fi
    ru_rules_json "${NODE_RU_POLICY:-off}" "${NODE_RU_RIPE:-no}" "$pfx"
    [[ -n "$pfx" ]] && rm -f "$pfx"
    return 0
}

# ---------- «Обход»: российское мимо VPN на устройстве ----------
# Нода не может отправить пакет «с домашнего IP» — туда трафик приходит уже из
# туннеля. Настоящий обход делает клиент, и правило ему можно отдать через
# подписку: в JSON-шаблоны (XRAY_JSON) панели. Панель ставит выходы серверов
# первыми, а «direct» шаблона — следом, поэтому правило «российское → direct»
# ведёт такой трафик мимо VPN. Happ в режиме JSON свою маршрутизацию не
# применяет — работают только правила из конфига, как раз это.
#   * зоны .ru .su .рф … и российские сервисы на иностранных доменах — без баз;
#   * geoip:ru — эта категория есть в любых geoip.dat;
#   * geosite:category-ru не берём: если её нет в гео-файлах приложения,
#     Xray на устройстве не запустится;
#   * сети RIPE — по желанию: подписка JSON несёт конфиг на каждый сервер,
#     и ~190 КБ списка добавятся к каждому.
ru_bypass_rules_json() {   # ripe(yes|no) [файл_префиксов]
    local doms; doms=$(printf 'domain:%s\n' "${RU_TLDS[@]}" "${RU_SERVICES[@]}" | jq -R . | jq -sc .)
    {
        echo "geoip:ru"
        [[ "${1:-no}" == yes && -n "${2:-}" && -s "$2" ]] && cat "$2"
    } | jq -R . | jq -sc --argjson d "$doms" \
        'map(select(. != "")) as $i | [{ruleTag: "f2d-ru-bypass-domains", domain: $d, outboundTag: "direct"},
                                       {ruleTag: "f2d-ru-bypass-ip", ip: $i, outboundTag: "direct"}]'
}

# вставить в шаблон подписки: старые f2d-ru-bypass-* убрать, новые — первыми
# (до правила балансировщика «всё → auto»), выход direct — добавить, если нет
ru_bypass_apply() {   # template_json rules_json ('[]' — убрать)
    jq -c --slurpfile rr <(printf '%s' "$2") '$rr[0] as $r
        | .routing = (.routing // {})
        | .routing.rules = ($r + ((.routing.rules // []) | map(select((.ruleTag // "") | startswith("f2d-ru-bypass-") | not))))
        | if ($r | length) > 0 and ((.outbounds // []) | map(.tag) | index("direct") | not)
          then .outbounds = ((.outbounds // []) + [{tag: "direct", protocol: "freedom"}]) else . end' <<<"$1"
}

ru_bypass_of() {   # template_json → "bypass ripe" / "bypass" / "off"
    jq -r '[.routing.rules[]? | select((.ruleTag // "") | startswith("f2d-ru-bypass-"))] as $r
        | if ($r | length) == 0 then "off" else "bypass" + (if ([$r[] | .ip // [] | length] | max) > 100 then " ripe" else "" end) end' <<<"$1"
}

# JSON-шаблоны подписки: uuid, имя
_ru_templates() {
    rw_api GET /api/subscription-templates | jq -c '.response.templates[]? | select(.templateType == "XRAY_JSON") | {uuid, name}'
}

node_ru_bypass() {   # on|off|status|update [--ripe|--no-ripe] [--template ИМЯ|№ …] [--all]
    local act="${1:-status}" ripe="" all=0; shift || true
    local -a sel=()
    while (($#)); do
        case "$1" in
            --ripe) ripe=yes;; --no-ripe) ripe=no;; --all) all=1;;
            --template|-t|--profile|-p) sel+=("${2:?имя шаблона}"); shift;;
            *) die "node ru-traffic bypass|bypass-off [--ripe] [--template ИМЯ … | --all]";;
        esac; shift
    done
    rw_need_api || return 1
    local tpls; tpls=$(_ru_templates)
    if [[ -z "$tpls" ]]; then
        # для status/update это не ошибка — обходу просто негде быть
        [[ "$act" == status || "$act" == update ]] && return 0
        err "В панели нет JSON-шаблонов подписки (XRAY_JSON)"; return 1
    fi
    if [[ "$act" == status ]]; then
        title "Обход в подписке (JSON-шаблоны)"
        local p u n t pol i=0
        while IFS= read -r p; do
            i=$((i + 1)); u=$(jq -r .uuid <<<"$p"); n=$(jq -r .name <<<"$p")
            t=$(rw_api GET "/api/subscription-templates/$u" | jq -c '.response.templateJson // {}')
            pol=$(ru_bypass_of "$t")
            printf '  %s%2d.%s %-28s %s\n' "$C_YELLOW" "$i" "$C_RESET" "$n" \
                "$([[ "$pol" == off ]] && echo "нет" || echo "обход$([[ "$pol" == *ripe* ]] && echo " + сети RIPE")")"
        done <<<"$tpls"
        local jb; jb=$(bal_json_base 2>/dev/null)
        [[ "$jb" == false ]] && echo "  ${C_GRAY}JSON отдаётся только клиентам, которые сами его просят: «Отдавать JSON на базовом пути подписки» выключено${C_RESET}"
        return 0
    fi
    require_root
    [[ "$act" == update && $all == 0 && ${#sel[@]} -eq 0 ]] && all=1
    local picked
    picked=$(RU_PICK_WHAT="шаблонов" RU_PICK_FLAG=template RU_PICK_HINT="Обычно — Default (все хосты) и «fail2detect Auto»." \
        _ru_pick_profiles "$tpls" "$all" "${sel[@]}") || return 1
    local pfx; pfx=$(mktemp)
    local p u n t cur new rules r use_ripe done_names=()
    while IFS= read -r p; do
        u=$(jq -r .uuid <<<"$p"); n=$(jq -r .name <<<"$p")
        grep -qxF "$u" <<<"$picked" || continue
        t=$(rw_api GET "/api/subscription-templates/$u" | jq -c '.response.templateJson // {}')
        cur=$(ru_bypass_of "$t")
        use_ripe="$ripe"
        case "$act" in
            on) [[ -z "$use_ripe" ]] && { [[ "$cur" == *ripe* ]] && use_ripe=yes || use_ripe=no; };;
            update) [[ "$cur" == off ]] && continue; [[ "$cur" == *ripe* ]] && use_ripe=yes || use_ripe=no;;
            off) use_ripe=no;;
        esac
        if [[ "$use_ripe" == yes && ! -s "$pfx" ]]; then
            info "Скачиваю IP-сети России из RIPE…"
            ru_ripe_prefixes > "$pfx" || { warn "RIPE недоступен — без списка сетей"; use_ripe=no; }
        fi
        if [[ "$act" == off ]]; then rules='[]'; else rules=$(ru_bypass_rules_json "$use_ripe" "$pfx"); fi
        new=$(ru_bypass_apply "$t" "$rules")
        r=$(rw_api PATCH /api/subscription-templates "$(jq -c --arg u "$u" '{uuid: $u, templateJson: .}' <<<"$new")")
        if jq -e '.response.uuid' >/dev/null 2>&1 <<<"$r"; then
            if [[ "$act" == off ]]; then ok "«${n}»: обход убран"
            else ok "«${n}»: обход$([[ "$use_ripe" == yes ]] && echo " + сети RIPE") — клиенты получат его при обновлении подписки"; fi
            done_names+=("$n")
        elif [[ -z "$r" ]]; then err "«${n}» не обновлён: панель не ответила${RW_API_ERROR:+ ($RW_API_ERROR)}"
        else err "«${n}» не обновлён: $(jq -c '.message // .' <<<"$r" 2>/dev/null)"; fi
    done <<<"$tpls"
    rm -f "$pfx"
    if [[ "$act" == on && ${#done_names[@]} -gt 0 && "$(bal_json_base 2>/dev/null)" == false ]]; then
        info "Обход работает у клиентов, получающих подписку JSON. Happ и INCY по обычной ссылке получают JSON,"
        info "если включено «Отдавать JSON на базовом пути подписки» (его включает f2d balancer setup)."
    fi
    audit_write RU_BYPASS - - - "$act${ripe:+ ripe=$ripe}: ${done_names[*]:-ничего}"
    return 0
}

# ---------- работающие ноды: через API панели ----------
# выбрать профили: по именам/номерам из аргументов, --all, или спросить.
# Профили мостов (белые списки) и другие, которые трогать нельзя, просто не выбирайте.
_ru_pick_profiles() {   # profiles_jsonl all(0|1) имя_или_номер…  → uuid по строке
    local profiles="$1" all="$2"; shift 2
    local what="${RU_PICK_WHAT:-профилей}" hint="${RU_PICK_HINT:-Профили мостов (белые списки) не выбирайте.}"
    local -a names=() uuids=(); local p
    while IFS= read -r p; do names+=("$(jq -r .name <<<"$p")"); uuids+=("$(jq -r .uuid <<<"$p")"); done <<<"$profiles"
    if [[ "$all" == 1 ]]; then printf '%s\n' "${uuids[@]}"; return 0; fi
    local -a want=("$@")
    if ((${#want[@]} == 0)); then
        [[ -t 0 ]] || { err "Укажите ${what%ей}и: --${RU_PICK_FLAG:-profile} ИМЯ (можно несколько) или --all"; return 1; }
        echo >&2
        echo "  ${C_BOLD}Для каких ${what}?${C_RESET} $hint" >&2
        local i; for i in "${!names[@]}"; do printf '  %s%2d.%s %s\n' "$C_YELLOW" $((i + 1)) "$C_RESET" "${names[i]}" >&2; done
        ask "Номера через пробел или запятую (all — все, Enter — отмена)" ""
        [[ -n "$REPLY" ]] || { info "Отменено"; return 1; }
        [[ "$REPLY" == all || "$REPLY" == все ]] && { printf '%s\n' "${uuids[@]}"; return 0; }
        read -r -a want <<<"${REPLY//,/ }"
    fi
    local w j found out=()
    for w in "${want[@]}"; do
        found=""
        if [[ "$w" =~ ^[0-9]+$ ]] && ((w >= 1 && w <= ${#uuids[@]})); then found="${uuids[w - 1]}"
        else for j in "${!names[@]}"; do [[ "${names[j]}" == "$w" ]] && { found="${uuids[j]}"; break; }; done; fi
        [[ -n "$found" ]] || { err "Нет профиля «${w}»"; return 1; }
        [[ " ${out[*]} " == *" $found "* ]] || out+=("$found")
    done
    printf '%s\n' "${out[@]}"
}

node_ru_traffic() {   # block|direct|off|status|update [--ripe|--no-ripe] [--profile ИМЯ|№ …] [--all]
    local act="${1:-status}" ripe="" all=0 ; shift || true
    # обход живёт в шаблонах подписки, а не в профилях нод
    case "$act" in
        bypass|обход) node_ru_bypass on "$@"; return;;
        bypass-off|unbypass) node_ru_bypass off "$@"; return;;
        block|direct|off|status|update) ;;
        *) die "node ru-traffic bypass|block|direct|off|bypass-off|status|update [--ripe|--no-ripe] [--profile ИМЯ … | --all]";;
    esac
    local -a sel=()
    while (($#)); do
        case "$1" in
            --ripe) ripe=yes;; --no-ripe) ripe=no;; --all) all=1;;
            --profile|-p) sel+=("${2:?имя профиля}"); shift;;
            *) die "node ru-traffic block|direct|off|status|update [--ripe|--no-ripe] [--profile ИМЯ … | --all]";;
        esac; shift
    done
    rw_need_api || return 1
    local profiles; profiles=$(rw_api GET /api/config-profiles | jq -c '.response.configProfiles[]? | {uuid, name}')
    [[ -n "$profiles" ]] || die "В панели нет профилей конфигурации"
    if [[ "$act" == status ]]; then
        title "Российский трафик на нодах"
        local p u n cfg pol i=0
        while IFS= read -r p; do
            i=$((i + 1)); u=$(jq -r .uuid <<<"$p"); n=$(jq -r .name <<<"$p")
            cfg=$(rw_api GET "/api/config-profiles/$u" | jq -c '.response.config')
            pol=$(ru_policy_of "$cfg")
            printf '  %s%2d.%s %-28s %s%s\n' "$C_YELLOW" "$i" "$C_RESET" "$n" "$(ru_policy_label "${pol%% *}")" "$([[ "$pol" == *ripe* ]] && echo " + сети RIPE")"
        done <<<"$profiles"
        node_ru_bypass status
        return 0
    fi
    require_root
    # update ничего не меняет по сути (только освежает сети RIPE) — без выбора берёт все профили с правилом
    local picked
    if [[ "$act" == update && $all == 0 && ${#sel[@]} -eq 0 ]]; then all=1; fi
    picked=$(_ru_pick_profiles "$profiles" "$all" "${sel[@]}") || return 1
    local pfx=""; pfx=$(mktemp)
    local p u n cfg cur new rules pol r done_names=()
    while IFS= read -r p; do
        u=$(jq -r .uuid <<<"$p"); n=$(jq -r .name <<<"$p")
        grep -qxF "$u" <<<"$picked" || continue
        cfg=$(rw_api GET "/api/config-profiles/$u" | jq -c '.response.config')
        cur=$(ru_policy_of "$cfg")
        pol="$act"; local use_ripe="$ripe"
        if [[ "$act" == update ]]; then
            [[ "$cur" == off ]] && continue
            pol="${cur%% *}"; [[ "$cur" == *ripe* ]] && use_ripe=yes
        fi
        [[ -z "$use_ripe" ]] && { [[ "$cur" == *ripe* || "${NODE_RU_RIPE:-}" == yes ]] && use_ripe=yes || use_ripe=no; }
        if [[ "$use_ripe" == yes && ! -s "$pfx" ]]; then
            info "Скачиваю IP-сети России из RIPE…"
            ru_ripe_prefixes > "$pfx" || { warn "RIPE недоступен — без списка сетей"; use_ripe=no; }
            [[ -s "$pfx" ]] && ok "Сетей России: $(wc -l < "$pfx" | tr -d ' ') (IPv4 склеены)"
        fi
        rules=$(ru_rules_json "$pol" "$use_ripe" "$pfx")
        new=$(ru_apply_to_config "$cfg" "$rules")
        r=$(rw_api PATCH /api/config-profiles "$(rw_profile_body "$u" <<<"$new")")
        if jq -e '.response.uuid' >/dev/null <<<"$r"; then
            ok "«${n}»: $(ru_policy_label "$pol")$([[ "$use_ripe" == yes && "$pol" != off ]] && echo " + сети RIPE") — панель разошлёт конфиг на ноды"
            done_names+=("$n")
        else
            if [[ -z "$r" ]]; then err "«${n}» не обновлён: панель не ответила${RW_API_ERROR:+ ($RW_API_ERROR)} — повторите для этого профиля: f2d node ru-traffic $pol --profile \"$n\""
            else err "«${n}» не обновлён: $(jq -c '.message // .' <<<"$r" 2>/dev/null)"; fi
        fi
    done <<<"$profiles"
    rm -f "$pfx"
    # update освежает сети RIPE и в обходе (шаблоны подписки)
    [[ "$act" == update ]] && node_ru_bypass update --all
    audit_write RU_TRAFFIC - - - "$act${ripe:+ ripe=$ripe}: ${done_names[*]:-ничего}"
    return 0
}

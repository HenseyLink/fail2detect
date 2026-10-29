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
        block) echo "блокировать (российские сайты не видят ноду)";;
        direct) echo "напрямую (явно, мимо других правил)";;
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
    local doms ips
    doms=$( { echo "geosite:category-ru"; printf 'domain:%s\n' "${RU_TLDS[@]}" "${RU_SERVICES[@]}"; } | jq -R . | jq -sc .)
    if [[ "$ripe" == yes && -n "$pfx" && -s "$pfx" ]]; then ips=$( { echo "geoip:ru"; cat "$pfx"; } | jq -R . | jq -sc 'map(select(. != ""))')
    else ips='["geoip:ru"]'; fi
    jq -nc --arg t "$tag" --argjson d "$doms" --argjson i "$ips" \
        '[{ruleTag: "f2d-ru-domains", domain: $d, outboundTag: $t}, {ruleTag: "f2d-ru-ip", ip: $i, outboundTag: $t}]'
}

# вставить правила в конфиг профиля: старые f2d-ru-* убрать, новые — сразу после
# блокировки частных сетей (до остальных правил, чтобы их не обходили)
ru_apply_to_config() {   # config_json rules_json
    jq -c --argjson r "$2" '
        .routing = (.routing // {})
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
    echo "   1. блокировать (рекомендуется для зарубежной ноды)"
    echo "   2. напрямую"
    echo "   3. не трогать${def:+$([[ $def == 3 ]] && echo " (нода в России — например, мост для белых списков)")}"
    ask "Вариант" "$def"
    case "$REPLY" in 1) NODE_RU_POLICY=block;; 2) NODE_RU_POLICY=direct;; *) NODE_RU_POLICY=off;; esac
    NODE_RU_RIPE=no
    if [[ "$NODE_RU_POLICY" != off ]]; then
        confirm "Добавить все IP-сети России из реестра RIPE (не зависит от гео-баз GitHub)?" y && NODE_RU_RIPE=yes
    fi
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

# ---------- работающие ноды: через API панели ----------
node_ru_traffic() {   # block|direct|off|status|update [--ripe|--no-ripe] [--profile ИМЯ]
    local act="${1:-status}" ripe="" only="" ; shift || true
    while (($#)); do case "$1" in --ripe) ripe=yes;; --no-ripe) ripe=no;; --profile) only="${2:?имя}"; shift;; esac; shift; done
    case "$act" in block|direct|off|status|update) ;; *) die "node ru-traffic block|direct|off|status|update [--ripe|--no-ripe] [--profile ИМЯ]";; esac
    rw_need_api || return 1
    local profiles; profiles=$(rw_api GET /api/config-profiles | jq -c '.response.configProfiles[]? | {uuid, name}')
    [[ -n "$profiles" ]] || die "В панели нет профилей конфигурации"
    if [[ "$act" == status ]]; then
        title "Российский трафик на нодах"
        local p u n cfg pol
        while IFS= read -r p; do
            u=$(jq -r .uuid <<<"$p"); n=$(jq -r .name <<<"$p")
            cfg=$(rw_api GET "/api/config-profiles/$u" | jq -c '.response.config')
            pol=$(ru_policy_of "$cfg")
            printf '  %-28s %s%s\n' "$n" "$(ru_policy_label "${pol%% *}")" "$([[ "$pol" == *ripe* ]] && echo " + сети RIPE")"
        done <<<"$profiles"
        return 0
    fi
    require_root
    local pfx=""; pfx=$(mktemp)
    local p u n cfg cur new rules pol r
    while IFS= read -r p; do
        u=$(jq -r .uuid <<<"$p"); n=$(jq -r .name <<<"$p")
        [[ -n "$only" && "$n" != "$only" ]] && continue
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
        r=$(rw_api PATCH /api/config-profiles "$(jq -nc --arg u "$u" --argjson c "$new" '{uuid: $u, config: $c}')")
        if jq -e '.response.uuid' >/dev/null <<<"$r"; then
            ok "«${n}»: $(ru_policy_label "$pol")$([[ "$use_ripe" == yes && "$pol" != off ]] && echo " + сети RIPE") — панель разошлёт конфиг на ноды"
        else
            err "«${n}» не обновлён: $(jq -c '.message // .' <<<"$r" 2>/dev/null)"
        fi
    done <<<"$profiles"
    rm -f "$pfx"
    [[ "$act" != update ]] && config_set NODE_RU_POLICY "$act" >/dev/null
    audit_write RU_TRAFFIC - - - "$act${ripe:+ ripe=$ripe}${only:+ профиль $only}"
    return 0
}

#!/usr/bin/env bash
# fail2detect — обновления: самого fail2detect и Remnawave (панель, нода, подписка).
#
# Remnawave обновляется независимо от версии fail2detect: берутся свежие образы
# с Docker Hub по тегу из docker-compose.yml (latest, 2 и т.п.), версии
# сравниваются с последними релизами на GitHub.

F2D_UPDATE_CACHE="${F2D_STATE_DIR}/update-check"
F2D_UPDATE_TTL=21600   # 6 часов: меню не ходит в сеть при каждом запуске

# ---------- версии ----------
# a > b? Сравнение x.y.z; при равных числах релиз старше «-beta».
version_gt() {
    local a="${1#v}" b="${2#v}" an bn i x y
    an="${a%%-*}"; bn="${b%%-*}"
    IFS=. read -r -a x <<<"$an"; IFS=. read -r -a y <<<"$bn"
    for i in 0 1 2 3; do
        (( 10#${x[i]:-0} > 10#${y[i]:-0} )) && return 0
        (( 10#${x[i]:-0} < 10#${y[i]:-0} )) && return 1
    done
    [[ "$a" != *-* && "$b" == *-* ]] && return 0
    [[ "$a" == *-* && "$b" == *-* && "$a" > "$b" ]] && return 0
    return 1
}

# последняя версия в репозитории (из lib/common.sh ветки main)
f2d_remote_version() {
    curl -fsS --connect-timeout 3 --max-time 6 "https://raw.githubusercontent.com/${F2D_REPO}/main/lib/common.sh" 2>/dev/null \
        | sed -nE 's/^F2D_VERSION="([^"]+)".*/\1/p' | head -1
}

# версия, до которой можно обновиться (пусто — обновлений нет). С кэшем.
f2d_update_available() {   # [--force]
    [[ "${UPDATE_CHECK:-yes}" == yes || "${1:-}" == --force ]] || return 1
    local now_ts v="" ts=0
    now_ts=$(date +%s)
    [[ -r "$F2D_UPDATE_CACHE" ]] && read -r ts v < "$F2D_UPDATE_CACHE"
    if [[ "${1:-}" == --force ]] || (( now_ts - ${ts:-0} > F2D_UPDATE_TTL )); then
        v=$(f2d_remote_version)
        [[ -n "$v" ]] && { mkdir -p "$F2D_STATE_DIR" 2>/dev/null; printf '%s %s\n' "$now_ts" "$v" > "$F2D_UPDATE_CACHE" 2>/dev/null; }
    fi
    [[ -n "$v" ]] && version_gt "$v" "$F2D_VERSION" && { echo "$v"; return 0; }
    return 1
}

# обновить и перезапустить меню уже новой версией
f2d_self_update() {
    require_root
    local v; v=$(f2d_update_available --force) || { ok "У вас последняя версия fail2detect ($F2D_VERSION)"; return 0; }
    confirm "Обновить fail2detect $F2D_VERSION → $v?" y || return 0
    cmd_update || { err "Обновление не удалось"; return 1; }
    rm -f "$F2D_UPDATE_CACHE"
    if [[ "${1:-}" == --menu ]]; then
        info "Перезапускаю меню новой версией…"; sleep 1
        exec "$F2D_BIN"
    fi
}

# ---------- Remnawave ----------
# компоненты на этом сервере: имя<TAB>каталог compose<TAB>сервис<TAB>репозиторий GitHub
rw_components() {
    has_panel && printf 'panel\t%s\tremnawave\tremnawave/backend\n' "$RW_PANEL_DIR"
    local nd; nd=$(node_dir)
    [[ -n "$nd" ]] && printf 'node\t%s\tremnanode\tremnawave/node\n' "$nd"
    if [[ -f "$RW_SUB_DIR/docker-compose.yml" ]]; then
        printf 'sub\t%s\tremnawave-subscription-page\tremnawave/subscription-page\n' "$RW_SUB_DIR"
    elif compose_has_service "$RW_PANEL_DIR" remnawave-subscription-page; then
        printf 'sub\t%s\tremnawave-subscription-page\tremnawave/subscription-page\n' "$RW_PANEL_DIR"
    fi
}

rw_component_label() {
    case "$1" in panel) echo "Панель";; node) echo "Нода";; sub) echo "Страница подписки";; *) echo "$1";; esac
}

# образ сервиса из compose (как написан: remnawave/backend:2)
rw_service_image() {   # dir service
    local img
    img=$( (cd "$1" && docker compose config --format json 2>/dev/null) | jq -r --arg s "$2" '.services[$s].image // empty' 2>/dev/null)
    # старый docker compose без --format json — читаем файл
    [[ -n "$img" ]] || img=$(compose_service_image "$1/docker-compose.yml" "$2")
    echo "$img"
}

compose_service_image() {   # file service
    awk -v s="$2" '
        /^[^[:space:]#]/ { in_svc = ($0 ~ /^services:/) }
        in_svc && match($0, /^[[:space:]]+[A-Za-z0-9_.-]+:[[:space:]]*$/) {
            name = $0; gsub(/[[:space:]:]/, "", name)
            if (ind == "" || match($0, "^" ind "[A-Za-z0-9_.-]")) { ind = substr($0, 1, match($0, /[^[:space:]]/) - 1); cur = name }
        }
        cur == s && /^[[:space:]]+image:/ { sub(/^[[:space:]]+image:[[:space:]]*/, ""); gsub(/["\047]/, ""); print; exit }
    ' "$1"
}

# версия запущенного образа: метка OCI, иначе дата сборки
rw_image_version() {   # image
    local v
    v=$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.version"}}' "$1" 2>/dev/null)
    [[ -n "$v" && "$v" != "<no value>" ]] && { echo "${v#v}"; return; }
    v=$(docker image inspect -f '{{.Created}}' "$1" 2>/dev/null | cut -c1-10)
    [[ -n "$v" ]] && echo "сборка $v" || echo "?"
}

rw_image_id() { docker image inspect -f '{{.Id}}' "$1" 2>/dev/null; }

# последний релиз на GitHub (без «v»)
rw_latest_release() {   # owner/repo
    local v
    v=$(curl -fsS --connect-timeout 4 --max-time 8 "https://api.github.com/repos/$1/releases/latest" 2>/dev/null | jq -r '.tag_name // empty' 2>/dev/null)
    # без GitHub-релизов — по тегам
    [[ -n "$v" ]] || v=$(curl -fsS --connect-timeout 4 --max-time 8 "https://api.github.com/repos/$1/tags?per_page=30" 2>/dev/null \
        | jq -r '[.[].name | select(test("^v?[0-9]+\\.[0-9]+\\.[0-9]+$"))] | first // empty' 2>/dev/null)
    echo "${v#v}"
}

rw_versions() {
    title "Версии Remnawave на этом сервере"
    local comp dir svc repo img cur latest mark n=0
    while IFS=$'\t' read -r comp dir svc repo; do
        n=$((n + 1))
        img=$(rw_service_image "$dir" "$svc"); cur=$(rw_image_version "$img"); latest=$(rw_latest_release "$repo")
        mark="${C_GREEN}актуальна${C_RESET}"
        if [[ -n "$latest" && "$cur" =~ ^[0-9] ]] && version_gt "$latest" "$cur"; then mark="${C_YELLOW}есть ${latest}${C_RESET}"
        elif [[ -z "$latest" ]]; then mark="${C_GRAY}релиз не узнать${C_RESET}"
        elif ! [[ "$cur" =~ ^[0-9] ]]; then mark="${C_GRAY}последний релиз ${latest}${C_RESET}"; fi
        printf '  %-18s %-34s %-16s %s\n' "$(rw_component_label "$comp")" "${img:-?}" "$cur" "$mark"
    done < <(rw_components)
    ((n)) || info "Панели, ноды и страницы подписки на этом сервере нет"
    # ноды на других серверах — их версии видит панель
    if has_panel && F2D_NO_PROMPT=1 rw_token >/dev/null 2>&1; then
        local nodes; nodes=$(F2D_API_MAX_TIME=10 rw_api GET /api/nodes 2>/dev/null | jq -r '.response[]? |
            [.name, (.nodeVersion // "?"), (.xrayVersion // "?"), (if .isConnected then "подключена" else "нет связи" end)] | @tsv' 2>/dev/null)
        if [[ -n "$nodes" ]]; then
            echo; echo "  ${C_BOLD}Ноды в панели${C_RESET} (обновляются на своих серверах: f2d rw update node)"
            local name nv xv st
            while IFS=$'\t' read -r name nv xv st; do
                printf '  %-24s нода %-10s Xray %-10s %s\n' "${name:0:24}" "$nv" "$xv" "$st"
            done <<<"$nodes"
        fi
    fi
}

# дамп базы перед обновлением панели
rw_backup_db() {
    docker ps --format '{{.Names}}' | grep -qx remnawave-db || return 0
    install -d -m 700 "$F2D_BACKUP_DIR"
    local dump; dump="$F2D_BACKUP_DIR/remnawave-db-$(date +%Y%m%d-%H%M%S).sql.gz"
    if docker exec remnawave-db pg_dumpall -U postgres 2>/dev/null | gzip > "$dump" && (( $(gzip -dc "$dump" | head -c 100 | wc -c) > 0 )); then
        chmod 600 "$dump"; ok "Дамп базы: $dump"
    else
        rm -f "$dump"; err "Дамп базы не получился"
        confirm "Обновлять панель БЕЗ дампа базы?" n || return 1
    fi
}

# образ закреплён на точной версии (remnawave/node:2.1.3) — pull его не обновит
rw_unpin_image() {   # dir service image repo
    local tag="${3##*:}" latest
    [[ "$3" == *:* && "$tag" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+ ]] || return 0
    latest=$(rw_latest_release "$4")
    [[ -n "$latest" ]] && version_gt "$latest" "${tag#v}" || return 0
    warn "Образ закреплён на версии $tag, последний релиз — $latest"
    confirm "Переключить на $latest?" y || return 0
    local f="$1/docker-compose.yml"
    cp -p "$f" "$f.f2d-bak"
    local tmp; tmp=$(mktemp)
    sed "s|image:[[:space:]]*${3//./\\.}[[:space:]]*\$|image: ${3%:*}:${latest}|" "$f" > "$tmp" && cat "$tmp" > "$f"; rm -f "$tmp"
    grep -q "image: ${3%:*}:${latest}" "$f" && ok "docker-compose.yml: ${3%:*}:${latest} (копия: $f.f2d-bak)" || { mv -f "$f.f2d-bak" "$f"; warn "Тег не заменён — оставляю как есть"; }
}

# обновить один компонент; 0 — обновлён или уже свежий
rw_update_one() {   # comp dir svc repo
    local comp="$1" dir="$2" svc="$3" repo="$4" label img before after old new
    label=$(rw_component_label "$comp")
    img=$(rw_service_image "$dir" "$svc")
    [[ -n "$img" ]] || { err "$label: не найден образ сервиса $svc в $dir"; return 1; }
    rw_unpin_image "$dir" "$svc" "$img" "$repo"
    img=$(rw_service_image "$dir" "$svc")
    before=$(rw_image_id "$img"); old=$(rw_image_version "$img")
    info "$label: скачиваю свежие образы ($img)…"
    (cd "$dir" && docker compose pull -q) || { err "$label: docker compose pull не удался"; return 1; }
    after=$(rw_image_id "$img"); new=$(rw_image_version "$img")
    if [[ "$before" == "$after" ]]; then ok "$label: уже последняя версия ($old)"; return 0; fi
    [[ "$comp" == panel ]] && { rw_backup_db || return 1; }
    (cd "$dir" && docker compose up -d --remove-orphans >/dev/null 2>&1) || { err "$label: docker compose up не удался (cd $dir && docker compose logs)"; return 1; }
    local i run=""
    for i in $(seq 1 20); do
        run=$(docker inspect -f '{{.State.Running}}' "$svc" 2>/dev/null); [[ "$run" == true ]] && break; sleep 2
    done
    [[ "$run" == true ]] || { err "$label: контейнер $svc не запустился — cd $dir && docker compose logs $svc"; return 1; }
    ok "$label: $old → $new"
    audit_write UPDATE - - - "Remnawave $comp: $old → $new"
    docker image prune -f >/dev/null 2>&1 || true
    # у ноды порты Xray могли смениться вместе с конфигом — фаервол подтянет
    [[ "$comp" == node ]] && xray_ports_sync >/dev/null 2>&1
    return 0
}

rw_update() {   # panel|node|sub|all
    require_root; have docker || die "Docker не установлен"
    local want="${1:-all}" comp dir svc repo found=0 rc=0
    case "$want" in panel|node|sub|all) ;; *) die "rw update panel|node|sub|all";; esac
    title "Обновление Remnawave"
    while IFS=$'\t' read -r comp dir svc repo; do
        [[ "$want" == all || "$want" == "$comp" ]] || continue
        found=1
        rw_update_one "$comp" "$dir" "$svc" "$repo" || rc=1
    done < <(rw_components)
    ((found)) || { info "На этом сервере нет: $([[ $want == all ]] && echo "Remnawave" || rw_component_label "$want")"; return 1; }
    return "$rc"
}

rw_cli() {
    case "${1:-versions}" in
        versions|status|version) rw_versions;;
        update|upgrade) rw_update "${2:-all}";;
        *) die "rw versions | rw update [panel|node|sub|all]";;
    esac
}

menu_updates() {
    banner
    echo "  ${C_BOLD}Обновления${C_RESET}"
    local v; v=$(f2d_update_available) && echo "  ${C_YELLOW}Доступен fail2detect $v${C_RESET}"
    menu_item 1 "Обновить fail2detect$([[ -n "$v" ]] && echo " до $v" || echo " (проверить)")"
    menu_item 2 "Версии Remnawave (панель, ноды, подписка)"
    menu_item 3 "Обновить всё Remnawave на этом сервере"
    menu_item 4 "Обновить только панель"
    menu_item 5 "Обновить только ноду"
    menu_item 6 "Обновить только страницу подписки"
    menu_item 7 "Проверять обновления fail2detect при запуске: ${UPDATE_CHECK:-yes}"
    menu_item 0 "Назад"
    ask "Выбор" ""
    case "$REPLY" in
        1) f2d_self_update --menu;; 2) rw_versions;; 3) rw_update all;; 4) rw_update panel;;
        5) rw_update node;; 6) rw_update sub;;
        7) config_set UPDATE_CHECK "$([[ ${UPDATE_CHECK:-yes} == yes ]] && echo no || echo yes)"; return;;
        *) return;;
    esac
    pause
}

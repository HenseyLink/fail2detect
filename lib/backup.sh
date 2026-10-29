#!/usr/bin/env bash
# fail2detect — резервные копии панели Remnawave и перенос на другой сервер.
#
# Копия — один файл panel-<сервер>-<время>.tar (или .tar.enc, если с паролем):
#   manifest.json   что внутри, откуда, версии
#   db.sql.gz       pg_dumpall базы панели (пользователи, подписки, ноды, хосты, ключи)
#   files.tar.gz    /opt/remnawave (.env с секретами, compose), страница подписки,
#                   нода на этом же сервере, настройки fail2detect, сайт, сертификаты
#
# Ключи нод (SECRET_KEY) подписаны ключами из базы, поэтому после восстановления
# прежние ноды принимают новую панель — нужно только разрешить им её новый IP
# (fail2detect node panel-ip <IP> на каждой ноде; перенос предлагает сделать это сам).

: "${F2D_BACKUP_DIR:=${F2D_STATE_DIR}/backup}"
RW_DB_CONTAINER="${RW_DB_CONTAINER:-remnawave-db}"
# что копировать (если есть); для тестов — F2D_BACKUP_PATHS и F2D_BACKUP_ROOT
BACKUP_PATHS=(/opt/remnawave /opt/subscription /opt/remnanode /opt/fail2detect-web /etc/fail2detect /var/www/fail2detect /usr/local/remnawave_reverse)
# ключи fail2detect.conf, которые переезжают вместе с панелью (фаервол нового сервера — его собственный)
BACKUP_CONF_KEYS=(RW_API_URL RW_API_TOKEN RW_API_COOKIE TG_BOT_TOKEN TG_CHAT_ID CERT_METHOD CERT_EMAIL ABUSEIPDB_KEY
    BALANCER_TEMPLATE_UUID BALANCER_HOST_UUID BALANCER_JSON_BASE_SET BACKUP_KEEP BACKUP_TELEGRAM BACKUP_SCHEDULE)
BACKUP_TG_LIMIT=$((45 * 1024 * 1024))   # Telegram-боты принимают файлы до 50 МБ

_bk_root() { echo "${F2D_BACKUP_ROOT:-}"; }
_bk_env_get() { [[ -f "$1" ]] && grep -m1 "^$2=" "$1" | cut -d= -f2- | sed 's/^"//; s/"$//'; }
bk_db_user() { local u; u=$(_bk_env_get "$(_bk_root)$RW_PANEL_DIR/.env" POSTGRES_USER); echo "${u:-postgres}"; }
_bk_human() { awk -v b="$1" 'BEGIN { split("Б КБ МБ ГБ", u, " "); i = 1; while (b >= 1024 && i < 4) { b /= 1024; i++ } printf (i == 1 ? "%d %s" : "%.1f %s"), b, u[i] }'; }

# ---------------------------------------------------------------- база
bk_dump_db() {   # файл.sql.gz
    docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$RW_DB_CONTAINER" || { err "Контейнер базы $RW_DB_CONTAINER не запущен"; return 1; }
    local user; user=$(bk_db_user)
    docker exec "$RW_DB_CONTAINER" pg_dumpall -U "$user" --clean --if-exists 2>/dev/null | gzip > "$1"
    gzip -dc "$1" 2>/dev/null | head -c 4096 | grep -q 'PostgreSQL database cluster dump' || { err "Дамп базы пустой или повреждён"; return 1; }
}

# Свежий том postgres сначала поднимает временный сервер (только unix-сокет) для
# инициализации, потом перезапускается. Готовность — по TCP, это только настоящий
# сервер, и дважды подряд, чтобы не попасть на перезапуск.
bk_db_wait() {   # секунд
    local i user ok=0; user=$(bk_db_user)
    for ((i = 0; i < ${1:-60}; i++)); do
        if docker exec "$RW_DB_CONTAINER" pg_isready -h 127.0.0.1 -U "$user" >/dev/null 2>&1 \
            && docker exec "$RW_DB_CONTAINER" psql -h 127.0.0.1 -U "$user" -d postgres -tAc 'select 1' >/dev/null 2>&1; then
            ok=$((ok + 1)); ((ok >= 2)) && return 0
        else
            ok=0
        fi
        sleep 1
    done
    return 1
}

bk_load_db() {   # файл.sql.gz
    local user; user=$(bk_db_user)
    # ошибки вида «роль уже существует» безвредны — проверяем результат по таблицам
    gzip -dc "$1" | docker exec -i "$RW_DB_CONTAINER" psql -U "$user" -d postgres -q >/dev/null 2>"$F2D_BACKUP_DIR/restore-psql.log"
    local n; n=$(docker exec "$RW_DB_CONTAINER" psql -U "$user" -d postgres -tAc "select count(*) from information_schema.tables where table_schema = 'public'" 2>/dev/null)
    [[ "${n:-0}" -gt 0 ]] || { err "После загрузки в базе нет таблиц — см. $F2D_BACKUP_DIR/restore-psql.log"; return 1; }
}

# сколько пользователей/нод в базе (для отчёта; таблицы могут называться по-разному в версиях)
bk_db_counts() {
    local user t out="" n; user=$(bk_db_user)
    for t in users nodes hosts; do
        n=$(docker exec "$RW_DB_CONTAINER" psql -U "$user" -d postgres -tAc "select count(*) from $t" 2>/dev/null) || continue
        [[ "$n" =~ ^[0-9]+$ ]] && out+="$t=$n "
    done
    echo "${out% }"
}

# ---------------------------------------------------------------- шифрование
bk_encrypt() { F2D_BK_PASS="$3" openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass env:F2D_BK_PASS -in "$1" -out "$2"; }
bk_decrypt() { F2D_BK_PASS="$3" openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass env:F2D_BK_PASS -in "$1" -out "$2" 2>/dev/null; }

_bk_ask_password() {   # → REPLY (пусто — без пароля)
    local p1
    while true; do
        read_secret "Пароль для копии (Enter — без пароля)"; p1="$REPLY"
        [[ -z "$p1" ]] && { REPLY=""; return 0; }
        ((${#p1} >= 8)) || { warn "Не короче 8 символов"; continue; }
        read_secret "Повторите пароль"
        [[ "$REPLY" == "$p1" ]] && return 0
        warn "Пароли не совпали"
    done
}

# ---------------------------------------------------------------- создание
backup_create() {   # [--out DIR] [--no-certs] [--password P | --no-password] [--quiet] [--auto]
    local out="$F2D_BACKUP_DIR" certs=yes pass="" passmode=ask quiet="" auto="" a
    while (($#)); do
        case "$1" in
            --out) out="${2:?каталог}"; shift;; --no-certs) certs=no;; --quiet) quiet=1;;
            --password) pass="${2:?пароль}"; passmode="given"; shift;; --no-password) passmode="none";;
            --auto) auto=1; quiet=1;;
            *) die "backup create [--out DIR] [--no-certs] [--password P | --no-password]";;
        esac; shift
    done
    require_root
    local root; root=$(_bk_root)
    compose_file "$root$RW_PANEL_DIR" >/dev/null || die "Панели на этом сервере нет ($RW_PANEL_DIR)"
    if [[ "$passmode" == ask ]]; then
        if [[ -n "${BACKUP_PASSWORD:-}" ]]; then pass="$BACKUP_PASSWORD"
        elif [[ -z "$auto" && -t 0 ]]; then
            info "В копии вся база (пользователи, ключи нод) и секреты панели. Если копия уйдёт с сервера — задайте пароль."
            _bk_ask_password; pass="$REPLY"
        fi
    fi
    [[ -z "$quiet" ]] && title "Резервная копия панели"
    mkdir -p "$out"; chmod 700 "$out" 2>/dev/null
    local stage; stage=$(mktemp -d)
    # 1) база
    [[ -z "$quiet" ]] && info "Дамп базы ($RW_DB_CONTAINER)…"
    bk_dump_db "$stage/db.sql.gz" || { rm -rf "$stage"; return 1; }
    local counts; counts=$(bk_db_counts)
    [[ -z "$quiet" ]] && ok "База: $(_bk_human "$(wc -c < "$stage/db.sql.gz")")${counts:+ ($counts)}"
    # 2) файлы
    local paths=() p
    local -a list=("${BACKUP_PATHS[@]}"); [[ -n "${F2D_BACKUP_PATHS:-}" ]] && read -r -a list <<<"$F2D_BACKUP_PATHS"
    [[ "$certs" == yes ]] && list+=(/etc/letsencrypt)
    for p in "${list[@]}"; do [[ -e "$root$p" ]] && paths+=("${p#/}"); done
    tar -czf "$stage/files.tar.gz" -C "${root:-/}" --exclude='*.sock' --exclude='*/node_modules' "${paths[@]}" 2>/dev/null \
        || { err "Не удалось упаковать файлы"; rm -rf "$stage"; return 1; }
    [[ -z "$quiet" ]] && ok "Файлы: $(printf '/%s ' "${paths[@]}")($(_bk_human "$(wc -c < "$stage/files.tar.gz")"))"
    # 3) опись
    local env="$root$RW_PANEL_DIR/.env" host; host=$(hostname -s 2>/dev/null || echo server)
    jq -n --arg v "$F2D_VERSION" --arg h "$host" --arg ip "$(curl -fsS4 --max-time 4 https://api.ipify.org 2>/dev/null)" \
        --arg pd "$(_bk_env_get "$env" PANEL_DOMAIN)" --arg sd "$(_bk_env_get "$env" SUB_PUBLIC_DOMAIN)" \
        --arg img "$(docker inspect -f '{{.Config.Image}}' remnawave 2>/dev/null)" --arg c "$counts" \
        --argjson paths "$(printf '/%s\n' "${paths[@]}" | jq -R . | jq -sc .)" \
        '{format: 1, fail2detect: $v, created: (now | todate), host: $h, ip: $ip, panel_domain: $pd, sub_domain: $sd,
          remnawave_image: $img, counts: $c, paths: $paths}' > "$stage/manifest.json"
    local name; name="panel-${host}-$(date +%Y%m%d-%H%M%S)"
    tar -cf "$stage/$name.tar" -C "$stage" manifest.json db.sql.gz files.tar.gz
    local file="$out/$name.tar"
    if [[ -n "$pass" ]]; then
        bk_encrypt "$stage/$name.tar" "$out/$name.tar.enc" "$pass" || { err "Шифрование не удалось"; rm -rf "$stage"; return 1; }
        file="$out/$name.tar.enc"
    else
        mv "$stage/$name.tar" "$file"
    fi
    chmod 600 "$file"; rm -rf "$stage"
    BACKUP_LAST="$file"
    audit_write BACKUP - - - "копия панели $(basename "$file")${counts:+ ($counts)}"
    if [[ -z "$quiet" ]]; then
        ok "Готово: $file ($(_bk_human "$(wc -c < "$file")"))$([[ -n "$pass" ]] && echo ", зашифрована")"
        backup_save_hint "$file"
    fi
    { mkdir -p "$F2D_BACKUP_DIR" && echo "$file" > "$F2D_BACKUP_DIR/.last"; } 2>/dev/null
    return 0
}

# как забрать копию с сервера
backup_save_hint() {   # файл
    local ip; ip=$(curl -fsS4 --max-time 4 https://api.ipify.org 2>/dev/null || echo "<IP сервера>")
    echo
    echo "  ${C_BOLD}Сохраните копию вне этого сервера:${C_RESET}"
    echo "    на свой компьютер:   scp root@$ip:$1 ."
    echo "    на другой сервер:    fail2detect backup send $(basename "$1") --to root@<сервер>"
    [[ -n "${TG_BOT_TOKEN:-}" ]] && echo "    в Telegram:          fail2detect backup send $(basename "$1") --telegram"
    echo "    перенести панель:    fail2detect panel migrate --to root@<новый сервер>"
}

_bk_resolve() {   # имя/путь → путь (по умолчанию — последняя копия)
    local f="${1:-}"
    [[ -z "$f" || "$f" == last ]] && f=$(cat "$F2D_BACKUP_DIR/.last" 2>/dev/null)
    [[ -f "$f" ]] || f="$F2D_BACKUP_DIR/$f"
    [[ -f "$f" ]] || die "Копия не найдена: ${1:-последняя} (список: fail2detect backup list)"
    echo "$f"
}

backup_list() {
    title "Резервные копии панели ($F2D_BACKUP_DIR)"
    local f n=0
    for f in "$F2D_BACKUP_DIR"/panel-*.tar "$F2D_BACKUP_DIR"/panel-*.tar.enc; do
        [[ -f "$f" ]] || continue
        n=$((n + 1))
        printf '  %s %s%10s%s  %s\n' "$(basename "$f")" "$C_GRAY" "$(_bk_human "$(wc -c < "$f")")" "$C_RESET" "$([[ "$f" == *.enc ]] && echo "🔒")"
    done | sort -r
    compgen -G "$F2D_BACKUP_DIR/panel-*" >/dev/null || info "Копий нет: fail2detect backup create"
    [[ -n "${BACKUP_SCHEDULE:-}" ]] && info "Автокопии: ${BACKUP_SCHEDULE}, хранится ${BACKUP_KEEP:-7}$([[ ${BACKUP_TELEGRAM:-} == yes ]] && echo ", отправка в Telegram")"
    return 0
}

# оставить N последних
backup_prune() {   # N
    local keep="${1:-7}" all=() f
    for f in "$F2D_BACKUP_DIR"/panel-*.tar "$F2D_BACKUP_DIR"/panel-*.tar.enc; do [[ -f "$f" ]] && all+=("$f"); done
    ((${#all[@]} > keep)) || return 0
    mapfile -t all < <(printf '%s\n' "${all[@]}" | sort)   # имена — время создания
    rm -f "${all[@]:0:${#all[@]}-keep}"
}

# ---------------------------------------------------------------- отправка
backup_send() {   # файл --telegram | --to user@host[:каталог] [-p порт]
    local f="" mode="" dest="" port=22
    while (($#)); do
        case "$1" in --telegram|--tg) mode=tg;; --to) mode=scp; dest="${2:?user@host}"; shift;; -p|--port) port="${2:?порт}"; shift;; *) f="$1";; esac
        shift
    done
    f=$(_bk_resolve "$f")
    case "$mode" in
        tg)
            [[ -n "${TG_BOT_TOKEN:-}" && -n "${TG_CHAT_ID:-}" ]] || die "Telegram не настроен: fail2detect config TG_BOT_TOKEN … и TG_CHAT_ID …"
            [[ "$f" == *.enc ]] || { warn "Копия без пароля — в Telegram уйдут все ключи и пользователи."; confirm "Всё равно отправить?" n || return 1; }
            backup_send_tg "$f";;
        scp)
            have scp || die "Нет scp (apt install openssh-client)"
            local target="$dest"; [[ "$target" == *:* ]] || target="$target:/root/"
            info "Копирую на ${target}…"
            scp -P "$port" -o StrictHostKeyChecking=accept-new "$f" "$target" && ok "Скопировано: $target$(basename "$f")";;
        *) die "backup send <копия> --telegram | --to root@сервер[:каталог]";;
    esac
}

backup_send_tg() {   # файл
    local f="$1" size parts=() p i=0 cap
    size=$(wc -c < "$f")
    if ((size > BACKUP_TG_LIMIT)); then
        local dir; dir=$(mktemp -d)
        split -b "$BACKUP_TG_LIMIT" -d -a 2 "$f" "$dir/$(basename "$f").part"
        for p in "$dir"/*; do parts+=("$p"); done
    else
        parts=("$f")
    fi
    for p in "${parts[@]}"; do
        i=$((i + 1))
        cap="fail2detect: копия панели $(hostname -s) · $(_bk_human "$size")"
        ((${#parts[@]} > 1)) && cap+=" · часть $i/${#parts[@]} (собрать: cat $(basename "$f").part* > $(basename "$f"))"
        curl -fsS --max-time 300 -F "chat_id=$TG_CHAT_ID" -F "caption=$cap" -F "document=@$p" \
            "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendDocument" >/dev/null \
            || { err "Telegram не принял файл $(basename "$p")"; return 1; }
    done
    ((${#parts[@]} > 1)) && rm -rf "$(dirname "${parts[0]}")"
    ok "Отправлено в Telegram$( ((${#parts[@]} > 1)) && echo " (${#parts[@]} части)")"
}

# ---------------------------------------------------------------- восстановление
backup_inspect() {   # файл → manifest (расшифровывает во временный каталог)
    local f; f=$(_bk_resolve "${1:-}")
    local stage; stage=$(mktemp -d)
    _bk_unpack "$f" "$stage" || { rm -rf "$stage"; return 1; }
    jq . "$stage/manifest.json"; rm -rf "$stage"
}

_bk_unpack() {   # файл каталог
    local f="$1" st="$2" tarf="$1"
    if [[ "$f" == *.enc ]]; then
        local pass="${F2D_BACKUP_PASS:-}"
        [[ -n "$pass" ]] || { read_secret "Пароль копии"; pass="$REPLY"; }
        bk_decrypt "$f" "$st/backup.tar" "$pass" || { err "Неверный пароль или копия повреждена"; return 1; }
        tarf="$st/backup.tar"
    fi
    tar -xf "$tarf" -C "$st" manifest.json db.sql.gz files.tar.gz 2>/dev/null || { err "Это не копия fail2detect (нет manifest.json/db.sql.gz/files.tar.gz)"; return 1; }
    rm -f "$st/backup.tar"
    jq -e '.format == 1' "$st/manifest.json" >/dev/null 2>&1 || { err "Неизвестный формат копии"; return 1; }
}

# перенести «панельные» ключи из старого fail2detect.conf и файлы из /etc/fail2detect
_bk_restore_conf() {   # каталог_старого_etc
    local old="$1" k v f
    [[ -d "$old" ]] || return 0
    mkdir -p "$F2D_CONF_DIR"
    for f in "$old"/*; do
        case "$(basename "$f")" in fail2detect.conf|jail.d) continue;; esac
        cp -a "$f" "$F2D_CONF_DIR/"
    done
    if [[ -f "$old/fail2detect.conf" ]]; then
        for k in "${BACKUP_CONF_KEYS[@]}"; do
            v=$( (set +u; # shellcheck disable=SC1091
                  source "$old/fail2detect.conf" >/dev/null 2>&1; printf '%s' "${!k:-}") )
            [[ -n "$v" ]] && config_set "$k" "$v" >/dev/null
        done
    fi
}

# сменить домены панели/подписки после переноса (если старые тоже заблокированы)
_bk_set_domains() {   # панель подписка
    local env="$RW_PANEL_DIR/.env" pd="$1" sd="$2"
    [[ -n "$pd" ]] && sed -i "s|^PANEL_DOMAIN=.*|PANEL_DOMAIN=$pd|" "$env"
    [[ -n "$sd" ]] && sed -i "s|^SUB_PUBLIC_DOMAIN=.*|SUB_PUBLIC_DOMAIN=$sd|" "$env"
    web_load
    [[ -n "$pd" && -n "$PANEL_DOMAIN" ]] && { cert_ensure "$pd" || return 1; web_set PANEL_DOMAIN "$pd"; }
    [[ -n "$sd" && -n "$SUB_DOMAIN" ]] && { cert_ensure "$sd" || return 1; web_set SUB_DOMAIN "$sd"; }
    return 0
}

backup_restore() {   # файл [--yes] [--panel-domain D] [--sub-domain D] [--migrated-from IP]
    local stage rc=0; stage=$(mktemp -d)
    _backup_restore "$stage" "$@" || rc=$?
    rm -rf "$stage"
    return "$rc"
}

_backup_restore() {   # каталог_распаковки аргументы…
    local stage="$1"; shift
    local f="" yes="" npd="" nsd="" from=""
    while (($#)); do
        case "$1" in
            --yes|-y) yes=1;; --panel-domain) npd="${2:?домен}"; shift;; --sub-domain) nsd="${2:?домен}"; shift;;
            --migrated-from) from="${2:?IP}"; shift;; *) f="$1";;
        esac; shift
    done
    require_root
    f=$(_bk_resolve "$f")
    title "Восстановление панели из $(basename "$f")"
    _bk_unpack "$f" "$stage" || return 1
    local m="$stage/manifest.json"
    echo "  Создана:   $(jq -r .created "$m") на $(jq -r .host "$m") ($(jq -r '.ip // "?"' "$m"))"
    echo "  Панель:    $(jq -r '.panel_domain // "?"' "$m")   подписка: $(jq -r '.sub_domain // "?"' "$m")"
    echo "  В базе:    $(jq -r '.counts // "?"' "$m")"
    echo "  Файлы:     $(jq -r '.paths | join(" ")' "$m")"
    echo
    require_docker
    # на этом сервере уже есть панель или её база — заменить можно только явно
    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$RW_DB_CONTAINER" || docker volume inspect remnawave-db-data >/dev/null 2>&1; then
        warn "На этом сервере уже есть база панели — она будет ЗАМЕНЕНА копией."
        if [[ -z "$yes" ]]; then ask "Чтобы продолжить, введите «заменить»" ""; [[ "$REPLY" == заменить ]] || die "Отменено"; fi
        if compose_file "$RW_PANEL_DIR" >/dev/null; then
            info "Снимаю копию текущей базы на всякий случай…"
            bk_dump_db "$F2D_BACKUP_DIR/before-restore-$(date +%Y%m%d-%H%M%S).sql.gz" >/dev/null 2>&1 || true
            (cd "$RW_PANEL_DIR" && docker compose down >/dev/null 2>&1)
        fi
        docker rm -f "$RW_DB_CONTAINER" >/dev/null 2>&1
        docker volume rm remnawave-db-data >/dev/null 2>&1
    elif [[ -z "$yes" ]]; then
        confirm "Восстановить панель на этом сервере?" y || return 1
    fi
    # 1) файлы; настройки fail2detect — выборочно (фаервол и SSH нового сервера не трогаем)
    mkdir -p "$stage/files"
    tar -xzf "$stage/files.tar.gz" -C "$stage/files" || { err "Архив файлов повреждён"; return 1; }
    local top
    while IFS= read -r top; do
        [[ "$top" == etc/fail2detect ]] && continue
        mkdir -p "/$(dirname "$top")"
        cp -a "$stage/files/$top" "/$(dirname "$top")/"
    done < <(jq -r '.paths[] | ltrimstr("/")' "$m")
    _bk_restore_conf "$stage/files/etc/fail2detect"
    load_config
    ok "Файлы панели восстановлены"
    # 2) домены (если старые заблокированы)
    if [[ -z "$npd$nsd" && -z "$yes" && -t 0 ]]; then
        confirm "Сменить домены панели/подписки (если старые тоже заблокированы)?" n && {
            ask "Новый домен панели (Enter — оставить $(_bk_env_get "$RW_PANEL_DIR/.env" PANEL_DOMAIN))" ""; npd="$REPLY"
            ask "Новый домен подписки (Enter — оставить $(_bk_env_get "$RW_PANEL_DIR/.env" SUB_PUBLIC_DOMAIN))" ""; nsd="$REPLY"; }
    fi
    [[ -n "$npd$nsd" ]] && { _bk_set_domains "$npd" "$nsd" || return 1; ok "Домены обновлены"; }
    # 3) база
    info "Поднимаю базу…"
    local dbsvc; dbsvc=$(cd "$RW_PANEL_DIR" && docker compose config --services 2>/dev/null | grep -m1 -E 'db|postgres')
    (cd "$RW_PANEL_DIR" && docker compose up -d "${dbsvc:-remnawave-db}" >/dev/null 2>&1) || { err "База не запустилась (cd $RW_PANEL_DIR && docker compose logs)"; return 1; }
    bk_db_wait 90 || { err "База не отвечает"; return 1; }
    info "Загружаю данные…"
    bk_load_db "$stage/db.sql.gz" || return 1
    ok "База восстановлена ($(bk_db_counts))"
    # 4) всё остальное
    info "Запускаю панель…"
    (cd "$RW_PANEL_DIR" && docker compose up -d >/dev/null 2>&1) || { err "docker compose up не удался"; return 1; }
    compose_file "$RW_SUB_DIR" >/dev/null && (cd "$RW_SUB_DIR" && docker compose up -d >/dev/null 2>&1)
    panel_wait_api && ok "Панель отвечает" || warn "Панель пока не отвечает на 127.0.0.1:3000 (docker compose logs -f remnawave)"
    web_load
    if [[ -n "$PANEL_DOMAIN$SUB_DOMAIN$SELFSTEAL_DOMAIN" ]] && ! docker ps --format '{{.Names}}' | grep -qx remnawave-nginx; then
        web_apply || warn "nginx не поднялся — проверьте сертификаты: fail2detect cert list"
    fi
    if compose_file "$RW_NODE_DIR" >/dev/null && jq -e '.paths | index("/opt/remnanode")' "$m" >/dev/null; then
        { [[ -n "$yes" ]] || confirm "В копии есть нода этого сервера — запустить её здесь?" y; } && (cd "$RW_NODE_DIR" && docker compose up -d >/dev/null 2>&1) && ok "Нода запущена"
    fi
    config_set RW_API_URL "http://127.0.0.1:3000" >/dev/null
    audit_write RESTORE - - - "панель из $(basename "$f")"
    _bk_after_move "$from" "$yes"
}

# что сделать после переноса: DNS и IP панели на нодах
_bk_after_move() {   # старый_IP [yes]
    local new old="$1" env="$RW_PANEL_DIR/.env"
    new=$(curl -fsS4 --max-time 5 https://api.ipify.org 2>/dev/null || echo "<IP этого сервера>")
    title "Осталось"
    echo "  1. DNS: A-записи на ${C_BOLD}$new${C_RESET}:"
    local d; for d in "$(_bk_env_get "$env" PANEL_DOMAIN)" "$(_bk_env_get "$env" SUB_PUBLIC_DOMAIN)"; do
        d="${d%%/*}"; [[ -n "$d" ]] && echo "       $d"
    done
    echo "     Клиенты обновят подписку по тому же адресу, когда DNS переключится."
    echo "  2. Ноды должны пускать к себе новую панель (порт API ноды открыт только для IP панели):"
    local nodes; nodes=$(F2D_NO_PROMPT=1 rw_api GET /api/nodes 2>/dev/null | jq -r '.response[]? | [.name, .address] | join(" ")' 2>/dev/null)
    local cmd="fail2detect node panel-ip $new${old:+ --replace $old}"
    if [[ -n "$nodes" ]]; then
        local name addr
        while read -r name addr; do printf '       %-20s ssh root@%s "%s"\n' "$name" "$addr" "$cmd"; done <<<"$nodes"
        if [[ -z "${2:-}" && -t 0 ]] && have ssh && confirm "Выполнить это на нодах по SSH сейчас?" y; then
            while read -r name addr; do
                [[ "$addr" =~ ^(127\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.|10\.|192\.168\.) ]] && continue   # нода на этом же сервере
                info "$name ($addr)…"
                # shellcheck disable=SC2029
                ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "root@$addr" "$cmd" </dev/tty && ok "$name: IP панели обновлён" || warn "$name: не вышло — выполните команду на ноде сами"
            done <<<"$nodes"
        fi
    else
        echo "       на каждой ноде: $cmd"
    fi
    echo "  3. Фаервол и баны на этом сервере: fail2detect setup"
}

# ---------------------------------------------------------------- перенос
panel_migrate() {   # --to user@host [-p порт]
    local to="" port=22
    while (($#)); do case "$1" in --to) to="${2:?user@host}"; shift;; -p|--port) port="${2:?порт}"; shift;; *) to="$1";; esac; shift; done
    [[ -n "$to" ]] || die "panel migrate --to root@<новый сервер> [-p порт]"
    [[ "$to" == *@* ]] || to="root@$to"
    require_root; have ssh && have scp || die "Нужны ssh и scp (apt install openssh-client)"
    title "Перенос панели на $to"
    echo "  1. Копия панели здесь (база, секреты, сертификаты)"
    echo "  2. fail2detect на новом сервере (если ещё нет)"
    echo "  3. Копия → новый сервер по SSH и восстановление там"
    echo "  4. IP панели на нодах, остановка панели здесь"
    echo
    confirm "Начать?" y || return 1
    local ssh_opts=(-p "$port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15)
    ssh "${ssh_opts[@]}" "$to" true || die "Нет SSH-доступа к $to"
    local tmp; tmp=$(mktemp -d)
    # по SSH копия идёт зашифрованным каналом — пароль на файл не нужен
    backup_create --out "$tmp" --no-password --quiet || { rm -rf "$tmp"; die "Копия не создана"; }
    local f="$BACKUP_LAST" name; name=$(basename "$f")
    ok "Копия: $(_bk_human "$(wc -c < "$f")")"
    info "Ставлю fail2detect на $to (если нет)…"
    # shellcheck disable=SC2029  # F2D_REPO — намеренно с этой стороны
    ssh "${ssh_opts[@]}" "$to" "command -v fail2detect >/dev/null || bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/${F2D_REPO}/main/install.sh)\" -- --no-setup" \
        || { rm -rf "$tmp"; die "Не удалось установить fail2detect на $to"; }
    info "Передаю копию…"
    scp -P "$port" -o StrictHostKeyChecking=accept-new "$f" "$to:/root/$name" || { rm -rf "$tmp"; die "Копия не передана"; }
    # на старом сервере копию тоже оставляем
    mkdir -p "$F2D_BACKUP_DIR"; mv "$f" "$F2D_BACKUP_DIR/" 2>/dev/null; rm -rf "$tmp"
    local old_ip; old_ip=$(curl -fsS4 --max-time 5 https://api.ipify.org 2>/dev/null)
    info "Восстанавливаю на ${to}…"
    # shellcheck disable=SC2029
    ssh -t "${ssh_opts[@]}" "$to" "fail2detect backup restore /root/$name ${old_ip:+--migrated-from $old_ip}" \
        || { err "Восстановление на $to не завершилось — копия лежит там в /root/$name"; return 1; }
    echo
    ok "Панель перенесена на $to"
    # две панели, управляющие одними нодами, будут спорить — старую останавливаем
    if confirm "Остановить панель на ЭТОМ (старом) сервере? Данные останутся" y; then
        (cd "$RW_PANEL_DIR" && docker compose stop >/dev/null 2>&1) && ok "Старая панель остановлена (запустить снова: cd $RW_PANEL_DIR && docker compose start)"
    fi
    audit_write MIGRATE - - - "панель → $to"
}

# ---------------------------------------------------------------- на ноде
node_panel_ip() {   # новый_IP [--replace старый | --add]
    local new="${1:-}" old="" add="" ; shift || true
    while (($#)); do case "$1" in --replace) old="${2:-}"; shift;; --add) add=1;; esac; shift; done
    require_root
    is_ip "$new" || die "node panel-ip <IP новой панели> [--replace <старый IP>] [--add]"
    has_node || warn "Ноды на этом сервере не видно — правлю только фаервол"
    local cur=" $PANEL_IPS " ips="" ip
    if [[ -n "$add" ]]; then ips="$PANEL_IPS $new"
    elif [[ -n "$old" ]]; then ips="${cur/ $old / }"; ips="$ips $new"
    else ips="$new"; fi
    ips=$(tr ' ' '\n' <<<"$ips" | awk 'NF && !seen[$0]++' | paste -sd' ' -)
    local napi="${NODE_API_PORT:-$(detect_node_api_port)}"
    # UFW: старые правила к API ноды — убрать, новые — добавить
    for ip in $PANEL_IPS; do
        [[ " $ips " == *" $ip "* ]] || { ufw_active && ufw --force delete allow proto tcp from "$ip" to any port "$napi" >/dev/null 2>&1; }
    done
    for ip in $ips; do ufw_allow "$napi" tcp "$ip" "Remnawave panel"; done
    config_set PANEL_IPS "$ips"
    fw_apply >/dev/null && ok "API ноды ($napi/tcp) открыт для: $ips"
    audit_write NODE_PANEL_IP - - - "$ips"
}

# ---------------------------------------------------------------- расписание
backup_schedule() {   # daily|weekly|off [--keep N] [--telegram]
    local when="${1:-}" keep="${BACKUP_KEEP:-7}" tg="${BACKUP_TELEGRAM:-no}"; shift || true
    while (($#)); do case "$1" in --keep) keep="${2:?N}"; shift;; --telegram|--tg) tg=yes;; --no-telegram) tg=no;; esac; shift; done
    require_root
    local svc=/etc/systemd/system/fail2detect-backup.service tmr=/etc/systemd/system/fail2detect-backup.timer
    case "$when" in
        off|disable)
            systemctl disable --now fail2detect-backup.timer >/dev/null 2>&1; rm -f "$svc" "$tmr"; systemctl daemon-reload
            config_set BACKUP_SCHEDULE ""; ok "Автокопии выключены"; return 0;;
        daily|weekly|hourly) ;;
        *) die "backup schedule daily|weekly|off [--keep N] [--telegram]";;
    esac
    if [[ "$tg" == yes ]]; then
        [[ -n "${TG_BOT_TOKEN:-}" && -n "${TG_CHAT_ID:-}" ]] || die "Telegram не настроен: fail2detect config TG_BOT_TOKEN … и TG_CHAT_ID …"
        if [[ -z "${BACKUP_PASSWORD:-}" ]]; then
            info "Копии в Telegram — только с паролем (в них ключи и все пользователи)."
            _bk_ask_password; [[ -n "$REPLY" ]] || die "Без пароля в Telegram не отправляю"
            config_set BACKUP_PASSWORD "$REPLY" >/dev/null
            warn "Запомните пароль: без него копию не восстановить. Он хранится в $F2D_CONF (только root)."
        fi
    fi
    cat > "$svc" <<EOF
[Unit]
Description=fail2detect — резервная копия панели Remnawave
After=docker.service network-online.target

[Service]
Type=oneshot
Environment=NO_COLOR=1
ExecStart=/usr/local/bin/fail2detect backup create --auto
EOF
    cat > "$tmr" <<EOF
[Unit]
Description=fail2detect — автокопии панели ($when)

[Timer]
OnCalendar=$([[ $when == daily ]] && echo '*-*-* 04:20' || { [[ $when == weekly ]] && echo 'Sun *-*-* 04:20' || echo hourly; })
RandomizedDelaySec=20min
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload && systemctl enable --now fail2detect-backup.timer >/dev/null 2>&1
    config_set BACKUP_SCHEDULE "$when" >/dev/null; config_set BACKUP_KEEP "$keep" >/dev/null; config_set BACKUP_TELEGRAM "$tg" >/dev/null
    ok "Автокопии: $when, хранится $keep$([[ $tg == yes ]] && echo ", копия уходит в Telegram")"
}

# запуск по таймеру: копия → чистка → Telegram
backup_auto() {
    if backup_create --auto; then
        backup_prune "${BACKUP_KEEP:-7}"
        [[ "${BACKUP_TELEGRAM:-}" == yes ]] && backup_send_tg "$BACKUP_LAST"
        return 0
    fi
    notify "⚠️ fail2detect: резервная копия панели на $(hostname -s) не создана"
    return 1
}

# ---------------------------------------------------------------- CLI и меню
backup_cli() {
    local cmd="${1:-list}"; shift || true
    case "$cmd" in
        create|new|make) if [[ " $* " == *" --auto "* ]]; then backup_auto; else backup_create "$@"; fi;;
        list|ls) backup_list;;
        restore) backup_restore "$@";;
        send) backup_send "$@";;
        info|inspect) backup_inspect "${1:-}";;
        schedule|auto) backup_schedule "$@";;
        prune) backup_prune "${1:-${BACKUP_KEEP:-7}}"; ok "Оставлено ${1:-${BACKUP_KEEP:-7}} последних";;
        *) die "backup create|list|restore <копия>|send <копия> --telegram|--to root@сервер|info|schedule daily|weekly|off";;
    esac
}

menu_backup() {
    while true; do
        banner
        echo "  ${C_BOLD}Резервные копии и перенос панели${C_RESET}"
        menu_item 1 "Создать копию сейчас"
        menu_item 2 "Список копий"
        menu_item 3 "Отправить копию (Telegram / другой сервер)"
        menu_item 4 "Восстановить из копии на этом сервере"
        menu_item 5 "Перенести панель на другой сервер"
        menu_item 6 "Автокопии по расписанию$([[ -n "${BACKUP_SCHEDULE:-}" ]] && echo " (${BACKUP_SCHEDULE})")"
        menu_item 7 "Нода: сменить IP панели (после переноса)"
        menu_item 0 "Назад"
        ask "Выбор" ""
        case "$REPLY" in
            1) backup_create;;
            2) backup_list;;
            3) backup_list; ask "Копия (Enter — последняя)" ""; local f="$REPLY"
               echo "  1. Telegram   2. другой сервер по SSH"; ask "Куда" "1"
               if [[ "$REPLY" == 2 ]]; then ask "Сервер (root@IP)" ""; backup_send "$f" --to "$REPLY"; else backup_send "$f" --telegram; fi;;
            4) backup_list; ask "Копия (имя или путь)" ""; backup_restore "$REPLY";;
            5) ask "Новый сервер (root@IP)" ""; panel_migrate --to "$REPLY";;
            6) echo "  1. ежедневно  2. еженедельно  3. выключить"; ask "Расписание" "1"
               case "$REPLY" in
                   3) backup_schedule off;;
                   *) local w=daily; [[ "$REPLY" == 2 ]] && w=weekly
                      ask "Сколько копий хранить" "${BACKUP_KEEP:-7}"; local k="$REPLY"
                      if [[ -n "${TG_BOT_TOKEN:-}" ]] && confirm "Отправлять копию в Telegram?" y; then backup_schedule "$w" --keep "$k" --telegram
                      else backup_schedule "$w" --keep "$k"; fi;;
               esac;;
            7) ask "IP новой панели" ""; local nip="$REPLY"; ask "Старый IP панели (Enter — заменить все)" ""
               if [[ -n "$REPLY" ]]; then node_panel_ip "$nip" --replace "$REPLY"; else node_panel_ip "$nip"; fi;;
            0|q|"") return;;
            *) continue;;
        esac
        pause
    done
}

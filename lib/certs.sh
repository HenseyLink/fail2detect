#!/usr/bin/env bash
# fail2detect — сертификаты.
#
# Где ищем готовый сертификат (в этом порядке):
#   1) Let's Encrypt / certbot — /etc/letsencrypt/live/<lineage>/
#   2) Caddy — если на сервере работает Caddy, он сам выпускает и продлевает
#      сертификаты (docker-том caddy_data или стандартные пути Caddy)
# Если готового нет — выпускаем certbot'ом:
#   CERT_METHOD=http        HTTP-01: порт 80 открывается в фаерволе на время проверки
#   CERT_METHOD=cloudflare  DNS-01 через API Cloudflare (порт 80 не нужен, можно wildcard)
# Способ можно сменить в любой момент: fail2detect cert method.

LE_LIVE="/etc/letsencrypt/live"
CF_INI="${F2D_CONF_DIR}/cloudflare.ini"

cert_deps() {
    have certbot && return 0
    info "Устанавливаю certbot…"
    pkg_install certbot python3-certbot-dns-cloudflare || pkg_install certbot || die "Не удалось установить certbot"
}

# покрывает ли сертификат домен (точное имя или wildcard одного уровня)
_cert_covers() {   # файл домен
    local name
    while read -r name; do
        [[ "$name" == "$2" ]] && return 0
        [[ "$name" == \*.* && "$2" == *."${name#\*.}" && "${2%%.*}.${name#\*.}" == "$2" ]] && return 0
    done < <(openssl x509 -in "$1" -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' | sed -n 's/.*DNS://p')
    return 1
}

# каталог lineage certbot, чей сертификат покрывает домен
cert_dir() {
    local d
    for d in "$LE_LIVE"/*/; do
        [[ -f "$d/fullchain.pem" ]] && _cert_covers "$d/fullchain.pem" "$1" && { echo "${d%/}"; return 0; }
    done
    return 1
}

# каталоги хранилища сертификатов Caddy на этом сервере
caddy_cert_roots() {
    local v mp
    # shellcheck disable=SC2086  # список каталогов через пробел — для тестов
    [[ -n "${F2D_CADDY_ROOTS:-}" ]] && { printf '%s\n' $F2D_CADDY_ROOTS; return; }
    if have docker; then
        for v in $(docker volume ls -q 2>/dev/null | grep -i caddy); do
            mp=$(docker volume inspect "$v" -f '{{.Mountpoint}}' 2>/dev/null)
            [[ -d "$mp/caddy/certificates" ]] && echo "$mp/caddy/certificates"
        done
    fi
    for v in /var/lib/caddy/.local/share/caddy/certificates /root/.local/share/caddy/certificates \
             /opt/*/caddy_data/caddy/certificates /opt/*/caddy/data/caddy/certificates; do
        [[ -d "$v" ]] && echo "$v"
    done
}

# сертификат Caddy для домена -> "файл_сертификата файл_ключа"
caddy_cert_files() {
    local root d name
    while read -r root; do
        for d in "$root"/*/"$1" "$root"/*/"wildcard_.${1#*.}"; do
            name="${d##*/}"
            [[ -f "$d/$name.crt" && -f "$d/$name.key" ]] || continue
            _cert_covers "$d/$name.crt" "$1" && { echo "$d/$name.crt $d/$name.key"; return 0; }
        done
    done < <(caddy_cert_roots | sort -u)
    return 1
}

# любой готовый сертификат -> "файл_сертификата файл_ключа источник"
cert_files() {   # домен
    local dir pair
    if dir=$(cert_dir "$1"); then echo "$dir/fullchain.pem $dir/privkey.pem certbot"; return 0; fi
    if pair=$(caddy_cert_files "$1"); then echo "$pair caddy"; return 0; fi
    return 1
}

cert_days_left() {   # файл_сертификата
    local end; end=$(openssl x509 -in "$1" -noout -enddate 2>/dev/null | cut -d= -f2) || return 1
    echo $(( ($(date -d "$end" +%s) - $(now)) / 86400 ))
}

cert_ask_method() {   # [--again] — спросить, даже если способ уже выбран
    [[ -n "${CERT_METHOD:-}" && "${1:-}" != --again ]] && return 0
    echo "  Как получать сертификаты:"
    echo "   1. HTTP-01 — A-запись домена на этот сервер, порт 80 свободен (откроется на минуту)"
    echo "   2. Cloudflare DNS — API-токен Cloudflare с правом Zone.DNS:Edit, порт 80 не нужен"
    ask "Способ" "$([[ "${CERT_METHOD:-}" == cloudflare ]] && echo 2 || echo 1)"
    if [[ "$REPLY" == 2 ]]; then
        CERT_METHOD=cloudflare
        if [[ ! -s "$CF_INI" || "${1:-}" == --again ]]; then
            read_secret "Cloudflare API token (вставьте)"
            [[ -n "$REPLY" ]] || { warn "Токен не задан"; return 1; }
            install -m 600 /dev/null "$CF_INI"
            printf 'dns_cloudflare_api_token = %s\n' "$REPLY" > "$CF_INI"
        fi
    else
        CERT_METHOD=http
    fi
    cert_ask_email
}

cert_email_valid() { [[ "$1" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; }

# запомнить способ и e-mail — только когда сертификат реально выпущен
cert_save_choice() { config_set CERT_METHOD "$CERT_METHOD"; config_set CERT_EMAIL "${CERT_EMAIL:-}"; }
cert_forget_choice() { config_set CERT_METHOD ""; config_set CERT_EMAIL ""; }

# e-mail для Let's Encrypt: формат проверяем, ошибку можно исправить
cert_ask_email() {
    local email def="${CERT_EMAIL:-}"
    cert_email_valid "$def" || def=""
    while true; do
        ask "E-mail для Let's Encrypt (пусто — без e-mail)" "$def"
        email="$REPLY"
        if [[ -z "$email" || "$email" == "-" ]]; then CERT_EMAIL=""; return 0; fi
        if ! cert_email_valid "$email"; then
            warn "«${email}» не похож на e-mail. Введите заново (или «-» — без e-mail)."
            continue
        fi
        confirm "E-mail $email — верно?" y || continue
        CERT_EMAIL="$email"; return 0
    done
}

# получить сертификат, если готового нет
cert_ensure() {   # domain
    local domain="$1" found
    if found=$(cert_files "$domain"); then
        local f src; f="${found%% *}"; src="${found##* }"
        ok "Сертификат для $domain есть ($src: ${f%/*}, осталось $(cert_days_left "$f" || echo ?) дн.)"
        return 0
    fi
    cert_deps
    # в конфиге мог остаться неверный e-mail (раньше туда попадало «y») — спросить заново
    if [[ -n "${CERT_EMAIL:-}" ]] && ! cert_email_valid "$CERT_EMAIL"; then
        warn "Сохранённый e-mail «${CERT_EMAIL}» неверный — укажите заново."
        CERT_EMAIL=""; cert_ask_method --again || return 1
    else
        cert_ask_method || return 1
    fi
    cert_hooks_install
    local try
    for try in 1 2 3; do
        if _cert_issue "$domain"; then cert_save_choice; return 0; fi
        # не вышло — ничего не запоминаем и предлагаем исправить способ/e-mail
        cert_forget_choice
        [[ -t 0 ]] || return 1
        warn "Выпустить сертификат способом «${CERT_METHOD}»${CERT_EMAIL:+ (e-mail $CERT_EMAIL)} не получилось."
        confirm "Исправить способ или e-mail и попробовать снова?" y || return 1
        cert_ask_method --again || return 1
    done
    return 1
}

_cert_issue() {   # domain
    local domain="$1" rc=0 mail=(--register-unsafely-without-email)
    [[ -n "${CERT_EMAIL:-}" ]] && mail=(-m "$CERT_EMAIL")
    info "Выпускаю сертификат для $domain ($CERT_METHOD)…"
    if [[ "$CERT_METHOD" == cloudflare ]]; then
        [[ -s "$CF_INI" ]] || { err "Нет токена Cloudflare ($CF_INI)"; return 1; }
        local base="$domain"; [[ "$domain" == *.*.* ]] && base="${domain#*.}"
        certbot certonly --non-interactive --agree-tos "${mail[@]}" \
            --dns-cloudflare --dns-cloudflare-credentials "$CF_INI" --dns-cloudflare-propagation-seconds 30 \
            -d "$base" -d "*.$base" --cert-name "$base" || rc=$?
    else
        # порт 80 держит наш nginx — выпускаем через webroot, ничего не останавливая
        if [[ "${WEB_HTTP:-}" == yes ]] && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$F2D_WEB_CONTAINER" \
            && ss -H -tlnp '( sport = :80 )' 2>/dev/null | grep -q '"nginx"'; then
            mkdir -p "$F2D_ACME_ROOT"
            certbot certonly --non-interactive --agree-tos "${mail[@]}" --webroot -w "$F2D_ACME_ROOT" \
                -d "$domain" --cert-name "$domain" || rc=$?
            (( rc == 0 )) || { err "certbot завершился с ошибкой"; return 1; }
            audit_write CERT - - - "выпущен сертификат $domain (webroot)"
            ok "Сертификат для $domain выпущен"
            return 0
        fi
        if ss -H -tln '( sport = :80 )' | grep -q .; then
            local who; who=$(ss -H -tlnp '( sport = :80 )' | grep -o 'users:(("[^"]*' | cut -d'"' -f2 | head -1)
            err "Порт 80 занят (${who:-?}) — HTTP-01 невозможен."
            [[ "$who" == caddy ]] && info "Caddy сам выпускает сертификаты, но для $domain готового у него не нашлось."
            return 1
        fi
        acme_port80 open
        certbot certonly --non-interactive --agree-tos "${mail[@]}" --standalone \
            --preferred-challenges http -d "$domain" --cert-name "$domain" || rc=$?
        acme_port80 close
    fi
    (( rc == 0 )) || { err "certbot завершился с ошибкой"; return 1; }
    audit_write CERT - - - "выпущен сертификат $domain ($CERT_METHOD)"
    ok "Сертификат для $domain выпущен"
}

# временно открыть/закрыть 80/tcp — и в UFW, и в таблице fail2detect
acme_port80() {
    if [[ "$1" == open ]]; then
        ufw_active && ufw allow 80/tcp comment 'fail2detect ACME' >/dev/null 2>&1
        nft add element inet "$F2D_NFT_TABLE" pub_tcp '{ 80 }' 2>/dev/null
    else
        ufw_active && ufw --force delete allow 80/tcp >/dev/null 2>&1
        [[ " $PUBLIC_TCP " == *" 80 "* ]] || nft delete element inet "$F2D_NFT_TABLE" pub_tcp '{ 80 }' 2>/dev/null
    fi
    return 0
}

# сертификат для Xray — копией в <node_dir>/certs (монтируется в контейнер)
cert_install_for_node() {   # domain
    local d found; d=$(node_dir); found=$(cert_files "$1") || return 1
    [[ -n "$d" ]] || return 1
    local crt key; read -r crt key _ <<<"$found"
    install -d -m 700 "$d/certs"
    install -m 644 "$crt" "$d/certs/fullchain.pem"
    install -m 600 "$key" "$d/certs/privkey.pem"
}

# Копия в ноде отстала от источника (продлил certbot или Caddy)? Обновить и
# перезапустить ноду. Вызывается демоном раз в 10 минут и хуком certbot.
cert_sync_node() {
    [[ -n "${NODE_TLS_DOMAIN:-}" ]] && has_node || return 0
    local d found crt; d=$(node_dir); found=$(cert_files "$NODE_TLS_DOMAIN") || return 0
    crt="${found%% *}"
    cmp -s "$crt" "$d/certs/fullchain.pem" && return 0
    cert_install_for_node "$NODE_TLS_DOMAIN" || return 0
    docker restart remnanode >/dev/null 2>&1 || true
    audit_write CERT - - - "сертификат $NODE_TLS_DOMAIN обновлён в ноде"
}

cert_hooks_install() {
    local h
    for h in pre post deploy; do
        mkdir -p "/etc/letsencrypt/renewal-hooks/$h"
        printf '#!/bin/sh\nexec /usr/local/bin/fail2detect acme %s\n' "$h" > "/etc/letsencrypt/renewal-hooks/$h/fail2detect.sh"
        chmod 755 "/etc/letsencrypt/renewal-hooks/$h/fail2detect.sh"
    done
}

# вызывается certbot'ом при продлении
acme_hook() {
    case "$1" in
        pre)
            if [[ "$(grep -h '^authenticator' /etc/letsencrypt/renewal/*.conf 2>/dev/null)" == *standalone* ]]; then
                acme_port80 open
                # старые сертификаты (standalone) продлеваются на порту 80 — освобождаем его на минуту
                if ss -H -tlnp '( sport = :80 )' 2>/dev/null | grep -q '"nginx"' && docker stop "$F2D_WEB_CONTAINER" >/dev/null 2>&1; then
                    touch /run/f2d-nginx-stopped
                fi
            fi;;
        post)
            [[ -f /run/f2d-nginx-stopped ]] && { docker start "$F2D_WEB_CONTAINER" >/dev/null 2>&1; rm -f /run/f2d-nginx-stopped; }
            web_load; [[ "$WEB_HTTP" == yes ]] || acme_port80 close;;
        deploy)
            cert_sync_node
            docker exec "$F2D_WEB_CONTAINER" nginx -s reload >/dev/null 2>&1 || true
            audit_write CERT - - - "сертификат продлён: ${RENEWED_DOMAINS:-?}";;
    esac
}

# fail2detect cert list | method | issue <домен>
cert_cli() {
    case "${1:-list}" in
        method) require_root; cert_ask_method --again && cert_save_choice && ok "Способ выпуска: $CERT_METHOD${CERT_EMAIL:+, e-mail $CERT_EMAIL}";;
        issue)  require_root; [[ -n "${2:-}" ]] || die "fail2detect cert issue <домен>"; cert_deps; cert_ensure "$2";;
        list)
            title "Сертификаты"
            printf '  %-28s %s\n' "Способ выпуска:" "${CERT_METHOD:-не выбран (спросит при первом выпуске)}"
            local d f
            for d in "$LE_LIVE"/*/; do
                f="$d/fullchain.pem"; [[ -f "$f" ]] || continue
                printf '  certbot  %-32s осталось %s дн.\n' "$(basename "$d")" "$(cert_days_left "$f" || echo ?)"
            done
            while read -r root; do
                for f in "$root"/*/*/*.crt; do
                    [[ -f "$f" ]] || continue
                    printf '  caddy    %-32s осталось %s дн.\n' "$(basename "$f" .crt)" "$(cert_days_left "$f" || echo ?)"
                done
            done < <(caddy_cert_roots | sort -u)
            [[ -n "${NODE_TLS_DOMAIN:-}" ]] && printf '  %-28s %s\n' "В ноде (Xray TLS):" "$NODE_TLS_DOMAIN"
            ;;
        *) die "cert list|method|issue <домен>";;
    esac
}

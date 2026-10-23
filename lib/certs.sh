#!/usr/bin/env bash
# fail2detect — сертификаты Let's Encrypt (certbot).
#
#   CERT_METHOD=http        HTTP-01: порт 80 открывается в фаерволе только на время проверки
#   CERT_METHOD=cloudflare  DNS-01 через API Cloudflare (порт 80 не нужен, можно wildcard)
# Продление — штатный таймер certbot; хуки fail2detect открывают/закрывают
# порт 80 и раскладывают обновлённый сертификат по nginx и ноде.

LE_LIVE="/etc/letsencrypt/live"
CF_INI="${F2D_CONF_DIR}/cloudflare.ini"

cert_deps() {
    have certbot && return 0
    info "Устанавливаю certbot…"
    pkg_install certbot python3-certbot-dns-cloudflare || pkg_install certbot || die "Не удалось установить certbot"
}

# каталог lineage, чей сертификат покрывает домен (в т.ч. wildcard)
cert_dir() {
    local domain="$1" d san
    for d in "$LE_LIVE"/*/; do
        [[ -f "$d/fullchain.pem" ]] || continue
        san=$(openssl x509 -in "$d/fullchain.pem" -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' | sed -n 's/.*DNS://p')
        while read -r name; do
            [[ "$name" == "$domain" ]] && { echo "${d%/}"; return 0; }
            [[ "$name" == \*.* && "$domain" == *."${name#\*.}" && "${domain%%.*}.${name#\*.}" == "$domain" ]] && { echo "${d%/}"; return 0; }
        done <<<"$san"
    done
    return 1
}

cert_days_left() {
    local end; end=$(openssl x509 -in "$1/fullchain.pem" -noout -enddate 2>/dev/null | cut -d= -f2) || return 1
    echo $(( ($(date -d "$end" +%s) - $(now)) / 86400 ))
}

cert_ask_method() {
    [[ -n "${CERT_METHOD:-}" ]] && return 0
    echo "  Как получать сертификаты:"
    echo "   1. HTTP-01 — нужен A-запись домена на этот сервер, порт 80 откроется на минуту"
    echo "   2. Cloudflare DNS — нужен API-токен Cloudflare (Zone.DNS:Edit), порт 80 не нужен"
    ask "Способ" "1"
    if [[ "$REPLY" == 2 ]]; then
        config_set CERT_METHOD cloudflare
        if [[ ! -s "$CF_INI" ]]; then
            local tok; read -r -s -p "Cloudflare API token: " tok; echo
            install -m 600 /dev/null "$CF_INI"
            printf 'dns_cloudflare_api_token = %s\n' "$tok" > "$CF_INI"
        fi
    else
        config_set CERT_METHOD http
    fi
    ask "E-mail для Let's Encrypt (пусто — без e-mail)" ""
    config_set CERT_EMAIL "$REPLY"
}

# получить сертификат, если его ещё нет
cert_ensure() {   # domain
    local domain="$1" dir
    if dir=$(cert_dir "$domain"); then
        local left; left=$(cert_days_left "$dir")
        ok "Сертификат для $domain есть ($dir, осталось ${left:-?} дн.)"
        return 0
    fi
    cert_deps
    cert_ask_method
    cert_hooks_install
    local mail=(--register-unsafely-without-email)
    [[ -n "${CERT_EMAIL:-}" ]] && mail=(-m "$CERT_EMAIL")
    info "Выпускаю сертификат для $domain ($CERT_METHOD)…"
    local rc=0
    if [[ "$CERT_METHOD" == cloudflare ]]; then
        local base="$domain"; [[ "$domain" == *.*.* ]] && base="${domain#*.}"
        certbot certonly --non-interactive --agree-tos "${mail[@]}" \
            --dns-cloudflare --dns-cloudflare-credentials "$CF_INI" --dns-cloudflare-propagation-seconds 30 \
            -d "$base" -d "*.$base" --cert-name "$base" || rc=$?
    else
        if ss -H -tln '( sport = :80 )' | grep -q .; then
            err "Порт 80 занят ($(ss -H -tlnp '( sport = :80 )' | grep -o 'users:(("[^"]*' | cut -d'"' -f2)) — HTTP-01 невозможен. Выберите Cloudflare DNS."
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

# сертификат для Xray кладём копией в <node_dir>/certs (монтируется в контейнер)
cert_install_for_node() {   # domain
    local d dir; d=$(node_dir); dir=$(cert_dir "$1") || return 1
    [[ -n "$d" ]] || return 1
    install -d -m 700 "$d/certs"
    install -m 644 "$dir/fullchain.pem" "$d/certs/fullchain.pem"
    install -m 600 "$dir/privkey.pem" "$d/certs/privkey.pem"
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
        pre)  [[ "$(grep -h '^authenticator' /etc/letsencrypt/renewal/*.conf 2>/dev/null)" == *standalone* ]] && acme_port80 open;;
        post) acme_port80 close;;
        deploy)
            if [[ -n "${NODE_TLS_DOMAIN:-}" ]] && has_node && cert_install_for_node "$NODE_TLS_DOMAIN"; then
                docker restart remnanode >/dev/null 2>&1 || true
            fi
            docker exec "$F2D_WEB_CONTAINER" nginx -s reload >/dev/null 2>&1 || true
            audit_write CERT - - - "сертификат продлён: ${RENEWED_DOMAINS:-?}";;
    esac
}

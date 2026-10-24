#!/usr/bin/env bash
# fail2detect — транспорты Xray для нод Remnawave.
#
#   tcp-reality    VLESS + TCP + Reality (+ xtls-rprx-vision, Remnawave ставит сам)
#   xhttp-reality  VLESS + XHTTP + Reality
#   xhttp-tls      VLESS + XHTTP + TLS (сертификат; можно за CDN)
#   grpc-reality   VLESS + gRPC + Reality
#   grpc-tls       VLESS + gRPC + TLS
#   hysteria2      Hysteria 2 (QUIC/UDP, TLS, опционально обфускация Salamander)
#
# Reality по умолчанию — «selfsteal»: неавторизованные подключения уходят на
# свой nginx (/dev/shm/nginx.sock) с настоящим сайтом и сертификатом на домен
# ноды. Так сканер видит обычный сайт, а IP и домен совпадают. Можно указать и
# чужой сайт (target вида www.example.com:443) — тогда домен и сертификат не нужны.

TRANSPORTS=(tcp-reality xhttp-reality xhttp-tls grpc-reality grpc-tls hysteria2)

# путь к сертификату ВНУТРИ контейнера remnanode (один и тот же на всех нодах,
# поэтому профиль можно переиспользовать)
XRAY_CERT_DIR="/etc/xray-certs"
NGINX_SOCK="/dev/shm/nginx.sock"

transport_title() {
    case "$1" in
        tcp-reality)   echo "VLESS · TCP · Reality (Vision)";;
        xhttp-reality) echo "VLESS · XHTTP · Reality";;
        xhttp-tls)     echo "VLESS · XHTTP · TLS";;
        grpc-reality)  echo "VLESS · gRPC · Reality";;
        grpc-tls)      echo "VLESS · gRPC · TLS";;
        hysteria2)     echo "Hysteria 2 · QUIC/UDP";;
        *) echo "$1";;
    esac
}
transport_valid()   { [[ " ${TRANSPORTS[*]} " == *" $1 "* ]]; }
# короткое имя для хоста в подписке: «Нода · Reality», «Нода · Hysteria2»
transport_label() {
    case "$1" in
        tcp-reality) echo "Reality";; xhttp-reality) echo "XHTTP";; xhttp-tls) echo "XHTTP TLS";;
        grpc-reality) echo "gRPC";; grpc-tls) echo "gRPC TLS";; hysteria2) echo "Hysteria2";; *) echo "$1";;
    esac
}
# порт по умолчанию — разные, чтобы транспорты уживались на одной ноде
transport_default_port() {
    case "$1" in
        tcp-reality|hysteria2) echo 443;; grpc-reality) echo 8443;; xhttp-reality) echo 4443;;
        xhttp-tls) echo 2083;; grpc-tls) echo 2087;; *) echo 443;;
    esac
}
transport_l4()      { [[ "$1" == hysteria2 ]] && echo udp || echo tcp; }
transport_reality() { [[ "$1" == *-reality ]]; }
transport_tls()     { [[ "$1" == *-tls || "$1" == hysteria2 ]]; }

# определить транспорт по JSON inbound'а
transport_of_inbound() {
    jq -r '
        (.streamSettings.network // "tcp") as $n | (.streamSettings.security // "none") as $s
        | if .protocol == "hysteria" then "hysteria2"
          elif ($n == "tcp" or $n == "raw") and $s == "reality" then "tcp-reality"
          elif $n == "xhttp" then "xhttp-" + $s
          elif $n == "grpc" then "grpc-" + $s
          else $n + "-" + $s end'
}

choose_transport() {   # -> REPLY
    local i=0 t
    for t in "${TRANSPORTS[@]}"; do
        i=$((i + 1)); printf '  %s%d.%s %-14s %s%s%s\n' "$C_YELLOW" "$i" "$C_RESET" "$t" "$C_GRAY" "$(transport_title "$t")" "$C_RESET"
    done
    ask "Транспорт" "${1:-1}"
    [[ "$REPLY" =~ ^[0-9]+$ ]] && REPLY="${TRANSPORTS[REPLY - 1]:-}"
    transport_valid "$REPLY" || die "Неизвестный транспорт: $REPLY"
}

rand_hex()  { openssl rand -hex "${1:-8}"; }
rand_path() { echo "/$(openssl rand -hex 6)"; }

# пара ключей X25519 для Reality: "private public" в base64url без '='
x25519_keys() {
    local pem; pem=$(openssl genpkey -algorithm X25519 2>/dev/null) || return 1
    local priv pub
    priv=$(openssl pkey -outform DER <<<"$pem" | tail -c 32 | base64 | tr '+/' '-_' | tr -d '=\n')
    pub=$(openssl pkey -pubout -outform DER <<<"$pem" | tail -c 32 | base64 | tr '+/' '-_' | tr -d '=\n')
    echo "$priv $pub"
}

# inbound_build transport tag port domain [target] [path] [privkey] [shortid] [obfs]
#   target  — куда Reality отдаёт чужих (по умолчанию свой nginx)
#   path    — XHTTP path или gRPC serviceName
#   obfs    — пароль Salamander для Hysteria 2 (пусто — без обфускации)
inbound_build() {
    local t="$1" tag="$2" port="$3" domain="${4:-}" target="${5:-}" path="${6:-}" priv="${7:-}" sid="${8:-}" obfs="${9:-}"
    [[ -z "$target" ]] && target="$NGINX_SOCK"
    if transport_reality "$t"; then
        [[ -z "$priv" ]] && priv=$(x25519_keys | cut -d' ' -f1)
        [[ -z "$sid" ]] && sid=$(rand_hex 8)
    fi
    [[ -z "$path" && "$t" == xhttp-* ]] && path=$(rand_path)
    [[ -z "$path" && "$t" == grpc-* ]] && path=$(rand_hex 6)
    local sni="$domain"
    # для чужого target serverNames = его домен
    if transport_reality "$t" && [[ "$target" != "$NGINX_SOCK" && -z "$sni" ]]; then sni="${target%%:*}"; fi

    jq -n --arg t "$t" --arg tag "$tag" --argjson port "$port" --arg sni "$sni" --arg target "$target" \
          --arg path "${path#/}" --arg priv "$priv" --arg sid "$sid" --arg obfs "$obfs" --arg certdir "$XRAY_CERT_DIR" --arg sock "$NGINX_SOCK" '
        def reality: {
            security: "reality",
            realitySettings: ({
                show: false, target: $target, serverNames: [$sni],
                privateKey: $priv, shortIds: [$sid]
            } + (if $target == $sock then {xver: 1} else {} end))
        };
        def tls($alpn): {
            security: "tls",
            tlsSettings: {
                serverName: $sni, alpn: $alpn, minVersion: "1.2",
                certificates: [{ certificateFile: ($certdir + "/fullchain.pem"), keyFile: ($certdir + "/privkey.pem") }]
            }
        };
        def vless($stream): {
            tag: $tag, port: $port, listen: "0.0.0.0", protocol: "vless",
            settings: { clients: [], decryption: "none" },
            sniffing: { enabled: true, destOverride: ["http", "tls", "quic"] },
            streamSettings: $stream
        };
        if   $t == "tcp-reality"   then vless({network: "raw"} + reality)
        elif $t == "xhttp-reality" then vless({network: "xhttp", xhttpSettings: {path: ("/" + $path), mode: "auto"}} + reality)
        elif $t == "xhttp-tls"     then vless({network: "xhttp", xhttpSettings: {path: ("/" + $path), mode: "auto", host: $sni}} + tls(["h2", "http/1.1"]))
        elif $t == "grpc-reality"  then vless({network: "grpc", grpcSettings: {serviceName: $path}} + reality)
        elif $t == "grpc-tls"      then vless({network: "grpc", grpcSettings: {serviceName: $path}} + tls(["h2"]))
        elif $t == "hysteria2" then {
            tag: $tag, port: $port, listen: "0.0.0.0", protocol: "hysteria",
            settings: { version: 2, clients: [] },
            sniffing: { enabled: true, destOverride: ["http", "tls", "quic"] },
            streamSettings: ({
                network: "hysteria",
                hysteriaSettings: { version: 2, udpIdleTimeout: 60 }
            } + tls(["h3"])
              + (if $obfs != "" then {finalmask: {udp: [{type: "salamander", settings: {password: $obfs}}]}} else {} end))
        }
        else error("unknown transport") end'
}

# поля хоста Remnawave (что попадёт в подписку клиентам) для транспорта
host_fields() {   # inbound_json address
    local inb="$1" addr="$2"
    jq -n --argjson i "$inb" --arg addr "$addr" '
        ($i.streamSettings // {}) as $s
        | (if $s.security == "reality" then ($s.realitySettings.serverNames[0] // "")
           elif $s.security == "tls" then ($s.tlsSettings.serverName // "") else "" end) as $sni
        | {
            address: $addr,
            port: $i.port,
            sni: (if $sni == "" then null else $sni end),
            host: (if $s.network == "xhttp" and $s.security == "tls" then $sni else null end),
            path: (if $s.network == "xhttp" then $s.xhttpSettings.path
                   elif $s.network == "grpc" then $s.grpcSettings.serviceName else null end),
            alpn: (if $i.protocol == "hysteria" then "h3"
                   elif $s.network == "grpc" and $s.security == "tls" then "h2" else null end),
            fingerprint: (if $i.protocol == "hysteria" then null else "chrome" end),
            securityLayer: "DEFAULT",
            finalMask: ($s.finalmask // null)
        }'
}

# базовый конфиг Xray для нового профиля
profile_config() {   # inbound_json или [inbound, …]
    jq -n --argjson i "$1" '{
        log: { loglevel: "warning" },
        inbounds: (if ($i | type) == "array" then $i else [$i] end),
        outbounds: [
            { tag: "DIRECT", protocol: "freedom" },
            { tag: "BLOCK", protocol: "blackhole" }
        ],
        routing: {
            rules: [
                { ip: ["geoip:private"], outboundTag: "BLOCK" },
                { protocol: ["bittorrent"], outboundTag: "BLOCK" }
            ]
        }
    }'
}

# ---------- подготовка ноды под транспорт (выполняется на сервере ноды) ----------

# Добавить в docker-compose ноды монтирование сертификатов (подходит и для
# compose сторонних установщиков). 0 — файл изменён, 1 — уже было.
node_compose_add_certs() {
    local f; f="$(node_dir)/docker-compose.yml"
    [[ -f "$f" ]] || return 1
    grep -q "$XRAY_CERT_DIR" "$f" && return 1
    cp -a "$f" "$f.f2d.bak"
    # Отступы берём из самого файла: у разных установщиков сервисы сдвинуты
    # на 2 или 4 пробела, ключи и списки — на свою глубину.
    awk -v mnt="./certs:${XRAY_CERT_DIR}:ro" '
        function ind(s) { match(s, /^ */); return RLENGTH }
        function sp(n,   r) { r=""; while (n-- > 0) r = r " "; return r }
        function flush() {
            if (insvc && !done) { k = kind ? kind : sind + 2
                print sp(k) "volumes:"; print sp(k + 2) "- " mnt; done = 1 }
        }
        # ждём первую строку после «volumes:» — по ней узнаём отступ элементов списка
        invol {
            if ($0 ~ /^ *- /) { print sp(ind($0)) "- " mnt }
            else { print sp(kind + 2) "- " mnt }
            invol = 0; done = 1
        }
        /^ *remnanode:[ \t]*$/ && !insvc && !done { insvc = 1; sind = ind($0); print; next }
        insvc && NF {
            if (ind($0) <= sind) { flush(); insvc = 0 }
            else if (!kind) kind = ind($0)
        }
        insvc && !done && kind && ind($0) == kind && $0 ~ /^ *volumes:[ \t]*$/ { print; invol = 1; next }
        { print }
        END { if (invol) print sp(kind + 2) "- " mnt; flush() }
    ' "$f.f2d.bak" > "$f"
    grep -q "$XRAY_CERT_DIR" "$f" || { cp -a "$f.f2d.bak" "$f"; err "Не удалось добавить монтирование сертификатов в $f"; return 2; }
    return 0
}

# Видит ли контейнер ноды сертификат? Проверяем ДО изменения панели: иначе
# Xray получит конфиг с TLS, не найдёт файл и нода ляжет.
node_certs_visible() {
    docker exec remnanode test -s "$XRAY_CERT_DIR/fullchain.pem" 2>/dev/null \
        && docker exec remnanode test -s "$XRAY_CERT_DIR/privkey.pem" 2>/dev/null
}

# node_prepare transport port domain [target] [old_port/proto]
node_prepare() {
    local t="$1" port="$2" domain="${3:-}" target="${4:-}" old="${5:-}"
    transport_valid "$t" || die "Неизвестный транспорт: $t"
    is_port "$port" || die "Неверный порт: $port"
    local d; d=$(node_dir); [[ -n "$d" ]] || die "Нода на этом сервере не найдена"
    local l4; l4=$(transport_l4 "$t")
    title "Подготовка ноды: $(transport_title "$t") на $port/$l4"

    # порт свободен? (тот же порт у старого inbound'а — не помеха)
    if [[ "$old" != "$port/$l4" ]] && ss -H -"${l4:0:1}"ln "( sport = :$port )" 2>/dev/null | grep -q .; then
        die "Порт $port/$l4 уже занят: $(ss -H -"${l4:0:1}"lnp "( sport = :$port )" | grep -o 'users:(("[^"]*' | cut -d'"' -f2 | head -1)"
    fi

    # сертификат для TLS-транспортов
    if transport_tls "$t"; then
        [[ -n "$domain" ]] || die "Для $t нужен домен ноды"
        cert_ensure "$domain" || die "Не удалось получить сертификат для $domain"
        cert_install_for_node "$domain" || die "Не удалось скопировать сертификат $domain в $d/certs"
        config_set NODE_TLS_DOMAIN "$domain"
        local rc=0; node_compose_add_certs || rc=$?
        (( rc == 2 )) && die "Добавьте в $d/docker-compose.yml в volumes сервиса remnanode: - ./certs:$XRAY_CERT_DIR:ro"
        if (( rc == 0 )) || ! node_certs_visible; then
            info "Пересоздаю контейнер ноды, чтобы подключить ${XRAY_CERT_DIR}…"
            (cd "$d" && docker compose up -d --force-recreate remnanode >/dev/null 2>&1) || die "docker compose не пересоздал remnanode"
            local i; for i in $(seq 1 15); do node_certs_visible && break; sleep 1; done
        fi
        node_certs_visible || die "Контейнер remnanode не видит $XRAY_CERT_DIR/fullchain.pem — панель НЕ изменена. Проверьте volumes в $d/docker-compose.yml"
        ok "Нода видит сертификат $domain ($XRAY_CERT_DIR)"
    fi

    # selfsteal-сайт для Reality
    if transport_reality "$t" && [[ -z "$target" || "$target" == "$NGINX_SOCK" ]]; then
        if [[ -S "$NGINX_SOCK" ]]; then
            ok "Selfsteal-сайт уже работает ($NGINX_SOCK)"
        else
            [[ -n "$domain" ]] || die "Для Reality-selfsteal нужен домен (или укажите чужой target)"
            cert_ensure "$domain" || die "Не удалось получить сертификат для $domain"
            web_set SELFSTEAL_DOMAIN "$domain"
            web_apply || die "Не удалось поднять nginx для selfsteal"
        fi
    fi

    # фаервол
    list_add "PUBLIC_$( [[ $l4 == udp ]] && echo UDP || echo TCP )" "$port"
    list_add NODE_XRAY_PORTS "$port/$l4"   # чтобы при удалении ноды закрыть именно их
    ufw_allow "$port" "$l4" "" "Xray $t"
    if [[ -n "$old" && "$old" != "$port/$l4" ]]; then
        local op="${old%/*}" ol="${old#*/}"
        if [[ " $(detect_ssh_ports) " != *" $op "* ]]; then
            list_del NODE_XRAY_PORTS "$old"
            list_del "PUBLIC_$( [[ $ol == udp ]] && echo UDP || echo TCP )" "$op"
            ufw_delete_allow "$op" "$ol"
            info "Старый порт $op/$ol закрыт"
        fi
    fi
    fw_apply >/dev/null && ok "Фаервол: открыт $port/$l4"
    audit_write NODE_PREPARE - - - "$t $port/$l4 ${domain:-}"
}

# дождаться, что Xray слушает порт
node_wait_port() {   # port l4
    local i flag; [[ "$2" == udp ]] && flag=-uln || flag=-tln
    for i in $(seq 1 40); do ss -H $flag "( sport = :$1 )" 2>/dev/null | grep -q . && return 0; sleep 1; done
    return 1
}

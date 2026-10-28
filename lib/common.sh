#!/usr/bin/env bash
# fail2detect — общие функции: цвета, вывод, конфиг, зависимости.

F2D_VERSION="0.5.0-beta"
F2D_REPO="${F2D_REPO:-HenseyLink/fail2detect}"

F2D_CONF_DIR="${F2D_CONF_DIR:-/etc/fail2detect}"
F2D_CONF="${F2D_CONF_DIR}/fail2detect.conf"
F2D_JAIL_DIR="${F2D_CONF_DIR}/jail.d"
F2D_STATE_DIR="${F2D_STATE_DIR:-/var/lib/fail2detect}"
F2D_LOG_DIR="${F2D_LOG_DIR:-/var/log/fail2detect}"
F2D_AUDIT_LOG="${F2D_LOG_DIR}/audit.log"
F2D_BANS_DB="${F2D_STATE_DIR}/bans.tsv"
F2D_NFT_FILE="${F2D_STATE_DIR}/fail2detect.nft"
F2D_NFT_TABLE="fail2detect"

# совместимость с серверами, поставленными сторонним установщиком remnawave-reverse-proxy
RP_DIR="/usr/local/remnawave_reverse"
RW_PANEL_DIR="/opt/remnawave"
RW_NODE_DIR="/opt/remnanode"

# ---------- цвета и вывод ----------
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
    C_RED=$'\033[1;31m'; C_GREEN=$'\033[1;32m'; C_YELLOW=$'\033[1;33m'
    C_BLUE=$'\033[1;34m'; C_MAGENTA=$'\033[1;35m'; C_CYAN=$'\033[1;36m'
    C_WHITE=$'\033[1;37m'; C_GRAY=$'\033[0;90m'
else
    C_RESET=""; C_BOLD=""; C_DIM=""; C_RED=""; C_GREEN=""; C_YELLOW=""
    C_BLUE=""; C_MAGENTA=""; C_CYAN=""; C_WHITE=""; C_GRAY=""
fi

info()  { printf '%s➜%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }
ok()    { printf '%s✔%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn()  { printf '%s!%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
err()   { printf '%s✘%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
die()   { err "$*"; exit 1; }
hr()    { printf '%s%s%s\n' "$C_GRAY" "$(printf '─%.0s' $(seq 1 "${1:-60}"))" "$C_RESET"; }
title() { printf '\n%s%s%s\n' "$C_BOLD$C_MAGENTA" "$*" "$C_RESET"; hr; }

# ask "Вопрос" [default] -> REPLY
# Вопрос с редактированием строки (стрелки, Backspace, Home/End — readline).
# Текст вопроса отдаём самому readline (read -e -p), а цветовые коды
# оборачиваем в \001…\002: иначе readline не знает ширину вопроса, и
# Backspace стирал его с экрана, хотя ввод продолжал ждать ответа.
_rl() { [[ -n "$1" ]] && printf '\001%s\002' "$1"; }
ask() {
    local prompt="$1" def="${2:-}" p
    if [[ -n "$def" ]]; then
        p="$(_rl "$C_YELLOW")?$(_rl "$C_RESET") $prompt $(_rl "$C_GRAY")[$def]$(_rl "$C_RESET"): "
    else
        p="$(_rl "$C_YELLOW")?$(_rl "$C_RESET") $prompt: "
    fi
    if [[ -t 0 ]]; then
        IFS= read -r -e -p "$p" REPLY || REPLY=""
    else
        printf '%s' "${p//[$'\001\002']/}" >&2
        IFS= read -r REPLY || REPLY=""
    fi
    [[ -z "$REPLY" && -n "$def" ]] && REPLY="$def"
    REPLY="${REPLY#"${REPLY%%[![:space:]]*}"}"; REPLY="${REPLY%"${REPLY##*[![:space:]]}"}"   # обрезать пробелы
}

# confirm "Вопрос" [y|n] — 0 если да
# Ответ читаем в СВОЮ переменную: REPLY часто ещё хранит то, что ввели перед
# вопросом (e-mail, IP), и «y» его затирал — так в конфиг попадал e-mail «y».
confirm() {
    local def="${2:-n}" hint="y/N" ans=""
    [[ "$def" == y ]] && hint="Y/n"
    [[ "${F2D_ASSUME_YES:-0}" == 1 ]] && return 0
    printf '%s?%s %s %s[%s]%s: ' "$C_YELLOW" "$C_RESET" "$1" "$C_GRAY" "$hint" "$C_RESET" >&2
    IFS= read -r ans || ans=""
    is_yes "${ans:-$def}"
}

# Ввод секрета (токены): вставка ВИДНА — в скрытом режиме (read -s) кажется,
# что вставить не получилось, а терминалы с bracketed paste подмешивают в
# значение \e[200~…\e[201~. После Enter строка стирается и вместо неё
# показывается маска. Результат — в REPLY.
mask_secret() {
    local v="$1"
    if (( ${#v} <= 12 )); then echo "${v:0:2}… (${#v} симв.)"; else echo "${v:0:4}…${v: -4} (${#v} симв.)"; fi
}
read_secret() {   # "вопрос"
    local prompt="$1" v="" plain lines cols
    printf '%s?%s %s: ' "$C_YELLOW" "$C_RESET" "$prompt" >&2
    IFS= read -r v || true
    v="${v//$'\e[200~'/}"; v="${v//$'\e[201~'/}"; v="${v//[$'\r\t ']/}"
    if [[ -t 2 ]]; then
        # стереть всё, что заняли вопрос и вставленное значение (с учётом переноса строк)
        cols=$(stty size </dev/tty 2>/dev/null | awk '{print $2}'); [[ "$cols" =~ ^[0-9]+$ && cols -gt 0 ]] || cols=80
        plain="? $prompt: $v"
        lines=$(( (${#plain} + cols - 1) / cols )); (( lines < 1 )) && lines=1
        printf '\033[%dA\r\033[J' "$lines" >&2
        if [[ -n "$v" ]]; then
            printf '%s?%s %s: %s%s%s\n' "$C_YELLOW" "$C_RESET" "$prompt" "$C_GREEN" "$(mask_secret "$v")" "$C_RESET" >&2
        else
            printf '%s?%s %s: %sпусто%s\n' "$C_YELLOW" "$C_RESET" "$prompt" "$C_GRAY" "$C_RESET" >&2
        fi
    fi
    REPLY="$v"
}

# «да» — любой ответ, начинающийся с y/д (y, yy, yes, да, Д…)
is_yes() { [[ "${1:-}" =~ ^[[:space:]]*[yYдД] ]]; }

pause() { [[ -t 0 ]] && read -r -s -n1 -p "$(printf '%sНажмите любую клавишу…%s' "$C_GRAY" "$C_RESET")" && echo; }

# ---------- проверки ----------
require_root() { [[ $EUID -eq 0 ]] || die "Нужны права root (sudo fail2detect …)"; }

have() { command -v "$1" >/dev/null 2>&1; }

is_ipv4() {
    local ip="${1%/*}" o
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for o in "${BASH_REMATCH[@]:1}"; do (( o <= 255 )) || return 1; done
    if [[ "$1" == */* ]]; then local m="${1#*/}"; [[ "$m" =~ ^[0-9]+$ ]] && (( m <= 32 )) || return 1; fi
}
is_ipv6() { [[ "${1%/*}" == *:* && "${1%/*}" =~ ^[0-9a-fA-F:.]+$ ]]; }
is_ip()   { is_ipv4 "$1" || is_ipv6 "$1"; }
is_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }

# частные/служебные сети никогда не баним
is_private_ip() {
    local ip="$1"
    [[ "$ip" =~ ^(127\.|10\.|192\.168\.|169\.254\.|0\.) ]] && return 0
    [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]] && return 0
    [[ "$ip" =~ ^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\. ]] && return 0
    [[ "${ip,,}" =~ ^(::1$|fe80:|fc|fd) ]] && return 0
    return 1
}

now() { date +%s; }
iso_now() { date '+%Y-%m-%d %H:%M:%S'; }

# "1h", "30m", "7d", "3600" -> секунды
to_seconds() {
    local v="$1"
    case "$v" in
        *d) echo $(( ${v%d} * 86400 ));;
        *h) echo $(( ${v%h} * 3600 ));;
        *m) echo $(( ${v%m} * 60 ));;
        *s) echo "${v%s}";;
        *)  echo "$v";;
    esac
}
human_duration() {
    local s="$1"
    (( s <= 0 )) && { echo "навсегда"; return; }
    if   (( s >= 86400 )); then printf '%dд%dч\n' $((s/86400)) $((s%86400/3600))
    elif (( s >= 3600 ));  then printf '%dч%dм\n' $((s/3600)) $((s%3600/60))
    elif (( s >= 60 ));    then printf '%dм%dс\n' $((s/60)) $((s%60))
    else printf '%dс\n' "$s"; fi
}

# ---------- конфиг ----------
# Значения по умолчанию; /etc/fail2detect/fail2detect.conf переопределяет.
config_defaults() {
    FW_MODE="auto"              # auto | ufw | nft
    SSH_PORTS=""                # пусто = автоопределение
    PUBLIC_TCP=""               # доп. открытые TCP-порты (через пробел)
    PUBLIC_UDP=""
    XRAY_PORTS=""               # пусто = автоопределение
    NODE_API_PORT=""            # пусто = из docker-compose ноды
    PANEL_IPS=""                # IP панели (доступ к NODE_PORT)
    TRUSTED_IPS=""              # белый список (админ, мониторинг)
    STEALTH_ICMP="yes"          # не отвечать на ping
    DOCKER_GUARD="yes"          # не пускать извне в опубликованные docker-порты
    UPDATE_CHECK="yes"          # проверять новую версию fail2detect при запуске меню (раз в 6 часов)
    BAN_SCOPE="except-xray"     # except-xray — бан не закрывает порты Xray (CGNAT мобильных); all — закрывает всё
    FLOOD_GUARD="no"            # бан за шквал новых соединений
    FLOOD_RATE="600/minute"     # осторожно: CGNAT мобильных операторов
    FLOOD_BANTIME="10m"
    BLOCKLISTS="antiscanner skipa"
    BLOCKLIST_URL_antiscanner="https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/main/public/antiscanner.list"
    BLOCKLIST_URL_skipa="https://raw.githubusercontent.com/tread-lightly/CyberOK_Skipa_ips/main/lists/skipa_cidr.txt"
    BLOCKLIST_URL_government="https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/main/public/government_networks.list"
    BANTIME_INCREMENT="yes"     # повторный бан — вдвое дольше
    BANTIME_MAX="30d"
    GEO_LOOKUP="yes"            # страна в журнале аудита
    RW_API_URL="http://127.0.0.1:3000"
    RW_API_TOKEN=""
    CERT_METHOD=""              # http | cloudflare (спросит при первом сертификате)
    CERT_EMAIL=""
    NODE_TLS_DOMAIN=""          # домен, чей сертификат лежит в ноде (/etc/xray-certs)
    NODE_XRAY_PORTS=""          # порты Xray, открытые fail2detect (443/tcp 443/udp …)
    ABUSEIPDB_KEY=""            # бесплатный ключ AbuseIPDB для IPQuality (необязательно)
    TG_BOT_TOKEN=""             # уведомления о банах (необязательно)
    TG_CHAT_ID=""
}

load_config() {
    config_defaults
    # shellcheck disable=SC1090
    [[ -f "$F2D_CONF" ]] && source "$F2D_CONF"
    return 0
}

# config_set KEY VALUE — правит/добавляет строку в конфиге
config_set() {
    local key="$1" val="$2"
    mkdir -p "$F2D_CONF_DIR"
    touch "$F2D_CONF"; chmod 600 "$F2D_CONF"
    local esc; esc=$(printf '%s' "$val" | sed 's/[\\"$`]/\\&/g')
    if grep -qE "^${key}=" "$F2D_CONF"; then
        local tmp; tmp=$(mktemp)
        awk -v k="$key" -v v="$esc" 'BEGIN{FS=OFS="="} $1==k{print k "=\"" v "\""; next} {print}' "$F2D_CONF" > "$tmp" && cat "$tmp" > "$F2D_CONF"
        rm -f "$tmp"
    else
        printf '%s="%s"\n' "$key" "$esc" >> "$F2D_CONF"
    fi
    printf -v "$key" '%s' "$val"
}

# добавить/убрать элемент в списке через пробел
list_add() {
    local cur=" ${!1} "; [[ "$cur" == *" $2 "* ]] && return 0
    local -a items; read -ra items <<<"${!1}"
    items+=("$2"); config_set "$1" "${items[*]}"
}
list_del() { local out="" x; for x in ${!1}; do [[ "$x" == "$2" ]] || out+="$x "; done; config_set "$1" "${out% }"; }

ensure_dirs() {
    mkdir -p "$F2D_CONF_DIR" "$F2D_JAIL_DIR" "$F2D_STATE_DIR" "$F2D_LOG_DIR"
    chmod 700 "$F2D_CONF_DIR" "$F2D_STATE_DIR"
    touch "$F2D_AUDIT_LOG" "$F2D_BANS_DB"
}

pkg_install() {
    if have apt-get; then DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null
    elif have dnf; then dnf install -y -q "$@" >/dev/null
    elif have yum; then yum install -y -q "$@" >/dev/null
    else return 1; fi
}

ensure_deps() {
    local missing=() c
    for c in nft curl jq ss awk; do have "$c" || missing+=("$c"); done
    ((${#missing[@]})) || return 0
    info "Устанавливаю зависимости: ${missing[*]}"
    local pkgs=()
    for c in "${missing[@]}"; do
        case "$c" in nft) pkgs+=(nftables);; ss) pkgs+=(iproute2);; awk) pkgs+=(gawk);; *) pkgs+=("$c");; esac
    done
    have apt-get && apt-get update -qq >/dev/null 2>&1
    pkg_install "${pkgs[@]}" || die "Не удалось установить: ${pkgs[*]}"
}

# публичный IPv4 сервера
public_ip() {
    local ip
    for u in https://api.ipify.org https://ifconfig.me https://ipv4.icanhazip.com; do
        ip=$(curl -fsS4 --max-time 6 "$u" 2>/dev/null | tr -d '[:space:]')
        is_ipv4 "$ip" && { echo "$ip"; return 0; }
    done
    return 1
}

# Telegram-уведомление (тихо, если не настроено)
notify() {
    [[ -n "$TG_BOT_TOKEN" && -n "$TG_CHAT_ID" ]] || return 0
    curl -fsS --max-time 8 -o /dev/null \
        --data-urlencode "chat_id=${TG_CHAT_ID}" --data-urlencode "text=$1" \
        "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage" 2>/dev/null &
}

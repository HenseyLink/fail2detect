# fail2detect

Защита нод и панели [Remnawave](https://github.com/remnawave) от сканеров РКН, активного зондирования и брутфорса.

Проект объединяет две идеи:

- **[fail2ban](https://github.com/fail2ban/fail2ban)**: читать логи, считать неудачные попытки с одного IP и банить его;
- **[remnawave-reverse-proxy от eGames](https://github.com/eGamesAPI/remnawave-reverse-proxy)**: популярный установщик панели, нод и страницы подписки. fail2detect с ним совместим: защищает ноды, поставленные eGames, умеет менять у них порт и транспорт и может запустить сам скрипт eGames.

Главная задача fail2detect — защита уже работающих нод и панелей. Кроме того, в нём есть собственный установщик. Он не копирует скрипт eGames: файлы панели и страницы подписки берутся из официальных репозиториев Remnawave. В отличие от eGames, порт ноды и транспорт можно выбрать.

## Установка

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/fail2detect/fail2detect/main/install.sh)
```

Скрипт ставит зависимости (`nftables curl jq`), копирует файлы в `/opt/fail2detect` и создаёт команду `fail2detect`. Затем он предлагает запустить мастер настройки.

Если запустить `fail2detect` без аргументов, откроется интерактивное меню.

## Что делает

### 1. Фаервол и порты

Правила лежат в отдельной таблице nftables `inet fail2detect`. Она обрабатывает пакеты раньше UFW и Docker и может их только запрещать. Если пакет разрешён в таблице fail2detect, его дальше проверяют правила UFW, поэтому то, что настроил eGames, продолжает работать.

| Защита | Зачем |
|---|---|
| Закрытые порты + журнал попыток | Сканер видит только Xray и SSH. Остальное молчит |
| API ноды (`NODE_PORT`, 2222) доступен только с IP панели | Сканер не найдёт характерный порт ноды Remnawave |
| Блок-листы сканеров ([antiscanner](https://github.com/shadow-netlab/traffic-guard-lists), [CyberOK «Скипа»](https://github.com/tread-lightly/CyberOK_Skipa_ips)) | Известные сети сканеров отсекаются ещё до рукопожатия. Списки обновляются раз в сутки |
| Блок-лист госсетей РФ (опционально) | Около 12 тыс. подсетей |
| Скрытие от ping | Сервер не попадает в выдачу массовых ICMP-сканов |
| Защита docker-портов | Docker публикует порты в обход UFW. fail2detect это закрывает |
| Анти-флуд (опционально) | Бан за шквал новых соединений прямо в ядре |
| Безопасное применение | Если не подтвердить, что SSH работает, через 60 с правила откатываются |

Режимы работы:
- `ufw` (сервер настроен eGames): списком открытых портов управляет UFW, а fail2detect добавляет поверх баны и защиту;
- `nft` (UFW нет): fail2detect сам закрывает всё, кроме SSH, Xray и явно открытых портов.

### 2. Баны по принципу fail2ban

| Jail | Источник | Что ловит | По умолчанию |
|---|---|---|---|
| `sshd` | journald | перебор паролей, SSH-сканеры | вкл, 5 за 10 мин → 1 ч |
| `portscan` | журнал ядра | стук в закрытые порты и в API ноды | вкл, 3 за 10 мин → 1 сутки |
| `flood` | журнал ядра | записывает баны анти-флуда | вкл |
| `panel` | `docker logs remnawave-nginx` | запросы к панели без секретного ключа eGames (ответ 444) | вкл на сервере с одной панелью |
| `reality` | лог Xray | невалидные Reality-подключения (активное зондирование) | выкл, включается `fail2detect node logs` |

Повторный бан того же IP длится вдвое дольше, максимум 30 дней. Баны переживают перезагрузку. Никогда не банятся частные сети, IP панели, белый список и адрес вашей текущей SSH-сессии.

Jail'ы — это файлы `/etc/fail2detect/jail.d/*.conf`. Синтаксис похож на fail2ban, IP в регулярке обозначается `<HOST>`. Регулярки можно проверить на реальных логах командой `fail2detect jail test sshd`.

### 3. Журнал аудита

В `/var/log/fail2detect/audit.log` (TSV) записываются все баны, разбаны, пропуски из-за белого списка, смена портов и изменения фаервола. Для каждого бана указаны страна и строка лога, которая к нему привела.

```bash
fail2detect log                     # последние 50 записей
fail2detect log --ip 1.2.3.4        # история конкретного IP
fail2detect log --action BAN --today
fail2detect stats                   # топ jail'ов, стран, подсетей
fail2detect unban 1.2.3.4           # разбанить чистый IP
fail2detect trust add 1.2.3.4       # и больше никогда не банить
```

Уведомления о банах можно получать в Telegram: задайте `TG_BOT_TOKEN` и `TG_CHAT_ID`.

### 4. Установка: любой порт и транспорт

```bash
fail2detect install panel     # панель (+ страница подписки, + нода на этом же сервере)
fail2detect node add          # на сервере панели: профиль + нода + хост + squad, выдаёт команду для ноды
fail2detect install node      # на сервере ноды (или готовая команда из `node add`)
fail2detect install sub       # страница подписки (на сервере панели или отдельно)
fail2detect install egames    # оригинальный скрипт eGames
```

| Транспорт | Что это | Что нужно на ноде |
|---|---|---|
| `tcp-reality` | VLESS + TCP + Reality + Vision | домен (selfsteal) или чужой сайт |
| `xhttp-reality` | VLESS + XHTTP + Reality | то же |
| `xhttp-tls` | VLESS + XHTTP + TLS (можно за CDN) | домен + сертификат |
| `grpc-reality` | VLESS + gRPC + Reality | домен (selfsteal) или чужой сайт |
| `grpc-tls` | VLESS + gRPC + TLS | домен + сертификат |
| `hysteria2` | Hysteria 2, QUIC/UDP (+ обфускация Salamander) | домен + сертификат, UDP-порт |

Как это устроено:
- **Порт** любой, Hysteria 2 работает по UDP. Фаервол открывает нужный протокол сам.
- **Selfsteal для Reality.** Сканер, пришедший на порт Reality, видит обычный сайт на домене ноды. Сайт обслуживает свой nginx через `/dev/shm/nginx.sock`, сертификат выпускается автоматически. Вместо своего сайта можно указать чужой (`www.example.com:443`).
- **Сертификаты:** Let's Encrypt, через HTTP-01 (порт 80 открывается на минуту) или Cloudflare DNS. Продление автоматическое, обновлённый сертификат копируется в ноду (`/etc/xray-certs`).
- **Панель** скрыта за секретным ключом в ссылке входа: без него nginx рвёт соединение (444). API доступно по Bearer-токену.

### 5. Смена порта и транспорта у работающей ноды

```bash
fail2detect node transport          # сменить транспорт и/или порт (например tcp-reality:443 → xhttp-reality:8443 или → hysteria2)
fail2detect node port 8443          # только перенести порт
fail2detect node api-port 32222     # сменить NODE_PORT (2222) в compose, UFW и панели
fail2detect node inbounds           # посмотреть inbound'ы, порты и транспорты
```

`node transport` делает всё согласованно:
1. Готовит ноду, пока она ещё работает на старом конфиге: сертификат, монтирование в контейнер, selfsteal-сайт, фаервол TCP/UDP.
2. Пересобирает inbound с тем же tag. Ключи Reality и path сохраняются, где это возможно.
3. Перепривязывает ноды, хосты и squad'ы, если панель выдала inbound'у новый uuid.
4. Обновляет хосты: порт, SNI, path и ALPN уходят клиентам в подписку.

Если нода на другом сервере, fail2detect покажет команду `fail2detect node prepare …` для неё и подождёт подтверждения. Только после этого он изменит панель.

**Нода от eGames.** Установите на неё fail2detect и выполните `node transport` (или `node prepare` на ноде и `node transport` на панели). fail2detect не трогает nginx eGames: Reality продолжает работать через его сокет, а для TLS-транспортов берётся сертификат, который eGames уже выпустил.

**Почему eGames не ставит ноду на 8443.** Его установщик жёстко прописывает 443 в нескольких местах:
- правило UFW `allow 443/tcp`;
- inbound в профиле конфигурации (`port: 443`);
- хост (порт, который уходит клиентам в подписку);
- финальная проверка `curl https://домен` (по умолчанию на 443).

Если ставить на 8443, проверка падает, и установщик сообщает, что нода не подключилась. Есть два выхода: поставить ноду через eGames на 443 и затем выполнить `fail2detect node port 8443`, либо сразу ставить через `fail2detect install node`.

**Вручную, без скриптов.** Порядок такой:
1. На ноде: если меняется протокол, откройте новый порт в UFW (`ufw allow 8443/tcp`, для Hysteria — `/udp`).
2. Для TLS-транспортов на ноде: положите сертификат в каталог, смонтированный в контейнер `remnanode`.
3. В панели, Профили конфигурации: поменяйте у inbound'а `port` и `streamSettings`. Готовый JSON выдаст `fail2detect node inbound-json <транспорт> <порт> <домен>`.
4. В панели, Хосты: поменяйте порт, SNI и path.
5. Проверьте, что inbound включён у ноды и в squad'е.

API-токен берётся в таком порядке:
- после `install panel` — токен fail2detect;
- иначе — токен скрипта eGames (`/usr/local/remnawave_reverse/token`);
- если нет ни того, ни другого, fail2detect спросит токен один раз.

Если панель на другом сервере, укажите `RW_API_URL` и, если панель закрыта cookie-ключом, `RW_API_COOKIE`.

После смены порта или транспорта клиентам нужно обновить подписку.

### 6. GeoCheck и Cloudflare Speedtest

```bash
fail2detect geo        # страна IP по 7 гео-базам + YouTube, Netflix, ChatGPT, Claude, Gemini, Google, Steam
fail2detect speed      # задержка, джиттер, скачивание/загрузка через speed.cloudflare.com
fail2detect speed --tui  # полноэкранный cloudflare-speed-cli (kavehtehrani), ставится по запросу
```

### 7. Аудит безопасности

`fail2detect doctor` проверяет:
- торчат ли наружу внутренние порты панели (3000, 5432, …);
- открыт ли API ноды всему интернету;
- не обходят ли docker-порты фаервол;
- разрешён ли вход по паролю в SSH;
- какой транспорт у inbound'ов.

## Про TLS-in-TLS (честно)

Закрытие портов защищает от **активного** обнаружения, когда регулятор сам сканирует сервер и зондирует найденные TLS-сервисы. Это главное, что делает fail2detect.

Детект «двойного рукопожатия» (TLS-in-TLS) — **пассивный** анализ трафика клиента. Фаерволом сервера его не закрыть. Против него работает транспорт: VLESS + Reality поверх TCP с `flow: xtls-rprx-vision`. `fail2detect doctor` предупреждает, если inbound настроен иначе (ws/grpc/xhttp поверх TLS и т. п.).

## Осторожно: CGNAT

Мобильные операторы в РФ выводят тысячи абонентов через один IP. Поэтому:
- jail'ы, которые смотрят на соединения клиентов (`reality`, анти-флуд), по умолчанию выключены или с высоким порогом;
- jail'ы `portscan` и `sshd` безопасны, потому что ваши клиенты не стучатся в закрытые порты и SSH.

## Файлы

```
/opt/fail2detect/                 код
/etc/fail2detect/fail2detect.conf   настройки (см. conf/fail2detect.conf)
/etc/fail2detect/jail.d/          jail'ы
/var/lib/fail2detect/             баны, блок-листы, сгенерированные правила
/var/log/fail2detect/audit.log    журнал аудита
/etc/fail2detect/web.env          домены и ключ панели для nginx
/opt/fail2detect-web/             nginx (панель, подписка, selfsteal)
/opt/remnawave/  /opt/remnanode/  /opt/subscription/   Remnawave (те же пути, что у eGames)
```

Службы: `fail2detect.service` (фаервол + демон банов) и `fail2detect-blocklist.timer` (ежедневное обновление блок-листов).

## Удаление

`fail2detect uninstall` снимает таблицу nftables, службы и команду. UFW остаётся как был.

## Благодарности

- [fail2ban](https://github.com/fail2ban/fail2ban) — идея и модель jail'ов
- [eGamesAPI/remnawave-reverse-proxy](https://github.com/eGamesAPI/remnawave-reverse-proxy) — установка Remnawave
- [shadow-netlab/traffic-guard-lists](https://github.com/shadow-netlab/traffic-guard-lists), [tread-lightly/CyberOK_Skipa_ips](https://github.com/tread-lightly/CyberOK_Skipa_ips) — списки сканеров
- [Remnawave](https://github.com/remnawave) — официальные compose-файлы для установки
- [kavehtehrani/cloudflare-speed-cli](https://github.com/kavehtehrani/cloudflare-speed-cli) — вдохновение для speedtest

## Тесты

```bash
tests/run.sh                    # всё, включая nftables, в изолированном Debian-контейнере (нужен Docker)
IMAGE=ubuntu:24.04 tests/run.sh
bash tests/linux.sh             # без Docker: регулярки jail'ов, транспорты, compose, CLI
bash tests/configs.sh           # xray -test и nginx -t (нужен Docker)
```

`tests/configs.sh` прогоняет сгенерированные конфиги через настоящие `xray run -test` (все 6 транспортов) и `nginx -t`. `tests/linux.sh` проверяет правила `nft -c` во всех комбинациях режимов, применяет их, а также проверяет баны, белый список, удвоение срока, восстановление банов, блок-листы, сквозной jail и откат. Фикстуры логов лежат в `tests/fixtures/`. CI (`.github/workflows/ci.yml`) запускает shellcheck и тесты на Debian 12 и Ubuntu 22.04/24.04.

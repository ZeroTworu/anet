# Архитектура и документация `anet-appfilter` (Windows Per-App Split Tunneling)

Документация актуальна для ветки `dev/bump_windevert` (`windivert = "0.7.0-beta.4"`, `windows-sys = "0.61.2"`).  
Статус: **Реализовано (Production Ready)**.

---

## 1. Назначение и обзор (Overview)

Крейт `anet-appfilter` реализует поприложенческое раздельное туннелирование (**Per-App Split Tunneling**) на ОС Windows с использованием драйвера ядра **WinDivert 2.2** (WFP — Windows Filtering Platform).

### 1.1. Ключевая особенность архитектуры
Когда на Windows в конфигурации клиента (`client.toml` или через GUI) активирован фильтр приложений (`Include` или `Exclude`), **виртуальный сетевой интерфейс Wintun НЕ создаётся**, а системная таблица маршрутизации Windows не перехватывает весь трафик по умолчанию (`0.0.0.0/1`, `128.0.0.0/1`).

Вместо этого `anet-appfilter` работает как прозрачный перехватчик и L3-NAT на уровне сетевого стека Windows:
1. **Трафик прямых приложений (`Pass`)** остаётся нетронутым и уходит через физический сетевой адаптер с реальным локальным IP-адресом.
2. **Трафик туннелируемых приложений (`Tunnel`)** изымается из сетевого стека Windows до выхода с сетевой карты, его `src_ip` перезаписывается на виртуальный IP клиента в VPN (`tunnel_ip`, например `10.8.0.2`), и пакет отправляется в зашифрованный канал `anet-client-core`.
3. **Ответные пакеты из VPN-туннеля** получают обратную замену `dst_ip` (`10.8.0.2` $\rightarrow$ реальный `orig_src_ip` физического интерфейса) и инжектируются как входящие (`inbound = true`) напрямую в сетевой стек Windows на тот же интерфейс (`if_idx` / `sub_if_idx`), с которого ушёл запрос.

---

## 2. Сквозная схема работы

```text
+---------------------------------------------------------------------------------------------------+
|                                     ЯДРО WINDOWS (WFP / WinDivert)                                |
+---------------------------------------------------------------------------------------------------+
         | (События сокетов: Bind, Listen, Connect, Accept, Close)        | (Исходящие IP-пакеты)
         v                                                                v
+----------------------------------------+               +------------------------------------------+
| 1. Поток `anet-socket-tracker`         |               | 2. Поток `anet-pkt-router`               |
|    (WinDivertLayer::Socket, Priority   |               |    (WinDivertLayer::Network,             |
|     1000, SNIFF | RECV_ONLY)           |               |     фильтр: "outbound and (ip or ipv6)") |
|                                        |               |                                          |
|  При старте (ДО цикла recv):           |               |  На каждый исходящий пакет:              |
|  - `populate_initial_sockets()`:       |               |  1. Loopback / Multicast / Broadcast     |
|    снимает слепок уже открытых TCP/UDP |               |     / Link-Local -> PASS                 |
|    сокетов через WinAPI                |               |  2. `dst_ip` в `BypassSet` (IP сервера   |
|    `GetExtendedTcpTable` /             |               |     VPN, Direct-маршруты, DNS) -> PASS   |
|    `GetExtendedUdpTable` (IPv4 + IPv6) |               |  3. `dst_ip` == `tunnel_ip` -> PASS      |
|                                        |               |  4. Быстрый путь (`NatTable`):           |
|  В рантайме:                           |               |     Если поток уже в `nat_table` И       |
|  - Каноникализирует IPv6 `::ffff:`     |               |     `entry.confirmed == true` -> TUNNEL  |
|  - Разрешает `PID -> exe_name`         |               |  5. Поиск владельца в `FlowMap::lookup`: |
|    через `ProcNameCache`               |-------------->|     - Если `pid == self_pid` (сам        |
|  - Обновляет `FlowMap`:                |   Shared      |       процесс VPN-клиента) -> PASS       |
|    * `map` (5-tuple -> ProcessOwner)   |   `FlowMap`   |     - Проверка `FilterMode`:             |
|    * `tcp_ports` (port -> owner)       |               |       * `Include`: в списке -> TUNNEL    |
|    * `udp_ports` (port -> owner)       |               |       * `Exclude`: в списке -> PASS      |
|  - На `SocketClose`:                   |               |     - Если сокет ещё не найден           |
|    помещает ключ/порт в очереди        |               |       (`owner_opt.is_none()`):           |
|    отложенного удаления                |               |       * `Include` -> PASS                |
|    `closing_flows` / `closing_ports`   |               |       * `Exclude` -> TUNNEL              |
|    (удаление через 15 секунд)          |               |         (но `confirmed = false`!)        |
+----------------------------------------+               +------------------------------------------+
                                                                   |                      |
                                                          [ Решение: PASS ]      [ Решение: TUNNEL ]
                                                                   |                      |
                                                                   v                      v
                                                         Реинжект в WinDivert   1. Сохранение `orig_src_ip`,
                                                         (`handle.send(&pkt)`)     `if_idx`, `sub_if_idx`,
                                                         Пакет уходит напрямую     `confirmed` в `NatTable`
                                                         мимо VPN               2. Перезапись `src_ip = tunnel_ip`
                                                                                3. Пересчёт L3/L4 checksum
                                                                                4. Отправка в `to_tunnel_tx`
                                                                                          |
                                                                                          v
+---------------------------------------------------------------------------------------------------+
|                                   ЯДРО VPN (`anet-client-core`)                                   |
|   DnsInterceptor / RuleEngine / Шифрование транспорта (QUIC / WSS / SSH / AHTTP)                  |
+---------------------------------------------------------------------------------------------------+
                                                                                          |
                                                                 (Входящий пакет из VPN)  |
                                                                                          v
                                                         +------------------------------------------+
                                                         | 3. Поток `anet-tun-injector`             |
                                                         |    Читает из `from_tunnel_rx`:           |
                                                         |    1. Ищет `(proto, dst_port, src_ip,    |
                                                         |       src_port)` в `NatTable`            |
                                                         |    2. Перезаписывает `dst_ip` с          |
                                                         |       `tunnel_ip` на `orig_src_ip`       |
                                                         |    3. Выставляет `inbound = true`,       |
                                                         |       `if_idx`, `sub_if_idx`             |
                                                         |    4. Пересчитывает checksums и вызывает |
                                                         |       `handle.send(&pkt)` в стек Windows |
                                                         +------------------------------------------+
```

---

## 3. Внутреннее устройство модулей

### 3.1. Конфигурация и режимы (`src/config.rs`)

Поддерживаются два взаимоисключающих режима фильтрации (`FilterMode`):
- **`FilterMode::Include` (Белый список)**:
  - В VPN-туннель направляется **только** трафик процессов, перечисленных в `apps`.
  - Трафик всех остальных приложений (и системных служб) идёт напрямую (`Pass`).
- **`FilterMode::Exclude` (Чёрный список)**:
  - Весь трафик системы направляется в VPN-туннель, **кроме** процессов, перечисленных в `apps` (например, торрент-клиенты, игры, локальные сервисы).

**Нормализация имён процессов**:
- При создании `AppFilterConfig` все имена из конфига приводятся к `ascii_lowercase`, отрезаются пути (`C:\Program Files\App\app.exe` $\rightarrow$ `app.exe`), а если расширение `.exe` не было указано пользователем (`chrome` $\rightarrow$ `chrome.exe`), оно добавляется автоматически.

---

### 3.2. Разрешение `PID` $\rightarrow$ имя процесса (`src/proc_name.rs`)

На уровне `WinDivertLayer::Socket` драйвер сообщает только числовой `process_id` (`u32`). Для сопоставления с правилами необходим `exe_name`.

1. **Специальные системные PID**:
   - `PID 0` (System Idle Process) и `PID 4` (System Kernel / SMB / драйверы ядра) всегда возвращают имя `"system"`.
2. **Отказ от `OpenProcess` в пользу `CreateToolhelp32Snapshot`**:
   - Многие приложения на Windows (игры с античитами, UWP/AppContainer-приложения, антивирусы, системные защищённые процессы `Protected Process Light`) блокируют вызов `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` ошибкой `ERROR_ACCESS_DENIED`.
   - `ProcNameCache` использует `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)` + `Process32FirstW` / `Process32NextW`. Снимок процессов читает метаданные из ядра без открытия дескрипторов целевых процессов и безотказно возвращает `szExeFile` для любых процессов.
3. **Кеширование (`DashMap<u32, CachedEntry>`)**:
   - Результат кешируется на **30 секунд (`TTL`)**, чтобы не вызывать системный снимок на каждый новый сокет браузера или торрента.
   - Отрицательные результаты (`None`) **не кешируются**: если короткоживущий или только что стартующий процесс не попал в снимок в первую микросекунду, следующая попытка повторит поиск.

---

### 3.3. Таблица потоков и портов (`src/flow_map.rs`)

`FlowMap` — связующее звено между событиями сокетов (`SocketLayer`) и маршрутизатором пакетов (`NetworkLayer`).

#### 3.3.1. Каноникализация IP-адресов (`to_canonical()`)
В Windows приложения (особенно Chrome, Telegram, qBittorrent, Node.js, Java) активно используют **Dual-Stack IPv6 сокеты** (`AF_INET6` с отключённым `IPV6_V6ONLY`).
- На уровне `WinDivertLayer::Socket` соединение с IPv4-сервером через такой сокет репортится как IPv6-адрес вида `::ffff:91.184.242.63`.
- На уровне `WinDivertLayer::Network` по проводу при этом идёт обычный **IPv4-пакет** с адресом `91.184.242.63`.
- Поэтому `FlowKey::new`, `BypassSet`, `run_socket_tracker` и `classify_v6` в обязательном порядке вызывают `ip.to_canonical()`, преобразуя `::ffff:a.b.c.d` в `IpAddr::V4(a.b.c.d)`. Без этого ключи в `FlowMap` никогда не совпадут с заголовками L3-пакетов.

#### 3.3.2. Трёхуровневый поиск владельца пакета (`FlowMap::lookup`)
Когда `anet-pkt-router` видит исходящий пакет `(proto, src_ip, src_port, dst_ip, dst_port)`, он ищет владельца в следующем порядке:
1. **Точное совпадение 5-tuple**:
   - `(proto, src_ip, src_port, dst_ip, dst_port)` в `map`.
2. **5-tuple с wildcard локальным адресом (`0.0.0.0` или `::`)**:
   - При вызове `connect()` на сокете, который ранее не был явно привязан к конкретному интерфейсу, событие `SocketConnect` в WFP часто приходит с `local_addr = 0.0.0.0` (или `::`), тогда как в исходящем IP-пакете на `NetworkLayer` ядро Windows уже подставило реальный IP сетевой карты (например, `192.168.1.50`).
   - Если точный ключ не найден, `lookup` проверяет `(proto, 0.0.0.0, src_port, dst_ip, dst_port)` (и `::` для IPv6).
3. **Fallback по локальному порту (`tcp_ports` для TCP и `udp_ports` для UDP)**:
   - Для UDP (`sendto` без `connect`, QUIC, DHT/uTP в торрентах, WebRTC) и для слушающих или заранее привязанных TCP-сокетов (`Bind`/`Listen`, входящие/исходящие P2P-соединения на фиксированном порту) 5-tuple с конкретным `dst_ip:dst_port` на уровне `SocketLayer` отсутствует.
   - В этом случае владелец определяется по карте локальных портов `tcp_ports` (`proto == 6`) или `udp_ports` (`proto == 17`).

#### 3.3.3. Начальное сканирование уже открытых сокетов (`populate_initial_sockets`)
Драйвер `WinDivertLayer::Socket` перехватывает **только события изменения состояния сокетов**, происходящие **после** вызова `WinDivert::socket(...)`.
- Если приложение (например, торрент-клиент на порту `63870`, браузер с пулом HTTP/2-3 соединений или мессенджер) было запущено **до** нажатия кнопки «Подключить VPN», события `SocketBind`, `SocketListen` и `SocketConnect` для этих сокетов уже произошли в прошлом.
- Чтобы такие сокеты не оказались «невидимыми» для фильтра (что в режиме `Exclude` приводило бы к отправке трафика исключённого приложения внутрь VPN-туннеля, а в режиме `Include` — к утечке уже открытых соединений мимо VPN), метод `AppFilter::new` сразу после открытия `socket_handle` вызывает `map.populate_initial_sockets()`.
- `populate_initial_sockets()` опрашивает системные таблицы сокетов Windows через `iphlpapi.dll` (`windows-sys`):
  - `GetExtendedTcpTable` (`AF_INET` и `AF_INET6`, `TCP_TABLE_OWNER_PID_ALL`) — заполняет и `tcp_ports` (для всех состояний), и `map` (5-tuple для активных соединений).
  - `GetExtendedUdpTable` (`AF_INET` и `AF_INET6`, `UDP_TABLE_OWNER_PID`) — заполняет `udp_ports`.

#### 3.3.4. Отложенное удаление при `SocketClose` (`closing_flows` / `closing_ports`)
Когда приложение закрывает сокет (`closesocket`), событие `SocketClose` на уровне `WinDivertLayer::Socket` срабатывает **мгновенно**, в то время как TCP-стек ядра Windows ещё продолжает досылать в сеть завершающие пакеты `FIN+ACK`, `ACK` или `RST` (иногда с ретрансляциями в течение нескольких секунд).
- Если удалить запись из `FlowMap` мгновенно в момент `SocketClose`, эти завершающие пакеты потеряют привязку к процессу и в режиме `Include` уйдут в сеть напрямую с реальным IP пользователя (**утечка IP на закрытии соединения**).
- Поэтому `FlowMap::schedule_remove` и `schedule_remove_port` не удаляют записи сразу, а помещают их в очереди `closing_flows` и `closing_ports` с временной меткой.
- Фоновый поток `anet-nat-sweeper` раз в 2 секунды вызывает `FlowMap::sweep_closed(Duration::from_secs(15))` и очищает записи, закрытые более 15 секунд назад, **без создания отдельных потоков ОС на каждое закрытие сокета**.

---

### 3.4. Конвейер перехвата и NAT (`src/windivert_backend.rs`)

#### 3.4.1. Поток `anet-socket-tracker`
- Открывает `WinDivert::socket("true", 1000, WinDivertFlags::new().set_sniff().set_recv_only())`.
- Высокий приоритет (`1000`) гарантирует получение уведомлений о сокетах раньше других фильтров WFP.
- Обрабатывает:
  - `SocketBind` и `SocketListen` для `protocol == 6` (TCP) и `protocol == 17` (UDP) $\rightarrow$ записывает локальный порт в `tcp_ports` / `udp_ports`.
  - `SocketConnect` и `SocketAccept` $\rightarrow$ записывает 5-tuple в `map` и дополнительно обновляет `tcp_ports` / `udp_ports`.
  - `SocketClose` $\rightarrow$ ставит 5-tuple и локальный порт в очередь отложенной очистки (`schedule_remove` / `schedule_remove_port`).

#### 3.4.2. Поток `anet-pkt-router` и флаг `NatEntry::confirmed`
- Открывает `WinDivert::network("outbound and (ip or ipv6)", 0, WinDivertFlags::new())`.
- Для каждого пакета проверяет:
  1. Является ли адрес назначения локальным/служебным (`is_ignored_ip`: loopback, link-local, broadcast, multicast, документационные подсети) $\rightarrow$ `Pass`.
  2. Находится ли `dst_ip` в `BypassSet` (IP самого VPN-сервера, CDN/TURN, системные DNS, маршруты `exclude_route_for`, статические и динамические правила `Direct`) $\rightarrow$ `Pass`.
  3. Принадлежит ли пакет уже известному подтверждённому потоку туннеля (`is_existing_tunnel_flow` $\rightarrow$ `nat_table.get(&nat_key).is_some_and(|e| e.confirmed)`) $\rightarrow$ `Tunnel`.
  4. Если поток ещё не подтверждён, вызывает `classify_v4` / `classify_v6`:
     - При `pid == std::process::id()` (собственный процесс клиента ANet) всегда возвращает `Pass` (**защита от петли маршрутизации**).
     - Если владелец сокета найден (`Some(owner)`):
       - сверяется с `AppFilterConfig` (`Include` / `Exclude`);
       - при решении `Tunnel` возвращается `confirmed = true`.
     - Если владелец сокета **ещё не найден (`None`)** (микросекундная гонка, когда первый пакет обогнал событие `SocketLayer`):
       - в режиме `Include` пакет пропускается напрямую (`Pass`), так как по умолчанию всё идёт мимо VPN;
       - в режиме `Exclude` пакет отправляется в `Tunnel` (чтобы не допустить утечки реального IP на первом пакете), но с флагом **`confirmed = false`**.
       - Благодаря `confirmed = false` запись в `NatTable` создаётся только для того, чтобы ответ на этот первый пакет смог вернуться приложению, но **не блокирует** проверку `FlowMap` для второго и последующих пакетов потока! Как только событие `SocketLayer` доходит до `FlowMap` (или если сокет принадлежит исключённому приложению), следующий пакет проходит через `classify_v4`/`classify_v6` и корректно переключается в `Pass`.

#### 3.4.3. Поток `anet-tun-injector`
- Получает расшифрованные IPv4-пакеты из `from_tunnel_rx`.
- Проверяет, что `dst_ip == tunnel_ip`, извлекает `(proto, dst_port, src_ip, src_port)` и ищет `NatEntry` в `nat_table`.
- Восстанавливает исходный локальный адрес (`dst_ip = nat_entry.orig_src_ip`) и интерфейсы (`if_idx`, `sub_if_idx`), выставляет `inbound = true`, пересчитывает контрольные суммы IP + TCP/UDP (`recalculate_checksums`) и инжектирует пакет в стек Windows.

---

## 4. Интеграция с `anet-client-core` (`anet-client-core/src/client.rs`)

Когда на Windows активна фича `per-app` и в конфигурации задан блок `[app_filter]` с непустым списком приложений:
1. В `acquire_packet_source` вместо поднятия интерфейса Wintun создаётся экземпляр `anet_appfilter::AppFilter::new(af_cfg, auth.ip)`.
2. Чтобы исключить захват служебного трафика и соблюсти правила маршрутизации, в `AppFilter` синхронно до старта цикла пакетов регистрируются bypass-исключения (`add_bypass_sync` / `add_bypass_net`):
   - IP-адреса текущего VPN-сервера (`result.remote_ip`, `result.bypass_ips`, `bypass_ips`);
   - Прямые апстрим DNS-серверы (`DIRECT_UPSTREAM_DNS_IPS`);
   - Все подсети и IP из `config.main.exclude_route_for`;
   - Статические IP/CIDR из `config.routing.overrides.direct`.
3. В рантайме, когда `DnsInterceptor` разрешает домен по правилу `RuleAction::Direct`, разрешённые IP-адреса немедленно добавляются в `AppFilter::add_bypass_sync` **до** того, как DNS-ответ будет отправлен приложению.

---

## 5. Памятка для ИИ и разработчиков (AI Agent & Maintainer Invariants)

> **ВАЖНО ДЛЯ ИИ-АГЕНТОВ**: Перед внесением любых изменений в `anet-appfilter` или его интеграцию в `anet-client-core` обязательно проверьте соблюдение всех 8 инвариантов ниже. Нарушение любого из них приводит либо к утечке реального IP пользователя (IP/BitTorrent leak), либо к падению сетевого стека Windows.

### Инвариант 1: Каноникализация IPv4-mapped IPv6 (`::ffff:a.b.c.d`)
- **Проблема**: На Windows сокеты часто открываются как dual-stack IPv6 (`[::ffff:x.x.x.x]`), но пакеты в сети идут как IPv4 (`x.x.x.x`).
- **Правило**: Любой `IpAddr`, поступающий из `WinDivertLayer::Socket`, из таблиц `GetExtendedTcpTable`/`GetExtendedUdpTable` или из `BypassSet`, **обязан** проходить через `.to_canonical()`. Никогда не создавайте `FlowKey` напрямую со структурным литералом в обход `FlowKey::new(...)`.

### Инвариант 2: Запрет отбрасывания `0.0.0.0` и `::` для `local_addr` на `SocketLayer`
- **Проблема**: В `WinDivertLayer::Socket` события `SocketBind`, `SocketListen` и `SocketConnect` регулярно имеют `local_addr == 0.0.0.0` (IPv4 Unspecified) или `::` (IPv6 Unspecified), потому что ОС выбирает конкретный исходящий IP-адрес интерфейса позже (на уровне маршрутизации пакета).
- **Правило**: Для проверки `local_addr` в `run_socket_tracker` используйте `is_ignored_local_ip()`, которая разрешает `is_unspecified()`, отсекая только loopback/multicast/link-local. Для проверки `remote_addr` на `Connect`/`Accept` и адресов пакетов на `NetworkLayer` используйте `is_ignored_ip()`.

### Инвариант 3: Сканирование начальных сокетов (`populate_initial_sockets`) при старте
- **Проблема**: `WinDivertLayer::Socket` не генерирует ретроспективных событий для сокетов, открытых до запуска VPN (например, qBittorrent, запущенный с утра на порту `63870`, или открытый браузер/Telegram).
- **Правило**: Вызов `map.populate_initial_sockets()` должен выполняться **после** открытия `socket_handle` (чтобы новые сокеты уже буферизовались драйвером) и **до** запуска потока `anet-pkt-router`.

### Инвариант 4: КАТЕГОРИЧЕСКИЙ ЗАПРЕТ `std::thread::spawn` на событие `SocketClose`
- **Проблема**: При активном браузере, P2P/торрентах или сканерах закрываются сотни сокетов в секунду. Порождение потока ОС (`thread::spawn` + `sleep(15s)`) на каждый `SocketClose` вызывает лавинное создание тысяч потоков и исчерпание памяти/дескрипторов процесса.
- **Правило**: Отложенное удаление записей из `FlowMap` при `SocketClose` должно выполняться **только** через неблокирующие очереди `closing_flows` и `closing_ports`, которые очищаются существующим фоновым потоком `anet-nat-sweeper` (`flow_map.sweep_closed(...)`).

### Инвариант 5: Семантика флага `NatEntry::confirmed` в `NatTable`
- **Проблема**:
  1. Если при закрытии сокета (`SocketClose`) запись в `FlowMap` уже удалилась, а TCP-стек досылает последний `FIN+ACK`, без быстрой проверки `is_existing_tunnel_flow` в режиме `Include` этот пакет уйдёт мимо туннеля с реальным IP.
  2. Но если в режиме `Exclude` первый пакет сокета обогнал событие `SocketLayer` (`owner_opt.is_none()`), он предварительно отправляется в туннель. Если при этом безусловно запереть поток в `NatTable`, то даже когда через 1 мс придёт событие `SocketLayer` от исключённого приложения (например, торрента), все последующие пакеты этого соединения навсегда останутся в VPN-туннеле!
- **Правило**:
  - `NatEntry` хранит поле `confirmed: bool`.
  - Если решение `Tunnel` принято на основании найденного владельца сокета (`Some(owner)`), выставляется `confirmed = true` (и `is_existing_tunnel_flow` возвращает `true`, защищая поток вплоть до закрытия).
  - Если решение `Tunnel` принято только из-за `owner_opt.is_none()` в режиме `Exclude`, выставляется `confirmed = false`. Для таких записей `is_existing_tunnel_flow` возвращает `false`, заставляя `run_packet_router` перепроверять `FlowMap` на следующих пакетах.

### Инвариант 6: Защита от петли маршрутизации (`self_pid` и `BypassSet`)
- **Проблема**: В режиме `Exclude` все неизвестные конфигу процессы заворачиваются в туннель. Если сам процесс VPN-клиента (`anet-client-gui.exe` или `anet-client-cli.exe`) откроет новое соединение (переподключение транспорта, STUN/TURN, запрос правил `.abc`, прямой DNS-резолв в `DnsInterceptor`), перехват собственных пакетов приведёт к бесконечной петле (deadlock туннеля).
- **Правило**:
  1. В `run_packet_router` всегда проверяется `owner.pid == std::process::id()`, и для собственного процесса возвращается `Pass`.
  2. Все IP-адреса серверов VPN, STUN/TURN, апстрим-резолверов и `Direct`-правил должны добавляться в `BypassSet` через `add_bypass_sync` / `add_bypass_net`.

### Инвариант 7: Работа с крейтом `windivert 0.7.0-beta.4` и `Drop`
- **Правило**:
  - В `windivert 0.7.0-beta.4` на `WinDivert<SocketLayer>` метод `handle.recv()` вызывается **без аргументов** и возвращает `WinDivertPacket<SocketLayer>` с массивом `events`.
  - На `WinDivert<NetworkLayer>` метод `handle.recv(&mut buf)` принимает буфер `&mut [u8]`.
  - Для штатной остановки блокирующих вызовов `recv()` в `Drop for AppFilter` используйте `handle.shutdown_handle()` (`windivert::ShutdownHandle::shutdown()`). Не используйте `unsafe`-касты структуры `WinDivert` к сырым указателям `HANDLE` и не добавляйте старые версии `windows = "0.48"` или `windivert-sys = "0.10"` в `Cargo.toml`.

### Инвариант 8: Сохранение `if_idx` и `sub_if_idx` при инъекции ответов
- **Проблема**: Сетевой стек Windows может отбросить инжектированный входящий пакет (`inbound = true`), если у него не указаны индексы сетевого интерфейса (`interface_index` и `sub_interface_index`), через который ушёл исходный запрос.
- **Правило**: При перезаписи исходящего пакета в `anet-pkt-router` всегда сохраняйте `pkt.address.interface_index()` и `pkt.address.sub_interface_index()` в `NatEntry` и восстанавливайте их в `anet-tun-injector` перед вызовом `handle.send(&pkt)`.

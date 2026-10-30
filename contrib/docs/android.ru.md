# Архитектура взаимодействия Android UI (`anet-android`) и Rust Core (`anet-mobile` / `anet-client-core`)

Документация актуальна для ветки `master` (ANet v0.7.2+).

---

## 1. Обзор архитектуры и границы ответственности

Мобильный клиент ANet для Android построен по схеме **Тонкий UI/системный сервис на Kotlin + Полное сетевое ядро на Rust (`libanet_mobile.so`)**:

1. **Android-уровень (`ZeroTworu/anet-android` — `MainActivity.kt`, `ANetVpnService.kt`)**:
   - Управляет системным разрешением `android.net.VpnService` и жизненным циклом Foreground-сервиса (`specialUse`).
   - Вызывает системный `VpnService.Builder.establish()` по запросу из Rust (`configureTun`) и возвращает сырой файловый дескриптор (`fd`) виртуального сетевого интерфейса `tun0`.
   - Защищает транспортные сокеты ядра от петли маршрутизации через `VpnService.protect(fd)` (либо через системные исключения маршрутов `excludeRoute` на Android 13+ API 33+ и табличные split-маршруты на Android 10–12).
   - Отрисовывает UI-компоненты по готовым снимкам состояния, приходящим из Rust:
     - Виджет «Щит диагностики сети» и линейный индикатор пульса (`ConnectivitySnapshot`);
     - Выпадающий селектор групп/нод с прогресс-баром доступности и пингом по протоколам (`NodeProbeSnapshot`);
     - Живой сглаженный график скоростей (`TelemetrySparklineView`) и счётчики трафика (`TelemetrySnapshot`);
     - Карточку тарифа и лимитов активной сессии (`AccountInfo`).

2. **Слой JNI-адаптера (`anet-mobile` — `lib.rs`, `android_impl.rs`)**:
   - Инициализирует единый многопоточный рантайм Tokio (`worker_threads = 8`).
   - Поднимает **выделенный фоновый поток JNI-моста** (`Rust JNI Bridge`), который один раз вызывает `jvm.attach_current_thread()` и асинхронно вычитывает события `AnetEvent` из неблокирующего канала `mpsc::channel`, доставляя их в `MainActivity` и `ANetVpnService` внутри локальных фреймов (`with_local_frame(128)`).
   - Реализует трейты `TunFactory` (`AndroidCallbackTunFactory`) и `RouteManager` (`AndroidRouteManager`) для интеграции с `anet-client-core`.

3. **Сетевое ядро (`anet-client-core`, `anet-common`)**:
   - Управляет транспортами (`QUIC`, `WRTC Data`, `WRTC Video`, `VNC`, `SSH`, `WSS`, `AHTTP`, `ASTP-L`, `IMAP`).
   - Выполняет **все** HTTP/HTTPS/WebSocket запросы в системе (включая скачивание серверного конфига `Updater::fetch_config_from_url`, проверку обновлений, проверку связности `ConnectivityProber`, опрос нод `NodeProbeMonitor` и сигнальные каналы транспортов) **исключительно через `anet-common/src/http_help.rs` (`BrowserProfile` + BoringSSL)** с полной синхронизацией L4 TLS ClientHello и L7 HTTP/2 `SETTINGS` / заголовков браузера. Прямое использование системного `HttpURLConnection` в Kotlin или голого `reqwest::Client` в обход `http_help.rs` запрещено.
   - Генерирует внутритуннельные ICMP-зонды (`0x414E`), агрегирует телеметрию (`start_fast_stats_monitor` с частотой 2 Гц / 500 мс) и управляет фоновыми мониторами (`ConnectivityMonitor`, `NodeProbeMonitor`).

```
+---------------------------------------------------------------------------------------------------+
|                                   ANDROID (Kotlin / ART VM)                                       |
|                                                                                                   |
|  +----------------------------------------+           +----------------------------------------+  |
|  |            MainActivity.kt             |           |           ANetVpnService.kt            |  |
|  |  - Селектор групп/нод и бейджи RTT     |<--------->|  - Foreground Service + WakeLock       |  |
|  |  - Щит диагностики + Линейный пульс    | Broadcast |  - VpnService.Builder.establish()      |  |
|  |  - График скоростей (Sparkline 2 Гц)   |  Intents  |  - configureTun() -> raw fd            |  |
|  |  - Карточка тарифа активной сессии     |           |  - closeTun() -> ParcelFileDescriptor  |  |
|  +-------------------+--------------------+           +-------------------+--------------------+  |
+----------------------|----------------------------------------------------|-----------------------+
                       | JNI Calls / Callbacks                              | JNI Calls / Callbacks
+----------------------v----------------------------------------------------v-----------------------+
|                                  RUST JNI LAYER (anet-mobile)                                     |
|                                                                                                   |
|  +---------------------------------------------------------------------------------------------+  |
|  | Выделенный OS-поток: Rust JNI Bridge (mpsc::Receiver<TimestampedEvent> -> CallVoidMethod)   |  |
|  +---------------------------------------------------------------------------------------------+  |
|                                                ^                                                  |
|  +---------------------------------------------|-----------------------------------------------+  |
|  | Tokio Multi-Thread Runtime (8 workers)      |                                               |  |
|  |  - AndroidCallbackTunFactory (dup(fd) + O_NONBLOCK + FD_CLOEXEC -> tun::AsyncDevice)        |  |
|  |  - spawn_tun_io_worker (reader_handle + writer loop + горячая замена TunSwapRequest)        |  |
|  |  - AndroidRouteManager (динамический bypass_ips + пересчёт префиксов исключений)            |  |
|  +---------------------------------------------|-----------------------------------------------+  |
+------------------------------------------------|--------------------------------------------------+
                                                 |
+------------------------------------------------v--------------------------------------------------+
|                           RUST CORE (anet-client-core / anet-common)                              |
|                                                                                                   |
|  +------------------------+  +--------------------------+  +-----------------------------------+  |
|  |      AnetClient        |  |   ConnectivityMonitor    |  |         NodeProbeMonitor          |  |
|  | - Транспорты (QUIC,    |  | - Матрица 6 состояний    |  | - Параллельный опрос [[servers]]  |  |
|  |   WRTC, VNC, SSH, ...) |  | - Опрос РФ (3) / Мир (3) |  | - 2 замера: TCP+TLS и чистое      |  |
|  | - In-Tunnel ICMP Probe |  |   через http_help.rs     |  |   время рукопожатия протокола     |  |
|  | - Fast Stats (500 мс)  |  | - Мгновенный ICMP RTT    |  | - Хеширование списка ProbeTarget  |  |
|  +------------------------+  +--------------------------+  +-----------------------------------+  |
|                                                |                                                  |
|                                                v                                                  |
|  +---------------------------------------------------------------------------------------------+  |
|  |                  http_help.rs (BrowserProfile + BoringSSL L4/L7 Mimicry)                    |  |
|  +---------------------------------------------------------------------------------------------+  |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Жизненный цикл TUN-интерфейса и неблокирующий ввод-вывод (`android_impl.rs`)

### 2.1. Проблема блокирующего дескриптора `VpnService.Builder.establish()`
В ОС Android вызов `VpnService.Builder.establish()` возвращает `ParcelFileDescriptor`, чей нижележащий файловый дескриптор ядра Linux по умолчанию открыт **в блокирующем режиме (без флага `O_NONBLOCK`)**.

При передаче такого дескриптора в `tun::create_as_async(&config)` библиотека оборачивает его в `tokio::io::unix::AsyncFd`. Механизм `AsyncFd` в Tokio работает по схеме edge-triggered (`EPOLLET`): при получении уведомления о готовности чтения он вызывает системный `read(fd)` в цикле до тех пор, пока ядро не вернёт `EAGAIN` (`WouldBlock`), чтобы повторно взвести ожидание в `epoll`.

Если флаг `O_NONBLOCK` не установлен:
- Пока идёт плотный поток пакетов (например, во время активного Speedtest), `read(fd)` находит пакеты в очереди ядра и возвращает управление.
- Как только бурст трафика заканчивается и очередь TUN пустеет, очередной вызов `read(fd)` внутри `AsyncFd` **не возвращает `EAGAIN`, а блокирует поток воркера Tokio внутри ядра ОС** до прихода следующего пакета.
- Последовательное застревание всех воркер-потоков Tokio приводит к полному замиранию таймеров телеметрии (`start_fast_stats_monitor`), монитора связности (`ConnectivityMonitor`) и дедлоку при вызове `stopVpn`.

### 2.2. Решение: Принудительный `O_NONBLOCK` и `FD_CLOEXEC`
В `open_async_tun(fd: i32, auth: &AuthResponse)` (`anet-mobile/src/android_impl.rs`) перед созданием `tun::AsyncDevice`:
1. На исходном `fd` и на его дубликате `dup_fd` (полученном через `BorrowedFd::borrow_raw(fd).try_clone_to_owned()`) принудительно вызывается `fcntl`:
   - `F_SETFL` с битовой маской `O_NONBLOCK` (`0o4000`);
   - `F_SETFD` с битовой маской `FD_CLOEXEC` (`1`).
2. `dup_fd` передаётся в `tun::Configuration::raw_fd(dup_fd)` с `close_fd_on_drop(true)`.
3. Это гарантирует, что ни `reader.read_buf()`, ни `writer.write_all()` в `spawn_tun_io_worker` никогда не заблокируют поток Tokio на системном вызове.

### 2.3. Мгновенная и потокобезопасная остановка (`request_tun_shutdown` / `stopVpn`)
Для того чтобы нажатие кнопки `STOP` в UI никогда не зависало и немедленно убирало системную иконку ключа VPN в статус-баре Android:
1. При создании воркера `spawn_tun_io_worker` его `AbortHandle` и `Arc<Notify>` сохраняются в синхронном слоте `ACTIVE_TUN_ABORT`.
2. При вызове `request_tun_shutdown()` (из `stopVpn` или `connectVpn`) **синхронно и без ожидания асинхронных мьютексов** вызываются `stop_notify.notify_waiters()` и `abort_handle.abort()`.
3. На стороне Kotlin (`ANetVpnService.requestStop()`) немедленно закрывается `ParcelFileDescriptor` (`closeTun()`), а в Rust `stop_and_close_tun_session` и `client.stop()` выполняются со строгими верхними таймаутами (`400 мс` на закрытие TUN, `1200 мс` на остановку транспорта), полностью исключая зависание JNI-потока.

---

## 3. Протокол JNI-моста (`Android` <-> `Rust Core`)

### 3.1. Вызовы из Kotlin в Rust (JNI Exports)

| Класс Kotlin | Метод JNI | Назначение |
| :--- | :--- | :--- |
| `MainActivity` | `initLogger()` | Инициализация `android_logger` с тегом `ANetRust` |
| `MainActivity` | `getAppVersion()` / `getBuildInfo()` | Версия, хеш коммита и время сборки из `anet-mobile/build.rs` (пересобирается при любом изменении `.git/HEAD` и `.git/refs`) |
| `MainActivity` | `inspectConfig(configToml)` | Валидация TOML, извлечение списка групп `id\|name` (или серверов) и передача целей в `NodeProbeMonitor::update_config_toml` |
| `MainActivity` | `fetchConfigFromUrl(url)` | Скачивание удалённого конфига через `Updater::fetch_config_from_url` с полной браузерной мимикрией `http_help.rs` (`BrowserProfile` + BoringSSL) и таймаутом 12 с |
| `MainActivity` | `startConnectivityMonitor(configToml)` | Запуск/обновление `ConnectivityMonitor` и `NodeProbeMonitor`, привязка `UI_CALLBACK_REF` |
| `MainActivity` | `triggerConnectivityCheck()` | Немедленное пробуждение `ConnectivityMonitor` по кнопке обновления на виджете щита |
| `MainActivity` | `triggerNodeProbe()` | Немедленный перезапуск опроса всех нод `NodeProbeMonitor` по кнопке рядом с селектором |
| `MainActivity` | `getVpnStateCode()` / `getVpnServerName()` | Синхронное получение текущего кода состояния (`0..6`) и имени активного сервера |
| `MainActivity` | `clearUiCallback()` | Очистка `UI_CALLBACK_REF` при уничтожении `MainActivity` |
| `ANetVpnService` | `connectVpn(configToml, selectedServer)` | Асинхронный запуск новой сессии `AnetClient` с фильтрацией по выбранной группе/серверу |
| `ANetVpnService` | `reconnectVpn()` | Мгновенный триггер переподключения при смене физической сети Android (`ConnectivityManager.NetworkCallback`) |
| `ANetVpnService` | `stopVpn()` | Неблокирующая остановка активного клиента, закрытие TUN и сброс сессионного кэша телеметрии/аккаунта |
| `ANetVpnService` | `clearVpnCallback()` | Очистка `VPN_CALLBACK_REF` при остановке сервиса |

### 3.2. Асинхронные обратные вызовы из Rust в Kotlin (JNI Bridge Callbacks)

Поток `Rust JNI Bridge` принимает события `AnetEvent` и вызывает методы на зарегистрированных `UI_CALLBACK_REF` (`MainActivity`) и `VPN_CALLBACK_REF` (`ANetVpnService`):

1. **`onStateChanged(stateCode: Int, message: String, serverName: String)`**:
   - Коды состояний: `0 = Disconnected`, `1 = Connecting`, `2 = Connected`, `3 = Reconnecting`, `4 = Stopping`, `5 = Stopped`, `6 = Failed`.
2. **`onConnectivityUpdated(conditionCode, pulseColorCode, rttMs, vpnConnected, title, subtitle, globalOk, globalTotal, domesticOk, domesticTotal)`**:
   - Доставляет полный снимок `ConnectivitySnapshot` (матрица из 6 состояний `NetworkCondition`, цвет пульса `Red/Yellow/Green`, пинг `display_rtt_ms`, счётчики `РФ X/3 • Мир Y/3`).
3. **`onStatsUpdated(rxBps, txBps, totalRxBytes, totalTxBytes, rttMs, rxSpeedStr, txSpeedStr, totalRxStr, totalTxStr, rxCurve: FloatArray, txCurve: FloatArray)`**:
   - Вызывается каждые **500 мс** (2 Гц) воркером `start_fast_stats_monitor`.
   - Передаёт готовые отформатированные строки скоростей/объёмов и два нормализованных массива `FloatArray` (по 60 точек, `0.0..1.0` с гамма-компрессией `0.62` и запасом по высоте `18%`) для прямой отрисовки кривых `DOWN` и `UP` на `TelemetrySparklineView`.
4. **`onNodeProbeUpdated(isChecking, completed, total, payload)`**:
   - Доставляет прогресс проверки узлов (`ПРОВЕРКА УЗЛОВ X/Y`) и детальные результаты по каждой группе и протоколу (`statusCode`, `bestRtt` — чистое время рукопожатия, `bestFullRtt` — полный цикл TCP+TLS+протокол).
5. **`onAccountInfo(billing, group, sessions, speed, consumed, limit, expires)`**:
   - Доставляет данные тарифа и лимитов, полученные от сервера в `AuthResponse` при подключении.

---

## 4. Браузерная мимикрия HTTP-запросов (`http_help.rs`) и диагностика сети

Все HTTP-запросы на Android (как служебные запросы самого приложения, так и фоновые проверки) проходят исключительно через `anet-common/src/http_help.rs`:

1. **Загрузка конфигурации (`Updater::fetch_config_from_url`)**:
   - Вызывается через JNI `fetchConfigFromUrl`.
   - Создаёт `BrowserProfile::random()` (на Android — шаблоны мобильного Chrome 135/136 или Firefox 136 для Android с соответствующим TLS-отпечатком BoringSSL и заголовками `Sec-CH-UA-Mobile: ?1`, `Sec-CH-UA-Platform: "Android"`).
2. **Щит диагностики сети (`ConnectivityProber` в `anet-common/src/connectivity.rs`)**:
   - Использует `BrowserProfile::with_tls_config(...)` и `profile.apply_to_reqwest(...)`.
   - Опрашивает параллельно 3 глобальные и 3 российские контрольные точки.
   - Каждая цель ограничена индивидуальным жёстким таймаутом (`hard_cap`), а для `gosuslugi.ru` при недоступности зарубежного выходного IP автоматически выполняется быстрый fallback на `https://dzen.ru` внутри отведённого бюджета времени. Благодаря этому замедление одной точки никогда не сбрасывает результаты остальных 5 точек и не вызывает ложного состояния «Тишина в эфире (`0/3 • 0/3`)».
3. **Монитор доступности нод (`NodeProbeMonitor` в `anet-client-core/src/connectivity_monitor.rs`)**:
   - Вычисляет хеш непосредственно по массиву извлечённых целей `Vec<ProbeTarget>` (`group_id`, `dsn`, `protocol`), а не по сырому тексту TOML. Поэтому локальные модификации конфига (инъекция `auth_key` или пользовательских `exclude_route_for`) не вызывают лишнего сброса индикатора нод в `0/16` и не прерывают текущую проверку.
   - При одиночном таймауте узла на старте выполняет автоматический быстрый повторный опрос (retry) перед выставлением статуса `Unavailable`.

---

## 5. Правила жизненного цикла UI в `MainActivity.kt`

1. **Отсутствие ложного кеша тарифа на холодном старте**:
   - В состоянии `DISCONNECTED` карточка тарифа не подгружает устаревшие значения из прошлых сессий (`SharedPreferences`), а в `anet-mobile` статический `LAST_ACCOUNT_INFO` очищается при остановке туннеля и пересылается в UI только при активном состоянии `Connected`.
2. **Сохранение состояния и живого графика при сворачивании/разворачивании**:
   - При пересоздании или возврате в `MainActivity` (`onCreate` / `onResume`), если `ANetVpnService.isServiceRunning` активен и `getVpnStateCode()` равен `STATE_CONNECTED` / `STATE_CONNECTING`:
     - UI сразу инициализируется в актуальном состоянии без промежуточного сброса в `State.DISCONNECTED` и без очистки `telemetrySparklineView`;
     - Фоновое автообновление конфига по URL (`fetchServerConfigFromUrl`) не перезапускается поверх активного VPN-соединения;
     - Селектор серверов сопоставляет как точное имя группы (`group_id` / `group_name`), так и префикс имени конкретного сервера в группе (например, `🇫🇮 FN First [WRTC] (VIDEO)` $\to$ группа `🇫🇮 FN WRTC VIDEO`).

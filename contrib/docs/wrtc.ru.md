# Архитектура и спецификация транспорта `wrtc` (WebRTC over Ktalk / Jitsi SFU)

---

## 1. Введение и архитектурная концепция

### 1.1. Назначение
Транспорт `wrtc` предназначен для отказоустойчивой передачи туннелированного IP-трафика ANet через облачную и корпоративную инфраструктуру видеоконференцсвязи (ВКС) сервисов **Ktalk (Контур.Толк)** и стандартных инстансов **Jitsi Meet**. Сервисы функционируют на базе стека **Jitsi (Prosody + Jicofo + Jitsi Videobridge / JVB)**. Трафик полностью соответствует профилю стандартного участника видеоконференции в браузере:
1. **HTTP/REST и WSS уровень (`http_help.rs` + `providers/`):** единый профиль браузера (`BrowserProfile`: Chrome / Firefox / Safari / Randomized) с общим хранилищем `CookieJar`, синхронизированным TLS-отпечатком BoringSSL, валидными Client Hints (`sec-ch-ua`, `sec-ch-ua-mobile`, `sec-ch-ua-platform`), Fetch Metadata (`Sec-Fetch-*`), языковыми заголовками и естественными именами гостей («Пользователь 248», «Гость 5433», «Денис»).
2. **Мульти-провайдерный реестр (`WrtcProviderRegistry`):** автоматическое определение платформы ВКС по домену (`ProviderKind::KonturTalk` для `*.ktalk.ru` / `*.kontur.ru` и `ProviderKind::StandardJitsi` для стандартных серверов Jitsi Meet) с индивидуальной пред-сигнальной подготовкой (`bootstrap_room`).
3. **Сигнальный транспорт (XMPP over WebSocket, RFC 7395 + XEP-0198):** взаимодействие по протоколу RFC 7395 с сервером Prosody на базе синтаксического DOM/AST-парсера (`roxmltree`), строгого XML-билдера с явным пространством имён `xmlns="jabber:client"` на каждой станзе и поддержкой бесшовного возобновления потока по **XEP-0198 Stream Management** (`urn:xmpp:sm:3`).
4. **Высокоскоростной медиауровень (`media_video` / VP8 over DTLS-SRTP) и резервный канал (`Colibri-WS`):** передача сетевых пакетов внутри видеопотока VP8 (с микро-батчингом и микро-пейсером EDT) либо через выделенный полнодуплексный WebSocket моста JVB (`wss://.../colibri-ws/...`) при нестабильном прохождении UDP.
5. **Аудио-активность (WebRTC keep-alive):** непрерывная передача фреймов тишины Opus (`0xf8, 0xff, 0xfe`) каждые 20 мс переводит эндпоинт на стороне JVB в состояние `Connected` и предотвращает отключение участника по неактивности.

### 1.2. Базовая топология
* **Топология сети:** Клиент-серверное соединение поверх топологии **SFU (Selective Forwarding Unit)**. Прямое соединение (P2P) между узлами по умолчанию не требуется; все участники взаимодействуют через медиамост JVB.
* **Среда встречи (Rendezvous):** Клиенты и сервер подключаются в одну заранее подготовленную постоянную комнату с фиксированным коротким именем (например, `example-room-id`).
* **Роли в парадигме ANet:**
  * `anet-server` выступает в роли дежурного участника ВКС, непрерывно присутствующего в комнате.
  * `anet-client` подключается к комнате по требованию, находит сервер посредством криптографического механизма Unicast Discovery и инициирует внутреннее рукопожатие ASTP.
* **Управляющий канал:** Протокол **Colibri** поверх защищенного WebSocket соединения к JVB (`Colibri-WS`) или SCTP DataChannel. Сообщения упаковываются в типизированную структуру `colibriClass: ColibriClass::EndpointMessage` с адресной маршрутизацией через поле `to`.

---

## 2. Этап 1. Авторизация и пред-сигнальная инициализация (`WrtcProviderRegistry`)

Перед открытием сигнального WebSocket-соединения модуль `wrtc::providers::WrtcProviderRegistry::bootstrap_room()` выполняет подготовку комнаты в зависимости от типа ВКС-платформы, используя переданный `BrowserProfile` (все полученные заголовки `Set-Cookie` автоматически сохраняются в `profile.cookie_jar` и подставляются в последующий `wss://` запрос).

```
+-------------+                     +----------------------+
| ANet Client |                     | Ktalk HTTP API       |
|  or Server  |                     | (example.ktalk.ru)   |
+-------------+                     +----------------------+
       |                                       |
       | 1. POST /api/authorize/session        |
       |    Headers: BrowserProfile + Cookies  |
       |    Body: { name: "Гость ...", ... }   |
       |-------------------------------------->|
       |                                       |
       | 2. JSON: { token, expiresIn: 6 days } |
       |<--------------------------------------|
       |                                       |
       | 3. GET /api/rooms/{short_name}        |
       |    Headers: BrowserProfile + Cookies  |
       |             Authorization: Session {t}|
       |-------------------------------------->|
       |                                       |
       | 4. JSON: { conferenceId: "{name}_{h}"}|
       |<--------------------------------------|
       |                                       |
       v                                       v
   [Формирование RoomBootstrapInfo и открытие WSS сигналинга XMPP]
```

### 2.1. Провайдер `KonturTalkProvider` (`*.ktalk.ru`, `*.kontur.ru`)
1. **Получение сессионного токена гостя (`POST https://{domain}/api/authorize/session`):**
   * Выполняется через `http_help.rs` с профилем `BrowserProfile` и поддержкой быстрого перебора исходных TCP-портов (`tcp_port_hop_attempts`) при нестабильной связности на балансировщиках маршрута.
   * **Тело запроса (JSON):**
     ```json
     {
       "name": "Гость 4821",
       "anonymousSecret": "EXAMPLE15SECRET",
       "consentOnCreate": true
     }
     ```
   * **Ответ Ktalk API:** возвращает `token` и `anonymousId`.
2. **Разрешение внутреннего имени конференции (`GET https://{domain}/api/rooms/{room_short_name}`):**
   * Передаётся заголовок `Authorization: Session {token}`.
   * **Ответ Ktalk API:** возвращает внутренний идентификатор `conferenceId` вида `"{room_short_name}_{hex_hash}"`.
3. **Параметры `RoomBootstrapInfo` для Контур.Толк:**
   * Приоритетный URL сигнализации: `wss://{domain}/jitsi/xmpp-websocket?room={conferenceId}&sessionToken={token}` (с резервным `wss://{domain}/xmpp-websocket?room={conferenceId}&token={token}& Lists=true`).
   * Внутренний флаг провайдера `pre_allocate_before_muc = false` (вход в MUC выполняется строго до обращения к `focus.meet.jitsi`).

### 2.2. Провайдер `JitsiMeetProvider` (стандартный Jitsi Meet)
1. Приводит имя комнаты к нижнему регистру (требование Prosody MUC).
2. Выполняет быстрый предварительный HTTP-запрос (`GET https://{domain}/xmpp-websocket?room={conference_id}`) через `BrowserProfile`, сохраняя балансировочные cookie (такие как `session-cookie`) в `profile.cookie_jar`.
3. Устанавливает внутренний флаг `pre_allocate_before_muc = true`, чтобы перед отправкой `<presence>` в MUC гарантированно инициализировать комнату через IQ `<conference xmlns="http://jitsi.org/protocol/focus" .../>`.

---

## 3. Этап 2. Сигналинг XMPP (RFC 7395 + XEP-0198) и запуск медиамоста

```
+-------------+                 +-----------------+                 +---------------+
| ANet Node   |                 | Prosody (XMPP)  |                 | Jicofo / JVB  |
+-------------+                 +-----------------+                 +---------------+
       |                                 |                                  |
       | 1. Connect WebSocket            |                                  |
       |    /jitsi/xmpp-websocket        |                                  |
       |    (BrowserProfile + Cookies)   |                                  |
       |-------------------------------->|                                  |
       | 2. SASL ANONYMOUS Auth          |                                  |
       |<------------------------------->|                                  |
       | 3. Resource Bind + XEP-0198 SM  |                                  |
       |    + XEP-0215 extdisco          |                                  |
       |<------------------------------->|                                  |
       | 4. MUC Presence (Enter Room)    |                                  |
       |    xmlns="jabber:client"        |                                  |
       |-------------------------------->|                                  |
       | 5. Self Presence (status 110)   |                                  |
       |<--------------------------------|                                  |
       |                                 | 6. Jicofo detects participant    |
       |                                 |    (or fallback focus IQ after   |
       |                                 |     4s in wait_jingle_offer)     |
       |                                 |<-------------------------------->|
       | 7. Jingle Offer (session-init)  |<---------------------------------|
       |<--------------------------------|                                  |
       | 8. Parse colibri-ws url, ICE,   |                                  |
       |    DTLS, fingerprint, ufrag/pwd |                                  |
       |                                 |                                  |
       | 9. Jingle session-accept        |                                  |
       |    (xmlns="jabber:client")      |                                  |
       |-------------------------------->|                                  |
       |                                 |                                  |
       | 10. Open Colibri WebSocket      |                                  |
       |<==================================================================>|
       | 11. Multi-Socket UDP ICE / DTLS |                                  |
       |<==================================================================>|
       | 12. Media & Control Plane Active:                                  |
       |     - VP8 RTP Video Track (EDT Micro-Pacer + Batching)             |
       |     - Opus Audio silence frame every 20ms                          |
       |     - WebSocket Colibri Ping & XMPP Ping / XEP-0198 Ack            |
```

### 3.1. Архитектура XML-парсера и требования RFC 7395 (`xmpp_xml.rs`)
Входящий XMPP-поток разбирается синтаксическим DOM-парсером `roxmltree`:
1. **Явное пространство имён `xmlns="jabber:client"` (RFC 7395 §3.3.3):**
   * В классическом XMPP поверх TCP (RFC 6120) корневой тег `<stream:stream xmlns="jabber:client">` задаёт пространство имён для всей сессии. В XMPP поверх WebSocket (RFC 7395) каждый WebSocket-фрейм парсится сервером Prosody как отдельный независимый XML-документ.
   * Поэтому **все** станзы верхнего уровня в `XmppBuilder` (`<iq ... xmlns="jabber:client">`, `<presence ... xmlns="jabber:client">`) в обязательном порядке содержат атрибут `xmlns="jabber:client"`. Без этого атрибута Prosody игнорирует станзы привязки ресурса и входа в комнату.
2. **Мульти-станзы в одном фрейме:** парсер оборачивает входящий буфер в виртуальный `<stream>...</stream>` и разбирает каждую станзу отдельно (`parse_xmpp_stanzas`).
3. **Разделение порядка входа в MUC для Ktalk и стандартного Jitsi:**
   * В инфраструктуре Контур.Толк компонент `focus.meet.jitsi` не принимает прямые IQ-запросы `<conference>` до того, как участник вошёл в комнату MUC (возвращая `<error type="cancel"><service-unavailable/></error>`). Поэтому на Ktalk узел сразу после `BindResult` отправляет `<presence to="{conf}@muc.meet.jitsi/{ep}" xmlns="jabber:client">`, дожидается собственного отражённого присутствия (`<status code="110"/>`), а если Jicofo не присылает `session-initiate` в течение 4 секунд в `wait_jingle_offer`, отправляет резервный запрос аллокации.
4. **Бесшовное управление потоком XEP-0198 Stream Management (`urn:xmpp:sm:3`):**
   * Если Prosody анонсирует поддержку `<sm xmlns="urn:xmpp:sm:3"/>` в `<features>`, клиент включает управление потоком (`<enable xmlns="urn:xmpp:sm:3" resume="true"/>`), ведёт подсчёт входящих станз (`inbound_h`) и отвечает `<a xmlns="urn:xmpp:sm:3" h="..."/>` на запросы `<r/>`.
   * При кратковременном разрыве TCP-соединения сигналинга фоновая задача `io_handle` автоматически вызывает `try_resume_xmpp_stream()` и восстанавливает сессию на месте (`<resume xmlns="urn:xmpp:sm:3" previd="..." h="..."/>`) без выхода из комнаты MUC и без прерывания медиапотока.

### 3.2. Архитектура ICE-соединения с JVB, привязка к интерфейсу и Multi-Socket UDP ICE
1. **Топология «клиент-сервер» через SFU вместо P2P:**
   * Медиамост JVB всегда имеет **публичный белый IP-адрес** (например, `89.169.16.6:10002`, тип `host` в Jingle Offer).
   * При отправке первых пакетов ICE Connectivity Check узел инициирует исходящий UDP-поток на адрес JVB, мгновенно открывая двустороннюю трансляцию портов на роутере или CGNAT оператора.
2. **Привязка UDP-сокетов WebRTC к физическому сетевому адаптеру (`detect_physical_bind_addr`) и пул сокетов (`udp_ice_socket_count = 6`):**
   * До создания маршрутов TUN функция `detect_physical_bind_addr()` открывает пробный UDP-сокет к IP медиамоста JVB, определяя точный локальный IPv4-адрес исходящего интерфейса (например, `192.168.1.x` или адрес туннельного интерфейса `172.16.0.2` при табличной маршрутизации через WARP).
   * В `PeerConnectionBuilder::with_udp_addrs` передаётся сразу `udp_ice_socket_count` (по умолчанию `6`) локальных адресов `ip:0`. Стек `webrtc-rs` открывает 6 независимых UDP-сокетов с разными эфемерными портами источника (`src_port`), что позволяет ICE-агенту автоматически выбрать наиболее стабильный L4-маршрут при наличии ECMP/LAG-балансировки на промежуточных узлах сети.
3. **Приоритет прямого UDP к JVB (`jvb_use_turn = false`):**
   * По умолчанию параметр `jvb_use_turn` установлен в `false`: для связи с медиамостом JVB используются прямые UDP-кандидаты (`Tier 0: STUN` и `host`-кандидаты моста). Это исключает двойное релейное проксирование через TCP-TURN (`turns_proxy`), предотвращает просадку скорости из-за TCP Head-of-Line blocking и исключает таймауты `TURN transaction timed out`.

### 3.3. Защита от петли маршрутизации (`bypass_ips`)
Чтобы туннель не перехватил собственный сигнальный или медиатрафик после поднятия маршрутов `0.0.0.0/0`, модуль WebRTC собирает `bypass_ips` сразу из нескольких независимых источников:
* Фактические `peer_addr()` уже открытых TCP/TLS сокетов (`xmpp.remote_ip` и `peer.colibri_ws_ip()`);
* Все IP-адреса сигнального домена (`domain:443`) и хоста `colibri-ws`;
* Все `host`/`srflx` кандидаты из Jingle Offer и резервный IP JVB (`wrtc_fallback_jvb_ip`);
* Обнаруженные STUN/TURN серверы из ответа XEP-0215 (`extdisco`).

---

## 4. Этап 3. Строгая типизация Colibri, Unicast Discovery и авторизация ASTP

### 4.1. Схема протокола сообщений
Все управляющие и туннельные сообщения внутри `EndpointMessage` оформлены в соответствии со структурой сервисных событий Jitsi Meet:

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WrtcMessage {
    #[serde(rename = "e2ee-ping", alias = "anet_discover")]
    Discover {
        client_nonce: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        video_ssrc: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        video_v2: Option<bool>,
    },
    #[serde(rename = "e2ee-ack", alias = "anet_beacon")]
    Beacon {
        server_id: String,
        client_nonce: String,
        signature: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        video_ssrc: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        video_v2: Option<bool>,
    },
    #[serde(rename = "ReceiverAudioSubscription", alias = "astp")]
    Astp { data: String },
    #[serde(rename = "dominant-speaker-stats", alias = "astp_batch")]
    AstpBatch { data: String },
    #[serde(rename = "ice-offer", alias = "anet_p2p_offer")]
    P2pOffer { sdp: String, candidates: Vec<String> },
    #[serde(rename = "ice-answer", alias = "anet_p2p_answer")]
    P2pAnswer { sdp: String, candidates: Vec<String> },
    #[serde(rename = "ice-candidate", alias = "anet_p2p_candidate")]
    P2pCandidate { candidate: String },
    #[serde(rename = "keepalive", alias = "anet_ping")]
    Ping,
    #[serde(rename = "keepalive-ack", alias = "anet_pong")]
    Pong,
    #[serde(other)]
    Unknown,
}
```

### 4.2. Детерминированный механизм обнаружения сервера (Unicast Discovery)
1. При подключении к MUC-комнате сервер формирует свой 8-символьный hex `endpoint_id` (`generate_server_endpoint_id`) так, чтобы старшие 2 байта были случайными, а младшие 2 байта (4 hex-символа) детерминированно вычислялись от публичного ключа Ed25519 и идентификатора конференции:
   $$\text{server\_ep\_suffix} = \text{hex}\big(\text{SHA256}(\text{server\_pub\_key\_bytes} \parallel \text{conference\_id})[0..2]\big)$$
2. Клиент вычисляет этот же 4-символьный суффикс и фильтрует список присутствующих в MUC участников (`get_other_occupants`) по совпадению суффикса.
3. Клиент отправляет `WrtcMessage::Discover` (`"type": "e2ee-ping"`) **строго адресно (`to: Some(server_occupant_id)`)**, исключая широковещательную рассылку сторонним участникам комнаты.
4. Сервер подписывает `(client_nonce + server_id)` своим ключом `server_signing_key` (Ed25519) и отправляет `WrtcMessage::Beacon` (`"type": "e2ee-ack"`) в адрес клиента.

---

## 5. Этап 4. Лимит 40 минут и бесшовное восстановление сессии

* При нахождении в комнате одного участника (дежурный `anet-server`) 40-минутный таймер комнаты не активен и запускается только при входе второго участника.
* При плановом закрытии комнаты или переподключении сервер переводит активные клиентские контексты в `suspended` через `registry.suspend_client`.
* При повторном входе клиент выполняет быстрый Discovery и отправляет ASTP с сохранённым `resume_session_id`. Вызов `ClientRegistry::take_suspended` мгновенно перепривязывает новый `endpoint_id` клиента к ранее выделенному туннельному IP без разрыва открытых пользовательских TCP-соединений.

---

## 6. Актуальная конфигурация узлов (`client.toml` и `server.toml`)

Конфигурация секции `[wrtc]` полностью синхронизирована со структурой `WrtcConfig` (`anet-common/src/config.rs`) и содержит два профиля: для прямого подключения и для работы через туннель стабилизации маршрута Cloudflare WARP (`wgcf-profile`).

### В `server.toml`:
```toml
[network]
net = "172.112.224.0"
mask = "255.255.255.0"
gateway = "172.112.224.1"
self_ip = "172.112.224.2"
if_name = "anet-server"
# На прямом соединении: 1400. При работе через CF WARP (MTU 1280): 1100
mtu = 1100

[server]
wrtc_room_url = "wrtc://example.ktalk.ru/example-room-id"
wrtc_mode = "media_video"
wrtc_media_keepalive_interval_ms = 20
wrtc_ping_interval_secs = 10          # 25 на прямом соединении, 10 для CF WARP
wrtc_fallback_jvb_ip = "89.169.16.6"
wrtc_fallback_jvb_port = 10002

[wrtc]
# --- Тайм-ауты сигнализации HTTP API и XMPP/Colibri WebSocket (сек) ---
http_connect_timeout_secs = 15        # 10 (прямой) | 15 (CF WARP)
http_request_timeout_secs = 20        # 15 (прямой) | 20 (CF WARP)
xmpp_handshake_timeout_secs = 20      # 15 (прямой) | 20 (CF WARP)
ws_write_timeout_secs = 15            # 5  (прямой) | 15 (CF WARP)
colibri_ws_connect_timeout_secs = 15  # 10 (прямой) | 15 (CF WARP)
colibri_ws_read_timeout_secs = 25

# --- Стабилизация L4 ECMP / LAG маршрутов (Fast TCP Port Hopping и Multi-Socket UDP ICE) ---
tcp_port_hop_attempts = 8
tcp_port_hop_timeout_ms = 1000
udp_ice_socket_count = 6

# --- Системные буферы UDP, реактор и параметры ICE / STUN / TURN ---
udp_socket_buffer_size = 8388608
reactor_pool_size = 4
ice_disconnected_timeout_ms = 15000   # 10000 (прямой) | 15000 (CF WARP)
ice_failed_timeout_ms = 35000         # 25000 (прямой) | 35000 (CF WARP)
ice_keepalive_interval_ms = 1500      # 2000  (прямой) | 1500  (CF WARP)
turn_refresh_interval_secs = 90
jvb_use_turn = false

# --- Параметры MTU, микро-батчинга VP8 (media_video) и коалесценции пакетов ---
sctp_max_receive_buffer_size = 8388608
sctp_mtu = 1000                       # 1200 (прямой) | 1000 (CF WARP)
receive_mtu = 1600
video_mtu_overhead = 110
min_tun_mtu = 900
max_video_batch_bytes = 960           # 1260 (прямой) | 960  (CF WARP)
video_batch_max_packets = 12          # 16   (прямой) | 12   (CF WARP)
uplink_burst_max_packets = 32         # 64   (прямой) | 32   (CF WARP)
ws_batcher_max_bytes = 4096           # 12288 (прямой)| 4096 (CF WARP)
ws_batcher_max_delay_ms = 2
video_keepalive_interval_ms = 500     # 1000 (прямой) | 500  (CF WARP)

# --- Сторожевые таймеры (watchdog) и проверка живого тракта (сек) ---
watchdog_disconnected_timeout_secs = 12 # 8  (прямой) | 12 (CF WARP)
watchdog_channel_grace_secs = 15        # 12 (прямой) | 15 (CF WARP)
peer_close_timeout_secs = 3
tunnel_ping_interval_secs = 10          # 15 (прямой) | 10 (CF WARP)
tunnel_ping_timeout_secs = 60           # 45 (прямой) | 60 (CF WARP)
server_idle_room_rotation_secs = 1800
```

---

## 7. Трехуровневая архитектура передачи данных (Tiered Data Plane)

1. **Основной высокоскоростной режим `media_video` (Fake Video Track VP8 over DTLS-SRTP):**
   * Трафик упаковывается в RTP-пакеты видеокодека VP8 (`1920x1080`) с 26-байтным префиксом (`VP8_ASTP_PREFIX_LEN`), микро-батчингом и микро-пейсером EDT (подробная спецификация приведена в `contrib/docs/wrtc.video.ru.md`).
2. **Режим `jvb_datachannel` / `ws` (Colibri WebSocket с микробатчингом `PacketBatcher`):**
   * Пакеты из TUN коалесцируются в буфере до `ws_batcher_max_bytes` (`12288` байт на прямом соединении или `4096` байт через WARP) либо по таймеру `2 мс` и отправляются одним фреймом `WrtcMessage::AstpBatch`.
3. **Режим `p2p_direct` (Relay-Only WebRTC P2P DataChannel):**
   * Создаёт прямое соединение `RTCDataChannel` (`ordered: false`, `max_retransmits: Some(0)`) исключительно через инфраструктурные TURN/TURNS релеи (`filter_p2p_sdp_relay_only`), скрывая реальные IP-адреса клиента и сервера.

---

## 8. Механизмы поддержания стабильного соединения в сложных сетевых условиях

### 8.1. Быстрый перебор исходных TCP-портов (`tcp_port_hop_attempts = 8`)
На магистральных каналах с балансировкой нагрузки по хешу заголовков L4 (ECMP / LAG) отдельные пары `(src_ip, dst_ip, src_port, dst_port)` могут попадать на перегруженные или деградировавшие линки.
* При установке HTTP-сессии в `KonturTalkProvider` / `JitsiMeetProvider`, открытии `XMPP-WS` (`open_xmpp_ws_stream`) и подключении `Colibri-WS` выполняется до `tcp_port_hop_attempts` (8) быстрых попыток подключения с коротким таймаутом `tcp_port_hop_timeout_ms` (`1000 мс`).
* Каждая новая попытка `TcpStream::connect` выделяет в ОС новый эфемерный порт источника (`src_port`), мгновенно переводя поток на соседний рабочий линк балансировщика.

### 8.2. Развязка жизнеспособности видеоканала от состояния `Colibri-WS` и UDP ICE
* **Независимое переоткрытие `Colibri-WS` (`colibri_ws_read_timeout_secs = 25`):** если управляющий WebSocket к JVB перестаёт получать кадры дольше 25 секунд, он тихо переоткрывается в фоновой задаче без остановки видеопотока `media_video`.
* **Автоматическое резервирование `MediaVideo` $\leftrightarrow$ `Colibri-WS`:** если на клиентской сети возникают потери UDP-пакетов до порта JVB `10000–10010` и входящие видеокадры не поступают дольше 5 секунд, клиент и сервер синхронно переключают передачу пакетов в `Colibri-WS` (`AstpBatch`) без разрыва туннельной сессии.

### 8.3. Неразделённый цикл ввода-вывода в `XMPP-WS` поверх `tokio_boring::SslStream`
* Поток `ws_stream` в `XmppSession` обрабатывается в **единой задаче `io_handle` через `tokio::select!`** без разделения через `ws_stream.split()` (`BiLock`). Это исключает потерю уведомлений (`Waker`) чтения в `tokio_boring::SslStream` при одновременной отправке пингов и приёме входящих станз от сервера Prosody.

---

## 9. Инженерный разбор реального эксплуатационного кейса (узлы `NL` и `FN`) и стабилизация работы через Cloudflare WARP

В данном разделе задокументирован реальный производственный кейс потери связности зарубежных серверных узлов (`NL` и `FN`) с инфраструктурой ВКС и пошаговая методика полной стабилизации соединения.

### 9.1. Хронология и диагностика: почему до внедрения `turns_proxy.rs` соединение работало стабильно, а после — деградировало через 5 суток

1. **Режим работы до 25 октября (до коммита `348995d`):**
   * Движок `webrtc-rs` (`rtc-turn 0.21`) нативно поддерживает только UDP-сокеты и не устанавливает соединения по схемам `turns:...:443?transport=tcp`.
   * Когда `PeerConnectionBuilder::build()` перебирал эшелоны ICE, он пропускал `turns:` URL и автоматически выбирал прямой обмен по UDP с публичным адресом медиамоста JVB (`*.ktalk.host:10000–10010`).
   * Трафик между зарубежным `anet-server` и медиамостом шёл исключительно по штатному протоколу DTLS/SRTP/STUN поверх UDP на порт JVB, а сигнализация шла по стандартному WebSocket с валидным HTTP Upgrade. Никаких длительных соединений на порт `TCP:443` к узлам `coturn` (`bst-talk-stun7.ktalk.host:443`, `dtl-talk-stun5.ktalk.host:443`) сервер не создавал.

2. **Что изменилось после включения `turns_proxy.rs` и `jvb_use_turn = true`:**
   * Для каждого `turns:*.ktalk.host:443?transport=tcp` начал подниматься локальный мост `spawn_turns_udp_proxy` (`turn:127.0.0.1:<port>`), который вызывал `connect_ws_tls` на порт `TCP:443` серверов `coturn`.
   * При этом функция `connect_ws_tls` указывала в открытом заголовке TLS `ClientHello` расширение **`ALPN: ["http/1.1"]`**, однако сразу после завершения TLS Handshake функция `bridge_turn_stream` отправляла внутри TLS-потока **бинарные фреймы STUN Allocate (`0x00 0x03 ...`) и TURN `ChannelData` (`0x40 0x00 ...`)** вместо HTTP/1.1-запроса.
   * Одновременно из-за `jvb_use_turn = true` зарубежный сервер `anet-server` начал круглосуточно удерживать эти нестандартные TLS-сессии на порту `443` к узлам `coturn` и обновлять их каждые 90 секунд.
   * **Результат:** через 5 суток непрерывной передачи не-HTTP бинарного потока внутри TLS-сессии с заявленным `ALPN: http/1.1` на порту `TCP:443` маршруты между IP-адресами серверов `NL`/`FN` и подсетями ВКС попали под автоматическое ограничение связности на промежуточных магистральных шлюзах.

---

### 9.2. Практическая стабилизация маршрута на сервере `FN` через Cloudflare WARP (`setup_warp_ktalk.sh`)

Для восстановления стабильной связи зарубежного сервера `FN` с серверами ВКС без замены самого VPS был применён избирательный вывод трафика к подсетям Контур.Толк и медиамостов JVB через туннельный интерфейс Cloudflare WARP (`wgcf-profile`). В ходе развёртывания на живом сервере были выявлены и решены **пять практических проблем**:

#### Проблема 1. Захват маршрута по умолчанию стандартным профилем `wg-quick`
* **Симптом:** При запуске `wg-quick up wgcf-profile` со стандартным конфигом весь исходящий трафик сервера уходит в интерфейс WARP, из-за чего пропадает доступ к серверу по SSH и перестают работать прямые клиентские подключения на внешний интерфейс `ens3`.
* **Решение:** В конфигурацию `/etc/wireguard/wgcf-profile.conf` принудительно добавляются директивы `Table = off` и `MTU = 1280`. Маршрут в `wgcf-profile` создаётся в отдельной таблице маршрутизации `100` (`ip route replace default dev wgcf-profile table 100`), а через `ip -4 rule add to <CIDR> table 100 priority 100` в неё направляются только целевые подсети ВКС и облачных медиамостов JVB (`46.17.200.0/21`, `89.169.16.0/24`, `84.201.128.0/18`, `51.250.0.0/17`, `158.160.0.0/16`, `130.193.32.0/19`, `178.154.128.0/17`, `91.209.56.0/22`, `91.197.180.0/23`, `193.160.208.0/22`, `193.232.166.0/24`).

#### Проблема 2. Сброс пакетов фильтром обратного пути (`rp_filter`) и отсутствие форвардинга из `anet+`
* **Симптом:** Даже после поднятия `wgcf-profile` и добавления `iptables -t nat -A POSTROUTING -o ens3 -j MASQUERADE` трафик клиентов внутри туннеля (`172.112.224.x`) не проходил во внешнюю сеть, либо терялись пакеты при асимметричной маршрутизации между `ens3` и `wgcf-profile`.
* **Решение:**
  1. Перевод проверки обратного пути ядра Linux в режим Loose (`rp_filter = 2`) на всех интерфейсах (`all`, `default`, `wgcf-profile`, `ens3`) и включение `net.ipv4.ip_forward = 1`.
  2. Явное разрешение транзита пакетов для всех туннельных интерфейсов `anet+` в начале цепочки `FORWARD`:
     ```bash
     iptables -I FORWARD 1 -i anet+ -j ACCEPT
     iptables -I FORWARD 2 -o anet+ -m state --state RELATED,ESTABLISHED -j ACCEPT
     ```

#### Проблема 3. Фрагментация UDP/RTP пакетов внутри `wgcf-profile` (MTU 1280) и просадка скорости через `turns_proxy`
* **Симптом:** На стандартном серверном `[network] mtu = 1400` и `max_video_batch_bytes = 1260` размер исходящих RTP-кадров превышал MTU `1280` интерфейса `wgcf-profile`, вызывая фрагментацию и потери пакетов при скачивании. Кроме того, при `jvb_use_turn = true` ICE переключал медиапоток на TCP-релей `turns_proxy`, что роняло скорость и вызывало разрыв сессии через ~90 секунд по `TURN transaction timed out`.
* **Решение:**
  1. В `server.toml` отключено использование TURN для соединения с JVB: `jvb_use_turn = false`.
  2. Выстроен согласованный каскад MTU:
     * На интерфейсе `wgcf-profile`: `MTU = 1280`, планировщик `fq_codel` и `TCPMSS --set-mss 1080`.
     * В `server.toml`: `[network] mtu = 1100`, `video_mtu_overhead = 110`, `min_tun_mtu = 900`, `max_video_batch_bytes = 960`. В результате клиент получает эффективный MTU туннеля `990` байт, а каждый зашифрованный VP8 RTP-кадр укладывается в `~1070–1150` байт и проходит через WireGuard WARP без единого фрагментированного пакета.

#### Проблема 4. Ошибка `XMPP MUC handshake timed out after 20s` при входе сервера `FN` в комнату Ktalk
* **Симптом:** При запуске `RUST_LOG=debug ./anet-server` на сервере `FN` HTTP-авторизация (`POST /api/authorize/session` и `GET /api/rooms/...`) и TLS WebSocket handshake проходили успешно (`HTTP status: 101 Switching Protocols`), однако после `SASL ANONYMOUS` хендшейк зависал и обрывался по таймауту 20 секунд.
* **Корневая причина (две особенности Prosody и Jicofo на Ktalk):**
  1. В WebSocket-фреймах RFC 7395 станзы `<iq type="set" id="_bind_auth_2"><bind.../></iq>` и `<presence.../>` отправлялись без атрибута `xmlns="jabber:client"` на внешнем теге. Модуль `mod_websocket` в Prosody отбрасывал такие станзы без ответа.
  2. Отправка `<iq to="focus.meet.jitsi" type="set"><conference .../></iq>` до завершения входа в комнату MUC вызывала ответ `<error type="cancel"><service-unavailable/></error>` от Prosody/Jicofo.
* **Решение (коммит `dc984ea`):**
  1. Во все методы `XmppBuilder` (`xmpp_xml.rs`) добавлен обязательный атрибут `xmlns="jabber:client"` для каждой станзы `<iq>` и `<presence>`.
  2. Для провайдера `KonturTalk` установлен порядок `pre_allocate_before_muc = false` (сначала вход в MUC и получение `status code="110"`), а резервный запрос `conference_allocation` в `wait_jingle_offer` отправляется автоматически через 4 секунды, если Jicofo ещё не прислал `session-initiate`.

### 9.3. Автоматическая настройка маршрутизации WARP скриптами `./contrib/scripts/cf_ktalk_setup.sh` и `./contrib/scripts/setup_warp_ktalk.sh`

В директории `./contrib/scripts/` находятся два скрипта автоматической настройки маршрутизации Cloudflare WARP на сервере:
1. **`./contrib/scripts/cf_ktalk_setup.sh` (полная установка «под ключ» с сохранением после перезагрузки):**
   * Автоматически устанавливает системные пакеты (`wireguard-tools`, `iproute2`, `iptables-persistent`, `jq`) и скачивает бинарник `wgcf`;
   * Автоматически регистрирует аккаунт Cloudflare WARP и генерирует `/etc/wireguard/wgcf-profile.conf` (если профиль ещё не создан);
   * Создаёт постоянный конфиг `/etc/sysctl.d/99-anet-warp-ktalk.conf` (`ip_forward=1`, `rp_filter=2`) и идемпотентный хук `/etc/wireguard/anet-warp-ktalk-hook.sh` (`PostUp`/`PostDown`), настраивающий маршруты с `mtu 1240 advmss 1160` (для беспрепятственного прохождения крупных пакетов TLS 1.3 `ClientHello` с постквантовым гибридным ключом `X25519MLKEM768`), таблицу `100`, `fq_codel`, правила `FORWARD` (включая перевод браузерного трафика с транзитного `UDP:443` на TCP с зажатым MSS) и `TCPMSS`;
   * Активирует автозапуск через `systemctl enable --now wg-quick@wgcf-profile.service`.
2. **`./contrib/scripts/setup_warp_ktalk.sh` (облегчённый скрипт быстрой перенастройки уже установленного профиля `wgcf-profile.conf`):**
```bash
sudo ./contrib/scripts/cf_ktalk_setup.sh
# или для быстрой ручной перенастройки существующего профиля:
sudo ./contrib/scripts/setup_warp_ktalk.sh
```
Что делает скрипт:
1. Прописывает `Table = off` и `MTU = 1280` в `/etc/wireguard/wgcf-profile.conf`.
2. Перезапускает интерфейс `wgcf-profile` и очищает старые правила маршрутизации.
3. Устанавливает `mtu 1280`, `txqueuelen 1000` и дисциплину очереди `fq_codel` на `wgcf-profile`.
4. Включает `net.ipv4.ip_forward=1` и `rp_filter=2` (Loose Reverse Path Filtering) на всех сетевых адаптерах.
5. Настраивает таблицу маршрутизации `100` (`default dev wgcf-profile table 100`) и направляет в неё префиксы Контур.Толк (AS49675) и облачных медиамостов JVB.
6. Добавляет правила `iptables` (`FORWARD` для `anet+`, `MASQUERADE` для `ens3` и `wgcf-profile`, а также `TCPMSS --set-mss 1080` и `--clamp-mss-to-pmtu`).

---

## 10. Рекомендации по дальнейшему повышению эксплуатационной надёжности

1. **Использование коннектора без `ALPN: http/1.1` в `turns_proxy.rs`:**
   * При использовании `turns_proxy` на клиентских устройствах в сетях с ограниченным UDP следует устанавливать TLS-соединение к серверам `coturn` без HTTP ALPN (либо с `ALPN: stun.turn` по RFC 7443) и передавать в `spawn_turns_udp_proxy` настройки `TlsClientConfig` из секции `[stealth]`.
2. **Ленивая инициализация `spawn_turns_udp_proxy`:**
   * Запускать локальный мост `TurnsProxyHandle` только в том случае, если прямой UDP-эшелон (`Tier 0: STUN`) недоступен или явно выбран режим `p2p_direct`.
3. **Добавление случайного фазового сдвига (джиттера) к сервисным таймерам:**
   * Варьировать интервал профилактической ротации пустой комнаты `server_idle_room_rotation_secs` в пределах $\pm 30\%$, а интервалы фоновых пингов `Colibri-WS`, `XMPP-WS` и тестовых кадров `video_keepalive_interval_ms` — в пределах $\pm 25\%$, исключая строго периодические сетевые паттерны при длительном дежурстве сервера в комнате.

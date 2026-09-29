# Архитектура и спецификация транспорта `wrtc` (WebRTC over Ktalk / Jitsi SFU)

---

## 1. Введение и архитектурная концепция

### 1.1. Назначение
Транспорт `wrtc` предназначен для скрытной и отказоустойчивой передачи туннелированного IP-трафика ANet через корпоративную инфраструктуру видеоконференцсвязи (ВКС) сервиса **Ktalk (Контур.Толк)**. Сервис функционирует на базе стека **Jitsi (Prosody + Jicofo + Jitsi Videobridge / JVB)**. Трафик полностью маскируется под легитимного участника видеоконференции в браузере:
1. **HTTP/REST и WSS уровень:** полная маскировка под современные браузеры (Chrome / Firefox / Safari) со случайным профилем (`BrowserProfile`), валидными Client Hints (`sec-ch-ua`, `sec-ch-ua-mobile`, `sec-ch-ua-platform`), Fetch Metadata (`Sec-Fetch-*`), языковыми заголовками и естественными именами гостей («Пользователь 248», «Гость 5433», «Денис»).
2. **Сигнальный транспорт (XMPP over WebSocket):** взаимодействие по RFC 7395 с сервером Prosody на базе синтаксического DOM/AST-парсера (`roxmltree`) и строгого XML-билдера с экранированием спецсимволов.
3. **Транспорт данных (Colibri-WS):** передача управляющих и зашифрованных сетевых пакетов через выделенный полнодуплексный WebSocket моста JVB (`wss://.../colibri-ws/...`), исключающий фрагментацию и проблемы с блокировкой UDP/SCTP.
4. **Медиауровень (WebRTC keep-alive):** эмуляция реального медиапотока (Opus silence) через библиотеку `webrtc = "0.21.0"`. Непрерывная передача аудиотрека тишины каждые 20 мс переводит эндпоинт на стороне JVB в состояние `Connected` и предотвращает изоляцию участника по неактивности.

### 1.2. Базовая топология
* **Топология сети:** Клиент-серверное соединение поверх топологии **SFU (Selective Forwarding Unit)**. Прямое соединение (P2P) между пирами не требуется; все участники взаимодействуют через медиамост JVB.
* **Среда встречи (Rendezvous):** Клиенты и сервер подключаются в одну заранее подготовленную постоянную комнату с фиксированным коротким именем (например, `gj9xl7vm4jmw`).
* **Роли в парадигме ANet:**
  * `anet-server` выступает в роли дежурного участника ВКС, непрерывно присутствующего в комнате.
  * `anet-client` подключается к комнате по требованию, находит сервер посредством криптографического механизма Discovery и инициирует внутреннее рукопожатие ASTP.
* **Канал передачи данных:** Протокол **Colibri** поверх защищенного WebSocket соединения к JVB. Сообщения упаковываются в типизированную структуру `colibriClass: ColibriClass::EndpointMessage` с адресной маршрутизацией через поле `to`.

---

## 2. Этап 1. Авторизация и предстартовое согласование (REST API)

Подключение к WebSockets и сигнальной сети Jitsi требует предварительного получения сессионного токена гостя и внутреннего идентификатора конференции (`conferenceId`). Выполняется клиентом и сервером единообразно через REST API Ktalk.

```
+-------------+                     +----------------------+
| ANet Client |                     | Ktalk HTTP API       |
|  or Server  |                     | (ycs3y048.ktalk.ru)  |
+-------------+                     +----------------------+
       |                                       |
       | 1. POST /api/authorize/session        |
       |    Headers: Browser Stealth + Hints   |
       |    Body: { name: "Гость ...", ... }   |
       |-------------------------------------->|
       |                                       |
       | 2. JSON: { token, expiresIn: 6 days } |
       |<--------------------------------------|
       |                                       |
       | 3. GET /api/rooms/{short_name}        |
       |    Headers: Browser Stealth           |
       |             Authorization: Session {t}|
       |-------------------------------------->|
       |                                       |
       | 4. JSON: { conferenceId: "{name}_{h}"}|
       |<--------------------------------------|
       |                                       |
       v                                       v
   [Готовность к открытию WSS сигналинга XMPP]
```

### 2.1. Получение сессионного токена гостя
Клиент формирует запрос на создание анонимной сессии.

* **HTTP Метод:** `POST`
* **URL:** `https://{domain}/api/authorize/session`
* **Заголовки маскировки под браузер:**
  * `Content-Type: application/json`
  * `Origin: https://{domain}`
  * `Referer: https://{domain}/{room_short_name}`
  * `User-Agent: Mozilla/5.0 ... Chrome/124.0.0.0 Safari/537.36` (выбирается из пула `BrowserProfile`)
  * `Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7`
  * `sec-ch-ua: "Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"`
  * `sec-ch-ua-mobile: ?0`
  * `sec-ch-ua-platform: "Windows"`
  * `Sec-Fetch-Dest: empty`, `Sec-Fetch-Mode: cors`, `Sec-Fetch-Site: same-origin`
  * `Cache-Control: no-cache`, `Pragma: no-cache`
* **Тело запроса (JSON):**
  ```json
  {
    "name": "Гость 4821",
    "anonymousSecret": "GYJ0ELL13CY24UG",
    "consentOnCreate": true
  }
  ```
* **Ответ Ktalk API:**
  ```json
  {
    "token": "3fzNXERAn22TEqOwvmGT",
    "expiresAt": "2026-10-01T02:00:00Z",
    "expiresIn": 543740,
    "anonymousId": "A56CBDE4BF1CE3D2C6C3782CCD15CD871A812D1CDCD46C9343C23870F2EE2F17"
  }
  ```

### 2.2. Разрешение внутреннего имени конференции Jitsi
Короткое имя комнаты транслируется во внутренний хэшированный идентификатор комнаты Jicofo.

* **HTTP Метод:** `GET`
* **URL:** `https://{domain}/api/rooms/{room_short_name}`
* **Заголовки:** `Authorization: Session {token}`, браузерные Client Hints и `Accept: application/json`.
* **Ответ Ktalk API:**
  ```json
  {
    "roomName": "gj9xl7vm4jmw",
    "conferenceId": "gj9xl7vm4jmw_f10854d499a27df7f7d6c843136749e41ed14839e16939f4a3dccaab9fac2874",
    "allowAnonymous": true
  }
  ```

---

## 3. Этап 2. Сигналинг XMPP и запуск медиамоста

```
+-------------+                 +-----------------+                 +---------------+
| ANet Node   |                 | Prosody (XMPP)  |                 | Jicofo / JVB  |
+-------------+                 +-----------------+                 +---------------+
       |                                 |                                  |
       | 1. Connect WebSocket            |                                  |
       |    /jitsi/xmpp-websocket        |                                  |
       |    (Browser Stealth Headers)    |                                  |
       |-------------------------------->|                                  |
       | 2. SASL ANONYMOUS Auth          |                                  |
       |<------------------------------->|                                  |
       | 3. Resource Bind                |                                  |
       |<------------------------------->|                                  |
       | 4. MUC Presence (Enter Room)    |                                  |
       |    with random guest nickname   |                                  |
       |-------------------------------->|                                  |
       |                                 | 5. Conference allocation request |
       |                                 |    <iq type="set" ... />         |
       |                                 |--------------------------------->|
       |                                 | 6. Jingle Offer (session-initiate)|
       | 7. Jingle Offer (Dynamic ICE)   |<---------------------------------|
       |<--------------------------------|                                  |
       | 8. Parse colibri-ws url, ICE,   |                                  |
       |    DTLS, fingerprint, ufrag/pwd |                                  |
       |                                 |                                  |
       | 9. Jingle session-accept        |                                  |
       |-------------------------------->|                                  |
       |                                 |                                  |
       | 10. Open Colibri WebSocket      |                                  |
       |<==================================================================>|
       |     (Primary data channel)      |                                  |
       |                                 |                                  |
       | 11. ICE / DTLS Handshake to JVB |                                  |
       |<==================================================================>|
       | 12. Background Keep-Alive:                                         |
       |     - Opus Audio silence frame every 20ms                          |
       |     - WebSocket Colibri Ping every 10s                             |
       |     - XMPP WS ping / whitespace every 20s                          |
```

### 3.1. Параметры WebSocket-сигналинга и маскировка
* **Endpoint:** `wss://{domain}/jitsi/xmpp-websocket?room={conferenceId}&sessionToken={token}`
* **Subprotocol:** `xmpp`
* **Маскировка WS Handshake:** Установка полного комплекта браузерных заголовков (`User-Agent`, `Origin: https://{domain}`, `Accept-Language`, `sec-ch-ua`, `Cache-Control`, `Pragma`).

### 3.2. Архитектура XML-парсера (`xmpp_xml.rs`)
Входящий XMPP-поток разбирается синтаксическим DOM-парсером `roxmltree` без хрупкого строкового поиска:
1. **Мульти-станзы (RFC 7395):** Prosody может присылать несколько станз в одном WebSocket фрейме (например, `<open .../><features ...>`). Парсер оборачивает входящий буфер в виртуальный `<stream>...</stream>` и разбирает каждую станзу отдельно (`parse_xmpp_stanzas`).
2. **SASL Mechanisms:** Обрабатывается вложенность `<features><mechanisms><mechanism>ANONYMOUS</mechanism></mechanisms></features>`.
3. **Автоматическое экранирование:** Все исходящие станзы строятся через `XmppBuilder` с валидацией и экранированием спецсимволов (`&`, `<`, `>`, `"`, `'`).
4. **Обработка системных IQ:** В фоновом воркере автоматически подтверждаются запросы Jicofo:
   * `urn:xmpp:ping` -> ответ `<iq type="result"/>`.
   * `http://jabber.org/protocol/disco#info` -> ответ со списком поддерживаемых фичей Jitsi Meet (jingle, colibri, audio/video).
   * `urn:xmpp:jingle:1` (акты `session-` и `source-`) -> немедленный ACK `<iq type="result"/>`.

### 3.3. Разделение каналов: Colibri-WS и WebRTC Keepalive
1. **Основной транспорт данных (Colibri-WS):**
   * Из входящего Jingle Offer извлекается тег `<web-socket xmlns="http://jitsi.org/protocol/colibri" url="..."/>`.
   * Клиент и сервер подключаются к указанному URL с браузерными заголовками. Через этот сокет передаются `EndpointMessage` с протоколами Discovery и ASTP.
2. **Фоновый WebRTC Media Keepalive (Opus silence):**
   * Для предотвращения перевода эндпоинта мостом JVB в состояние `inactive` (что приводит к блокировке доставки `EndpointMessage`) поднимается минимальный `RTCPeerConnection`.
   * Регистрируется фиктивный Opus-аудиотрек (48000 Hz, 2 channels).
   * Запускается фоновый таймер отправки 3-байтового фрейма тишины Opus (`0xf8, 0xff, 0xfe`) каждые 20 мс (`wrtc_media_keepalive_interval_ms`).
   * После завершения ICE/DTLS хэндшейка статус PeerConnection переходит в `Connected`.

### 3.4. Автоматическое определение Bypass IP (Split Tunneling)
Чтобы туннель ANet не перехватил собственный медиатрафик и не создал петлю маршрутизации, модуль WebRTC при старте извлекает IP-адреса из:
* Host/srflx кандидатов Jingle Offer;
* Доменного имени Colibri WebSocket.
Список обнаруженных адресов (`Discovered media bypass IPs: [...]`) передается в ядро клиента и автоматически добавляется в исключения системного шлюза/маршрутизации.

---

## 4. Этап 3. Строгая типизация Colibri, обнаружение и авторизация

### 4.1. Схема протокола сообщений

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ColibriClass {
    #[serde(rename = "EndpointMessage")]
    EndpointMessage,
    #[serde(rename = "DominantSpeakerEndpointChangeEvent")]
    DominantSpeaker,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WrtcMessage {
    #[serde(rename = "anet_discover")]
    Discover { client_nonce: String },
    #[serde(rename = "anet_beacon")]
    Beacon {
        server_id: String,
        client_nonce: String,
        signature: String,
    },
    #[serde(rename = "anet_ping")]
    Ping,
    #[serde(rename = "anet_pong")]
    Pong,
    #[serde(rename = "astp")]
    Astp { data: String },
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColibriMessage {
    #[serde(rename = "colibriClass")]
    pub colibri_class: ColibriClass,
    pub to: Option<String>,
    pub from: Option<String>,
    #[serde(rename = "msgPayload")]
    pub msg_payload: WrtcMessage,
}
```

```
       [Клиент]                    [JVB Мост]                  [Сервер]
          |                            |                          |
          |                            |<--- Сервер в комнате     |
          |                            |     (WebRTC Connected)   |
          |                            |                          |
 1. Вошел в комнату                    |                          |
    Шлет Discovery:                    |                          |
    - broadcast (без "to")             |                          |
    - unicast ("to": occupant_id)      |                          |
    ---------------------------------->|                          |
                                       |--- forwards to Server -->| 2. Принял Discovery
                                       |                          |    Подписал (Nonce + SrvId)
                                       |                          |    ключом server_signing_key
                                       |                          |
                                       |<--- Beacon (to: Client) -| 3. Отправил Beacon
 4. Проверил подпись                   |<-------------------------|    {"type":"anet_beacon",
    по server_pub_key.                 |                               "signature":"..."}
    Сервер верифицирован!              |
                                       |
 5. ASTP Handshake (Phase 1-4)         |
    Таймаут: 6 секунд                  |
    unicast ("to": ServerId)           |
 <===============================================================>| 6. Вызов Control Plane API
                                       |                          |    Выдача IP (172.112.224.X)
                                       |                          |    Финализация сессии
                                       |                          |
 7. Туннелирование трафика             |                          |
    {"to": ServerId, payload: ...}     |                          |
 ================================================================>| 8. Маршрутизация в TUN
```

### 4.2. Механизм обнаружения сервера (Challenge-Response Discovery)
1. Клиент собирает список всех присутствующих в MUC участников (`get_other_occupants`).
2. Клиент отправляет `WrtcMessage::Discover` с криптографическим нонсом (`client_nonce`):
   * В общий broadcast (без поля `to`);
   * Адресно каждому известному эндпоинту комнаты.
3. Сервер, получив запрос, подписывает `(client_nonce + server_id)` своим `server_signing_key` (Ed25519) и отправляет `WrtcMessage::Beacon` строго в адрес клиента (`to: client_endpoint`).
4. Клиент верифицирует подпись открытым ключом `server_pub_key`. При успехе `server_id` фиксируется как целевой адрес для ASTP.

### 4.3. Рукопожатие ASTP и предотвращение рассинхронизации ключей
1. В Phase III клиент передает зашифрованные авторизационные данные серверу.
2. Сервер при обработке Phase III регистрирует клиента и параллельно отчитывается в Control Plane (`auth_provider.report_session_start`). Сетевой вызов может занимать до 2–4 секунд.
3. **Таймауты ASTP (`INITIAL_DELAY = 6s`):**
   * Таймаут ожидания Phase IV на клиенте установлен на **6 секунд** (с ростом до 60 с при сетевых сбоях).
   * Это предотвращает срыв клиента в повторный ретрай до завершения серверной авторизации, устраняя рассинхрон сессионных ключей X25519 (`Decryption failed`) и утечку виртуальных IP-адресов.
4. **Фильтрация шума:** В циклах ожидания Phase II и Phase IV реализована безопасная фильтрация некорректных/старых пакетов без аварийного сброса рукопожатия.

---

## 5. Этап 4. Лимит 40 минут и бесшовное восстановление сессии

### 5.1. Условия работы таймера Ktalk
* При нахождении в комнате **одного** участника (дежурный `anet-server`) счетчик 40 минут остановлен.
* Счетчик запускается в момент входа второго участника.
* По истечении 40 минут комната расформировывается Контуром: WebSockets и WebRTC закрываются у всех участников.

### 5.2. Процедура реконнекта
1. Клиент и сервер ловят обрыв сокета и независимо перезапускают цикл входа в комнату.
2. При разрыве сервер переводит активные клиентские контексты в `suspended` через `registry.suspend_client`.
3. После входа и повторного обнаружения клиент отправляет ASTP с флагом возобновления и сохраненным `resume_session_id`.
4. Сервер вызывает `ClientRegistry::take_suspended`:
   * Связывает **новый** `endpoint_id` клиента со старым выделенным IP.
   * Сессия восстанавливается мгновенно без сброса пользовательских TCP-соединений.

---

## 6. Конфигурация узлов

### В `client.toml`:
```toml
[[servers]]
name = "Ktalk Node [WRTC]"
dsn = "wrtc://ycs3y048.ktalk.ru/gj9xl7vm4jmw"
timeout_secs = 15
server_pub_key = "<BASE64_ED25519_PUBLIC_KEY>"
wrtc_media_keepalive_interval_ms = 20 # Эмуляция Opus тишины (мс)
wrtc_ping_interval_secs = 20          # Пинг сигнального WSS (сек)
wrtc_fallback_jvb_ip = "89.169.19.7"  # Fallback IP медиасервера JVB
wrtc_fallback_jvb_port = 10004        # Fallback UDP порт JVB
```

### В `server.toml`:
```toml
[server]
wrtc_room_url = "https://ycs3y048.ktalk.ru/gj9xl7vm4jmw"
wrtc_media_keepalive_interval_ms = 20 # Эмуляция Opus тишины (мс)
wrtc_ping_interval_secs = 20          # Пинг сигнального WSS (сек)
wrtc_fallback_jvb_ip = "89.169.19.7"  # Fallback IP медиасервера JVB
wrtc_fallback_jvb_port = 10004        # Fallback UDP порт JVB

[crypto]
server_signing_key = "<BASE64_ED25519_PRIVATE_KEY>"
```

# Техническое задание: Реализация транспорта `wrtc` для ANet (WebRTC over Ktalk/Jitsi SFU)

---

## 1. Введение и архитектурная концепция

### 1.1. Назначение
Транспорт `wrtc` предназначен для скрытной передачи туннелированного IP-трафика ANet через инфраструктуру корпоративной видеоконференцсвязи (ВКС) сервиса **Ktalk (Контур.Толк)**. Сервис функционирует на базе стека **Jitsi (Prosody + Jicofo + Jitsi Videobridge / JVB)**. Трафик маскируется под легитимный браузер в видеоконференции:
1. **HTTP/WSS уровень:** маскировка под реальный браузер (Chrome / Firefox / Safari) с валидными Client Hints (`sec-ch-ua`), Fetch Metadata (`Sec-Fetch-*`), языковыми заголовками и реалистичными случайными именами гостей.
2. **WebRTC уровень:** медиапотоки (SRTP/DTLS) со вспомогательным Opus-аудиотреком тишины и сервисные данные (SCTP DataChannel) к серверам, находящимся в корпоративных белых списках.
3. **Реализация:** на базе `webrtc = "0.21.0"` (с подсистемами SCTP и DataChannel).

### 1.2. Базовая топология
* **Топология сети:** Клиент-серверное соединение поверх топологии **SFU (Selective Forwarding Unit)**. Прямое соединение (P2P) между пирами не используется; все участники взаимодействуют с медиасервером Контура (JVB).
* **Среда встречи (Rendezvous):** Клиенты и сервер подключаются в одну заранее подготовленную постоянную комнату с фиксированным коротким именем (например, `oaj4kr56yubb`).
* **Роли в парадигме ANet:**
    * `anet-server` физически выступает в роли клиента сервиса ВКС, непрерывно присутствующего в комнате.
    * `anet-client` подключается к комнате в произвольный момент времени, обнаруживает сервер и инициирует внутреннее рукопожатие ASTP.
* **Канал передачи данных:** Штатный протокол **Colibri** поверх `RTCDataChannel` (SCTP). Сообщения инкапсулируются в типизированную структуру `colibriClass: ColibriClass::EndpointMessage` с адресной маршрутизацией через поле `to`.

---

## 2. Этап 1. Авторизация и предстартовое согласование (REST API)

Подключение к WebSockets и сигнальной сети Jitsi требует предварительного получения гостевого сессионного токена и внутреннего идентификатора конференции (`conferenceId`). Выполняется клиентом и сервером единообразно с использованием случайного профиля браузера (`BrowserProfile`) и маскировочных заголовков.

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
   [Готовность к открытию WSS сигналинга Jitsi]
```

### 2.1. Получение сессионного токена гостя (с маскировкой)
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
  *Примечание: Имя участника генерируется случайно при каждом подключении (`generate_random_guest_name()`) в естественных форматах («Гость 4821», «Алексей», «Пользователь 528»), исключая любые упоминания ANet.*
  *`anonymousSecret` — случайная буквенно-цифровая последовательность длиной 15 символов.*

* **Фактический ответ Ktalk API:**
  ```json
  {
    "token": "3fzNXERAn22TEqOwvmGT",
    "expiresAt": "2026-10-01T02:00:00Z",
    "expiresIn": 543740,
    "anonymousId": "A56CBDE4BF1CE3D2C6C3782CCD15CD871A812D1CDCD46C9343C23870F2EE2F17"
  }
  ```
* **Результат:** Значение `token` извлекается для последующего использования. Токен действителен ~6 суток (`expiresIn: ~543740` сек).

### 2.2. Разрешение внутреннего имени конференции Jitsi
Короткое имя комнаты транслируется во внутренний хэшированный идентификатор комнаты Jicofo.

* **HTTP Метод:** `GET`
* **URL:** `https://{domain}/api/rooms/{room_short_name}`
* **Заголовки:** `Authorization: Session {token}`, браузерные Client Hints и `Accept: application/json`.
* **Фактический ответ Ktalk API:**
  ```json
  {
    "roomName": "oaj4kr56yubb",
    "conferenceId": "oaj4kr56yubb_da8633dcf339cf5d31d854d8f02191a2b29f6729bb3e46a0905d9c13134479d6",
    "allowAnonymous": true
  }
  ```
* **Результат:** Значение `conferenceId` извлекается и используется как параметр комнаты при открытии XMPP WebSocket.

---

## 3. Этап 2. Сигналинг XMPP и согласование WebRTC-сессии

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
       | 3. MUC Presence (Enter Room)    |                                  |
       |    with random guest nickname   |                                  |
       |-------------------------------->|                                  |
       |                                 | 4. Conference allocation request |
       |                                 |    <iq type="set" ... />         |
       |                                 |--------------------------------->|
       |                                 | 5. Jingle Offer (session-initiate)|
       | 6. Jingle Offer (Dynamic ICE)   |<---------------------------------|
       |<--------------------------------|                                  |
       | 7. Parse candidates, DTLS, ufrag|                                  |
       |    (with JVB fallback if empty) |                                  |
       |                                 |                                  |
       | 8. ICE / DTLS Handshake to JVB  |                                  |
       |<==================================================================>|
       | 9. Open SCTP DataChannel: "JVB data channel"                       |
       |<==================================================================>|
       | 10. Background Keep-Alive:                                         |
       |     - Opus Audio silence frame every 20ms                          |
       |     - WebSocket & XMPP whitespace ping every 30s                   |
```

### 3.1. Параметры WebSocket-сигналинга и маскировка
* **Endpoint:** `wss://{domain}/jitsi/xmpp-websocket?room={conferenceId}&sessionToken={token}`
* **Subprotocol:** `xmpp`
* **Маскировка WS Handshake:** Установка полного комплекта браузерных заголовков (`User-Agent`, `Origin: https://{domain}`, `Accept-Language`, `sec-ch-ua`, `Cache-Control`, `Pragma`).

### 3.2. Этапы XMPP-сессии:
1. Инициализация обрамления: `<open to="meet.jitsi" version="1.0" xmlns="urn:ietf:params:xml:ns:xmpp-framing"/>`.
2. Аутентификация: `<auth mechanism="ANONYMOUS" xmlns="urn:ietf:params:xml:ns:xmpp-sasl"/>`.
3. Привязка ресурса: `<iq type="set" id="_bind_auth_2"><bind xmlns="urn:ietf:params:xml:ns:xmpp-bind"/></iq>`.
4. Вход в MUC комнаты: отправка `<presence to="{conferenceId}@muc.meet.jitsi/{random_8hex_endpoint_id}"><nick>{random_guest_name}</nick></presence>`.
5. Запрос выделения видеомоста Jicofo: `<iq type="set" to="focus@auth.meet.jitsi"><conference xmlns="http://jitsi.org/protocol/focus" room="{conferenceId}@muc.meet.jitsi"/></iq>`.

### 3.3. Динамический ICE-сигналинг и WebRTC DataChannel
* **Парсинг Jingle Offer:** Извлекаются актуальные параметры, возвращаемые Jicofo:
  * `<candidate ip="..." port="..." protocol="..." type="..." />`
  * `ufrag`, `pwd`, `<fingerprint hash="..." setup="...">`
  * Параметры SCTP (порт 5000).
* **Динамический Fallback:** Если Jicofo не вернул кандидатов, применяются значения по умолчанию:
  * Медиасервер JVB: хост `89.169.16.6`, UDP-порт `10002` (тип `host`).
  * Резервные TURN (TCP/TLS): `turns:dtl-talk-stun7.ktalk.host:443?transport=tcp`.
* **Спецификация DataChannel:**
  * **Label:** `"JVB data channel"`
  * **Protocol:** `"http://jitsi.org/protocols/colibri"`
  * **Ordered:** `false`, `maxRetransmits: 0`.

### 3.4. Защита от сброса соединения (Anti-Drop)
1. **Эмуляция медиа (Opus silence keep-alive):**
   * В `RTCPeerConnection` регистрируется фиктивный аудиотрек (`mime_type: audio/opus`, 48000 Hz, stereo).
   * Фоновый воркер каждые `wrtc_media_keepalive_interval_ms` (по умолчанию 20 мс) отправляет 3-байтовый фрейм тишины Opus (`0xf8, 0xff, 0xfe`). Это предотвращает закрытие моста со стороны JVB/Jicofo по таймауту отсутствия медиа.
2. **Двойной Ping сигналинга:**
   * Фоновый воркер каждые `wrtc_ping_interval_secs` (по умолчанию 30 с) отправляет WebSocket `Ping` и XMPP whitespace-пинг (`" "`), поддерживая WSS-соединение через промежуточные корпоративные прокси и NAT.

---

## 4. Этап 3. Строгая типизация Colibri, обнаружение и мультиплексирование

### 4.1. Строгая схема сообщений (Enum)

Все протокольные взаимодействия типизированы без хрупкого парсинга XML-подстрок:

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
       [Клиент А]                  [JVB Мост]                  [Сервер]
            |                            |                         |
            |                            |<--- Сервер уже в комнате|
            |                            |     (или входит позже)  |
            |                            |                         |
 1. Вошел в комнату                      |                         |
    Шлет Discovery:                      |                         |
    {"colibriClass":"EndpointMessage",   |                         |
     "msgPayload":{"type":"anet_discover"|                         |
                   "client_nonce":"N1"}} |                         |
    ------------------------------------>|                         |
    (broadcast без "to")                 |--- forwards to all ---->| 2. Принял Discovery
                                         |                         |    Подписал (N1 + SrvId)
                                         |                         |    ключом server_signing_key
                                         |                         |
                                         |<--- Beacon (to: Client) | 3. Отправил Beacon
    4. Проверил подпись                  |<------------------------|    {"type":"anet_beacon",
       по server_pub_key.                |                              "signature":"..."}
       Сервер верифицирован!             |
                                         |
    5. ASTP Handshake Phase 1-4          |
       (unicast to: ServerId)            |
    <=============================================================>| 6. Выдача IP (10.0.0.X)
                                         |                         |    Привязка ClientId <-> IP
                                         |                         |
    7. Туннелирование трафика            |                         |
       {"to": ServerId, payload: ...}    |                         |
    ==============================================================>|
```

### 4.2. Протокол обнаружения сервера (Challenge-Response Discovery)
* Клиент при подключении к DataChannel отправляет широковещательный `WrtcMessage::Discover`. Повторяет каждые 2 секунды до получения ответа.
* Сервер, получив `WrtcMessage::Discover`, извлекает идентификатор отправителя из поля `from` и отвечает строго по этому адресу (`to`):
  `WrtcMessage::Beacon` с Ed25519 подписью `(client_nonce + server_id)`, выполненной с помощью имеющегося `config.crypto.server_signing_key`.
* Клиент проверяет подпись открытым ключом `server_pub_key`. При успехе `server_id` фиксируется как целевой шлюз.

### 4.3. Сквозное рукопожатие ASTP и туннелирование
1. Клиент инициирует 4-фазный ASTP Handshake (X25519 DH + ChaCha20Poly1305), передавая Protobuf-пакеты в `WrtcMessage::Astp { data: base64 }`.
2. Сервер валидирует фингерпринт клиента и аллоцирует IPv4 из `IpPool`.
3. **Маршрутизация пакетов:**
   * Входящие из DataChannel клиенты маршрутизируются в TUN.
   * Ответные пакеты из TUN упаковываются в `WrtcMessage::Astp` и отправляются адресно в `to: client_endpoint_id`.

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
   * Связывает **новый** `endpoint_id` клиента со старым выделенным IP (`10.0.0.X`).
   * Сессия восстанавливается мгновенно без сброса пользовательских TCP-соединений.

---

## 6. Формат конфигурации узлов

### В `client.toml`:
```toml
[[servers]]
name = "Ktalk Node [WRTC]"
dsn = "wrtc://ycs3y048.ktalk.ru/oaj4kr56yubb"
timeout_secs = 15
server_pub_key = "<BASE64_ED25519_PUBLIC_KEY>"
wrtc_media_keepalive_interval_ms = 20 # Эмуляция Opus тишины (мс)
wrtc_ping_interval_secs = 30          # Двойной пинг WebSocket и XMPP (сек)
wrtc_fallback_jvb_ip = "89.169.16.6"  # Fallback IP медиасервера JVB
wrtc_fallback_jvb_port = 10002        # Fallback UDP порт JVB
```

### В `server.toml`:
```toml
[server]
wrtc_room_url = "https://ycs3y048.ktalk.ru/oaj4kr56yubb"
wrtc_media_keepalive_interval_ms = 20 # Эмуляция Opus тишины (мс)
wrtc_ping_interval_secs = 30          # Двойной пинг WebSocket и XMPP (сек)
wrtc_fallback_jvb_ip = "89.169.16.6"  # Fallback IP медиасервера JVB
wrtc_fallback_jvb_port = 10002        # Fallback UDP порт JVB

[crypto]
server_signing_key = "<BASE64_ED25519_PRIVATE_KEY>"
```

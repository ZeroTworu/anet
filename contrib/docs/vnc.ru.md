# Архитектура и спецификация транспорта `vnc` (ASTP over RFB 3.8 Clipboard Channel)

Документация актуальна для ветки `master`.

---

## 1. Введение и архитектурная концепция

### 1.1. Назначение
Транспорт `vnc` (`dsn = "vnc://host:port"`) маскирует VPN-туннель ANet под сессию удалённого рабочего стола **VNC (протокол RFB 003.008, RFC 6143)** поверх TCP (порт `5900` по умолчанию).

Вместо передачи видеокадров фреймбуфера транспорт после выполнения абсолютно валидного рукопожатия RFB 3.8 (`SecurityType = None`, разрешение экрана `1024x768`, 32 bpp, имя рабочего стола `"Xvnc"`) инкапсулирует все пакеты рукопожатия ASTP и зашифрованные сетевые пакеты в стандартные сообщения синхронизации буфера обмена (Clipboard / CutText):
* **От клиента к серверу (`Client -> Server`):** сообщение **`ClientCutText` (тип `6` / `0x06`)**.
* **От сервера к клиенту (`Server -> Client`):** сообщение **`ServerCutText` (тип `3` / `0x03`)**.

Для внешних анализаторов трафика (DPI / ТСПУ / межсетевых экранов) соединение в начале сессии выглядит как подключение VNC-клиента к Xvnc-серверу, за которым следует двусторонний обмен бинарными буферами обмена по протоколу RFB 3.8.

### 1.2. Ключевые файлы реализации
* **Кодек и валидатор RFB 3.8 (`CutText`):** `anet-common/src/vnc.rs` (`RFB_VERSION`, `SECURITY_TYPE_NONE`, `CLIENT_CUT_TEXT`, `SERVER_CUT_TEXT`, `encode_cut_text`, `write_cut_text`, `read_cut_text`).
* **Клиент:** `anet-client-core/src/transport/vnc.rs` (`VncTransport`, `VncAuthChannel`, `emulate_rfb_client_handshake`, `send_to_server`, `receive_from_server`).
* **Сервер:** `anet-server/src/servers/vnc.rs` (`run_vnc_server`, `emulate_rfb_server_handshake`, `handle_vnc_session`, `receive_from_client`, `send_to_client`).

---

## 2. Схема рукопожатия RFB 3.8 и ASTP

```text
+-----------------------------------+                         +---------------------------------------+
|            anet-client            |                         |              anet-server              |
|           (VncTransport)          |                         |            (run_vnc_server)           |
+-----------------------------------+                         +---------------------------------------+
                  |                                                               |
                  | 1. TCP Connect (timeout = 15s, TCP_NODELAY = true)            |
                  |-------------------------------------------------------------->|
                  |                                                               |
                  | 2. ProtocolVersion: "RFB 003.008\n" (12 байт)                 |
                  |<--------------------------------------------------------------|
                  | 3. ProtocolVersion: "RFB 003.008\n" (12 байт)                 |
                  |-------------------------------------------------------------->|
                  |                                                               |
                  | 4. SecurityTypes: [count=1, type=1 (None)] (2 байта)          |
                  |<--------------------------------------------------------------|
                  | 5. Selected SecurityType: 1 (None) (1 байт)                   |
                  |-------------------------------------------------------------->|
                  |                                                               |
                  | 6. SecurityResult: 0x00000000 (OK, 4 байта BE)                |
                  |<--------------------------------------------------------------|
                  | 7. ClientInit: shared_flag = 1 (1 байт)                       |
                  |-------------------------------------------------------------->|
                  |                                                               |
                  | 8. ServerInit (28 байт):                                      |
                  |    width=1024, height=768, 32bpp, depth=24, true-colour,      |
                  |    red/green/blue max=255, shifts=16/8/0, name="Xvnc" (len=4) |
                  |<--------------------------------------------------------------|
                  |                                                               |
                  | 9. ASTP Handshake (authenticate_once via VncAuthChannel):     |
                  |    Client -> Server: ClientCutText (type=6) + write_fragmented|
                  |    Server -> Client: ServerCutText (type=3) (timeout = 30s)   |
                  |<=============================================================>|
                  |                                                               |
                  | 10. Data Plane (Coalesced up to 16 KB per TCP write):         |
                  |     Client -> Server: [ClientCutText(6)][ASTP Envelope]       |
                  |     Server -> Client: [ServerCutText(3)][ASTP Envelope]       |
                  |<=============================================================>|
```

---

## 3. Спецификация протокола и формат кадров (Wire Format)

### 3.1. Заголовок `ServerInit` (28 байт, отправляется сервером в шаге 8)
Сервер эмулирует стандартный ответ X11 VNC-сервера (`RFB_SERVER_INIT` в `anet-server/src/servers/vnc.rs`):

```text
+-------------------+-------------------+-------------------------------------------+
| Поле              | Размер (байт)     | Значение в ANet                           |
+-------------------+-------------------+-------------------------------------------+
| framebuffer-width | 2 (u16 BE)        | 0x0400 (1024 px)                          |
| framebuffer-height| 2 (u16 BE)        | 0x0300 (768 px)                           |
| bits-per-pixel    | 1 (u8)            | 0x20 (32 bpp)                             |
| depth             | 1 (u8)            | 0x18 (24-bit color)                       |
| big-endian-flag   | 1 (u8)            | 0x00 (Little-Endian)                      |
| true-colour-flag  | 1 (u8)            | 0x01 (True Colour)                        |
| red-max           | 2 (u16 BE)        | 0x00FF (255)                              |
| green-max         | 2 (u16 BE)        | 0x00FF (255)                              |
| blue-max          | 2 (u16 BE)        | 0x00FF (255)                              |
| red-shift         | 1 (u8)            | 0x10 (16)                                 |
| green-shift       | 1 (u8)            | 0x08 (8)                                  |
| blue-shift        | 1 (u8)            | 0x00 (0)                                  |
| padding           | 3 (u8 x 3)        | [0x00, 0x00, 0x00]                        |
| name-length       | 4 (u32 BE)        | 0x00000004 (4 байта, макс. до 1024 на кл.)|
| name-string       | 4 (ASCII)         | "Xvnc"                                    |
+-------------------+-------------------+-------------------------------------------+
```

### 3.2. Формат фрейма `ClientCutText` / `ServerCutText` (`anet-common/src/vnc.rs`)
После завершения `ServerInit` каждый пакет (как во время ASTP-хендшейка, так и в режиме передачи данных) упаковывается функцией `encode_cut_text(message_type, payload)` с 8-байтным заголовком RFC 6143:

```text
+---------------------------------------------------------------------------------------------------+
|                                   TCP Stream (RFB 3.8 CutText Frame)                              |
+-------------------+-------------------+-------------------+---------------------------------------+
| Message Type (1 Б)| Padding (3 байта) | Length (4 байта)  | Payload (ASTP Handshake или Data)     |
| 0x06 (Client->Srv)| [0x00, 0x00, 0x00]| u32 Big-Endian    | [Nonce (12 Б)][ChaCha20 + Poly1305]   |
| 0x03 (Srv->Client)|                   | (до 4096 байт)    |                                       |
+-------------------+-------------------+-------------------+---------------------------------------+
| <----------------- 8 байт заголовок RFB ----------------> | <----- 38 + IP_Len + Padding байт --->|
```

### 3.3. Строгая валидация фреймов в `read_cut_text`
Функция `read_cut_text(reader, expected_type)` в `anet-common/src/vnc.rs` защищает парсер от рассинхронизации потока и атак на исчерпание памяти (OOM):
1. **Корректная обработка чистого `EOF`:** Сначала читается ровно 1 первый байт (`header[..1]`). Если TCP-соединение закрыто (`UnexpectedEof` на границе фрейма), возвращается `Ok(None)`. Если же `UnexpectedEof` возникает при дочитывании остальных 7 байт заголовка (`header[1..8]`) или тела пакета, возвращается ошибка `Err(UnexpectedEof)` (оборванный посередине кадр не маскируется под штатное закрытие).
2. **Проверка направления (`expected_type`):** Клиент принимает исключительно `SERVER_CUT_TEXT (3)`, сервер — исключительно `CLIENT_CUT_TEXT (6)`. Любой другой байт типа немедленно вызывает `InvalidData`.
3. **Проверка нулевого паддинга:** Байты `header[1..4]` обязаны быть равны `[0, 0, 0]`, иначе возвращается `InvalidData`.
4. **Защита от OOM до аллокации буфера:** Поле длины `payload_len` (`u32 BE`) проверяется на `payload_len <= MAX_CUT_TEXT_PAYLOAD` (`MAX_PACKET_SIZE * 2 = 4096` байт) **до** вызова `vec![0; payload_len]`.

---

## 4. Особенности Data Plane, коалесценции и Stealth-режима

### 4.1. TCP-фрагментация рукопожатия ASTP (`VncAuthChannel`)
В `VncAuthChannel::send` (`anet-client-core/src/transport/vnc.rs`) пакеты Phase I и Phase III сначала упаковываются в `ClientCutText` (`encode_cut_text(CLIENT_CUT_TEXT, &data)`), а затем записываются в TCP-сокет с `TCP_NODELAY = true` через **`write_fragmented(&mut *stream, &frame, fragmentation)`**.
Если в `[stealth]` включён `frag_enabled = true`, первый `ClientCutText`-фрейм разрезается в случайных точках на несколько TCP-сегментов с наносекундным джиттером между ними, сохраняя полную совместимость с потоковым парсером `read_cut_text` на сервере.

### 4.2. Коалесценция CutText-фреймов (`CRYPTO_COALESCE_BUDGET_BYTES = 16 КБ`)
Как в `send_to_server` (клиент), так и в `send_to_client` (сервер) реализован высокопроизводительный цикл пакетной отправки:
1. Каждый IP-пакет шифруется через `anet_common::transport::wrap_packet` с добавлением выравнивающего паддинга (`padding_step`, но не более `PADDING_MTU = 1450` байт).
2. Зашифрованный конверт оборачивается в `encode_cut_text(CLIENT_CUT_TEXT / SERVER_CUT_TEXT, &encrypted)` и дописывается в общий буфер `batch_buf: BytesMut`.
3. В неблокирующем цикле `try_recv()` в этот же `batch_buf` добираются следующие готовые пакеты из очереди до достижения бюджета **`CRYPTO_COALESCE_BUDGET_BYTES = 16 384` байт (16 КиБ)**.
4. Весь буфер из нескольких подряд идущих `CutText`-фреймов отправляется в `TcpStream` за один системный вызов `writer.write_all(&batch_buf).await` без принудительного `flush()`.

### 4.3. Zero-Copy дешифрация и Backpressure
* **На приёме (`receive_from_server` и `receive_from_client`):** Полученный `Bytes` из `read_cut_text` передаётся в `unwrap_packet_bytes_in_place(&cipher, encrypted)`, который расшифровывает `ChaCha20-Poly1305` прямо поверх выделенного буфера без повторной аллокации.
* **На сервере (`receive_from_client`):** Запись в канал TUN-интерфейса выполняется через неблокирующий `tun_tx.try_send(packet)`. При переполнении очереди TUN пакет отбрасывается (`[VNC] TUN queue full, dropping uplink packet`), исключая взаимную блокировку (Deadlock) TCP-чтения и записи.

---

## 5. Конфигурация

### 5.1. Настройка клиента (`client.toml`)
```toml
[[servers]]
name = "VNC Node"
dsn = "vnc://vpn.example.com:5900"  # Если порт не указан (vnc://host), по умолчанию используется порт 5900
timeout_secs = 15
server_pub_key = "<BASE64_ED25519_PUBLIC_KEY>"

[stealth]
padding_step = 64                   # Выравнивание размера зашифрованного пакета внутри CutText
min_jitter_ns = 0
max_jitter_ns = 0
frag_enabled = true                 # TCP-фрагментация пакетов рукопожатия ClientCutText
frag_min_chunks = 2
frag_max_chunks = 3
```

### 5.2. Настройка сервера (`server.toml`)
```toml
[server]
vnc_bind_to = "0.0.0.0:5900"        # Пустая строка "" отключает VNC-сервер

[crypto]
server_signing_key = "<BASE64_ED25519_PRIVATE_KEY>"

[stealth]
padding_step = 64
min_jitter_ns = 0
max_jitter_ns = 0
```

---

## 6. Верификация через `tcpdump` / Wireshark

Для проверки маскировки под протокол RFB 3.8 на порту `5900`:
```bash
sudo tcpdump -ni any "tcp port 5900" -c 30 -A
```
В начале TCP-потока будут видны стандартные ASCII-маркеры `RFB 003.008` и имя десктопа `Xvnc`, а последующие пакеты распознаются диссектором Wireshark (`VNC`) как сообщения `ClientCutText` и `ServerCutText`.

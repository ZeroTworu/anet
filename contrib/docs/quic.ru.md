# Архитектура и спецификация транспорта `quic` (ASTP over Obfuscated QUIC)

Документация актуальна для ветки `master`.

---

## 1. Введение и архитектурная концепция

### 1.1. Назначение
Транспорт `quic` (`dsn = "quic://host:port"`) — базовый высокопроизводительный UDP-транспорт ANet, сочетающий современный стек **QUIC (`quinn` + `rustls`)** с полным криптографическим сокрытием заголовков QUIC на уровне UDP-сокета (**Crypted QUIC / ASTP UDP Envelope**).

В отличие от стандартного RFC 9000 QUIC, где пакеты начинаются с узнаваемых флагов (`Long Header` с открытым `ClientHello` SNI/ALPN и версией `0x00000001`, либо `Short Header` с `Connection ID`), в ANet `quinn::Endpoint` работает поверх виртуального сокета (`AsyncUdpSocket` trait):
* На стороне клиента: `AnetUdpSocket` (`anet-client-core/src/socket.rs`).
* На стороне сервера: `MultiKeyAnetUdpSocket` (`anet-server/src/multikey_udp_socket.rs`).

Каждая UDP-датаграмма, выходящая из `quinn`, дополнительно упаковывается в конверт **ASTP** (ChaCha20-Poly1305) с выравниванием длины (`padding_step`). Для внешнего наблюдателя и систем DPI/ТСПУ на проводе присутствуют исключительно случайные UDP-датаграммы без сигнатур QUIC, TLS 1.3 или криптографических заголовков.

### 1.2. Ключевые особенности реализации
1. **Единый UDP-порт для Handshake и Data Plane:** Сервер слушает один UDP-сокет (`server.quic_bind_to`, по умолчанию `0.0.0.0:8443`). Демультиплексор в `MultiKeyAnetUdpSocket::poll_recv` за $O(1)$ отличает трафик активных QUIC-сессий по 4-байтному `nonce_prefix` от пакетов первичного рукопожатия ASTP (Phase I / Phase III).
2. **Поддержка UDP-фрагментации хендшейка (`DatagramReassembler`):** Первые пакеты рукопожатия (до появления сессионного ключа) могут дробиться клиентом на $N$ независимых UDP-фрагментов со случайными точками разреза и наносекундным джиттером (`[stealth] frag_enabled = true`) и собираться на сервере даже при перестановке датаграмм в сети.
3. **Zero-Copy дешифрация на месте (`unwrap_packet_in_place`):** Приём пакетов в `AnetUdpSocket` и `MultiKeyAnetUdpSocket` выполняется в стековом буфере без промежуточных аллокаций кучи, после чего чистый QUIC-пакет передаётся directamente в слайс `IoSliceMut` движка `quinn`.
4. **Адаптивный расчёт окон BDP и BBR/Cubic:** Модуль `anet-common/src/quic_settings.rs` автоматически вычисляет окна управления потоком (`receive_window`, `stream_receive_window`, `send_window`) по формуле $\text{BDP} \times 2.5$ с поддержкой алгоритмов контроля перегрузки **BBR** (по умолчанию) и **Cubic**.
5. **Бесшовная миграция адреса клиента (NAT Rebinding):** При смене внешнего IP/порта клиента (переход Wi-Fi $\leftrightarrow$ LTE или протухание NAT-таблицы) сервер находит сессию по `nonce_prefix`, вызывает `registry.update_client_addr(&client_info, remote_addr)` и прозрачно передаёт новый адрес в `quinn::RecvMeta`.

---

## 2. Схема установки соединения и мультиплексирования сокета

```text
+-----------------------------------+                         +---------------------------------------+
|            anet-client            |                         |              anet-server              |
|        (QuicTransport / UDP)      |                         |  (MultiKeyAnetUdpSocket + Quinn Ep)   |
+-----------------------------------+                         +---------------------------------------+
                  |                                                               |
                  | 1. Bind UdpSocket (0.0.0.0:0)                                 |
                  |    Wrap in UdpAuthChannel                                     |
                  |                                                               |
                  | 2. ASTP Phase I: DhClientExchange                             |
                  |    (Obfuscated with HandshakeKey = SHA256(ServerPubKey))      |
                  |    Optional UDP Fragmentation: [idx: u8][total: u8][chunk...] |
                  |-------------------------------------------------------------->|
                  |                                                               | 3. DatagramReassembler::feed()
                  |                                                               |    Verify Ed25519 signature,
                  | 4. ASTP Phase II: DhServerExchange                            |    derive X25519 shared_key,
                  |    (Server Ephemeral X25519 PubKey + Ed25519 Signature)       |    store TempDHInfo
                  |<--------------------------------------------------------------|
                  |                                                               |
                  | 5. ASTP Phase III: EncryptedAuthRequest                       |
                  |    (Double envelope: HandshakeCipher(SessionCipher(AuthReq))) |
                  |-------------------------------------------------------------->|
                  |                                                               | 6. AuthProvider::authenticate()
                  |                                                               |    Allocate VPN IP & 4B nonce_prefix
                  | 7. ASTP Phase IV: EncryptedAuthResponse                       |    Register in ClientRegistry
                  |    (ip, netmask, gateway, mtu, nonce_prefix, quic_cert, SEID) |
                  |<--------------------------------------------------------------|
                  |                                                               |
                  | 8. Wrap same UdpSocket into AnetUdpSocket                     |
                  |    (cipher = ChaCha20Poly1305(shared_key), nonce_prefix)      |
                  |                                                               |
                  | 9. Quinn Endpoint::connect(server_addr, SNI="alco")           |
                  |    TLS 1.3 pinned to dynamically received auth_response.cert  |
                  |<=============================================================>| 10. MultiKeyAnetUdpSocket matches
                  |                                                               |     raw_packet[0..4] == nonce_prefix,
                  | 11. connection.open_bi() -> QuicDuplexStream                  |     unwraps in-place & feeds Quinn
                  |<=============================================================>|
                  |     [u16 BE length][IPv4/IPv6 Packet] (Coalesced up to 64 KB) |
```

---

## 3. Структура пакетов на уровне сети (Wire Format)

### 3.1. Фрагментированный UDP-хендшейк (Phase I и Phase III)
В фазе аутентификации (`UdpAuthChannel::send` $\to$ `send_fragmented_datagrams` в `anet-common/src/handshake_fragmentation.rs`) каждое сообщение ASTP снабжается 2-байтным заголовком фрагментации:

```text
+-----------------------------------------------------------------------+
| L4: UDP Datagram (Client -> Server)                                   |
+-------------------+-------------------+-------------------------------+
| Frag Index (1 Б)  | Frag Total (1 Б)  | Срез пакета ASTP Handshake    |
| u8 (0 .. total-1) | u8 (1 .. N)       | [Nonce (12 Б)][Ciphertext+Tag]|
+-------------------+-------------------+-------------------------------+
```

* Если `frag_enabled = false`, отправляется одна датаграмма с заголовком `[0x00, 0x01]`.
* Если `frag_enabled = true`, пакет режется в случайных точках (`random_split_points` через `OsRng` без выравнивания по кратным границам) на `frag_min_chunks..=frag_max_chunks` частей с задержкой `min_jitter_ns..=max_jitter_ns` между отправками.
* На сервере `MultiKeyAnetUdpSocket` хранит `DashMap<SocketAddr, (Instant, DatagramReassembler)>` с таймаутом самоочистки `REASSEMBLY_TIMEOUT = 5s`. Как только все части собраны (`parts.len() == total`) и суммарная длина $\ge \text{MIN\_HANDSHAKE\_LEN}$ (`78` байт), собранный буфер отправляется в асинхронный воркер `serve_udp_auth_layer`.
* Ответы сервера (Phase II и Phase IV) отправляются одиночными UDP-датаграммами напрямую через `socket.send_to(&resp, remote_addr)`.

### 3.2. Конверт данных (Data Plane — `AnetUdpSocket` $\leftrightarrow$ `MultiKeyAnetUdpSocket`)
После завершения Phase IV все пакеты протокола QUIC упаковываются функцией `anet_common::transport::wrap_packet_slice`:

```text
+---------------------------------------------------------------------------------------------------+
|                                        L4: UDP Datagram                                           |
+-----------------------------------+-----------------------------------------------+---------------+
|            Nonce (12 Б)           |         Зашифрованный блок (ChaCha20)         | Poly1305 Tag  |
+----------------+------------------+---------------+---------------+---------------+---------------+
| Nonce Prefix   | Sequence         | Sequence      | QUIC Len      | QUIC Payload  | Zero Padding  |
| 4 Б (от серв.) | 8 Б (u64 BE)     | 8 Б (u64 BE)  | 2 Б (u16 BE)  | (N байт)      | (0..P байт)   |
+----------------+------------------+---------------+---------------+---------------+---------------+
| <--------- Открытый ------------> | <------------- Зашифровано ChaCha20 --------> | <-- 16 байт ->|
```

* **Суммарный оверхед конверта (`TRANSPORT_ENVELOPE_OVERHEAD`):**
  $$\text{12 (Nonce)} + \text{8 (Seq)} + \text{2 (Payload Len)} + \text{16 (Poly1305 Tag)} = 38\text{ байт}$$
* **Идентификация сессии на сервере:** Первые 4 байта датаграммы (`nonce[0..4]`) равны уникальному `nonce_prefix`, выданному клиенту в `AuthResponse`. Сервер за $O(1)$ извлекает `ClientTransportInfo` через `registry.get_by_prefix(&nonce_prefix)`, проверяет подлинность тега Poly1305 в `unwrap_packet_in_place` и отрезает выравнивающий паддинг по полю `QUIC Len (u16 BE)`.
* **Защита от превышения MTU при паддинге:** Выравнивание размера датаграммы до шага `stealth.padding_step` выполняется только если итоговый размер не превышает `PADDING_MTU = 1450` байт:
  ```rust
  let total_len = transmit.contents.len() + TRANSPORT_ENVELOPE_OVERHEAD;
  let padding = calculate_padding_needed(total_len, self.stealth_config.padding_step);
  let safe_padding = if total_len + (padding as usize) > PADDING_MTU { 0 } else { padding };
  ```

### 3.3. Фрейминг IP-пакетов внутри QUIC Bi-Stream (`stream_framing.rs`)
После установки QUIC-соединения клиент открывает один долгоживущий двунаправленный поток (`connection.open_bi()`), внутри которого передаются L3 IP-пакеты с 2-байтным префиксом длины:

```text
+------------------------+----------------------------------------------+
| Length Prefix (2 байта)| Полезная нагрузка (Сырой IPv4/IPv6 пакет)    |
| u16 Big-Endian         | от 20 до MAX_PACKET_SIZE (2048) байт         |
+------------------------+----------------------------------------------+
```

* Фреймы с `len == 0` безопасно пропускаются парсером `read_next_packet` без разрыва соединения (защита от keep-alive пустышек).
* Фреймы с `len > MAX_PACKET_SIZE (2048)` немедленно прерывают поток с ошибкой `InvalidData`.

---

## 4. Тонкая настройка QUIC, BDP и MTU (`quic_settings.rs`)

### 4.1. Автоматический расчёт окон потока по BDP (Bandwidth-Delay Product)
Поскольку весь туннельный трафик мультиплексируется в один двунаправленный QUIC-стрим, окно уровня стрима (`stream_receive_window`) по умолчанию приравнивается к окну всего соединения (`receive_window`), чтобы не ограничивать скорость скачивания:

$$\text{BDP} = \left(\text{Mbps} \times 125\,000\right) \times \frac{\text{expected\_rtt\_ms}}{1000}$$

$$\text{Window} = \max\left(\lfloor \text{BDP} \times 2.5 \rfloor,\; 1\,048\,576\text{ байт}\right)$$

* При значениях по умолчанию (`bandwidth_down_mbps = 200`, `bandwidth_up_mbps = 100`, `expected_rtt_ms = 60`):
  * `receive_window` = `stream_receive_window` = `3 750 000` байт (~3.57 МиБ).
  * `send_window` = `1 875 000` байт (~1.78 МиБ).

### 4.2. Отключение GSO (Generic Segmentation Offload)
В `build_transport_config()` принудительно вызывается:
```rust
config.enable_segmentation_offload(false);
```
**Причина:** Каждый UDP-пакет шифруется в `AnetUdpSocket::try_send` со своим уникальным `sequence` (nonce) и тегом Poly1305. Если бы `quinn` склеивал несколько QUIC-пакетов в один GSO супер-сегмент, криптографический адаптер зашифровал бы их как единую датаграмму, нарушив границы пакетов при расшифровке.

### 4.3. Согласование MTU и PMTUD
Чтобы зашифрованный конверт (`+38` байт) гарантированно помещался в `PADDING_MTU = 1450` без IP-фрагментации во внешней сети:
* Верхний потолок для QUIC (`envelope_limit`) рассчитывается как:
  $$\text{envelope\_limit} = 1450 - 38 = 1412\text{ байт}$$
* `initial_mtu = mtu.min(1412).max(1200)`.
* Верхняя граница Path MTU Discovery (`MtuDiscoveryConfig::upper_bound`) ограничивается `cfg.max_mtu.min(1412).max(initial_mtu)`.

### 4.4. Защита от вымывания NAT на клиенте
В `anet-client-core/src/transport/quic.rs` клиент принудительно корректирует таймауты перед сборкой `TransportConfig`:
* `keep_alive_interval_seconds` зажимается сверху пределом **$\le 10$ секунд** (по умолчанию **7 секунд**), чтобы NAT-таблицы домашних роутеров и мобильных операторов (CGNAT) не закрывали UDP-трансляцию при простое.
* `idle_timeout_seconds` гарантированно устанавливается **$\ge 60$ секунд**, чтобы кратковременный сетевой джиттер или потеря 1–2 пингов не приводили к обрыву сессии.

---

## 5. Коалесценция пакетов, джиттер и защита от Bufferbloat

### 5.1. Пакетная запись в стрим (`COALESCE_BUDGET_BYTES = 64 КБ`)
Как на клиенте (`client.rs`), так и на сервере (`bridge_with_jitter` в `anet-common/src/jitter.rs`):
* При отсутствии искусственного джиттера (`max_jitter_ns <= min_jitter_ns`) воркер отправки вычитывает первый пакет из канала `rx.recv().await`, а затем в неблокирующем цикле `rx.try_recv()` добирает все ожидающие в очереди IP-пакеты в единый буфер `BytesMut` вплоть до бюджета **`COALESCE_BUDGET_BYTES = 65 536` байт** через `frame_packet_into(&mut buf, &packet)`.
* Весь накопленный батч записывается в `SendStream` одним вызовом `stream.write_all(&buf).await` без принудительного `flush()`, позволяя `quinn` максимально плотно упаковывать QUIC STREAM-фреймы в UDP-датаграммы.
* Если джиттер включён (`max_jitter_ns > min_jitter_ns`), каждый пакет ставится в очередь задержки `FuturesUnordered` (до `MAX_PENDING_JITTER_PACKETS = 256` пакетов в полёте) на случайное время $\text{delay} \in [\text{min\_jitter\_ns}, \text{max\_jitter\_ns}]$.

### 5.2. Неблокирующий Backpressure на сервере (`servers/quic.rs`)
В задаче чтения потока от клиента (`reader_task` в `anet-server/src/servers/quic.rs`) запись в очередь TUN-интерфейса выполняется через **`t_tx.try_send(pkt)`**:
* Если очередь `client_pkt_tx` (`CHANNEL_BUFFER_SIZE = 4096`) заполнена, сервер **отбрасывает** пакет с предупреждением `[QUIC] TUN queue full, dropping uplink packet`, не приостанавливая чтение из QUIC-стрима.
* Это предотвращает раздувание буферов (Bufferbloat) и позволяет алгоритму BBR внутри туннеля вовремя отреагировать на потерю пакета.

---

## 6. Конфигурация

### 6.1. Настройка клиента (`client.toml`)
```toml
[[servers]]
name = "Frankfurt QUIC"
dsn = "quic://vpn.example.com:8443" # Если порт не указан (quic://host), по умолчанию используется 443
timeout_secs = 10
server_pub_key = "<BASE64_ED25519_PUBLIC_KEY>" # Опциональное переопределение глобального ключа

[quic_transport]
algorithm = "bbr"                   # "bbr" (по умолчанию) или "cubic"
expected_rtt_ms = 60
bandwidth_down_mbps = 200
bandwidth_up_mbps = 100
max_mtu = 1500                      # Автоматически зажимается до 1412 байт под крипто-конверт
keep_alive_interval_seconds = 7     # На клиенте ограничивается <= 10 сек
idle_timeout_seconds = 60           # На клиенте ограничивается >= 60 сек

[stealth]
padding_step = 64                   # Выравнивание размера UDP-датаграмм (до 1450 байт)
min_jitter_ns = 0
max_jitter_ns = 0
frag_enabled = true                 # Фрагментация UDP-датаграмм хендшейка (Phase I / Phase III)
frag_min_chunks = 2
frag_max_chunks = 4
```

### 6.2. Настройка сервера (`server.toml`)
```toml
[server]
quic_bind_to = "0.0.0.0:8443"       # Пустая строка "" отключает QUIC-сервер

[network]
mtu = 1400

[crypto]
server_signing_key = "<BASE64_ED25519_PRIVATE_KEY>"
quic_cert = """-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----"""
quic_key = """-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----"""

[quic_transport]
algorithm = "bbr"
expected_rtt_ms = 60
bandwidth_down_mbps = 200
bandwidth_up_mbps = 100
max_mtu = 1500
keep_alive_interval_seconds = 20
idle_timeout_seconds = 3600

[stealth]
padding_step = 64
min_jitter_ns = 0
max_jitter_ns = 0
```

> **Примечание о сертификате `quic_cert`:** Клиент **не использует** системные корневые УЦ при проверке TLS внутри QUIC. Сервер передаёт свой PEM-сертификат `quic_cert` внутри зашифрованного и аутентифицированного ответа `AuthResponse` (Phase IV), а клиент добавляет ровно этот сертификат в изолированный `rustls::RootCertStore` и подключается с фиксированным SNI `"alco"`.

---

## 7. Памятка для будущей сессии: анализ двустороннего шейпинга ТСПУ (Uplink + Downlink) и архитектура `UDP Finalmask`

> **Статус:** Зафиксировано как архитектурное ТЗ для следующей итерации (в текущей сессии код `QUIC`-транспорта не модифицируется).

### 7.1. Причина просадки скорости как на выгрузку (Uplink), так и на скачивание (Downlink)
По результатам замеров на провайдерах (в т.ч. Уфанет) наблюдается симметричное срабатывание полисера ТСПУ на транспорте `QUIC` (`~64 Mbps` Downlink / `~65 Mbps` Uplink с ростом подгрузочного RTT до `313 ms`), тогда как транспорт `WRTC VIDEO` на том же канале выдаёт полную скорость (`~83.5 Mbps` / `~80.7 Mbps`, RTT `93 ms`).

Причина кроется в структуре заголовка датаграммы `AnetUdpSocket` (`anet-client-core/src/socket.rs`) и `MultiKeyAnetUdpSocket` (`anet-server/src/multikey_udp_socket.rs`):
1. **Открытый статический паттерн первых 12 байт (`Nonce`) в обе стороны:**
   * Каждая датаграмма начинается с `nonce[0..12] = [nonce_prefix(4B), 0x00, 0x00, 0x00, 0x00, seq(u32 BE)]`.
   * Первые **4 байта** (`nonce_prefix`) абсолютно одинаковы в каждом пакете сессии **как от клиента к серверу, так и от сервера к клиенту**.
   * Байты **`4..8`** всегда равны нулям (`00 00 00 00`), а байты **`8..12`** — монотонно растущий счётчик `00 00 00 01`, `00 00 00 02`...
2. **Stateful-классификация 5-tuple потока на ТСПУ:**
   * Классификатор ТСПУ отслеживает UDP-поток в обоих направлениях по 5-tuple `(client_ip, client_port, server_ip, server_port, udp)`.
   * Неизвестный высокоинтенсивный UDP-протокол без заголовков STUN/RTP/DTLS/QUIC v1 и с константными 8 байтами в начале каждого пакета попадает под эвристику *«Unknown Encrypted UDP Tunnel / Custom WireGuard-like»*.
   * Как только поток помечен классификатором, аппаратный policer ТСПУ режет полосу (применяет искусственный packet drop / token bucket) **на весь 5-tuple в обе стороны** (и на `Uplink`, и на `Downlink`), а также может независимо детектировать `Downlink` по тем же 8 константным байтам `[nonce_prefix(4B), 0, 0, 0, 0]` в ответах сервера.

### 7.2. Архитектура двусторонней маскировки с настройкой только на клиенте (Server Auto-Detect)
Чтобы устранить деградацию и на `Uplink`, и на `Downlink`, не требуя синхронной правки `server.toml` при переключении режима на клиенте, в следующей сессии планируется внедрить механизм **Client-Configured / Server-Auto-Detected UDP Finalmask**:

1. **Конфигурация исключительно на клиенте (`client.toml` / `dsn`):**
   * В `[quic_transport]` (или `[stealth]`) и в query-параметрах `dsn` (`quic://host:port?mask=rtp_vp8`) добавляется параметр:
     `udp_mask = "none" | "xor" | "rtp_vp8" | "stun"`
2. **Режимы маскировки:**
   * **`xor` (Header Obfuscation):**
     * Вместо открытого `[nonce_prefix(4B), 0, 0, 0, 0, seq(4B)]` первые 12 байт датаграммы XOR-ятся с детерминированной маской `mask_12b = BLAKE3/SHA256(shared_key || "anet-udp-nonce-mask")[0..12]` (или `nonce_prefix` шифруется одноразовым PRF от `seq` / последних байт Poly1305 tag). Для $O(1)$ поиска сессии на сервере `ClientRegistry` индексирует сессию сразу по обоим ключам: `raw_prefix` и `masked_prefix = nonce_prefix ^ mask[0..4]`.
   * **`rtp_vp8` (Маскировка под WebRTC SRTP/RTP VP8, по аналогии с `wrtc.ru.md` разд. 8.4):**
     * Перед конвертом ASTP добавляется валидный 12-байтный заголовок RTP (`[0x80, 0x60, seq(u16 BE), timestamp(u32 BE), ssrc(u32 BE)]`, где `ssrc = u32::from_be_bytes(nonce_prefix)`), а первые байты `Nonce` сжимаются/маскируются под VP8 Payload Descriptor (`0x90 0x80 ...`).
     * Для ТСПУ поток в обе стороны выглядит как стандартный медиапоток WebRTC RTP VP8 (`PT=96`), который пропускается по белому списку ВКС без включения полисера.
   * **`stun` (Маскировка под STUN Data Indication):**
     * Оборачивает датаграмму в 20-байтный заголовок STUN с Magic Cookie `0x2112A442`.
3. **Автоматическое определение режима сервером (`MultiKeyAnetUdpSocket`):**
   * В структуру `ClientTransportInfo` на сервере добавляется атомарное поле `detected_udp_mask: AtomicU8`.
   * Когда сервер получает первый пакет от клиента в `MultiKeyAnetUdpSocket::poll_recv`:
     * Если `raw[0..2] == [0x80, 0x60]` (или `raw[0] & 0xC0 == 0x80` и `ssrc` на смещении `8..12` совпадает с `nonce_prefix` в `ClientRegistry`) $\to$ сервер автоматически помечает сессию как `UdpMask::RtpVp8`, снимает RTP-шапку на приёме и **автоматически оборачивает все исходящие Downlink-пакеты этой сессии в такой же RTP VP8 заголовок**.
     * Если `raw[4..8] == [0x21, 0x12, 0xA4, 0x42]` $\to$ сервер переключает сессию в `UdpMask::Stun` для приёма и отправки.
     * Если `raw[0..4]` совпал с `masked_prefix` $\to$ сервер переключает сессию в `UdpMask::Xor` для обоих направлений.
     * Если `raw[0..4]` совпал с открытым `nonce_prefix` $\to$ используется классический режим `UdpMask::None` (полная обратная совместимость со старыми клиентами).
   * Такой же авто-детект (по магическим байтам заголовка перед `DatagramReassembler::feed`) применяется и к пакетам рукопожатия Phase I–IV.


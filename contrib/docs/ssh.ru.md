# Архитектура и спецификация транспорта `ssh` (ASTP over SSHv2 Exec Channel)

Документация актуальна для ветки `master`.

---

## 1. Введение и архитектурная концепция

### 1.1. Назначение
Транспорт `ssh` (`dsn = "ssh://host:port"`) предназначен для туннелирования IP-трафика ANet внутри стандартного протокола **SSHv2 (RFC 4251–4254)** на базе асинхронной библиотеки **`russh`**.

Для внешних систем анализа трафика (DPI / ТСПУ / корпоративных межсетевых экранов) соединение выглядит как стандартная интерактивная или автоматизированная SSH-сессия администрирования сервера:
1. Открывается обычное TCP-соединение (по умолчанию порт `22` на клиенте при отсутствии порта в DSN, либо любой настроенный порт `server.ssh_bind_to`, например `822` или `22`).
2. Выполняется полноценный обмен версиями SSH-2.0, согласование алгоритмов (KEX) и проверка ключа хоста.
3. Клиент проходит SSH-аутентификацию (`none`) под заданным именем пользователя (`ssh_user`) и открывает сессионный канал (`channel_open_session`) с вызовом команды **`exec "anet-vpn"`**.
4. Внутри открытого SSH-канала поверх уже защищённого SSH-соединения выполняется стандартное криптографическое рукопожатие **ASTP** (Phase I–IV) с опциональной TCP-фрагментацией первого пакета и далее передаётся поток дополнительно зашифрованных пакетов (`ChaCha20-Poly1305` + `padding_step` + микробатчинг до `16 КБ`).

### 1.2. Ключевые файлы реализации
* **Клиент:** `anet-client-core/src/transport/ssh.rs` (`SshTransport`, `ClientHandler`).
* **Сервер:** `anet-server/src/servers/ssh.rs` (`run_ssh_server`, `AnetSshHandler`, `handle_ssh_vpn_session`).
* **Потоковый конвейер шифрования и батчинга:** `anet-common/src/jitter.rs` (`bridge_crypto_stream_with_jitter`, `receive_crypto_stream`), `anet-common/src/stream_framing.rs` (`frame_packet`, `frame_packet_into`, `read_next_packet`).
* **Фрагментация рукопожатия:** `anet-common/src/handshake_fragmentation.rs` (`write_fragmented`).

---

## 2. Жизненный цикл соединения и схема протокола

```text
+-----------------------------------+                         +---------------------------------------+
|            anet-client            |                         |              anet-server              |
|     (SshTransport / russh)        |                         |     (run_ssh_server / AnetSshHandler) |
+-----------------------------------+                         +---------------------------------------+
                  |                                                               |
                  | 1. TCP Connect (timeout = 15s, TCP_NODELAY = true)            |
                  |-------------------------------------------------------------->|
                  |                                                               |
                  | 2. SSH-2.0 Protocol Banner & KEX (russh)                      |
                  |<=============================================================>|
                  |                                                               |
                  | 3. SSH USERAUTH_REQUEST (method = "none", user = ssh_user)    |
                  |-------------------------------------------------------------->| 4. AnetSshHandler::auth_none()
                  |<--------------------------------------------------------------|    -> Auth::Accept
                  |                                                               |
                  | 5. SSH CHANNEL_OPEN ("session")                               |
                  |-------------------------------------------------------------->| 6. Store in pending_channels
                  |<--------------------------------------------------------------|    -> reply.accept()
                  |                                                               |
                  | 7. SSH CHANNEL_REQUEST (exec, command = "anet-vpn")           |
                  |-------------------------------------------------------------->| 8. Verify command == b"anet-vpn"
                  |<--------------------------------------------------------------|    (reject shell/other commands)
                  |                                                               |    -> channel_success + into_stream()
                  |                                                               |
                  | 9. ASTP Handshake (authenticate_once via StreamAuthChannel)   |
                  |    [u16 BE len][ASTP Phase I..IV] (with write_fragmented)     | 10. Server authenticate()
                  |<=============================================================>|     (timeout = 30s)
                  |                                                               |
                  | 11. Encrypted Data Plane (bridge_crypto_stream_with_jitter)   |
                  |     [u16 BE len][Nonce(12B) + ChaCha20(Seq+Len+IP+Pad) + Tag] |
                  |<=============================================================>|
```

### 2.1. Изоляция и безопасность SSH-обработчика на сервере (`AnetSshHandler`)
Сервер `anet-server` реализует минималистичный и защищённый обработчик `russh::server::Handler`:
* **Запрет интерактивного шелла:** Метод `shell_request` всегда возвращает `session.channel_failure(channel)`, не позволяя открыть терминал.
* **Строгий фильтр команд в `exec_request`:** Если запрошенная команда отлична от байтовой строки `b"anet-vpn"`, сервер удаляет канал из `pending_channels`, отправляет `channel_failure(channel_id)` и немедленно закрывает канал `session.close(channel_id)`.
* **Двойная криптографическая верификация:** Хотя `auth_none` на уровне SSH возвращает `Auth::Accept`, а клиентский `ClientHandler::check_server_key` принимает любой SSH-ключ хоста, доступ к VPN-сети невозможен без прохождения 4-фазного рукопожатия **ASTP** (с проверкой подписей Ed25519 обеих сторон и тайм-аутом `ASTP_AUTH_TIMEOUT = 30s`). Если клиент не завершает ASTP за 30 секунд, сессия принудительно разрывается.

### 2.2. Однократная попытка рукопожатия на потоке (`authenticate_once`)
В отличие от UDP/QUIC, где потеря датаграммы компенсируется повторными попытками (`authenticate`), для SSH используется `auth_handler.authenticate_once(&auth_channel)`:
* При отказе сервера или разрыве TCP/SSH-потока повторная отправка в тот же закрытый поток бессмысленна и лишь задерживает переключение на следующую ноду (failover).
* При включённом `[stealth] frag_enabled = true` метод `StreamAuthChannel::send` вызывает `write_fragmented(&mut *stream, &framed, frag)`, разбивая фрейм рукопожатия `[u16 len][ASTP payload]` на несколько отдельных записей `write_all + flush` со случайными границами и джиттером. Поскольку на TCP-сокете включён `set_nodelay(true)` (`TCP_NODELAY`), каждый кусок уходит в отдельном пакете SSH/TCP.

---

## 3. Структура пакетов внутри SSH-канала (Wire Format)

После вызова `channel.into_stream()` канал `russh` предоставляет стандартный байтовый поток `AsyncRead + AsyncWrite`.

### 3.1. Фаза рукопожатия ASTP (Phase I–IV)
Каждое сообщение рукопожатия обрамляется 2-байтным префиксом длины (`frame_packet` в `anet-common/src/stream_framing.rs`):

```text
+-------------------------------------------------------------------------------+
| Поток данных внутри SSH Channel (SSH_MSG_CHANNEL_DATA)                        |
+------------------------+------------------------------------------------------+
| Length Prefix (2 байта)| Пакет рукопожатия ASTP                               |
| u16 Big-Endian         | [Nonce (12 Б)][Ciphertext (Protobuf Message) + Tag]  |
+------------------------+------------------------------------------------------+
```

### 3.2. Фаза передачи данных (Data Plane)
В фазе передачи трафика оба конца (`SshTransport` на клиенте и `handle_ssh_vpn_session` на сервере) используют `bridge_crypto_stream_with_jitter` (отправка) и `receive_crypto_stream` (приём). Каждый IP-пакет индивидуально шифруется сессионным ключом ASTP (`ChaCha20-Poly1305`) с выравниванием и оборачивается в 2-байтный фрейм длины:

```text
+------------------------------------------------------------------------------------------------------------+
|                              Поток данных внутри SSH Channel (SSH_MSG_CHANNEL_DATA)                        |
+----------------+---------------------------------------------------------------------------+---------------+
| Frame Len (2 Б)|                     ASTP Transport Envelope (ChaCha20-Poly1305)           |               |
| u16 Big-Endian +---------------+---------------+---------------+---------------+-----------+ Poly1305 Tag  |
| (= 38+N+P)     | Nonce (12 Б)  | Sequence (8 Б)| IP Len (2 Б)  | IP Packet     | Padding   | (16 байт)     |
|                | [Prefix4|Seq8]| u64 BE        | u16 BE (= N)  | (N байт)      | (P байт)  |               |
+----------------+---------------+---------------+---------------+---------------+-----------+---------------+
```

* На приёмной стороне `receive_crypto_stream` вычитывает фрейм через `read_next_packet(&mut reader)` и расшифровывает его **на месте без копирования** через `unwrap_packet_bytes_in_place(&cipher, encrypted)`.

---

## 4. Управление буферами, окнами SSH и коалесценцией

### 4.1. Параметры окна канала `russh` и `CRYPTO_COALESCE_BUDGET_BYTES`
На клиенте и сервере конфигурация `russh` задаётся идентичными константами:
* `SSH_CHANNEL_WINDOW_SIZE = 4 * 1024 * 1024` (**4 МиБ**) — окно управления потоком SSH-канала, позволяющее прокачивать сотни мегабит/с на линках с высоким RTT без остановки на `SSH_MSG_CHANNEL_WINDOW_ADJUST`.
* `SSH_MAX_PACKET_SIZE = 32 * 1024` (**32 КиБ**) — максимальный размер одного SSH-пакета (`SSH_MSG_CHANNEL_DATA`).
* `nodelay = true` — отключение алгоритма Нейгла на уровне TCP и `russh`.

**Критическая деталь (`CRYPTO_COALESCE_BUDGET_BYTES = 16 КБ`):**
В функции `bridge_crypto_stream_with_jitter` (`anet-common/src/jitter.rs`) несколько исходящих IP-пакетов из очереди склеиваются в один буфер `BytesMut` перед вызовом `stream.write_all(&buf).await`. Бюджет коалесценции специально ограничен константой **`CRYPTO_COALESCE_BUDGET_BYTES = 16 * 1024` (16 КиБ)** (вместо 64 КиБ у чистого QUIC), чтобы:
1. Склеенный батч с учётом заголовков гарантированно помещался в `SSH_MAX_PACKET_SIZE (32 КиБ)` и не вызывал лишней фрагментации или паники перераспределения буфера `CryptoVec::resize` внутри `russh`.
2. Принудительный `stream.flush().await` после каждого `write_all` **удалён** — отправка происходит естественным образом по мере формирования пакетов `russh`, что снижает количество системных вызовов `sendto`/`write`.

### 4.2. Архитектура воркеров на клиенте и устранение `MutexVpnStream`
В `anet-client-core/src/transport/ssh.rs`:
1. Создаётся внутренний полнодуплексный мост `tokio::io::duplex(MAX_PACKET_SIZE * 10)` между ядром клиента (`client.rs`) и фоновой задачей SSH-транспорта.
2. Половина `client_stream` передаётся в `ConnectionResult::vpn_stream` **напрямую (`Box::new(client_stream)`) без обёртки `Arc<Mutex<...>>`**, что полностью исключает аллокации `Box::pin(lock())` на каждом `poll_read` / `poll_write`.
3. Внутри фоновой задачи работают 4 асинхронных воркера под управлением `tokio::select!`:
   * `tunnel_input`: читает фреймированные IP-пакеты из `tunnel_reader` и передаёт в `packet_tx`.
   * `outbound`: шифрует, выравнивает, коалесцирует (до 16 КБ) и пишет в `writer` SSH-канала (`bridge_crypto_stream_with_jitter`).
   * `inbound`: читает из `reader` SSH-канала, расшифровывает in-place и отправляет в `network_tx` (`receive_crypto_stream`).
   * `tunnel_output`: читает расшифрованные пакеты из `network_rx` и пишет во внутренний `tunnel_writer`.
4. **Безопасное завершение `tokio::select!`:** Как только любой из 4 воркеров завершается (например, `Inbound` при закрытии канала сервером), его `JoinHandle` помечается как `finished_worker`, а `abort()` и `.await` вызываются **только для трёх остальных воркеров** (предотвращая панику Tokio `"JoinHandle polled after completion"`).
5. Сама структура `ssh_session` (`russh::client::Handle`) удерживается внутри задачи (`let _session_guard = ssh_session;`) на всё время жизни туннеля и автоматически закрывает SSH-соединение при завершении задачи.

### 4.3. Защита от переполнения очереди TUN на сервере (Backpressure)
В `anet-server/src/servers/ssh.rs` (`receive_from_client`) отправка расшифрованного пакета в TUN выполняется через неблокирующий `tun_tx.try_send(packet)`:
* При переполнении очереди (`TrySendError::Full`) пакет отбрасывается с логом `[SSH] TUN queue full, dropping uplink packet`, что не блокирует чтение TCP/SSH-сокета.

---

## 5. Маскировка идентификационного баннера SSHv2 и защита от DPI/ТСПУ

### 5.1. Замена дефолтного баннера `SSH-2.0-russh_*` на `OpenSSH`
По умолчанию библиотека `russh` отправляет в первых открытых байтах TCP-потока нестандартную идентификационную строку `SSH-2.0-russh_0.54.0\r\n`. На нестандартных портах (например, `822`) эта строка легко выделяется сигнатурными правилами ТСПУ.

В `anet-client-core/src/transport/ssh.rs` и `anet-server/src/servers/ssh.rs` поля `russh::client::Config::client_id` и `russh::server::Config::server_id` принудительно переопределены на стандартный баннер Ubuntu OpenSSH:
* **Баннер по умолчанию:** `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5` (`SshId::Standard`).
* **Кастомный баннер:** может быть переопределён пользователем в `client.toml` (`[transport] ssh_banner = "..."` или в `[[servers]] ssh_banner = "..."`) и `server.toml` (`[server] ssh_banner = "..."`). При указании строки без префикса `SSH-2.0-` он добавляется автоматически.
* **Рекомендация по выбору порта:** при жёсткой фильтрации со стороны ТСПУ по матрице `Порт != Протокол` рекомендуется размещать SSH-транспорт на стандартном порту `22` (или пробрасывать порт `22` внешнего IP на `ssh_bind_to`).

---

## 6. Конфигурация

### 6.1. Настройка клиента (`client.toml`)
```toml
[transport]
ssh_user = "hanyuu"                 # Глобальное имя пользователя SSH по умолчанию (если не задано — "root")
ssh_banner = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5" # Опциональное переопределение SSH-2.0 баннера клиента

[[servers]]
name = "SSH Node"
dsn = "ssh://vpn.example.com:22"    # Если порт не указан (ssh://host), по умолчанию используется порт 22
ssh_user = "deploy"                 # Опциональное переопределение пользователя SSH для конкретной ноды
# ssh_banner = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
timeout_secs = 15
server_pub_key = "<BASE64_ED25519_PUBLIC_KEY>"

[stealth]
padding_step = 64                   # Выравнивание каждого зашифрованного пакета внутри потока
min_jitter_ns = 0
max_jitter_ns = 0
frag_enabled = true                 # TCP-фрагментация первого пакета рукопожатия ASTP внутри SSH-канала
frag_min_chunks = 2
frag_max_chunks = 3
```

### 6.2. Настройка сервера (`server.toml`)
```toml
[server]
ssh_bind_to = "0.0.0.0:822"         # Пустая строка "" отключает SSH-сервер (рекомендуется порт 22 или DNAT :22 -> :822)
ssh_host_key = "/etc/ssh/ssh_host_rsa_key" # Путь к приватному ключу хоста OpenSSH (RSA / Ed25519 / ECDSA)
ssh_banner = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5" # Строка идентификации SSH-сервера

[crypto]
server_signing_key = "<BASE64_ED25519_PRIVATE_KEY>"

[stealth]
padding_step = 64
min_jitter_ns = 0
max_jitter_ns = 0
```

### Генерация ключа хоста для сервера (если `/etc/ssh/ssh_host_rsa_key` отсутствует):
```bash
ssh-keygen -t ed25519 -f /etc/anet/ssh_host_ed25519_key -N ""
```
И укажите в `server.toml`:
```toml
[server]
ssh_host_key = "/etc/anet/ssh_host_ed25519_key"
```


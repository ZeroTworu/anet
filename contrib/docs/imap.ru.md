# Архитектура и спецификация транспорта `imap` (ASTP over IMAPS:993)
Спецификация верифицирована серией нагрузочных тестов на боевом сервере `imap.mail.ru:993`, включая 30-минутный High-Throughput Soak-Test (346.13 МиБ суммарного трафика, 128 КБ батчи, ~0.81 Mbps Uplink / ~0.80 Mbps Downlink, 99.5% доставка, 0 ошибок, 0 троттлингов).

---

## 1. Введение и концепция
Транспорт `imap` — это специализированный транспорт повышенной отказоустойчивости (High Resilience Transport). Он спроектирован для обеспечения стабильной связи в сетях со сложной топологией, строгими корпоративными политиками маршрутизации (Default Deny), «Белыми списками» и системами глубокой инспекции пакетов (ТСПУ / IDS / IPS), где традиционные протоколы блокируются, но сохраняется приоритетный доступ к базовым российским почтовым сервисам (`imap.mail.ru`, `imap.yandex.ru`, `imap.timeweb.ru`).

Транспорт инкапсулирует батчи зашифрованных IP-пакетов (ASTP) в валидные RFC 5322 черновики (MIME/Base64 с флагами `\Seen \Draft`) и передает их через инфраструктуру публичных почтовых провайдеров по протоколу IMAPS (TLS 1.3 поверх **BoringSSL** на порт `993`) с использованием команд `APPEND`, `IDLE`, `UID FETCH`, `UID STORE` и `UID EXPUNGE`.

Для промежуточных узлов сетевой инфраструктуры и ТСПУ обмен данными неотличим от штатной сессии почтового клиента, синхронизирующего черновики и заметки с сервером `imap.mail.ru:993`.

---

## 2. Схема маршрутизации трафика и архитектура «Cross-Selected Writer»

Клиент и Сервер ANet не устанавливают прямого TCP/UDP соединения друг с другом. Оба узла выступают в роли IMAPS-клиентов по отношению к почтовому провайдеру. Направления трафика (Uplink/Downlink) разнесены по разным папкам (`Drafts` и `Notes`).

В почтовом аккаунте создаются отдельные пароли внешних приложений (App Passwords): один — для сервера (`anet-server`), другой — для клиентов (`anet-client`).

### Архитектура «Cross-Selected Writer» (Ноль переключений `SELECT` при сборке мусора)
По стандарту RFC 3501 §6.3.11 команда `APPEND "<Folder>" ...` **не требует**, чтобы целевая папка была открыта через `SELECT`. Напротив, команды удаления `UID STORE ... (\Deleted)` и `UID EXPUNGE` работают строго в текущей выбранной (`SELECT`) папке.
Поэтому парные соединения на клиенте и сервере скрещиваются по папкам:
* **На Сервере:**
  * `SRV_READER` делает `SELECT "Drafts"` и крутит только цикл `IDLE` $\leftrightarrow$ `UID FETCH` (читает Uplink), передавая прочитанные UIDs в локальный канал очистки.
  * `SRV_WRITER` также делает `SELECT "Drafts"` один раз при старте: он отправляет Downlink-пакеты клиенту через `APPEND "Notes" (\Seen \Draft) {<len>}`, а в паузах удаляет прочитанные `SRV_READER`'ом письма в текущей папке `"Drafts"` через `UID STORE` + `UID EXPUNGE` без единого вызова `SELECT`!
* **На Клиенте:**
  * `CLI_READER` делает `SELECT "Notes"` и крутит только цикл `IDLE` $\leftrightarrow$ `UID FETCH` (читает Downlink), передавая прочитанные UIDs в локальный канал очистки.
  * `CLI_WRITER` также делает `SELECT "Notes"` один раз при старте: он отправляет Uplink-пакеты серверу через `APPEND "Drafts" (\Seen \Draft) {<len>}`, а в паузах удаляет прочитанные `CLI_READER`'ом письма в текущей папке `"Notes"`!

```text
[UPLINK: Клиент -> Сервер (папка "Drafts")]
+--------------------+   1. APPEND "Drafts" (\Seen \Draft)   +--------------------+
|     CLI_WRITER     |======================================>|    imap.mail.ru    |
| (SELECT "Notes")   |   Subject: {Prefix} [ID: <SRV>:<ID>]  |  CAPABILITY: IDLE, |
+--------------------+                                       |  UIDPLUS, MOVE     |
                                                             +--------------------+
                                                                       |
                                                             2. * N EXISTS (0.1ms)
                                                                UID FETCH <last+1>:*
                                                                       V
                                                             +--------------------+
                                                             |     SRV_READER     |
                                                             | (SELECT "Drafts")  |
                                                             +--------------------+
                                                                       |
                                                             3. UIDs -> SRV_WRITER
                                                                UID STORE + UID EXPUNGE

[DOWNLINK: Сервер -> Клиент (папка "Notes")]
+--------------------+   4. * N EXISTS -> UID FETCH          +--------------------+
|     CLI_READER     |<--------------------------------------|    imap.mail.ru    |
| (SELECT "Notes")   |   Subject: {Prefix} [ID: <SessID>]    |     (Port 993)     |
+--------------------+                                       +--------------------+
          |                                                            ^
5. UIDs -> CLI_WRITER                                                  | 3. APPEND "Notes" (\Seen \Draft)
   UID STORE + UID EXPUNGE                                   +--------------------+
                                                             |     SRV_WRITER     |
                                                             | (SELECT "Drafts")  |
                                                             +--------------------+
```

---

## 3. Профиль работы `imap.mail.ru:993` и критические оптимизации Data Plane

По результатам 10-минутного нагрузочного тестирования на `imap.mail.ru:993` зафиксированы следующие характеристики сервера:
* **Поддерживаемые расширения (`CAPABILITY`):** `IMAP4rev1 ID XLIST UIDPLUS UNSELECT MOVE LIST-STATUS IDLE` (расширение `LITERAL+` не поддерживается, `APPEND` выполняется в 2 шага с ожиданием `+`).
* **Задержка `APPEND`:** медиана `p50 = 316 мс` (Uplink) / `455 мс` (Downlink).
* **Задержка `UID FETCH`:** медиана `p50 = 296 мс`.
* **Задержка `STORE + EXPUNGE`:** медиана `p50 = 248 мс`.
* **Вероятность попадания в «Слепое окно» (`BlindWindowHits`):** на сервере в **48.8% случаев (459 из 940 батчей)** уведомление `* <N> EXISTS` о следующем письме приходит от `imap.mail.ru` в тот момент, когда Reader уже вышел из `IDLE` и читает ответ `UID FETCH`.

### 3.1. Защита от гонки «Слепого окна» (`pending_exists`) и отказ от `async-imap`
В готовом крейте `async-imap` метод `session.uid_fetch()` поглощает нетегированные ответы `* <N> EXISTS` внутри стрима `Fetch`, не уведомляя вызывающий код. При следующем входе в `IDLE` сервер `imap.mail.ru` повторно `* EXISTS` не присылает, что приводит к зависанию туннеля.

Поэтому транспорт `imap` реализует собственный легковесный клиент `ImapConn` (~150 строк кода) напрямую поверх `tokio::io::BufReader<tokio_boring::SslStream<TcpStream>>`:
1. Низкоуровневый метод `read_line()` проверяет **каждую** входящую строку от сервера (включая строки, приходящие во время `DONE` и `UID FETCH`).
2. Если строка соответствует `^\*\s+\d+\s+EXISTS`, немедленно взводится флаг `self.pending_exists = true`.
3. Перед входом в `IDLE` метод `wait_idle_or_pending()` проверяет `if self.pending_exists`: если флаг уже взведён, воркер **пропускает фазу `IDLE` / `DONE`** (экономя ~250 мс) и мгновенно переходит к следующему `UID FETCH`!

### 3.2. Защита от дублей UID при запросе `<last_uid + 1>:*`
В стандарте RFC 3501 символ `*` обозначает максимальный существующий UID в папке. Если новых писем больше нет, запрос `UID FETCH 100:*` при максимальном UID в папке `99` интерпретируется сервером как `100:99` $\equiv$ `99:100` и повторно возвращает письмо с `UID = 99` (в 10-минутном тесте это произошло 491 раз).
* **Обязательное правило:** При разборе ответа `UID FETCH <last_uid + 1>:*` код обязан проверять `if msg_uid <= last_uid { continue; }` и обновлять `last_uid = last_uid.max(msg_uid)`.

### 3.3. Self-Clocking коалесценция (`PacketBatcher`) — снижение RTT на 500 мс
Чтобы не добавлять искусственную задержку `batch_ms` к одиночным пакетам (DNS, TCP SYN, ICMP-пинг):
1. Когда `Writer` свободен и из канала `tx_queue` приходит первый пакет, воркер ждёт микро-окно не более **`10–15 мс`** (собирая текущий бурст через `try_recv`) и **немедленно начинает `APPEND`**.
2. Пока этот `APPEND` выполняется по сети (`~320–450 мс`), новые пакеты из TUN естественным образом накапливаются в `tx_queue`.
3. Как только `APPEND` завершается, `Writer` выгребает все накопившиеся за эти `320 мс` пакеты (до `max_kb = 32 КБ`) в один `PacketBatcher`, шифрует весь собранный буфер **одним вызовом** `wrap_packet_slice(&cipher, &nonce_prefix, seq, &raw_batch, 0)` и сразу запускает следующий `APPEND`.

### 3.4. Неблокирующая сборка мусора (`UID EXPUNGE` в паузах трафика)
Поскольку `imap.mail.ru` поддерживает расширение `UIDPLUS` (RFC 4315):
1. Для удаления прочитанных писем используется точечная команда `UID EXPUNGE <uid_set>` (с фолбэком на `EXPUNGE`):
   ```text
   UID STORE 4,5,6,7,8 +FLAGS.SILENT (\Deleted)
   UID EXPUNGE 4,5,6,7,8
   ```
2. `Writer` запускает удаление в двух случаях:
   * **Приоритетно в паузе трафика:** когда очередь исходящих пакетов `tx_queue` пуста (`is_empty()`), а в списке `cleanup_uids` есть хотя бы 1 прочитанный UID;
   * **Принудительно под нагрузкой:** когда в `cleanup_uids` накопилось $\ge 20$ прочитанных UIDs (чтобы не тормозить серию активных `APPEND` каждые 5 пакетов).

### 3.5. Формат письма RFC 5322 при `APPEND`
Каждое сообщение отправляется с флагами **`(\Seen \Draft)`** и валидной шапкой RFC 5322 с разбивкой Base64 по 76 символов:

```text
From: <account_email>
To: <account_email>
Subject: {subject_prefix} [ID: <TargetID>]
Date: <RFC2822_Date>
Message-ID: <<random_hex>@mail.ru>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: base64

<Base64_Payload_Chunked_76_Chars>
```

### 3.6. Особенности IMAP-ответов Mail.ru и побайтовый парсер (FETCH Literal & Trailing UID)
В ходе натурных soak-тестов на живом сервере `imap.mail.ru:993` выявлены критические особенности реализации IMAP:
1. **Строгий синтаксис RFC 3501 для тела сообщения (`BODY.PEEK[]`):**
   * Запрос `RFC822.PEEK` **не поддерживается** Mail.ru и возвращает ошибку `A0003 BAD [PARSE] Cannot parse fetch part: RFC822.PEEK`.
   * Валидный RFC 3501 запрос полного сообщения без изменения статуса:
     `tag UID FETCH <last_uid + 1>:* (UID BODY.PEEK[])`
2. **Постфиксное расположение UID (Trailing UID placement):**
   * Mail.ru возвращает строку FETCH с литералом тела, помещая токен `UID <id>` **после** тела сообщения:
     `* 1 FETCH (BODY[] {<len>}\r\n<raw message bytes> UID 123)\r\n`
   * Парсер не должен предполагать, что `UID` находится перед `{len}`. Алгоритм разбора:
     1. Считать заголовок строки ответа `* <seq> FETCH (...{len}`;
     2. Прочитать ровно `len` байт через `read_exact(len)`;
     3. Дочитать остаток строки до `\r\n` (`rest_line`);
     4. Извлечь `UID` регулярным выражением или поиском токена `UID <id>` из объединенной строки `(header_line + " " + rest_line)`.
3. **Прямое бинарное извлечение полезной нагрузки (Без промежуточного UTF-8):**
   * Полезная нагрузка ASTP — это зашифрованный бинарный поток байт, закодированный в Base64.
   * Использование стандартных почтовых библиотек, автоматически декодирующих тело в строку Unicode (`utf-8`), приводит к фатальным исключениям при наличии не-ASCII байт.
   * Разбор сообщения в памяти выполняется напрямую по границе заголовков `\r\n\r\n` (или `\n\n`), после чего из `body_raw` удаляются символы `\r`, `\n` и пробелы, и выполняется прямой вызов `base64::decode()`.

### 3.7. Управление переполнением (Flow Control / Backpressure) во избежание блокировок IP
В ходе тестирования высокой нагрузки (1–2 Мбит/с) выявлено поведение анти-флуд механизмов Mail.ru:
* **Симптом блокировки:** Если `Writer` непрерывно отправляет письма быстрее, чем `Reader` их забирает и удаляет через `EXPUNGE` (например, при накоплении более 35 МБ невычищенных черновиков), `imap.mail.ru` мгновенно сбрасывает TCP-сессию (`Connection reset by peer` / `Connection closed by server`), а IP-адрес клиента попадает во временный бан почтовой инфраструктуры на 10–15 минут (пакеты на порт 993 перестают маршрутизироваться или дропаются, вызывая `[Errno 101] Network is unreachable`).
* **Требование к реализации:** `Writer` обязан поддерживать ограничение скользящего окна (Sliding Window): если количество отправленных, но еще не подтвержденных/не удаленных сообщений превышает **15–20 пакетов** (~1 МБ), `Writer` приостанавливает вызовы `APPEND` и дает паузу в 50 мс для завершения очистки `Reader`'ом.

### 3.8. Активное асинхронное чтение в IDLE (`wait_idle_or_event`)
* **Проблема пассивного сна:** При использовании `IDLE` сервер `imap.mail.ru` отправляет нетегированные уведомления `* <N> EXISTS\r\n` в реальном времени. Если клиент в фазе ожидания засыпает по таймеру (`sleep`) без вызова методов чтения сокета (`read_line`), внутренний буфер сокета заполняется, но прикладной цикл не получает уведомление до истечения общего таймаута (например, 30 секунд), что приводит к искусственным задержкам и блокировке отправки по Backpressure.
* **Решение:** Метод ожидания IDLE обязан активно удерживать асинхронную операцию чтения сокета (`await asyncio.wait_for(self.readline(), timeout=...)` в Python или `tokio::select!` с чтением из `BufReader` в Rust). При поступлении строки `* EXISTS` воркер немедленно отправляет команду `DONE`, дожидается тегированного ответа `OK IDLE` и переходит к выборке `UID FETCH` с минимальной сетевой задержкой (~500–750 мс вместо 30 с).

### 3.9. Определение базового максимального UID (`UID FETCH * (UID)`)
* **Проблема:** Если при подключении к папкам (`Drafts` или `Notes`) воркер начинает выборку с фиксированного `last_seen_uid = 0` (запрос `UID FETCH 1:*`), он вынужден скачивать и парсить тысячи старых сообщений от предыдущих запусков, что блокирует data plane на несколько минут и перегружает канал.
* **Решение:** Сразу после выполнения `SELECT "<Folder>"` воркер выполняет легковесный запрос `UID FETCH * (UID)` (занимает ~50 мс). Максимальный полученный номер принимается за базовый `last_seen_uid = current_max_uid`. Текущая сессия обрабатывает строго новые пакеты с `UID > current_max_uid`.

### 3.10. Результаты 30-минутного High-Throughput стресс-тестирования (128 КБ батчи)
При проведении полнодуплексного теста на боевом сервере `imap.mail.ru:993` с батчами 128 КБ зафиксированы следующие параметры стабильности:
* **Длительность:** 30 минут (1801.0 сек) непрерывной прокачки.
* **Суммарный объем трафика:** 346.13 МиБ.
* **Uplink (Клиент $\to$ Сервер, папка "Drafts"):** 1390 батчей (173.69 МиБ, средняя скорость **0.809 Mbps**).
* **Downlink (Сервер $\to$ Клиент, папка "Notes"):** 1380 батчей (172.44 МиБ, средняя скорость **0.800 Mbps**).
* **Принято клиентом:** 1374 батча (171.69 МиБ).
* **Успешность доставки:** 99.5% (потери 7 Uplink, 6 Downlink).
* **Ошибки и аномалии:**
  * Ошибок парсинга (Parse errors): **0**.
  * Срабатываний троттлинга (`NO [THROTTLED]`): **0**.
  * Превышений дисковой квоты (`NO [OVERQUOTA]`): **0**.
  * Разрывов TLS-сокетов и переподключений: **0**.
* **Задержки (Data Plane):**
  * `APPEND` p50: **709.1 мс** на 128 КБ батч.
  * `UID FETCH` p50: **3500.0 мс** на 128 КБ батч.
  * `End-to-End RTT` (с учетом буферизации Backpressure на 12–15 пакетов in-flight): p50 = **17.8 сек**, p95 = **27.1 сек**.

---

## 4. Идентификация, Фазы Handshake и Виртуальные Сокеты (Virtual Sockets)

Тема письма формируется динамически: `Subject: {Template_Prefix} [ID: <TargetID>]`
* **На этапе Handshake (Фаза 1 и Фаза 3):**
  * Клиент $\to$ Сервер (`Drafts`): `Subject: {Prefix} [ID: <SRV_ID>:<Client_TempID>]`
    где `SRV_ID` — первые 8 hex-символов от `SHA256(server_pub_key_bytes)`, а `Client_TempID` — первые 8 hex-символов от `SHA256(client_ephemeral_or_pub_key)`.
  * Сервер $\to$ Клиент (`Notes`, Фаза 2 и Фаза 4): `Subject: [ID: <Client_TempID>]` (в приватной папке `"Notes"` префикс шаблона избыточен).
* **На этапе Data Plane (после завершения Фазы 4 и получения `session_id`):**
  * Клиент $\to$ Сервер (`Drafts`): `Subject: {Prefix} [ID: <SRV_ID>:<session_id>]`
  * Сервер $\to$ Клиент (`Notes`): `Subject: [ID: <session_id>]`

### 4.1. Генерация виртуального `SocketAddr` (Сторона Сервера)
Поскольку `ServerAuthHandler` привязывает состояние Фазы 1 (`temp_dh_map`) к `SocketAddr`, IMAP-воркер сервера детерминированно конвертирует `Client_TempID` в уникальный виртуальный `SocketAddr`:

```rust
use sha2::{Sha256, Digest};
use std::net::{SocketAddr, Ipv4Addr};
use std::str::FromStr;

/// Определяет безопасный базовый IP-адрес для виртуальных сокетов,
/// гарантируя отсутствие коллизий с маршрутами внутри VPN-туннеля.
pub fn get_safe_fake_base(vpn_net_str: &str) -> Ipv4Addr {
    let vpn_ip = Ipv4Addr::from_str(vpn_net_str).unwrap_or(Ipv4Addr::new(10, 0, 0, 0));
    if vpn_ip.octets()[0] == 127 {
        Ipv4Addr::new(198, 18, 0, 0)
    } else {
        Ipv4Addr::new(127, 127, 0, 0)
    }
}

/// Превращает строковый TempID клиента из темы письма в детерминированный виртуальный SocketAddr
/// для использования в качестве ключа во внутреннем temp_dh_map (ServerAuthHandler).
pub fn fake_addr_from_cli_id(cli_id: &str, safe_base: Ipv4Addr) -> SocketAddr {
    let hash = Sha256::digest(cli_id.as_bytes());
    let base = safe_base.octets();
    let ip = Ipv4Addr::new(base[0], base[1], hash[2], hash[3]);
    let port = (u16::from_be_bytes([hash[4], hash[5]]) | 0x8000).max(1024);
    SocketAddr::new(std::net::IpAddr::V4(ip), port)
}
```

---

## 5. Обработка стадий Auth и Data на сервере (`anet-server/src/servers/imap.rs`)

На стороне сервера критически важно обработать второй элемент ответа `auth_handler.process_handshake_packet(...)`: когда в Фазе 3 возвращается `Some((client_info, _auth_response))`, сервер обязан зарегистрировать канал маршрутизации через `registry.finalize_client(&client_info.assigned_ip, tx_router)` и запустить фоновую задачу Downlink-отправки для этого клиента:

```rust
// Псевдокод обработки входящего письма из папки "Drafts" на сервере:
let Some((msg_srv_id, cli_token)) = extract_srv_and_cli_token(&subject) else {
    continue;
};
if msg_srv_id != worker_ctx.srv_id {
    continue; // Письмо предназначено другому серверу
}

// 1. FAST PATH (Установленная сессия Data Plane, cli_token == session_id)
if let Some(client_info) = local_sessions.get(cli_token).cloned()
    .or_else(|| {
        let info = worker_ctx.registry.get_by_session(cli_token)?;
        local_sessions.insert(cli_token.to_string(), info.clone());
        Some(info)
    })
{
    // Обновляем метку последней активности для контроля TTL сессии
    worker_ctx.registry.touch_client(&client_info);

    if let Ok(decrypted_batch) = anet_common::transport::unwrap_packet(&client_info.cipher, &raw_payload) {
        for pkt in anet_common::batcher::unpack_batch(&decrypted_batch) {
            if let Some(reply) = anet_common::icmp_probe::handle_in_tunnel_icmp_probe(&pkt) {
                if let Some(dst_ip) = crate::utils::extract_ip_dst(&reply) {
                    worker_ctx.registry.route_packet_to_ipv4(dst_ip, reply).await;
                }
                continue;
            }
            let pkt_len = pkt.len();
            if worker_ctx.tun_tx.try_send(pkt).is_ok() {
                worker_ctx.registry.record_rx(&client_info, pkt_len, "imap");
            }
        }
    }
    continue;
}

// 2. AUTH PLANE (Хендшейк Фазы 1 или Фазы 3, cli_token == Client_TempID)
let fake_addr = fake_addr_from_cli_id(cli_token, worker_ctx.safe_base_ip);
match worker_ctx.auth_handler.process_handshake_packet(raw_payload, fake_addr, "imap").await {
    Ok((response_opt, auth_tuple_opt)) => {
        if let Some((client_info, _auth_response)) = auth_tuple_opt {
            let assigned_ip = client_info.assigned_ip.clone();
            let session_id = client_info.session_id.clone();
            local_sessions.insert(session_id.clone(), client_info.clone());

            let (tx_router, mut rx_router) = tokio::sync::mpsc::channel::<Bytes>(CHANNEL_BUFFER_SIZE);
            worker_ctx.registry.finalize_client(&assigned_ip, tx_router);

            let writer_tx = worker_ctx.notes_append_tx.clone();
            let c_info = client_info.clone();
            tokio::spawn(async move {
                // Задача Downlink: собирает пакеты из rx_router в PacketBatcher (Self-Clocking),
                // шифрует одним вызовом wrap_packet_slice и отправляет через APPEND в "Notes"
                // с темой Subject: "{Prefix} [ID: <session_id>]"
                run_client_downlink_batcher(&mut rx_router, c_info, writer_tx).await;
            });
        }

        if let Some(response_bytes) = response_opt {
            let _ = worker_ctx.notes_append_tx.send((cli_token.to_string(), response_bytes)).await;
        }
    }
    Err(e) => {
        log::debug!("[IMAP Auth] Handshake packet ignored for {}: {e}", cli_token);
    }
}
```

---

## 6. Интеграция в панель управления (`anet-auth` & `anet-webui`)
Во избежание компрометации паролей и для удобства управления почтовые ящики хранятся в базе данных как справочник. Пароли шифруются с помощью компонента `DbEncryptor`. Строка подключения (DSN) собирается сервером «на лету» при выдаче конфигурации клиенту.

### 6.1. База данных и DTO (`anet-auth`)
1. В `anet-auth/src/entities/protocol_type.rs` (и миграцией PostgreSQL `ALTER TYPE protocol_type ADD VALUE IF NOT EXISTS 'imap';`) добавить вариант `ProtocolType::Imap` (`"imap"`).
2. Создать таблицу `imap_mailboxes` через SeaORM миграцию:

```rust
/// Модель данных служебного почтового ящика в БД
pub struct Model {
    pub id: Uuid,
    /// Адрес IMAP-сервера провайдера (например, imap.mail.ru)
    pub host: String,
    /// Порт IMAP-сервера (обычно 993 для IMAPS)
    pub port: i32,
    /// Логин (email) от почтового ящика
    pub email: String,
    /// Зашифрованный пароль приложения для КЛИЕНТОВ (шифруется через DbEncryptor::encrypt)
    pub client_password_encrypted: String,
    /// Опциональный отдельный зашифрованный пароль приложения для СЕРВЕРА
    pub server_password_encrypted: Option<String>,
    pub is_active: bool,
    pub created_at: DateTime,
    pub updated_at: DateTime,
}
```

### 6.2. Изменения в `anet-webui` (Frontend)
1. **Справочник ящиков:** Создать раздел в UI для управления пулом почтовых ящиков (CRUD операции).
2. **Настройка пулов (Node Pools):** В компоненте `PoolModal.vue` добавить протокол `IMAP`.
3. При выборе протокола `IMAP` отображать выпадающий список (Multiple Select) для выбора ящиков из справочника БД. Выбранные ID ящиков сериализуются через запятую в поле `port_or_url` таблицы `node_pool_members`.

### 6.3. Сборка DSN «на лету» (`anet-auth/src/api/users.rs`)
При вызове эндпоинта генерации `client.toml` (`download_config`):
1. Бэкенд обрабатывает `ProtocolType::Imap` в блоке генерации серверов.
2. Извлекает ID ящиков из `port_or_url`, загружает активные записи из `imap_mailboxes`, дешифрует клиентские пароли через `DbEncryptor::decrypt()`.
3. Формирует строку DSN:
   `imap://imap.mail.ru:993?acc=user1%40mail.ru:client_pass1&acc=user2%40mail.ru:client_pass2&batch_ms=250`
   и экспортирует её в блок `[[servers]]` файла `client.toml`.

---

## 7. Интеграция в ядро ANet (Core Integration)

### 7.1. Никаких внешних IMAP-крейтов с `rustls`!
Транспорт **не использует** крейт `async-imap` (так как `async-imap` теряет нетегированные `* EXISTS` во время `UID FETCH` и тянет `rustls`).
Вместо этого в `anet-common/src/imap_conn.rs` реализуется нативный асинхронный `ImapConn` поверх `tokio::io::BufReader<tokio_boring::SslStream<TcpStream>>`, использующий штатный **BoringSSL** коннектор из `anet-common/src/boring_tls.rs`.

### 7.1.1. Эталонный TLS-фингерпринт почтового клиента (KMail / OpenSSL 3.x)
В результате реального сниффинга сессии десктопного почтового клиента `KMail` (KDE / Qt6 / OpenSSL 3.x) на порт `993` (`imap.gmail.com:993`) зафиксирован эталонный сетевой отпечаток почтового трафика:
1. **Ноль GREASE и ноль Permutation:** Настоящие почтовые клиенты (KMail, Thunderbird, Evolution) не используют GREASE (`0x?a?a`) и не тасуют расширения ClientHello. Порядок расширений строго детерминирован стеком OpenSSL/Qt:
   `0xff01 (renegotiation_info)` $\to$ `0x0000 (server_name)` $\to$ `0x000b (ec_point_formats)` $\to$ `0x000a (supported_groups)` $\to$ `0x0023 (session_ticket)` $\to$ `0x0016 (encrypt_then_mac)` $\to$ `0x0017 (extended_master_secret)` $\to$ `0x000d (signature_algorithms)` $\to$ `0x002b (supported_versions)` $\to$ `0x002d (psk_modes)` $\to$ `0x0033 (key_share)`.
2. **Отсутствие ALPN (0x0010):** Для неявного IMAPS на порту 993 расширение ALPN **не отправляется вовсе** (никаких `h2`/`http/1.1`).
3. **Отсутствие Padding (0x0015):** В отличие от Chromium, дополняющего ClientHello до 512 байт, почтовый клиент не использует расширение 0x0015.
4. **Пост-квантовая криптография (ML-KEM / Kyber 768):** В `supported_groups` во главе списка передаётся гибридная группа `0x11ec` (`X25519MLKEM768`), а в `key_share` сразу включается 1216-байтный квантово-устойчивый публичный ключ.
5. **Приоритет AES-256 в TLS 1.3:** В списке шифров первым идёт `1302` (`TLS_AES_256_GCM_SHA384`), далее `1303` (`TLS_CHACHA20_POLY1305_SHA256`) и `1301` (`TLS_AES_128_GCM_SHA256`).

### 7.1.2. Реализация профиля в `anet-common/src/boring_tls.rs`
В `boring_tls.rs` добавляется выделенный конструктор `build_email_ssl_connector_with_config`:
```rust
/// Создает конфигуратор BoringSSL с идеальной мимикрией под Linux-почтовик (KMail / OpenSSL 3.x):
/// отключены GREASE, Permutation и ALPN, выставлен приоритет AES-256 и поддержка X25519MLKEM768.
pub fn build_email_ssl_connector_with_config(
    cfg: &TlsClientConfig,
) -> anyhow::Result<SslConnectorBuilder> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    // Отключаем браузерный GREASE и случайную перестановку расширений
    builder.set_grease_enabled(false);
    builder.set_permute_extensions(false);

    // НЕ вызываем builder.set_alpn_protos() - на 993 порту ALPN отсутствует!

    // Шифры: приоритет AES-256-GCM в TLS 1.3 и полный классический стек OpenSSL
    builder.set_cipher_list(
        "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:         ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:         DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:         ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
    )?;

    // Пост-квантовые группы обмена ключами
    let _ = builder.set_curves_list("X25519MLKEM768:X25519:P-256:P-384");

    // Политика проверки сертификата сервера
    configure_verify_and_pinning(&mut builder, cfg)?;

    Ok(builder)
}

/// Выполняет асинхронный клиентский TLS-хендшейк для IMAPS (порт 993) с профилем почтового клиента
pub async fn connect_email_tls_with_config<S>(
    domain: &str,
    stream: S,
    cfg: &TlsClientConfig,
) -> anyhow::Result<tokio_boring::SslStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let builder = build_email_ssl_connector_with_config(cfg)?;
    let ssl = builder.build().configure()?.into_ssl(domain)?;
    tokio_boring::connect(ssl, stream).await
        .map_err(|e| anyhow::anyhow!("BoringSSL Email TLS handshake failed for {domain}: {e}"))
}
```

### 7.2. Клиент (`anet-client-core`)
1. **`config.rs`**:
   * В `TransportMode` добавить вариант `Imap`.
   * В `ServerConfig::mode()` добавить `"imap" | "imaps" => Ok(TransportMode::Imap)`.
   * В `ServerConfig::host_port()` добавить `"imap" | "imaps" => 993`, чтобы `AnetClient::connect_and_run` автоматически добавлял все IP-адреса `imap.mail.ru` в `route_manager.add_bypass_route()` (и в исключения `VpnService` на Android)!
   * В `ServerConfig::get_name()` добавить `TransportMode::Imap => "IMAP"`.
2. **`transport/factory.rs`**: Добавить ветвление `TransportMode::Imap => Box::new(ImapTransport::new(config.clone(), server.clone()))`.
3. **Вынесение `PacketBatcher` в общее пространство:** Модуль пакетирования выносится из `anet-common/src/wrtc/batcher.rs` в `anet-common/src/batcher.rs` (с реэкспортом в `wrtc` для обратной совместимости).
4. **Связывание с VPN-стеком через `tokio::io::duplex`:**
   В методе `ImapTransport::connect()` создаётся локальный дуплексный канал `(client_stream, internal_router) = tokio::io::duplex(DUPLEX_BUFFER_SIZE)`.
   * `client_stream` возвращается в `ConnectionResult { vpn_stream: Box::new(client_stream), ... }`.
   * `internal_router` разделяется на `(reader, writer)`: накопитель `PacketBatcher` выгребает пакеты из `reader` и отправляет через `CLI_WRITER (APPEND "Drafts")`, а `CLI_READER (IDLE/FETCH "Notes")` распаковывает входящие батчи и инжектирует пакеты в `writer`.
5. Создать `transport/imap.rs` со структурами конфигурации `ImapConfig` и реализацией `ClientTransport`.

### 7.3. Сервер (`anet-server`)
1. **`config.rs`**: В структуру `ServerCoreConfig` добавить поле `pub imap_dsn: Option<String>`.
2. **`server.rs`**: В методе `ANetServer::run()` добавить запуск супервизора:
   ```rust
   if let Some(ref imap_dsn) = self.cfg.server.imap_dsn {
       if !imap_dsn.trim().is_empty() {
           let c = self.cfg.clone();
           let rg = self.registry.clone();
           let tx = client_pkt_tx.clone();
           let auth = self.auth_handler_core.clone();
           handle_collection.push(tokio::spawn(async move {
               if let Err(e) = imap::run_imap_server(c, rg, tx, auth).await {
                   error!("Fatal error: [IMAP] Server halted: {}", e);
               }
           }));
       }
   }
   ```
3. Создать модуль `servers/imap.rs` с реализацией пула воркеров для всех ящиков из `imap_dsn`.

---

## 7.4. Конфигурационные параметры в `client.toml` и `server.toml` (Все интервалы строго в миллисекундах!)

### В `client.toml` / `client_template.toml`:
```toml
# =========================================================================
# Тонкая настройка транспорта IMAP (секция [imap])
# =========================================================================
[imap]
# Интервал перевхода в IDLE (keepalive) для проверки живости соединения (мс).
# По умолчанию: 120000 мс (2 минуты).
idle_refresh_interval_ms = 120000

# Таймаут ожидания ответа на команду IMAP (APPEND, FETCH, DONE) (мс).
# По умолчанию: 15000 мс (15 секунд).
command_timeout_ms = 15000

# Максимальная задержка накопления микро-батча перед первым APPEND (мс).
# По умолчанию: 15 мс.
batch_coalesce_ms = 15

# Максимальный размер одного зашифрованного пакета-черновика (КБ).
max_batch_kb = 32

# Таймаут переподключения при получении THROTTLED/OVERQUOTA (мс).
# По умолчанию: 30000 мс (30 секунд).
throttle_backoff_ms = 30000
```

### В `server.toml`:
```toml
[server]
# Строка подключения IMAP пула (DSN)
imap_dsn = "imap://imap.mail.ru:993?acc=node1%40mail.ru:srv_pass1&acc=node2%40mail.ru:srv_pass2"

[imap]
# Время жизни неактивной клиентской сессии при отсутствии пакетов (мс).
# По умолчанию: 180000 мс (3 минуты).
session_ttl_ms = 180000

# Интервал перевхода серверного воркера в IDLE (мс).
# По умолчанию: 120000 мс (2 минуты).
idle_refresh_interval_ms = 120000

# Таймаут ожидания команды IMAP (мс).
# По умолчанию: 15000 мс (15 секунд).
command_timeout_ms = 15000

# Интервал проверки и очистки зависших сессий (мс).
# По умолчанию: 30000 мс (30 секунд).
cleanup_interval_ms = 30000

# Таймаут отката при рейт-лимитах провайдера (мс).
# По умолчанию: 30000 мс (30 секунд).
throttle_backoff_ms = 30000
```

---

## 8. Строгие директивы для ИИ-агента при написании Rust-кода

1. **BoringSSL Only (Никакого `rustls` на 993 порту):** Устанавливать TCP-соединение через `TcpStream::connect`, оборачивать его через `anet_common::boring_tls::connect_raw_tls_with_config(&host, tcp_stream, &tls_cfg)`.
2. **Архитектура «Cross-Selected Writer»:**
   * На сервере и `SRV_READER`, и `SRV_WRITER` делают `SELECT "Drafts"`. `SRV_WRITER` выполняет `APPEND "Notes" (\Seen \Draft) {<len>}` и чистит прочитанные UIDs в `"Drafts"`.
   * На клиенте и `CLI_READER`, и `CLI_WRITER` делают `SELECT "Notes"`. `CLI_WRITER` выполняет `APPEND "Drafts" (\Seen \Draft) {<len>}` и чистит прочитанные UIDs в `"Notes"`.
3. **Защита от «Слепого окна» (`pending_exists`):** В методе чтения строк из сокета любая строка `^\*\s+\d+\s+EXISTS` обязана взводить `self.pending_exists = true`. Метод `wait_idle_or_pending()` обязан проверять этот флаг до входа в `IDLE` и сразу после выхода из `IDLE`.
4. **Чтение строго по `UID FETCH <last_uid + 1>:* (UID BODY.PEEK[])`:** Никогда не использовать `SEARCH` или `RFC822.PEEK` (Mail.ru возвращает BAD). Запрашивать `BODY.PEEK[]`, побайтово считывать литерал через `read_exact(len)`, извлекать `UID` из хвоста строки ответа (у Mail.ru токен `UID <id>` передается **после** литерала тела), парсить тело прямым бинарным поиском `\r\n\r\n` без преобразования в `utf-8` строку, игнорировать элементы с `uid <= last_uid` и обновлять `last_uid = last_uid.max(uid)`.
5. **Self-Clocking Batcher:** Первый пакет при свободном `Writer` отправляется с микро-задержкой коалесценции не более `15 мс`, а следующие пакеты естественно коалесцируются в очереди, пока текущий `APPEND` выполняется по сети (`~320 мс`).
6. **Неблокирующий `UID EXPUNGE`:** Использовать `UID STORE <uids> +FLAGS.SILENT (\Deleted)` + `UID EXPUNGE <uids>` (с фолбэком на `EXPUNGE`) в моменты, когда очередь отправки `Writer` пуста, либо при накоплении $\ge 20$ прочитанных UIDs.
7. **Управление переполнением (Backpressure):** `Writer` обязан ограничивать окно отправки (не более 15–20 неподтвержденных/неочищенных сообщений в папке), приостанавливая `APPEND` во избежание переполнения ящика (>35 МБ), сброса TCP-сессии и временного сетевого бана IP-адреса со стороны Mail.ru.
8. **Failover ящиков (Клиент):** Если клиент получает ошибку авторизации, разрыв соединения или лимит от провайдера на текущем ящике, он переключается на следующий аккаунт `(index + 1) % accounts.len()` с сохранением `resume_session_id` (бесшовный реконнект без пересоздания TUN).
9. **Мультиплексирование (Сервер):** Сервер спавнит независимые пары воркеров (Reader + Writer) для каждого почтового ящика из `imap_dsn` параллельно, разделяя единый `ClientRegistry`.
10. **Активный слушатель IDLE (`wait_idle_or_event`):** Воркер обязан активно ожидать данные из сокета во время IDLE, реагируя на `* EXISTS` немедленной отправкой `DONE` и переходом к чтению, а не засыпать по пассивному таймеру.
11. **Инициализация базового UID (`UID FETCH * (UID)`):** Сразу после `SELECT` выполнять быстрый запрос максимального UID в папке и начинать выборку строго с `last_seen_uid = current_max_uid`, предотвращая загрузку сотен мегабайт исторических сообщений прошлых сессий.
````
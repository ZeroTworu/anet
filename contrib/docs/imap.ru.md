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
* **Автоматическая инициализация папок (`CREATE "Drafts"` / `CREATE "Notes"` на свежих ящиках):**
  * На только что зарегистрированных русскоязычных аккаунтах `mail.ru` системная папка черновиков имеет имя в кодировке modified UTF-7 (`&BCcENQRABD0EPgQyBDgEOgQ4-`), а папки с ASCII-именами `"Drafts"` и `"Notes"` по умолчанию отсутствуют (`SELECT` возвращает `NO [NONEXISTENT] Unknown Mailbox`).
  * Поэтому метод `ImapConn::select(folder)` при получении `NO` автоматически выполняет команду `CREATE "<folder>"` и повторяет `SELECT "<folder>"`, а `SRV_WRITER` и `CLI_WRITER` при старте проверяют наличие обеих папок (`"Drafts"` и `"Notes"`), обеспечивая работу свежезарегистрированных ящиков «из коробки» без ручного создания папок в веб-интерфейсе.

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

### 3.3. Двухполосная Self-Clocking коалесценция и QoS Fast-Lane (`PacketBatcher`) — поддержка батчей > 64 КБ
Чтобы свести к минимуму сетевую задержку интерактивного трафика и одновременно достичь околомегабитной скорости:
1. **QoS Fast-Lane (`is_priority_ip_packet`):**
   * В `PacketBatcher` реализованы две раздельные очереди: `prio_queue` (высокий приоритет) и `queue` (bulk-трафик).
   * В `prio_queue` вне очереди помещаются: ICMP Echo/Reply (включая внутритуннельные пинги 0x414E), DNS-запросы и ответы (UDP/TCP 53, 853), пакеты установки/завершения TCP (SYN, FIN, RST, а также чистые ACK), мелкие интерактивные кадры $\le 256$ байт (управляющие пакеты iperf3, сообщения Telegram MTProto, SSH keystrokes).
   * При упаковке батча (`flush()`) кадры из `prio_queue` **всегда размещаются в начале буфера**, предотвращая застревание пингов и DNS позади крупных TCP-сегментов.
2. **Поддержка батчей более 64 КБ без переполнения `u16` (`LARGE_PACKET_LEN_SENTINEL`):**
   * В формате заголовка ASTP поле длины полезной нагрузки имеет размер 2 байта (`u16`). При батчах 128..512 КБ значение `payload_len` превышает 65 535 байт.
   * Для прозрачной совместимости в `anet_common::transport` введен сигнальный маркер `LARGE_PACKET_LEN_SENTINEL = u16::MAX` (0xFFFF). При длине данных $\ge 65535$ байт в поле длины записывается `0xFFFF`, а паддинг обнуляется. Принимающая сторона при обнаружении `raw_len == 0xFFFF` автоматически вычисляет точный размер: `data_len = plaintext_len - 10`.
3. **Self-Clocking конвейер:**
   * Когда `Writer` свободен и поступает первый пакет, воркер ждет микро-окно `batch_coalesce_ms = 15 мс` и начинает `APPEND`.
   * Пока `APPEND` выполняется по сети (`~320–450 мс`), новые пакеты из TUN накапливаются в очередях. По завершении `APPEND` `Writer` выгребает все накопившиеся данные (по умолчанию до `max_batch_kb = 128 КБ`, настраивается до 512 КБ), шифрует буфер одним вызовом `wrap_packet_slice` и немедленно отправляет следующий `APPEND`.

### 3.4. Ленивая пакетная сборка мусора (`Lazy Batch Expunge`)
Чтобы не тратить дорогостоящие RTT на вызовы `UID STORE` + `UID EXPUNGE` после каждого небольшого `FETCH`:
1. Воркер накапливает прочитанные UIDs в локальном векторе.
2. Очистка выполняется одной пачкой:
   ```text
   UID STORE <uid_1>,<uid_2>,...<uid_N> +FLAGS.SILENT (\Deleted)
   UID EXPUNGE <uid_1>,<uid_2>,...<uid_N>
   ```
3. Триггеры очистки:
   * **По объему (`expunge_batch_size = 25`):** при накоплении 25 и более прочитанных UIDs очистка запускается немедленно;
   * **По паузе трафика (`expunge_idle_delay_ms = 1500 мс`):** если новых входящих писем нет в течение 1.5 секунд, накопленные UIDs вычищаются фоном, даже если их меньше 25;
   * **В паузах `Writer`:** если очередь исходящих пакетов пуста.

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

### 3.7. Управление переполнением (Flow Control / Backpressure) и емкость очередей
* **Скользящее окно пакетов в полете (`max_inflight_batches = 35`):** `Writer` отслеживает число отправленных, но еще не подтвержденных/не очищенных батчей. При достижении порога 35 батчей `Writer` приостанавливает вызовы `APPEND` на 40 мс для завершения цикла очистки `Reader`'ом.
* **Защита от Bufferbloat (`tx_queue_capacity = 256`):** емкость очередей роутера пакетов TUN строго ограничена 256 пакетами, предотвращая накопление устаревших TCP-сегментов и снижая джиттер.

### 3.8. Адаптивный короткий IDLE (`Adaptive Short-IDLE`) и жадный слив (`Greedy Fetch Drain`)
* **Проблема «Слепого окна» между FETCH и IDLE:** В моменты пиковой нагрузки уведомление `* N EXISTS` от почтового сервера может прийти в момент завершения `UID FETCH` до того, как воркер успел войти в `IDLE`. При классическом длинном таймауте IDLE (10–120 секунд) воркер засыпает в сокете, а скорость передачи проседает на 5–10 секунд.
* **Двухрежимный адаптивный опрос:**
  1. **Активный режим (`idle_active_poll_ms = 400 мс`):** Пока идет активный обмен трафиком (окно `idle_active_window_ms = 5000 мс` с момента последнего принятого или переданного пакета), воркер удерживает IDLE с коротким интервалом **400 мс**.
  2. **Спокойный режим (`idle_refresh_interval_ms = 10000 мс`):** При отсутствии трафика более 5 секунд воркер переключается на энергоэффективный 10-секундный IDLE.
  3. **Межпоточное пробуждение (`wait_idle_or_wake`):** Если локальный `Writer` отправляет пакет во время долгого спокойного IDLE, он дергает `Notify`, мгновенно пробуждая `Reader` из IDLE для перехода в быстрый режим.
  4. **Жадный слив (`Greedy Fetch Drain`):** Если во время разбора `UID FETCH` зафиксирован флаг `pending_exists`, следующий `UID FETCH` вызывается немедленно без засыпания в `IDLE`.

### 3.9. Автоматический детект `LITERAL+` / `LITERAL-` (1-RTT APPEND)
При вызове `LOGIN` метод `detect_capabilities()` анализирует ответ сервера:
* Если почтовый провайдер поддерживает RFC 7888 / RFC 2088 (`LITERAL+` или `LITERAL-`), команда `APPEND` отправляет длину с плюсом `{size+}\r\n` и MIME-тело сообщения **в одном TLS-буфере за 1 RTT** без ожидания синхронизирующего ответа `+ go ahead`.
* На серверах без поддержки `LITERAL+` (например, `imap.mail.ru`) клиент автоматически сохраняет надежный 2-шаговый протокол с ожиданием `+`.

#### 3.10. Определение базового максимального UID (`UID FETCH * (UID)`)
* **Проблема:** Если при подключении к папкам (`Drafts` или `Notes`) воркер начинает выборку с фиксированного `last_seen_uid = 0` (запрос `UID FETCH 1:*`), он вынужден скачивать и парсить тысячи старых сообщений от предыдущих запусков, что блокирует data plane на несколько минут и перегружает канал.
* **Решение:** Сразу после выполнения `SELECT "<Folder>"` воркер выполняет легковесный запрос `UID FETCH * (UID)` (занимает ~50 мс). Максимальный полученный номер принимается за базовый `last_seen_uid = current_max_uid`. Текущая сессия обрабатывает строго новые пакеты с `UID > current_max_uid`.

### 3.11. Результаты 30-минутного High-Throughput стресс-тестирования (128 КБ батчи)
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

            let (tx_router, mut rx_router) = tokio::sync::mpsc::channel::<Bytes>(tx_queue_capacity);
            worker_ctx.registry.finalize_client(&assigned_ip, tx_router);

            let writer_tx = worker_ctx.notes_append_tx.clone();
            let c_info = client_info.clone();
            tokio::spawn(async move {
                // Задача Downlink: собирает пакеты из rx_router в PacketBatcher с приоритизацией QoS,
                // шифрует одним вызовом wrap_packet_slice (до 128..512 КБ) и передает через APPEND в "Notes"
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
        "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:\
         ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
         DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:\
         ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
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
   * `internal_router` разделяется на `(reader, writer)`: накопитель `PacketBatcher` с поддержкой QoS выгребает пакеты из `reader` и отправляет через `CLI_WRITER (APPEND "Drafts")`, а `CLI_READER (IDLE/FETCH "Notes")` распаковывает входящие батчи и инжектирует пакеты в `writer`.
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
# Интервал перевхода в IDLE (keepalive) в состоянии покоя (мс).
# По умолчанию: 10000 мс (10 секунд).
idle_refresh_interval_ms = 10000

# Короткий интервал удержания IDLE во время активного обмена трафиком (мс).
# Исключает 5–10 секундные провалы скорости при попадании уведомления EXISTS в «Слепое окно».
idle_active_poll_ms = 400

# Время удержания быстрого режима опроса (idle_active_poll_ms) после последнего переданного/принятого пакета (мс).
idle_active_window_ms = 5000

# Таймаут ожидания ответа на команду IMAP (LOGIN, CAPABILITY, SELECT, APPEND, FETCH, STORE, EXPUNGE) (мс).
# По умолчанию: 15000 мс (15 секунд).
command_timeout_ms = 15000

# Максимальная задержка накопления микро-батча перед первым APPEND (мс).
# По умолчанию: 15 мс.
batch_coalesce_ms = 15

# Максимальный размер одного зашифрованного пакета-черновика (КБ, от 4 до 512 КБ без переполнения u16).
# По умолчанию: 128 КБ.
max_batch_kb = 128

# Порог накопления прочитанных писем для ленивого пакетного удаления (UID STORE +FLAGS.SILENT (\Deleted) + UID EXPUNGE).
expunge_batch_size = 25

# Пауза отсутствия новых входящих писем перед фоновой очисткой накопленных прочитанных UID (мс).
expunge_idle_delay_ms = 1500

# Максимальное окно неподтвержденных батчей в полете до срабатывания Backpressure.
max_inflight_batches = 35

# Емкость очереди bulk-пакетов из TUN (защита от Bufferbloat при пиковых всплесках).
tx_queue_capacity = 256

# Автоматическое определение поддержки расширения LITERAL+ (1-RTT APPEND) при подключении.
literal_plus_auto = true

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

# Интервал перевхода серверного воркера в IDLE в состоянии покоя (без активного трафика) (мс).
# По умолчанию: 10000 мс (10 секунд).
idle_refresh_interval_ms = 10000

# Короткий интервал удержания IDLE во время активного обмена трафиком (мс).
idle_active_poll_ms = 400

# Время удержания быстрого режима опроса (idle_active_poll_ms) после последнего переданного/принятого пакета (мс).
idle_active_window_ms = 5000

# Таймаут ожидания команды IMAP (мс).
# По умолчанию: 15000 мс (15 секунд).
command_timeout_ms = 15000

# Интервал проверки и очистки зависших сессий (мс).
# По умолчанию: 30000 мс (30 секунд).
cleanup_interval_ms = 30000

# Максимальный размер одного зашифрованного пакета-черновика (КБ, от 4 до 512 КБ без переполнения u16).
# По умолчанию: 128 КБ.
max_batch_kb = 128

# Задержка микро-коалесценции батчера перед отправкой первого письма (мс, 5..100).
batch_coalesce_ms = 15

# Порог накопления прочитанных писем для ленивого пакетного удаления (UID STORE +FLAGS.SILENT (\Deleted) + UID EXPUNGE).
expunge_batch_size = 25

# Пауза отсутствия новых входящих писем перед фоновой очисткой накопленных прочитанных UID (мс).
expunge_idle_delay_ms = 1500

# Максимальное окно неподтвержденных батчей в полете до срабатывания Backpressure.
max_inflight_batches = 35

# Емкость очереди клиентского Downlink-роутера (защита от Bufferbloat).
tx_queue_capacity = 256

# Автоматическое определение поддержки расширения LITERAL+ (1-RTT APPEND) при подключении.
literal_plus_auto = true

# Таймаут отката при рейт-лимитах провайдера (мс).
# По умолчанию: 30000 мс (30 секунд).
throttle_backoff_ms = 30000
```

---

## 8. Строгие директивы для ИИ-агента при написании Rust-кода

1. **BoringSSL Only (Никакого `rustls` на 993 порту):** Устанавливать TCP-соединение через `TcpStream::connect`, оборачивать его через `anet_common::boring_tls::connect_email_tls_with_config(&host, tcp_stream, &tls_cfg)`.
2. **Архитектура «Cross-Selected Writer»:**
   * На сервере и `SRV_READER`, и `SRV_WRITER` делают `SELECT "Drafts"`. `SRV_WRITER` выполняет `APPEND "Notes" (\Seen \Draft) {<len>}` и чистит прочитанные UIDs в `"Drafts"`.
   * На клиенте и `CLI_READER`, и `CLI_WRITER` делают `SELECT "Notes"`. `CLI_WRITER` выполняет `APPEND "Drafts" (\Seen \Draft) {<len>}` и чистит прочитанные UIDs в `"Notes"`.
3. **Защита от «Слепого окна» (`pending_exists`) и адаптивный Short-IDLE:** В методе чтения строк из сокета любая строка `^\*\s+\d+\s+EXISTS` обязана взводить `self.pending_exists = true`. В активном окне обмена трафиком IDLE удерживается короткими интервалами `400 мс` (`wait_idle_or_wake`), а при отправке локальным Writer'ом передается сигнал пробуждения через `tokio::sync::Notify`. При взведенном `pending_exists` следующий `FETCH` запускается немедленно (Greedy Drain).
4. **Чтение строго по `UID FETCH <last_uid + 1>:* (UID BODY.PEEK[])`:** Никогда не использовать `SEARCH` или `RFC822.PEEK` (Mail.ru возвращает BAD). Запрашивать `BODY.PEEK[]`, побайтово считывать литерал через `read_exact(len)`, извлекать `UID` из хвоста строки ответа (у Mail.ru токен `UID <id>` передается **после** литерала тела), парсить тело прямым бинарным поиском `\r\n\r\n` без преобразования в `utf-8` строку, игнорировать элементы с `uid <= last_uid` и обновлять `last_uid = last_uid.max(uid)`.
5. **QoS Fast-Lane и Self-Clocking Batcher:** В `PacketBatcher` выделена приоритетная очередь для ICMP, внутритуннельных зондов 0x414E, DNS (53/853), TCP SYN/FIN/RST/ACK и мелких пакетов $\le 256$ байт. Приоритетные пакеты всегда кладутся в начало батча. Первый пакет отправляется с микро-задержкой коалесценции не более `15 мс`, а крупные объемы (до 128..512 КБ) коалесцируются в очереди, пока текущий `APPEND` выполняется по сети.
6. **Поддержка батчей > 64 КБ (`LARGE_PACKET_LEN_SENTINEL`):** При размере буфера $\ge 65535$ байт в поле длины ASTP записывается `0xFFFF`, а фактическая длина извлекается из `plaintext_len - 10`.
7. **Ленивый пакетный `UID EXPUNGE`:** Не слать `STORE + EXPUNGE` после каждого письма. Накапливать прочитанные UID и вычищать их пачками по `expunge_batch_size = 25`, либо при простое более `1500 мс`, либо в момент, когда очередь передачи пуста.
8. **Автодетект `LITERAL+`:** По отклику команды `CAPABILITY` после `LOGIN` проверять поддержку `LITERAL+`/`LITERAL-`. Если поддерживается — выполнять `APPEND` в 1 RTT (`{len+}\r\n<body_bytes>`), экономя один сетевой round-trip на каждую отправку.
9. **Управление переполнением (Backpressure) и защита от Bufferbloat:** Ограничивать окно неподтвержденных батчей `max_inflight_batches = 35` (с паузой 40 мс при насыщении), ограничивать буферы очередей TUN `tx_queue_capacity = 256`.
10. **Active-Active Multi-Mailbox Striping & Self-Healing (Клиент):** Если в `dsn` передано $N \ge 2$ почтовых ящиков (`?acc=box1&acc=box2...`), клиент выполняет первичный ASTP-хендшейк через первый доступный ящик для получения единого `session_id`, `assigned_ip`, `cipher` и `nonce_prefix`, после чего параллельно поднимает пары воркеров (`CLI_WRITER[i]` + `CLI_READER[i]`) на всех $N$ ящиках. Исходящие батчи распределяются диспетчером по всем здоровым `CLI_WRITER[i]` в режиме **Self-Clocking Round-Robin** (первый свободный слот по кругу). Отказ одного ящика изолированно переводит только его воркер в фоновый реконнект без прерывания потока данных на оставшихся $N - 1$ ящиках; полный `Session Resume` запускается только при одновременной недоступности всех $N$ ящиков.
11. **Мультиплексирование, Dynamic Mailbox Affinity и Downlink Round-Robin (Сервер):** Сервер спавнит независимые пары воркеров (`SRV_READER[i]` + `SRV_WRITER[i]`) для каждого почтового ящика из `imap_dsn` параллельно, разделяя единый `ClientRegistry` и карту `session_mailboxes`. Каналы `notes_auth_tx`/`notes_data_tx` и буфер `pending_retry_msg` создаются **вне** цикла переподключения IMAP-воркера, благодаря чему клиентские задачи `run_client_downlink_batcher` и не успевший уйти перед обрывом сокета батч переживают переподключение `SRV_READER`/`SRV_WRITER` без потери Downlink-маршрутизации. При получении криптографически валидного пакета сессии `session_id` на ящике $i$ сервер автоматически регистрирует `notes_data_tx[i]` в активном пуле ящиков этой сессии (`SessionMailboxPool`), а `run_client_downlink_batcher` балансирует Downlink-батчи по всем активным здоровым ящикам клиента в режиме **Self-Clocking Round-Robin**.
12. **Инициализация базового UID (`UID FETCH * (UID)`):** Сразу после `SELECT` выполнять быстрый запрос максимального UID в папке и начинать выборку строго с `last_seen_uid = current_max_uid`, предотвращая загрузку сотен мегабайт исторических сообщений прошлых сессий.
13. **Разделение пространств AEAD-нонсов C2S и S2C (`CLIENT_SEQUENCE_START`):** Поскольку `Uplink` (клиент $\to$ сервер) и `Downlink` (сервер $\to$ клиент) используют общий сессионный ключ `shared_key` и 4-байтовый `nonce_prefix`, счётчик пакетов клиента инициализируется с установленным старшим битом `CLIENT_SEQUENCE_START = 1u64 << 63` (`0x8000_0000_0000_0000`), а счётчик сервера — с `SERVER_SEQUENCE_START = 0`. Это гарантирует нулевое пересечение пар `(Key, Nonce)` в ChaCha20-Poly1305 при сохранении 100% совместимости с форматом заголовка ASTP.
14. **Защита `fetch_messages_robust` от зависаний, `NO/BAD` и OOM:**
    * Тегированные ответы `{tag} NO` и `{tag} BAD` на команду `UID FETCH` немедленно возвращают `Err(...)` для запуска цикла переподключения/Failover (вместо молчаливого возврата пустого списка).
    * Размер литерала `{len}` жестко ограничен константой `MAX_IMAP_LITERAL_BYTES = 2 МиБ` (защита от OOM и блокировки потока при попадании в ящик стороннего письма с крупным вложением).
    * Чтение тела литерала (`read_exact`) и хвостовой строки (`read_line`) строго ограничено общим `deadline` команды `timeout_dur`.
15. **Адаптация `ConnectivityMonitor` / `ConnectivityProber` под высоколатентный туннель:**
    * При поднятии VPN монитор связности даёт до `1200 мс` форы легковесному внутритуннельному ICMP-пингу (`0x414E`) до запуска параллельных HTTPS-проверок.
    * При `tunnel_rtt >= 300 мс` (или отсутствии ICMP-отклика за 1200 мс) таймаут `ConnectivityProber::probe_group` расширяется до `8000..12000 мс` (верхний предел `per_target_timeout` поднят до `15000 мс`), повторный «тёплый» HTTP-запрос (`warm_req`) отключается при `first_ms >= 500 мс`, а интервал фонового опроса автоматически увеличивается минимум до `45 секунд`.

---

## 9. Архитектура Active-Active Multi-Mailbox Round-Robin / Striping (Масштабирование полосы и снижение RTT пулом ящиков)

### 9.1. Физика узкого места одиночного ящика и математическая модель пула $N$ ящиков
На публичных почтовых серверах (`imap.mail.ru:993`, `imap.yandex.ru:993`) каждая команда `APPEND` требует эксклюзивной блокировки индекса папки конкретного почтового аккаунта (`mailbox lock`) и синхронного сброса данных на диск (`fsync`).
* В результате медианное время выполнения одного `APPEND` составляет $T_{\text{append}} \approx 320\text{–}450\text{ мс}$ (до `700 мс` на 128 КБ батчах с Base64).
* При работе через **один** почтовый ящик (`N = 1`, либо при использовании остальных ящиков из `imap_dsn` только в качестве холодного резерва `Active-Passive Failover`):
  1. **Потолок частоты батчей:** один `Writer` физически не может выполнять более $\approx 1.5\text{–}2.5$ операций `APPEND` в секунду ($\sim 0.8\text{–}1.5\text{ Мбит/с}$).
  2. **Head-of-Line (HoL) блокировка интерактивного трафика:** если крупный батч только что ушёл в `APPEND` на $450\text{ мс}$, любой пришедший следом приоритетный пакет (ICMP, DNS, TCP SYN/ACK) вынужден ждать освобождения единственного сокета записи в среднем $T_{\text{wait}} = \frac{T_{\text{append}}}{2} \approx 225\text{ мс}$.
  3. **Простой серверных воркеров:** на стороне `anet-server` функция `run_imap_server` изначально поднимает независимые воркеры для всех ящиков из `imap_dsn`, но при `Active-Passive` клиенте $N - 1$ серверных воркеров простаивают впустую.

При объединении $N$ почтовых ящиков из `imap_dsn` (`?acc=box1:pass1&acc=box2:pass2&...&acc=boxN:passN`) в **Active-Active пул с параллельным страйпингом (Self-Clocking Round-Robin)** достигается:
1. **Линейное масштабирование пропускной способности ($N\times$):**
   Независимые почтовые аккаунты обслуживаются разными шардами хранилища почтового провайдера и имеют раздельные `mailbox lock` и анти-спам счётчики. Суммарная частота записи возрастает до $N \times \frac{1}{T_{\text{append}}}$ батчей/с:
   * $N = 1$: $\sim 0.8\text{–}1.2\text{ Мбит/с}$
   * $N = 2$: $\sim 1.6\text{–}2.4\text{ Мбит/с}$
   * $N = 3$: $\sim 2.4\text{–}3.6\text{ Мбит/с}$
   * $N = 4$: $\sim 3.2\text{–}4.8\text{ Мбит/с}$
2. **Кратное снижение джиттера и задержки ожидания ($\div N$):**
   Пока `Writer #0` ждёт ответа `OK [APPENDUID ...]` от первого ящика, `Writer #1` свободен и немедленно отправляет следующий батч через второй ящик. Среднее время ожидания свободного канала записи сокращается до:
   $$T_{\text{wait}}(N) \approx \frac{T_{\text{append}}}{2 \cdot N}$$
3. **Кратное снижение риска `NO [THROTTLED]` / `NO [OVERQUOTA]`:**
   При фиксированной скорости потока частота операций `APPEND` и `UID EXPUNGE` на каждый отдельный ящик падает в $N$ раз.

---

### 9.2. Топология потоков данных при Active-Active страйпинге ($N$ ящиков)

```text
                       КЛИЕНТ (anet-client-core)                                   СЕРВЕР (anet-server)
+-------------------------------------------------------------------+     +-------------------------------------------------------------------+
| TUN -> FrameReader -> [prio_rx / bulk_rx]                         |     |ClientRegistry (assigned_ip -> tx_router -> rx_router)             |
|                              |                                    |     |                              |                                    |
|                     +--------v--------+                           |     |                     +--------v--------+                           |
|                     | Uplink Batcher  | (Единый PacketBatcher     |     |                     | DownlinkBatcher | (Единый PacketBatcher     |
|                     |  & RR Dispatch  |  + общий AtomicU64 seq)   |     |                     |  & RR Dispatch  |  + общий AtomicU64 seq)   |
|                     +--+-----+-----+--+                           |     |                     +--+-----+-----+--+                           |
|                        |     |     |  Self-Clocking Round-Robin   |     |                        |     |     |  Self-Clocking Round-Robin   |
|       +----------------+     |     +----------------+             |     |       +----------------+     |     +----------------+             |
|       v                      v                      v             |     |       v                      v                      v             |
| [CLI_WRITER #0]        [CLI_WRITER #1]        [CLI_WRITER #N-1]   |     | [SRV_WRITER #0]        [SRV_WRITER #1]        [SRV_WRITER #N-1]   |
| APPEND "Drafts"        APPEND "Drafts"        APPEND "Drafts"     |     | APPEND "Notes"         APPEND "Notes"         APPEND "Notes"      |
| (box1@mail.ru)         (box2@mail.ru)         (boxN@mail.ru)      |     | (box1@mail.ru)         (box2@mail.ru)         (boxN@mail.ru)      |
+-------+----------------------+----------------------+-------------+     +-------+----------------------+----------------------+-------------+
        |                      |                      |                           |                      |                      |
        |   IMAPS :993         |   IMAPS :993         |   IMAPS :993              |   IMAPS :993         |   IMAPS :993         |   IMAPS :993
        v                      v                      v                           v                      v                      v
+-------+----------------------+----------------------+-------------+     +-------+----------------------+----------------------+-------------+
| [SRV_READER #0]        [SRV_READER #1]        [SRV_READER #N-1]   |     | [CLI_READER #0]        [CLI_READER #1]        [CLI_READER #N-1]   |
| IDLE/FETCH "Drafts"    IDLE/FETCH "Drafts"    IDLE/FETCH "Drafts" |     | IDLE/FETCH "Notes"     IDLE/FETCH "Notes"     IDLE/FETCH "Notes"  |
|       |                      |                      |             |     |       |                      |                      |             |
|       +----------------+     |     +----------------+             |     |       +----------------+     |     +----------------+             |
|                        v     v     v                              |     |                        v     v     v                              |
|                 Общий tun_tx -> Server TUN                        |     |               Общий downlink_tun_tx -> Client TUN                 |
+-------------------------------------------------------------------+     +-------------------------------------------------------------------+
```

---

### 9.3. Жизненный цикл сессии и криптографическая синхронизация

#### 9.3.1. Единый ASTP-хендшейк через Primary-ящик (Без дублирования IP и сессий)
Клиент **не выполняет** $N$ отдельных ASTP-рукопожатий и не запрашивает $N$ виртуальных IP-адресов:
1. При вызове `ImapTransport::connect()` клиент перебирает `accounts[0..N]` до первого успешно ответившего ящика `primary_idx` и выполняет на нём полный 4-фазный ASTP-хендшейк через `establish_mailbox_session(...)`.
2. В результате хендшейка клиент получает единый криптографический контекст туннеля (`ActiveImapSessionState`):
   * `session_id: String` — уникальный идентификатор сессии в `ClientRegistry` сервера;
   * `assigned_ip: String` — выделенный клиенту IPv4-адрес внутри VPN;
   * `cipher: Arc<Cipher>` — общий сессионный шифр `ChaCha20Poly1305`;
   * `nonce_prefix: [u8; 4]` — 4-байтовый префикс нонса сессии;
   * `sequence: Arc<AtomicU64>` — единый атомарный счётчик исходящих батчей клиента, инициализированный значением `CLIENT_SEQUENCE_START` (`1u64 << 63`).

#### 9.3.2. Безопасность при параллельной и внепорядковой доставке (Out-of-Order AEAD Safety)
Поскольку батчи $k$ и $k+1$ отправляются параллельно через разные почтовые ящики (например, `box1` и `box2`), батч $k+1$ может быть прочитан принимающей стороной раньше батча $k$:
* В протоколе ASTP (`anet-common/src/transport.rs`) функция `wrap_packet_slice(&cipher, &nonce_prefix, seq, &raw_batch, 0)` формирует 12-байтный нонс `[nonce_prefix (4 B) | seq.to_be_bytes() (8 B)]` и **явно записывает его в первые 12 байт заголовка пакета**.
* Принимающая сторона в `unwrap_packet(&cipher, &payload)` извлекает 12-байтный нонс непосредственно из заголовка пришедшего батча и верифицирует 16-байтный тег `Poly1305` без привязки к порядку прихода пакетов.
* Атомарное приращение `sequence.fetch_add(1, Ordering::Relaxed)` перед каждым `wrap_packet_slice` гарантирует абсолютную уникальность нонса каждого батча независимо от того, какой именно воркер (`#0..#N-1`) выполняет отправку.
* Стек TCP и QUIC внутри TUN-интерфейса штатно обрабатывает переупорядочивание IP-пакетов в пределах окна нескольких сотен миллисекунд, а благодаря уменьшению джиттера в $N$ раз итоговый TCP RTT и число дублирующихся ACK существенно снижаются.

#### 9.3.3. Подключение вторичных ящиков (`Secondary Mailbox Workers`) и `Mailbox Binding Frame`
Сразу после успешного рукопожатия на `primary_idx`:
1. Ящик `primary_idx` немедленно переводится в рабочий режим Data Plane (пакеты начинают ходить с нулевой задержкой).
2. Для всех остальных ящиков $i \in \{0 \dots N-1\} \setminus \{\text{primary\_idx}\}$ параллельно запускаются фоновые задачи инициализации `connect_data_only_mailbox_pair(...)`:
   * Подключается `CLI_WRITER[i]` $\to$ `SELECT "Notes"`;
   * Подключается `CLI_READER[i]` $\to$ `SELECT "Notes"` $\to$ запрашивается `initial_max_uid = cli_reader.get_max_uid()`;
   * Все IP-адреса сокетов заранее добавляются в `bypass_ips` при резолвинге хоста.
3. **Анонсирование ящика серверу (`Mailbox Binding Frame`):**
   * Чтобы сервер узнал, что клиент с данным `session_id` теперь активно слушает папку `"Notes"` и на ящике $i$ (даже если клиент в этот момент только скачивает данные и не шлёт Uplink-трафик), `CLI_WRITER[i]` сразу после подключения отправляет в `"Drafts"` ящика $i$ один легковесный управляющий фрейм привязки — пустой зашифрованный ASTP-батч:
     ```rust
     let seq = sequence.fetch_add(1, Ordering::Relaxed);
     let binding_frame = wrap_packet_slice(&cipher, &nonce_prefix, seq, &[], 0)?;
     let subject = format!("ANet-Data [ID: {}:{}]", srv_id, session_id);
     cli_writer.append_message("Drafts", &subject, &binding_frame, &account.email, command_timeout).await?;
     ```
   * На сервере `SRV_READER[i]` ящика $i$ получает письмо с `[ID: <srv_id>:<session_id>]`, успешно проверяет AEAD-тег через `unwrap_packet(&client_info.cipher, &msg.payload)` (распаковка `unpack_batch(&[])` даёт 0 IP-пакетов, ничего в TUN не пишется) и **мгновенно регистрирует ящик $i$ в пуле активных Downlink-каналов этой сессии**!

---

### 9.4. Детальная архитектура Клиента (`anet-client-core/src/transport/imap.rs`)

#### 9.4.1. Строгое разделение глобального состояния сессии и локального состояния ящика
Поскольку нумерация `UID` писем в папке `"Notes"` у каждого почтового ящика `box1..boxN` своя собственная, структуры данных делятся на два уровня:

1. **Глобальное состояние туннеля (`SharedImapTunnelState`, единое на все $N$ ящиков):**
   ```rust
   struct ActiveImapSessionState {
       pub session_id: String,
       pub cipher: Arc<Cipher>,
       pub nonce_prefix: [u8; 4],
   }

   /// Готовый к отправке зашифрованный батч Uplink
   struct EncryptedUplinkBatch {
       pub session_id: String,
       pub encrypted_payload: Bytes,
   }
   ```
   * `session_state: Arc<RwLock<ActiveImapSessionState>>` — текущий ключ и `session_id`;
   * `sequence: Arc<AtomicU64>` — общий счётчик исходящих батчей (`CLIENT_SEQUENCE_START`);
   * `downlink_tun_tx: mpsc::Sender<Bytes>` — общий канал, куда все $N$ задач `CLI_READER[i]` отправляют расфреймированные IP-пакеты для записи в `tunnel_write` единой задачей `tun_writer_task`;
   * `retry_uplink_tx / retry_uplink_rx` — канал возврата батча: если `CLI_WRITER[i]` получил сетевую ошибку во время `APPEND`, он возвращает `EncryptedUplinkBatch` обратно диспетчеру, который мгновенно перенаправляет его через другой живой ящик $j \ne i$ без потери ни одного пакета!

2. **Локальное состояние воркера конкретного ящика (`ClientMailboxWorker`, изолированное для каждого $i \in 0..N$):**
   ```rust
   struct ClientMailboxSlot {
       pub index: usize,
       pub account: ImapAccount,
       /// Канал ёмкостью 1 для передачи зашифрованного батча от центрального диспетчера конкретному CLI_WRITER[i]
       pub uplink_tx: mpsc::Sender<EncryptedUplinkBatch>,
       /// Флаг готовности и здоровья пары (CLI_WRITER[i] + CLI_READER[i])
       pub healthy: Arc<AtomicBool>,
       /// Локальный счётчик неподтверждённых батчей именно этого ящика
       pub inflight: Arc<AtomicUsize>,
   }
   ```
   Внутри каждого воркера ящика $i$ хранятся **только его собственные**:
   * `last_seen_uid: u32` — последний прочитанный `UID` в папке `"Notes"` ящика $i$;
   * `cleanup_uids: Arc<Mutex<Vec<u32>>>` — список прочитанных `UID` в `"Notes"` ящика $i$, который очищается через `UID STORE` + `UID EXPUNGE` исключительно `CLI_WRITER[i]` этого же ящика!

#### 9.4.2. Алгоритм центрального диспетчера Uplink (`Self-Clocking Round-Robin Uplink Dispatcher`)
Вместо того чтобы раздавать сырые пакеты по разным `PacketBatcher` заранее (что привело бы к застреванию пакетов в очереди медленного ящика), на клиенте работает **один центральный `UplinkDispatcher`**, владеющий `prio_rx`, `bulk_rx` и единым `PacketBatcher`:

1. **Коалесценция стартового бурста:**
   Диспетчер ждёт первый пакет из `prio_rx` или `bulk_rx` (или проверяет `retry_uplink_rx`) и добирает пакеты в течение микро-окна `coalesce_ms` (`15 мс`).
2. **Фаза 1 диспетчеризации — Мгновенный неблокирующий Round-Robin (`Fast Path`):**
   Диспетчер проверяет $N$ слотов начиная с курсора `rr_cursor`:
   ```rust
   let mut selected_permit = None;
   for offset in 0..slots.len() {
       let idx = (rr_cursor + offset) % slots.len();
       let slot = &slots[idx];
       if !slot.healthy.load(Ordering::Acquire) {
           continue;
       }
       if slot.inflight.load(Ordering::Relaxed) >= max_inflight_batches {
           continue;
       }
       if let Ok(permit) = slot.uplink_tx.clone().try_reserve_owned() {
           rr_cursor = (idx + 1) % slots.len();
           selected_permit = Some((idx, permit));
           break;
       }
   }
   ```
3. **Фаза 2 диспетчеризации — Ожидание первого освободившегося воркера (`All-Busy Self-Clocking Path`):**
   Если в данный момент все здоровые воркеры заняты выполнением `APPEND` (`selected_permit.is_none()`):
   * Диспетчер собирает фьючерсы `slot.uplink_tx.clone().reserve_owned()` для всех здоровых слотов (в порядке от `rr_cursor`) и ожидает **первого завершившегося** через `futures::future::select_all(...)`.
   * **Критическое преимущество:** Пока все $N$ ящиков заняты в сети, новые пакеты из TUN не отправляются полупустыми, а продолжают накапливаться в `prio_rx` и `bulk_rx`!
   * Как только самый быстрый из $N$ ящиков завершил свой `APPEND` и освободил `reserve_owned()`, диспетчер **добирает все накопившиеся за это время пакеты** из `prio_rx` и `bulk_rx` до `max_batch_bytes` (приоритетные ICMP/DNS/ACK всегда встают в начало батча), шифрует весь буфер одним вызовом `wrap_packet_slice` и отправляет готовый `EncryptedUplinkBatch` именно в этот освободившийся `OwnedPermit`!

#### 9.4.3. Изолированное самовосстановление ящиков (`Per-Mailbox Auto-Heal` vs `Full Session Failover`)
* Если на ящике $i$ возникает ошибка `APPEND`, `UID FETCH` или `UID EXPUNGE`:
  1. Воркер ящика $i$ немедленно выставляет `slot.healthy.store(false, Ordering::Release)`.
  2. Если в руках у `CLI_WRITER[i]` был неотправленный `EncryptedUplinkBatch`, он передаёт его в `retry_uplink_tx`, и диспетчер тут же отправляет его через соседний здоровый ящик $j \ne i$.
  3. Пока хотя бы один другой ящик в пуле остаётся здоровым (`slots.iter().any(|s| s.healthy.load(Ordering::Acquire))`), **туннель не прерывается ни на миллисекунду**, а воркер ящика $i$ в собственной фоновой задаче ждёт паузу (`2000 мс` при сетевом обрыве или `throttle_backoff` при `THROTTLED`/`OVERQUOTA`), переподключает `CLI_WRITER[i]` + `CLI_READER[i]`, отправляет `Mailbox Binding Frame` и возвращает `slot.healthy.store(true, Ordering::Release)`.
* Если же **все $N$ ящиков одновременно** потеряли связь (`healthy == false` у всех слотов), активируется глобальный координатор восстановления сессии с `resume_session_id`, который заново проходит `establish_mailbox_session` на первом ожившем ящике и обновляет `ActiveImapSessionState`.

---

### 9.5. Детальная архитектура Сервера (`anet-server/src/servers/imap.rs`)

#### 9.5.1. Проблема привязки ящиков на сервере и почему нельзя слепо слать во все ящики `imap_dsn`
На сервере в `server.toml` (`imap_dsn`) может быть сконфигурирован общий пул из $M$ почтовых ящиков (например, 6 ящиков для разных пулов в `anet-auth`), из которых конкретному клиенту выданы $N \le M$ ящиков (например, 2 или 3 ящика).
Кроме того, в существующей одноящичной реализации при завершении рукопожатия на ящике `box1` сервер запускал `run_client_downlink_batcher` с жёстко привязанным `notes_data_tx` только одного ящика `box1`, из-за чего весь Downlink шёл в один поток.

#### 9.5.2. Динамический пул ящиков клиентской сессии (`SessionMailboxPool` / Dynamic Affinity)
Для каждой активной клиентской сессии `session_id` на сервере создаётся потокобезопасный реестр подтверждённых ящиков этого клиента:

```rust
#[derive(Clone)]
pub struct ServerMailboxHandle {
    pub mailbox_idx: usize,
    pub email: String,
    pub notes_data_tx: mpsc::Sender<DownlinkMessage>,
    pub healthy: Arc<AtomicBool>,
    pub inflight: Arc<AtomicUsize>,
}

pub struct SessionMailboxPool {
    /// Список ящиков, с которых данный session_id прислал криптографически валидные пакеты
    pub active_mailboxes: RwLock<Vec<ServerMailboxHandle>>,
    /// Курсор Round-Robin для балансировки Downlink-батчей этой сессии
    pub rr_cursor: AtomicUsize,
    /// Сигнал о добавлении нового ящика в пул сессии
    pub pool_updated: Notify,
}
```

**Как работает привязка и маршрутизация на сервере:**
1. **Инициализация пула воркеров сервера (`run_imap_server`):**
   * При старте каждого `run_mailbox_worker_pair(mailbox_idx, ...)` создаются долговечные каналы `notes_auth_tx` и `notes_data_tx` и дескриптор `ServerMailboxHandle` с флагом `healthy: Arc<AtomicBool>`.
   * Когда `SRV_READER` и `SRV_WRITER` успешно подключились и выполнили `SELECT "Drafts"`, воркер выставляет `healthy.store(true, Ordering::Release)`. При обрыве соединения и уходе на реконнект флаг временно сбрасывается в `false`.
2. **Регистрация первого ящика при ASTP Handshake (Фаза 3):**
   * Когда клиент завершает Фазу 3 рукопожатия на ящике `M_primary`, сервер создаёт `SessionMailboxPool`, сразу добавляет в него `ServerMailboxHandle` ящика `M_primary`, сохраняет `Arc<SessionMailboxPool>` в глобальной карте `session_pools: Arc<DashMap<String, Arc<SessionMailboxPool>>>` и запускает одну задачу `run_client_downlink_batcher(rx_router, client_info, session_pool, ...)`.
3. **Автоматическое подключение дополнительных ящиков ($M_1 \dots M_{N-1}$) по входящему Uplink / Binding Frame:**
   * Когда `SRV_READER` любого другого ящика `M_i` получает сообщение в `"Drafts"` с темой `[ID: <srv_id>:<session_id>]` и **успешно расшифровывает его** через `unwrap_packet(&client_info.cipher, &msg.payload)`:
   * Воркер `M_i` проверяет `session_pools.get(session_id)`: если `mailbox_idx` ящика `M_i` ещё не входит в `session_pool.active_mailboxes`, он добавляет свой `ServerMailboxHandle` в `active_mailboxes` и вызывает `session_pool.pool_updated.notify_waiters()`!
   * Если расшифрованный батч содержал `0` IP-пакетов (`Mailbox Binding Frame`), `SRV_READER` просто фиксирует привязку ящика и обновляет `touch_client(&client_info)` без записи в `tun_tx`. Если батч содержал IP-пакеты — они штатно отправляются в `tun_tx`.
4. **Бесшовное обновление при `resume_session_id`:**
   * Если клиент переподключился с `resume_session_id`, сервер не убивает существующий `SessionMailboxPool`, а обновляет список его активных ящиков по мере прихода новых пакетов с новым ключом.

#### 9.5.3. Балансировка Downlink в `run_client_downlink_batcher` на сервере
Задача `run_client_downlink_batcher` для клиента работает по точно такому же алгоритму **Self-Clocking Round-Robin**, как и клиентский Uplink-диспетчер:
1. Собирает стартовый пакет из `rx_router` и ждёт микро-окно `coalesce_ms` (`15 мс`).
2. Читает текущий список `handles = session_pool.active_mailboxes.read().await.clone()`.
3. **Fast Path (Неблокирующий Round-Robin):**
   Ищет первый здоровый ящик (`handle.healthy.load(Ordering::Acquire)`), у которого свободен канал `handle.notes_data_tx.clone().try_reserve_owned()`, начиная с `rr_cursor = session_pool.rr_cursor.fetch_add(1, Ordering::Relaxed) % handles.len()`.
4. **All-Busy Path (Гонка `select_all` по всем активным ящикам клиента):**
   Если все привязанные ящики клиента сейчас заняты выполнением `APPEND "Notes"`, батчер ждёт освобождения **первого любого** из здоровых `notes_data_tx` через `futures::future::select_all` (параллельно слушая `session_pool.pool_updated.notified()`, чтобы мгновенно подхватить только что привязавшийся новый ящик!).
5. В момент получения `OwnedPermit` от первого освободившегося `SRV_WRITER[k]`, батчер добирает из `rx_router` все накопившиеся за время ожидания пакеты до `max_batch_bytes`, шифрует их одним вызовом `wrap_packet_slice` (с атомарным `client_info.sequence.fetch_add(1, Ordering::Relaxed)`) и отправляет в `permit.send(DownlinkMessage { subject, payload })`.

---

### 9.6. План верификации и модульного тестирования (Unit & Integration Tests)

При реализации раздела 9 в кодовую базу обязательно добавляются следующие автоматические тесты:
1. **`test_multi_mailbox_uplink_round_robin_distribution` (`anet-client-core`):**
   * Проверяет, что при наличии $N = 3$ здоровых слотов `ClientMailboxSlot` последовательные батчи распределяются диспетчером равномерно (`0 -> 1 -> 2 -> 0 -> 1 -> 2`).
2. **`test_multi_mailbox_self_clocking_bypass_slow_worker` (`anet-client-core` & `anet-server`):**
   * Имитирует ситуацию, когда ящик `#0` заблокирован долгим `APPEND` (`500 мс`), а ящики `#1` и `#2` освобождаются каждые `50 мс`. Проверяет, что диспетчер не блокируется на ящике `#0`, а прокачивает все очереди через ящики `#1` и `#2` без простоев.
3. **`test_multi_mailbox_zero_loss_on_single_worker_failure` (`anet-client-core`):**
   * Имитирует обрыв `APPEND` на ящике `#1` во время передачи батча. Проверяет, что `EncryptedUplinkBatch` возвращается через `retry_uplink_tx` и мгновенно доставляется через ящик `#2` без потерь и без разрыва VPN-сессии.
4. **`test_server_session_mailbox_pool_dynamic_binding_and_striping` (`anet-server/src/servers/imap.rs`):**
   * Проверяет регистрацию `M_0` при хендшейке, динамическое добавление `M_1` и `M_2` при приходе `Mailbox Binding Frame` (`wrap_packet_slice(..., &[], 0)`), и равномерную балансировку Downlink-трафика по всем 3 ящикам с выживанием при отключении любого из воркеров.

````
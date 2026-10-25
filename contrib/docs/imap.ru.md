# Архитектура и спецификация транспорта `imap` (ASTP over IMAP)

Документация актуальна для ветки `master`.

## 1. Введение и концепция
Транспорт `imap` — это специализированный транспорт повышенной отказоустойчивости (High Resilience Transport). Он спроектирован для обеспечения стабильной связи в сетях со сложной топологией, строгими корпоративными политиками маршрутизации (Default Deny) и системами глубокой инспекции пакетов (IDS/IPS), где традиционные протоколы работают нестабильно, но сохраняется приоритетный доступ к базовым корпоративным сервисам (электронной почте).

Транспорт инкапсулирует зашифрованные IP-пакеты (ASTP) в текстовые сообщения (MIME/Base64) и передает их через инфраструктуру публичных почтовых провайдеров (Mail.ru, Timeweb) с использованием стандартных команд IMAP `APPEND`, `FETCH` и `IDLE`.

Для промежуточных узлов сетевой инфраструктуры обмен данными абсолютно неотличим от штатной сессии легитимного почтового клиента, синхронизирующего черновики по протоколу TLS 1.3 на порт 993.

## 2. Схема маршрутизации трафика (Data Flow)
Клиент и Сервер ANet не устанавливают прямого TCP/UDP соединения друг с другом. Оба узла выступают в роли IMAP-клиентов по отношению к почтовому провайдеру. Направления трафика (Uplink/Downlink) разнесены по разным папкам для предотвращения широковещательных коллизий.

```text
[UPLINK: Клиент -> Сервер]
+---------------+      1. IMAP APPEND (TLS:993)      +-------------------+
|  ANet Client  |      Folder: "Drafts"              |   IMAP Provider   |
| (Packet Batch)|===================================>| (e.g., Mail.ru)   |
+---------------+      Subject: {Prefix} [ID: SRV]   +-------------------+
                                                               |
                                                               | 2. IMAP IDLE Wakeup
                                                               |    SEARCH UNSEEN
                                                               V
                                                     +-------------------+
                                                     |    ANet Server    |
                                                     |  (IMAP Worker)    |
                                                     +-------------------+

[DOWNLINK: Сервер -> Клиент]
+---------------+      4. IMAP IDLE Wakeup           +-------------------+
|  ANet Client  |      SEARCH UNSEEN                 |   IMAP Provider   |
| (TUN Inject)  |<-----------------------------------| (e.g., Mail.ru)   |
+---------------+      Subject: {Prefix} [ID: Sess]  +-------------------+
          ^                                                    ^
          |                                                    | 3. IMAP APPEND
          +====================================================+ Folder: "Notes"
```

## 3. Обработка VPN-трафика (Data Plane)
После успешного прохождения криптографического рукопожатия (ASTP Handshake), транспорт переходит в режим передачи полезного трафика.

### 3.1. Клиентская часть
*   **Отправка (Uplink):** IP-пакеты, поступающие из виртуального TUN-интерфейса, попадают в компонент `PacketBatcher`. Для минимизации количества запросов к почтовому серверу пакеты накапливаются. По истечении таймаута (`batch_ms`) или при достижении лимита объема (`max_kb`), накопленный батч шифруется протоколом ASTP (ChaCha20Poly1305), кодируется в Base64 и отправляется на сервер провайдера командой `APPEND` в папку `Drafts`.
*   **Прием (Downlink):** Клиент удерживает фоновое соединение командой `IDLE` в папке `Notes`. При получении уведомления от провайдера о новом письме, клиент скачивает его (`FETCH`), немедленно удаляет из ящика (`STORE \Deleted` + `EXPUNGE`), декодирует Base64, расшифровывает батч, разделяет его на исходные IP-пакеты и инжектит их в TUN-интерфейс операционной системы.

### 3.2. Серверная часть
*   **Прием (Uplink):** Серверный воркер удерживает `IDLE` в папке `Drafts`. При появлении письма он скачивает его, удаляет из ящика, извлекает идентификатор клиента из темы письма, расшифровывает батч соответствующим ключом сессии и передает IP-пакеты в ядро маршрутизации сервера.
*   **Отправка (Downlink):** Пакеты, предназначенные клиенту, поступают из маршрутизатора сервера в индивидуальную очередь отправки. Воркер батчит их, шифрует ключом клиента, кодирует в Base64 и отправляет через `APPEND` в папку `Notes` с указанием идентификатора сессии клиента в теме письма.

## 4. Идентификация и Виртуальные Сокеты (Virtual Sockets)
Почтовый ящик функционирует как общая магистраль данных. Фильтрация пакетов осуществляется на стороне провайдера через команду `SEARCH SUBJECT`.

Тема письма формируется динамически: `Subject: {Template_Prefix} [ID: <TargetID>]`
*   `{Template_Prefix}` — настраиваемая строка (например, `Re: Отчет по проекту`).
*   **TargetID Сервера:** Первые 8 символов от `Base64(SHA256(server_pub_key))`. Это гарантирует уникальность узла без ручной настройки.
*   **TargetID Клиента:** До авторизации — `TempID` (первые 8 символов хэша от публичного ключа клиента). После авторизации — выданный `session_id`.

### 4.1. Генерация виртуального SocketAddr (Сторона Сервера)
Поскольку ядро ANet (`AuthHandler`) требует `SocketAddr` для привязки ключей хендшейка, IMAP-воркер сервера динамически конвертирует `TargetID` клиента в фейковый IP-адрес. Базовый IP-адрес вычисляется динамически, чтобы **гарантированно не пересекаться** с подсетью VPN.

```rust
use sha2::{Sha256, Digest};
use std::net::{SocketAddr, Ipv4Addr};
use std::str::FromStr;

/// Определяет безопасный базовый IP-адрес для виртуальных сокетов,
/// гарантируя отсутствие коллизий с маршрутами внутри VPN-туннеля.
pub fn get_safe_fake_base(vpn_net_str: &str) -> Ipv4Addr {
    let vpn_ip = Ipv4Addr::from_str(vpn_net_str).unwrap_or(Ipv4Addr::new(10, 0, 0, 0));
    let octets = vpn_ip.octets();

    // Используем loopback-блок 127.127.X.Y.
    // Если VPN настроен на 127.x.x.x, откатываемся на тестовую подсеть 198.18.x.x
    if octets[0] == 127 {
        Ipv4Addr::new(198, 18, 0, 0)
    } else {
        Ipv4Addr::new(127, 127, 0, 0)
    }
}

/// Превращает строковый ID клиента из темы письма в уникальный виртуальный SocketAddr
pub fn fake_addr_from_cli_id(cli_id: &str, safe_base: Ipv4Addr) -> SocketAddr {
    let mut hasher = Sha256::new();
    hasher.update(cli_id.as_bytes());
    let hash = hasher.finalize();

    let base_octets = safe_base.octets();
    let ip = Ipv4Addr::new(base_octets[0], base_octets[1], hash[2], hash[3]);
    
    let mut port = u16::from_be_bytes([hash[4], hash[5]]);
    if port == 0 { port = 1; }

    SocketAddr::new(std::net::IpAddr::V4(ip), port)
}
```

## 5. Разделение стадий Auth и Data (State-Based Dispatching)
Для обеспечения максимальной производительности (Zero-Lock Hot Path) сервер использует локальный кэш сессий внутри IMAP-воркера, что позволяет мгновенно отличать пакеты установленных сессий от новых рукопожатий.

```rust
use std::collections::HashMap;
use std::sync::Arc;
use bytes::Bytes;

/// Контекст, передаваемый каждому асинхронному воркеру на сервере
struct WorkerContext {
    /// Учетные данные конкретного почтового ящика (Логин, Пароль)
    account: (String, String),
    /// Глобальный реестр активных клиентских сессий
    registry: Arc<ClientRegistry>,
    /// Канал для передачи извлеченных IP-пакетов в виртуальный TUN-интерфейс
    tun_tx: tokio::sync::mpsc::Sender<Bytes>,
    /// Обработчик криптографических рукопожатий (ASTP)
    auth_handler: ServerAuthHandler,
    /// Безопасный базовый IP-адрес для генерации виртуальных сокетов
    safe_base_ip: Ipv4Addr,
    /// Уникальный идентификатор сервера, вычисленный из публичного ключа
    srv_id: String,
}

// Псевдокод внутри цикла чтения писем IMAP-воркера:
// Локальный кэш воркера (без мьютексов!)
let mut local_sessions: HashMap<String, Arc<ClientTransportInfo>> = HashMap::new();

let cli_id = extract_cli_id_from_subject(&subject); // "f9e8d7c6" или "sess_8899"

// 1. FAST PATH (Трафик) - Отрабатывает за наносекунды
if let Some(client_info) = local_sessions.get(&cli_id) {
    if let Ok(packet) = unwrap_packet_bytes(&client_info.cipher, payload) {
        let _ = tun_tx.try_send(packet);
    }
    continue;
}

// 2. SLOW PATH (Первый пакет трафика после авторизации)
if let Some(client_info) = registry.get_by_session(&cli_id) {
    local_sessions.insert(cli_id.clone(), client_info.clone());
    if let Ok(packet) = unwrap_packet_bytes(&client_info.cipher, payload) {
        let _ = tun_tx.try_send(packet);
    }
} else {
    // 3. AUTH PLANE (Хендшейк Фазы 1 или 3)
    let fake_addr = fake_addr_from_cli_id(&cli_id, safe_base_ip);
    let auth_res = auth_handler.process_handshake_packet(payload, fake_addr, "imap").await;
    
    if let Ok((Some(response_bytes), _)) = auth_res {
        // Отправка ответа клиенту (Фаза 2 или 4)
        send_imap_append("Notes", &cli_id, response_bytes).await;
    }
}
```

## 6. Интеграция в панель управления (anet-auth & anet-webui)
Во избежание компрометации паролей и для удобства управления, почтовые ящики хранятся в базе данных как справочник. Пароли шифруются с помощью компонента `DbEncryptor`. Строка подключения (DSN) собирается сервером «на лету» при выдаче конфигурации клиенту.

### 6.1. База данных и DTO (`anet-auth`)
Необходимо создать новую таблицу `imap_mailboxes` через SeaORM миграцию.

```rust
/// Модель данных служебного почтового ящика в БД
pub struct Model {
    /// Уникальный идентификатор записи ящика
    pub id: Uuid,
    /// Адрес IMAP-сервера провайдера (например, imap.mail.ru)
    pub host: String,
    /// Порт IMAP-сервера (обычно 993 для TLS)
    pub port: i32,
    /// Логин (email) от почтового ящика
    pub email: String,
    /// Зашифрованный пароль (ОБЯЗАТЕЛЬНО шифруется через DbEncryptor::encrypt при сохранении)
    pub password_encrypted: String,
    /// Статус активности ящика (используется ли он в пулах)
    pub is_active: bool,
    /// Дата создания записи
    pub created_at: DateTime,
    /// Дата последнего обновления записи
    pub updated_at: DateTime,
}
```

В контроллерах (API) при создании (`POST`) или обновлении (`PATCH`) записи почтового ящика, строковый пароль должен быть передан в `DbEncryptor::encrypt()` перед записью в базу данных.

### 6.2. Изменения в `anet-webui` (Frontend)
1.  **Справочник ящиков:** Создать новый раздел в UI (аналог DoH Resolvers) для управления пулом почтовых ящиков (CRUD операции).
2.  **Настройка пулов (Node Pools):** В компоненте `PoolModal.vue` добавить протокол `IMAP`.
3.  При выборе протокола `IMAP` отображать выпадающий список (Multiple Select) для выбора ящиков из справочника БД.
4.  Выбранные ID ящиков сериализуются в строку и сохраняются в поле `port_or_url` таблицы `node_pool_members` (например, `id1,id2,id3`).

### 6.3. Сборка DSN «на лету» (`anet-auth/src/api/users.rs`)
При вызове эндпоинта генерации `client.toml` (`download_config`):
1.  Бэкенд обрабатывает `ProtocolType::Imap` в блоке генерации серверов.
2.  Извлекает IDs ящиков из поля `port_or_url`.
3.  Делает запрос в БД (`imap_mailboxes`), получает записи.
4.  Дешифрует пароли с помощью `DbEncryptor::decrypt()`.
5.  Формирует строку DSN: `imap://imap.mail.ru:993?acc=user1%40mail.ru:pass1&acc=user2%40mail.ru:pass2&batch_ms=400` и экспортирует её в блок `[[servers]]` файла `client.toml` в исходном виде, без попыток автоматического добавления портов.

## 7. Интеграция в ядро ANet (Core Integration)

### 7.1. Зависимости (`Cargo.toml`)
Для реализации транспорта необходимо добавить крейт `async-imap` в воркспейс.
```toml
# Подключается в anet-client-core и anet-server.
# Строго отключаем async-std, используем только tokio и rustls.
async-imap = { version = "0.9", default-features = false, features = ["runtime-tokio", "rustls"] }
```

### 7.2. Клиент (`anet-client-core`)
1.  **`config.rs`**: Добавить `TransportMode::Imap` и парсинг схемы `imap` в `ServerConfig::mode()`.
2.  **`transport/factory.rs`**: Добавить ветвление `TransportMode::Imap => Box::new(ImapTransport::new(...))`.
3.  Создать `transport/imap.rs` со следующими структурами:

```rust
/// Конфигурация IMAP-транспорта, динамически извлеченная из DSN
struct ImapConfig {
    /// Хост почтового провайдера (например, imap.mail.ru)
    host: String,
    /// Порт подключения (TLS, обычно 993)
    port: u16,
    /// Пул служебных аккаунтов в формате (Логин, Пароль)
    accounts: Vec<(String, String)>,
    /// Базовый шаблон для темы письма (маскировка под легитимный трафик)
    subject_prefix: String,
    /// Максимальное время удержания пакетов в буфере (коалесценция) в миллисекундах
    batch_ms: u64,
    /// Максимальный размер одного отправляемого пакета-черновика в килобайтах
    max_kb: usize,
}

/// Основная структура клиента для IMAP-транспорта
pub struct ImapTransport {
    /// Глобальная конфигурация ядра клиента ANet
    config: CoreConfig,
    /// Конфигурация конкретного сервера из client.toml
    server: ServerConfig,
}
```

### 7.3. Сервер (`anet-server`)
1.  **`config.rs`**: В структуру `ServerCoreConfig` добавить поле `pub imap_dsn: Option<String>`. *(Администратор сервера генерирует эту строку через CLI или копирует из админки).*
2.  **`server.rs`**: В методе `ANetServer::run()` добавить запуск супервизора:
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
3.  Создать модуль `servers/imap.rs` с реализацией пула воркеров (по одному на каждый аккаунт из `imap_dsn`).

## 8. Строгие требования к реализации (AI Prompts)
При написании кода разработчик (или ИИ-ассистент) обязан соблюдать следующие директивы:

1.  **Strict Tokio Runtime:** Запрещено использовать `async-std` или синхронные блокирующие вызовы. Использовать только `async-imap` с фичей `runtime-tokio`.
2.  **Full-Duplex Connections:** Команда `IDLE` блокирует сессию. Строго обязательно открывать **два независимых TCP/TLS соединения** к одному ящику (одно исключительно для Writer/`APPEND`, второе исключительно для Reader/`IDLE`). Это критично для предотвращения Deadlock.
3.  **Adaptive Batching:** Использовать существующий `PacketBatcher` (перенести его из `wrtc/batcher.rs` в `anet-common/src/batcher.rs`). Накапливать IP-пакеты из TUN и отправлять их единым Base64-блоком по истечении `batch_ms` или при достижении `max_kb`.
4.  **Garbage Collection (Критично):** После выполнения `FETCH` и успешной обработки пакета, код обязан немедленно пометить письмо на удаление `STORE <UID> +FLAGS (\Deleted)` и выполнить `EXPUNGE`. Утечка писем недопустима.
5.  **Cryptography:** Использовать `wrap_packet` и `unwrap_packet` из `anet-common/src/transport.rs` (ChaCha20Poly1305). Инкапсулировать зашифрованный бинарный буфер в Base64 перед вставкой в тело письма.
6.  **Failover ящиков (только Клиент):** Если клиент получает ошибку авторизации или лимита от провайдера на текущем ящике, он должен инкрементировать индекс пула `(index + 1) % accounts.len()` и пересоздать сессии с новым ящиком, не обрывая TUN-интерфейс.
7.  **Мультиплексирование (только Сервер):** Сервер должен спавнить асинхронные воркеры (Reader/Writer) для **всех** ящиков, указанных в серверном DSN одновременно. Все воркеры должны обращаться к единому `ClientRegistry` и использовать локальный кэш (Fast Path).

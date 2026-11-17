use anet_common::config::{BrowserProfileConfig, StealthConfig, WrtcConfig};
use anet_common::quic_settings::QuicConfig;
use clap::Parser;
use log::warn;
use serde::Deserialize;
use std::process::exit;
use tokio::fs::read_to_string;

#[derive(Debug, Clone, Deserialize)]
pub struct CryptoConfig {
    pub quic_cert: String,
    pub quic_key: String,
    pub server_signing_key: String,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            quic_cert: "QUIC_CERT_PLACEHOLDER".to_string(),
            quic_key: "QUIC_KEY_PLACEHOLDER".to_string(),
            server_signing_key: "SERVER_SIGNING_KEY_PLACEHOLDER".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct StatsConfig {
    /// Включить или выключить периодический вывод статистики соединения.
    pub enabled: bool,
    /// Интервал вывода статистики в минутах.
    pub interval_minutes: u64,
}

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_minutes: 1,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticationConfig {
    /// Локальный список разрешенных клиентов (работает всегда)
    pub allowed_clients: Vec<String>,

    /// Список URL серверов авторизации (например, ["http://127.0.0.1:3000/api/v1"])
    #[serde(default)]
    pub auth_servers: Vec<String>,

    /// Токен для доступа к API авторизации (X-Auth-Key)
    #[serde(default)]
    pub auth_server_token: String,
}

impl Default for AuthenticationConfig {
    fn default() -> Self {
        Self {
            allowed_clients: vec![],
            auth_servers: vec![],
            auth_server_token: "default_secret".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ControlPlaneConfig {
    /// UUID узла из панели управления. Пустое значение отключает heartbeat.
    pub node_id: String,
    /// Базовый URL API, например http://127.0.0.1:3000/api/v1.
    pub url: String,
    /// Одноразово выданный в WebUI секрет этой ноды. Передаётся в X-Node-Token.
    pub token: String,
    /// Период исходящего heartbeat, отчёта трафика и polling команд.
    pub heartbeat_interval_seconds: u64,
}

impl Default for ControlPlaneConfig {
    fn default() -> Self {
        Self {
            node_id: String::new(),
            url: String::new(),
            token: String::new(),
            heartbeat_interval_seconds: 15,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    pub mask: String,
    pub net: String,
    pub gateway: String,
    pub self_ip: String,
    pub if_name: String,
    pub mtu: u16,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            mask: "255.255.255.0".to_string(),
            net: "10.0.0.0".to_string(),
            gateway: "10.0.0.1".to_string(),
            self_ip: "10.0.0.2".to_string(),
            if_name: "anet-server".to_string(),
            mtu: 1400,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerCoreConfig {
    pub quic_bind_to: String,
    pub ssh_bind_to: String,
    pub vnc_bind_to: String,
    pub websocket_bind_to: String,
    pub websocket_path: String,
    pub ahttp_bind_to: String,
    pub ahttp_path: String,
    pub ssh_host_key: String,
    pub ssh_banner: Option<String>,
    pub wrtc_room_url: Option<String>,
    pub wrtc_media_keepalive_interval_ms: u64,
    pub wrtc_ping_interval_secs: u64,
    pub wrtc_fallback_jvb_ip: String,
    pub wrtc_fallback_jvb_port: u16,
    pub wrtc_mode: Option<String>,
    pub imap_dsn: Option<String>,
}

impl Default for ServerCoreConfig {
    fn default() -> Self {
        Self {
            quic_bind_to: "0.0.0.0:8443".to_string(),
            ssh_bind_to: "0.0.0.0:822".to_string(),
            vnc_bind_to: "0.0.0.0:5900".to_string(),
            websocket_bind_to: "0.0.0.0:8080".to_string(),
            websocket_path: "/socket".to_string(),
            ahttp_bind_to: "127.0.0.1:8081".to_string(),
            ahttp_path: "/api/v2/telemetry".to_string(),
            ssh_host_key: "/etc/ssh/ssh_host_rsa_key".to_string(),
            ssh_banner: None,
            wrtc_room_url: None,
            wrtc_media_keepalive_interval_ms: 20,
            wrtc_ping_interval_secs: 30,
            wrtc_fallback_jvb_ip: "89.169.16.6".to_string(),
            wrtc_fallback_jvb_port: 10002,
            wrtc_mode: None,
            imap_dsn: None,
        }
    }
}

impl ServerCoreConfig {
    pub fn wrtc_transport_mode(&self) -> anet_common::wrtc::colibri::WrtcMode {
        match self.wrtc_mode.as_deref() {
            Some(s) => s.parse().unwrap_or_default(),
            None => anet_common::wrtc::colibri::WrtcMode::Auto,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ShaperConfig {
    /// Включает eBPF-шейпер трафика (per-user `speed_limit`) на TUN-
    /// интерфейсе. Требует `CAP_BPF` + `CAP_NET_ADMIN` (или root) и qdisc
    /// `fq` на TUN-интерфейсе (настраивается автоматически при старте).
    /// См. `anet-server::shaper`.
    pub enabled: bool,
}

impl Default for ShaperConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
}

// Конфигурация HTTP-транспорта на стороне сервера (секция `[ahttp]` в `server.toml`)
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AhttpServerConfig {
    pub handshake_path: String,
    pub auth_path: String,
    pub traffic_path: String,
    pub response_headers: String,
    pub max_header_bytes: usize,
    /// Максимальный допустимый размер тела входящего HTTP-запроса (для Content-Length и Transfer-Encoding: chunked).
    pub max_body_bytes: usize,
    /// Таймаут чтения HTTP-заголовков/тела после начала приёма данных (мс).
    pub read_timeout_ms: u64,
    /// Таймаут записи и flush HTTP-ответа (мс).
    pub write_timeout_ms: u64,
    /// Таймаут ожидания первого байта нового запроса на idle keep-alive соединении (сек).
    pub idle_keepalive_timeout_secs: u64,
    /// Период фоновой очистки устаревших сессий `active_sessions` в AHTTP-транспорте (сек).
    pub session_gc_interval_secs: u64,
    pub reassembly_queue_max_size: usize,
    /// Таймаут ожидания пропавшего/задержанного пакета при разрыве последовательности (мс).
    pub reassembly_gap_timeout_ms: u64,
    pub coalesce_budget_bytes: usize,
    /// Время удержания запроса при мелком непустом uplink-пакете в ожидании downlink-данных (мс).
    pub poll_timeout_ms: u64,
    /// Время удержания пустого poll-запроса (long-poll, мс, 0 = использовать `poll_timeout_ms`, макс. 60000).
    pub idle_poll_timeout_ms: u64,
    /// Порог размера uplink-тела (байт), выше которого сервер отвечает без ожидания poll-таймаута.
    pub heavy_uplink_threshold_bytes: usize,
    /// Максимальное окно добора downlink-пакетов после появления первого пакета (мс).
    pub coalesce_max_wait_ms: u64,
    /// Максимальная пауза между соседними пакетами при коалесценции downlink (мкс).
    pub coalesce_gap_timeout_us: u64,
    /// HTTP-заголовок, из которого сервер также может извлекать `session_id` (помимо query).
    pub session_id_header: String,
    /// Имя query-параметра URL для извлечения `session_id` (если не передан в `session_id_header`).
    pub session_id_query_param: String,
}

impl Default for AhttpServerConfig {
    fn default() -> Self {
        Self {
            handshake_path: anet_common::consts::AHTTP_DEFAULT_HANDSHAKE_PATH.to_string(),
            auth_path: anet_common::consts::AHTTP_DEFAULT_AUTH_PATH.to_string(),
            traffic_path: anet_common::consts::AHTTP_DEFAULT_TRAFFIC_PATH.to_string(),
            max_header_bytes: anet_common::consts::AHTTP_DEFAULT_MAX_HEADER_BYTES,
            max_body_bytes: anet_common::consts::AHTTP_DEFAULT_MAX_BODY_BYTES,
            read_timeout_ms: anet_common::consts::AHTTP_DEFAULT_READ_TIMEOUT_MS,
            write_timeout_ms: anet_common::consts::AHTTP_DEFAULT_WRITE_TIMEOUT_MS,
            idle_keepalive_timeout_secs:
                anet_common::consts::AHTTP_DEFAULT_IDLE_KEEPALIVE_TIMEOUT_SECS,
            session_gc_interval_secs: anet_common::consts::AHTTP_DEFAULT_SESSION_GC_INTERVAL_SECS,
            response_headers: "HTTP/1.1 200 OK\r\n\
                               Content-Type: video/mp4\r\n\
                               Cache-Control: no-cache, no-transform, private, must-revalidate\r\n\
                               Pragma: no-cache\r\n\
                               X-Accel-Buffering: no\r\n\
                               Content-Length: {}\r\n\
                               Connection: keep-alive\r\n\r\n"
                .to_string(),
            reassembly_queue_max_size:
                anet_common::consts::AHTTP_DEFAULT_REASSEMBLY_QUEUE_MAX_SIZE,
            reassembly_gap_timeout_ms:
                anet_common::consts::AHTTP_DEFAULT_REASSEMBLY_GAP_TIMEOUT_MS,
            coalesce_budget_bytes: anet_common::consts::AHTTP_DEFAULT_SERVER_COALESCE_BUDGET_BYTES,
            poll_timeout_ms: anet_common::consts::AHTTP_DEFAULT_SERVER_POLL_TIMEOUT_MS,
            idle_poll_timeout_ms: anet_common::consts::AHTTP_DEFAULT_SERVER_IDLE_POLL_TIMEOUT_MS,
            heavy_uplink_threshold_bytes:
                anet_common::consts::AHTTP_DEFAULT_SERVER_HEAVY_UPLINK_THRESHOLD_BYTES,
            coalesce_max_wait_ms: anet_common::consts::AHTTP_DEFAULT_SERVER_COALESCE_MAX_WAIT_MS,
            coalesce_gap_timeout_us:
                anet_common::consts::AHTTP_DEFAULT_SERVER_COALESCE_GAP_TIMEOUT_US,
            session_id_header: anet_common::consts::AHTTP_DEFAULT_SESSION_ID_HEADER.to_string(),
            session_id_query_param: anet_common::consts::AHTTP_DEFAULT_SESSION_ID_QUERY_PARAM
                .to_string(),
        }
    }
}

impl AhttpServerConfig {
    pub fn read_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.read_timeout_ms.max(500))
    }

    pub fn write_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.write_timeout_ms.max(500))
    }

    pub fn idle_keepalive_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.idle_keepalive_timeout_secs.max(5))
    }

    pub fn effective_max_body_bytes(&self) -> usize {
        self.max_body_bytes.max(64 * 1024)
    }

    pub fn effective_reassembly_gap_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.reassembly_gap_timeout_ms.max(1))
    }

    pub fn effective_idle_poll_timeout(&self) -> std::time::Duration {
        let ms = if self.idle_poll_timeout_ms == 0 {
            self.poll_timeout_ms.max(20)
        } else {
            self.idle_poll_timeout_ms
        };
        std::time::Duration::from_millis(ms.clamp(20, 60_000))
    }

    pub fn effective_active_poll_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.poll_timeout_ms.clamp(1, 60_000))
    }

    pub fn effective_session_id_query_param(&self) -> &str {
        let trimmed = self.session_id_query_param.trim();
        if trimmed.is_empty() {
            anet_common::consts::AHTTP_DEFAULT_SESSION_ID_QUERY_PARAM
        } else {
            trimmed
        }
    }
}

/// Конфигурация транспорта WebSocket на стороне сервера (секция `[websocket]` в `server.toml`).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct WebSocketServerConfig {
    /// Максимальный размер скользящего окна переупорядочивания входящих пакетов (`ReassemblyQueue`)
    /// при работе мульти-сокетного пула `WSS ?pool=N`.
    pub reassembly_queue_max_size: usize,
    /// Таймаут ожидания пропавшего/задержанного пакета при разрыве последовательности (мс).
    pub reassembly_gap_timeout_ms: u64,
    /// Таймаут отправки одного WebSocket-фрейма (мс). Защищает от зависания на «чёрной дыре» TCP.
    pub write_timeout_ms: u64,
    /// Таймаут закрытия WebSocket-сокета (мс).
    pub close_timeout_ms: u64,
    /// Таймаут HTTP Upgrade и фаз ASTP-рукопожатия / `WS_MUX_BIND` на сервере (сек).
    pub handshake_timeout_secs: u64,
    /// Минимальный интервал отправки keepalive Ping от сервера к клиенту (сек).
    pub ping_interval_min_secs: u64,
    /// Максимальный интервал отправки keepalive Ping от сервера к клиенту (сек).
    pub ping_interval_max_secs: u64,
    /// Бюджет коалесценции пакетов на один сокет при `active_sockets > 1` (байт).
    pub pool_coalesce_budget_bytes: usize,
    /// Бюджет коалесценции пакетов при одном активном сокете (байт).
    pub single_coalesce_budget_bytes: usize,
    /// Максимальный размер одного WebSocket-сообщения/фрейма `tokio-tungstenite` (байт).
    pub max_message_size: usize,
    /// Размер буфера чтения WebSocket-потока (байт).
    pub read_buffer_size: usize,
    /// Стартовый размер буфера записи WebSocket-потока (байт).
    pub write_buffer_size: usize,
    /// Верхний лимит буфера записи WebSocket-потока (байт).
    pub max_write_buffer_size: usize,
    /// Окно удержания suspended-сессии для `resume_session_id` после обрыва всех сокетов (сек).
    pub resume_window_secs: u64,
    /// Разрешать ли создание новой сессии с перепроверкой прав, если `resume_session_id` уже истёк/отсутствует.
    pub resume_allow_fresh_fallback: bool,
}

impl Default for WebSocketServerConfig {
    fn default() -> Self {
        Self {
            reassembly_queue_max_size: anet_common::consts::WS_REASSEMBLY_QUEUE_MAX_SIZE,
            reassembly_gap_timeout_ms: anet_common::consts::WS_REASSEMBLY_GAP_TIMEOUT_MS,
            write_timeout_ms: anet_common::consts::WS_DEFAULT_WRITE_TIMEOUT_MS,
            close_timeout_ms: anet_common::consts::WS_DEFAULT_CLOSE_TIMEOUT_MS,
            handshake_timeout_secs: anet_common::consts::WS_DEFAULT_HANDSHAKE_TIMEOUT_SECS,
            ping_interval_min_secs: anet_common::consts::WS_DEFAULT_SERVER_PING_MIN_SECS,
            ping_interval_max_secs: anet_common::consts::WS_DEFAULT_SERVER_PING_MAX_SECS,
            pool_coalesce_budget_bytes: anet_common::consts::WS_POOL_COALESCE_BUDGET_BYTES,
            single_coalesce_budget_bytes:
                anet_common::consts::WS_DEFAULT_SINGLE_COALESCE_BUDGET_BYTES,
            max_message_size: anet_common::consts::WS_DEFAULT_MAX_MESSAGE_SIZE,
            read_buffer_size: anet_common::consts::WS_DEFAULT_READ_BUFFER_SIZE,
            write_buffer_size: anet_common::consts::WS_DEFAULT_WRITE_BUFFER_SIZE,
            max_write_buffer_size: anet_common::consts::WS_DEFAULT_MAX_WRITE_BUFFER_SIZE,
            resume_window_secs: anet_common::consts::WS_DEFAULT_RESUME_WINDOW_SECS,
            resume_allow_fresh_fallback: true,
        }
    }
}

impl WebSocketServerConfig {
    pub fn write_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.write_timeout_ms.max(100))
    }

    pub fn close_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.close_timeout_ms.max(100))
    }

    pub fn handshake_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.handshake_timeout_secs.max(1))
    }

    pub fn random_ping_interval(&self) -> std::time::Duration {
        use rand::Rng;
        let min = self.ping_interval_min_secs.max(1);
        let max = self.ping_interval_max_secs.max(min);
        std::time::Duration::from_secs(rand::rngs::OsRng.gen_range(min..=max))
    }

    pub fn effective_pool_coalesce_budget(&self) -> usize {
        self.pool_coalesce_budget_bytes.max(1500)
    }

    pub fn effective_single_coalesce_budget(&self) -> usize {
        self.single_coalesce_budget_bytes.max(1500)
    }

    pub fn effective_max_message_size(&self) -> usize {
        self.max_message_size.max(4096)
    }

    pub fn effective_read_buffer_size(&self) -> usize {
        self.read_buffer_size.max(4096)
    }

    pub fn effective_write_buffer_size(&self) -> usize {
        self.write_buffer_size.max(4096)
    }

    pub fn effective_max_write_buffer_size(&self) -> usize {
        self.max_write_buffer_size
            .max(self.effective_write_buffer_size())
    }
}

// Конфигурация транспорта IMAP на сервере (секция [imap] в server.toml)
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ImapServerConfig {
    /// Опциональный DSN IMAP-пула (позволяет указывать `imap_dsn` или `dsn` как в `[server]`, так и в `[imap]`).
    #[serde(default, alias = "dsn")]
    pub imap_dsn: Option<String>,
    /// Время жизни неактивной клиентской сессии при отсутствии пакетов (мс).
    pub session_ttl_ms: u64,
    /// Интервал перевхода серверного воркера в IDLE в состоянии покоя (мс).
    pub idle_refresh_interval_ms: u64,
    /// Короткий интервал ожидания IDLE во время активного обмена трафиком (мс).
    pub idle_active_poll_ms: u64,
    /// Время удержания быстрого режима опроса после последнего переданного/принятого пакета (мс).
    pub idle_active_window_ms: u64,
    /// Таймаут ожидания команды IMAP (мс).
    pub command_timeout_ms: u64,
    /// Интервал проверки и очистки зависших сессий (мс).
    pub cleanup_interval_ms: u64,
    /// Таймаут отката при рейт-лимитах провайдера (мс).
    pub throttle_backoff_ms: u64,
    /// Максимальный размер одного зашифрованного пакета-черновика (КБ, до 512 КБ без переполнения u16).
    pub max_batch_kb: usize,
    /// Задержка микро-коалесценции батчера (мс).
    pub batch_coalesce_ms: u64,
    /// Максимальное число писем, скачиваемых за одну команду `UID FETCH` (0 = без лимита).
    pub fetch_max_messages: usize,
    /// Порог количества прочитанных писем для принудительного пакетного удаления (UID STORE + UID EXPUNGE).
    pub expunge_batch_size: usize,
    /// Пауза отсутствия исходящего трафика перед ленивой очисткой прочитанных писем (мс).
    pub expunge_idle_delay_ms: u64,
    /// Максимальное окно неподтвержденных батчей до срабатывания Backpressure.
    pub max_inflight_batches: usize,
    /// Емкость очереди клиентского Downlink-роутера (защита от Bufferbloat).
    pub tx_queue_capacity: usize,
    /// Автоматическое определение и использование расширения LITERAL+ (1-RTT APPEND) при подключении.
    pub literal_plus_auto: bool,
}

impl Default for ImapServerConfig {
    fn default() -> Self {
        Self {
            imap_dsn: None,
            session_ttl_ms: 180_000,
            idle_refresh_interval_ms: 10_000,
            idle_active_poll_ms: 400,
            idle_active_window_ms: 5_000,
            command_timeout_ms: 15_000,
            cleanup_interval_ms: 30_000,
            throttle_backoff_ms: 30_000,
            max_batch_kb: 128,
            batch_coalesce_ms: 15,
            fetch_max_messages: 3,
            expunge_batch_size: 25,
            expunge_idle_delay_ms: 1_500,
            max_inflight_batches: 35,
            tx_queue_capacity: 256,
            literal_plus_auto: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub network: NetworkConfig,

    #[serde(default)]
    pub server: ServerCoreConfig,

    #[serde(default)]
    pub quic_transport: QuicConfig,

    #[serde(default)]
    pub crypto: CryptoConfig,

    #[serde(default)]
    pub authentication: AuthenticationConfig,

    #[serde(default)]
    pub control_plane: ControlPlaneConfig,

    #[serde(default)]
    pub stealth: StealthConfig,

    #[serde(default)]
    pub shaper: ShaperConfig,

    #[serde(default)]
    pub ahttp: AhttpServerConfig,

    #[serde(default)]
    pub websocket: WebSocketServerConfig,

    #[serde(default)]
    pub wrtc: WrtcConfig,

    #[serde(default)]
    pub browser_profiles: Vec<BrowserProfileConfig>,

    #[serde(default)]
    pub imap: ImapServerConfig,
}

#[derive(Debug, Parser)]
pub struct Opt {
    #[clap(short, long, default_value = "./server.toml")]
    pub cfg: String,
}

pub async fn load() -> anyhow::Result<Config> {
    let opt = Opt::parse();
    let toml_str = read_to_string(&opt.cfg).await;
    match toml_str {
        Ok(toml_str) => {
            let cfg: Config = toml::from_str(&toml_str)?;
            anet_common::boring_tls::set_default_tls_config(cfg.stealth.to_tls_client_config());
            if !cfg.browser_profiles.is_empty() {
                anet_common::boring_tls::set_browser_profiles(cfg.browser_profiles.clone());
            }
            Ok(cfg)
        }
        Err(_) => {
            warn!("\nCannot find server config file in {}, use '-c' or '--cfg'\n", opt.cfg);
            exit(-1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Config;
    use std::time::Duration;

    #[test]
    fn websocket_server_config_defaults_and_overrides() {
        let default_cfg: Config = toml::from_str("").unwrap();
        assert_eq!(
            default_cfg.websocket.reassembly_queue_max_size,
            anet_common::consts::WS_REASSEMBLY_QUEUE_MAX_SIZE
        );
        assert_eq!(
            default_cfg.websocket.write_timeout(),
            Duration::from_millis(anet_common::consts::WS_DEFAULT_WRITE_TIMEOUT_MS)
        );
        assert_eq!(
            default_cfg.websocket.close_timeout(),
            Duration::from_millis(anet_common::consts::WS_DEFAULT_CLOSE_TIMEOUT_MS)
        );
        assert_eq!(
            default_cfg.websocket.handshake_timeout(),
            Duration::from_secs(anet_common::consts::WS_DEFAULT_HANDSHAKE_TIMEOUT_SECS)
        );
        assert!(default_cfg.websocket.resume_allow_fresh_fallback);

        let custom_toml = r#"
            [websocket]
            reassembly_queue_max_size = 4096
            reassembly_gap_timeout_ms = 90
            write_timeout_ms = 5000
            close_timeout_ms = 1500
            handshake_timeout_secs = 20
            ping_interval_min_secs = 15
            ping_interval_max_secs = 15
            pool_coalesce_budget_bytes = 32768
            single_coalesce_budget_bytes = 98304
            max_message_size = 524288
            read_buffer_size = 262144
            write_buffer_size = 262144
            max_write_buffer_size = 1048576
            resume_window_secs = 90
            resume_allow_fresh_fallback = false
        "#;
        let custom_cfg: Config = toml::from_str(custom_toml).unwrap();
        assert_eq!(custom_cfg.websocket.reassembly_queue_max_size, 4096);
        assert_eq!(custom_cfg.websocket.reassembly_gap_timeout_ms, 90);
        assert_eq!(custom_cfg.websocket.write_timeout(), Duration::from_millis(5000));
        assert_eq!(custom_cfg.websocket.close_timeout(), Duration::from_millis(1500));
        assert_eq!(custom_cfg.websocket.handshake_timeout(), Duration::from_secs(20));
        assert_eq!(custom_cfg.websocket.random_ping_interval(), Duration::from_secs(15));
        assert_eq!(custom_cfg.websocket.effective_pool_coalesce_budget(), 32768);
        assert_eq!(custom_cfg.websocket.effective_single_coalesce_budget(), 98304);
        assert_eq!(custom_cfg.websocket.effective_max_message_size(), 524288);
        assert_eq!(custom_cfg.websocket.effective_read_buffer_size(), 262144);
        assert_eq!(custom_cfg.websocket.effective_write_buffer_size(), 262144);
        assert_eq!(custom_cfg.websocket.effective_max_write_buffer_size(), 1048576);
        assert_eq!(custom_cfg.websocket.resume_window_secs, 90);
        assert!(!custom_cfg.websocket.resume_allow_fresh_fallback);
    }

    #[test]
    fn ahttp_server_config_defaults_and_overrides() {
        let default_cfg: Config = toml::from_str("").unwrap();
        assert_eq!(
            default_cfg.ahttp.max_body_bytes,
            anet_common::consts::AHTTP_DEFAULT_MAX_BODY_BYTES
        );
        assert_eq!(
            default_cfg.ahttp.effective_idle_poll_timeout(),
            Duration::from_millis(anet_common::consts::AHTTP_DEFAULT_SERVER_IDLE_POLL_TIMEOUT_MS)
        );
        assert_eq!(default_cfg.ahttp.session_id_header, "X-Session-Id");
        assert_eq!(default_cfg.ahttp.effective_session_id_query_param(), "session_id");

        let custom_toml = r#"
            [ahttp]
            max_body_bytes = 8388608
            read_timeout_ms = 20000
            write_timeout_ms = 25000
            idle_keepalive_timeout_secs = 90
            session_gc_interval_secs = 30
            reassembly_gap_timeout_ms = 120
            poll_timeout_ms = 35
            idle_poll_timeout_ms = 2500
            heavy_uplink_threshold_bytes = 16384
            coalesce_max_wait_ms = 6
            coalesce_gap_timeout_us = 1500
            session_id_header = "X-Client-Token"
            session_id_query_param = "sid"
        "#;
        let custom_cfg: Config = toml::from_str(custom_toml).unwrap();
        assert_eq!(custom_cfg.ahttp.effective_max_body_bytes(), 8_388_608);
        assert_eq!(custom_cfg.ahttp.read_timeout(), Duration::from_millis(20_000));
        assert_eq!(custom_cfg.ahttp.write_timeout(), Duration::from_millis(25_000));
        assert_eq!(custom_cfg.ahttp.idle_keepalive_timeout(), Duration::from_secs(90));
        assert_eq!(custom_cfg.ahttp.session_gc_interval_secs, 30);
        assert_eq!(custom_cfg.ahttp.effective_reassembly_gap_timeout(), Duration::from_millis(120));
        assert_eq!(custom_cfg.ahttp.effective_active_poll_timeout(), Duration::from_millis(35));
        assert_eq!(custom_cfg.ahttp.effective_idle_poll_timeout(), Duration::from_millis(2500));
        assert_eq!(custom_cfg.ahttp.heavy_uplink_threshold_bytes, 16_384);
        assert_eq!(custom_cfg.ahttp.coalesce_max_wait_ms, 6);
        assert_eq!(custom_cfg.ahttp.coalesce_gap_timeout_us, 1500);
        assert_eq!(custom_cfg.ahttp.session_id_header, "X-Client-Token");
        assert_eq!(custom_cfg.ahttp.effective_session_id_query_param(), "sid");
    }
}

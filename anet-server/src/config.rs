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

// Новая структура для настройки HTTP-транспорта на стороне сервера
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AhttpServerConfig {
    pub handshake_path: String,
    pub auth_path: String,
    pub traffic_path: String,
    pub response_headers: String,
    pub max_header_bytes: usize,
    pub reassembly_queue_max_size: usize,
    pub coalesce_budget_bytes: usize,
    pub poll_timeout_ms: u64,
}

impl Default for AhttpServerConfig {
    fn default() -> Self {
        Self {
            handshake_path: "/handshake".to_string(),
            auth_path: "/auth".to_string(),
            traffic_path: "/traffic".to_string(),
            max_header_bytes: 16384,
            response_headers: "HTTP/1.1 200 OK\r\n\
                               Content-Type: video/mp4\r\n\
                               Cache-Control: no-cache, no-transform, private, must-revalidate\r\n\
                               Pragma: no-cache\r\n\
                               X-Accel-Buffering: no\r\n\
                               Content-Length: {}\r\n\
                               Connection: keep-alive\r\n\r\n".to_string(),
            reassembly_queue_max_size: 1024,
            coalesce_budget_bytes: 131072,
            poll_timeout_ms: 25,
        }
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

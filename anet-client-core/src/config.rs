pub use anet_common::config::{
    BrowserProfileConfig, ConnectivityConfig, StealthConfig, WrtcConfig,
};
use anet_common::quic_settings::QuicConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PerAppMode {
    All,
    Include,
    Exclude,
}

impl Default for PerAppMode {
    fn default() -> Self {
        PerAppMode::All
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct MainConfig {
    pub tun_name: String,

    #[serde(default)]
    pub manual_routing: bool,

    #[serde(default)]
    pub route_for: Vec<String>,

    #[serde(default)]
    pub exclude_route_for: Vec<String>,

    #[serde(default = "default_dns_server_list")]
    pub dns_server_list: Vec<String>,

    /// Windows per-app split tunneling: список имён процессов ("firefox.exe").
    /// Пусто — обычный полный туннель через TUN (поведение по умолчанию).
    #[serde(default)]
    pub per_app: Vec<String>,

    /// all - весь трафик в тунель
    /// include  — в туннель идут ТОЛЬКО процессы из `per_app` (include-режим).
    /// exclude — процессы из `per_app` ИСКЛЮЧАЮТСЯ из туннеля (exclude-режим);
    #[serde(default)]
    pub per_app_mode: PerAppMode,

    /// Устаревший флаг из старых client.toml (при непустом `per_app` и `per_app_mode == All`
    /// автоматически маппится в `Exclude` при `true` или `Include` при `false`).
    #[serde(default)]
    pub per_app_exclude: Option<bool>,

    #[serde(default = "default_update_url")]
    pub update_url: String,

    /// URL для автоматического обновления конфигурации
    #[serde(default)]
    pub config_url: Option<String>,

    /// Альтернативное имя поля для совместимости с подписками
    #[serde(default)]
    pub subscription_url: Option<String>,
}

fn default_dns_server_list() -> Vec<String> {
    vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]
}

fn default_update_url() -> String {
    "https://api.github.com/repos/ZeroTworu/anet/releases/latest".to_string()
}

impl MainConfig {
    pub fn get_config_url(&self) -> Option<&str> {
        self.config_url.as_deref().or(self.subscription_url.as_deref())
    }

    pub fn effective_per_app_mode(&self) -> PerAppMode {
        if self.per_app_mode != PerAppMode::All {
            return self.per_app_mode;
        }
        if !self.per_app.is_empty() {
            if let Some(exclude) = self.per_app_exclude {
                return if exclude {
                    PerAppMode::Exclude
                } else {
                    PerAppMode::Include
                };
            }
        }
        PerAppMode::All
    }

    pub fn is_per_app_active(&self) -> bool {
        let mode = self.effective_per_app_mode();
        mode != PerAppMode::All && !(mode == PerAppMode::Include && self.per_app.is_empty())
    }
}

impl Default for MainConfig {
    fn default() -> Self {
        Self {
            tun_name: "anet-client".to_string(),
            route_for: vec![],
            exclude_route_for: vec![],
            dns_server_list: default_dns_server_list(),
            manual_routing: false,
            per_app: vec![],
            per_app_mode: PerAppMode::All,
            per_app_exclude: None,
            update_url: default_update_url(),
            config_url: None,
            subscription_url: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientKeys {
    pub private_key: String,
    pub server_pub_key: String,
}

impl Default for ClientKeys {
    fn default() -> Self {
        Self {
            private_key: "".to_string(),
            server_pub_key: "".to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct StatsConfig {
    pub enabled: bool,
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

#[derive(Debug, Clone, Deserialize, PartialEq, Copy)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    Quic,
    Ssh,
    Vnc,
    Websocket,
    Ahttp,
    Wrtc,
    Imap,
}

impl Default for TransportMode {
    fn default() -> Self {
        TransportMode::Quic
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TransportConfig {
    pub ssh_user: Option<String>,
    #[serde(default)]
    pub ssh_banner: Option<String>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            ssh_user: Some("hanyuu".to_string()),
            ssh_banner: None,
        }
    }
}

// Конфигурация транспорта IMAP (секция [imap] в client.toml)
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ImapConfig {
    /// Интервал перевхода в IDLE (keepalive) в состоянии покоя (мс).
    pub idle_refresh_interval_ms: u64,

    /// Короткий интервал ожидания IDLE во время активного обмена трафиком (мс).
    /// Устраняет 5–10 секундные провалы скорости при попадании уведомления EXISTS в «Слепое окно».
    pub idle_active_poll_ms: u64,

    /// Время удержания быстрого режима опроса после последнего переданного/принятого пакета (мс).
    pub idle_active_window_ms: u64,

    /// Таймаут ожидания ответа на команду IMAP (APPEND, FETCH, DONE) (мс).
    pub command_timeout_ms: u64,

    /// Максимальная задержка накопления микро-батча перед первым APPEND (мс).
    pub batch_coalesce_ms: u64,

    /// Максимальный размер одного зашифрованного пакета-черновика (КБ, до 512 КБ без переполнения u16).
    pub max_batch_kb: usize,

    /// Максимальное число писем, скачиваемых за одну команду `UID FETCH` (0 = без лимита).
    /// Предотвращает 5–12 секундные блокировки TUN при накоплении пачки писем в ящике.
    pub fetch_max_messages: usize,

    /// Порог количества прочитанных писем для принудительного пакетного удаления (UID STORE + UID EXPUNGE).
    pub expunge_batch_size: usize,

    /// Пауза отсутствия исходящего трафика перед ленивой очисткой прочитанных писем (мс).
    pub expunge_idle_delay_ms: u64,

    /// Максимальное окно неподтвержденных батчей до срабатывания Backpressure.
    pub max_inflight_batches: usize,

    /// Емкость очереди bulk-пакетов из TUN (защита от Bufferbloat).
    pub tx_queue_capacity: usize,

    /// Автоматическое определение и использование расширения LITERAL+ (1-RTT APPEND) при подключении.
    pub literal_plus_auto: bool,

    /// Таймаут переподключения при получении THROTTLED/OVERQUOTA (мс).
    pub throttle_backoff_ms: u64,
}

impl Default for ImapConfig {
    fn default() -> Self {
        Self {
            idle_refresh_interval_ms: 10_000,
            idle_active_poll_ms: 400,
            idle_active_window_ms: 5_000,
            command_timeout_ms: 15_000,
            batch_coalesce_ms: 15,
            max_batch_kb: 128,
            fetch_max_messages: 3,
            expunge_batch_size: 25,
            expunge_idle_delay_ms: 1_500,
            max_inflight_batches: 35,
            tx_queue_capacity: 256,
            literal_plus_auto: true,
            throttle_backoff_ms: 30_000,
        }
    }
}

// структура для точечного описания серверов в массиве [[servers]]
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    // Опциональное человекочитаемое имя сервера (например, "Germany-1")
    pub name: Option<String>,

    /// Endpoint and transport encoded as a single DSN, for example
    /// `quic://vpn.example.com:4519` or `wss://vpn.example.com/socket`.
    pub dsn: String,

    // Индивидуальный тайм-аут подключения (в секундах)
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,

    // Опциональное переопределение публичного ключа сервера
    pub server_pub_key: Option<String>,

    // Опциональное переопределение пользователя SSH
    pub ssh_user: Option<String>,

    // Опциональное переопределение идентификационного баннера SSHv2 (например, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5")
    #[serde(default)]
    pub ssh_banner: Option<String>,

    // Имя пула / группы серверов
    #[serde(default)]
    pub group_name: Option<String>,

    // Идентификатор пула / группы серверов
    #[serde(default)]
    pub group_id: Option<String>,

    // Вес сервера в группе
    #[serde(default, deserialize_with = "deserialize_weight")]
    pub weight: Option<i32>,

    // Поддержка опечатки weigth из конфига
    #[serde(default, deserialize_with = "deserialize_weight")]
    pub weigth: Option<i32>,

    /// Bounds for SSH session rotation (0 disables rotation).
    #[serde(default = "default_ssh_min_session_secs")]
    pub ssh_min_session_secs: u64,
    #[serde(default = "default_ssh_max_session_secs")]
    pub ssh_max_session_secs: u64,

    /// Bounds for VNC session rotation (0 disables rotation).
    #[serde(default = "default_vnc_min_session_secs")]
    pub vnc_min_session_secs: u64,
    #[serde(default = "default_vnc_max_session_secs")]
    pub vnc_max_session_secs: u64,

    /// Bounds for a browser-like WebSocket session rotation.
    #[serde(default = "default_websocket_min_session_secs")]
    pub websocket_min_session_secs: u64,
    #[serde(default = "default_websocket_max_session_secs")]
    pub websocket_max_session_secs: u64,

    /// WebRTC Ktalk keepalive and fallback settings
    pub wrtc_media_keepalive_interval_ms: Option<u64>,
    pub wrtc_ping_interval_secs: Option<u64>,
    pub wrtc_fallback_jvb_ip: Option<String>,
    pub wrtc_fallback_jvb_port: Option<u16>,
    /// WebRTC Data Transport mode: "auto" | "p2p_direct" | "jvb_datachannel" | "ws" | "media_video"
    #[serde(default)]
    pub wrtc_mode: Option<String>,

    /// Принудительное включение/отключение TURN релея в WebRTC
    #[serde(default)]
    pub wrtc_use_turn: Option<bool>,

    /// Принудительный приоритет TURNS Proxy (TCP:443) над UDP STUN/TURN для условий БС
    #[serde(default)]
    pub wrtc_turns_priority: Option<bool>,

    /// Опциональное переопределение TLS-отпечатка для конкретного сервера:
    /// "auto" | "chrome" | "firefox" | "safari" | "randomized"
    #[serde(default)]
    pub tls_fingerprint: Option<anet_common::boring_tls::TlsFingerprint>,

    /// Опциональное включение L4-фрагментации TLS ClientHello (`tlshello`) для данного сервера
    #[serde(default)]
    pub tls_frag_enabled: Option<bool>,

    /// Опциональный размер куска `tlshello` в стиле Xcore (`"10..20"`, `"16"`) для данного сервера
    #[serde(default)]
    pub tls_frag_length: Option<String>,

    /// Опциональная пауза между кусками `tlshello` в мс (`"0"`, `"1..5"`) для данного сервера
    #[serde(default)]
    pub tls_frag_delay_ms: Option<String>,

    /// Опциональное переопределение защиты от активного спуфинга ТСПУ для этого сервера.
    #[serde(default)]
    pub tls_verify_peer: Option<bool>,

    /// Опциональный SHA-256 пиннинг сертификата или SPKI публичного ключа для этого сервера.
    #[serde(default)]
    pub tls_pin_sha256: Option<String>,

    /// Опциональный пользовательский корневой/серверный PEM-сертификат для этого сервера.
    #[serde(default)]
    pub tls_ca_cert: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            name: None,
            dsn: String::new(),
            timeout_secs: default_timeout_secs(),
            server_pub_key: None,
            ssh_user: None,
            ssh_banner: None,
            group_name: None,
            group_id: None,
            weight: None,
            weigth: None,
            ssh_min_session_secs: default_ssh_min_session_secs(),
            ssh_max_session_secs: default_ssh_max_session_secs(),
            vnc_min_session_secs: default_vnc_min_session_secs(),
            vnc_max_session_secs: default_vnc_max_session_secs(),
            websocket_min_session_secs: default_websocket_min_session_secs(),
            websocket_max_session_secs: default_websocket_max_session_secs(),
            wrtc_media_keepalive_interval_ms: None,
            wrtc_ping_interval_secs: None,
            wrtc_fallback_jvb_ip: None,
            wrtc_fallback_jvb_port: None,
            wrtc_mode: None,
            wrtc_use_turn: None,
            wrtc_turns_priority: None,
            tls_fingerprint: None,
            tls_frag_enabled: None,
            tls_frag_length: None,
            tls_frag_delay_ms: None,
            tls_verify_peer: None,
            tls_pin_sha256: None,
            tls_ca_cert: None,
        }
    }
}

impl ServerConfig {
    pub fn weight(&self) -> i32 {
        self.weight.or(self.weigth).unwrap_or(1)
    }

    pub fn mode(&self) -> anyhow::Result<TransportMode> {
        match self.dsn.parse::<http::Uri>()?.scheme_str() {
            Some("quic") => Ok(TransportMode::Quic),
            Some("ssh") => Ok(TransportMode::Ssh),
            Some("vnc") => Ok(TransportMode::Vnc),
            Some("ws") | Some("wss") => Ok(TransportMode::Websocket),
            Some("http") | Some("https") => Ok(TransportMode::Ahttp),
            Some("wrtc") => Ok(TransportMode::Wrtc),
            Some("imap") | Some("imaps") => Ok(TransportMode::Imap),
            Some(scheme) => anyhow::bail!("unsupported server DSN scheme '{scheme}'"),
            None => anyhow::bail!("server DSN '{}' has no scheme", self.dsn),
        }
    }

    pub fn wrtc_room(&self) -> anyhow::Result<(String, String)> {
        let uri: http::Uri = self.dsn.parse()?;
        let host = uri.host().ok_or_else(|| anyhow::anyhow!("server DSN '{}' has no host", self.dsn))?;
        let path = uri.path().trim_start_matches('/');
        anyhow::ensure!(!path.is_empty(), "WRTC DSN '{}' has no room name in path", self.dsn);
        Ok((host.to_string(), path.to_string()))
    }

    pub fn wrtc_transport_mode(&self) -> anet_common::wrtc::colibri::WrtcMode {
        match self.wrtc_mode.as_deref() {
            Some(s) => s.parse().unwrap_or_default(),
            None => anet_common::wrtc::colibri::WrtcMode::Auto,
        }
    }

    /// Возвращает результирующую TLS-конфигурацию для данного сервера
    /// (объединяя глобальную секцию `[stealth]`, поля `[[servers]]` и query-параметры в `dsn`: `?fp=...&verify=...&pin=...`).
    pub fn effective_tls_config(
        &self,
        stealth: &StealthConfig,
    ) -> anet_common::boring_tls::TlsClientConfig {
        let mut cfg = stealth.to_tls_client_config();
        if let Some(fp) = self.tls_fingerprint {
            cfg.fingerprint = fp;
        }
        if let Some(verify) = self.tls_verify_peer {
            cfg.verify_peer = verify;
        }
        if let Some(ref pin) = self.tls_pin_sha256 {
            cfg.pin_sha256 = Some(pin.clone());
        }
        if let Some(ref ca) = self.tls_ca_cert {
            cfg.ca_cert = Some(ca.clone());
        }
        if let Some(enabled) = self.tls_frag_enabled {
            cfg.tls_frag.enabled = enabled;
        }
        if let Some(ref raw_len) = self.tls_frag_length {
            let (min_len, max_len) = anet_common::config::parse_range_pair(
                raw_len,
                cfg.tls_frag.min_len as u64,
                cfg.tls_frag.max_len as u64,
                1,
            );
            cfg.tls_frag.min_len = min_len as usize;
            cfg.tls_frag.max_len = max_len as usize;
        }
        if let Some(ref raw_delay) = self.tls_frag_delay_ms {
            let (min_d, max_d) = anet_common::config::parse_range_pair(
                raw_delay,
                cfg.tls_frag.min_delay_ms,
                cfg.tls_frag.max_delay_ms,
                0,
            );
            cfg.tls_frag.min_delay_ms = min_d;
            cfg.tls_frag.max_delay_ms = max_d;
        }

        if let Ok(parsed_url) = reqwest::Url::parse(&self.dsn) {
            for (k, v) in parsed_url.query_pairs() {
                match k.as_ref() {
                    "fp" | "tls_fingerprint" => {
                        if let Ok(fp) = v.parse::<anet_common::boring_tls::TlsFingerprint>() {
                            cfg.fingerprint = fp;
                        }
                    }
                    "verify" | "tls_verify_peer" => {
                        cfg.verify_peer = !matches!(
                            v.trim().to_ascii_lowercase().as_str(),
                            "0" | "false" | "no" | "off"
                        );
                    }
                    "pin" | "tls_pin_sha256" => {
                        if !v.trim().is_empty() {
                            cfg.pin_sha256 = Some(v.into_owned());
                        }
                    }
                    "tls_frag" | "tls_frag_enabled" => {
                        cfg.tls_frag.enabled = !matches!(
                            v.trim().to_ascii_lowercase().as_str(),
                            "0" | "false" | "no" | "off"
                        );
                    }
                    "tfrag" | "tls_frag_length" => {
                        let (min_len, max_len) = anet_common::config::parse_range_pair(
                            &v,
                            cfg.tls_frag.min_len as u64,
                            cfg.tls_frag.max_len as u64,
                            1,
                        );
                        cfg.tls_frag.min_len = min_len as usize;
                        cfg.tls_frag.max_len = max_len as usize;
                    }
                    "tdelay" | "tls_frag_delay_ms" => {
                        let (min_d, max_d) = anet_common::config::parse_range_pair(
                            &v,
                            cfg.tls_frag.min_delay_ms,
                            cfg.tls_frag.max_delay_ms,
                            0,
                        );
                        cfg.tls_frag.min_delay_ms = min_d;
                        cfg.tls_frag.max_delay_ms = max_d;
                    }
                    _ => {}
                }
            }
        }

        cfg
    }

    /// Гарантированно возвращает "host:port" даже если порт не был указан в DSN
    pub fn endpoint(&self) -> anyhow::Result<String> {
        let (host, port) = self.host_port()?;
        Ok(format!("{}:{}", host, port))
    }

    pub fn websocket_pool_size(&self) -> usize {
        let mut pool = anet_common::consts::WS_DEFAULT_POOL_SIZE;
        if let Ok(parsed) = reqwest::Url::parse(&self.dsn) {
            for (k, v) in parsed.query_pairs() {
                if matches!(k.as_ref(), "pool" | "mux") {
                    if let Ok(val) = v.trim().parse::<usize>() {
                        pool = val.clamp(1, anet_common::consts::WS_MAX_POOL_SIZE);
                    }
                }
            }
        }
        pool
    }

    pub fn websocket_url(&self) -> anyhow::Result<String> {
        let mode = self.mode()?;
        anyhow::ensure!(mode == TransportMode::Websocket, "DSN '{}' is not a websocket endpoint", self.dsn);
        if let Ok(mut parsed) = reqwest::Url::parse(&self.dsn) {
            if parsed.query().is_some() {
                let kept: Vec<(String, String)> = parsed
                    .query_pairs()
                    .filter(|(k, _)| {
                        !matches!(
                            k.as_ref(),
                            "fp" | "tls_fingerprint"
                                | "verify"
                                | "tls_verify_peer"
                                | "pin"
                                | "tls_pin_sha256"
                                | "tls_frag"
                                | "tls_frag_enabled"
                                | "tfrag"
                                | "tls_frag_length"
                                | "tdelay"
                                | "tls_frag_delay_ms"
                                | "pool"
                                | "mux"
                        )
                    })
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect();
                if kept.is_empty() {
                    parsed.set_query(None);
                } else {
                    let mut pairs = parsed.query_pairs_mut();
                    pairs.clear();
                    for (k, v) in kept {
                        pairs.append_pair(&k, &v);
                    }
                }
                return Ok(parsed.to_string());
            }
        }
        Ok(self.dsn.clone())
    }

    pub fn host_port(&self) -> anyhow::Result<(String, u16)> {
        let uri: http::Uri = self.dsn.parse()?;
        let host = uri.host().ok_or_else(|| anyhow::anyhow!("server DSN '{}' has no host", self.dsn))?;

        let scheme = uri.scheme_str().unwrap_or("").to_lowercase();
        let port = uri.port_u16().unwrap_or(match scheme.as_str() {
            "https" | "wss" | "wrtc" => 443,
            "http" | "ws" => 80,
            "ssh" => 22,
            "vnc" => 5900,
            "imap" | "imaps" => 993,
            "quic" => 443,
            _ => 0,
        });
        anyhow::ensure!(port != 0, "server DSN '{}' has no port and unknown scheme", self.dsn);
        Ok((host.to_string(), port))
    }

    /// Получить имя сервера.
    /// Если имя не указано в TOML — генерируем его на лету из DSN.
    pub fn get_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| {
            let host = self.host_port().map(|(host, _)| host).unwrap_or_else(|_| self.dsn.clone());
            let mode_str = match self.mode().unwrap_or(TransportMode::Quic) {
                TransportMode::Quic => "QUIC",
                TransportMode::Ssh => "SSH",
                TransportMode::Vnc => "VNC",
                TransportMode::Websocket => "WS",
                TransportMode::Ahttp => "AHTTP",
                TransportMode::Wrtc => "WRTC",
                TransportMode::Imap => "IMAP",
            };

            format!("{}:{}", host, mode_str)
        })
    }
}

fn default_timeout_secs() -> u64 {
    10
}

fn default_ssh_min_session_secs() -> u64 { 8 * 60 }
fn default_ssh_max_session_secs() -> u64 { 25 * 60 }
fn default_vnc_min_session_secs() -> u64 { 8 * 60 }
fn default_vnc_max_session_secs() -> u64 { 25 * 60 }
fn default_websocket_min_session_secs() -> u64 { 8 * 60 }
fn default_websocket_max_session_secs() -> u64 { 25 * 60 }

fn deserialize_weight<'de, D>(deserializer: D) -> Result<Option<i32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;
    struct WeightVisitor;

    impl<'de> de::Visitor<'de> for WeightVisitor {
        type Value = Option<i32>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("an integer or string representing server weight")
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E> {
            Ok(Some(v as i32))
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
            Ok(Some(v as i32))
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            v.trim().parse::<i32>().map(Some).map_err(de::Error::custom)
        }

        fn visit_none<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
            deserializer.deserialize_any(WeightVisitor)
        }
    }

    deserializer.deserialize_option(WeightVisitor)
}

// Расширенная конфигурация HTTP-транспорта на стороне клиента (секция `[ahttp]` в `client.toml`)
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AhttpConfig {
    pub pool_max_idle_per_host: usize,
    pub pool_idle_timeout_secs: u64,
    pub tcp_pool_size: Option<usize>,
    pub tcp_nodelay: bool,
    pub timeout_secs: u64,
    pub handshake_path: String,
    pub auth_path: String,
    pub traffic_path: String,
    pub coalesce_budget_bytes: usize,
    pub uplink_coalesce_budget_bytes: Option<usize>,
    pub poll_timeout_ms: u64,
    pub concurrency: usize,
    pub reassembly_queue_max_size: usize,
    /// Таймаут ожидания пропавшего/задержанного пакета при разрыве последовательности (мс).
    pub reassembly_gap_timeout_ms: u64,
    /// Емкость исходящей очереди пакетов (TUN -> AHTTP, защита от bufferbloat).
    pub tx_queue_capacity: usize,
    /// Емкость входящей очереди батчей (AHTTP -> ReassemblyQueue).
    pub downlink_queue_capacity: usize,
    /// Длительность микро-коалесценции тяжелого uplink-трафика (мкс, 0 отключает).
    pub micro_coalesce_us: u64,
    /// Минимальный размер накопленного батча (байт), при котором срабатывает `micro_coalesce_us`.
    pub micro_coalesce_min_bytes: usize,
    /// Максимум одновременных пустых idle long-poll запросов (`1` для CDN/CF, `0` — без ограничения).
    pub max_idle_polls: usize,
    /// Базовая пауза после пустого ответа сервера без данных (мс).
    pub idle_poll_interval_ms: u64,
    /// Потолок адаптивного backoff в состоянии полного простоя (мс).
    pub idle_backoff_max_ms: u64,
    /// Максимум повторных попыток одного HTTP-запроса при ошибках CDN (`429`/`502`/`503`/`52x`/сеть).
    pub max_retries: u32,
    /// Начальная задержка экспоненциального отката при ретрае HTTP-запроса (мс).
    pub retry_base_ms: u64,
    /// Максимальная задержка экспоненциального отката и потолок учёта `Retry-After` (мс).
    pub retry_max_ms: u64,
    /// Порог подряд идущих проваленных транзакций до запуска переподключения ASTP-сессии.
    pub max_consecutive_failures: u32,
    /// Общий таймаут цикла ASTP session-resume/reconnect (сек). При `None`: `server.timeout_secs.max(10) * 3`.
    pub reconnect_timeout_secs: Option<u64>,
    /// Минимальная пауза между попытками переподключения ASTP-сессии (мс).
    pub reconnect_retry_min_ms: u64,
    /// Максимальная пауза между попытками переподключения ASTP-сессии (мс).
    pub reconnect_retry_max_ms: u64,
    /// Прерывать транспорт и пересоздавать TUN, если после реконнекта сервер выдал новый IP/шлюз.
    pub abort_on_ip_change: bool,
    /// Передавать `session_id` в HTTP-заголовке (`session_id_header`) вместо query-параметра URL.
    pub send_session_in_header: bool,
    /// Имя HTTP-заголовка для `session_id` при `send_session_in_header = true`.
    pub session_id_header: String,
    /// Имя query-параметра URL для `session_id` при `send_session_in_header = false`.
    pub session_id_query_param: String,

    pub http2_adaptive_window: bool,
    pub http2_initial_stream_window_size: Option<u32>,
    pub http2_initial_connection_window_size: Option<u32>,
    pub http2_max_frame_size: Option<u32>,
    pub http2_max_header_list_size: Option<u32>,
    pub http2_keep_alive_interval_secs: Option<u64>,
    pub http2_keep_alive_timeout_secs: Option<u64>,
    pub http2_keep_alive_while_idle: bool,
}

impl Default for AhttpConfig {
    fn default() -> Self {
        Self {
            pool_max_idle_per_host: 16,
            pool_idle_timeout_secs: 60,
            tcp_pool_size: Some(1),
            tcp_nodelay: true,
            timeout_secs: 10,
            handshake_path: anet_common::consts::AHTTP_DEFAULT_HANDSHAKE_PATH.to_string(),
            auth_path: anet_common::consts::AHTTP_DEFAULT_AUTH_PATH.to_string(),
            traffic_path: anet_common::consts::AHTTP_DEFAULT_TRAFFIC_PATH.to_string(),
            coalesce_budget_bytes: 65536,
            uplink_coalesce_budget_bytes: None,
            poll_timeout_ms: 10,
            concurrency: 8,
            reassembly_queue_max_size:
                anet_common::consts::AHTTP_DEFAULT_REASSEMBLY_QUEUE_MAX_SIZE,
            reassembly_gap_timeout_ms:
                anet_common::consts::AHTTP_DEFAULT_REASSEMBLY_GAP_TIMEOUT_MS,
            tx_queue_capacity: anet_common::consts::AHTTP_DEFAULT_TX_QUEUE_CAPACITY,
            downlink_queue_capacity: anet_common::consts::AHTTP_DEFAULT_DOWNLINK_QUEUE_CAPACITY,
            micro_coalesce_us: anet_common::consts::AHTTP_DEFAULT_MICRO_COALESCE_US,
            micro_coalesce_min_bytes: anet_common::consts::AHTTP_DEFAULT_MICRO_COALESCE_MIN_BYTES,
            max_idle_polls: anet_common::consts::AHTTP_DEFAULT_MAX_IDLE_POLLS,
            idle_poll_interval_ms: anet_common::consts::AHTTP_DEFAULT_IDLE_POLL_INTERVAL_MS,
            idle_backoff_max_ms: anet_common::consts::AHTTP_DEFAULT_IDLE_BACKOFF_MAX_MS,
            max_retries: anet_common::consts::AHTTP_DEFAULT_MAX_RETRIES,
            retry_base_ms: anet_common::consts::AHTTP_DEFAULT_RETRY_BASE_MS,
            retry_max_ms: anet_common::consts::AHTTP_DEFAULT_RETRY_MAX_MS,
            max_consecutive_failures: anet_common::consts::AHTTP_DEFAULT_MAX_CONSECUTIVE_FAILURES,
            reconnect_timeout_secs: None,
            reconnect_retry_min_ms: anet_common::consts::AHTTP_DEFAULT_RECONNECT_RETRY_MIN_MS,
            reconnect_retry_max_ms: anet_common::consts::AHTTP_DEFAULT_RECONNECT_RETRY_MAX_MS,
            abort_on_ip_change: true,
            send_session_in_header: false,
            session_id_header: anet_common::consts::AHTTP_DEFAULT_SESSION_ID_HEADER.to_string(),
            session_id_query_param: anet_common::consts::AHTTP_DEFAULT_SESSION_ID_QUERY_PARAM
                .to_string(),

            http2_adaptive_window: false,
            http2_initial_stream_window_size: None,
            http2_initial_connection_window_size: None,
            http2_max_frame_size: None,
            http2_max_header_list_size: None,
            http2_keep_alive_interval_secs: Some(20),
            http2_keep_alive_timeout_secs: Some(10),
            http2_keep_alive_while_idle: true,
        }
    }
}

impl AhttpConfig {
    pub fn effective_reassembly_gap_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.reassembly_gap_timeout_ms.max(1))
    }

    pub fn effective_tx_queue_capacity(&self) -> usize {
        self.tx_queue_capacity.max(16)
    }

    pub fn effective_downlink_queue_capacity(&self) -> usize {
        self.downlink_queue_capacity.max(16)
    }

    pub fn effective_micro_coalesce(&self) -> std::time::Duration {
        std::time::Duration::from_micros(self.micro_coalesce_us)
    }

    pub fn effective_retry_base_ms(&self) -> u64 {
        self.retry_base_ms.max(10)
    }

    pub fn effective_retry_max_ms(&self) -> u64 {
        self.retry_max_ms.max(self.effective_retry_base_ms())
    }

    pub fn effective_reconnect_timeout(&self, server_timeout_secs: u64) -> std::time::Duration {
        let secs = self
            .reconnect_timeout_secs
            .unwrap_or_else(|| server_timeout_secs.max(10) * 3)
            .max(1);
        std::time::Duration::from_secs(secs)
    }

    pub fn random_reconnect_retry_delay(&self) -> std::time::Duration {
        use rand::Rng;
        let min = self.reconnect_retry_min_ms.max(50);
        let max = self.reconnect_retry_max_ms.max(min);
        std::time::Duration::from_millis(rand::rngs::OsRng.gen_range(min..=max))
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

/// Конфигурация транспорта WebSocket на стороне клиента (секция `[websocket]` в `client.toml`).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct WebSocketConfig {
    /// Максимальный размер скользящего окна переупорядочивания входящих пакетов (`ReassemblyQueue`)
    /// при работе мульти-сокетного пула `WSS ?pool=N`.
    pub reassembly_queue_max_size: usize,
    /// Таймаут ожидания пропавшего/задержанного пакета при разрыве последовательности (мс).
    pub reassembly_gap_timeout_ms: u64,
    /// Таймаут отправки одного WebSocket-фрейма (мс). Защищает от зависания на «чёрной дыре» TCP.
    pub write_timeout_ms: u64,
    /// Таймаут закрытия WebSocket-сокета (мс).
    pub close_timeout_ms: u64,
    /// Таймаут TCP + TLS + HTTP Upgrade (и `WS_MUX_BIND`) одного WebSocket-соединения (сек).
    pub handshake_timeout_secs: u64,
    /// Минимальный интервал отправки клиентского keepalive Ping (сек).
    pub ping_interval_min_secs: u64,
    /// Максимальный интервал отправки клиентского keepalive Ping (сек).
    pub ping_interval_max_secs: u64,
    /// Емкость исходящей очереди пакетов клиента из TUN в WS-пул (защита от bufferbloat).
    pub tx_queue_capacity: usize,
    /// Емкость входящей очереди батчей из WS-пула в `ReassemblyQueue`.
    pub downlink_queue_capacity: usize,
    /// Бюджет коалесценции пакетов на один сокет при `active_slots > 1` (байт).
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
    /// Максимум подряд неудачных попыток `WS_MUX_BIND` при `active_slots > 0` до эскалации
    /// к полному ASTP-переподключению (`0` — не ограничивать).
    pub bind_max_retries: u32,
    /// Максимум явных отклонений `WS_MUX_BIND` сервером при `active_slots > 0` до эскалации
    /// к полному ASTP-переподключению (`0` — не ограничивать).
    pub bind_reject_max_retries: u32,
    /// Минимальная пауза перед повтором `WS_MUX_BIND` (мс).
    pub bind_retry_min_ms: u64,
    /// Максимальная пауза перед повтором `WS_MUX_BIND` (мс).
    pub bind_retry_max_ms: u64,
    /// Общий таймаут цикла `reconnect_astp_session` (сек).
    /// При `None` вычисляется как `server.timeout_secs.max(10) * 3`.
    pub reconnect_timeout_secs: Option<u64>,
    /// Минимальная пауза между попытками `reconnect_astp_session` (мс).
    pub reconnect_retry_min_ms: u64,
    /// Максимальная пауза между попытками `reconnect_astp_session` (мс).
    pub reconnect_retry_max_ms: u64,
    /// Немедленно прерывать цикл `reconnect_astp_session`, если сервер выдал новый
    /// туннельный IP/шлюз (чтобы ядро клиента сразу перенастроило TUN).
    pub abort_on_ip_change: bool,
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            reassembly_queue_max_size: anet_common::consts::WS_REASSEMBLY_QUEUE_MAX_SIZE,
            reassembly_gap_timeout_ms: anet_common::consts::WS_REASSEMBLY_GAP_TIMEOUT_MS,
            write_timeout_ms: anet_common::consts::WS_DEFAULT_WRITE_TIMEOUT_MS,
            close_timeout_ms: anet_common::consts::WS_DEFAULT_CLOSE_TIMEOUT_MS,
            handshake_timeout_secs: anet_common::consts::WS_DEFAULT_HANDSHAKE_TIMEOUT_SECS,
            ping_interval_min_secs: anet_common::consts::WS_DEFAULT_CLIENT_PING_MIN_SECS,
            ping_interval_max_secs: anet_common::consts::WS_DEFAULT_CLIENT_PING_MAX_SECS,
            tx_queue_capacity: anet_common::consts::WS_DEFAULT_TX_QUEUE_CAPACITY,
            downlink_queue_capacity: anet_common::consts::WS_DEFAULT_DOWNLINK_QUEUE_CAPACITY,
            pool_coalesce_budget_bytes: anet_common::consts::WS_POOL_COALESCE_BUDGET_BYTES,
            single_coalesce_budget_bytes:
                anet_common::consts::WS_DEFAULT_SINGLE_COALESCE_BUDGET_BYTES,
            max_message_size: anet_common::consts::WS_DEFAULT_MAX_MESSAGE_SIZE,
            read_buffer_size: anet_common::consts::WS_DEFAULT_READ_BUFFER_SIZE,
            write_buffer_size: anet_common::consts::WS_DEFAULT_WRITE_BUFFER_SIZE,
            max_write_buffer_size: anet_common::consts::WS_DEFAULT_MAX_WRITE_BUFFER_SIZE,
            bind_max_retries: anet_common::consts::WS_DEFAULT_BIND_MAX_RETRIES,
            bind_reject_max_retries: anet_common::consts::WS_DEFAULT_BIND_REJECT_MAX_RETRIES,
            bind_retry_min_ms: anet_common::consts::WS_DEFAULT_BIND_RETRY_MIN_MS,
            bind_retry_max_ms: anet_common::consts::WS_DEFAULT_BIND_RETRY_MAX_MS,
            reconnect_timeout_secs: None,
            reconnect_retry_min_ms: anet_common::consts::WS_DEFAULT_RECONNECT_RETRY_MIN_MS,
            reconnect_retry_max_ms: anet_common::consts::WS_DEFAULT_RECONNECT_RETRY_MAX_MS,
            abort_on_ip_change: true,
        }
    }
}

impl WebSocketConfig {
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

    pub fn random_bind_retry_delay(&self) -> std::time::Duration {
        use rand::Rng;
        let min = self.bind_retry_min_ms.max(50);
        let max = self.bind_retry_max_ms.max(min);
        std::time::Duration::from_millis(rand::rngs::OsRng.gen_range(min..=max))
    }

    pub fn random_reconnect_retry_delay(&self) -> std::time::Duration {
        use rand::Rng;
        let min = self.reconnect_retry_min_ms.max(50);
        let max = self.reconnect_retry_max_ms.max(min);
        std::time::Duration::from_millis(rand::rngs::OsRng.gen_range(min..=max))
    }

    pub fn effective_reconnect_timeout(&self, server_timeout_secs: u64) -> std::time::Duration {
        let secs = self
            .reconnect_timeout_secs
            .unwrap_or_else(|| server_timeout_secs.max(10) * 3)
            .max(1);
        std::time::Duration::from_secs(secs)
    }

    pub fn effective_tx_queue_capacity(&self) -> usize {
        self.tx_queue_capacity.max(16)
    }

    pub fn effective_downlink_queue_capacity(&self) -> usize {
        self.downlink_queue_capacity.max(16)
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

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RoutingConfig {
    /// Опциональный URL для скачивания скомпилированного кэша правил rules.abc
    #[serde(default)]
    pub rules_url: Option<String>,

    /// Локальные пользовательские исключения [routing.overrides] (п. 4.2 ТЗ)
    #[serde(default)]
    pub overrides: anet_filter_core::LocalOverridesConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct CoreConfig {
    #[serde(default)]
    pub main: MainConfig,

    #[serde(default)]
    pub keys: ClientKeys,

    #[serde(default)]
    pub quic_transport: QuicConfig,

    #[serde(default)]
    pub stats: StatsConfig,

    #[serde(default)]
    pub stealth: StealthConfig,

    #[serde(default)]
    pub transport: TransportConfig,

    // Массив серверов [[servers]] для переключения при сбоях
    #[serde(default)]
    pub servers: Vec<ServerConfig>,

    #[serde(default)]
    pub ahttp: AhttpConfig,

    #[serde(default)]
    pub websocket: WebSocketConfig,

    #[serde(default)]
    pub routing: RoutingConfig,

    #[serde(default)]
    pub wrtc: WrtcConfig,

    #[serde(default)]
    pub connectivity: ConnectivityConfig,

    #[serde(default)]
    pub browser_profiles: Vec<BrowserProfileConfig>,

    #[serde(default)]
    pub imap: ImapConfig,
}

impl CoreConfig {
    /// Возвращает URL эндпоинта или базового сервера anet-auth для загрузки rules.abc
    pub fn get_rules_server_url(&self) -> Option<String> {
        if let Some(url) = &self.routing.rules_url {
            let trimmed = url.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
        if let Some(cfg_url) = self.main.get_config_url() {
            let trimmed = cfg_url.trim();
            if let Ok(uri) = trimmed.parse::<http::Uri>() {
                if let (Some(scheme), Some(authority)) = (uri.scheme_str(), uri.authority()) {
                    let base = format!("{}://{}", scheme, authority);
                    if let Some(idx) = trimmed.find("/config/") {
                        let tail = trimmed[idx + "/config/".len()..]
                            .trim_matches('/')
                            .split(['?', '#'])
                            .next()
                            .unwrap_or("");
                        if !tail.is_empty() {
                            return Some(format!("{}/api/v1/routing/compiled-rules/{}", base, tail));
                        }
                    }
                    return Some(base);
                }
            }
        }
        None
    }

    /// Проверяет обязательный список DSN-серверов.
    pub fn sanitize(&mut self) -> anyhow::Result<()> {
        if self.servers.is_empty() {
            anyhow::bail!("No servers defined in [[servers]]");
        }

        if self.main.dns_server_list.is_empty() {
            self.main.dns_server_list = default_dns_server_list();
        }

        self.main.per_app_mode = self.main.effective_per_app_mode();

        if self.main.per_app_mode == PerAppMode::Include && self.main.per_app.is_empty() {
            log::warn!(
                "[Config] Per-app 'include' mode selected, but 'per_app' list is empty. Falling back to 'all' traffic mode."
            );
            self.main.per_app_mode = PerAppMode::All;
        }

        if let Some(ref pin) = self.stealth.tls_pin_sha256 {
            if !pin.trim().is_empty() {
                anet_common::boring_tls::parse_sha256_pin(pin)?;
            }
        }

        for server in &self.servers {
            server.mode()?;
            server.host_port()?;
            if server.mode()? == TransportMode::Websocket {
                server.websocket_url()?;
            }
            if let Some(ref pin) = server.tls_pin_sha256 {
                if !pin.trim().is_empty() {
                    anet_common::boring_tls::parse_sha256_pin(pin)?;
                }
            }
        }

        anet_common::boring_tls::set_default_tls_config(self.stealth.to_tls_client_config());
        if !self.browser_profiles.is_empty() {
            anet_common::boring_tls::set_browser_profiles(self.browser_profiles.clone());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{ServerConfig, TransportMode};
    use serde::Deserialize;

    #[test]
    fn dsn_selects_transport_and_endpoint() {
        let server = ServerConfig {
            dsn: "quic://vpn.example.com:4519".to_string(),
            ..Default::default()
        };
        assert_eq!(server.mode().unwrap(), TransportMode::Quic);
        assert_eq!(server.endpoint().unwrap(), "vpn.example.com:4519");

        let websocket = ServerConfig {
            dsn: "wss://vpn.example.com:8443/socket".to_string(),
            ..server.clone()
        };
        assert_eq!(websocket.mode().unwrap(), TransportMode::Websocket);
        assert_eq!(websocket.websocket_url().unwrap(), "wss://vpn.example.com:8443/socket");

        let ws_no_port = ServerConfig {
            dsn: "wss://vpn.example.com/socket".to_string(),
            ..Default::default()
        };
        assert_eq!(ws_no_port.endpoint().unwrap(), "vpn.example.com:443");

        let imap_server = ServerConfig {
            dsn: "imap://imap.mail.ru:993?acc=user1%40mail.ru:pass1".to_string(),
            ..Default::default()
        };
        assert_eq!(imap_server.mode().unwrap(), TransportMode::Imap);
        assert_eq!(imap_server.endpoint().unwrap(), "imap.mail.ru:993");

        let imaps_no_port = ServerConfig {
            dsn: "imaps://imap.yandex.ru".to_string(),
            ..Default::default()
        };
        assert_eq!(imaps_no_port.mode().unwrap(), TransportMode::Imap);
        assert_eq!(imaps_no_port.endpoint().unwrap(), "imap.yandex.ru:993");
    }

    #[test]
    fn server_group_and_weight_deserialization() {
        let toml_str = r#"
            [[servers]]
            name = "Node 1"
            dsn = "quic://1.2.3.4:443"
            group_name = "Group A"
            group_id = "11111111-2222-3333-4444-555555555555"
            weight = 50
            weigth = 50

            [[servers]]
            name = "Node 2"
            dsn = "quic://1.2.3.4:444"
            group_name = "Group A"
            group_id = "11111111-2222-3333-4444-555555555555"
            weight = "100"
        "#;

        #[derive(Deserialize)]
        struct TestConfig {
            servers: Vec<ServerConfig>,
        }

        let cfg: TestConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.servers.len(), 2);
        assert_eq!(cfg.servers[0].group_name.as_deref(), Some("Group A"));
        assert_eq!(cfg.servers[0].weight(), 50);
        assert_eq!(cfg.servers[1].weight(), 100);
    }

    #[test]
    fn tls_fingerprint_and_verify_config_resolution() {
        use super::CoreConfig;
        use anet_common::boring_tls::TlsFingerprint;

        let toml_str = r#"
            [stealth]
            tls_fingerprint = "randomized"
            # tls_verify_peer по умолчанию должен быть true!

            [[servers]]
            name = "Default Inherited Node"
            dsn = "https://node1.example.com/api/v2/telemetry"

            [[servers]]
            name = "Firefox Pinned Node"
            dsn = "wss://node2.example.com/socket"
            tls_fingerprint = "firefox"
            tls_pin_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

            [[servers]]
            name = "Query Override Node"
            dsn = "https://node3.example.com/api/v2/telemetry?fp=safari&verify=0"
        "#;

        let mut cfg: CoreConfig = toml::from_str(toml_str).unwrap();
        cfg.sanitize().unwrap();

        assert_eq!(cfg.stealth.tls_fingerprint, TlsFingerprint::Randomized);
        assert!(cfg.stealth.tls_verify_peer);

        let eff0 = cfg.servers[0].effective_tls_config(&cfg.stealth);
        assert_eq!(eff0.fingerprint, TlsFingerprint::Randomized);
        assert!(eff0.verify_peer);
        assert!(eff0.pin_sha256.is_none());

        let eff1 = cfg.servers[1].effective_tls_config(&cfg.stealth);
        assert_eq!(eff1.fingerprint, TlsFingerprint::Firefox);
        assert!(eff1.verify_peer);
        assert_eq!(
            eff1.pin_sha256.as_deref(),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );

        let eff2 = cfg.servers[2].effective_tls_config(&cfg.stealth);
        assert_eq!(eff2.fingerprint, TlsFingerprint::Safari);
        assert!(!eff2.verify_peer);

        let ws_with_query = ServerConfig {
            dsn: "wss://node2.example.com/socket?pool=6&fp=firefox&verify=1&tls_frag=1&tfrag=12..24&tdelay=1..3".to_string(),
            ..Default::default()
        };
        assert_eq!(
            ws_with_query.websocket_url().unwrap(),
            "wss://node2.example.com/socket"
        );
        assert_eq!(ws_with_query.websocket_pool_size(), 6);
        let ws_default_pool = ServerConfig {
            dsn: "wss://node2.example.com/socket".to_string(),
            ..Default::default()
        };
        assert_eq!(ws_default_pool.websocket_pool_size(), 4);
        let ws_clamped_pool = ServerConfig {
            dsn: "wss://node2.example.com/socket?mux=99".to_string(),
            ..Default::default()
        };
        assert_eq!(ws_clamped_pool.websocket_pool_size(), 8);
        assert_eq!(ws_clamped_pool.websocket_url().unwrap(), "wss://node2.example.com/socket");
        let eff_ws = ws_with_query.effective_tls_config(&cfg.stealth);
        assert!(eff_ws.tls_frag.enabled);
        assert_eq!(eff_ws.tls_frag.min_len, 12);
        assert_eq!(eff_ws.tls_frag.max_len, 24);
        assert_eq!(eff_ws.tls_frag.min_delay_ms, 1);
        assert_eq!(eff_ws.tls_frag.max_delay_ms, 3);
    }

    #[test]
    fn browser_profiles_toml_deserialization() {
        use super::CoreConfig;

        let toml_str = r#"
            [[servers]]
            name = "Node 1"
            dsn = "https://node1.example.com/api/v2/telemetry"

            [[browser_profiles]]
            name = "Chrome"
            grease = true
            permute_extensions = true
            session_ticket = true
            ocsp_stapling = true
            signed_cert_timestamps = true
            ech_grease = true
            alps_h2 = true
            cert_compression = ["brotli"]
            user_agents = ["CustomUA/1.0"]
            headers = ["Accept-Language: ru-RU,ru;q=0.9"]
            ws_headers_order = ["Host", "Upgrade", "Connection"]
            h2_initial_stream_window_size = 6291456
            h2_initial_connection_window_size = 15728640
            h2_max_header_list_size = 262144
        "#;

        let mut cfg: CoreConfig = toml::from_str(toml_str).unwrap();
        cfg.sanitize().unwrap();
        assert_eq!(cfg.browser_profiles.len(), 1);
        assert_eq!(cfg.browser_profiles[0].name, "Chrome");
        assert_eq!(cfg.browser_profiles[0].cert_compression, vec!["brotli"]);
        assert_eq!(
            cfg.browser_profiles[0].h2_initial_stream_window_size,
            Some(6_291_456)
        );
        anet_common::boring_tls::set_browser_profiles(Vec::new());
    }

    #[test]
    fn websocket_reassembly_config_defaults_and_overrides() {
        use super::CoreConfig;
        use std::time::Duration;

        let default_toml = r#"
            [[servers]]
            name = "WS Node"
            dsn = "wss://node.example.com/socket?pool=4"
        "#;
        let default_cfg: CoreConfig = toml::from_str(default_toml).unwrap();
        assert_eq!(
            default_cfg.websocket.reassembly_queue_max_size,
            anet_common::consts::WS_REASSEMBLY_QUEUE_MAX_SIZE
        );
        assert_eq!(
            default_cfg.websocket.reassembly_gap_timeout_ms,
            anet_common::consts::WS_REASSEMBLY_GAP_TIMEOUT_MS
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
        assert_eq!(
            default_cfg.websocket.bind_max_retries,
            anet_common::consts::WS_DEFAULT_BIND_MAX_RETRIES
        );
        assert_eq!(
            default_cfg.websocket.bind_reject_max_retries,
            anet_common::consts::WS_DEFAULT_BIND_REJECT_MAX_RETRIES
        );
        assert_eq!(
            default_cfg.websocket.effective_reconnect_timeout(8),
            Duration::from_secs(30)
        );
        assert!(default_cfg.websocket.abort_on_ip_change);

        let custom_toml = r#"
            [websocket]
            reassembly_queue_max_size = 8192
            reassembly_gap_timeout_ms = 90
            write_timeout_ms = 6000
            close_timeout_ms = 1200
            handshake_timeout_secs = 20
            ping_interval_min_secs = 30
            ping_interval_max_secs = 30
            tx_queue_capacity = 1024
            downlink_queue_capacity = 2048
            pool_coalesce_budget_bytes = 32768
            single_coalesce_budget_bytes = 98304
            max_message_size = 524288
            read_buffer_size = 262144
            write_buffer_size = 262144
            max_write_buffer_size = 1048576
            bind_max_retries = 5
            bind_reject_max_retries = 3
            bind_retry_min_ms = 300
            bind_retry_max_ms = 300
            reconnect_timeout_secs = 45
            reconnect_retry_min_ms = 250
            reconnect_retry_max_ms = 250
            abort_on_ip_change = false

            [[servers]]
            name = "WS Node"
            dsn = "wss://node.example.com/socket?pool=4"
        "#;
        let custom_cfg: CoreConfig = toml::from_str(custom_toml).unwrap();
        assert_eq!(custom_cfg.websocket.reassembly_queue_max_size, 8192);
        assert_eq!(custom_cfg.websocket.reassembly_gap_timeout_ms, 90);
        assert_eq!(custom_cfg.websocket.write_timeout(), Duration::from_millis(6000));
        assert_eq!(custom_cfg.websocket.close_timeout(), Duration::from_millis(1200));
        assert_eq!(custom_cfg.websocket.handshake_timeout(), Duration::from_secs(20));
        assert_eq!(custom_cfg.websocket.random_ping_interval(), Duration::from_secs(30));
        assert_eq!(custom_cfg.websocket.effective_tx_queue_capacity(), 1024);
        assert_eq!(custom_cfg.websocket.effective_downlink_queue_capacity(), 2048);
        assert_eq!(custom_cfg.websocket.effective_pool_coalesce_budget(), 32768);
        assert_eq!(custom_cfg.websocket.effective_single_coalesce_budget(), 98304);
        assert_eq!(custom_cfg.websocket.effective_max_message_size(), 524288);
        assert_eq!(custom_cfg.websocket.effective_read_buffer_size(), 262144);
        assert_eq!(custom_cfg.websocket.effective_write_buffer_size(), 262144);
        assert_eq!(custom_cfg.websocket.effective_max_write_buffer_size(), 1048576);
        assert_eq!(custom_cfg.websocket.bind_max_retries, 5);
        assert_eq!(custom_cfg.websocket.bind_reject_max_retries, 3);
        assert_eq!(custom_cfg.websocket.random_bind_retry_delay(), Duration::from_millis(300));
        assert_eq!(custom_cfg.websocket.effective_reconnect_timeout(8), Duration::from_secs(45));
        assert_eq!(custom_cfg.websocket.random_reconnect_retry_delay(), Duration::from_millis(250));
        assert!(!custom_cfg.websocket.abort_on_ip_change);
    }

    #[test]
    fn ahttp_config_defaults_and_overrides() {
        use super::CoreConfig;
        use std::time::Duration;

        let default_cfg: CoreConfig = toml::from_str(
            r#"
            [[servers]]
            name = "AHTTP Node"
            dsn = "https://cdn.example.com/api/v2/telemetry"
            "#,
        )
        .unwrap();
        assert_eq!(
            default_cfg.ahttp.max_idle_polls,
            anet_common::consts::AHTTP_DEFAULT_MAX_IDLE_POLLS
        );
        assert_eq!(
            default_cfg.ahttp.effective_reassembly_gap_timeout(),
            Duration::from_millis(anet_common::consts::AHTTP_DEFAULT_REASSEMBLY_GAP_TIMEOUT_MS)
        );
        assert_eq!(
            default_cfg.ahttp.effective_reconnect_timeout(10),
            Duration::from_secs(30)
        );
        assert!(default_cfg.ahttp.abort_on_ip_change);
        assert!(!default_cfg.ahttp.send_session_in_header);
        assert_eq!(default_cfg.ahttp.session_id_header, "X-Session-Id");
        assert_eq!(default_cfg.ahttp.effective_session_id_query_param(), "session_id");

        let custom_cfg: CoreConfig = toml::from_str(
            r#"
            [ahttp]
            reassembly_gap_timeout_ms = 90
            tx_queue_capacity = 512
            downlink_queue_capacity = 1024
            micro_coalesce_us = 300
            micro_coalesce_min_bytes = 512
            max_idle_polls = 2
            idle_poll_interval_ms = 40
            idle_backoff_max_ms = 800
            max_retries = 6
            retry_base_ms = 150
            retry_max_ms = 5000
            max_consecutive_failures = 10
            reconnect_timeout_secs = 45
            reconnect_retry_min_ms = 200
            reconnect_retry_max_ms = 200
            abort_on_ip_change = false
            send_session_in_header = true
            session_id_header = "X-Client-Token"
            session_id_query_param = "sid"

            [[servers]]
            name = "AHTTP Node"
            dsn = "https://cdn.example.com/api/v2/telemetry"
            "#,
        )
        .unwrap();
        assert_eq!(
            custom_cfg.ahttp.effective_reassembly_gap_timeout(),
            Duration::from_millis(90)
        );
        assert_eq!(custom_cfg.ahttp.effective_tx_queue_capacity(), 512);
        assert_eq!(custom_cfg.ahttp.effective_downlink_queue_capacity(), 1024);
        assert_eq!(
            custom_cfg.ahttp.effective_micro_coalesce(),
            Duration::from_micros(300)
        );
        assert_eq!(custom_cfg.ahttp.micro_coalesce_min_bytes, 512);
        assert_eq!(custom_cfg.ahttp.max_idle_polls, 2);
        assert_eq!(custom_cfg.ahttp.idle_poll_interval_ms, 40);
        assert_eq!(custom_cfg.ahttp.idle_backoff_max_ms, 800);
        assert_eq!(custom_cfg.ahttp.max_retries, 6);
        assert_eq!(custom_cfg.ahttp.effective_retry_base_ms(), 150);
        assert_eq!(custom_cfg.ahttp.effective_retry_max_ms(), 5000);
        assert_eq!(custom_cfg.ahttp.max_consecutive_failures, 10);
        assert_eq!(
            custom_cfg.ahttp.effective_reconnect_timeout(10),
            Duration::from_secs(45)
        );
        assert_eq!(
            custom_cfg.ahttp.random_reconnect_retry_delay(),
            Duration::from_millis(200)
        );
        assert!(!custom_cfg.ahttp.abort_on_ip_change);
        assert!(custom_cfg.ahttp.send_session_in_header);
        assert_eq!(custom_cfg.ahttp.session_id_header, "X-Client-Token");
        assert_eq!(custom_cfg.ahttp.effective_session_id_query_param(), "sid");
    }
}


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

    #[serde(default)]
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

    #[serde(default = "default_update_url")]
    pub update_url: String,

    /// URL для автоматического обновления конфигурации
    #[serde(default)]
    pub config_url: Option<String>,

    /// Альтернативное имя поля для совместимости с подписками
    #[serde(default)]
    pub subscription_url: Option<String>,
}

fn default_update_url() -> String {
    "https://api.github.com/repos/ZeroTworu/anet/releases/latest".to_string()
}

impl MainConfig {
    pub fn get_config_url(&self) -> Option<&str> {
        self.config_url.as_deref().or(self.subscription_url.as_deref())
    }
}

impl Default for MainConfig {
    fn default() -> Self {
        Self {
            tun_name: "anet-client".to_string(),
            route_for: vec![],
            exclude_route_for: vec![],
            dns_server_list: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            manual_routing: false,
            per_app: vec![],
            per_app_mode: PerAppMode::All,
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
    Doh,
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
    /// DoH Transport mode: "authoritative" | "recursive"
    #[serde(default)]
    pub doh_mode: Option<String>,

    /// Опциональное переопределение TLS-отпечатка для конкретного сервера:
    /// "auto" | "chrome" | "firefox" | "safari" | "randomized"
    #[serde(default)]
    pub tls_fingerprint: Option<anet_common::boring_tls::TlsFingerprint>,

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
            websocket_min_session_secs: default_websocket_min_session_secs(),
            websocket_max_session_secs: default_websocket_max_session_secs(),
            wrtc_media_keepalive_interval_ms: None,
            wrtc_ping_interval_secs: None,
            wrtc_fallback_jvb_ip: None,
            wrtc_fallback_jvb_port: None,
            wrtc_mode: None,
            doh_mode: None,
            tls_fingerprint: None,
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
            Some("doh") => Ok(TransportMode::Doh),
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
                            "fp" | "tls_fingerprint" | "verify" | "tls_verify_peer" | "pin" | "tls_pin_sha256"
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
            "https" | "wss" | "wrtc" | "doh" => 443,
            "http" | "ws" => 80,
            "ssh" => 22,
            "vnc" => 5900,
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
                TransportMode::Doh => "DOH",
            };

            format!("{}:{}", host, mode_str)
        })
    }
}

fn default_timeout_secs() -> u64 {
    10
}

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

// Новая расширенная структура для настройки HTTP-транспорта на стороне клиента
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
            handshake_path: "/handshake".to_string(),
            auth_path: "/auth".to_string(),
            traffic_path: "/traffic".to_string(),
            coalesce_budget_bytes: 65536,
            uplink_coalesce_budget_bytes: None,
            poll_timeout_ms: 10,
            concurrency: 8,
            reassembly_queue_max_size: 1024,

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
    pub routing: RoutingConfig,

    #[serde(default)]
    pub wrtc: WrtcConfig,

    #[serde(default)]
    pub connectivity: ConnectivityConfig,

    #[serde(default)]
    pub browser_profiles: Vec<BrowserProfileConfig>,
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
            timeout_secs: 10,
            server_pub_key: None,
            ssh_user: None,
            group_name: None,
            group_id: None,
            weight: None,
            weigth: None,
            websocket_min_session_secs: 480,
            websocket_max_session_secs: 1500,
            wrtc_media_keepalive_interval_ms: None,
            wrtc_ping_interval_secs: None,
            wrtc_fallback_jvb_ip: None,
            wrtc_fallback_jvb_port: None,
            wrtc_mode: None,
            doh_mode: None,
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
            timeout_secs: 10,
            server_pub_key: None,
            ssh_user: None,
            group_name: None,
            group_id: None,
            weight: None,
            weigth: None,
            websocket_min_session_secs: 480,
            websocket_max_session_secs: 1500,
            wrtc_media_keepalive_interval_ms: None,
            wrtc_ping_interval_secs: None,
            wrtc_fallback_jvb_ip: None,
            wrtc_fallback_jvb_port: None,
            wrtc_mode: None,
            doh_mode: None,
            ..Default::default()
        };
        assert_eq!(ws_no_port.endpoint().unwrap(), "vpn.example.com:443");
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
            dsn: "wss://node2.example.com/socket?fp=firefox&verify=1".to_string(),
            ..Default::default()
        };
        assert_eq!(
            ws_with_query.websocket_url().unwrap(),
            "wss://node2.example.com/socket"
        );
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
}
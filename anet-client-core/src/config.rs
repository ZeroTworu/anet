use anet_common::config::StealthConfig;
use anet_common::quic_settings::QuicConfig;
use serde::Deserialize;

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
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
}

fn default_update_url() -> String {
    "https://api.github.com/repos/ZeroTworu/anet/releases/latest".to_string()
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
}

impl Default for TransportMode {
    fn default() -> Self {
        TransportMode::Quic
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TransportConfig {
    pub ssh_user: Option<String>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            ssh_user: Some("hanyuu".to_string()),
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
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            name: None,
            dsn: String::new(),
            timeout_secs: default_timeout_secs(),
            server_pub_key: None,
            ssh_user: None,
            group_name: None,
            group_id: None,
            weight: None,
            weigth: None,
            websocket_min_session_secs: default_websocket_min_session_secs(),
            websocket_max_session_secs: default_websocket_max_session_secs(),
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
            Some(scheme) => anyhow::bail!("unsupported server DSN scheme '{scheme}'"),
            None => anyhow::bail!("server DSN '{}' has no scheme", self.dsn),
        }
    }

    /// ИСПРАВЛЕНИЕ: гарантированно возвращает "host:port" даже если порт не был указан в DSN!
    pub fn endpoint(&self) -> anyhow::Result<String> {
        let (host, port) = self.host_port()?;
        Ok(format!("{}:{}", host, port))
    }

    pub fn websocket_url(&self) -> anyhow::Result<String> {
        let mode = self.mode()?;
        anyhow::ensure!(mode == TransportMode::Websocket, "DSN '{}' is not a websocket endpoint", self.dsn);
        Ok(self.dsn.clone())
    }

    pub fn host_port(&self) -> anyhow::Result<(String, u16)> {
        let uri: http::Uri = self.dsn.parse()?;
        let host = uri.host().ok_or_else(|| anyhow::anyhow!("server DSN '{}' has no host", self.dsn))?;

        let scheme = uri.scheme_str().unwrap_or("").to_lowercase();
        let port = uri.port_u16().unwrap_or(match scheme.as_str() {
            "https" | "wss" => 443,
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
    pub tcp_nodelay: bool,
    pub timeout_secs: u64,
    pub handshake_path: String,
    pub auth_path: String,
    pub traffic_path: String,
    pub coalesce_budget_bytes: usize,
    pub poll_timeout_ms: u64,
    pub concurrency: usize,
    pub reassembly_queue_max_size: usize,

    pub http2_adaptive_window: bool,
    pub http2_max_frame_size: Option<u32>,
    pub http2_max_header_list_size: Option<u32>,
    pub http2_keep_alive_interval_secs: Option<u64>,
    pub http2_keep_alive_timeout_secs: Option<u64>,
    pub http2_keep_alive_while_idle: bool,
}

impl Default for AhttpConfig {
    fn default() -> Self {
        Self {
            pool_max_idle_per_host: 8,
            pool_idle_timeout_secs: 60,
            tcp_nodelay: true,
            timeout_secs: 10,
            handshake_path: "/handshake".to_string(),
            auth_path: "/auth".to_string(),
            traffic_path: "/traffic".to_string(),
            coalesce_budget_bytes: 65536,
            poll_timeout_ms: 15,
            concurrency: 4, // 4 параллельных потока по умолчанию для обхода HOL-blocking
            reassembly_queue_max_size: 1024,

            http2_adaptive_window: true,
            http2_max_frame_size: None,
            http2_max_header_list_size: Some(16384),
            http2_keep_alive_interval_secs: Some(20),
            http2_keep_alive_timeout_secs: Some(10),
            http2_keep_alive_while_idle: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
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

    // Наш новый массив серверов [[servers]] для переключения при сбоях
    #[serde(default)]
    pub servers: Vec<ServerConfig>,

    #[serde(default)]
    pub ahttp: AhttpConfig,
}

impl CoreConfig {
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

        for server in &self.servers {
            server.mode()?;
            server.host_port()?;
            if server.mode()? == TransportMode::Websocket {
                server.websocket_url()?;
            }
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
            name: None,
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
        };
        assert_eq!(server.mode().unwrap(), TransportMode::Quic);
        assert_eq!(server.endpoint().unwrap(), "vpn.example.com:4519");

        let websocket = ServerConfig {
            dsn: "wss://vpn.example.com:8443/socket".to_string(),
            ..server.clone()
        };
        assert_eq!(websocket.mode().unwrap(), TransportMode::Websocket);
        assert_eq!(websocket.websocket_url().unwrap(), "wss://vpn.example.com:8443/socket");

        // Тест дефолтного порта
        let ws_no_port = ServerConfig {
            name: None,
            dsn: "wss://gm1.anet-project.org/socket".to_string(),
            timeout_secs: 10,
            server_pub_key: None,
            ssh_user: None,

            group_name: None,
            group_id: None,
            weight: None,
            weigth: None,

            websocket_min_session_secs: 480,
            websocket_max_session_secs: 1500,
        };
        assert_eq!(ws_no_port.endpoint().unwrap(), "gm1.anet-project.org:443");

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
}

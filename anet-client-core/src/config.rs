use anet_common::config::StealthConfig;
use anet_common::quic_settings::QuicConfig;
use serde::Deserialize;

// Добавьте этот enum рядом с другими (например, над MainConfig или под TransportMode)
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

    /// Bounds for a browser-like WebSocket session rotation.
    #[serde(default = "default_websocket_min_session_secs")]
    pub websocket_min_session_secs: u64,
    #[serde(default = "default_websocket_max_session_secs")]
    pub websocket_max_session_secs: u64,
}

impl ServerConfig {
    pub fn mode(&self) -> anyhow::Result<TransportMode> {
        match self.dsn.parse::<http::Uri>()?.scheme_str() {
            Some("quic") => Ok(TransportMode::Quic),
            Some("ssh") => Ok(TransportMode::Ssh),
            Some("vnc") => Ok(TransportMode::Vnc),
            Some("ws") | Some("wss") => Ok(TransportMode::Websocket),
            Some(scheme) => anyhow::bail!("unsupported server DSN scheme '{scheme}'"),
            None => anyhow::bail!("server DSN '{}' has no scheme", self.dsn),
        }
    }

    pub fn endpoint(&self) -> anyhow::Result<String> {
        let uri: http::Uri = self.dsn.parse()?;
        uri.authority()
            .map(ToString::to_string)
            .ok_or_else(|| anyhow::anyhow!("server DSN '{}' has no host", self.dsn))
    }

    pub fn websocket_url(&self) -> anyhow::Result<String> {
        let mode = self.mode()?;
        anyhow::ensure!(mode == TransportMode::Websocket, "DSN '{}' is not a websocket endpoint", self.dsn);
        Ok(self.dsn.clone())
    }

    pub fn host_port(&self) -> anyhow::Result<(String, u16)> {
        let uri: http::Uri = self.dsn.parse()?;
        let host = uri.host().ok_or_else(|| anyhow::anyhow!("server DSN '{}' has no host", self.dsn))?;
        let port = uri.port_u16().unwrap_or(match self.mode()? {
            TransportMode::Websocket if self.dsn.starts_with("wss://") => 443,
            TransportMode::Websocket => 80,
            _ => 0,
        });
        anyhow::ensure!(port != 0, "server DSN '{}' has no port", self.dsn);
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

    #[test]
    fn dsn_selects_transport_and_endpoint() {
        let server = ServerConfig {
            name: None,
            dsn: "quic://vpn.example.com:4519".to_string(),
            timeout_secs: 10,
            server_pub_key: None,
            ssh_user: None,
            websocket_min_session_secs: 480,
            websocket_max_session_secs: 1500,
        };
        assert_eq!(server.mode().unwrap(), TransportMode::Quic);
        assert_eq!(server.endpoint().unwrap(), "vpn.example.com:4519");

        let websocket = ServerConfig {
            dsn: "wss://vpn.example.com:8443/socket".to_string(),
            ..server
        };
        assert_eq!(websocket.mode().unwrap(), TransportMode::Websocket);
        assert_eq!(websocket.websocket_url().unwrap(), "wss://vpn.example.com:8443/socket");
    }
}

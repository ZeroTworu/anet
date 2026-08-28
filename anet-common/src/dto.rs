use serde::{Deserialize, Serialize};

/// [ VPN Core Communication: Check Access ]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "poem", derive(poem_openapi::Object))]
#[cfg_attr(feature = "poem", oai(rename = "CheckAccessRequest"))]
pub struct CheckAccessRequest {
    #[cfg_attr(feature = "poem", oai(validator(min_length = 10)))]
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "poem", derive(poem_openapi::Object))]
#[cfg_attr(feature = "poem", oai(rename = "CheckAccessResponse"))]
pub struct CheckAccessResponse {
    pub allowed: bool,
    pub message: String,
    pub static_ip: Option<String>,
    pub user_id: Option<String>,
}

/// [ VPN Core Communication: Session Events ]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "poem", derive(poem_openapi::Object))]
#[cfg_attr(feature = "poem", oai(rename = "SessionEventRequest"))]
pub struct SessionEventRequest {
    pub fingerprint: String,
}

/// Периодический отчёт фактического состояния ноды для control plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "poem", derive(poem_openapi::Object))]
#[cfg_attr(feature = "poem", oai(rename = "NodeHeartbeatRequest"))]
pub struct NodeHeartbeatRequest {
    pub node_id: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub active_connections: u64,
    pub accepting_connections: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "poem", derive(poem_openapi::Object))]
#[cfg_attr(feature = "poem", oai(rename = "NodeCommand"))]
pub struct NodeCommand {
    /// Идентификатор записи очереди в панели.
    pub command_id: String,
    /// Тип команды, который нода должна выполнить локально.
    pub command_type: String,
    /// Параметр команды admission: принимать ли новые подключения.
    pub accepting_connections: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "poem", derive(poem_openapi::Object))]
#[cfg_attr(feature = "poem", oai(rename = "NodeCommandResultRequest"))]
pub struct NodeCommandResultRequest {
    pub node_id: String,
    pub succeeded: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "poem", derive(poem_openapi::Object))]
#[cfg_attr(feature = "poem", oai(rename = "TrafficUsageSample"))]
pub struct TrafficUsageSample {
    /// Пользователь из ответа auth provider; может отсутствовать для legacy/VIP.
    pub user_id: Option<String>,
    /// Отпечаток клиента — стабильный fallback-идентификатор агрегации.
    pub fingerprint: String,
    /// Байты от клиента к VPN-ноде и от VPN-ноды к клиенту.
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub protocol: Option<String>, // Тип транспорта: "quic", "ssh", "vnc", "ws"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "poem", derive(poem_openapi::Object))]
#[cfg_attr(feature = "poem", oai(rename = "NodeTrafficReport"))]
pub struct NodeTrafficReport {
    pub node_id: String,
    pub boot_id: String,
    pub samples: Vec<TrafficUsageSample>,
}

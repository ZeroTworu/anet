use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct StealthConfig {
    /// Минимальная задержка джиттера (наносекунды)
    pub min_jitter_ns: u64,
    /// Максимальная задержка джиттера (наносекунды)
    pub max_jitter_ns: u64,
    /// Шаг выравнивания паддинга (байты)
    pub padding_step: u16,
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self {
            min_jitter_ns: 0,
            max_jitter_ns: 0,
            padding_step: 0,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TransportConfig {
    pub transport_type: String, // "udp-quic", "tcp-tls", "tcp-ssh"

    // SSH-specific
    pub ssh_private_key: Option<String>,
    pub ssh_server_public_key: Option<String>,

    // TLS-specific
    pub tls_ca_cert: Option<String>,
    pub tls_client_cert: Option<String>,
    pub tls_client_key: Option<String>,
    pub tls_skip_verify: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            transport_type: "udp-quic".to_string(),
            ssh_private_key: None,
            ssh_server_public_key: None,
            tls_ca_cert: None,
            tls_client_cert: None,
            tls_client_key: None,
            tls_skip_verify: false,
        }
    }
}

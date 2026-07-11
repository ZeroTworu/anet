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
}

/// [ VPN Core Communication: Session Events ]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "poem", derive(poem_openapi::Object))]
#[cfg_attr(feature = "poem", oai(rename = "SessionEventRequest"))]
pub struct SessionEventRequest {
    pub fingerprint: String,
}

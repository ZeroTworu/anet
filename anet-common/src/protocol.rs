use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignedIp {
    pub ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    AuthRequest(AuthRequest),
    AuthResponse(AssignedIp),
}

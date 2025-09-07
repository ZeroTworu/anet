use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssignedIp {
    pub ip: String,
    pub netmask: String,
    pub gateway: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientTrafficReceive {
    pub encrypted_packet: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientTrafficSend {
    pub encrypted_packet: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    AuthRequest(AuthRequest),
    AuthResponse(AssignedIp),
    ClientTrafficReceive(ClientTrafficReceive),
    ClientTrafficSend(ClientTrafficSend),
}

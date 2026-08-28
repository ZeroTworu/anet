use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumIter, DeriveActiveEnum, Serialize, Deserialize)]
#[sea_orm(rs_type = "String", db_type = "Enum", enum_name = "protocol_type")]
pub enum ProtocolType {
    #[sea_orm(string_value = "quic")]
    Quic,
    #[sea_orm(string_value = "ssh")]
    Ssh,
    #[sea_orm(string_value = "vnc")]
    Vnc,
    #[sea_orm(string_value = "ws")]
    Ws,
}

impl ProtocolType {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "ssh" => Self::Ssh,
            "vnc" => Self::Vnc,
            "ws" | "wss" => Self::Ws,
            _ => Self::Quic,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Quic => "quic",
            Self::Ssh => "ssh",
            Self::Vnc => "vnc",
            Self::Ws => "ws",
        }
    }
}

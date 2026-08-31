use super::{ClientTransport, quic::QuicTransport, ssh::SshTransport, vnc::VncTransport, websocket::WebSocketTransport, ahttp::AHttpTransport};
use crate::config::{CoreConfig, ServerConfig, TransportMode};


pub fn create_transport(config: &CoreConfig, server: &ServerConfig) -> anyhow::Result<Box<dyn ClientTransport>> {
    Ok(match server.mode()? {
        TransportMode::Ssh => Box::new(SshTransport::new(config.clone(), server.clone())),
        TransportMode::Quic => Box::new(QuicTransport::new(config.clone(), server.clone())),
        TransportMode::Vnc => Box::new(VncTransport::new(config.clone(), server.clone())),
        TransportMode::Websocket => Box::new(WebSocketTransport::new(config.clone(), server.clone())),
        TransportMode::Ahttp => Box::new(AHttpTransport::new(config.clone(), server.clone())),
    })
}

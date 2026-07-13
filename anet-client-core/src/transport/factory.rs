use super::{ClientTransport, quic::QuicTransport, ssh::SshTransport, vnc::VncTransport};
use crate::config::{CoreConfig, ServerConfig, TransportMode};

pub fn create_transport(config: &CoreConfig, server: &ServerConfig) -> Box<dyn ClientTransport> {
    match server.mode {
        TransportMode::Ssh => Box::new(SshTransport::new(config.clone(), server.clone())),
        TransportMode::Quic => Box::new(QuicTransport::new(config.clone(), server.clone())),
        TransportMode::Vnc => Box::new(VncTransport::new(config.clone(), server.clone())),
    }
}

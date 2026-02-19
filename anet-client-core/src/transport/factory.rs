use super::{ClientTransport, quic::QuicTransport, ssh::SshTransport};
use crate::config::{CoreConfig, TransportMode};

pub fn create_transport(config: &CoreConfig) -> Box<dyn ClientTransport> {
    match config.transport.mode {
        TransportMode::Ssh => Box::new(SshTransport::new(config.clone())),
        TransportMode::Quic | TransportMode::Auto => Box::new(QuicTransport::new(config.clone())),
    }
}

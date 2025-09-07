use tokio::sync::mpsc;

pub struct TlsChannels {
    pub rx_from_tls: mpsc::Receiver<Vec<u8>>,
    pub tx_to_tls: mpsc::Sender<Vec<u8>>,
}

pub struct TunChannels {
    pub rx_from_tun: mpsc::Receiver<Vec<u8>>,
    pub tx_to_tun: mpsc::Sender<Vec<u8>>,
}

impl TunChannels {
    pub fn new() -> Self {
        let (tx_to_framed, rx_from_framed) = mpsc::channel(100);
        Self{
            rx_from_tun: rx_from_framed,
            tx_to_tun: tx_to_framed,
        }
    }

}

impl TlsChannels {
    pub fn new() -> Self {
        let (tx_to_tls, rx_from_tls) = mpsc::channel(100);
        Self{
            tx_to_tls,
            rx_from_tls,
        }
    }
}


pub struct Exchange {
    pub tls_channels: TlsChannels,
    pub frame_channels: TunChannels,
}

impl Exchange {
    pub fn new() -> Self{
        Self{
            tls_channels: TlsChannels::new(),
            frame_channels: TunChannels::new(),
        }
    }
}
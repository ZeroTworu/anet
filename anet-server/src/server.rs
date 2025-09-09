use std::{fs::File, io::BufReader, net::Ipv4Addr, sync::Arc};

use crate::atun_server::TunManager;
use crate::config::Config;
use crate::ip_pool::IpPool;
use anet_common::protocol::{
    ClientTrafficReceive, ClientTrafficSend, Message as AnetMessage, message::Content,
};
use anet_common::tcp::optimize_tcp_connection;
use anet_common::tun_params::TunParams;
use anyhow::Context;
use bytes::Bytes;
use dashmap::DashMap;
use log::{debug, error, info};
use prost::Message;
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use std::collections::HashSet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::{Duration, interval};
use tokio_rustls::TlsAcceptor;

type ClientTx = mpsc::Sender<Vec<u8>>;

#[derive(Clone)]
pub struct Router {
    map: Arc<DashMap<Ipv4Addr, ClientTx>>,
}

impl Router {
    pub fn new() -> Self {
        Self {
            map: Arc::new(DashMap::new()),
        }
    }

    pub fn insert(&self, ip: Ipv4Addr, tx: ClientTx) {
        info!("{:?} success auth.", ip);
        self.map.insert(ip, tx);
    }

    pub fn remove(&self, ip: &Ipv4Addr) {
        info!("{:?} disconnected.", ip);
        self.map.remove(ip);
    }

    #[inline]
    pub fn find(&self, ip: &Ipv4Addr) -> Option<ClientTx> {
        match self.map.get(ip) {
            Some(tx) => Some(tx.clone()),
            None => None,
        }
    }

    pub fn allocated_ips(&self) -> HashSet<Ipv4Addr> {
        let mut result = HashSet::new();

        for entry in self.map.iter() {
            result.insert(*entry.key());
        }

        result
    }
}

struct PacketBatcher {
    batch_size: usize,
    batch_timeout: Duration,
}

impl PacketBatcher {
    fn new(batch_size: usize, batch_timeout_ms: u64) -> Self {
        Self {
            batch_size,
            batch_timeout: Duration::from_millis(batch_timeout_ms),
        }
    }

    async fn process_batches(&self, mut rx_from_tun: mpsc::Receiver<Vec<u8>>, router: &Router) {
        let mut batch = Vec::with_capacity(self.batch_size);
        let mut interval = interval(self.batch_timeout);

        loop {
            tokio::select! {
                biased;

                pkt = rx_from_tun.recv() => {
                    if let Some(pkt) = pkt {
                        if pkt.len() > 4 {
                            batch.push(pkt);

                            if batch.len() >= self.batch_size {
                                Self::process_batch(&batch, &router).await;
                                batch.clear();
                                batch.reserve(self.batch_size);
                            }
                        }
                    }
                }
                _ = interval.tick() => {
                    if !batch.is_empty() {
                        Self::process_batch(&batch, &router).await;
                        batch.clear();
                        batch.reserve(self.batch_size);
                    }
                }
            }
        }
    }

    async fn process_batch(batch: &Vec<Vec<u8>>, router: &Router) {
        for pkt in batch {
            if let Some(dst) = extract_ip_dst(&pkt) {
                if let Some(client_tx) = router.find(&dst) {
                    if let Err(e) = client_tx.send(pkt.to_vec()).await {
                        error!("Route to {dst} present but send failed: {e}");
                    }
                } else {
                    info!("No route for dst {dst}");
                }
            } else {
                debug!("Non-IPv4 or too-short packet from TLS, dropped");
            }
        }
    }
}

pub struct ANetServer {
    tls_acceptor: TlsAcceptor,
    router: Router,
    tun_manager: TunManager,
    ip_pool: IpPool,
    cfg: Config,
}

impl ANetServer {
    pub fn new(cfg: &Config) -> anyhow::Result<Self> {
        let tls_cfg = load_tls_config(cfg.cert_path.as_str(), cfg.key_path.as_str())?;
        let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));
        let params = TunParams {
            netmask: cfg.mask.parse().unwrap(),
            gateway: cfg.gateway.parse().unwrap(),
            address: cfg.self_ip.parse().unwrap(),
            name: cfg.if_name.parse().unwrap(),
            mtu: cfg.mtu,
        };
        let tun_manager = TunManager::new(params, cfg.net.parse().unwrap());
        let ip_pool = IpPool::new(
            cfg.net.parse().unwrap(),
            cfg.mask.parse().unwrap(),
            cfg.gateway.parse().unwrap(),
            cfg.self_ip.parse().unwrap(),
            cfg.mtu,
        );
        info!("Server TUN configuration: {}", tun_manager.get_info());

        Ok(Self {
            tls_acceptor: acceptor,
            router: Router::new(),
            tun_manager,
            ip_pool,
            cfg: cfg.clone(),
        })
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let (tx_to_tun, rx_from_tun) = self.tun_manager.run().await?;
        self.tun_manager
            .setup_tun_routing(self.cfg.external_if.as_str())
            .await?;

        let router_for_tun = self.router.clone();

        tokio::spawn(async move {
            let batcher = PacketBatcher::new(50, 1);
            batcher.process_batches(rx_from_tun, &router_for_tun).await;
        });

        let listener = TcpListener::bind(self.cfg.bind_to.as_str()).await?;
        info!("Listening on {}", self.cfg.bind_to.as_str());

        loop {
            let (socket, peer) = listener.accept().await?;
            let _ = optimize_tcp_connection(&socket);
            let acceptor = self.tls_acceptor.clone();
            let router = self.router.clone();
            let tx_to_tun = tx_to_tun.clone();
            let ip_pool = self.ip_pool.clone();
            let auth_phrase = self.cfg.auth_phrase.clone();

            // Если не запустить в отдельном потоке - новые клиенты не подрубятся.
            tokio::spawn(async move {
                match acceptor.accept(socket).await {
                    Ok(tls_stream) => {
                        info!("Accepted connection from {}", peer);
                        if let Err(e) =
                            handle_client(tls_stream, &router, tx_to_tun, &ip_pool, auth_phrase)
                                .await
                        {
                            error!("[{}] client task error: {e:?}", peer);
                        }
                    }
                    Err(e) => error!("TLS accept failed from {}: {:?}", peer, e),
                }
            });
        }
    }
}

async fn handle_client(
    tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
    router: &Router,
    tx_to_tun: mpsc::Sender<Vec<u8>>,
    ip_pool: &IpPool,
    auth_phrase: String,
) -> anyhow::Result<()> {
    let (reader, mut writer) = tokio::io::split(tls_stream);
    let mut reader = tokio::io::BufReader::new(reader);

    let mut len_buf = [0u8; 4];
    if let Err(e) = reader.read_exact(&mut len_buf).await {
        anyhow::bail!("Failed to read message length: {}", e);
    }
    let msg_len = u32::from_be_bytes(len_buf) as usize;

    if msg_len > 65536 {
        anyhow::bail!("Message too long, {} bytes", msg_len);
    }

    let mut msg_buf = vec![0u8; msg_len];
    if let Err(e) = reader.read_exact(&mut msg_buf).await {
        anyhow::bail!("Failed to read message: {}", e);
    }

    let message: AnetMessage = Message::decode(Bytes::from(msg_buf))?;

    let assigned_ip: Ipv4Addr = match message.content {
        Some(Content::AuthRequest(auth_request)) => {
            if auth_request.key != auth_phrase {
                anyhow::bail!("Auth failed: wrong auth phrase");
            }
            let used = router.allocated_ips();
            ip_pool.allocate(&used).context("No free IPs")?
        }
        _ => anyhow::bail!("First message must be AuthRequest"),
    };

    let response = AnetMessage {
        content: Some(Content::AuthResponse(anet_common::AssignedIp {
            ip: assigned_ip.to_string(),
            netmask: ip_pool.netmask.to_string(),
            gateway: ip_pool.gateway.to_string(),
            mtu: ip_pool.mtu as i32,
            crypto_key: "dsds".to_string(),
        })),
    };

    let mut response_data = Vec::new();
    response.encode(&mut response_data)?;

    writer
        .write_all(&(response_data.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(&response_data).await?;

    let (tx_to_client, mut rx_to_client) = mpsc::channel::<Vec<u8>>(8192);
    router.insert(assigned_ip, tx_to_client.clone());

    // Server -> Client (ClientTrafficSend) -> TLS
    let writer_task = tokio::spawn(async move {
        while let Some(pkt) = rx_to_client.recv().await {
            let msg = AnetMessage {
                content: Some(Content::ClientTrafficSend(ClientTrafficSend {
                    encrypted_packet: pkt,
                })),
            };

            let mut data = Vec::new();
            if let Err(e) = msg.encode(&mut data) {
                error!("Serialize ClientTrafficSend failed: {e}");
                continue;
            }

            if let Err(e) = writer.write_all(&(data.len() as u32).to_be_bytes()).await {
                error!("Write to client failed: {e}");
                break;
            }
            if let Err(e) = writer.write_all(&data).await {
                error!("Write to client failed: {e}");
                break;
            }
            debug!("Sent ClientTrafficSend to client");
        }
    });

    // Client -> Server (ClientTrafficReceive) -> TUN
    let reader_task = tokio::spawn(async move {
        let mut r = reader;
        let mut len_buf = [0u8; 4];

        loop {
            if let Err(e) = r.read_exact(&mut len_buf).await {
                error!("Read from client failed (length): {e}");
                break;
            }
            let msg_len = u32::from_be_bytes(len_buf) as usize;

            let mut msg_buf = vec![0u8; msg_len];
            if let Err(e) = r.read_exact(&mut msg_buf).await {
                error!("Read from client failed (message): {e}");
                break;
            }

            let message: AnetMessage = match Message::decode(Bytes::from(msg_buf)) {
                Ok(msg) => msg,
                Err(e) => {
                    error!("Failed to parse message: {e}");
                    continue;
                }
            };

            match message.content {
                Some(Content::ClientTrafficReceive(ClientTrafficReceive { encrypted_packet })) => {
                    debug!("Receive ClientTrafficReceive from client");

                    if let Err(e) = tx_to_tun.send(encrypted_packet).await {
                        error!("Send to TUN failed: {e}");
                        break;
                    }
                }
                Some(other) => {
                    info!("Unexpected message: {:?}", other);
                }
                None => {
                    error!("Empty message received");
                }
            }
        }
    });

    tokio::select! {
        _ = writer_task => {},
        _ = reader_task => {},
    }

    router.remove(&assigned_ip);
    Ok(())
}

fn load_tls_config(cert_path: &str, key_path: &str) -> anyhow::Result<ServerConfig> {
    let cert_file = File::open(cert_path)
        .context(format!("Failed to open certificate file: {}", cert_path))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<CertificateDer>, _>>()
        .context("Failed to parse certificate")?;

    let key_file = File::open(key_path)
        .context(format!("Failed to open key file: {}", key_path))?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("Failed to read private key")?
        .context("No private key found")?;

    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to create server config")?;

    cfg.alpn_protocols = vec![b"h2".to_vec()];

    Ok(cfg)
}

#[inline]
fn extract_ip_dst(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < 20 {
        return None;
    }

    if (pkt[0] >> 4) != 4 {
        return None;
    }

    Some(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
}

use std::{collections::HashMap, fs::File, io::BufReader, net::Ipv4Addr, sync::Arc};

use anyhow::Context;
use log::{debug, error, info};
use rustls::pki_types::CertificateDer;
use rustls::ServerConfig;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tokio_rustls::TlsAcceptor;
use std::collections::HashSet;

use anet_common::protocol::{
    AssignedIp, ClientTrafficReceive, ClientTrafficSend, Message,
};
use crate::atun_server::TunManager;
use crate::ip_pool::IpPool;
use crate::config::Config;
use crate::atun_server::TunParams;

type ClientTx = mpsc::Sender<Vec<u8>>;

#[derive(Clone, Default)]
struct Router {
    inner: Arc<RwLock<HashMap<Ipv4Addr, ClientTx>>>,
}
impl Router {
    async fn insert(&self, ip: Ipv4Addr, tx: ClientTx) {
        self.inner.write().await.insert(ip, tx);
    }
    async fn remove(&self, ip: &Ipv4Addr) {
        self.inner.write().await.remove(ip);
    }
    async fn find(&self, ip: &Ipv4Addr) -> Option<ClientTx> {
        self.inner.read().await.get(ip).cloned()
    }

    async fn allocated_ips(&self) -> HashSet<Ipv4Addr> {
        self.inner.read().await.keys().cloned().collect()
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

            name: "anet-server".to_string(),
            mtu: 1500,
        };
        let tun_manager = TunManager::new_with_params(params);
        let ip_pool = IpPool::new(
            cfg.net.parse().unwrap(),       // сеть
            cfg.mask.parse().unwrap(),  // маска
            cfg.gateway.parse().unwrap(),       // шлюз
            cfg.self_ip.parse().unwrap(),       // сервер
        );
        info!("Server TUN configuration: {}", tun_manager.get_info());

        Ok(Self {
            tls_acceptor: acceptor,
            router: Router::default(),
            tun_manager,
            ip_pool,
            cfg: cfg.clone(),
        })
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        TunManager::setup_tun_routing("anet-server", self.cfg.external_if.as_str()).await?;
        let (tx_to_tun, mut rx_from_tun) = self.tun_manager.run().await?;

        let router_for_tun = self.router.clone();

        // Диспетчер: читает из TUN и отправляет соответствующему клиенту
        tokio::spawn(async move {
            while let Some(pkt) = rx_from_tun.recv().await {
                if pkt.len() > 4 {
                    if let Some(dst) = extract_ip_dst(&pkt) {
                        if let Some(client_tx) = router_for_tun.find(&dst).await {
                            debug!("Send to {}", dst);
                            if let Err(e) = client_tx.send(pkt).await {
                                error!("Route to {dst} present but send failed: {e}");
                            }
                        } else {
                            info!("No route for dst {dst}");
                        }
                    } else {
                        debug!("Non-IPv4 or too-short packet from TUN, dropped, {:?}", &pkt);
                    }
                }
            }
        });

        let listener = TcpListener::bind(self.cfg.bind_to.as_str()).await?;
        info!("Listening on {}", self.cfg.bind_to.as_str());
          loop {
            let (socket, peer) = listener.accept().await?;
            let acceptor = self.tls_acceptor.clone();
            let router = self.router.clone();
            let tx_to_tun_conn = tx_to_tun.clone();
            let ip_pool = self.ip_pool.clone();
            let auth_phrase = self.cfg.auth_phrase.clone();
            tokio::spawn(async move {
                match acceptor.accept(socket).await {
                    Ok(tls_stream) => {
                        info!("Accepted connection from {}", peer);
                        if let Err(e) = handle_client(tls_stream, &router, tx_to_tun_conn, &ip_pool, auth_phrase).await {
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
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;

    if n == 0 {
        anyhow::bail!("Client closed before auth");
    }

    let assigned_ip: Ipv4Addr = match serde_json::from_str::<Message>(&line) {
        Ok(Message::AuthRequest(auth_request)) => {
            if auth_request.key != auth_phrase {
                anyhow::bail!("Auth failed: wrong auth phrase");
            }
            let used = router.allocated_ips().await;
            ip_pool.allocate(&used).context("No free IPs")?
        }
        Ok(_) => anyhow::bail!("First message must be AuthRequest"),
        Err(e) => anyhow::bail!("Failed to parse auth request: {e}"),
    };


    let response = Message::AuthResponse(AssignedIp {
        ip: assigned_ip.to_string(),
        netmask: ip_pool.netmask.to_string(),
        gateway: ip_pool.gateway.to_string(),
    });
    let response_line = serde_json::to_string(&response)? + "\n";
    writer.write_all(response_line.as_bytes()).await?;


    let (tx_to_client, mut rx_to_client) = mpsc::channel::<Vec<u8>>(1024);
    router.insert(assigned_ip, tx_to_client.clone()).await;

    // Server -> Client (ClientTrafficSend) -> TLS
    let writer_task = tokio::spawn(async move {
        while let Some(pkt) = rx_to_client.recv().await {
            let msg = Message::ClientTrafficSend(ClientTrafficSend { encrypted_packet: pkt });
            debug!("Sent ClientTrafficSend to client");

            match serde_json::to_string(&msg) {
                Ok(mut s) => {
                    s.push('\n');
                    if let Err(e) = writer.write_all(s.as_bytes()).await {
                        error!("Write to client failed: {e}");
                        break;
                    }
                }
                Err(e) => {
                    error!("Serialize ClientTrafficSend failed: {e}");
                    continue;
                }
            };
        }
    });

    // Client -> Server (ClientTrafficReceive) -> TUN
    let reader_task = tokio::spawn(async move {
        let mut r = reader;
        let mut line = String::new();
        loop {
            line.clear();
            let n = match r.read_line(&mut line).await {
                Ok(n) => n,
                Err(e) => {
                    error!("Read from client failed: {e}");
                    break;
                }
            };
            if n == 0 {

                break;
            }

            match serde_json::from_str::<Message>(&line) {
                Ok(Message::ClientTrafficReceive(ClientTrafficReceive { encrypted_packet })) => {
                    debug!("Receive ClientTrafficReceive from client");

                    if let Err(e) = tx_to_tun.send(encrypted_packet).await {
                        error!("Send to TUN failed: {e}");
                        break;
                    }
                }
                Ok(other) => {
                    info!("Unexpected message: {:?}", other);
                }
                Err(_) => {
                    error!("Failed to parse message: {}", line.trim_end());
                }
            }
        }
    });

    // 6) Ожидаем завершения любой из задач, чистим маршрутизатор.
    tokio::select! {
        _ = writer_task => {},
        _ = reader_task => {},
    }

    router.remove(&assigned_ip).await;
    Ok(())
}

fn load_tls_config(cert_path: &str, key_path: &str) -> anyhow::Result<ServerConfig> {
    let cert_file =
        File::open(cert_path).context(format!("Failed to open certificate file: {}", cert_path))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<CertificateDer>, _>>()
        .context("Failed to parse certificate")?;

    let key_file =
        File::open(key_path).context(format!("Failed to open key file: {}", key_path))?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("Failed to read private key")?
        .context("No private key found")?;

    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to create server config")?;

    Ok(cfg)
}

fn extract_ip_dst(pkt: &[u8]) -> Option<Ipv4Addr> {
    if pkt.len() < 20 {
        log::debug!("Packet too short: len={}", pkt.len());
        return None;
    }
    let ver = pkt[0] >> 4;
    if ver != 4 {
        log::debug!("Not IPv4: first_byte=0x{:02x}", pkt[0]);
        return None;
    }
    Some(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))
}

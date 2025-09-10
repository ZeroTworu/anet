use std::{fs::File, io::BufReader, net::Ipv4Addr, sync::Arc};

use crate::atun_server::TunManager;
use crate::client::Client;
use crate::config::Config;
use crate::ip_pool::IpPool;
use crate::router::{PacketBatcher, Router};
use crate::utils::{generate_crypto_key, generate_uid};
use anet_common::consts;
use anet_common::protocol::{
    ClientTrafficReceive, ClientTrafficSend, Message as AnetMessage, message::Content,
};
use anet_common::tcp::optimize_tcp_connection;
use anet_common::tun_params::TunParams;
use anyhow::Context;
use bytes::{Buf, Bytes, BytesMut};
use log::{debug, error, info};
use prost::Message;
use rustls::ServerConfig;
use rustls::pki_types::CertificateDer;
use std::io::IoSlice;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::Duration;
use tokio_rustls::TlsAcceptor;

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

    if msg_len > consts::MAX_PACKET_SIZE {
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
    let crypto_key = generate_crypto_key();
    let response = AnetMessage {
        content: Some(Content::AuthResponse(anet_common::AssignedIp {
            ip: assigned_ip.to_string(),
            netmask: ip_pool.netmask.to_string(),
            gateway: ip_pool.gateway.to_string(),
            mtu: ip_pool.mtu as i32,
            crypto_key: crypto_key.to_string(),
        })),
    };

    let mut response_data = Vec::new();
    response.encode(&mut response_data)?;

    writer
        .write_all(&(response_data.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(&response_data).await?;

    let (tx_to_client, mut rx_to_client) = mpsc::channel::<Vec<u8>>(consts::CHANNEL_BUFFER_SIZE);

    let client = Arc::new(Client::new(tx_to_client, generate_uid(), crypto_key));
    router.insert(assigned_ip, client.clone());

    // Server -> Client (ClientTrafficSend) | (TUN -> TLS)
    let writer_task = tokio::spawn(async move {
        let mut data = Vec::new();
        let mut packet_count = 0;

        while let Some(pkt) = rx_to_client.recv().await {
            let msg = AnetMessage {
                content: Some(Content::ClientTrafficSend(ClientTrafficSend {
                    encrypted_packet: pkt,
                })),
            };

            if let Err(e) = msg.encode(&mut data) {
                error!("TUN -> TLS, serialize ClientTrafficSend failed: {e}");
                continue;
            }

            let header = (data.len() as u32).to_be_bytes();
            let slices = [IoSlice::new(&header), IoSlice::new(&data)];
            debug!("TUN -> TLS, size: {}", data.len());

            let write_result = tokio::time::timeout(
                Duration::from_secs(consts::WRITE_TIMEOUT_SECONDS),
                writer.write_vectored(&slices),
            )
            .await;

            if let Err(e) = write_result {
                error!("TUN -> TLS, write timeout or error: {e}");
                break;
            }

            data.clear();

            packet_count += 1;
            if packet_count == consts::PACKETS_TO_YIELD {
                packet_count = 0;
                tokio::task::yield_now().await;
            }
        }
    });

    // Client -> Server (ClientTrafficReceive) | (TLS -> TUN)
    let reader_task = tokio::spawn(async move {
        let mut len_buf = [0u8; 4];
        let mut read_buffer = BytesMut::with_capacity(consts::MAX_PACKET_SIZE);
        let mut packet_count = 0;
        loop {
            let read_result = tokio::time::timeout(
                Duration::from_secs(consts::READ_TIMEOUT_SECONDS),
                reader.read_buf(&mut read_buffer),
            )
            .await;
            match read_result {
                Ok(Ok(n)) => {
                    if n == 0 {
                        break; // closed
                    }

                    while read_buffer.len() >= 4 {
                        len_buf.copy_from_slice(&read_buffer[0..4]);
                        let msg_len = u32::from_be_bytes(len_buf) as usize;

                        if read_buffer.len() < 4 + msg_len {
                            break;
                        }

                        read_buffer.advance(4);

                        let message_data = read_buffer.split_to(msg_len);

                        let message: AnetMessage = match Message::decode(Bytes::from(message_data))
                        {
                            Ok(msg) => msg,
                            Err(e) => {
                                error!("TLS -> TUN, failed to parse message: {e}");
                                continue;
                            }
                        };

                        debug!("TLS -> TUN, size: {}", msg_len);

                        match message.content {
                            Some(Content::ClientTrafficReceive(ClientTrafficReceive {
                                encrypted_packet,
                            })) => {
                                if let Err(e) = tx_to_tun.send(encrypted_packet).await {
                                    error!("TLS -> TUN, send to TUN failed: {e}");
                                    break;
                                }
                            }
                            Some(other) => {
                                info!("TLS -> TUN, unexpected message: {:?}", other);
                            }
                            None => {
                                error!("TLS -> TUN, empty message received");
                            }
                        }
                    }
                }
                Ok(Err(e)) => {
                    error!("TLS -> TUN, Read Error: {}", e);
                    break;
                }
                Err(_) => {
                    error!("TLS -> TUN, Read timeout - closing connection");
                    break;
                }
            }
            packet_count += 1;
            if packet_count == consts::PACKETS_TO_YIELD {
                packet_count = 0;
                tokio::task::yield_now().await;
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

    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to create server config")?;

    cfg.alpn_protocols = vec![b"h2".to_vec()];

    Ok(cfg)
}

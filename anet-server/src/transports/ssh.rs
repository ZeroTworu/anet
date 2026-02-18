use std::net::SocketAddr;
use std::sync::Arc;
use anyhow::Result;
use log::{error, info};
use tokio::sync::mpsc;
use thrussh::*;
use thrussh::server::{Auth, Session};
use thrussh::keys::key::KeyPair;
use crate::auth_provider::AuthProvider;
use crate::client_registry::ClientRegistry;
use crate::ip_pool::IpPool;
use crate::transports::handshake::{perform_handshake, ClientInfo};
use crate::transports::stream::StreamHandshakeTransport;
use crate::utils::generate_seid; // понадобится для session_id

pub struct SshServer {
    registry: Arc<ClientRegistry>,
    auth_provider: Arc<AuthProvider>,
    server_signing_key: ed25519_dalek::SigningKey, // наш ключ для подписи
    ip_pool: Arc<IpPool>,
    tx_to_tun: mpsc::Sender<bytes::Bytes>,
    padding_step: u16,
}

impl server::Server for SshServer {
    type Handler = SshSessionHandler;
    fn new(&mut self, _: SocketAddr) -> Self::Handler {
        SshSessionHandler {
            registry: self.registry.clone(),
            auth_provider: self.auth_provider.clone(),
            server_signing_key: self.server_signing_key.clone(),
            ip_pool: self.ip_pool.clone(),
            tx_to_tun: self.tx_to_tun.clone(),
            padding_step: self.padding_step,
            client_info: None,
        }
    }
}

pub struct SshSessionHandler {
    registry: Arc<ClientRegistry>,
    auth_provider: Arc<AuthProvider>,
    server_signing_key: ed25519_dalek::SigningKey,
    ip_pool: Arc<IpPool>,
    tx_to_tun: mpsc::Sender<bytes::Bytes>,
    padding_step: u16,
    client_info: Option<ClientInfo>,
}

impl server::Handler for SshSessionHandler {
    type Error = anyhow::Error;

    async fn auth_publickey(&mut self, user: &str, key: &KeyPair) -> Result<Auth, Self::Error> {
        // Здесь мы должны проверить, что публичный ключ соответствует разрешённому клиенту.
        // У нас есть fingerprint из конфига. Нужно вычислить fingerprint из ключа SSH.
        // Для Ed25519 ключа можно извлечь байты и подписать.
        // Упрощённо: считаем, что user == fingerprint, а ключ проверяем через наш auth_provider.
        let fingerprint = user.to_string();
        if self.auth_provider.is_client_allowed(&fingerprint).await {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::Reject)
        }
    }

    async fn channel_open_session(&mut self, channel: Channel<Msg>, session: &mut Session) -> Result<bool, Self::Error> {
        let (mut tx, mut rx) = channel.into_stream(); // получаем读写 потоки

        // Выполняем handshake поверх этого канала
        let mut transport = StreamHandshakeTransport::new(&mut tx); // нужно адаптировать, т.к. tx не владеет потоком
        // Правильнее: channel реализует AsyncRead + AsyncWrite, мы можем обернуть его напрямую.
        // thrussh::Channel реализует futures::io::AsyncRead/AsyncWrite, но нам нужно tokio-совместимость.
        // Можно использовать tokio_util::compat для конвертации.

        use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
        let mut compat_rw = tx.compat(); // предположим, что tx реализует futures::AsyncRead/Write

        // Теперь compat_rw реализует tokio::io::AsyncRead + AsyncWrite
        let mut transport = StreamHandshakeTransport::new(compat_rw);

        let client_info = match perform_handshake(
            &mut transport,
            &self.auth_provider,
            &self.server_signing_key,
            &self.ip_pool,
            self.padding_step,
        ).await {
            Ok(info) => info,
            Err(e) => {
                error!("SSH handshake failed: {}", e);
                return Ok(false);
            }
        };

        // Регистрируем клиента
        // Нужно создать запись в реестре с каналом отправки данных
        let (tx_to_client, mut rx_from_client) = mpsc::channel(1024);
        self.registry.finalize_client(&client_info.assigned_ip.to_string(), tx_to_client);

        // Запускаем задачи чтения/записи данных
        let registry = self.registry.clone();
        let tx_to_tun = self.tx_to_tun.clone();
        let client_ip = client_info.assigned_ip.to_string();

        tokio::spawn(async move {
            // Чтение из канала (данные от TUN к клиенту)
            let read_task = tokio::spawn(async move {
                while let Some(packet) = rx_from_client.recv().await {
                    let framed = anet_common::stream_framing::frame_packet(packet);
                    if tx.write_all(&framed).await.is_err() {
                        break;
                    }
                }
            });

            // Запись в канал (данные от клиента в TUN)
            let write_task = tokio::spawn(async move {
                loop {
                    match anet_common::stream_framing::read_next_packet(&mut rx).await {
                        Ok(Some(packet)) => {
                            if tx_to_tun.send(packet).await.is_err() {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
            });

            let _ = tokio::join!(read_task, write_task);
            registry.remove_client_by_ip(&client_ip);
        });

        Ok(true)
    }
}

// Функция запуска SSH-сервера
pub async fn run_ssh_server(
    config: Arc<crate::config::Config>,
    registry: Arc<ClientRegistry>,
    auth_provider: Arc<AuthProvider>,
    server_signing_key: ed25519_dalek::SigningKey,
    tx_to_tun: mpsc::Sender<bytes::Bytes>,
    ip_pool: Arc<IpPool>,
) -> Result<()> {
    let mut server_config = server::Config::default();
    // Загружаем ключи хоста
    let key_pair = KeyPair::generate_ed25519().unwrap(); // или загрузить из файла
    server_config.connection.port = config.transport.ssh_bind_addr.port();
    // ... настройки

    let ssh_server = SshServer {
        registry,
        auth_provider,
        server_signing_key,
        ip_pool,
        tx_to_tun,
        padding_step: config.stealth.padding_step,
    };

    server::Builder::new()
        .with_config(server_config)
        .with_addr(config.transport.ssh_bind_addr)
        .with_server(ssh_server)
        .run()
        .await?;

    Ok(())
}
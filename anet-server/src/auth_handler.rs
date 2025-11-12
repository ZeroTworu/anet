use crate::ip_pool::IpPool;
use crate::multikey_udp_socket::{ClientTransportInfo, HandshakeData, TempDHInfo};
use crate::utils::{generate_seid, generate_unique_nonce_prefix};
use anet_common::consts::{AUTH_PREFIX_LEN, NONCE_LEN};
use anet_common::crypto_utils::sign_data;
use anet_common::crypto_utils::{
    derive_shared_key, generate_auth_prefix, generate_key_fingerprint, verify_signature,
};
use anet_common::encryption::Cipher;
use anet_common::protocol::{
    AuthResponse, DhServerExchange, EncryptedAuthResponse, Message as AnetMessage, message::Content,
};
use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use bytes::{BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use ed25519_dalek::{SigningKey, VerifyingKey};
use log::{error, info};
use prost::Message;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use rand::RngCore;
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

pub async fn run_auth_handler(
    mut rx_from_auth: mpsc::Receiver<HandshakeData>,
    reply_socket: Arc<UdpSocket>,
    ip_pool: IpPool,
    clients_by_prefix: Arc<DashMap<[u8; 4], Arc<ClientTransportInfo>>>,
    clients_by_addr: Arc<DashMap<SocketAddr, Arc<ClientTransportInfo>>>,
    temp_dh_map: Arc<DashMap<SocketAddr, TempDHInfo>>,
    allowed_clients: Vec<String>,
    server_signing_key: SigningKey,
    quic_cert_pem: String,
) -> Result<()> {
    info!("ANet Auth Handler task started.");
    while let Some((packet, remote_addr)) = rx_from_auth.recv().await {
        let allowed_clients_clone = allowed_clients.clone();
        let cert_clone = quic_cert_pem.clone();

        let clients_by_prefix = clients_by_prefix.clone();
        let clients_by_addr = clients_by_addr.clone();
        let ip_pool = ip_pool.clone();
        let reply_socket_clone = reply_socket.clone();
        let temp_dh_map_clone = temp_dh_map.clone();
        let server_signet_key = server_signing_key.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_auth_request(
                packet,
                remote_addr,
                &reply_socket_clone,
                ip_pool,
                clients_by_prefix,
                clients_by_addr,
                temp_dh_map_clone,
                &allowed_clients_clone,
                &server_signet_key,
                &cert_clone,
            )
            .await
            {
                error!("[{}] UDP Auth handshake failed: {}", remote_addr, e);
            }
        });
    }
    Ok(())
}

async fn handle_auth_request(
    full_packet: Bytes,
    remote_addr: SocketAddr,
    socket: &Arc<UdpSocket>,
    ip_pool: IpPool,
    clients_by_prefix: Arc<DashMap<[u8; 4], Arc<ClientTransportInfo>>>,
    clients_by_addr: Arc<DashMap<SocketAddr, Arc<ClientTransportInfo>>>,
    temp_dh_map: Arc<DashMap<SocketAddr, TempDHInfo>>,
    allowed_clients: &[String],
    server_signing_key: &SigningKey,
    quic_cert_pem: &str,
) -> Result<()> {
    let message: AnetMessage = Message::decode(full_packet.slice(AUTH_PREFIX_LEN..))
        .context("Failed to decode AnetMessage during Auth flow")?;

    match message.content {
        // --- ФАЗА I (Init) ---
        Some(Content::DhClientExchange(req)) => {
            // Проверка подписи клиента
            let client_public_key = VerifyingKey::from_bytes(
                &req.client_public_key
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid client public key length"))?,
            )
            .map_err(|_| anyhow::anyhow!("Invalid client public key"))?;

            let client_fingerprint = generate_key_fingerprint(&client_public_key);

            // Проверяем, разрешен ли клиент
            if !allowed_clients.contains(&client_fingerprint) {
                anyhow::bail!("Client {} not in allowed list", client_fingerprint);
            }

            // Верифицируем подпись клиента
            verify_signature(
                &client_public_key,
                &req.public_key,
                &req.client_signed_dh_key,
            )
            .context("Client signature verification failed")?;

            info!(
                "[{}] Client {} authenticated via signature",
                remote_addr, client_fingerprint
            );

            let mut rng = OsRng;
            let mut secret_bytes = [0u8; 32];
            rng.fill_bytes(&mut secret_bytes);

            let server_ephemeral_secret = StaticSecret::from(secret_bytes);
            let server_pub_key = PublicKey::from(&server_ephemeral_secret);

            if req.public_key.len() != 32 {
                anyhow::bail!("Invalid client DH public key length");
            }

            let client_pub_key_bytes: [u8; 32] = req
                .public_key
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("Public key slice failed conversion"))?;

            let client_pub_key = PublicKey::from(client_pub_key_bytes);

            // Подписываем наш DH ключ
            let server_signed_dh_key = sign_data(server_signing_key, server_pub_key.as_bytes());

            // Вычисляем K_shared
            let shared_secret = server_ephemeral_secret.diffie_hellman(&client_pub_key);
            let shared_key = derive_shared_key(&shared_secret);
            info!(
                "[{}] Server shared key (first 8 bytes): {:02x?}",
                remote_addr,
                &shared_key[..8]
            );
            info!(
                "[{}] Phase I DH complete. Temp K_shared derived.",
                remote_addr
            );

            // Сохраняем DH State с fingerprint клиента
            let temp_info = TempDHInfo {
                shared_key,
                client_fingerprint: client_fingerprint.clone(), // ТЕПЕРЬ КОРРЕКТНО
                created_at: Instant::now(),
            };
            temp_dh_map.insert(remote_addr, temp_info);

            // --- ФАЗА II: ОТВЕТ С ПУБЛИЧНЫМ КЛЮЧОМ СЕРВЕРА И ПОДПИСЬЮ ---
            let response_payload = DhServerExchange {
                public_key: server_pub_key.as_bytes().to_vec(),
                server_signed_dh_key,
            };

            let response_message = AnetMessage {
                content: Some(Content::DhServerExchange(response_payload)),
            };
            let mut response_data = Vec::new();
            response_message.encode(&mut response_data)?;

            let mut response_packet = BytesMut::new();
            response_packet.put_slice(&generate_auth_prefix());
            response_packet.put(&response_data[..]);

            socket
                .send_to(&response_packet.freeze(), remote_addr)
                .await
                .context("Failed Phase II DH response")?;

            Ok(())
        }

        // --- ФАЗА III (Encrypted Auth Request) ---
        Some(Content::EncryptedAuthRequest(enc_req)) => {
            info!(
                "[{}] Phase III: Received EncryptedAuthRequest, packet length: {}",
                remote_addr,
                full_packet.len()
            );

            let temp_info = match temp_dh_map.get(&remote_addr) {
                Some(entry) => {
                    let info = entry.value().clone();
                    info
                }
                None => {
                    error!(
                        "[{}] Phase III Failed: DH shared key missing or expired.",
                        remote_addr
                    );
                    anyhow::bail!("Phase III received but DH shared key missing or expired.")
                }
            };

            info!(
                "[{}] Phase III: Attempting to decrypt AuthRequest...",
                remote_addr
            );
            let cipher = Cipher::new(&temp_info.shared_key);

            if enc_req.nonce.len() != NONCE_LEN {
                anyhow::bail!("Invalid nonce length in AuthRequest");
            }

            // Используем catch_unwind для перехвата паники
            let decryption_result = std::panic::catch_unwind(|| {
                cipher.decrypt(
                    enc_req.nonce.as_slice(),
                    Bytes::from(enc_req.ciphertext.clone()),
                )
            });

            let plaintext = match decryption_result {
                Ok(Ok(pt)) => pt,
                Ok(Err(e)) => {
                    anyhow::bail!("Failed Phase III decryption: {}", e)
                }
                Err(panic) => {
                    error!("[{}] PANIC during decryption: {:?}", remote_addr, panic);
                    anyhow::bail!("Panic during decryption")
                }
            };

            info!("[{}] Successfully passed decryption", remote_addr);

            let auth_message: AnetMessage = match Message::decode(plaintext.clone()) {
                Ok(msg) => msg,
                Err(e) => {
                    anyhow::bail!("Failed to decode AuthMessage: {}", e)
                }
            };

            let assigned_ip;

            match auth_message.content {
                Some(Content::AuthRequest(req)) => {
                    info!(
                        "[{}] AuthRequest received, client_id: {}",
                        remote_addr, req.client_id
                    );
                    // Проверяем, что client_id соответствует ожидаемому fingerprint
                    if req.client_id != temp_info.client_fingerprint {
                        error!(
                            "[{}] Client ID mismatch: expected {}, got {}",
                            remote_addr, temp_info.client_fingerprint, req.client_id
                        );
                        anyhow::bail!("Client ID mismatch in AuthRequest");
                    }

                    assigned_ip = match ip_pool.allocate() {
                        Some(ip) => ip,
                        None => {
                            anyhow::bail!("No free IPs available")
                        }
                    };
                }
                _ => {
                    anyhow::bail!("Unexpected content in EncryptedAuthRequest.")
                }
            };

            let client_ip_str = assigned_ip.to_string();
            let nonce_prefix = generate_unique_nonce_prefix(clients_by_prefix.clone());
            let session_id = generate_seid();

            info!(
                "[{}] Authorization success for client {}. Allocating ANet transport info.",
                remote_addr, temp_info.client_fingerprint
            );

            // ВСТАВКА В КАРТЫ
            let info = Arc::new(ClientTransportInfo {
                cipher: Arc::new(Cipher::new(&temp_info.shared_key)),
                sequence: Arc::new(AtomicU64::new(0)),
                assigned_ip: client_ip_str.clone(),
                session_id: session_id.clone(),
                nonce_prefix,
                remote_addr: ArcSwap::new(Arc::new(remote_addr)),
            });

            clients_by_prefix.insert(nonce_prefix, info.clone());
            clients_by_addr.insert(remote_addr, info.clone());

            // --- ФАЗА IV: ОТВЕТ С ПАРАМЕТРАМИ ---
            let response_payload = AuthResponse {
                ip: client_ip_str,
                netmask: ip_pool.netmask.to_string(),
                gateway: ip_pool.gateway.to_string(),
                mtu: ip_pool.mtu as i32,
                session_id,
                nonce_prefix: nonce_prefix.to_vec(),
                quic_cert: quic_cert_pem.as_bytes().to_vec(),
            };

            let response_message = AnetMessage {
                content: Some(Content::AuthResponse(response_payload)),
            };
            let mut raw_response = Vec::new();
            response_message.encode(&mut raw_response)?;

            // Шифруем AuthResponse
            let cipher_resp = Cipher::new(&temp_info.shared_key);
            let mut rng = OsRng;
            let mut nonce_bytes = [0u8; NONCE_LEN];
            rng.fill_bytes(&mut nonce_bytes);

            let ciphertext = cipher_resp
                .encrypt(&nonce_bytes, Bytes::from(raw_response))
                .map_err(|e| anyhow::anyhow!("Failed Phase IV encryption: {:?}", e))?;

            let encrypted_res = EncryptedAuthResponse {
                ciphertext: ciphertext.to_vec(),
                nonce: nonce_bytes.to_vec(),
            };

            let mut final_data = Vec::new();
            let wrapped_msg = AnetMessage {
                content: Some(Content::EncryptedAuthResponse(encrypted_res)),
            };
            wrapped_msg.encode(&mut final_data)?;

            // Отправка (Фаза IV)
            let mut response_packet = BytesMut::new();
            response_packet.put_slice(&generate_auth_prefix());
            response_packet.put(&final_data[..]);

            socket
                .send_to(&response_packet.freeze(), remote_addr)
                .await?;
            temp_dh_map.remove(&remote_addr);
            Ok(())
        }

        _ => anyhow::bail!("Unexpected message content type in DH handshake sequence."),
    }
}

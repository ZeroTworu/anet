use crate::client_registry::{ClientRegistry, ClientTransportInfo};
use crate::multikey_udp_socket::{HandshakeData, TempDHInfo};
use crate::utils::{generate_seid, generate_unique_nonce_prefix};
use anet_common::consts::{AUTH_PREFIX_LEN, NONCE_LEN};
use anet_common::crypto_utils;
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
use rand::RngCore;
use rand::rngs::OsRng;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use x25519_dalek::{PublicKey, StaticSecret};

pub async fn run_auth_handler(
    mut rx_from_auth: mpsc::Receiver<HandshakeData>,
    reply_socket: Arc<UdpSocket>,
    registry: Arc<ClientRegistry>,
    temp_dh_map: Arc<DashMap<SocketAddr, TempDHInfo>>,
    allowed_clients: Vec<String>,
    server_signing_key: SigningKey,
    quic_cert_pem: String,
) -> Result<()> {
    info!("ANet Auth Handler task started.");
    while let Some((packet, remote_addr)) = rx_from_auth.recv().await {
        let registry = registry.clone();
        let temp_dh_map = temp_dh_map.clone();
        let allowed_clients = allowed_clients.clone();
        let server_signing_key = server_signing_key.clone();
        let quic_cert_pem = quic_cert_pem.clone();
        let reply_socket = reply_socket.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_auth_request(
                packet,
                remote_addr,
                &reply_socket,
                registry,
                temp_dh_map,
                &allowed_clients,
                &server_signing_key,
                &quic_cert_pem,
            )
            .await
            {
                error!("[AUTH] Handshake failed for {}: {}", remote_addr, e);
            }
        });
    }
    Ok(())
}

async fn handle_auth_request(
    full_packet: Bytes,
    remote_addr: SocketAddr,
    socket: &Arc<UdpSocket>,
    registry: Arc<ClientRegistry>,
    temp_dh_map: Arc<DashMap<SocketAddr, TempDHInfo>>,
    allowed_clients: &[String],
    server_signing_key: &SigningKey,
    quic_cert_pem: &str,
) -> Result<()> {
    let prefix = &full_packet[..AUTH_PREFIX_LEN];
    let salt = crypto_utils::extract_salt_from_prefix(prefix)
        .unwrap()
        .to_vec();
    let mut payload = full_packet.slice(AUTH_PREFIX_LEN..).to_vec();
    crypto_utils::xor_bytes(&mut payload, &salt);
    let message: AnetMessage = Message::decode(Bytes::from(payload))?;

    match message.content {
        Some(Content::DhClientExchange(req)) => {
            let client_public_key = VerifyingKey::from_bytes(
                &req.client_public_key
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Invalid key length"))?,
            )?;
            let client_fingerprint = crypto_utils::generate_key_fingerprint(&client_public_key);
            if !allowed_clients.contains(&client_fingerprint) {
                return Err(anyhow::anyhow!(
                    "Client {} not in allowed list",
                    client_fingerprint
                ));
            }
            crypto_utils::verify_signature(
                &client_public_key,
                &req.public_key,
                &req.client_signed_dh_key,
            )?;
            info!(
                "[AUTH] Client {} authenticated via signature from {}",
                client_fingerprint, remote_addr
            );

            let server_ephemeral_secret = StaticSecret::random_from_rng(OsRng);
            let server_pub_key = PublicKey::from(&server_ephemeral_secret);

            if req.public_key.len() != 32 {
                return Err(anyhow::anyhow!("Invalid client DH public key length"));
            }
            let client_pub_key_array: [u8; 32] = req
                .public_key
                .as_slice()
                .try_into()
                .context("Failed to convert client public key to a fixed-size array")?;
            let client_pub_key = PublicKey::from(client_pub_key_array);

            let shared_secret = server_ephemeral_secret.diffie_hellman(&client_pub_key);

            temp_dh_map.insert(
                remote_addr,
                TempDHInfo {
                    shared_key: crypto_utils::derive_shared_key(&shared_secret),
                    client_fingerprint,
                    created_at: Instant::now(),
                },
            );

            let response_payload = DhServerExchange {
                public_key: server_pub_key.as_bytes().to_vec(),
                server_signed_dh_key: crypto_utils::sign_data(
                    server_signing_key,
                    server_pub_key.as_bytes(),
                ),
            };
            let response_message = AnetMessage {
                content: Some(Content::DhServerExchange(response_payload)),
            };
            let mut response_data = Vec::new();
            response_message.encode(&mut response_data)?;

            let prefix_info = crypto_utils::generate_prefix_with_salt();
            crypto_utils::xor_bytes(&mut response_data, &prefix_info.salt);
            let mut response_packet =
                BytesMut::with_capacity(AUTH_PREFIX_LEN + response_data.len());
            response_packet.put_slice(&prefix_info.prefix);
            response_packet.put_slice(&response_data);
            socket.send_to(&response_packet, remote_addr).await?;
            Ok(())
        }

        Some(Content::EncryptedAuthRequest(enc_req)) => {
            let temp_info = temp_dh_map
                .remove(&remote_addr)
                .map(|(_, v)| v)
                .context("DH session expired or not found")?;
            let cipher = Cipher::new(&temp_info.shared_key);
            let plaintext =
                cipher.decrypt(enc_req.nonce.as_slice(), Bytes::from(enc_req.ciphertext))?;
            let auth_message: AnetMessage = Message::decode(plaintext)?;

            match auth_message.content {
                Some(Content::AuthRequest(req))
                    if req.client_id == temp_info.client_fingerprint =>
                {
                    let assigned_ip = registry.allocate_ip().context("No free IPs available")?;
                    let client_ip_str = assigned_ip.to_string();
                    let nonce_prefix = generate_unique_nonce_prefix(registry.clone());
                    let session_id = generate_seid();

                    let client_info = Arc::new(ClientTransportInfo {
                        cipher: Arc::new(Cipher::new(&temp_info.shared_key)),
                        sequence: Arc::new(AtomicU64::new(0)),
                        assigned_ip: client_ip_str.clone(),
                        session_id: session_id.clone(),
                        nonce_prefix,
                        remote_addr: ArcSwap::new(Arc::new(remote_addr)),
                    });

                    registry.pre_register_client(client_info);

                    let (netmask, gateway, mtu) = registry.get_network_params();
                    let response_payload = AuthResponse {
                        ip: client_ip_str,
                        netmask: netmask.to_string(),
                        gateway: gateway.to_string(),
                        mtu: mtu as i32,
                        session_id,
                        nonce_prefix: nonce_prefix.to_vec(),
                        quic_cert: quic_cert_pem.as_bytes().to_vec(),
                    };

                    let mut final_data = Vec::new();

                    // --- ИСПРАВЛЕНИЕ: Генерируем nonce ОДИН раз ---
                    let mut nonce_bytes_for_response = [0u8; NONCE_LEN];
                    OsRng.fill_bytes(&mut nonce_bytes_for_response);

                    AnetMessage {
                        content: Some(Content::EncryptedAuthResponse(EncryptedAuthResponse {
                            ciphertext: {
                                let mut raw_resp = Vec::new();
                                AnetMessage {
                                    content: Some(Content::AuthResponse(response_payload)),
                                }
                                .encode(&mut raw_resp)?;
                                // Используем сгенерированный nonce для шифрования
                                cipher
                                    .encrypt(&nonce_bytes_for_response, Bytes::from(raw_resp))?
                                    .to_vec()
                            },
                            // Используем ТОТ ЖЕ САМЫЙ nonce в сообщении
                            nonce: nonce_bytes_for_response.to_vec(),
                        })),
                    }
                    .encode(&mut final_data)?;

                    let prefix_info = crypto_utils::generate_prefix_with_salt();
                    crypto_utils::xor_bytes(&mut final_data, &prefix_info.salt);
                    let mut response_packet =
                        BytesMut::with_capacity(AUTH_PREFIX_LEN + final_data.len());
                    response_packet.put_slice(&prefix_info.prefix);
                    response_packet.put_slice(&final_data);
                    socket.send_to(&response_packet, remote_addr).await?;
                    Ok(())
                }
                _ => Err(anyhow::anyhow!("Invalid or mismatched AuthRequest")),
            }
        }
        _ => Err(anyhow::anyhow!("Unexpected message type in handshake")),
    }
}

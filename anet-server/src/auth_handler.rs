use crate::auth_provider::AuthProvider;
use crate::client_registry::{ClientRegistry, ClientTransportInfo};
use crate::multikey_udp_socket::{HandshakeData, TempDHInfo};
use crate::utils::{generate_seid, generate_unique_nonce_prefix};
use anet_common::consts::{NONCE_LEN, PROTO_PAD_FIELD_OVERHEAD};
use anet_common::crypto_utils;
use anet_common::encryption::Cipher;
use anet_common::padding_utils::{calculate_padding_needed, generate_random_padding};
use anet_common::protocol::{
    AuthResponse, DhClientExchange, DhServerExchange, EncryptedAuthRequest, EncryptedAuthResponse,
    Message as AnetMessage, message::Content,
};
use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use bytes::{BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use ed25519_dalek::{SigningKey, VerifyingKey};
use log::{debug, info};
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

#[derive(Clone)]
pub struct ServerAuthHandler {
    socket: Arc<UdpSocket>,
    registry: Arc<ClientRegistry>,
    temp_dh_map: Arc<DashMap<SocketAddr, TempDHInfo>>,
    auth_provider: Arc<AuthProvider>,
    server_signing_key: SigningKey,
    handshake_cipher: Arc<Cipher>,
    quic_cert_pem: String,
    padding_step: u16,
}

impl ServerAuthHandler {
    pub fn new(
        socket: Arc<UdpSocket>,
        registry: Arc<ClientRegistry>,
        temp_dh_map: Arc<DashMap<SocketAddr, TempDHInfo>>,
        auth_provider: Arc<AuthProvider>,
        server_signing_key: SigningKey,
        quic_cert_pem: String,
        padding_step: u16,
    ) -> Self {
        // Генерируем Cipher из своего же публичного ключа
        let pub_key_bytes = server_signing_key.verifying_key().to_bytes();
        let handshake_cipher = Arc::new(crypto_utils::create_handshake_cipher(&pub_key_bytes));

        Self {
            socket,
            registry,
            temp_dh_map,
            auth_provider,
            server_signing_key,
            handshake_cipher,
            quic_cert_pem,
            padding_step,
        }
    }

    pub async fn run(self, mut rx_from_auth: mpsc::Receiver<HandshakeData>) {
        info!("ANet Auth Handler task started.");
        while let Some((packet, remote_addr)) = rx_from_auth.recv().await {
            let handler = self.clone();
            tokio::spawn(async move {
                if let Err(e) = handler.handle_packet(packet, remote_addr).await {
                    // Ошибки дешифровки здесь - это норма (сканнеры портов, мусор)
                    debug!("[AUTH] Handshake dropped from {}: {}", remote_addr, e);
                }
            });
        }
    }

    fn decode_obfuscated_packet(&self, packet: Bytes) -> Result<AnetMessage> {
        if packet.len() < NONCE_LEN + 16 {
            return Err(anyhow::anyhow!("Packet too short"));
        }

        let (nonce, ciphertext) = packet.split_at(NONCE_LEN);
        let plaintext = self
            .handshake_cipher
            .decrypt(nonce, Bytes::copy_from_slice(ciphertext))?;

        Message::decode(plaintext).context("Failed to decode Protobuf")
    }

    async fn handle_packet(&self, full_packet: Bytes, remote_addr: SocketAddr) -> Result<()> {
        let message = self.decode_obfuscated_packet(full_packet)?;

        match message.content {
            Some(Content::DhClientExchange(req)) => self.handle_dh_exchange(req, remote_addr).await,
            Some(Content::EncryptedAuthRequest(enc_req)) => {
                self.handle_encrypted_auth(enc_req, remote_addr).await
            }
            _ => Err(anyhow::anyhow!("Unexpected message type in handshake")),
        }
    }

    async fn handle_dh_exchange(
        &self,
        req: DhClientExchange,
        remote_addr: SocketAddr,
    ) -> Result<()> {
        let client_public_key = VerifyingKey::from_bytes(
            &req.client_public_key
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid key length"))?,
        )?;

        let client_fingerprint = crypto_utils::generate_key_fingerprint(&client_public_key);

        // --- ВНЕШНЯЯ АВТОРИЗАЦИЯ ---
        if !self
            .auth_provider
            .is_client_allowed(&client_fingerprint)
            .await
        {
            return Err(anyhow::anyhow!(
                "Client {} access denied",
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

        let client_dh_pub_array: [u8; 32] = req
            .public_key
            .as_slice()
            .try_into()
            .context("Failed to convert client DH public key")?;
        let client_dh_pub = PublicKey::from(client_dh_pub_array);

        let shared_secret = server_ephemeral_secret.diffie_hellman(&client_dh_pub);

        self.temp_dh_map.insert(
            remote_addr,
            TempDHInfo {
                auth_key: crypto_utils::derive_shared_key(&shared_secret, b"anet-auth-encrypt"),
                transport_key: crypto_utils::derive_shared_key(&shared_secret, b"anet-transport"),
                client_fingerprint,
                created_at: Instant::now(),
            },
        );

        let response_payload = DhServerExchange {
            public_key: server_pub_key.as_bytes().to_vec(),
            server_signed_dh_key: crypto_utils::sign_data(
                &self.server_signing_key,
                server_pub_key.as_bytes(),
            ),
        };

        let mut response_message = AnetMessage {
            content: Some(Content::DhServerExchange(response_payload)),
            padding: vec![],
        };

        let wire_len = response_message.encoded_len() + NONCE_LEN + PROTO_PAD_FIELD_OVERHEAD;
        response_message.padding =
            generate_random_padding(calculate_padding_needed(wire_len, self.padding_step));

        self.send_obfuscated(response_message, remote_addr).await
    }

    async fn handle_encrypted_auth(
        &self,
        enc_req: EncryptedAuthRequest,
        remote_addr: SocketAddr,
    ) -> Result<()> {
        let temp_info = self
            .temp_dh_map
            .remove(&remote_addr)
            .map(|(_, v)| v)
            .context("DH session expired or not found")?;

        let cipher = Cipher::new(&temp_info.auth_key);

        let plaintext =
            cipher.decrypt(enc_req.nonce.as_slice(), Bytes::from(enc_req.ciphertext))?;
        let auth_message: AnetMessage = Message::decode(plaintext)?;

        let req = match auth_message.content {
            Some(Content::AuthRequest(r)) => r,
            _ => return Err(anyhow::anyhow!("Invalid content")),
        };

        if req.client_id != temp_info.client_fingerprint {
            return Err(anyhow::anyhow!("Client ID mismatch"));
        }

        let assigned_ip = self
            .registry
            .allocate_ip()
            .context("No free IPs available")?;
        let client_ip_str = assigned_ip.to_string();
        let nonce_prefix = generate_unique_nonce_prefix(self.registry.clone());
        let session_id = generate_seid();

        let client_info = Arc::new(ClientTransportInfo {
            cipher: Arc::new(Cipher::new(&temp_info.transport_key)),
            sequence: Arc::new(AtomicU64::new(0)),
            assigned_ip: client_ip_str.clone(),
            session_id: session_id.clone(),
            nonce_prefix,
            remote_addr: ArcSwap::new(Arc::new(remote_addr)),
        });

        self.registry.pre_register_client(client_info);

        let (netmask, gateway, mtu) = self.registry.get_network_params();
        let response_payload = AuthResponse {
            ip: client_ip_str,
            netmask: netmask.to_string(),
            gateway: gateway.to_string(),
            mtu: mtu as i32,
            session_id,
            nonce_prefix: nonce_prefix.to_vec(),
            quic_cert: self.quic_cert_pem.as_bytes().to_vec(),
        };

        let mut inner_msg = AnetMessage {
            content: Some(Content::AuthResponse(response_payload)),
            padding: vec![],
        };
        let inner_len = inner_msg.encoded_len() + PROTO_PAD_FIELD_OVERHEAD;
        inner_msg.padding =
            generate_random_padding(calculate_padding_needed(inner_len, self.padding_step));

        let mut raw_resp = Vec::new();
        inner_msg.encode(&mut raw_resp)?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let ciphertext = cipher.encrypt(&nonce_bytes, Bytes::from(raw_resp))?;

        let mut outer_msg = AnetMessage {
            content: Some(Content::EncryptedAuthResponse(EncryptedAuthResponse {
                ciphertext: ciphertext.to_vec(),
                nonce: nonce_bytes.to_vec(),
            })),
            padding: vec![],
        };

        let outer_len = outer_msg.encoded_len() + NONCE_LEN + PROTO_PAD_FIELD_OVERHEAD;
        outer_msg.padding =
            generate_random_padding(calculate_padding_needed(outer_len, self.padding_step));

        self.send_obfuscated(outer_msg, remote_addr).await
    }

    async fn send_obfuscated(&self, message: AnetMessage, addr: SocketAddr) -> Result<()> {
        let mut data = Vec::new();
        message.encode(&mut data)?;

        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        // Шифруем нашим Handshake Cipher
        let ciphertext = self.handshake_cipher.encrypt(&nonce, Bytes::from(data))?;

        let mut packet = BytesMut::with_capacity(NONCE_LEN + ciphertext.len());
        packet.put_slice(&nonce);
        packet.put(ciphertext);

        self.socket.send_to(&packet, addr).await?;
        Ok(())
    }
}

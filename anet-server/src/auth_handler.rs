use crate::auth_provider::AuthProvider;
use crate::client_registry::{ClientRegistry, ClientTransportInfo};
use crate::multikey_udp_socket::{TempDHInfo};
use crate::utils::{generate_seid, generate_unique_nonce_prefix};
use anet_common::consts::{NONCE_LEN, PROTO_PAD_FIELD_OVERHEAD};
use anet_common::crypto_utils;
use anet_common::encryption::Cipher;
use anet_common::padding_utils::{calculate_padding_needed, generate_random_padding};
use anet_common::protocol::{
    AuthResponse, DhClientExchange, DhServerExchange, EncryptedAuthRequest, EncryptedAuthResponse,
    Message as AnetMessage, message::Content,
};
use anyhow::{Context, Result, anyhow};
use arc_swap::ArcSwap;
use bytes::{BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use ed25519_dalek::{SigningKey, VerifyingKey};
use log::info;
use prost::Message;
use rand::RngCore;
use rand::rngs::OsRng;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Instant;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Clone)]
pub struct ServerAuthHandler {
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
        registry: Arc<ClientRegistry>,
        temp_dh_map: Arc<DashMap<SocketAddr, TempDHInfo>>,
        auth_provider: Arc<AuthProvider>,
        server_signing_key: SigningKey,
        quic_cert_pem: String,
        padding_step: u16,
    ) -> Self {
        let pub_key_bytes = server_signing_key.verifying_key().to_bytes();
        let handshake_cipher = Arc::new(crypto_utils::create_handshake_cipher(&pub_key_bytes));

        Self {
            registry,
            temp_dh_map,
            auth_provider,
            server_signing_key,
            handshake_cipher,
            quic_cert_pem,
            padding_step,
        }
    }

    pub async fn process_handshake_packet(
        &self,
        packet: Bytes,
        remote_addr: SocketAddr,
    ) -> Result<(
        Option<Bytes>,
        Option<(Arc<ClientTransportInfo>, AuthResponse)>,
    )> {
        let message = self.decode_obfuscated_packet(packet)?;

        match message.content {
            Some(Content::DhClientExchange(req)) => {
                let resp_msg = self.handle_dh_exchange(req, remote_addr).await?;
                let resp_bytes = self.encode_obfuscated_packet(resp_msg)?;
                Ok((Some(resp_bytes), None))
            }
            Some(Content::EncryptedAuthRequest(enc_req)) => {
                let (resp_msg, client_info, auth_resp) =
                    self.handle_encrypted_auth(enc_req, remote_addr).await?;
                let resp_bytes = self.encode_obfuscated_packet(resp_msg)?;
                Ok((Some(resp_bytes), Some((client_info, auth_resp))))
            }
            _ => Err(anyhow!("Invalid payload message type")),
        }
    }

    fn decode_obfuscated_packet(&self, packet: Bytes) -> Result<AnetMessage> {
        if packet.len() < NONCE_LEN + 16 {
            return Err(anyhow::anyhow!("Packet too short"));
        }
        let (nonce, ciphertext) = packet.split_at(NONCE_LEN);
        let plaintext = self.handshake_cipher.decrypt(nonce, Bytes::copy_from_slice(ciphertext))?;
        Message::decode(plaintext).context("Failed to decode Protobuf")
    }

    fn encode_obfuscated_packet(&self, message: AnetMessage) -> Result<Bytes> {
        let mut data = Vec::new();
        message.encode(&mut data)?;

        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        let ciphertext = self.handshake_cipher.encrypt(&nonce, Bytes::from(data))?;
        let mut packet = BytesMut::with_capacity(NONCE_LEN + ciphertext.len());
        packet.put_slice(&nonce);
        packet.put(ciphertext);
        Ok(packet.freeze())
    }

    async fn handle_dh_exchange(&self, req: DhClientExchange, remote_addr: SocketAddr) -> Result<AnetMessage> {
        let client_public_key = VerifyingKey::from_bytes(
            &req.client_public_key.try_into().map_err(|_| anyhow::anyhow!("Invalid key length"))?,
        )?;
        let client_fingerprint = crypto_utils::generate_key_fingerprint(&client_public_key);

        if !self.auth_provider.is_client_allowed(&client_fingerprint).await {
            return Err(anyhow::anyhow!("Client access denied: {}", client_fingerprint));
        }
        crypto_utils::verify_signature(&client_public_key, &req.public_key, &req.client_signed_dh_key)?;

        info!("[AUTH] Auth Phase 1 success: {}", remote_addr);

        let server_ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let server_pub_key = PublicKey::from(&server_ephemeral_secret);

        let client_dh_pub_array: [u8; 32] = req.public_key.as_slice().try_into().unwrap();
        let client_dh_pub = PublicKey::from(client_dh_pub_array);

        let shared_secret = server_ephemeral_secret.diffie_hellman(&client_dh_pub);
        self.temp_dh_map.insert(remote_addr, TempDHInfo {
            shared_key: crypto_utils::derive_shared_key(&shared_secret),
            client_fingerprint,
            created_at: Instant::now(),
        });

        let response_payload = DhServerExchange {
            public_key: server_pub_key.as_bytes().to_vec(),
            server_signed_dh_key: crypto_utils::sign_data(&self.server_signing_key, server_pub_key.as_bytes()),
        };

        let mut response_message = AnetMessage {
            content: Some(Content::DhServerExchange(response_payload)),
            padding: vec![],
        };
        let wire_len = response_message.encoded_len() + NONCE_LEN + PROTO_PAD_FIELD_OVERHEAD;
        response_message.padding = generate_random_padding(calculate_padding_needed(wire_len, self.padding_step));

        Ok(response_message)
    }

    async fn handle_encrypted_auth(&self, enc_req: EncryptedAuthRequest, remote_addr: SocketAddr) -> Result<(AnetMessage, Arc<ClientTransportInfo>, AuthResponse)> {
        let temp_info = self.temp_dh_map.remove(&remote_addr).map(|(_, v)| v).context("DH session expired or not found")?;
        let cipher = Cipher::new(&temp_info.shared_key);
        let plaintext = cipher.decrypt(enc_req.nonce.as_slice(), Bytes::from(enc_req.ciphertext))?;
        let auth_message: AnetMessage = Message::decode(plaintext)?;

        let req = match auth_message.content {
            Some(Content::AuthRequest(r)) => r,
            _ => return Err(anyhow::anyhow!("Invalid content type")),
        };
        if req.client_id != temp_info.client_fingerprint { return Err(anyhow::anyhow!("Client ID mismatch")); }

        let assigned_ip = self.registry.allocate_ip(req.client_id).context("IP POOL DEPLETED")?.to_string();
        let session_id = generate_seid();
        let nonce_prefix = generate_unique_nonce_prefix(self.registry.clone());

        let client_info = Arc::new(ClientTransportInfo {
            cipher: Arc::new(Cipher::new(&temp_info.shared_key)),
            sequence: Arc::new(AtomicU64::new(0)),
            assigned_ip: assigned_ip.clone(),
            session_id: session_id.clone(),
            nonce_prefix,
            remote_addr: ArcSwap::new(Arc::new(remote_addr)),
        });

        self.registry.pre_register_client(client_info.clone());

        let (netmask, gateway, mtu) = self.registry.get_network_params();
        let response_payload = AuthResponse {
            ip: assigned_ip,
            netmask: netmask.to_string(),
            gateway: gateway.to_string(),
            mtu: mtu as i32,
            session_id,
            nonce_prefix: nonce_prefix.to_vec(),
            quic_cert: self.quic_cert_pem.as_bytes().to_vec(),
        };

        let mut inner_msg = AnetMessage { content: Some(Content::AuthResponse(response_payload.clone())), padding: vec![] };
        inner_msg.padding = generate_random_padding(calculate_padding_needed(inner_msg.encoded_len() + PROTO_PAD_FIELD_OVERHEAD, self.padding_step));

        let mut raw_resp = Vec::new();
        inner_msg.encode(&mut raw_resp)?;

        let cipher = Cipher::new(&temp_info.shared_key);
        let mut nonce_bytes = [0u8; NONCE_LEN]; OsRng.fill_bytes(&mut nonce_bytes);
        let ciphertext = cipher.encrypt(&nonce_bytes, Bytes::from(raw_resp))?;

        let mut outer_msg = AnetMessage {
            content: Some(Content::EncryptedAuthResponse(EncryptedAuthResponse { ciphertext: ciphertext.to_vec(), nonce: nonce_bytes.to_vec() })),
            padding: vec![],
        };
        outer_msg.padding = generate_random_padding(calculate_padding_needed(outer_msg.encoded_len() + NONCE_LEN + PROTO_PAD_FIELD_OVERHEAD, self.padding_step));

        Ok((outer_msg, client_info, response_payload))
    }
}

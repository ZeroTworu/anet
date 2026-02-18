use anet_common::crypto_utils;
use anet_common::encryption::Cipher;
use anet_common::padding_utils::{calculate_padding_needed, generate_random_padding};
use anet_common::protocol::{
    AuthResponse, DhClientExchange, DhServerExchange, EncryptedAuthRequest, EncryptedAuthResponse,
    Message as AnetMessage, message::Content,
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use log::info;
use prost::Message;
use rand::RngCore;
use rand::rngs::OsRng;
use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::auth_provider::AuthProvider;
use crate::utils::{generate_seid, generate_unique_nonce_prefix};

pub const NONCE_LEN: usize = 12;
pub const PROTO_PAD_FIELD_OVERHEAD: usize = 3;

#[async_trait]
pub trait HandshakeTransport: Send {
    async fn send_message(&mut self, msg: &AnetMessage) -> Result<()>;
    async fn receive_message(&mut self) -> Result<AnetMessage>;
}

pub struct ClientInfo {
    pub fingerprint: String,
    pub assigned_ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub mtu: u16,
    pub session_id: String,
    pub nonce_prefix: [u8; 4],
    pub shared_key: [u8; 32],
}

pub async fn perform_handshake(
    transport: &mut impl HandshakeTransport,
    auth_provider: &AuthProvider,
    server_signing_key: &SigningKey,
    ip_pool: &crate::ip_pool::IpPool, // передаём для выделения IP
    padding_step: u16,
) -> Result<ClientInfo> {
    // 1. Получаем DhClientExchange
    let msg = transport.receive_message().await?;
    let dh_client = match msg.content {
        Some(Content::DhClientExchange(ex)) => ex,
        _ => anyhow::bail!("Expected DhClientExchange"),
    };

    // 2. Проверяем подпись клиента
    let client_public_key = ed25519_dalek::VerifyingKey::from_bytes(
        dh_client.client_public_key.as_slice().try_into()?,
    )?;
    crypto_utils::verify_signature(
        &client_public_key,
        &dh_client.public_key,
        &dh_client.client_signed_dh_key,
    )?;

    let fingerprint = crypto_utils::generate_key_fingerprint(&client_public_key);

    // 3. Проверяем разрешение через AuthProvider
    if !auth_provider.is_client_allowed(&fingerprint).await {
        anyhow::bail!("Client {} not allowed", fingerprint);
    }

    // 4. Генерируем свой DH и вычисляем общий секрет
    let server_ephemeral_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let server_pub_key = x25519_dalek::PublicKey::from(&server_ephemeral_secret);

    let client_dh_pub_array: [u8; 32] = dh_client.public_key.as_slice().try_into()?;
    let client_dh_pub = x25519_dalek::PublicKey::from(client_dh_pub_array);
    let shared_secret = server_ephemeral_secret.diffie_hellman(&client_dh_pub);
    let shared_key = crypto_utils::derive_shared_key(&shared_secret);

    // 5. Отправляем DhServerExchange
    let server_exchange = DhServerExchange {
        public_key: server_pub_key.as_bytes().to_vec(),
        server_signed_dh_key: crypto_utils::sign_data(
            server_signing_key,
            server_pub_key.as_bytes(),
        ),
    };
    let mut resp_msg = AnetMessage {
        content: Some(Content::DhServerExchange(server_exchange)),
        padding: vec![],
    };
    let wire_len = resp_msg.encoded_len() + NONCE_LEN + PROTO_PAD_FIELD_OVERHEAD;
    resp_msg.padding = generate_random_padding(calculate_padding_needed(wire_len, padding_step));
    transport.send_message(&resp_msg).await?;

    // 6. Получаем EncryptedAuthRequest
    let msg = transport.receive_message().await?;
    let enc_req = match msg.content {
        Some(Content::EncryptedAuthRequest(e)) => e,
        _ => anyhow::bail!("Expected EncryptedAuthRequest"),
    };

    let cipher = Cipher::new(&shared_key);
    let plaintext = cipher.decrypt(&enc_req.nonce, Bytes::from(enc_req.ciphertext))?;
    let auth_req_msg: AnetMessage = Message::decode(plaintext)?;
    let auth_req = match auth_req_msg.content {
        Some(Content::AuthRequest(r)) => r,
        _ => anyhow::bail!("Expected AuthRequest"),
    };

    if auth_req.client_id != fingerprint {
        anyhow::bail!("Client ID mismatch");
    }

    // 7. Назначаем IP, генерируем nonce_prefix и session_id
    let assigned_ip = ip_pool
        .allocate()
        .context("No free IP addresses available")?;
    let (netmask, gateway, mtu) = ip_pool.get_network_params(); // метод, возвращающий кортеж
    let nonce_prefix = generate_unique_nonce_prefix(); // нужна функция
    let session_id = generate_seid();

    // 8. Отправляем EncryptedAuthResponse
    let auth_response = AuthResponse {
        ip: assigned_ip.to_string(),
        netmask: netmask.to_string(),
        gateway: gateway.to_string(),
        mtu: mtu as i32,
        session_id: session_id.clone(),
        nonce_prefix: nonce_prefix.to_vec(),
        quic_cert: vec![], // для TCP/SSH не нужен QUIC-сертификат, можно пустой или заглушку
    };

    let mut inner_msg = AnetMessage {
        content: Some(Content::AuthResponse(auth_response)),
        padding: vec![],
    };
    let inner_len = inner_msg.encoded_len() + PROTO_PAD_FIELD_OVERHEAD;
    inner_msg.padding =
        generate_random_padding(calculate_padding_needed(inner_len, padding_step));

    let mut raw_resp = Vec::new();
    inner_msg.encode(&mut raw_resp)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher.encrypt(&nonce_bytes, Bytes::from(raw_resp))?;

    let enc_resp = EncryptedAuthResponse {
        ciphertext: ciphertext.to_vec(),
        nonce: nonce_bytes.to_vec(),
    };
    let mut outer_msg = AnetMessage {
        content: Some(Content::EncryptedAuthResponse(enc_resp)),
        padding: vec![],
    };
    let outer_len = outer_msg.encoded_len() + NONCE_LEN + PROTO_FIELD_OVERHEAD; // нужна константа
    outer_msg.padding =
        generate_random_padding(calculate_padding_needed(outer_len, padding_step));

    transport.send_message(&outer_msg).await?;

    Ok(ClientInfo {
        fingerprint,
        assigned_ip,
        netmask,
        gateway,
        mtu,
        session_id,
        nonce_prefix,
        shared_key,
    })
}
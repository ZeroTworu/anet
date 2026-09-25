use base64::prelude::*;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColibriMessage {
    #[serde(rename = "colibriClass")]
    pub colibri_class: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(rename = "msgPayload")]
    pub msg_payload: ColibriPayload,
}

impl ColibriMessage {
    pub fn new_endpoint_message(to: Option<String>, payload: ColibriPayload) -> Self {
        Self {
            colibri_class: "EndpointMessage".to_string(),
            to,
            from: None,
            msg_payload: payload,
        }
    }

    pub fn discover(client_nonce: String) -> Self {
        Self::new_endpoint_message(
            None,
            ColibriPayload::Discover { client_nonce },
        )
    }

    pub fn beacon(
        to_client_endpoint: String,
        server_id: String,
        client_nonce: String,
        signature: String,
    ) -> Self {
        Self::new_endpoint_message(
            Some(to_client_endpoint),
            ColibriPayload::Beacon {
                server_id,
                client_nonce,
                signature,
            },
        )
    }

    pub fn astp(to: String, base64_data: String) -> Self {
        Self::new_endpoint_message(
            Some(to),
            ColibriPayload::Astp { data: base64_data },
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ColibriPayload {
    #[serde(rename = "anet_discover")]
    Discover {
        client_nonce: String,
    },
    #[serde(rename = "anet_beacon")]
    Beacon {
        server_id: String,
        client_nonce: String,
        signature: String,
    },
    #[serde(rename = "astp")]
    Astp {
        data: String,
    },
    #[serde(other)]
    Unknown,
}

/// Sign (client_nonce + server_id) with server Ed25519 private key.
pub fn sign_beacon(
    signing_key_bytes: &[u8; 32],
    client_nonce: &str,
    server_id: &str,
) -> String {
    let signing_key = SigningKey::from_bytes(signing_key_bytes);
    let mut message = Vec::with_capacity(client_nonce.len() + server_id.len());
    message.extend_from_slice(client_nonce.as_bytes());
    message.extend_from_slice(server_id.as_bytes());

    let signature = signing_key.sign(&message);
    BASE64_STANDARD.encode(signature.to_bytes())
}

/// Verify beacon signature against server public key.
pub fn verify_beacon(
    server_pub_key_b64: &str,
    client_nonce: &str,
    server_id: &str,
    signature_b64: &str,
) -> anyhow::Result<bool> {
    let pub_bytes = BASE64_STANDARD.decode(server_pub_key_b64.trim())?;
    let pub_array: [u8; 32] = pub_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid server public key length (expected 32 bytes)"))?;

    let verifying_key = VerifyingKey::from_bytes(&pub_array)
        .map_err(|e| anyhow::anyhow!("Invalid Ed25519 verifying key: {e}"))?;

    let sig_bytes = BASE64_STANDARD.decode(signature_b64.trim())?;
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid signature length (expected 64 bytes)"))?;

    let signature = Signature::from_bytes(&sig_array);

    let mut message = Vec::with_capacity(client_nonce.len() + server_id.len());
    message.extend_from_slice(client_nonce.as_bytes());
    message.extend_from_slice(server_id.as_bytes());

    Ok(verifying_key.verify_strict(&message, &signature).is_ok())
}

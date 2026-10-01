use anyhow::Context;
use base64::prelude::*;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ColibriClass {
    #[serde(rename = "EndpointMessage")]
    EndpointMessage,
    #[serde(rename = "DominantSpeakerEndpointChangeEvent")]
    DominantSpeaker,
    #[serde(other)]
    Unknown,
}

impl Default for ColibriClass {
    fn default() -> Self {
        ColibriClass::EndpointMessage
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WrtcMode {
    Auto,
    P2pDirect,
    JvbDatachannel,
    Ws,
    MediaVideo,
}

impl Default for WrtcMode {
    fn default() -> Self {
        WrtcMode::Auto
    }
}

impl std::str::FromStr for WrtcMode {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.trim().to_lowercase().as_str() {
            "p2p" | "p2p_direct" | "direct" => WrtcMode::P2pDirect,
            "dc" | "datachannel" | "jvb_dc" | "jvb_datachannel" => WrtcMode::JvbDatachannel,
            "ws" | "websocket" | "colibri_ws" => WrtcMode::Ws,
            "media_video" | "video" | "vp8" | "media_rtp" | "media" => WrtcMode::MediaVideo,
            _ => WrtcMode::Auto,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WrtcMessage {
    #[serde(rename = "anet_discover")]
    Discover {
        client_nonce: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        video_ssrc: Option<u32>,
    },
    #[serde(rename = "anet_beacon")]
    Beacon {
        server_id: String,
        client_nonce: String,
        signature: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        video_ssrc: Option<u32>,
    },
    #[serde(rename = "astp")]
    Astp {
        data: String,
    },
    #[serde(rename = "astp_batch")]
    AstpBatch {
        data: String,
    },
    #[serde(rename = "anet_p2p_offer")]
    P2pOffer {
        sdp: String,
        candidates: Vec<String>,
    },
    #[serde(rename = "anet_p2p_answer")]
    P2pAnswer {
        sdp: String,
        candidates: Vec<String>,
    },
    #[serde(rename = "anet_p2p_candidate")]
    P2pCandidate {
        candidate: String,
    },
    #[serde(rename = "anet_ping")]
    Ping,
    #[serde(rename = "anet_pong")]
    Pong,
    #[serde(other)]
    Unknown,
}

fn default_wrtc_message() -> WrtcMessage {
    WrtcMessage::Unknown
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColibriMessage {
    #[serde(rename = "colibriClass")]
    pub colibri_class: ColibriClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(rename = "msgPayload", default = "default_wrtc_message")]
    pub msg_payload: WrtcMessage,
}

impl ColibriMessage {
    pub fn new_endpoint_message(to: Option<String>, payload: WrtcMessage) -> Self {
        Self {
            colibri_class: ColibriClass::EndpointMessage,
            to,
            from: None,
            msg_payload: payload,
        }
    }

    pub fn discover(to: Option<String>, client_nonce: String, video_ssrc: Option<u32>) -> Self {
        Self::new_endpoint_message(
            to,
            WrtcMessage::Discover {
                client_nonce,
                video_ssrc,
            },
        )
    }

    pub fn beacon(
        to_client_endpoint: String,
        server_id: String,
        client_nonce: String,
        signature: String,
        video_ssrc: Option<u32>,
    ) -> Self {
        Self::new_endpoint_message(
            Some(to_client_endpoint),
            WrtcMessage::Beacon {
                server_id,
                client_nonce,
                signature,
                video_ssrc,
            },
        )
    }

    pub fn astp(to: String, base64_data: String) -> Self {
        Self::new_endpoint_message(
            Some(to),
            WrtcMessage::Astp { data: base64_data },
        )
    }

    pub fn astp_batch(to: String, base64_data: String) -> Self {
        Self::new_endpoint_message(
            Some(to),
            WrtcMessage::AstpBatch { data: base64_data },
        )
    }

    pub fn p2p_offer(to: String, sdp: String, candidates: Vec<String>) -> Self {
        Self::new_endpoint_message(
            Some(to),
            WrtcMessage::P2pOffer { sdp, candidates },
        )
    }

    pub fn p2p_answer(to: String, sdp: String, candidates: Vec<String>) -> Self {
        Self::new_endpoint_message(
            Some(to),
            WrtcMessage::P2pAnswer { sdp, candidates },
        )
    }

    pub fn p2p_candidate(to: String, candidate: String) -> Self {
        Self::new_endpoint_message(
            Some(to),
            WrtcMessage::P2pCandidate { candidate },
        )
    }

    pub fn ping(to: String) -> Self {
        Self::new_endpoint_message(
            Some(to),
            WrtcMessage::Ping,
        )
    }

    pub fn pong(to: String) -> Self {
        Self::new_endpoint_message(
            Some(to),
            WrtcMessage::Pong,
        )
    }
}

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

pub fn verify_beacon(
    server_pub_key_b64: &str,
    client_nonce: &str,
    server_id: &str,
    signature_b64: &str,
) -> anyhow::Result<bool> {
    let pub_bytes = BASE64_STANDARD.decode(server_pub_key_b64.trim())
        .context("Failed to base64 decode server_pub_key")?;
    let pub_array: [u8; 32] = pub_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid server public key length (expected 32 bytes)"))?;

    let verifying_key = VerifyingKey::from_bytes(&pub_array)
        .map_err(|e| anyhow::anyhow!("Invalid Ed25519 verifying key: {e}"))?;

    let sig_bytes = BASE64_STANDARD.decode(signature_b64.trim())
        .context("Failed to base64 decode beacon signature")?;
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid signature length (expected 64 bytes)"))?;

    let signature = Signature::from_bytes(&sig_array);

    let mut message = Vec::with_capacity(client_nonce.len() + server_id.len());
    message.extend_from_slice(client_nonce.as_bytes());
    message.extend_from_slice(server_id.as_bytes());

    Ok(verifying_key.verify(&message, &signature).is_ok())
}

use crate::wrtc::colibri::{ColibriMessage, WrtcMessage};
use crate::wrtc::jingle::JingleCandidate;
use bytes::Bytes;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::media::Sample;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability;
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;
use webrtc::track::track_local::TrackLocal;

/// 3-byte Opus silence frame (48 kHz, stereo/mono, 20ms).
const OPUS_SILENCE_FRAME: [u8; 3] = [0xf8, 0xff, 0xfe];

pub struct WrtcPeer {
    pub peer_connection: Arc<RTCPeerConnection>,
    pub data_channel: Arc<RTCDataChannel>,
    pub outgoing_tx: mpsc::Sender<ColibriMessage>,
    pub incoming_rx: mpsc::Receiver<ColibriMessage>,
}

impl WrtcPeer {
    /// Initialize WebRTC PeerConnection, apply dynamic ICE candidates (with fallback),
    /// open "JVB data channel", start Opus silence keep-alive, and bind message channels.
    pub async fn create(
        candidates: &[JingleCandidate],
        fallback_ip: &str,
        fallback_port: u16,
        audio_keepalive_ms: u64,
    ) -> anyhow::Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;

        let api = APIBuilder::new()
            .with_media_engine(media_engine)
            .build();

        let config = RTCConfiguration {
            ice_servers: vec![
                RTCIceServer {
                    urls: vec![
                        format!("turn:dtl-talk-stun7.ktalk.host:443?transport=tcp"),
                        format!("stun:dtl-talk-stun7.ktalk.host:443"),
                    ],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        let peer_connection = Arc::new(api.new_peer_connection(config).await?);

        // 1. Add fake Opus audio track to simulate human presence and prevent JVB inactivity drop
        let audio_track = Arc::new(TrackLocalStaticSample::new(
            RTCRtpCodecCapability {
                mime_type: "audio/opus".to_string(),
                clock_rate: 48000,
                channels: 2,
                ..Default::default()
            },
            "audio-silence-track".to_string(),
            "webrtc-stream".to_string(),
        ));

        let _transceiver = peer_connection
            .add_transceiver_from_track(
                Arc::clone(&audio_track) as Arc<dyn TrackLocal + Send + Sync>,
                None,
            )
            .await?;

        // Background Opus audio silence keepalive loop
        let keepalive_ms = if audio_keepalive_ms > 0 { audio_keepalive_ms } else { 20 };
        let silence_track = Arc::clone(&audio_track);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(keepalive_ms));
            let silence_bytes = Bytes::from_static(&OPUS_SILENCE_FRAME);
            loop {
                interval.tick().await;
                let sample = Sample {
                    data: silence_bytes.clone(),
                    duration: Duration::from_millis(keepalive_ms),
                    ..Default::default()
                };
                if let Err(_e) = silence_track.write_sample(&sample).await {
                    break;
                }
            }
        });

        // 2. Open RTCDataChannel with JVB specifications
        let dc_init = RTCDataChannelInit {
            ordered: Some(false),
            max_retransmits: Some(0),
            protocol: Some("http://jitsi.org/protocols/colibri".to_string()),
            ..Default::default()
        };

        let data_channel = peer_connection
            .create_data_channel("JVB data channel", Some(dc_init))
            .await?;

        // 3. Apply dynamic ICE candidates, with fallback if list is empty
        let effective_candidates = if candidates.is_empty() {
            vec![JingleCandidate {
                ip: fallback_ip.to_string(),
                port: fallback_port,
                protocol: "udp".to_string(),
                candidate_type: "host".to_string(),
                priority: 2130706431,
                foundation: "1".to_string(),
                component: 1,
            }]
        } else {
            candidates.to_vec()
        };

        for c in effective_candidates {
            let candidate_sdp = format!(
                "candidate:{} {} {} {} {} {} typ {}",
                c.foundation, c.component, c.protocol, c.priority, c.ip, c.port, c.candidate_type
            );
            let init = RTCIceCandidateInit {
                candidate: candidate_sdp,
                ..Default::default()
            };
            if let Err(e) = peer_connection.add_ice_candidate(init).await {
                log::debug!("[WRTC] Applying candidate failed: {e}");
            }
        }

        // 4. Setup channels for ColibriMessage
        let (incoming_tx, incoming_rx) = mpsc::channel::<ColibriMessage>(256);
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<ColibriMessage>(256);

        let dc_clone = Arc::clone(&data_channel);
        tokio::spawn(async move {
            while let Some(msg) = outgoing_rx.recv().await {
                if let Ok(json_str) = serde_json::to_string(&msg) {
                    let bytes = Bytes::from(json_str.into_bytes());
                    if let Err(e) = dc_clone.send(&bytes).await {
                        log::error!("[WRTC] Error sending message to DataChannel: {e}");
                        break;
                    }
                }
            }
        });

        data_channel.on_message(Box::new(move |msg| {
            let tx = incoming_tx.clone();
            Box::pin(async move {
                if let Ok(colibri_msg) = serde_json::from_slice::<ColibriMessage>(&msg.data) {
                    let _ = tx.send(colibri_msg).await;
                } else if let Ok(text) = std::str::from_utf8(&msg.data) {
                    if let Ok(colibri_msg) = serde_json::from_str::<ColibriMessage>(text) {
                        let _ = tx.send(colibri_msg).await;
                    }
                }
            })
        }));

        Ok(Self {
            peer_connection,
            data_channel,
            outgoing_tx,
            incoming_rx,
        })
    }

    /// Send a ColibriMessage over the DataChannel.
    pub async fn send(&self, msg: ColibriMessage) -> anyhow::Result<()> {
        self.outgoing_tx
            .send(msg)
            .await
            .map_err(|_| anyhow::anyhow!("DataChannel write channel closed"))
    }

    /// Receive the next ColibriMessage from the DataChannel.
    pub async fn recv(&mut self) -> Option<ColibriMessage> {
        self.incoming_rx.recv().await
    }
}

use crate::wrtc::colibri::ColibriMessage;
use crate::wrtc::jingle::JingleCandidate;
use std::sync::Arc;
use tokio::sync::mpsc;
use webrtc::data_channel::{DataChannel, DataChannelEvent, RTCDataChannelInit};
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, RTCConfigurationBuilder, RTCIceCandidateInit,
    RTCIceServer,
};

pub struct WrtcPeer {
    pub peer_connection: Arc<dyn PeerConnection>,
    pub data_channel: Arc<dyn DataChannel>,
    pub outgoing_tx: mpsc::Sender<ColibriMessage>,
    pub incoming_rx: mpsc::Receiver<ColibriMessage>,
}

impl WrtcPeer {
    /// Initialize WebRTC PeerConnection, apply dynamic ICE candidates (with fallback),
    /// open "JVB data channel" with Colibri protocol, and bind message channels.
    pub async fn create(
        candidates: &[JingleCandidate],
        fallback_ip: &str,
        fallback_port: u16,
        _audio_keepalive_ms: u64,
    ) -> anyhow::Result<Self> {
        let config = RTCConfigurationBuilder::new()
            .with_ice_servers(vec![RTCIceServer {
                urls: vec![
                    "turn:dtl-talk-stun7.ktalk.host:443?transport=tcp".to_string(),
                    "stun:dtl-talk-stun7.ktalk.host:443".to_string(),
                ],
                username: String::new(),
                credential: String::new(),
            }])
            .build();

        let peer_connection: Arc<dyn PeerConnection> = Arc::new(
            PeerConnectionBuilder::<std::net::SocketAddr>::new()
                .with_configuration(config)
                .build()
                .await
                .map_err(|e| anyhow::anyhow!("PeerConnection build failed: {e}"))?,
        );

        // Open RTCDataChannel with JVB specifications
        let dc_init = RTCDataChannelInit {
            ordered: false,
            max_packet_life_time: None,
            max_retransmits: Some(0),
            protocol: "http://jitsi.org/protocols/colibri".to_string(),
            negotiated: None,
        };

        let data_channel: Arc<dyn DataChannel> = peer_connection
            .create_data_channel("JVB data channel", Some(dc_init))
            .await
            .map_err(|e| anyhow::anyhow!("create_data_channel failed: {e}"))?;

        // Apply dynamic ICE candidates, with fallback if list is empty
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
                sdp_mid: None,
                sdp_mline_index: None,
                username_fragment: None,
                url: None,
            };
            if let Err(e) = peer_connection.add_ice_candidate(init).await {
                log::debug!("[WRTC] Applying candidate failed: {e}");
            }
        }

        // Setup channels for ColibriMessage
        let (incoming_tx, incoming_rx) = mpsc::channel::<ColibriMessage>(256);
        let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<ColibriMessage>(256);

        // Outgoing sender loop
        let dc_out = Arc::clone(&data_channel);
        tokio::spawn(async move {
            while let Some(msg) = outgoing_rx.recv().await {
                if let Ok(json_str) = serde_json::to_string(&msg) {
                    if let Err(e) = dc_out.send_text(&json_str).await {
                        log::error!("[WRTC] Error sending message to DataChannel: {e}");
                        break;
                    }
                }
            }
        });

        // Incoming receiver poll loop
        let dc_in = Arc::clone(&data_channel);
        tokio::spawn(async move {
            while let Some(event) = dc_in.poll().await {
                match event {
                    DataChannelEvent::OnMessage(msg) => {
                        if let Ok(colibri_msg) = serde_json::from_slice::<ColibriMessage>(&msg.data) {
                            let _ = incoming_tx.send(colibri_msg).await;
                        } else if let Ok(text) = std::str::from_utf8(&msg.data) {
                            if let Ok(colibri_msg) = serde_json::from_str::<ColibriMessage>(text) {
                                let _ = incoming_tx.send(colibri_msg).await;
                            }
                        }
                    }
                    DataChannelEvent::OnClose => {
                        log::info!("[WRTC] DataChannel closed event received");
                        break;
                    }
                    _ => {}
                }
            }
        });

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

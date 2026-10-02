use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JingleCandidate {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub candidate_type: String,
    pub priority: u32,
    pub foundation: String,
    pub component: u16,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JingleTransportInfo {
    pub ufrag: String,
    pub pwd: String,
    pub fingerprint: Option<String>,
    pub fingerprint_hash: Option<String>,
    pub fingerprint_setup: Option<String>,
    pub candidates: Vec<JingleCandidate>,
    pub colibri_ws_url: Option<String>,
}

fn default_vp8_pt() -> u8 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JingleSession {
    pub iq_id: Option<String>,
    pub sid: String,
    pub from: String,
    pub action: String,
    pub transport: JingleTransportInfo,
    pub sources: Vec<u32>,
    #[serde(default)]
    pub video_sources: Vec<u32>,
    #[serde(default = "default_vp8_pt")]
    pub video_payload_type: u8,
    #[serde(default)]
    pub has_data_channel: bool,
    #[serde(default)]
    pub has_video: bool,
}

impl JingleSession {
    pub fn to_sdp(
        &self,
        fallback_ip: &str,
        fallback_port: u16,
        _remote_ssrc: u32,
        _video_ssrc: u32,
    ) -> String {
        let (primary_ip, primary_port) = if let Some(first) = self
            .transport
            .candidates
            .iter()
            .find(|c| c.ip != "127.0.0.1" && !c.ip.starts_with("127.") && c.ip != "0.0.0.0")
        {
            (first.ip.as_str(), first.port)
        } else {
            (fallback_ip, fallback_port)
        };

        let ufrag = if !self.transport.ufrag.is_empty() {
            &self.transport.ufrag
        } else {
            "jvb_ufrag"
        };
        let pwd = if !self.transport.pwd.is_empty() {
            &self.transport.pwd
        } else {
            "jvb_pwd_secret"
        };
        let fp_hash = self.transport.fingerprint_hash.as_deref().unwrap_or("sha-256");
        let fp = self.transport.fingerprint.as_deref().unwrap_or("00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00");
        let setup = self.transport.fingerprint_setup.as_deref().unwrap_or("actpass");

        let mut candidate_lines = String::new();
        for c in &self.transport.candidates {
            if c.ip == "127.0.0.1" || c.ip.starts_with("127.") || c.ip == "0.0.0.0" || c.ip.starts_with("172.112.") {
                continue;
            }
            let proto_lower = c.protocol.to_lowercase();
            candidate_lines.push_str(&format!(
                "a=candidate:{} {} {} {} {} {} typ {}\r\n",
                c.foundation, c.component, proto_lower, c.priority, c.ip, c.port, c.candidate_type
            ));
        }
        if candidate_lines.is_empty() {
            candidate_lines.push_str(&format!(
                "a=candidate:1 1 udp 2130706431 {} {} typ host\r\n",
                fallback_ip, fallback_port
            ));
        }

        let include_video = self.has_video;
        let mut bundle_groups = vec!["audio"];
        if include_video {
            bundle_groups.push("video");
        }
        if self.has_data_channel {
            bundle_groups.push("data");
        }
        let bundle_str = bundle_groups.join(" ");

        // ВАЖНО: Удалены жесткие a=ssrc для Remote SDP, чтобы webrtc-rs принимал любые SSRC от JVB
        let video_section = if include_video {
            let pt = self.video_payload_type;
            let alt_pt = if pt == 100 { 96 } else { 100 };
            format!(
                "m=video {primary_port} UDP/TLS/RTP/SAVPF {pt} {alt_pt}\r\n\
                 c=IN IP4 {primary_ip}\r\n\
                 a=rtcp-mux\r\n\
                 a=rtpmap:{pt} VP8/90000\r\n\
                 a=rtpmap:{alt_pt} VP8/90000\r\n\
                 a=ice-ufrag:{ufrag}\r\n\
                 a=ice-pwd:{pwd}\r\n\
                 a=fingerprint:{fp_hash} {fp}\r\n\
                 a=setup:{setup}\r\n\
                 a=mid:video\r\n\
                 a=sendrecv\r\n\
                 {candidate_lines}"
            )
        } else {
            String::new()
        };

        let data_section = if self.has_data_channel {
            format!(
                "m=application {primary_port} UDP/DTLS/SCTP webrtc-datachannel\r\n\
                 c=IN IP4 {primary_ip}\r\n\
                 a=ice-ufrag:{ufrag}\r\n\
                 a=ice-pwd:{pwd}\r\n\
                 a=fingerprint:{fp_hash} {fp}\r\n\
                 a=setup:{setup}\r\n\
                 a=mid:data\r\n\
                 a=sctp-port:5000\r\n\
                 {candidate_lines}"
            )
        } else {
            String::new()
        };

        format!(
            "v=0\r\n\
             o=- 123456789 2 IN IP4 0.0.0.0\r\n\
             s=-\r\n\
             t=0 0\r\n\
             a=ice-ufrag:{ufrag}\r\n\
             a=ice-pwd:{pwd}\r\n\
             a=fingerprint:{fp_hash} {fp}\r\n\
             a=group:BUNDLE {bundle_str}\r\n\
             m=audio {primary_port} UDP/TLS/RTP/SAVPF 111\r\n\
             c=IN IP4 {primary_ip}\r\n\
             a=rtcp-mux\r\n\
             a=rtpmap:111 opus/48000/2\r\n\
             a=ice-ufrag:{ufrag}\r\n\
             a=ice-pwd:{pwd}\r\n\
             a=fingerprint:{fp_hash} {fp}\r\n\
             a=setup:{setup}\r\n\
             a=mid:audio\r\n\
             a=sendrecv\r\n\
             {candidate_lines}\
             {video_section}\
             {data_section}"
        )
    }
}

pub fn parse_jingle_session(
    xml: &str,
    fallback_ip: &str,
    fallback_port: u16,
) -> Option<JingleSession> {
    for stanza in crate::wrtc::xmpp_xml::parse_xmpp_stanzas(xml, fallback_ip, fallback_port) {
        if let crate::wrtc::xmpp_xml::InboundXmpp::Jingle(session) = stanza {
            return Some(session);
        }
    }
    None
}

#[derive(Debug, Clone, Default)]
pub struct LocalJingleParams {
    pub ufrag: String,
    pub pwd: String,
    pub fingerprint: String,
    pub fingerprint_hash: String,
    pub candidates: Vec<String>,
}

pub fn parse_sdp_answer(sdp: &str) -> LocalJingleParams {
    let mut ufrag = String::new();
    let mut pwd = String::new();
    let mut fingerprint = String::new();
    let mut fingerprint_hash = "sha-256".to_string();
    let mut candidates = Vec::new();

    for line in sdp.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("a=ice-ufrag:") {
            ufrag = rest.to_string();
        } else if let Some(rest) = line.strip_prefix("a=ice-pwd:") {
            pwd = rest.to_string();
        } else if let Some(rest) = line.strip_prefix("a=fingerprint:") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() >= 2 {
                fingerprint_hash = parts[0].to_string();
                fingerprint = parts[1].to_string();
            }
        } else if let Some(rest) = line.strip_prefix("a=candidate:") {
            candidates.push(rest.to_string());
        }
    }

    LocalJingleParams {
        ufrag,
        pwd,
        fingerprint,
        fingerprint_hash,
        candidates,
    }
}

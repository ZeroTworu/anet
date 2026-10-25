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

        let include_video = self.has_video || _video_ssrc != 0;
        let mut bundle_groups = vec!["audio"];
        if include_video {
            bundle_groups.push("video");
        }
        if self.has_data_channel {
            bundle_groups.push("data");
        }
        let bundle_str = bundle_groups.join(" ");

        let remote_audio_ssrc = self.sources.first().copied().unwrap_or(10001);
        let primary_video_ssrc = 10002u32;

        let video_section = if include_video {
            let pt = self.video_payload_type;
            let alt_pt = if pt == 100 { 96 } else { 100 };
            format!(
                "m=video {primary_port} UDP/TLS/RTP/SAVPF {pt} {alt_pt}\r\n\
                 c=IN IP4 {primary_ip}\r\n\
                 a=rtcp-mux\r\n\
                 a=rtpmap:{pt} VP8/90000\r\n\
                 a=rtpmap:{alt_pt} VP8/90000\r\n\
                 a=rtcp-fb:{pt} goog-remb\r\n\
                 a=rtcp-fb:{pt} ccm fir\r\n\
                 a=rtcp-fb:{pt} nack\r\n\
                 a=rtcp-fb:{pt} nack pli\r\n\
                 a=rtcp-fb:{alt_pt} goog-remb\r\n\
                 a=rtcp-fb:{alt_pt} ccm fir\r\n\
                 a=rtcp-fb:{alt_pt} nack\r\n\
                 a=rtcp-fb:{alt_pt} nack pli\r\n\
                 a=ice-ufrag:{ufrag}\r\n\
                 a=ice-pwd:{pwd}\r\n\
                 a=fingerprint:{fp_hash} {fp}\r\n\
                 a=setup:{setup}\r\n\
                 a=mid:video\r\n\
                 a=sendrecv\r\n\
                 a=ssrc:{primary_video_ssrc} cname:jvb-video\r\n\
                 a=ssrc:{primary_video_ssrc} msid:jvb-vstream-{primary_video_ssrc} jvb-vtrack-{primary_video_ssrc}\r\n\
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

        let sdp = format!(
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
             a=ssrc:{remote_audio_ssrc} cname:jvb-audio\r\n\
             a=ssrc:{remote_audio_ssrc} msid:jvb-astream jvb-atrack0\r\n\
             {candidate_lines}\
             {video_section}\
             {data_section}"
        );

        sdp
    }
}

/// Appends a dedicated `m=video` (`a=mid:v_<ssrc>`, `a=sendonly`) section to the remote SDP
/// so `rtc-0.21.0` creates a dedicated `Recvonly` transceiver and `TrackRemote` for `new_ssrc`
/// without overwriting any existing active video transceiver.
pub fn append_remote_video_ssrc_to_sdp(current_sdp: &str, new_ssrc: u32, video_pt: u8) -> String {
    let mid_tag = format!("v_{new_ssrc}");
    if current_sdp.contains(&format!("a=mid:{mid_tag}\r\n"))
        || current_sdp.contains(&format!("a=ssrc:{new_ssrc} "))
    {
        return current_sdp.to_string();
    }

    let mut primary_port = "9";
    let mut c_line = "c=IN IP4 0.0.0.0";
    let mut ufrag = "jvb_ufrag";
    let mut pwd = "jvb_pwd_secret";
    let mut fingerprint = "sha-256 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00";
    let mut setup = "actpass";
    let mut candidate_lines = String::new();
    let mut in_first_media = false;
    let mut past_first_media = false;

    for raw_line in current_sdp.lines() {
        let line = raw_line.trim();
        if line.starts_with("m=") {
            if !in_first_media && !past_first_media {
                in_first_media = true;
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    primary_port = parts[1];
                }
            } else if in_first_media {
                in_first_media = false;
                past_first_media = true;
            }
        } else if line.starts_with("c=IN IP4 ") {
            c_line = line;
        } else if let Some(u) = line.strip_prefix("a=ice-ufrag:") {
            ufrag = u;
        } else if let Some(p) = line.strip_prefix("a=ice-pwd:") {
            pwd = p;
        } else if let Some(fp) = line.strip_prefix("a=fingerprint:") {
            fingerprint = fp;
        } else if let Some(s) = line.strip_prefix("a=setup:") {
            setup = s;
        } else if in_first_media && line.starts_with("a=candidate:") {
            candidate_lines.push_str(line);
            candidate_lines.push_str("\r\n");
        }
    }

    let pt = if video_pt != 0 { video_pt } else { 100 };
    let alt_pt = if pt == 100 { 96 } else { 100 };

    let mut updated = String::with_capacity(current_sdp.len() + 640);
    for raw_line in current_sdp.lines() {
        let line = raw_line.trim_end_matches('\r');
        if let Some(bundle_rest) = line.strip_prefix("a=group:BUNDLE ") {
            updated.push_str(&format!("a=group:BUNDLE {bundle_rest} {mid_tag}\r\n"));
        } else {
            updated.push_str(line);
            updated.push_str("\r\n");
        }
    }

    updated.push_str(&format!(
        "m=video {primary_port} UDP/TLS/RTP/SAVPF {pt} {alt_pt}\r\n\
         {c_line}\r\n\
         a=rtcp-mux\r\n\
         a=rtpmap:{pt} VP8/90000\r\n\
         a=rtpmap:{alt_pt} VP8/90000\r\n\
         a=rtcp-fb:{pt} goog-remb\r\n\
         a=rtcp-fb:{pt} ccm fir\r\n\
         a=rtcp-fb:{pt} nack\r\n\
         a=rtcp-fb:{pt} nack pli\r\n\
         a=rtcp-fb:{alt_pt} goog-remb\r\n\
         a=rtcp-fb:{alt_pt} ccm fir\r\n\
         a=rtcp-fb:{alt_pt} nack\r\n\
         a=rtcp-fb:{alt_pt} nack pli\r\n\
         a=ice-ufrag:{ufrag}\r\n\
         a=ice-pwd:{pwd}\r\n\
         a=fingerprint:{fingerprint}\r\n\
         a=setup:{setup}\r\n\
         a=mid:{mid_tag}\r\n\
         a=sendonly\r\n\
         a=ssrc:{new_ssrc} cname:jvb-video-{new_ssrc}\r\n\
         a=ssrc:{new_ssrc} msid:jvb-vstream-{new_ssrc} jvb-vtrack-{new_ssrc}\r\n\
         {candidate_lines}"
    ));

    updated
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

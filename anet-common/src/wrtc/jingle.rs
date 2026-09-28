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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JingleSession {
    pub iq_id: Option<String>,
    pub sid: String,
    pub from: String,
    pub action: String,
    pub transport: JingleTransportInfo,
    pub sources: Vec<u32>,
}

impl JingleSession {
    pub fn to_sdp(&self, fallback_ip: &str, fallback_port: u16, remote_ssrc: u32) -> String {
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
            if c.ip == "127.0.0.1" || c.ip.starts_with("127.") || c.ip == "0.0.0.0" {
                continue;
            }
            let proto_upper = c.protocol.to_uppercase();
            candidate_lines.push_str(&format!(
                "a=candidate:{} {} {} {} {} {} typ {}\r\n",
                c.foundation, c.component, proto_upper, c.priority, c.ip, c.port, c.candidate_type
            ));
        }
        if candidate_lines.is_empty() {
            candidate_lines.push_str(&format!(
                "a=candidate:1 1 UDP 2130706431 {} {} typ host\r\n",
                fallback_ip, fallback_port
            ));
        }
        let mut ssrc_lines = String::new();
        if remote_ssrc != 0 {
            ssrc_lines.push_str(&format!(
                "a=ssrc:{remote_ssrc} cname:cname_{remote_ssrc:x}\r\n\
                 a=ssrc:{remote_ssrc} msid:msid_{remote_ssrc:x} a0\r\n"
            ));
        }
        for ssrc in &self.sources {
            if *ssrc != remote_ssrc && *ssrc != 0 {
                ssrc_lines.push_str(&format!(
                    "a=ssrc:{ssrc} cname:cname_{ssrc:x}\r\n\
                     a=ssrc:{ssrc} msid:msid_{ssrc:x} a0\r\n"
                ));
            }
        }

        // Формируем BUNDLE аудио (Opus) + WebRTC DataChannel (SCTP)
        format!(
            "v=0\r\n\
             o=- 123456789 2 IN IP4 0.0.0.0\r\n\
             s=-\r\n\
             t=0 0\r\n\
             a=ice-lite\r\n\
             a=group:BUNDLE audio data\r\n\
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
             {ssrc_lines}\
             {candidate_lines}\
             m=application {primary_port} UDP/DTLS/SCTP webrtc-datachannel\r\n\
             c=IN IP4 {primary_ip}\r\n\
             a=ice-ufrag:{ufrag}\r\n\
             a=ice-pwd:{pwd}\r\n\
             a=fingerprint:{fp_hash} {fp}\r\n\
             a=setup:{setup}\r\n\
             a=mid:data\r\n\
             a=sctp-port:5000\r\n\
             {candidate_lines}"
        )
    }}

pub fn parse_jingle_session(
    xml: &str,
    fallback_ip: &str,
    fallback_port: u16,
) -> Option<JingleSession> {
    if !xml.contains("urn:xmpp:jingle:1") {
        return None;
    }

    let iq_id = extract_attr(xml, "id");
    let sid = extract_attr(xml, "sid")?;
    let action = extract_attr(xml, "action")?;
    let from = extract_attr(xml, "from").unwrap_or_default();

    let ufrag = extract_attr(xml, "ufrag").unwrap_or_else(|| "jvb_ufrag".to_string());
    let pwd = extract_attr(xml, "pwd").unwrap_or_else(|| "jvb_pwd".to_string());

    let fingerprint = extract_tag_content(xml, "fingerprint");
    let fingerprint_hash = extract_attr(xml, "hash");
    let fingerprint_setup = extract_attr(xml, "setup");

    let colibri_ws_url = if let Some(ws_start) = xml.find("<web-socket") {
        extract_attr(&xml[ws_start..], "url")
    } else {
        None
    };

    let mut candidates = Vec::new();
    let mut search_from = 0;
    while let Some(c_start) = xml[search_from..].find("<candidate") {
        let actual_start = search_from + c_start;
        if let Some(c_end) = xml[actual_start..].find("/>") {
            let candidate_str = &xml[actual_start..actual_start + c_end + 2];
            if let (Some(ip), Some(port_str)) = (
                extract_attr(candidate_str, "ip"),
                extract_attr(candidate_str, "port"),
            ) {
                if let Ok(port) = port_str.parse::<u16>() {
                    // Игнорируем loopback-кандидаты JVB (127.0.0.1, 0.0.0.0 и т.д.), которые ломают ICE
                    if ip == "127.0.0.1" || ip.starts_with("127.") || ip == "0.0.0.0" {
                        search_from = actual_start + c_end + 2;
                        continue;
                    }

                    let protocol = extract_attr(candidate_str, "protocol")
                        .unwrap_or_else(|| "udp".to_string());
                    let candidate_type = extract_attr(candidate_str, "type")
                        .unwrap_or_else(|| "host".to_string());
                    let priority = extract_attr(candidate_str, "priority")
                        .and_then(|p| p.parse::<u32>().ok())
                        .unwrap_or(2130706431);
                    let foundation = extract_attr(candidate_str, "foundation")
                        .unwrap_or_else(|| "1".to_string());
                    let component = extract_attr(candidate_str, "component")
                        .and_then(|c| c.parse::<u16>().ok())
                        .unwrap_or(1);

                    candidates.push(JingleCandidate {
                        ip,
                        port,
                        protocol,
                        candidate_type,
                        priority,
                        foundation,
                        component,
                    });
                }
            }
            search_from = actual_start + c_end + 2;
        } else {
            break;
        }
    }

    if candidates.is_empty() {
        candidates.push(JingleCandidate {
            ip: fallback_ip.to_string(),
            port: fallback_port,
            protocol: "udp".to_string(),
            candidate_type: "host".to_string(),
            priority: 2130706431,
            foundation: "1".to_string(),
            component: 1,
        });
    }

    let mut sources = Vec::new();
    let mut search_from = 0;
    while let Some(s_start) = xml[search_from..].find("<source") {
        let actual_start = search_from + s_start;
        if let Some(s_end) = xml[actual_start..].find('>') {
            let source_str = &xml[actual_start..actual_start + s_end + 1];
            if let Some(ssrc_str) = extract_attr(source_str, "ssrc") {
                if let Ok(ssrc) = ssrc_str.parse::<u32>() {
                    sources.push(ssrc);
                }
            }
            search_from = actual_start + s_end + 1;
        } else {
            break;
        }
    }

    Some(JingleSession {
        iq_id,
        sid,
        from,
        action,
        transport: JingleTransportInfo {
            ufrag,
            pwd,
            fingerprint,
            fingerprint_hash,
            fingerprint_setup,
            candidates,
            colibri_ws_url,
        },
        sources,
    })
}

fn extract_attr(text: &str, attr_name: &str) -> Option<String> {
    let pattern = format!("{attr_name}=\"");
    let start = text.find(&pattern)? + pattern.len();
    let end = text[start..].find('"')? + start;
    Some(text[start..end].to_string())
}

fn extract_tag_content(text: &str, tag_name: &str) -> Option<String> {
    let open_tag = format!("<{tag_name}");
    let close_tag = format!("</{tag_name}>");
    let start_open = text.find(&open_tag)?;
    let end_open = text[start_open..].find('>')? + start_open + 1;
    let end_close = text[end_open..].find(&close_tag)? + end_open;
    Some(text[end_open..end_close].trim().to_string())
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

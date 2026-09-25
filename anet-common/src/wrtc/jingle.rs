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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JingleSession {
    pub sid: String,
    pub from: String,
    pub action: String,
    pub transport: JingleTransportInfo,
}

/// Parses Jingle session from XMPP XML stanza.
pub fn parse_jingle_session(
    xml: &str,
    fallback_ip: &str,
    fallback_port: u16,
) -> Option<JingleSession> {
    if !xml.contains("urn:xmpp:jingle:1") {
        return None;
    }

    let sid = extract_attr(xml, "sid")?;
    let action = extract_attr(xml, "action")?;
    let from = extract_attr(xml, "from").unwrap_or_default();

    let ufrag = extract_attr(xml, "ufrag").unwrap_or_else(|| "jvb_ufrag".to_string());
    let pwd = extract_attr(xml, "pwd").unwrap_or_else(|| "jvb_pwd".to_string());

    let fingerprint = extract_tag_content(xml, "fingerprint");
    let fingerprint_hash = extract_attr(xml, "hash");
    let fingerprint_setup = extract_attr(xml, "setup");

    // Dynamic ICE candidate parsing from XML
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

    // Dynamic fallback: if remote server returned no candidates, use fallback values
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

    Some(JingleSession {
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
        },
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

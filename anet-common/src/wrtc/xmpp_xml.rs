use crate::wrtc::jingle::{JingleCandidate, JingleSession, JingleTransportInfo};

pub fn escape_xml_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

#[derive(Debug, Clone)]
pub enum InboundXmpp {
    Open,
    SaslMechanisms,
    SaslSuccess,
    SaslFailure(String),
    Features { has_bind: bool },
    BindResult { id: String, jid: String },
    Presence {
        from: String,
        is_unavailable: bool,
        is_self_110: bool,
    },
    Ping { id: String, from: String },
    DiscoInfo {
        id: String,
        from: String,
        node: Option<String>,
    },
    JingleAck { id: String, from: String },
    Jingle(JingleSession),
    ExtdiscoServices(Vec<String>),
    Other,
}

/// Разбирает XML фрейм, который может содержать одну или несколько станз (например, `<open/><features>`).
pub fn parse_xmpp_stanzas(
    xml: &str,
    fallback_ip: &str,
    fallback_port: u16,
) -> Vec<InboundXmpp> {
    let trimmed = xml.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    // Оборачиваем в искусственный корневой элемент <stream>,
    // чтобы roxmltree корректно разбирал фрагменты с несколькими станзами в одном фрейме
    let wrapped = format!("<stream>{trimmed}</stream>");
    let doc = match roxmltree::Document::parse(&wrapped) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };

    let mut stanzas = Vec::new();
    for node in doc.root_element().children().filter(|n| n.is_element()) {
        if let Some(stanza) = parse_single_element(&node, fallback_ip, fallback_port) {
            stanzas.push(stanza);
        }
    }
    stanzas
}

pub fn parse_xmpp_message(
    xml: &str,
    fallback_ip: &str,
    fallback_port: u16,
) -> Option<InboundXmpp> {
    parse_xmpp_stanzas(xml, fallback_ip, fallback_port).into_iter().next()
}

/// Верхнеуровневые XML-теги протокола XMPP (RFC 6120 / RFC 7395).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmppElementTag {
    Open,
    Close,
    Features,
    Mechanisms,
    Success,
    Failure,
    Presence,
    Iq,
    Message,
    Other,
}

impl<'a> From<&'a str> for XmppElementTag {
    fn from(name: &'a str) -> Self {
        match name {
            "open" => Self::Open,
            "close" => Self::Close,
            "features" => Self::Features,
            "mechanisms" => Self::Mechanisms,
            "success" => Self::Success,
            "failure" => Self::Failure,
            "presence" => Self::Presence,
            "iq" => Self::Iq,
            "message" => Self::Message,
            _ => Self::Other,
        }
    }
}

/// Типы станзы IQ в XMPP (RFC 6120 §8.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IqType {
    Get,
    Set,
    Result,
    Error,
    Other,
}

impl<'a> From<&'a str> for IqType {
    fn from(s: &'a str) -> Self {
        match s {
            "get" => Self::Get,
            "set" => Self::Set,
            "result" => Self::Result,
            "error" => Self::Error,
            _ => Self::Other,
        }
    }
}

fn parse_single_element(
    root: &roxmltree::Node,
    fallback_ip: &str,
    fallback_port: u16,
) -> Option<InboundXmpp> {
    let tag = XmppElementTag::from(root.tag_name().name());

    match tag {
        XmppElementTag::Open => Some(InboundXmpp::Open),
        XmppElementTag::Mechanisms => Some(InboundXmpp::SaslMechanisms),
        XmppElementTag::Features => {
            // В XMPP mechanisms приходят внутри <features><mechanisms>...</mechanisms></features>!
            if root.descendants().any(|n| n.has_tag_name("mechanisms")) {
                Some(InboundXmpp::SaslMechanisms)
            } else {
                let has_bind = root.descendants().any(|n| n.has_tag_name("bind"));
                Some(InboundXmpp::Features { has_bind })
            }
        }
        XmppElementTag::Success => Some(InboundXmpp::SaslSuccess),
        XmppElementTag::Failure => {
            Some(InboundXmpp::SaslFailure("SASL authentication failed".to_string()))
        }
        XmppElementTag::Presence => {
            let from = root.attribute("from").unwrap_or_default().to_string();
            let p_type = root.attribute("type").unwrap_or_default();
            let is_unavailable = p_type == "unavailable";
            let is_self_110 = root.descendants().any(|n| {
                n.has_tag_name("status") && n.attribute("code") == Some("110")
            });
            Some(InboundXmpp::Presence {
                from,
                is_unavailable,
                is_self_110,
            })
        }
        XmppElementTag::Iq => {
            let iq_id = root.attribute("id").unwrap_or_default().to_string();
            let from = root.attribute("from").unwrap_or_default().to_string();
            let iq_type = IqType::from(root.attribute("type").unwrap_or_default());

            // 1. Проверяем bind result:
            if let Some(bind_node) = root.descendants().find(|n| n.has_tag_name("bind")) {
                if let Some(jid_node) = bind_node.descendants().find(|n| n.has_tag_name("jid")) {
                    if let Some(jid) = jid_node.text() {
                        return Some(InboundXmpp::BindResult {
                            id: iq_id,
                            jid: jid.to_string(),
                        });
                    }
                }
            }

            // 2. Проверяем ping get:
            if iq_type == IqType::Get && root.descendants().any(|n| n.has_tag_name("ping")) {
                return Some(InboundXmpp::Ping { id: iq_id, from });
            }

            // 3. Проверяем disco#info get:
            if iq_type == IqType::Get {
                if let Some(query_node) = root.descendants().find(|n| n.has_tag_name("query")) {
                    let node = query_node.attribute("node").map(|s| s.to_string());
                    return Some(InboundXmpp::DiscoInfo {
                        id: iq_id,
                        from,
                        node,
                    });
                }
            }

            // 4. Проверяем Jingle:
            if let Some(jingle_node) = root.descendants().find(|n| n.has_tag_name("jingle")) {
                if let Some(session) =
                    parse_jingle_node(root, &jingle_node, fallback_ip, fallback_port)
                {
                    return Some(InboundXmpp::Jingle(session));
                }
            }

            // 5. Проверяем extdisco (XEP-0215 services):
            if let Some(services_node) = root.descendants().find(|n| n.has_tag_name("services")) {
                let mut stuns = Vec::new();
                for svc in services_node.children().filter(|n| n.has_tag_name("service")) {
                    if svc.attribute("type") == Some("stun") {
                        if let (Some(host), Some(port)) =
                            (svc.attribute("host"), svc.attribute("port"))
                        {
                            stuns.push(format!("stun:{host}:{port}"));
                        }
                    }
                }
                if !stuns.is_empty() {
                    return Some(InboundXmpp::ExtdiscoServices(stuns));
                }
            }

            // 6. Проверяем Jingle ACK result:
            if iq_type == IqType::Result {
                return Some(InboundXmpp::JingleAck { id: iq_id, from });
            }

            Some(InboundXmpp::Other)
        }
        XmppElementTag::Close | XmppElementTag::Message | XmppElementTag::Other => {
            Some(InboundXmpp::Other)
        }
    }
}

pub fn parse_jingle_node(
    iq_node: &roxmltree::Node,
    jingle_node: &roxmltree::Node,
    fallback_ip: &str,
    fallback_port: u16,
) -> Option<JingleSession> {
    let sid = jingle_node.attribute("sid")?.to_string();
    let action = jingle_node.attribute("action")?.to_string();
    let iq_id = iq_node.attribute("id").map(|s| s.to_string());
    let from = iq_node.attribute("from").unwrap_or_default().to_string();

    let mut transport_info = JingleTransportInfo::default();
    let mut sources = Vec::new();
    let mut has_data_channel = false;
    let mut has_video = false;

    for content in jingle_node.children().filter(|n| n.has_tag_name("content")) {
        if content.attribute("name") == Some("data") {
            has_data_channel = true;
        }
        if content.attribute("name") == Some("video") {
            has_video = true;
        }

        for desc in content.children().filter(|n| n.has_tag_name("description")) {
            for src in desc.children().filter(|n| n.has_tag_name("source")) {
                if let Some(ssrc_str) = src.attribute("ssrc") {
                    if let Ok(ssrc) = ssrc_str.parse::<u32>() {
                        sources.push(ssrc);
                    }
                }
            }
        }

        for transport in content.children().filter(|n| n.has_tag_name("transport")) {
            if let Some(ufrag) = transport.attribute("ufrag") {
                transport_info.ufrag = ufrag.to_string();
            }
            if let Some(pwd) = transport.attribute("pwd") {
                transport_info.pwd = pwd.to_string();
            }

            for child in transport.children() {
                if child.has_tag_name("fingerprint") {
                    transport_info.fingerprint = child.text().map(|s| s.trim().to_string());
                    transport_info.fingerprint_hash =
                        child.attribute("hash").map(|s| s.to_string());
                    transport_info.fingerprint_setup =
                        child.attribute("setup").map(|s| s.to_string());
                } else if child.has_tag_name("web-socket") {
                    transport_info.colibri_ws_url =
                        child.attribute("url").map(|s| s.to_string());
                } else if child.has_tag_name("candidate") {
                    if let (Some(ip), Some(port_str)) =
                        (child.attribute("ip"), child.attribute("port"))
                    {
                        if ip == "127.0.0.1" || ip.starts_with("127.") || ip == "0.0.0.0" {
                            continue;
                        }
                        if let Ok(port) = port_str.parse::<u16>() {
                            let protocol =
                                child.attribute("protocol").unwrap_or("udp").to_string();
                            let candidate_type =
                                child.attribute("type").unwrap_or("host").to_string();
                            let priority = child
                                .attribute("priority")
                                .and_then(|p| p.parse().ok())
                                .unwrap_or(2130706431);
                            let foundation =
                                child.attribute("foundation").unwrap_or("1").to_string();
                            let component = child
                                .attribute("component")
                                .and_then(|c| c.parse().ok())
                                .unwrap_or(1);
                            transport_info.candidates.push(JingleCandidate {
                                ip: ip.to_string(),
                                port,
                                protocol,
                                candidate_type,
                                priority,
                                foundation,
                                component,
                            });
                        }
                    }
                }
            }
        }
    }

    if transport_info.candidates.is_empty() {
        transport_info.candidates.push(JingleCandidate {
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
        iq_id,
        sid,
        from,
        action,
        transport: transport_info,
        sources,
        has_data_channel,
        has_video,
    })
}

pub struct XmppBuilder;

impl XmppBuilder {
    pub fn open() -> &'static str {
        r#"<open to="meet.jitsi" version="1.0" xmlns="urn:ietf:params:xml:ns:xmpp-framing"/>"#
    }

    pub fn auth_anonymous() -> &'static str {
        r#"<auth mechanism="ANONYMOUS" xmlns="urn:ietf:params:xml:ns:xmpp-sasl"/>"#
    }

    pub fn bind_resource(id: &str) -> String {
        format!(
            r#"<iq type="set" id="{}"><bind xmlns="urn:ietf:params:xml:ns:xmpp-bind"/></iq>"#,
            escape_xml_attr(id)
        )
    }

    pub fn muc_presence(
        conference_id: &str,
        endpoint_id: &str,
        client_name: &str,
    ) -> String {
        let conf_esc = escape_xml_attr(conference_id);
        let ep_esc = escape_xml_attr(endpoint_id);
        let name_esc = escape_xml_attr(client_name);
        format!(
            r#"<presence to="{conf_esc}@muc.meet.jitsi/{ep_esc}"><x xmlns="http://jabber.org/protocol/muc"/><nick xmlns="http://jabber.org/protocol/nick">{name_esc}</nick><c xmlns="http://jabber.org/protocol/caps" hash="sha-1" node="https://jitsi.org/jitsi-meet" ver="7Y4Yx3m5c03c5188efb8b2ebda41e8c072e912da"/><jitsi_participant_id>{ep_esc}</jitsi_participant_id></presence>"#
        )
    }

    pub fn iq_result(to: &str, id: &str) -> String {
        format!(
            r#"<iq type="result" to="{}" id="{}"/>"#,
            escape_xml_attr(to),
            escape_xml_attr(id)
        )
    }

    pub fn disco_info_result(to: &str, id: &str, node: Option<&str>) -> String {
        let node_attr = match node {
            Some(n) if !n.is_empty() => format!(r#" node="{}""#, escape_xml_attr(n)),
            _ => String::new(),
        };
        format!(
            r#"<iq type="result" to="{to}" id="{id}"><query xmlns="http://jabber.org/protocol/disco#info"{node_attr}><identity category="client" type="web" name="jitsi-meet"/><feature var="urn:xmpp:jingle:1"/><feature var="urn:xmpp:jingle:apps:rtp:1"/><feature var="urn:xmpp:jingle:apps:rtp:audio"/><feature var="urn:xmpp:jingle:apps:rtp:video"/><feature var="urn:xmpp:jingle:apps:dtls:0"/><feature var="urn:xmpp:jingle:apps:sctp:1"/><feature var="http://jitsi.org/protocols/sctp"/><feature var="urn:xmpp:jingle:transports:ice-udp:1"/><feature var="http://jitsi.org/protocols/colibri"/><feature var="urn:ietf:rfc:5761"/><feature var="urn:ietf:rfc:5888"/><feature var="http://jabber.org/protocol/caps"/></query></iq>"#,
            to = escape_xml_attr(to),
            id = escape_xml_attr(id),
            node_attr = node_attr
        )
    }

    pub fn conference_allocation(
        conference_id: &str,
        endpoint_id: &str,
        iq_id: &str,
    ) -> String {
        let conf_room = format!("{}@muc.meet.jitsi", escape_xml_attr(conference_id));
        let ep_esc = escape_xml_attr(endpoint_id);
        let id_esc = escape_xml_attr(iq_id);
        format!(
            r#"<iq to="focus.meet.jitsi" type="set" id="{id_esc}"><conference xmlns="http://jitsi.org/protocol/focus" room="{conf_room}" machine-uid="{ep_esc}"/></iq>"#
        )
    }

    pub fn jingle_session_accept(
        focus_jid: &str,
        req_id: &str,
        my_jid: &str,
        sid: &str,
        ssrc: u32,
        video_ssrc: u32,
        cname: &str,
        msid: &str,
        ufrag: &str,
        pwd: &str,
        fingerprint_hash: &str,
        fingerprint: &str,
        candidate_xml: &str,
        include_data_content: bool,
        include_video_content: bool,
    ) -> String {
        let video_section = if include_video_content && video_ssrc != 0 {
            format!(
                r#"<content creator="initiator" name="video" senders="both"><description xmlns="urn:xmpp:jingle:apps:rtp:1" media="video"><payload-type id="96" name="VP8" clockrate="90000"/><rtcp-mux/><source xmlns="urn:xmpp:jingle:apps:rtp:ssma:0" ssrc="{video_ssrc}"><parameter xmlns="urn:xmpp:jingle:apps:rtp:1" name="cname" value="{cname}"/><parameter xmlns="urn:xmpp:jingle:apps:rtp:1" name="msid" value="{msid} v0"/></source></description><transport xmlns="urn:xmpp:jingle:transports:ice-udp:1" ufrag="{ufrag}" pwd="{pwd}"><rtcp-mux/><fingerprint xmlns="urn:xmpp:jingle:apps:dtls:0" hash="{fingerprint_hash}" setup="active">{fingerprint}</fingerprint>{candidate_xml}</transport></content>"#,
                ufrag = escape_xml_attr(ufrag),
                pwd = escape_xml_attr(pwd),
                fingerprint_hash = escape_xml_attr(fingerprint_hash),
                fingerprint = escape_xml_attr(fingerprint),
                candidate_xml = candidate_xml,
                video_ssrc = video_ssrc,
                cname = escape_xml_attr(cname),
                msid = escape_xml_attr(msid),
            )
        } else {
            String::new()
        };

        let data_section = if include_data_content {
            format!(
                r#"<content creator="initiator" name="data"><description xmlns="urn:xmpp:jingle:apps:sctp:1"><payload-type id="5000"/></description><transport xmlns="urn:xmpp:jingle:transports:ice-udp:1" ufrag="{ufrag}" pwd="{pwd}"><fingerprint xmlns="urn:xmpp:jingle:apps:dtls:0" hash="{fingerprint_hash}" setup="active">{fingerprint}</fingerprint>{candidate_xml}</transport></content>"#,
                ufrag = escape_xml_attr(ufrag),
                pwd = escape_xml_attr(pwd),
                fingerprint_hash = escape_xml_attr(fingerprint_hash),
                fingerprint = escape_xml_attr(fingerprint),
                candidate_xml = candidate_xml
            )
        } else {
            String::new()
        };

        format!(
            r#"<iq to="{to}" type="set" id="{id}"><jingle xmlns="urn:xmpp:jingle:1" action="session-accept" initiator="{init}" responder="{resp}" sid="{sid}"><content creator="initiator" name="audio" senders="both"><description xmlns="urn:xmpp:jingle:apps:rtp:1" media="audio"><payload-type id="111" name="opus" clockrate="48000" channels="2"/><rtcp-mux/><source xmlns="urn:xmpp:jingle:apps:rtp:ssma:0" ssrc="{ssrc}"><parameter xmlns="urn:xmpp:jingle:apps:rtp:1" name="cname" value="{cname}"/><parameter xmlns="urn:xmpp:jingle:apps:rtp:1" name="msid" value="{msid} a0"/></source></description><transport xmlns="urn:xmpp:jingle:transports:ice-udp:1" ufrag="{ufrag}" pwd="{pwd}"><rtcp-mux/><fingerprint xmlns="urn:xmpp:jingle:apps:dtls:0" hash="{fp_hash}" setup="active">{fp}</fingerprint>{candidate_xml}</transport></content>{video_section}{data_section}</jingle></iq>"#,
            to = escape_xml_attr(focus_jid),
            id = escape_xml_attr(req_id),
            init = escape_xml_attr(focus_jid),
            resp = escape_xml_attr(my_jid),
            sid = escape_xml_attr(sid),
            ssrc = ssrc,
            cname = escape_xml_attr(cname),
            msid = escape_xml_attr(msid),
            ufrag = escape_xml_attr(ufrag),
            pwd = escape_xml_attr(pwd),
            fp_hash = escape_xml_attr(fingerprint_hash),
            fp = escape_xml_attr(fingerprint),
            candidate_xml = candidate_xml,
            video_section = video_section,
            data_section = data_section
        )
    }

    pub fn jingle_source_add(
        focus_jid: &str,
        req_id: &str,
        sid: &str,
        ssrc: u32,
        cname: &str,
        msid: &str,
    ) -> String {
        format!(
            r#"<iq to="{to}" type="set" id="{id}"><jingle xmlns="urn:xmpp:jingle:1" action="source-add" initiator="{init}" sid="{sid}"><content name="audio"><description xmlns="urn:xmpp:jingle:apps:rtp:1" media="audio"><source xmlns="urn:xmpp:jingle:apps:rtp:ssma:0" ssrc="{ssrc}"><parameter name="cname" value="{cname}"/><parameter name="msid" value="{msid} a0"/></source></description></content></jingle></iq>"#,
            to = escape_xml_attr(focus_jid),
            id = escape_xml_attr(req_id),
            init = escape_xml_attr(focus_jid),
            sid = escape_xml_attr(sid),
            ssrc = ssrc,
            cname = escape_xml_attr(cname),
            msid = escape_xml_attr(msid)
        )
    }

    pub fn ping(to: &str, id: &str) -> String {
        format!(
            r#"<iq to="{}" type="get" id="{}"><ping xmlns="urn:xmpp:ping"/></iq>"#,
            escape_xml_attr(to),
            escape_xml_attr(id)
        )
    }

    pub fn extdisco_services(id: &str) -> String {
        format!(
            r#"<iq to="meet.jitsi" type="get" id="{}"><services xmlns="urn:xmpp:extdisco:2"/></iq>"#,
            escape_xml_attr(id)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_xml_attr() {
        assert_eq!(escape_xml_attr("Hello & <World> \"'"), "Hello &amp; &lt;World&gt; &quot;&apos;");
    }

    #[test]
    fn test_parse_open_and_sasl() {
        // Тест на склейку двух станз в одном WebSocket фрейме (как шлет Prosody по RFC 7395):
        let multi_xml = r#"<open xmlns="urn:ietf:params:xml:ns:xmpp-framing" to="meet.jitsi" version="1.0"/><features xmlns="http://etherx.jabber.org/streams"><mechanisms xmlns="urn:ietf:params:xml:ns:xmpp-sasl"><mechanism>ANONYMOUS</mechanism></mechanisms></features>"#;
        let stanzas = parse_xmpp_stanzas(multi_xml, "127.0.0.1", 10000);
        assert_eq!(stanzas.len(), 2);
        assert!(matches!(stanzas[0], InboundXmpp::Open));
        assert!(matches!(stanzas[1], InboundXmpp::SaslMechanisms));
    }

    #[test]
    fn test_parse_features_and_bind() {
        let feat = r#"<features xmlns="http://etherx.jabber.org/streams"><bind xmlns="urn:ietf:params:xml:ns:xmpp-bind"/></features>"#;
        match parse_xmpp_message(feat, "127.0.0.1", 10000) {
            Some(InboundXmpp::Features { has_bind }) => assert!(has_bind),
            other => panic!("Unexpected: {:?}", other),
        }

        let bind_res = r#"<iq id="_bind_auth_2" type="result"><bind xmlns="urn:ietf:params:xml:ns:xmpp-bind"><jid>testuser@meet.jitsi/xyz</jid></bind></iq>"#;
        match parse_xmpp_message(bind_res, "127.0.0.1", 10000) {
            Some(InboundXmpp::BindResult { id, jid }) => {
                assert_eq!(id, "_bind_auth_2");
                assert_eq!(jid, "testuser@meet.jitsi/xyz");
            }
            other => panic!("Unexpected: {:?}", other),
        }
    }

    #[test]
    fn test_parse_ping_and_disco() {
        let ping = r#"<iq from="focus.meet.jitsi" id="ping_123" to="test@meet.jitsi" type="get"><ping xmlns="urn:xmpp:ping"/></iq>"#;
        match parse_xmpp_message(ping, "127.0.0.1", 10000) {
            Some(InboundXmpp::Ping { id, from }) => {
                assert_eq!(id, "ping_123");
                assert_eq!(from, "focus.meet.jitsi");
            }
            other => panic!("Unexpected: {:?}", other),
        }

        let disco = r#"<iq from="focus.meet.jitsi" id="disco_1" type="get"><query xmlns="http://jabber.org/protocol/disco#info" node="https://jitsi.org/jitsi-meet#7Y4Yx3m5c03c5188efb8b2ebda41e8c072e912da"/></iq>"#;
        match parse_xmpp_message(disco, "127.0.0.1", 10000) {
            Some(InboundXmpp::DiscoInfo { id, from, node }) => {
                assert_eq!(id, "disco_1");
                assert_eq!(from, "focus.meet.jitsi");
                assert_eq!(
                    node.as_deref(),
                    Some("https://jitsi.org/jitsi-meet#7Y4Yx3m5c03c5188efb8b2ebda41e8c072e912da")
                );
            }
            other => panic!("Unexpected: {:?}", other),
        }
    }

    #[test]
    fn test_parse_jingle_initiate() {
        let jingle_xml = r#"<iq from="focus@meet.jitsi" id="jingle_1" type="set">
            <jingle action="session-initiate" initiator="focus@meet.jitsi" sid="sid_abc123" xmlns="urn:xmpp:jingle:1">
                <content creator="initiator" name="audio">
                    <description media="audio" xmlns="urn:xmpp:jingle:apps:rtp:1">
                        <source ssrc="12345678" xmlns="urn:xmpp:jingle:apps:rtp:ssma:0"/>
                    </description>
                    <transport pwd="secretpassword" ufrag="abcde" xmlns="urn:xmpp:jingle:transports:ice-udp:1">
                        <web-socket url="wss://jvb.meet.jitsi/colibri-ws"/>
                        <fingerprint hash="sha-256" setup="actpass" xmlns="urn:xmpp:jingle:apps:dtls:0">AA:BB:CC</fingerprint>
                        <candidate component="1" foundation="1" generation="0" id="c0" ip="192.168.1.50" network="0" port="10000" priority="2130706431" protocol="udp" type="host"/>
                    </transport>
                </content>
            </jingle>
        </iq>"#;

        match parse_xmpp_message(jingle_xml, "127.0.0.1", 10000) {
            Some(InboundXmpp::Jingle(sess)) => {
                assert_eq!(sess.sid, "sid_abc123");
                assert_eq!(sess.action, "session-initiate");
                assert_eq!(sess.transport.ufrag, "abcde");
                assert_eq!(sess.transport.pwd, "secretpassword");
                assert_eq!(sess.transport.fingerprint.as_deref(), Some("AA:BB:CC"));
                assert_eq!(sess.transport.colibri_ws_url.as_deref(), Some("wss://jvb.meet.jitsi/colibri-ws"));
                assert_eq!(sess.transport.candidates.len(), 1);
                assert_eq!(sess.transport.candidates[0].ip, "192.168.1.50");
                assert_eq!(sess.transport.candidates[0].port, 10000);
                assert_eq!(sess.sources, vec![12345678]);
            }
            other => panic!("Unexpected: {:?}", other),
        }
    }
}

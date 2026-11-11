use crate::config::WrtcConfig;
use crate::http_help::BrowserProfile;
use crate::wrtc::providers::{ProviderKind, RoomBootstrapInfo};
use crate::wrtc::xmpp_xml::XmppIceServer;
use std::time::Duration;

/// Провайдер для стандартных публичных и корпоративных инстансов Jitsi Meet
/// (`meet.riddlerx.org`, `meet.egovm.ru` и др.).
pub struct JitsiMeetProvider;

impl JitsiMeetProvider {
    /// Выполняет пред-сигнальную инициализацию комнаты стандартного Jitsi Meet:
    /// 1. Нормализует имя комнаты в нижний регистр (требование Prosody MUC).
    /// 2. Выполняет быстрый HTTP-прогрев через `BrowserProfile` (с поддержкой L4 Port Hopping),
    ///    автоматически сохраняя балансировочные `Set-Cookie` (например, `session-cookie` на `meet.egovm.ru`)
    ///    в `profile.cookie_jar`, откуда `BrowserProfile::build_ws_request` подставит их в `wss://`.
    /// 3. Формирует упорядоченный список кандидатов URL для `XMPP-WS`.
    pub async fn bootstrap_room(
        domain: &str,
        room_short_name: &str,
        _client_name_opt: Option<&str>,
        profile: &BrowserProfile,
        wrtc_cfg: &WrtcConfig,
    ) -> anyhow::Result<RoomBootstrapInfo> {
        let conference_id = if room_short_name.trim().is_empty() {
            "general".to_string()
        } else {
            room_short_name.trim().to_lowercase()
        };

        let hop_attempts = wrtc_cfg.tcp_port_hop_attempts.clamp(1, 16);
        let connect_timeout = Duration::from_millis(wrtc_cfg.tcp_port_hop_timeout_ms.clamp(300, 5_000));

        if let Ok(builder) = profile.build_reqwest_builder(profile.cookie_jar.clone()) {
            if let Ok(http) = builder
                .connect_timeout(connect_timeout)
                .timeout(connect_timeout.saturating_add(Duration::from_secs(2)))
                .build()
            {
                let probe_url = format!("https://{domain}/xmpp-websocket?room={conference_id}");
                let origin = format!("https://{domain}");
                let referer = format!("https://{domain}/{conference_id}");

                for attempt in 1..=hop_attempts {
                    let req = http.get(&probe_url);
                    let req = profile.apply_to_reqwest(req, Some(&origin), Some(&referer));
                    match req.send().await {
                        Ok(resp) => {
                            log::info!(
                                "[WRTC Jitsi] Pre-flight HTTP probe to {} succeeded on attempt {}/{} (status: {})",
                                domain,
                                attempt,
                                hop_attempts,
                                resp.status()
                            );
                            break;
                        }
                        Err(e) => {
                            log::debug!(
                                "[WRTC Jitsi] Pre-flight HTTP probe attempt {}/{} to {} timed out/failed: {}",
                                attempt,
                                hop_attempts,
                                domain,
                                e
                            );
                        }
                    }
                }
            }
        }

        let ws_urls = vec![
            format!("wss://{domain}/xmpp-websocket?room={conference_id}"),
            format!("wss://{domain}/{conference_id}/xmpp-websocket?room={conference_id}"),
            format!("wss://{domain}/xmpp-websocket"),
        ];

        // Для стандартного Jitsi Meet (meet.riddlerx.org, meet.egovm.ru и др.) НЕ используем
        // сторонние внешние STUN-серверы (stun.l.google.com / jitsi.net), которые недоступны в БС:
        // - В режиме JVB (MediaVideo) сам видеомост JVB на публичном IP сервера отвечает на ICE
        //   Binding Request напрямую (host -> prflx) в пределах IP самого Jitsi-сервера.
        // - Если у инстанса Jitsi настроен собственный coturn (например, meet.egovm.ru),
        //   он автоматически получается через XEP-0215 extdisco на том же домене.
        let default_ice_servers: Vec<XmppIceServer> = Vec::new();

        Ok(RoomBootstrapInfo {
            provider_kind: ProviderKind::StandardJitsi,
            domain: domain.to_string(),
            room_name: room_short_name.to_string(),
            conference_id,
            session_token: String::new(),
            ws_urls,
            pre_allocate_before_muc: true,
            default_ice_servers,
        })
    }
}

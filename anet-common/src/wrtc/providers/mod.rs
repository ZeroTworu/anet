pub mod jitsi;
pub mod ktalk;

use crate::config::WrtcConfig;
use crate::http_help::BrowserProfile;
use crate::wrtc::xmpp_xml::XmppIceServer;

/// Тип провайдера ВКС-конференции.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    /// Платформа Контур.Толк (`*.ktalk.ru`, `*.kontur.ru`).
    KonturTalk,
    /// Стандартный инстанс Jitsi Meet (`meet.riddlerx.org`, `meet.egovm.ru` и др.).
    StandardJitsi,
}

/// Унифицированный результат пред-сигнальной инициализации комнаты ВКС.
#[derive(Debug, Clone)]
pub struct RoomBootstrapInfo {
    /// Тип провайдера ВКС.
    pub provider_kind: ProviderKind,
    /// Целевой домен ВКС.
    pub domain: String,
    /// Исходное короткое имя комнаты из конфига.
    pub room_name: String,
    /// Идентификатор конференции в XMPP MUC (`{conference_id}@muc.meet.jitsi`).
    pub conference_id: String,
    /// Сессионный токен авторизации (для Контур.Толк).
    pub session_token: String,
    /// Упорядоченный список кандидатов URL для подключения XMPP WebSocket.
    pub ws_urls: Vec<String>,
    /// Отправлять ли `<conference xmlns="http://jitsi.org/protocol/focus" .../>` ДО входа в MUC.
    /// Для Контур.Толк строго `false` (аллокация отправляется только после MUC status 110);
    /// для стандартного Jitsi Meet — `true` (гарантирует создание комнаты в Prosody до `<presence>`).
    pub pre_allocate_before_muc: bool,
    /// Дефолтные ICE/STUN серверы провайдера (если `extdisco` не вернул список).
    pub default_ice_servers: Vec<XmppIceServer>,
}

/// Реестр провайдеров ВКС, автоматически выбирающий реализацию по домену и нормализующий URL/комнату.
pub struct WrtcProviderRegistry;

impl WrtcProviderRegistry {
    /// Определяет тип провайдера по домену.
    pub fn detect(domain: &str) -> ProviderKind {
        Self::detect_provider(domain)
    }

    /// Проверяет, относится ли домен к платформе Контур.Толк (`*.ktalk.ru`, `*.kontur.ru`).
    pub fn is_ktalk_domain(domain: &str) -> bool {
        let host = Self::normalize_domain(domain);
        ktalk::KonturTalkProvider::is_ktalk_domain(&host)
    }

    /// Определяет тип провайдера по домену.
    pub fn detect_provider(domain: &str) -> ProviderKind {
        if Self::is_ktalk_domain(domain) {
            ProviderKind::KonturTalk
        } else {
            ProviderKind::StandardJitsi
        }
    }

    /// Очищает строку домена от схемы (`https://`, `wss://`), порта и путей.
    pub fn normalize_domain(raw_domain: &str) -> String {
        let trimmed = raw_domain.trim();
        let no_scheme = trimmed
            .strip_prefix("https://")
            .or_else(|| trimmed.strip_prefix("http://"))
            .or_else(|| trimmed.strip_prefix("wss://"))
            .or_else(|| trimmed.strip_prefix("ws://"))
            .unwrap_or(trimmed);
        no_scheme
            .split('/')
            .next()
            .unwrap_or(no_scheme)
            .trim()
            .to_lowercase()
    }

    /// Извлекает чистое имя комнаты (в нижнем регистре для Jitsi) из короткого имени или полной ссылки.
    pub fn normalize_room_name(raw_room: &str) -> String {
        let trimmed = raw_room.trim().trim_matches('/');
        let after_scheme = trimmed
            .strip_prefix("https://")
            .or_else(|| trimmed.strip_prefix("http://"))
            .unwrap_or(trimmed);
        let segment = if let Some((_host, path)) = after_scheme.split_once('/') {
            path.split(['?', '#']).next().unwrap_or(path).trim_matches('/')
        } else {
            after_scheme.split(['?', '#']).next().unwrap_or(after_scheme)
        };
        segment.trim().to_string()
    }

    /// Выполняет полный цикл пред-сигнальной подготовки комнаты (`authorize` + `resolve` или HTTP-прогрев Cookie)
    /// через переданный `BrowserProfile` (с сохранением всех `Set-Cookie` в `profile.cookie_jar`).
    pub async fn bootstrap_room(
        domain: &str,
        room_name: &str,
        client_name_opt: Option<&str>,
        profile: &BrowserProfile,
        wrtc_cfg: &WrtcConfig,
    ) -> anyhow::Result<RoomBootstrapInfo> {
        let clean_domain = Self::normalize_domain(domain);
        let clean_room = Self::normalize_room_name(room_name);

        match Self::detect_provider(&clean_domain) {
            ProviderKind::KonturTalk => {
                ktalk::KonturTalkProvider::bootstrap_room(
                    &clean_domain,
                    &clean_room,
                    client_name_opt,
                    profile,
                    wrtc_cfg,
                )
                .await
            }
            ProviderKind::StandardJitsi => {
                jitsi::JitsiMeetProvider::bootstrap_room(
                    &clean_domain,
                    &clean_room,
                    client_name_opt,
                    profile,
                    wrtc_cfg,
                )
                .await
            }
        }
    }
}

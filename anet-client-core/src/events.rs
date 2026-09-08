#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Stopping,
    Stopped,
    Failed,
}

/// Информация об аккаунте и тарифе пользователя
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AccountInfo {
    /// Тип тарификации строкой ("Индивидуальный тариф", "Группа", и т.д.)
    pub billing_str: String,
    /// Название группы доступа
    pub group_str: String,
    /// Сессии строкой ("1 / 5" или "1 / Безлимит")
    pub sessions_str: String,
    /// Ограничение скорости ("100.00 Мбит/с" или "Безлимит")
    pub speed_str: String,
    /// Израсходованный трафик строкой ("1.42 GiB")
    pub consumed_str: String,
    /// Лимит трафика строкой ("100.00 GiB" или "Безлимит")
    pub limit_str: String,
    /// Срок действия ("2026-12-31" или "Бессрочно")
    pub expires_str: String,
    /// Активные сессии
    pub active_sessions: i32,
    /// Разрешённые сессии (0 - безлимит)
    pub allowed_sessions: i32,
    /// Ограничение скорости в Кбит/с
    pub speed_limit_kbps: Option<u64>,
    /// Израсходованный трафик в байтах
    pub traffic_consumed_bytes: Option<u64>,
    /// Лимит трафика в байтах
    pub traffic_limit_bytes: Option<u64>,
    /// Дата окончания действия
    pub expires_at: Option<String>,
}

/// Типы событий
#[derive(Clone, Debug)]
pub enum AnetEvent {
    // Новый вариант специально для передачи метрик трафика
    Stats {
        rx: String,
        tx: String,
        rtt: String,
        rxm: String,
        txm: String,
    },
    Status(String),
    ClientStateChanged {
        state: ClientState,
        message: String,
        server_name: Option<String>,
    },
    AccountInfo(AccountInfo),
    TrafficUpdate {
        rx: u64,
        tx: u64,
        rtt: u64,
        rxm: u64,
        txm: u64,
    }, // а точно так?
    Warn(String),
    Error(String),
    UpdateAvailable(crate::updater::GithubRelease),
    UpdateProgress(f32), // 0.0 до 1.0
    UpdateStatus(String),
    UpdateReady,
}

/// Трейт для подписчика
pub trait EventHandler: Send + Sync {
    fn on_event(&self, event: AnetEvent);
}

static GLOBAL_HANDLER: std::sync::OnceLock<Box<dyn EventHandler>> = std::sync::OnceLock::new();

// Инициализация (вызывается один раз в main/android_lib)
pub fn set_handler(handler: Box<dyn EventHandler>) {
    let _ = GLOBAL_HANDLER.set(handler);
}

// Публичная функция для отправки событий откуда угодно
pub fn emit(event: AnetEvent) {
    if let Some(handler) = GLOBAL_HANDLER.get() {
        handler.on_event(event);
    }
}

// Хелперы для удобства
pub fn status(s: impl Into<String>) {
    emit(AnetEvent::Status(s.into()));
}

pub fn client_state(state: ClientState, message: impl Into<String>, server_name: Option<String>) {
    emit(AnetEvent::ClientStateChanged {
        state,
        message: message.into(),
        server_name,
    });
}

pub fn err(s: impl Into<String>) {
    emit(AnetEvent::Error(s.into()));
}

pub fn warn(s: impl Into<String>) {
    emit(AnetEvent::Warn(s.into()));
}

pub fn update_progress(p: f32) {
    emit(AnetEvent::UpdateProgress(p));
}

pub fn account_info(info: AccountInfo) {
    emit(AnetEvent::AccountInfo(info));
}

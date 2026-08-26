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

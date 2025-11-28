/// Типы событий
#[derive(Clone, Debug)]
pub enum AnetEvent {
    Status(String),
    TrafficUpdate { rx: u64, tx: u64 }, // а точно так?
    Warn(String),
    Error(String),
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

pub fn err(s: impl Into<String>) {
    emit(AnetEvent::Error(s.into()));
}

pub fn warn(s: impl Into<String>) {
    emit(AnetEvent::Warn(s.into()));
}

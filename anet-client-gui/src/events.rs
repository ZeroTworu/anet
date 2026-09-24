//! Обработчик событий от ядра anet_client_core

use std::sync::{ mpsc::Sender, Arc, Mutex };
use eframe::egui;
use anet_client_core::events::{ AnetEvent, ClientState, EventHandler };

use crate::{
    types::{ ConnectionState, SharedState },
    utils::helpers::lock_ignore_poison,
};

/// Обработчик событий для связи фонового ядра с UI
pub struct GuiEventHandler {
    pub tx: Sender<AnetEvent>,
    pub ctx: egui::Context,
    pub shared: Arc<Mutex<SharedState>>,
}

impl EventHandler for GuiEventHandler {
    fn on_event(&self, event: AnetEvent) {
        let _ = self.tx.send(event.clone());

        if let AnetEvent::ClientStateChanged { state, .. } = &event {
            let new_state = match state {
                ClientState::Connected => ConnectionState::Connected,
                ClientState::Connecting | ClientState::Reconnecting => {
                    ConnectionState::Connecting
                }
                ClientState::Stopping | ClientState::Disconnected | ClientState::Stopped | ClientState::Failed => {
                    ConnectionState::Disconnected
                }
            };

            // Событие "идёт подключение" могло быть отправлено core до того,
            // как пользователь нажал кнопку стоп (UI уже Disconnected) — не
            // даём такому отложенному событию перебрать состояние обратно на
            // Connecting/Connected.
            let mut guard = lock_ignore_poison(&self.shared);
            let stale_after_user_stop = guard.state == ConnectionState::Disconnected
                && matches!(new_state, ConnectionState::Connecting | ConnectionState::Connected);

            if !stale_after_user_stop {
                guard.state = new_state;
            }
        }

        self.ctx.request_repaint();
    }
}

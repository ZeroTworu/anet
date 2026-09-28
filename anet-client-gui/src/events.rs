//! Обработчик событий от ядра anet_client_core

use std::sync::{ mpsc::Sender, Arc, Mutex };
use eframe::egui;
use anet_client_core::events::{ AnetEvent, ClientState, EventHandler, TimestampedEvent };

use crate::{
    types::{ ConnectionState, SharedState },
    utils::helpers::lock_ignore_poison,
};

pub struct GuiEventHandler {
    pub tx: Sender<AnetEvent>,
    pub ctx: egui::Context,
    pub shared: Arc<Mutex<SharedState>>,
}

impl EventHandler for GuiEventHandler {
    fn on_event(&self, TimestampedEvent { timestamp, event }: TimestampedEvent) {
        // Добавляем timestamp к текстовым событиям перед отправкой в GUI канал:
        let event_to_send = match event {
            AnetEvent::Status(msg) => AnetEvent::Status(format!("[{}] {}", timestamp, msg)),
            AnetEvent::Warn(msg) => AnetEvent::Warn(format!("[{}] {}", timestamp, msg)),
            AnetEvent::Error(msg) => AnetEvent::Error(format!("[{}] {}", timestamp, msg)),
            AnetEvent::UpdateStatus(msg) => AnetEvent::UpdateStatus(format!("[{}] {}", timestamp, msg)),
            other => other,
        };

        let _ = self.tx.send(event_to_send.clone());

        if let AnetEvent::ClientStateChanged { state, .. } = &event_to_send {
            let new_state = match state {
                ClientState::Connected => ConnectionState::Connected,
                ClientState::Connecting | ClientState::Reconnecting => {
                    ConnectionState::Connecting
                }
                ClientState::Stopping | ClientState::Disconnected | ClientState::Stopped | ClientState::Failed => {
                    ConnectionState::Disconnected
                }
            };

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
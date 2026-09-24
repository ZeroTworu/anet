//! Корневой модуль графического интерфейса пользователя

pub mod titlebar;
pub mod central_panel;
pub mod bottom_console;
pub mod tariff_card;
pub mod node_selector;
pub mod connect_button;
pub mod settings_modal;
pub mod logs_modal;
pub mod update_modal;
pub mod error_modal;
pub mod toast;

#[cfg(target_os = "windows")]
pub mod process_grid;

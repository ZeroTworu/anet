//! Вспомогательные функции общего назначения

use std::sync::{ Arc, Mutex };
use tokio::runtime::Handle;
use eframe::egui;
use notify_rust::Notification;

use crate::types::{ ConnectionState, SharedState };

/// Безопасный захват мьютекса даже если он отравлен другим запаниковавшим потоком
pub fn lock_ignore_poison<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Добавление строки в циклический буфер логов (с автоматическим таймстемпом)
pub fn push_log(logs: &Arc<Mutex<Vec<String>>>, msg: &str) {
    // Если в строке уже есть таймстемп вида [17:03:51], не дублируем его
    let formatted_msg = if msg.starts_with('[') && msg.len() >= 10 && &msg[9..10] == "]" {
        msg.to_string()
    } else {
        let time = chrono::Local::now().format("[%H:%M:%S]");
        format!("{} {}", time, msg)
    };

    let mut guard = lock_ignore_poison(logs);
    guard.push(formatted_msg);
    if guard.len() > 1000 {
        guard.drain(0..100);
    }
}

/// Отправка нативного системного уведомления
pub fn send_notification(title: &str, body: &str) {
    let _ = Notification::new()
        .summary(title)
        .body(body)
        .appname("ANet VPN")
        .icon("dialog-information")
        .show();
}

/// Переключение состояния VPN соединения
pub fn toggle_vpn(
    shared: &Arc<Mutex<SharedState>>,
    rt_handle: &Handle,
    _logs: &Arc<Mutex<Vec<String>>>
) {
    enum ToggleAction {
        Start(Arc<anet_client_core::client::AnetClient>),
        Stop(Arc<anet_client_core::client::AnetClient>),
        Noop,
    }

    let action = {
        let mut guard = lock_ignore_poison(shared);
        match guard.state {
            ConnectionState::Disconnected => {
                if let Some(client_clone) = guard.client.clone() {
                    client_clone.prepare_for_start();
                    guard.state = ConnectionState::Connecting;
                    ToggleAction::Start(client_clone)
                } else {
                    ToggleAction::Noop
                }
            }
            ConnectionState::Connecting | ConnectionState::Connected => {
                if let Some(client_clone) = guard.client.clone() {
                    guard.state = ConnectionState::Stopping;
                    ToggleAction::Stop(client_clone)
                } else {
                    guard.state = ConnectionState::Disconnected;
                    ToggleAction::Noop
                }
            }
            ConnectionState::Stopping => ToggleAction::Noop,
        }
    };

    match action {
        ToggleAction::Start(client_clone) => {
            let shared_clone = shared.clone();
            rt_handle.spawn(async move {
                match client_clone.start().await {
                    Ok(()) => {
                        let mut guard = lock_ignore_poison(&shared_clone);
                        if !client_clone.is_running()
                            && matches!(
                                guard.state,
                                ConnectionState::Connecting | ConnectionState::Stopping
                            )
                        {
                            guard.state = ConnectionState::Disconnected;
                        }
                    }
                    Err(e) => {
                        lock_ignore_poison(&shared_clone).state = ConnectionState::Disconnected;
                        anet_client_core::events::err(e.to_string());
                    }
                }
            });
        }
        ToggleAction::Stop(client_clone) => {
            let shared_clone = shared.clone();
            rt_handle.spawn(async move {
                let _ = client_clone.stop().await;
                let mut guard = lock_ignore_poison(&shared_clone);
                if guard.state == ConnectionState::Stopping {
                    guard.state = ConnectionState::Disconnected;
                }
            });
        }
        ToggleAction::Noop => {}
    }
}

/// Принудительное восстановление и активация окна из трея
pub fn force_wake_up_window(ctx: &egui::Context) {
    #[cfg(target_os = "windows")]
    {
        use windows_sys::core::BOOL;
        use windows_sys::Win32::Foundation::{ HWND, LPARAM };
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            EnumWindows,
            GetWindowTextW,
            GetWindowThreadProcessId,
            SetForegroundWindow,
            ShowWindow,
            SW_RESTORE,
            SW_SHOW,
        };
        unsafe extern "system" fn enum_window_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
            let mut process_id: u32 = 0;
            unsafe {
                GetWindowThreadProcessId(hwnd, &mut process_id);
            }
            if process_id == (lparam as u32) {
                let mut title_buf = [0u16; 256];
                let len = unsafe {
                    GetWindowTextW(hwnd, title_buf.as_mut_ptr(), title_buf.len() as i32)
                };
                if len > 0 {
                    let title = String::from_utf16_lossy(&title_buf[..len as usize]);
                    if title.starts_with("ANet") {
                        unsafe {
                            ShowWindow(hwnd, SW_RESTORE);
                            ShowWindow(hwnd, SW_SHOW);
                            SetForegroundWindow(hwnd);
                        }
                        return 0;
                    }
                }
            }
            1
        }
        unsafe {
            let pid = std::process::id();
            EnumWindows(Some(enum_window_callback), pid as LPARAM);
        }
    }
    ctx.send_viewport_cmd_to(egui::ViewportId::ROOT, egui::ViewportCommand::Minimized(false));
    ctx.send_viewport_cmd_to(egui::ViewportId::ROOT, egui::ViewportCommand::Visible(true));
    ctx.send_viewport_cmd_to(egui::ViewportId::ROOT, egui::ViewportCommand::Focus);
    ctx.request_repaint_of(egui::ViewportId::ROOT);
}

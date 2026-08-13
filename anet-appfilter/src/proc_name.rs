//! Резолв PID -> имя исполняемого файла (Windows) через пассивный Snapshot API.

use std::sync::Arc;

/// Возвращает имя исполняемого файла процесса в нижнем регистре без пути
/// (например `"firefox.exe"`), используя Snapshot API.
/// Полностью обходит ошибки прав доступа 10013 / Access Denied для песочниц AppContainer.
#[cfg(all(windows, feature = "windivert"))]
pub fn image_name_for_pid(pid: u32) -> Option<Arc<str>> {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};

    // PID 0 (System Idle) и 4 (System) не имеют обычного образа.
    if pid == 0 || pid == 4 {
        return None;
    }

    unsafe {
        // Создаем снимок процессов в системе. Не требует открытия дескрипторов
        // целевых процессов, поэтому работает для AppContainer и UWP приложений.
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }

        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                if entry.th32ProcessID == pid {
                    CloseHandle(snapshot);

                    // Ищем нуль-терминатор в UTF-16 массиве имени файла
                    let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
                    let full_name = String::from_utf16_lossy(&entry.szExeFile[..len]);

                    let name = full_name
                        .rsplit(['\\', '/'])
                        .next()
                        .unwrap_or(&full_name)
                        .to_ascii_lowercase();

                    if name.is_empty() {
                        return None;
                    } else {
                        return Some(Arc::from(name.as_str()));
                    }
                }
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
    }
    None
}

/// Заглушка для не-Windows платформ
#[cfg(not(all(windows, feature = "windivert")))]
pub fn image_name_for_pid(_pid: u32) -> Option<Arc<str>> {
    None
}

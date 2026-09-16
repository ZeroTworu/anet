//! Резолв PID -> имя исполняемого файла (Windows) через пассивный Snapshot API.
//!
//! Поверх снапшота — небольшой TTL-кеш `PID -> image_name`. Без него каждый
//! SocketBind/Connect/Accept в трекере заново обходит всю таблицу процессов
//! через `CreateToolhelp32Snapshot`, что занимает миллисекунды и заставляет
//! packet-router решать «untracked» для первых пакетов нового flow.

use std::sync::Arc;

#[cfg(all(windows, feature = "windivert"))]
use std::sync::OnceLock;
#[cfg(all(windows, feature = "windivert"))]
use std::time::{Duration, Instant};

#[cfg(all(windows, feature = "windivert"))]
use dashmap::DashMap;

/// Кеш разрешённых имён процессов. TTL короткий: его хватает, чтобы схлопнуть
/// «пачку» событий одного процесса (обычно это 5–30 Connect'ов подряд), но
/// достаточно маленький, чтобы не бояться PID reuse — при переиспользовании
/// PID запись устареет и снапшот перечитается.
#[cfg(all(windows, feature = "windivert"))]
struct CachedName {
    name: Option<Arc<str>>,
    at: Instant,
}

#[cfg(all(windows, feature = "windivert"))]
const CACHE_TTL: Duration = Duration::from_millis(500);

#[cfg(all(windows, feature = "windivert"))]
fn cache() -> &'static DashMap<u32, CachedName> {
    static CACHE: OnceLock<DashMap<u32, CachedName>> = OnceLock::new();
    CACHE.get_or_init(DashMap::new)
}

/// Возвращает имя исполняемого файла процесса в нижнем регистре без пути
/// (например `"firefox.exe"`), используя Snapshot API.
/// Полностью обходит ошибки прав доступа 10013 / Access Denied для песочниц AppContainer.
///
/// Результат кешируется на [`CACHE_TTL`]. Для PID 0 и 4 кеш не используется —
/// они всегда возвращают `None`.
#[cfg(all(windows, feature = "windivert"))]
pub fn image_name_for_pid(pid: u32) -> Option<Arc<str>> {
    // PID 0 (System Idle) и 4 (System) не имеют обычного образа.
    if pid == 0 || pid == 4 {
        return None;
    }

    let cache = cache();

    if let Some(entry) = cache.get(&pid) {
        if entry.at.elapsed() < CACHE_TTL {
            return entry.name.clone();
        }
    }

    let name = scan_snapshot_for_pid(pid);
    cache.insert(
        pid,
        CachedName {
            name: name.clone(),
            at: Instant::now(),
        },
    );
    name
}

/// Непосредственный обход снапшота процессов. Внутренняя функция —
/// вызывающий обязан позаботиться о кешировании.
#[cfg(all(windows, feature = "windivert"))]
fn scan_snapshot_for_pid(pid: u32) -> Option<Arc<str>> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };

    unsafe {
        // Создаём снимок процессов в системе. Не требует открытия дескрипторов
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
                    let len = entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len());
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
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn format_timestamp(timestamp: u64) -> String {
    let duration = Duration::from_secs(timestamp);
    let datetime = UNIX_EPOCH + duration;
    let datetime: chrono::DateTime<chrono::Local> = datetime.into();
    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
}

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("built.rs");
    let mut f = File::create(&dest_path).unwrap();

    // Получаем хэш коммита
    let commit_hash = if let Ok(hash) = env::var("GITHUB_SHA") {
        // CI/CD сборка - используем переменную из окружения
        hash
    } else {
        // Локальная сборка - пытаемся получить из git
        Command::new("git")
            .args(&["rev-parse", "--short", "HEAD"])
            .output()
            .ok()
            .and_then(|output| {
                if output.status.success() {
                    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "unknown".to_string())
    };

    // Получаем время сборки в формате UNIX timestamp
    let build_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Определяем тип сборки
    let build_type = if env::var("GITHUB_SHA").is_ok() {
        "CI/CD"
    } else {
        "Local dev"
    };

    // Записываем константы в файл
    writeln!(f, "pub const COMMIT_HASH: &str = \"{}\";", commit_hash).unwrap();
    writeln!(f, "pub const BUILD_TIME: &str = \"{}\";", format_timestamp(build_time)).unwrap();
    writeln!(f, "pub const BUILD_TYPE: &str = \"{}\";", build_type).unwrap();

    // Перекомпилируем при изменении build.rs
    println!("cargo:rerun-if-changed=build.rs");
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());

    println!(
        "cargo:warning=Compiling for: {} on {} (target: {})",
        std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown".to_string()),
        std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "unknown".to_string()),
        target
    );
}


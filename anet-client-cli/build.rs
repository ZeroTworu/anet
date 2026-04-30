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

    // 1. Получаем ТЕГ (версию)
    let git_tag = Command::new("git")
        .args(&["describe", "--tags", "--always"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "v0.0.0-dev".to_string());

    // 2. Получаем ХЕШ коммита
    let commit_hash = Command::new("git")
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
        .unwrap_or_else(|| "unknown".to_string());

    // 3. Время сборки
    let build_time_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let datetime = format_timestamp(build_time_secs);

    let build_type = if env::var("GITHUB_SHA").is_ok() {
        "CI/CD"
    } else {
        "Local dev"
    };

    // Записываем всё в промежуточный файл
    writeln!(f, "pub const GIT_TAG: &str = \"{}\";", git_tag).unwrap();
    writeln!(f, "pub const COMMIT_HASH: &str = \"{}\";", commit_hash).unwrap();
    writeln!(f, "pub const BUILD_TIME: &str = \"{}\";", datetime).unwrap();
    writeln!(f, "pub const BUILD_TYPE: &str = \"{}\";", build_type).unwrap();

    println!("cargo:rerun-if-changed=build.rs");
}
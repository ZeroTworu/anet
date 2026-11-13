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

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        // BoringSSL 5.4.0 uses C++17 (std::variant, std::optional, std::bitset, virtual destructors).
        // Pass -Wl,-Bstatic -lc++_static -lc++abi -Wl,-Bdynamic directly to the NDK clang linker
        // when linking libanet_mobile.so (cdylib), because NDK clang knows the sysroot path to
        // libc++_static.a and libc++abi.a whereas rustc's own -L paths only include the API-level dir.
        println!("cargo:rustc-cdylib-link-arg=-Wl,-Bstatic");
        println!("cargo:rustc-cdylib-link-arg=-lc++_static");
        println!("cargo:rustc-cdylib-link-arg=-lc++abi");
        println!("cargo:rustc-cdylib-link-arg=-Wl,-Bdynamic");
    }

    emit_git_rerun_hints();
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=../anet-common/src");
    println!("cargo:rerun-if-changed=../anet-client-core/src");
}

fn emit_git_watch_dir(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            println!("cargo:rerun-if-changed={}", path.display());
            if path.is_dir() {
                emit_git_watch_dir(&path);
            }
        }
    }
}

fn emit_git_rerun_hints() {
    let git_dir = Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                (!s.is_empty()).then(|| std::path::PathBuf::from(s))
            } else {
                None
            }
        })
        .unwrap_or_else(|| std::path::PathBuf::from("../.git"));

    for rel in ["HEAD", "logs/HEAD", "FETCH_HEAD", "index", "packed-refs"] {
        println!("cargo:rerun-if-changed={}", git_dir.join(rel).display());
    }
    let refs_dir = git_dir.join("refs");
    println!("cargo:rerun-if-changed={}", refs_dir.display());
    emit_git_watch_dir(&refs_dir);
}
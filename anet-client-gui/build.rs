use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::Command;


fn main() {
    if cfg!(target_os = "windows") {
        let mut res = winres::WindowsResource::new();
        res.set_manifest_file("app.manifest");
        res.set_icon("icon.ico");
        res.compile().unwrap();
    }

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

    // Записываем всё в промежуточный файл
    writeln!(f, "pub const GIT_TAG: &str = \"{}\";", git_tag).unwrap();
    writeln!(f, "pub const COMMIT_HASH: &str = \"{}\";", commit_hash).unwrap();
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
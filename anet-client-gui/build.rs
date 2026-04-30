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
    println!("cargo:rerun-if-changed=build.rs");
}
use anyhow::{Context, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    // 1. Получаем метаданные проекта
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;

    // 2. Ищем наш eBPF пакет
    let ebpf_metadata = packages
        .into_iter()
        .find(|p| p.name == "anet-ebpf")
        .ok_or_else(|| anyhow!("anet-ebpf package not found"))?;

    // 3. Получаем путь к директории (родитель manifest_path)
    let root_dir = ebpf_metadata
        .manifest_path
        .parent()
        .ok_or_else(|| anyhow!("Failed to get root_dir for ebpf package"))?;

    // 4. КОНВЕРТАЦИЯ: Создаем aya_build::Package с правильными полями
    let ebpf_package = aya_build::Package {
        name: &ebpf_metadata.name,
        root_dir: root_dir.as_str(), // Используем root_dir вместо path
        no_default_features: false,
        features: &[],
    };

    // 5. Вызываем сборку eBPF.
    // ВАЖНО: передаем Toolchain::Nightly вторым аргументом
    aya_build::build_ebpf([ebpf_package], Toolchain::Nightly)?;

    // Диагностика
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!(
        "cargo:warning=Compiling eBPF for: {} on {} (target: {})",
        std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown".to_string()),
        std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "unknown".to_string()),
        target
    );

    Ok(())
}
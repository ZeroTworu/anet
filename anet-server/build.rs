fn main() {
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());

    println!(
        "cargo:warning=Compiling for: {} on {} (target: {})",
        std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown".to_string()),
        std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "unknown".to_string()),
        target
    );

    // Собираем встроенный eBPF-объект `anet-ebpf` в OUT_DIR, чтобы
    // `anet_server::shaper` мог включить его целиком через
    // `aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/anet-ebpf"))`.
    //
    // aya-build сам дёргает `rustup run nightly ...` только для сборки
    // подкрейта `anet-ebpf` (nightly + rust-src нужны из-за `-Z build-std=core`
    // под таргет bpfel-unknown-none) — стабильный тулчейн, которым собирается
    // сам anet-server, здесь не трогается и не переключается.
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "anet-ebpf",
            root_dir: concat!(env!("CARGO_MANIFEST_DIR"), "/../anet-ebpf"),
            no_default_features: false,
            features: &[],
        }],
        aya_build::Toolchain::Nightly,
    )
    .expect("Failed to build embedded anet-ebpf object");
}

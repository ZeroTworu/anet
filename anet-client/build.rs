fn main() {
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());

    println!(
        "cargo:warning=Compiling for: {} on {} (target: {})",
        std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown".to_string()),
        std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "unknown".to_string()),
        target
    );
}

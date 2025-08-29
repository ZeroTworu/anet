fn main() {
    println!(
        "cargo:warning=Compiling for: {} on {}",
        std::env::var("CARGO_CFG_TARGET_OS").unwrap(),
        std::env::var("CARGO_CFG_TARGET_ARCH").unwrap()
    );
}

.PHONY: musl

musl:
	RUSTFLAGS="-C target-feature=+crt-static"  cargo build --release --target x86_64-unknown-linux-musl

.PHONY: musl cert mob

musl:
	RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-unknown-linux-musl

mob:
	cargo ndk -t x86_64-linux-android -t aarch64-linux-android -o ./android-build/jniLibs build --release -p anet-mobile


cert:
	openssl req -x509 -newkey ed25519 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=alco" -addext "subjectAltName = DNS:alco" -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=digitalSignature,keyEncipherment"

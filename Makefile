.PHONY: musl cert

musl:
	RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-unknown-linux-musl

cert:
	openssl req -x509 -newkey ed25519 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=alco" -addext "subjectAltName = DNS:alco" -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=digitalSignature,keyEncipherment"

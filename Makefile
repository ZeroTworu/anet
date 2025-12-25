.PHONY: all check test clean musl cert mob macos macos-gui macos-all macos-universal macos-app infra

# Default target
all:
	cargo build --release

# Run all checks (compile check without building)
check:
	cargo check --workspace

# Run tests
test:
	cargo test --workspace

# Clean build artifacts
clean:
	cargo clean

# Build static Linux binary (musl)
musl:
	RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target x86_64-unknown-linux-musl

# Build Android libraries (requires cargo-ndk)
mob:
	cargo ndk -t x86_64-linux-android -t aarch64-linux-android -o ./android-build/jniLibs build --release -p anet-mobile

# run infrastructure
infra:
	docker-compose -f contrib/docker/docker-compose.infra.yaml up --remove-orphans
# Build macOS CLI client
macos:
	cargo build --release -p anet-client-cli
	@echo ""
	@echo "Build complete: target/release/anet-client"
	@echo "Run with: sudo ./target/release/anet-client -c client.toml"

# Build macOS GUI client
macos-gui:
	cargo build --release -p anet-client-gui
	@echo ""
	@echo "Build complete: target/release/anet-gui"
	@echo "Run with: ./target/release/anet-gui"

# Build both macOS CLI and GUI
macos-all:
	cargo build --release -p anet-client-cli -p anet-client-gui
	@echo ""
	@echo "Build complete:"
	@echo "  CLI: target/release/anet-client (run with sudo)"
	@echo "  GUI: target/release/anet-gui"

# Build universal macOS binaries (Intel + Apple Silicon)
macos-universal:
	@echo "Building for Apple Silicon (aarch64)..."
	cargo build --release -p anet-client-cli -p anet-client-gui --target aarch64-apple-darwin
	@echo "Building for Intel (x86_64)..."
	cargo build --release -p anet-client-cli -p anet-client-gui --target x86_64-apple-darwin
	@echo "Creating universal binaries..."
	@mkdir -p target/release/universal
	lipo -create -output target/release/universal/anet-client \
		target/aarch64-apple-darwin/release/anet-client \
		target/x86_64-apple-darwin/release/anet-client
	lipo -create -output target/release/universal/anet-gui \
		target/aarch64-apple-darwin/release/anet-gui \
		target/x86_64-apple-darwin/release/anet-gui
	@echo ""
	@echo "Universal binaries created:"
	@echo "  CLI: target/release/universal/anet-client"
	@echo "  GUI: target/release/universal/anet-gui"

cert:
	openssl req -x509 -newkey ed25519 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=alco" -addext "subjectAltName = DNS:alco" -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=digitalSignature,keyEncipherment"

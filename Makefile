.PHONY: all check test clean musl cert mob macos macos-gui macos-all macos-universal macos-app

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

# Build macOS app bundle (GUI)
macos-app:
	./scripts/build-macos-app.sh
	@echo ""
	@echo "To sign the app, run:"
	@echo "  ./scripts/build-macos-app.sh --sign 'Developer ID Application: Your Name'"

# Generate TLS certificates for QUIC
cert:
	openssl req -x509 -newkey ed25519 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=alco" -addext "subjectAltName = DNS:alco" -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=digitalSignature,keyEncipherment"

# Show help
help:
	@echo "ANet VPN Build Targets:"
	@echo ""
	@echo "  make all            - Build all components (release)"
	@echo "  make check          - Run cargo check on workspace"
	@echo "  make test           - Run all tests"
	@echo "  make clean          - Clean build artifacts"
	@echo ""
	@echo "Platform-specific builds:"
	@echo "  make musl           - Build static Linux binary (musl)"
	@echo "  make mob            - Build Android libraries"
	@echo "  make macos          - Build macOS CLI client"
	@echo "  make macos-gui      - Build macOS GUI client"
	@echo "  make macos-all      - Build both macOS CLI and GUI"
	@echo "  make macos-universal - Build universal macOS binaries (Intel + ARM)"
	@echo "  make macos-app      - Build macOS app bundle (.app)"
	@echo ""
	@echo "Utilities:"
	@echo "  make cert           - Generate TLS certificates for QUIC"

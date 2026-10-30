.PHONY: all check test clean musl cert mob macos macos-gui macos-all macos-universal macos-app infra win-gui


win-gui:
	cargo update -p rtc-turn -p reqwest-boring
	cargo build --release --target x86_64-pc-windows-gnu --package anet-client-gui
win-gui-d:
	cargo update -p rtc-turn -p reqwest-boring
	cargo build --release --target x86_64-pc-windows-gnu --package anet-client-gui --features per-app --features console
lin-gui:
	cargo build --release --package anet-client-gui

# Default target
all:
	cargo update -p rtc-turn -p reqwest-boring
	cargo build --release

# Run all checks (compile check without building)
check:
	cargo update -p rtc-turn -p reqwest-boring
	cargo check --workspace

# Run tests
test:
	cargo update -p rtc-turn -p reqwest-boring
	cargo test --workspace

# Clean build artifacts
clean:
	cargo clean

# Build static Linux binary (musl)
musl:
	cargo update -p rtc-turn -p reqwest-boring
	@for d in target/x86_64-unknown-linux-musl/release/build/boring-sys-*/out; do \
		if [ -d "$$d/build" ]; then \
			if [ ! -f "$$d/build/ssl/libssl.a" ] && [ ! -f "$$d/build/libssl.a" ]; then \
				rm -rf "$$d/build"; \
			elif ! grep -q -- "-fno-exceptions" "$$d/build/CMakeCache.txt" 2>/dev/null; then \
				rm -rf "$$d/build"; \
				cargo clean -p boring-sys --release --target x86_64-unknown-linux-musl; \
			fi; \
		fi; \
	done
	CXX_x86_64_unknown_linux_musl=g++ \
	CXXFLAGS_x86_64_unknown_linux_musl="-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fno-exceptions -fno-rtti -fno-sized-deallocation -DBORINGSSL_TEMPORARY_NO_CXX_RUNTIME" \
	BORING_BSSL_RUST_CPPLIB_x86_64_unknown_linux_musl=c \
	RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-Wl,--defsym=fopen64=fopen -C link-arg=-Wl,--defsym=__isoc23_strtoull=strtoull -C link-arg=-Wl,--defsym=__isoc23_strtol=strtol -C link-arg=-Wl,--defsym=__isoc23_strtoul=strtoul -C link-arg=-Wl,--defsym=__cxa_pure_virtual=abort -C link-arg=-Wl,--defsym=_ZdlPv=free -C link-arg=-Wl,--defsym=_ZdlPvm=free -C link-arg=-Wl,--defsym=_ZSt24__throw_out_of_range_fmtPKcz=abort -C link-arg=-Wl,--defsym=_ZSt20__throw_length_errorPKc=abort -C link-arg=-Wl,--defsym=_ZSt17__throw_bad_allocv=abort -C link-arg=-Wl,--defsym=_ZSt28__throw_bad_array_new_lengthv=abort" \
	cargo build --release --target x86_64-unknown-linux-musl --package anet-server --package anet-client-cli --package anet-auth

# Build Android libraries (requires cargo-ndk)
mob:
	cargo update -p rtc-turn -p reqwest-boring
	@for t in x86_64-linux-android aarch64-linux-android armv7-linux-androideabi; do \
		for d in target/$$t/release/build/boring-sys-*/out; do \
			if [ -d "$$d/build" ]; then \
				if [ ! -f "$$d/build/ssl/libssl.a" ] && [ ! -f "$$d/build/libssl.a" ]; then \
					rm -rf "$$d/build"; \
				elif ! grep -q -- "-fno-exceptions" "$$d/build/CMakeCache.txt" 2>/dev/null; then \
					rm -rf "$$d/build"; \
					cargo clean -p boring-sys -p anet-mobile --release --target $$t; \
				fi; \
			fi; \
		done; \
	done
	@NDK_HOME_RESOLVED="$${ANDROID_NDK_HOME:-$${ANDROID_NDK_ROOT:-$${ANDROID_NDK_PATH:-$${NDK_HOME:-}}}}"; \
	if [ -n "$$NDK_HOME_RESOLVED" ] && [ ! -f "$$NDK_HOME_RESOLVED/build/cmake/android.toolchain.cmake" ]; then \
		SUB_NDK="$$(ls -1d "$$NDK_HOME_RESOLVED"/* 2>/dev/null | sort -V | tail -n 1)"; \
		if [ -n "$$SUB_NDK" ] && [ -f "$$SUB_NDK/build/cmake/android.toolchain.cmake" ]; then \
			NDK_HOME_RESOLVED="$$SUB_NDK"; \
		fi; \
	fi; \
	if [ -z "$$NDK_HOME_RESOLVED" ]; then \
		SYSROOT="$$(cargo ndk env 2>/dev/null | sed -n "s/^export CARGO_NDK_SYSROOT_PATH='\(.*\)'$$/\1/p" | head -n 1)"; \
		if [ -n "$$SYSROOT" ]; then \
			NDK_HOME_RESOLVED="$${SYSROOT%/toolchains/llvm/prebuilt/*}"; \
		fi; \
	fi; \
	if [ -z "$$NDK_HOME_RESOLVED" ]; then \
		for base in "$${ANDROID_HOME:+$${ANDROID_HOME}/ndk}" "$${ANDROID_SDK_ROOT:+$${ANDROID_SDK_ROOT}/ndk}" "$${ANDROID_SDK_HOME:+$${ANDROID_SDK_HOME}/ndk}" "$$HOME/Android/Sdk/ndk" "$$HOME/Library/Android/sdk/ndk" "/opt/android-sdk/ndk" "/usr/lib/android-sdk/ndk"; do \
			if [ -n "$$base" ] && [ -d "$$base" ]; then \
				NDK_HOME_RESOLVED="$$(ls -1d "$$base"/* 2>/dev/null | sort -V | tail -n 1)"; \
				[ -n "$$NDK_HOME_RESOLVED" ] && break; \
			fi; \
		done; \
	fi; \
	if [ -z "$$NDK_HOME_RESOLVED" ] && [ -d "/opt/android-ndk" ]; then \
		NDK_HOME_RESOLVED="/opt/android-ndk"; \
	fi; \
	echo "Using ANDROID_NDK_HOME=$$NDK_HOME_RESOLVED"; \
	ANDROID_NDK_HOME="$$NDK_HOME_RESOLVED" \
	cargo ndk -t x86_64-linux-android -t aarch64-linux-android -t armv7-linux-androideabi -o ./android-build/jniLibs build --release -p anet-mobile

# run infrastructure
infra:
	docker-compose -f contrib/docker/docker-compose.infra.yaml up --remove-orphans
# Build macOS CLI client
macos:
	cargo update -p rtc-turn -p reqwest-boring
	cargo build --release -p anet-client-cli
	@echo ""
	@echo "Build complete: target/release/anet-client"
	@echo "Run with: sudo ./target/release/anet-client -c client.toml"

# Build macOS GUI client
macos-gui:
	cargo update -p rtc-turn -p reqwest-boring
	cargo build --release -p anet-client-gui
	@echo ""
	@echo "Build complete: target/release/anet-gui"
	@echo "Run with: ./target/release/anet-gui"

# Build both macOS CLI and GUI
macos-all:
	cargo update -p rtc-turn -p reqwest-boring
	cargo build --release -p anet-client-cli -p anet-client-gui
	@echo ""
	@echo "Build complete:"
	@echo "  CLI: target/release/anet-client (run with sudo)"
	@echo "  GUI: target/release/anet-gui"

# Build universal macOS binaries (Intel + Apple Silicon)
macos-universal:
	cargo update -p rtc-turn -p reqwest-boring
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
	openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=alco" -addext "subjectAltName = DNS:alco" -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=digitalSignature,keyEncipherment"

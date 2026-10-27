# reqwest-boring

[![crates.io](https://img.shields.io/crates/v/reqwest-boring.svg)](https://crates.io/crates/reqwest-boring)
[![Documentation](https://docs.rs/reqwest-boring/badge.svg)](https://docs.rs/reqwest-boring)
[![MIT/Apache-2 licensed](https://img.shields.io/crates/l/reqwest-boring.svg)](./LICENSE-APACHE)
[![CI](https://github.com/madeye/reqwest-boring/actions/workflows/ci.yml/badge.svg)](https://github.com/madeye/reqwest-boring/actions/workflows/ci.yml)

`reqwest-boring` is a fork of the original [reqwest](https://github.com/seanmonstar/reqwest) HTTP client by Sean McArthur and contributors. It replaces the default TLS layer with [boring](https://crates.io/crates/boring), the Rust bindings to BoringSSL, and uses [Quiche](https://github.com/cloudflare/quiche) for HTTP/3.

The package is published as `reqwest-boring`; the Rust library remains named `reqwest`. Existing client, request, response, and builder APIs are preserved, with the backend-specific configuration difference documented below.

- Async and blocking `Client`s
- Plain bodies, JSON, urlencoded, multipart
- Customizable redirect policy
- HTTP Proxies
- HTTPS via BoringSSL (or optionally, system-native TLS)
- HTTP/3 via Quiche, sharing the same BoringSSL build
- Cookie Store
- WASM


## Example

This asynchronous example uses [Tokio](https://tokio.rs) and enables some
optional features, so your `Cargo.toml` could look like this:

```toml
[dependencies]
reqwest = { package = "reqwest-boring", version = "0.13.5", features = ["json"] }
tokio = { version = "1", features = ["full"] }
```

And then the code:

```rust,no_run
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let resp = reqwest::get("https://httpbin.org/ip")
        .await?
        .json::<HashMap<String, String>>()
        .await?;
    println!("{resp:#?}");
    Ok(())
}
```

## Requirements

The default TLS backend uses `boring` and `tokio-boring`. Building BoringSSL requires a C/C++ compiler, CMake, Perl, and libclang (for bindgen). On Windows, install LLVM and NASM as well. HTTP/3 uses `quiche` with `boringssl-boring-crate`, so it links the same BoringSSL library. Enable it with `features = ["http3"]` and `RUSTFLAGS="--cfg reqwest_unstable"`.

The `rustls` and `rustls-no-provider` features and the `tls_backend_rustls()` / `use_rustls_tls()` builder methods remain compatibility aliases for BoringSSL. A Rustls crypto provider is no longer needed. `tls_backend_preconfigured()` / `use_preconfigured_tls()` keep their signatures but accept `boring::ssl::SslConnector` in place of Rustls configuration objects; this backend-specific escape hatch has no upstream semver guarantee. Configure HTTP/3 through the standard builder methods.

Apple platforms use Security.framework to validate system trust; Windows loads the system root store, and other native platforms use system CA files. Custom certificates, PEM client identities, certificate revocation lists, TLS versions, SNI, key logging, and TLS metadata remain available through the existing API.

Browser WASM targets use the browser's TLS implementation.

The optional `native-tls` backend still uses the system TLS framework on Windows and macOS and OpenSSL on Linux. `native-tls-vendored` builds OpenSSL from source.

## Attribution and License

This fork builds on the original reqwest project by Sean McArthur and its contributors. The upstream MIT and Apache-2.0 licenses and copyright notices are retained. Fork-specific issues and contributions belong in [madeye/reqwest-boring](https://github.com/madeye/reqwest-boring).

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

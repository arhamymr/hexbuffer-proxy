# hexbuffer-proxy

An HTTPS MITM (Man-in-the-Middle) proxy written in Rust. It intercepts encrypted HTTPS traffic by dynamically generating TLS certificates for target domains, allowing inspection and modification of request/response data.

## How It Works

```
Browser → hexbuffer-proxy (decrypts) → Upstream Server
              │
              ├─ Forges TLS cert per domain (via local CA)
              ├─ Intercepts inner HTTP request
              └─ Forwards to real server over TLS
```

1. Client sends `CONNECT` to the proxy
2. Proxy generates a trusted TLS certificate for the target domain on-the-fly
3. Proxy performs TLS handshake with the client using the forged certificate
4. Proxy reads the decrypted HTTP request
5. Proxy connects to the real upstream server via TLS and forwards the request
6. Response is streamed back to the client through the TLS tunnel

## Prerequisites

- **Rust** (stable, edition 2024)
- The proxy CA certificate (`cert/ca.pem`) must be trusted by your system/browser for HTTPS interception to work without certificate warnings

## Quick Start

```bash
# Build and run
make run

# Or manually
cargo run
```

The proxy listens on `127.0.0.1:8080`. Configure your browser or system to use it as an HTTP/HTTPS proxy.

### Makefile Targets

| Command | Description |
|---------|-------------|
| `make run` | Build and run the proxy |
| `make build` | Compile debug build |
| `make release` | Compile optimized release build |
| `make check` | Check for compilation errors (fast, no output binary) |
| `make test` | Run all unit tests |
| `make fmt` | Format code with `rustfmt` |
| `make lint` | Run clippy with `-D warnings` |
| `make watch` | Auto-rebuild on file changes (`cargo watch`) |
| `make clean` | Remove build artifacts |

## Project Structure

```
src/
├── main.rs        # Entry point — thin binary, 12 lines via ProxyBuilder
├── lib.rs         # Library root — module declarations + public re-exports
├── ca.rs          # Certificate authority — generates CA & per-domain TLS certs (rcgen)
├── proxy.rs       # Request dispatcher — routes CONNECT vs HTTP, shared parse/serialize/body helpers
├── http_proxy.rs  # Plain HTTP — forward proxy handler, host extraction, WS relay
├── https_proxy.rs # HTTPS MITM — TLS interception, cert forging, handler pipeline
├── ws_proxy.rs    # WebSocket — upgrade detection, bidirectional relay, frame handler
├── upstream.rs    # Tower service stack — Hyper client + DecompressionLayer, HTTP/2 ALPN
├── handler.rs     # HttpHandler + WebSocketHandler traits, Body, HttpContext, Direction
├── builder.rs     # ProxyBuilder — ergonomic proxy configuration
├── decoder.rs     # App-layer body decoder — DecodeHandler plugin + encode/decode utilities
└── error.rs       # Centralized ProxyError enum (thiserror)
```

## Trusting the CA Certificate

After the first run, the proxy generates a CA certificate at `cert/ca.pem`. Trust it in your system:

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain cert/ca.pem
```

**Linux (Firefox):**
Preferences → Privacy & Security → Certificates → View Certificates → Authorities → Import `cert/ca.pem`

## Current Implementation State

- ✅ HTTPS MITM interception via CONNECT tunneling
- ✅ Plain HTTP proxying — forward non-CONNECT requests with handler hooks
- ✅ Dynamic TLS certificate generation per domain
- ✅ CA certificate persistence, caching, and auto-creation
- ✅ **Trait-based `HttpHandler` system** — intercept and modify requests/responses
- ✅ **`ProxyBuilder`** — ergonomic one-liner proxy configuration
- ✅ **Handler pipeline** — parse → handler stack → serialize integrated into proxy flow
- ✅ **Short-circuit support** — return responses without contacting upstream
- ✅ **Library + binary split** — `lib.rs` with `pub(crate)` visibility, thin `main.rs`
- ✅ **Clean module separation** — `http_proxy.rs` + `https_proxy.rs` + `ws_proxy.rs` + `upstream.rs`
- ✅ **Streaming body support** — Content-Length, chunked transfer encoding, Connection: close
- ✅ **WebSocket support** — upgrade detection, bidirectional relay, `WebSocketHandler` trait
- ✅ **Upstream connection pooling** — Hyper client with `LazyLock`-shared pool, HTTP/2 ALPN
- ✅ **Tower middleware decompression** — gzip, deflate, brotli, zstd via tower-http DecompressionLayer
- ✅ Unit test coverage for builder, handler stack, and core modules
- ✅ **Application-level body decoder** — `DecodeHandler` plugin + `decode_request`/`decode_response`/`encode_body` utilities

## Body Decoder (`decoder` feature)

The `decoder` module provides application-level body decoding as an **opt-in plugin**.
Unlike the transparent tower-http decompression in `upstream.rs` (which handles
response bodies automatically), the decoder gives handlers explicit control over
when and how to decode.

### Relationship with tower-http

| Direction | Tower (`decompress=true`) | DecodeHandler |
|-----------|--------------------------|---------------|
| Request   | Never touches            | Decodes gzip/deflate/brotli/zstd |
| Response  | Decompresses automatically | Skips (header already stripped) |
| Response  | Passes raw (`decompress=false`) | Decodes |

### Usage — Tier 1 (Inspection)

Add `DecodeHandler` to your chain. Tower stays on. Request bodies are decoded
for downstream handlers; response bodies are already handled by tower.

```rust
use hexbuffer_proxy::decoder::DecodeHandler;

let proxy = ProxyBuilder::new()
    .with_ca(ca)
    .with_http_handler(LoggingHandler::new())
    .add_http_handler(DecodeHandler)           // ← decode request bodies
    .add_http_handler(MyInspectionHandler)     // ← sees plain bytes
    .build()?;
```

### Usage — Tier 2 (Forensic)

Disable tower, add `DecodeHandler`. Both directions decoded at the app layer.
Add a wire-capture handler before DecodeHandler to snapshot raw bytes.

```rust
let proxy = ProxyBuilder::new()
    .with_ca(ca)
    .with_decompression(false)                 // tower off
    .with_http_handler(WireCapture::new("/tmp/capture"))
    .add_http_handler(DecodeHandler)           // decode both directions
    .add_http_handler(MyInspector)
    .build()?;
```

### Usage — Tier 3 (Repeater / Modifier)

Use the free functions directly for fine-grained control:

```rust
use hexbuffer_proxy::decoder::{decode_request, encode_body};

async fn handle_request(&self, ctx: &mut HttpContext, req: Request<Body>) -> Result<RequestOrResponse> {
    // Decode
    let req = decode_request(req).await?;
    let bytes = req.body().into_bytes().await?;

    // Modify
    let modified = modify_body(&bytes);

    // Re-encode with original compression
    let body = encode_body(Body::Full(modified.into()), "gzip", None)?;

    let (mut parts, _) = req.into_parts();
    parts.headers.insert("Content-Encoding", "gzip".parse().unwrap());
    Ok(RequestOrResponse::Request(Request::from_parts(parts, body)))
}
```

### Cargo feature

Enabled by default. Opt out to keep the binary lean:

```toml
hexbuffer-proxy = { default-features = false }
```

## Versioning

The version is derived from git tags at build time via [`vergen-gitcl`](https://crates.io/crates/vergen-gitcl).

**Check the version:**
```bash
cargo run -- --version
# hexbuffer-proxy v0.0.1

# Or with -V
cargo run -- -V
```

The startup banner also prints the version dynamically.

**From library code:**
```rust
use hexbuffer_proxy::version;

println!("{}", version::GIT_VERSION);  // e.g. "v0.0.2-3-gabc1234"
println!("{}", version::GIT_SHA);      // full commit hash
println!("{}", version::GIT_DIRTY);    // "true" if uncommitted changes
```

**Release workflow:**
```bash
# 1. Bump the version in Cargo.toml
#    Edit version = "0.0.2"

# 2. Commit and tag
git add Cargo.toml
git commit -m "release: v0.0.2"
git tag v0.0.2

# 3. Rebuild — the tag is now embedded
cargo build
cargo run -- --version
# → hexbuffer-proxy v0.0.2
```

After more commits on top of a tag, `git describe` automatically shows the distance: `v0.0.2-3-gabc1234` (3 commits after v0.0.2, at commit `abc1234`).

## Tech Stack

| Dependency | Purpose |
|------------|---------|
| `tokio` | Async runtime |
| `tokio-rustls` / `rustls` | TLS client/server handshakes |
| `rcgen` | CA and per-domain certificate generation |
| `webpki-roots` | Trusted root CA store for upstream connections |
| `hyper` / `http` / `hyper-util` | HTTP types, parsing, connection pooling |
| `hyper-rustls` | TLS connector for upstream Hyper client (ALPN, HTTP/2) |
| `async-trait` | Async trait dynamic dispatch |
| `thiserror` | Ergonomic error types |
| `bytes` | Zero-copy byte buffers |
| `tokio-tungstenite` | WebSocket frame parsing and relay |
| `futures-util` | Stream/Sink combinators for WebSocket frames |
| `tower` / `tower-http` | Middleware stack — DecompressionLayer for transparent body decoding |
| `flate2` | Gzip/zlib codec — used by the `decoder` feature (opt-in) |
| `brotli` | Brotli codec — used by the `decoder` feature (opt-in) |
| `zstd` | Zstd codec — used by the `decoder` feature (opt-in) |

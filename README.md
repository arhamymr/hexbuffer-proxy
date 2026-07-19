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
├── proxy.rs       # Request dispatcher — routes CONNECT vs plain HTTP, shared helpers
├── https_proxy.rs # HTTPS MITM — TLS interception, cert forging, handler pipeline
├── parser.rs      # CONNECT request line parser — extracts host:port
├── handler.rs     # HttpHandler trait, Body, HttpContext, RequestOrResponse, NoopHandler
├── builder.rs     # ProxyBuilder — ergonomic proxy configuration
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
- ✅ **Module separation** — `https_proxy.rs` extracted from `proxy.rs`
- ✅ Unit test coverage for builder, handler stack, and core modules

## Future Planning

See [docs/plan.md](docs/plan.md) for the full roadmap. Planned features:

- **WebSocket support** — intercept and relay WebSocket frames with message modification
- **HTTP/2 support** — optional feature-gated HTTP/2 proxying
- **Body decoding helpers** — decode gzip/deflate/brotli/zstd compressed bodies
- **Persistent connections** — HTTP/1.1 keep-alive across multiple requests per tunnel

## Tech Stack

| Dependency | Purpose |
|------------|---------|
| `tokio` | Async runtime |
| `tokio-rustls` / `rustls` | TLS client/server handshakes |
| `rcgen` | CA and per-domain certificate generation |
| `webpki-roots` | Trusted root CA store for upstream connections |
| `hyper` / `http` | HTTP types and parsing |
| `async-trait` | Async trait dynamic dispatch |
| `thiserror` | Ergonomic error types |
| `bytes` | Zero-copy byte buffers |
| `thiserror` | Ergonomic error types |
| `bytes` | Zero-copy byte buffers |

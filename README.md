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
├── main.rs    # Entry point — binds TCP listener, spawns client handlers
├── ca.rs      # Certificate authority — generates CA & per-domain TLS certs (rcgen)
├── proxy.rs   # CONNECT tunnel handling — TLS interception & request forwarding
└── parser.rs  # CONNECT request line parser — extracts host:port
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
- ✅ Dynamic TLS certificate generation per domain
- ✅ CA certificate persistence and caching
- ✅ Unit test coverage for core modules

## Future Planning

See [docs/feature-spec-mitm-proxy.md](docs/feature-spec-mitm-proxy.md) for the full roadmap. Planned features:

- **Plain HTTP proxying** — forward non-CONNECT requests with handler hooks
- **Response modification** — intercept and modify upstream responses before returning to client
- **Trait-based handler system** — `HttpHandler` / `WebSocketHandler` traits for composable interception logic
- **ProxyBuilder** — ergonomic builder pattern for proxy configuration
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
| `base64` | PEM certificate encoding |

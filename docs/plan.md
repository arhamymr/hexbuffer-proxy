# Feature Specification: MITM Proxy

## Overview

Transform hexbuffer-proxy from a basic HTTPS interception proxy into a full-featured, extensible MITM HTTP/S proxy supporting:

- **Modify HTTP/S requests** before they reach the upstream server
- **Modify HTTP/S responses** before they reach the client
- **Modify WebSocket messages** in both directions
- **Trait-based handler system** for composable, testable interception logic
- **ProxyBuilder** for ergonomic configuration
- **HTTP/2** support (optional feature gate)

---

## Architecture

### Component Diagram

```
┌──────────┐     ┌─────────────────────────────────────────────────┐     ┌──────────┐
│  Client  │────▶│              hexbuffer-proxy                     │────▶│ Upstream │
│ (Browser)│     │                                                  │     │  Server  │
└──────────┘     │  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │     └──────────┘
                 │  │  Proxy   │  │ Handlers │  │   TLS Layer  │  │
                 │  │ (Builder)│──▶│  Stack   │──▶│ (CA / MITM)  │  │
                 │  └──────────┘  └──────────┘  └──────────────┘  │
                 │                                                  │
                 │  ┌──────────────────────────────────────────┐   │
                 │  │         Certificate Authority             │   │
                 │  │  (already implemented — ca.rs)           │   │
                 │  └──────────────────────────────────────────┘   │
                 └─────────────────────────────────────────────────┘
```

### Module Map

```
src/
├── main.rs          # Entry point (simplified — delegates to proxy builder)
├── ca.rs            # ✅ Existing: CA cert generation & caching (rcgen)
├── parser.rs        # ✅ Existing: CONNECT request parsing
├── proxy.rs         # 🔄 Refactor: split into multiple modules
├── builder.rs       # 🆕 ProxyBuilder configuration
├── handler.rs       # 🆕 HttpHandler / WebSocketHandler traits
├── http_proxy.rs    # 🆕 Plain HTTP forwarding (non-CONNECT)
├── https_proxy.rs   # 🆕 HTTPS MITM interception (refactored from proxy.rs)
├── ws_proxy.rs      # 🆕 WebSocket upgrade & message relay
├── body.rs          # 🆕 Body decoding helpers (Content-Encoding aware)
└── error.rs         # 🆕 Centralized error types
```

---

## Feature Breakdown

### 1. Trait-Based Handler System 🆕

The core extensibility mechanism. Users implement traits to intercept and modify traffic.

```rust
/// Handler for HTTP requests and responses.
/// Called for every intercepted request/response pair.
pub trait HttpHandler: Send + Sync {
    /// Called when a request is intercepted (before forwarding to upstream).
    /// Return `RequestOrResponse::Request(modified_request)` 
    /// or `RequestOrResponse::Response(response)` to short-circuit.
    async fn handle_request(
        &self,
        ctx: &mut HttpContext,
        request: Request<Body>,
    ) -> RequestOrResponse;

    /// Called when a response is intercepted (before returning to client).
    async fn handle_response(
        &self,
        ctx: &mut HttpContext,
        response: Response<Body>,
    ) -> Response<Body>;
}

/// Context available during request/response processing.
pub struct HttpContext {
    /// Unique request ID for tracing/logging
    pub id: u64,
    /// Target hostname
    pub host: String,
    /// Client socket address
    pub client_addr: SocketAddr,
    /// Whether this is an HTTPS (CONNECT-tunneled) request
    pub is_https: bool,
}

/// Handler for WebSocket messages.
pub trait WebSocketHandler: Send + Sync {
    /// Called for each WebSocket message from client → server.
    async fn handle_client_message(
        &self,
        ctx: &WebSocketContext,
        message: Message,
    ) -> Message;

    /// Called for each WebSocket message from server → client.
    async fn handle_server_message(
        &self,
        ctx: &WebSocketContext,
        message: Message,
    ) -> Message;
}

/// Context for WebSocket connections.
pub struct WebSocketContext {
    pub host: String,
    pub client_addr: SocketAddr,
}
```

**Design decisions:**
- Handlers are `Arc<dyn HttpHandler>` — composable via a handler stack (chain of responsibility)
- `RequestOrResponse` enum allows short-circuiting (return a response without hitting upstream)
- All handler methods are `async` to support database lookups, external API calls, etc.

---

### 2. ProxyBuilder 🆕

Ergonomic builder pattern to configure and launch the proxy.

```rust
let proxy = ProxyBuilder::new()
    .with_addr("127.0.0.1:8080")
    .with_ca(CertificationAuthority::new())
    .with_http_handler(my_handler)
    .with_websocket_handler(my_ws_handler)
    .with_rustls_client()          // TLS to upstream
    .build()?;

proxy.start().await?;
```

**Configuration options:**

| Method | Description | Default |
|--------|-------------|---------|
| `with_addr(addr)` | Bind address | `127.0.0.1:8080` |
| `with_ca(ca)` | Certificate authority | `CertificationAuthority::new()` |
| `with_http_handler(h)` | Primary HTTP handler | `NoopHandler` |
| `add_http_handler(h)` | Append to handler stack | — |
| `with_websocket_handler(h)` | WebSocket handler | `NoopWsHandler` |
| `with_rustls_client()` | Use rustls for upstream TLS | enabled |
| `with_native_tls_client()` | Use native-tls for upstream | disabled |
| `with_http2()` | Enable HTTP/2 support | disabled |
| `with_request_buffer_size(n)` | Per-request read buffer | 16384 (16KB) |

**Features gates (Cargo.toml):**

```toml
[features]
default = ["rcgen-ca", "rustls-client", "decoder"]
full = ["http2", "native-tls-client"]
http2 = ["hyper/http2"]
native-tls-client = ["tokio-native-tls"]
rcgen-ca = ["rcgen"]          # already present
rustls-client = ["tokio-rustls", "webpki-roots"]  # already present
decoder = []                  # enables body decoding helpers
```

---

### 3. HTTP Proxy (Plain HTTP) 🆕

Currently hexbuffer-proxy only handles `CONNECT` (HTTPS) traffic. Plain HTTP requests are silently dropped. We need to add full HTTP forwarding.

**Flow:**

```
Client → hexbuffer-proxy → Upstream Server
         │
         ├─ Read HTTP request headers
         ├─ Call handler.handle_request()
         ├─ Forward (possibly modified) request to upstream
         ├─ Read upstream response
         ├─ Call handler.handle_response()
         └─ Return (possibly modified) response to client
```

**Key implementation details:**
- Use `hyper` for HTTP/1.1 parsing (instead of raw byte manipulation)
- Support chunked transfer encoding
- Support streaming bodies (not just `Connection: close` one-shot)
- Extract `Host` header to determine upstream target

---

### 4. HTTPS MITM Proxy (Refactor) 🔄

Refactor the existing `proxy.rs` `handle_client()` into a clean module that:

1. Receives CONNECT, returns 200 to client
2. Performs TLS handshake with client using forged cert
3. Reads decrypted HTTP request
4. Calls `handler.handle_request()`
5. Connects to upstream via TLS
6. Forwards request, reads response
7. Calls `handler.handle_response()`
8. Returns response to client via TLS tunnel

**Improvements over current implementation:**
- Keep TLS tunnel alive for multiple requests (HTTP/1.1 keep-alive / pipelining)
- Instead of `force_connection_close()`, properly handle persistent connections
- Use `hyper` HTTP types for request/response representation

---

### 5. WebSocket Proxy 🆕

Intercept `Upgrade: websocket` requests and relay WebSocket frames.

**Flow:**

```
Client ←→ hexbuffer-proxy ←→ Upstream Server
           │
           ├─ Detect Upgrade: websocket header
           ├─ Perform WebSocket handshake with client
           ├─ Connect WebSocket to upstream
           ├─ For each client message: handler.handle_client_message()
           ├─ For each server message: handler.handle_server_message()
           └─ Relay (possibly modified) messages
```

**Dependency:** `tokio-tungstenite` for WebSocket frame handling.

**HTTPS + WebSocket:** Works through the existing CONNECT TLS tunnel — after TLS decryption, detect the `Upgrade` header in the inner HTTP request and switch to WebSocket relay mode.

---

### 6. Body Decoding Helpers 🆕

Utility functions to decode compressed/encoded HTTP bodies.

```rust
/// Decode a request body (handles gzip, deflate, br, zstd).
/// Feature-gated behind `decoder`.
pub async fn decode_request(
    headers: &HeaderMap,
    body: Body,
) -> Result<Body, Error>;

/// Decode a response body (handles gzip, deflate, br, zstd).
pub async fn decode_response(
    headers: &HeaderMap,
    body: Body,
) -> Result<Body, Error>;
```

---

### 7. HTTP/2 Support 🆕 (Optional)

Feature-gated behind `http2`. When enabled:
- Accept HTTP/2 prior knowledge and h2c upgrade on plain HTTP
- Accept h2 ALPN negotiation in TLS handshake
- Handler traits work identically — protocol is transparent to handlers

---

## Backlog

| ID | Task | Priority | Est. | Dependencies |
|----|------|----------|------|--------------|
| **BK-01** | Add `hyper`, `http`, `thiserror` dependencies to `Cargo.toml` | P0 | S | — |
| **BK-02** | Create `error.rs` — centralized `Error` enum | P0 | S | BK-01 |
| **BK-03** | Create `handler.rs` — `HttpHandler` / `WebSocketHandler` traits + `NoopHandler` | P0 | M | — |
| **BK-04** | Create `body.rs` — `Body` type wrapping `hyper::body::Body` | P0 | S | BK-01 |
| **BK-05** | Extract `https_proxy.rs` from `proxy.rs` — clean HTTPS MITM module | P0 | M | — |
| **BK-06** | Create `http_proxy.rs` — plain HTTP forwarding with handler hooks | P1 | L | BK-03 |
| **BK-07** | Support streaming bodies and chunked transfer encoding | P1 | M | BK-06 |
| **BK-08** | Integrate `HttpHandler` calls into `http_proxy.rs` and `https_proxy.rs` | P1 | M | BK-03, BK-05, BK-06 |
| **BK-09** | Implement handler stack (chain of responsibility) | P1 | S | BK-08 |
| **BK-10** | Support short-circuit responses via `RequestOrResponse` | P1 | S | BK-09 |
| **BK-11** | Create `builder.rs` — `ProxyBuilder` struct with configuration methods | P2 | M | BK-08 |
| **BK-12** | `Proxy::start()` — bind and run accept loop delegating to proxy modules | P2 | M | BK-11 |
| **BK-13** | Refactor `main.rs` to use `ProxyBuilder` | P2 | S | BK-12 |
| **BK-14** | Add `tokio-tungstenite` dependency | P2 | S | — |
| **BK-15** | Create `ws_proxy.rs` — WebSocket upgrade detection and frame relay | P2 | L | BK-03, BK-14 |
| **BK-16** | Integrate `WebSocketHandler` trait calls in `ws_proxy.rs` | P2 | M | BK-15 |
| **BK-17** | Implement `decode_request` / `decode_response` behind `decoder` feature gate | P3 | M | BK-04 |
| **BK-18** | Enable `hyper/http2` feature + ALPN negotiation | P3 | L | BK-12 |

### Priority Legend

| Priority | Meaning |
|----------|---------|
| P0 | Blocking — must ship first (foundation) |
| P1 | Core — HTTP proxy + handler integration |
| P2 | Extension — builder pattern + WebSocket |
| P3 | Optional — body decoding + HTTP/2 |

### Size Legend

| Size | Meaning |
|------|---------|
| S | Small — single file, few types |
| M | Medium — multi-file refactor or new module with logic |
| L | Large — new protocol support or complex module |

---

## Dependency Changes

### New Dependencies (Cargo.toml)

```toml
[dependencies]
# Existing
tokio = { version = "1.0", features = ["full"] }
tokio-rustls = "0.26"
rustls-pki-types = "1.0"
rcgen = { version = "0.14", features = ["pem"] }
anyhow = "1.0"
base64 = "0.22"
webpki-roots = "1.0"

# New
hyper = { version = "1", features = ["server", "http1", "client"] }
hyper-util = { version = "0.1", features = ["tokio", "server-auto", "client-legacy"] }
http-body-util = "0.1"
http = "1"
tokio-tungstenite = { version = "0.24", features = ["rustls-tls-webpki-roots"] }
thiserror = "2"
futures = "0.3"
bytes = "1"

# Optional
tokio-native-tls = { version = "0.3", optional = true }
```

---

## API Usage Example (Post-Implementation)

```rust
use hexbuffer_proxy::{
    builder::ProxyBuilder,
    handler::{HttpHandler, HttpContext, RequestOrResponse, NoopHandler},
    ca::CertificationAuthority,
};
use http::{Request, Response};
use hyper::body::Body;

struct LoggingHandler;

impl HttpHandler for LoggingHandler {
    async fn handle_request(
        &self,
        ctx: &mut HttpContext,
        request: Request<Body>,
    ) -> RequestOrResponse {
        println!("[{}] {} {} — {}", 
            ctx.id, request.method(), request.uri(), ctx.host);
        RequestOrResponse::Request(request)
    }

    async fn handle_response(
        &self,
        ctx: &mut HttpContext,
        response: Response<Body>,
    ) -> Response<Body> {
        println!("[{}] ← {} {}", 
            ctx.id, response.status(), ctx.host);
        response
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let ca = CertificationAuthority::new();

    let proxy = ProxyBuilder::new()
        .with_addr("127.0.0.1:8080")
        .with_ca(ca)
        .with_http_handler(LoggingHandler)
        .build()?;

    proxy.start().await
}
```

---

## Assumptions & Constraints

1. **Hyper 1.x** is used for HTTP parsing and types (stable, widely adopted)
2. **TLS stack** remains `tokio-rustls` + `rustls` (already working)
3. **CA module** (`ca.rs`) requires no changes — API is already sufficient
4. **Single-threaded handler execution** per request (no `Send` requirement beyond `Arc`)
5. **HTTP/2** is optional and feature-gated — not required for MVP
6. **No gRPC or SSE** support in initial scope (can be added later via handler traits)
7. **Backward compatibility:** The existing `main.rs` entry point should continue working with minimal changes

---

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| `hyper` 1.x API complexity | Use `hyper-util` helpers for common patterns |
| Connection pooling breaks MITM interception | Each request goes through handler stack regardless of pooling |
| WebSocket frame fragmentation | `tokio-tungstenite` handles frame reassembly automatically |
| TLS certificate cache memory growth | Add TTL-based eviction to `ca.rs` cert_cache (future enhancement) |
| Handler panics crashing the proxy | Wrap handler calls in `std::panic::catch_unwind` |

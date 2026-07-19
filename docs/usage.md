# hexbuffer-proxy — Library Usage Guide

## Overview

`hexbuffer-proxy` is an HTTPS MITM proxy library for Rust. Add it as a dependency, implement one or more handler traits, and you have a production-grade intercepting proxy with connection pooling, HTTP/2, transparent decompression, and WebSocket support.

```toml
[dependencies]
hexbuffer-proxy = { path = "." }   # or git/crates.io
tokio = { version = "1", features = ["full"] }
tokio-rustls = "0.26"
anyhow = "1"
async-trait = "0.1"
http = "1"
```

---

## Quick Start — Minimal Proxy

```rust
use hexbuffer_proxy::{CertificationAuthority, ProxyBuilder};
use tokio_rustls::rustls::crypto::aws_lc_rs::default_provider;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Required: install rustls crypto provider before any TLS
    let _ = default_provider().install_default();

    // CA auto-creates cert/ca.pem on first run
    let ca = CertificationAuthority::new();

    ProxyBuilder::new()
        .with_ca(ca)
        .build()?                // defaults to NoopHandler (pass-through)
        .start()                 // blocks, listens on 127.0.0.1:8080
        .await?;

    Ok(())
}
```

This starts a pass-through proxy. Configure your browser to use `127.0.0.1:8080` and trust `cert/ca.pem` for HTTPS interception. All traffic flows through unchanged.

---

## Public API Reference

### Re-exports (crate root)

| Symbol | Kind | Description |
|---|---|---|
| `ProxyBuilder` | struct | Builder-pattern proxy configuration |
| `Proxy` | struct | Running proxy server (call `.start()`) |
| `CertificationAuthority` | struct | CA certificate generation + per-domain forging |
| `HttpHandler` | trait | Intercept & modify HTTP requests/responses |
| `WebSocketHandler` | trait | Intercept & modify WebSocket frames |
| `NoopHandler` | struct | Pass-through `HttpHandler` (default) |
| `NoopWebSocketHandler` | struct | Pass-through `WebSocketHandler` |
| `HttpContext` | struct | Per-request metadata (id, host, client addr) |
| `Body` | enum | HTTP body — `Full(Bytes)` or `Streaming(Incoming)` |
| `RequestOrResponse` | enum | Handler return: forward request or short-circuit |
| `Direction` | enum | WebSocket frame direction (`ClientToServer` / `ServerToClient`) |
| `WebSocketMessage` | type alias | Re-export of `tungstenite::Message` |
| `full_body` | fn | Helper: `Full<Bytes>` from any `Into<Bytes>` |
| `ProxyError` | enum | All error variants |
| `Result<T>` | type alias | `std::result::Result<T, ProxyError>` |

### `ProxyBuilder` methods

| Method | Default | Description |
|---|---|---|
| `new()` | — | Create builder with sensible defaults |
| `with_addr(addr)` | `127.0.0.1:8080` | Bind address |
| `with_ca(ca)` | auto-creates | Certificate authority |
| `with_http_handler(h)` | `NoopHandler` | Set primary handler (replaces any existing) |
| `add_http_handler(h)` | — | Append handler to chain |
| `with_ws_handler(h)` | `None` | Set WebSocket frame handler |
| `with_request_buffer_size(n)` | `16384` | Per-request read buffer (bytes) |
| `build()` | — | Consume builder → `Result<Proxy>` |

### `HttpContext`

```rust
pub struct HttpContext {
    pub id: u64,              // unique request ID (mutable — set in handle_request)
    pub host: String,         // target hostname (e.g. "example.com")
    pub client_addr: SocketAddr, // client's socket address
    pub is_https: bool,       // true for CONNECT-tunneled (HTTPS), false for plain HTTP
}
```

### `Body`

```rust
pub enum Body {
    Streaming(hyper::body::Incoming),  // partial, streamed from upstream
    Full(Bytes),                        // fully buffered in memory
}

impl Body {
    pub async fn into_bytes(self) -> Result<Bytes>;  // collect & buffer
}

// Constructors
impl From<Bytes> for Body { ... }
impl From<hyper::body::Incoming> for Body { ... }
pub fn full_body(data: impl Into<Bytes>) -> Full<Bytes>;
```

---

## Custom `HttpHandler` — Recipes

### 1. Logging Handler

Log every request and response with a unique ID:

```rust
use std::sync::atomic::{AtomicU64, Ordering};
use async_trait::async_trait;
use http::{Request, Response};
use hexbuffer_proxy::{
    Body, HttpContext, HttpHandler, RequestOrResponse, Result,
};

struct Logger {
    counter: AtomicU64,
}

#[async_trait]
impl HttpHandler for Logger {
    async fn handle_request(
        &self,
        ctx: &mut HttpContext,
        request: Request<Body>,
    ) -> Result<RequestOrResponse> {
        let id = self.counter.fetch_add(1, Ordering::Relaxed);
        ctx.id = id; // downstream handlers see this ID
        eprintln!("[#{id:>04}] → {} {}", request.method(), request.uri());
        Ok(RequestOrResponse::Request(request))
    }

    async fn handle_response(
        &self,
        ctx: &mut HttpContext,
        response: Response<Body>,
    ) -> Result<Response<Body>> {
        eprintln!("[#{:>04}] ← {}", ctx.id, response.status());
        Ok(response)
    }
}
```

### 2. Modify Request Headers

Add or remove headers before the request reaches the upstream:

```rust
#[async_trait]
impl HttpHandler for AddUserAgent {
    async fn handle_request(
        &self,
        _ctx: &mut HttpContext,
        mut request: Request<Body>,
    ) -> Result<RequestOrResponse> {
        request.headers_mut().insert(
            "User-Agent",
            "hexbuffer-proxy/0.1".parse().unwrap(),
        );
        request.headers_mut().remove("X-Internal-Token");
        Ok(RequestOrResponse::Request(request))
    }

    async fn handle_response(
        &self,
        _ctx: &mut HttpContext,
        response: Response<Body>,
    ) -> Result<Response<Body>> {
        Ok(response)
    }
}
```

### 3. Short-Circuit (Block Requests)

Return a response immediately — the upstream is never contacted:

```rust
#[async_trait]
impl HttpHandler for BlockHost {
    async fn handle_request(
        &self,
        ctx: &mut HttpContext,
        _request: Request<Body>,
    ) -> Result<RequestOrResponse> {
        if ctx.host.contains("blocked-site.com") {
            let res = Response::builder()
                .status(403)
                .header("Content-Type", "text/plain")
                .body(Body::Full("blocked".into()))
                .unwrap();
            return Ok(RequestOrResponse::Response(res)); // short-circuit!
        }
        Ok(RequestOrResponse::Request(_request))
    }

    async fn handle_response(
        &self,
        _ctx: &mut HttpContext,
        response: Response<Body>,
    ) -> Result<Response<Body>> {
        Ok(response)
    }
}
```

### 4. Inspect & Modify Response Body

```rust
#[async_trait]
impl HttpHandler for StripAnalytics {
    async fn handle_request(
        &self,
        _ctx: &mut HttpContext,
        request: Request<Body>,
    ) -> Result<RequestOrResponse> {
        Ok(RequestOrResponse::Request(request))
    }

    async fn handle_response(
        &self,
        ctx: &mut HttpContext,
        response: Response<Body>,
    ) -> Result<Response<Body>> {
        // Only inspect text/html responses
        let is_html = response.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("text/html"))
            .unwrap_or(false);

        if !is_html {
            return Ok(response);
        }

        // Buffer the body
        let (parts, body) = response.into_parts();
        let bytes = body.into_bytes().await?;
        let mut html = String::from_utf8_lossy(&bytes).into_owned();

        // Modify: remove Google Analytics script tags
        html = html.replace(
            "www.googletagmanager.com",
            "",
        );

        eprintln!("[#{:>04}] stripped analytics from {}-byte HTML page",
            ctx.id, html.len());

        let new_body = Body::Full(html.into_bytes().into());
        Ok(Response::from_parts(parts, new_body))
    }
}
```

### 5. Chaining Multiple Handlers

Handlers run in order for **requests** and in **reverse** for **responses**:

```rust
ProxyBuilder::new()
    .with_ca(ca)
    .with_http_handler(Logger::new())       // runs 1st on request, last on response
    .add_http_handler(AddUserAgent)         // runs 2nd on request, 2nd-last on response
    .add_http_handler(BlockHost {           // runs 3rd on request, 1st on response
        blocked: vec!["evil.com".into()],
    })
    .build()?
    .start()
    .await?;
```

**Flow for a request that passes all handlers:**
```
Browser → Logger → AddUserAgent → BlockHost → [upstream] → BlockHost → AddUserAgent → Logger → Browser
```

**Flow for a short-circuit (BlockHost says "blocked"):**
```
Browser → Logger → AddUserAgent → BlockHost → [SHORT-CIRCUIT] → Logger → Browser
```
(BlockHost returns `Response(403)`, `AddUserAgent.handle_response` is skipped)

---

## WebSocket Handler

Intercept WebSocket frames after a successful 101 upgrade:

```rust
use hexbuffer_proxy::{Direction, WebSocketHandler, WebSocketMessage, HttpContext};
use http::Request;

struct WsInspector;

#[async_trait]
impl WebSocketHandler for WsInspector {
    async fn on_upgrade(
        &self,
        _ctx: &mut HttpContext,
        request: Request<Body>,
    ) -> Request<Body> {
        eprintln!("WebSocket upgrade: {}", request.uri());
        request
    }

    async fn on_frame(
        &self,
        _ctx: &mut HttpContext,
        frame: WebSocketMessage,
        direction: Direction,
    ) -> Option<WebSocketMessage> {
        match direction {
            Direction::ClientToServer => {
                // Inspect client→server frames
                if let WebSocketMessage::Text(ref t) = frame {
                    eprintln!("WS C→S: {t}");
                }
            }
            Direction::ServerToClient => {
                // Inspect server→client frames
                if let WebSocketMessage::Binary(ref b) = frame {
                    eprintln!("WS S→C: {} bytes", b.len());
                }
            }
        }
        Some(frame) // return Some to forward, None to drop
    }

    async fn on_close(&self, _ctx: &mut HttpContext) {
        eprintln!("WebSocket closed");
    }
}

// Register it:
ProxyBuilder::new()
    .with_ca(ca)
    .with_ws_handler(WsInspector)
    .build()?
    .start()
    .await?;
```

When no `WebSocketHandler` is registered, WebSocket traffic is relayed as raw bytes (no frame-level interception).

### `WebSocketMessage` variants

`WebSocketMessage` is a re-export of `tungstenite::Message`:

| Variant | Content |
|---|---|
| `Text(String)` | UTF-8 text frame |
| `Binary(Vec<u8>)` | Binary data frame |
| `Ping(Vec<u8>)` | Ping (keep-alive) |
| `Pong(Vec<u8>)` | Pong (keep-alive response) |
| `Close(Option<CloseFrame>)` | Connection close with optional reason |
| `Frame(Frame)` | Raw frame |

---

## Graceful Shutdown

The proxy blocks on `.start()`. Use `tokio::select!` to add Ctrl+C handling:

```rust
tokio::select! {
    result = proxy.start() => {
        if let Err(e) = result {
            eprintln!("Proxy error: {e}");
        }
    }
    _ = tokio::signal::ctrl_c() => {
        eprintln!("Shutting down...");
    }
}
```

---

## CA Certificate

The CA certificate is loaded from `cert/ca.pem` if it exists, or generated fresh on first run. Trust it in your system for HTTPS interception to work:

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot -k \
  /Library/Keychains/System.keychain cert/ca.pem
```

**Linux (Firefox):**
Preferences → Privacy & Security → Certificates → View Certificates → Authorities → Import `cert/ca.pem`

**Windows:**
```
certutil -addstore Root cert/ca.pem
```

---

## Error Handling

All handler methods return `hexbuffer_proxy::Result<T>`, which is `std::result::Result<T, ProxyError>`:

```rust
pub enum ProxyError {
    Io(std::io::Error),
    Tls(rustls::Error),
    Hyper(hyper::Error),
    Http(http::Error),
    Cert(String),
    Connection(String),
    Protocol(String),
}
```

Common error conversions (via `thiserror`'s `#[from]`):
- `std::io::Error` → `ProxyError::Io`
- `rustls::Error` → `ProxyError::Tls`
- `hyper::Error` → `ProxyError::Hyper`
- `http::Error` → `ProxyError::Http`

Use `?` freely in handler methods — any `io::Error`, `hyper::Error`, etc. will auto-convert.

---

## Architecture

```
Browser ──TCP──▶ hexbuffer-proxy ──Hyper──▶ Upstream Server
                     │                (pooled, HTTP/2)
                     │
    ┌────────────────┼────────────────┐
    │  Handler Stack (chain)         │
    │  ┌──────────┐                  │
    │  │ H1: Logger │ → request     │
    │  │ H2: WAF    │ → request     │
    │  │ H3: Modify │ → request     │
    │  └──────────┘                  │
    │  Response chain runs in        │
    │  reverse: H3 → H2 → H1        │
    └────────────────────────────────┘
                     │
              ┌──────┴──────┐
              │  WebSocket?  │
              │  relay_framed│ ← WebSocketHandler::on_frame
              │  or raw relay│
              └──────────────┘
```

- **Upstream transport**: shared Hyper client with `LazyLock`-pooled connections, HTTP/2 ALPN negotiation, transparent body decompression via tower-http `DecompressionLayer` (gzip, deflate, brotli, zstd)
- **Handler pipeline**: `HttpHandler` chain for request/response interception, `WebSocketHandler` for frame-level interception
- **HTTPS MITM**: dynamic TLS certificate forging per domain via `rcgen`, trusted through the local CA

---

## Full Example

See [`src/main.rs`](../src/main.rs) for a complete working example with:
- `LoggingHandler` — assigns request IDs, logs method/URI/status/size with direction icons
- `BlocklistHandler` — blocks ad/tracking hosts (doubleclick.net, google-analytics.com, googletagmanager.com) with 403
- `WsLogger` — logs every WebSocket frame (text size, binary size, ping/pong, close reason)
- Graceful Ctrl+C shutdown

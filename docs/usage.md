# hexbuffer-proxy — Library Usage Guide

## Overview

`hexbuffer-proxy` is a high-performance HTTPS MITM (Man-in-the-Middle) proxy library for Rust built on **Tokio**, **Hyper**, and **rustls**. It provides connection pooling, WebSocket frame-level interception, and dynamic TLS certificate forging.

```toml
[dependencies]
hexbuffer-proxy = { path = "." }   # or git/crates.io
tokio = { version = "1", features = ["full"] }
tokio-rustls = "0.26"
anyhow = "1"
async-trait = "0.1"
http = "1"
bytes = "1"
```

### Feature Flags

| Feature | Default | Description |
|---|---|---|
| `decoder` | **Enabled** | Application-level request/response body decompression (`decode_request`, `decode_response`), re-encoding (`encode_body`), and `DecodeHandler` plugin for gzip, deflate, brotli, and zstd. |

---

## Quick Start — Minimal Proxy

```rust
use hexbuffer_proxy::{CertificationAuthority, ProxyBuilder};
use tokio_rustls::rustls::crypto::aws_lc_rs::default_provider;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Install rustls crypto provider (required before any TLS operations)
    let _ = default_provider().install_default();

    // 2. Initialize CA (loads from or creates cert/ca.pem and cert/ca-key.pem)
    let ca = CertificationAuthority::new();

    // 3. Build and run the proxy (defaults to 127.0.0.1:8080 and pass-through NoopHandler)
    ProxyBuilder::new()
        .with_ca(ca)
        .build()?
        .start()
        .await?;

    Ok(())
}
```

This starts a pass-through proxy listening on `127.0.0.1:8080`. Configure your application or browser to proxy through `127.0.0.1:8080` and trust `cert/ca.pem` for HTTPS interception.

---

## Public API Reference

### Re-exports (Crate Root)

All primary types and traits are re-exported at the crate root (`hexbuffer_proxy::*`):

| Symbol | Kind | Origin Module | Description |
|---|---|---|---|
| [`ProxyBuilder`](#proxybuilder) | `struct` | `builder` | Builder-pattern proxy configuration and assembly |
| [`Proxy`](#proxy) | `struct` | `builder` | Ready-to-run proxy instance |
| [`CertificationAuthority`](#certificationauthority) | `struct` | `ca` | CA certificate authority & per-domain certificate forging |
| [`HttpHandler`](#httphandler-trait) | `trait` | `handler` | Trait for inspecting/modifying HTTP requests & responses |
| [`WebSocketHandler`](#websockethandler-trait) | `trait` | `handler` | Trait for inspecting/modifying WebSocket frames |
| [`NoopHandler`](#noop-handlers) | `struct` | `handler` | Pass-through `HttpHandler` implementation (default) |
| [`NoopWebSocketHandler`](#noop-handlers) | `struct` | `handler` | Pass-through `WebSocketHandler` implementation |
| [`HttpContext`](#httpcontext) | `struct` | `handler` | Metadata for an intercepted HTTP request/response pair |
| [`Body`](#body) | `enum` | `handler` | HTTP body representation (`Streaming` or `Full`) |
| [`RequestOrResponse`](#requestorresponse) | `enum` | `handler` | Return value of `handle_request` (forward vs. short-circuit) |
| [`Direction`](#direction) | `enum` | `handler` | WebSocket frame direction (`ClientToServer` / `ServerToClient`) |
| [`WebSocketMessage`](#websocketmessage) | `type` | `handler` | Re-export of `tokio_tungstenite::tungstenite::Message` |
| [`full_body`](#full_body) | `fn` | `handler` | Helper function creating `Full<Bytes>` body from bytes |
| [`ProxyError`](#proxyerror) | `enum` | `error` | Error variants returned by proxy operations |
| [`Result<T>`](#resultt) | `type` | `error` | Alias for `std::result::Result<T, ProxyError>` |
| [`decoder`](#decoder-module-feature--decoder) | `module` | `decoder` | Application-level body decompression/re-encoding module (`#[cfg(feature = "decoder")]`) |

---

### `ProxyBuilder`

Builder for assembling and configuring a [`Proxy`].

#### Methods

##### `pub fn new() -> Self`
Creates a `ProxyBuilder` with default settings:
- Bind address: `127.0.0.1:8080`
- Request read buffer size: `16384` bytes (16 KB)
- Enabled state: `true`
- Default CA directory: `"cert"`

##### `pub fn with_addr(mut self, addr: impl Into<SocketAddr>) -> Self`
Sets the socket address for the proxy server to bind to.

##### `pub fn with_ca(mut self, ca: CertificationAuthority) -> Self`
Provides an explicit [`CertificationAuthority`] instance for forging TLS certificates. Overrides any `cert_dir` configuration.

##### `pub fn with_http_handler(mut self, handler: impl HttpHandler + 'static) -> Self`
Sets the primary HTTP handler. Replaces any previously registered HTTP handlers.

##### `pub fn add_http_handler(mut self, handler: impl HttpHandler + 'static) -> Self`
Appends an HTTP handler to the pipeline (Chain of Responsibility pattern). Multiple handlers run in insertion order for requests and in reverse order for responses.

##### `pub fn with_ws_handler(mut self, handler: impl WebSocketHandler + 'static) -> Self`
Sets the WebSocket frame handler for inspecting and modifying WebSocket connections after an HTTP 101 upgrade.

##### `pub fn with_request_buffer_size(mut self, size: usize) -> Self`
Configures the per-request read buffer size in bytes (default: `16384`).

##### `pub fn with_enabled(self, enabled: bool) -> Self`
Sets the initial enabled state of the proxy (default: `true`). When set to `false`, TLS interception is bypassed (`should_intercept_tls` returns `false`), allowing CONNECT tunnels to pass through as raw TCP streams.

##### `pub fn enabled_flag(&self) -> Arc<AtomicBool>`
Returns a shared handle (`Arc<AtomicBool>`) to the atomic enabled flag prior to building.

##### `pub fn with_cert_dir(mut self, dir: impl Into<PathBuf>) -> Self`
Sets a custom directory path for persisting CA certificate files (`ca.pem` and `ca-key.pem`). Used only if no explicit CA was provided via `with_ca`.

##### `pub fn build(self) -> Result<Proxy>`
Consumes the builder and returns a ready-to-run [`Proxy`] instance.

##### `impl Default for ProxyBuilder`
`ProxyBuilder::default()` is equivalent to `ProxyBuilder::new()`.

---

### `Proxy`

A fully assembled proxy server created by [`ProxyBuilder::build`].

#### Methods

##### `pub fn is_enabled(&self) -> bool`
Returns `true` if the proxy is currently enabled for TLS interception and handling, or `false` if disabled.

##### `pub fn set_enabled(&self, enabled: bool)`
Dynamically enables or disables proxy interception at runtime across all active and new client connections.

##### `pub fn enable(&self)`
Convenience method to set proxy state to enabled (`set_enabled(true)`).

##### `pub fn disable(&self)`
Convenience method to set proxy state to disabled (`set_enabled(false)`). When disabled, TLS interception is bypassed and CONNECT requests pass through as raw TCP tunnels.

##### `pub fn enabled_flag(&self) -> Arc<AtomicBool>`
Returns a shared handle (`Arc<AtomicBool>`) to the atomic enabled flag controlling the proxy's active state.

##### `pub async fn start(self) -> Result<()>`
Binds the TCP listener to the configured address and runs the asynchronous client accept loop. This method runs indefinitely until cancelled or an unrecoverable bind error occurs.

---

### `CertificationAuthority`

Handles self-signed CA generation, file persistence, and dynamic per-host TLS certificate forging.

#### Methods

##### `pub fn new() -> Self`
Creates a CA with key/certificate files persisted under the default `"cert/"` directory (`ca.pem` and `ca-key.pem`). If existing keys are found on disk, they are loaded automatically.

##### `pub fn new_in(dir: impl Into<PathBuf>) -> Self`
Creates a CA with key/certificate files persisted under the specified custom directory.

##### `pub fn save_ca_to_pem(&self, check_path: &str) -> std::io::Result<()>`
Exports the CA certificate to disk in PEM format (using standard 64-character line wrapping).

##### `pub fn save_key_to_pem(&self, check_path: &str) -> std::io::Result<()>`
Exports the CA private key to disk in PEM format.

##### `pub fn forge_certificate(&self, host: &str) -> (Vec<u8>, Vec<u8>)`
Generates (or retrieves from the internal read/write locked cache) a forged DER-encoded TLS certificate and private key for the given hostname. Returns `(cert_der, key_der)`.

---

### `HttpHandler` (trait)

Core trait for inspecting or mutating HTTP traffic flowing through the proxy.

```rust
#[async_trait]
pub trait HttpHandler: Send + Sync {
    async fn handle_request(
        &self,
        ctx: &mut HttpContext,
        request: Request<Body>,
    ) -> Result<RequestOrResponse>;

    async fn handle_response(
        &self,
        ctx: &mut HttpContext,
        response: Response<Body>,
    ) -> Result<Response<Body>>;

    async fn should_intercept_tls(&self, _host: &str) -> bool {
        true
    }
}
```

#### Trait Methods

##### `async fn handle_request(&self, ctx: &mut HttpContext, request: Request<Body>) -> Result<RequestOrResponse>`
Called before sending a request to the upstream server.
- Return `Ok(RequestOrResponse::Request(modified_req))` to forward the request.
- Return `Ok(RequestOrResponse::Response(short_circuit_res))` to return a response directly to the client without contacting the upstream.

##### `async fn handle_response(&self, ctx: &mut HttpContext, response: Response<Body>) -> Result<Response<Body>>`
Called when an upstream response is received before sending it back to the client.

##### `async fn should_intercept_tls(&self, host: &str) -> bool`
Polled before establishing a TLS CONNECT tunnel. Return `false` to skip MITM decryption and pass raw TCP bytes through (useful for cert-pinned domains like `gemini.google.com`). Defaults to `true`.

---

### `WebSocketHandler` (trait)

Trait for frame-level inspection and modification of WebSocket traffic.

```rust
#[async_trait]
pub trait WebSocketHandler: Send + Sync {
    async fn on_upgrade(
        &self,
        _ctx: &mut HttpContext,
        request: Request<Body>,
    ) -> Request<Body> {
        request
    }

    async fn on_frame(
        &self,
        _ctx: &mut HttpContext,
        frame: WebSocketMessage,
        _direction: Direction,
    ) -> Option<WebSocketMessage> {
        Some(frame)
    }

    async fn on_close(&self, _ctx: &mut HttpContext) {}
}
```

#### Trait Methods

##### `async fn on_upgrade(&self, ctx: &mut HttpContext, request: Request<Body>) -> Request<Body>`
Called when a WebSocket upgrade request (HTTP 101) is detected before forwarding upstream. Default implementation returns `request` unchanged.

##### `async fn on_frame(&self, ctx: &mut HttpContext, frame: WebSocketMessage, direction: Direction) -> Option<WebSocketMessage>`
Called for every WebSocket frame exchanged between client and server.
- Return `Some(modified_frame)` to pass the frame through.
- Return `None` to drop the frame.

##### `async fn on_close(&self, ctx: &mut HttpContext)`
Called when the WebSocket connection is closed by either client or server. Default implementation is a no-op.

---

### Data Types & Structs

#### `HttpContext`

Per-request metadata passed through the handler chain.

```rust
pub struct HttpContext {
    pub id: u64,              // Unique request ID (mutable by handlers)
    pub host: String,         // Target host (e.g., "example.com")
    pub client_addr: SocketAddr, // Address of client socket
    pub is_https: bool,       // true for HTTPS CONNECT tunnels, false for plain HTTP
}
```

#### `Body`

HTTP body representation:

```rust
pub enum Body {
    Streaming(BoxBody<Bytes, hyper::Error>), // Streamed live response from upstream
    Full(Bytes),                             // Pre-buffered body in memory
}
```

##### Methods & Conversions
- `pub async fn into_bytes(self) -> Result<Bytes>`: Asynchronously collects and buffers streaming or full body bytes into memory.
- `impl From<Bytes> for Body`: Converts `Bytes` into `Body::Full`.
- `impl From<hyper::body::Incoming> for Body`: Converts a `hyper::body::Incoming` body into `Body::Streaming`.

#### `full_body`

```rust
pub fn full_body(data: impl Into<Bytes>) -> Full<Bytes>
```
Helper function wrapping bytes into an `http_body_util::Full<Bytes>` structure.

#### `RequestOrResponse`

Enum returned by `HttpHandler::handle_request`:

```rust
pub enum RequestOrResponse {
    Request(Request<Body>),   // Forward request upstream
    Response(Response<Body>), // Short-circuit response to client
}
```

#### `Direction`

Indicates direction of a WebSocket frame:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}
```

#### `WebSocketMessage`

Type alias for `tokio_tungstenite::tungstenite::Message`:
- `Text(String)` — UTF-8 text frame
- `Binary(Vec<u8>)` — Binary data frame
- `Ping(Vec<u8>)` — Ping keep-alive frame
- `Pong(Vec<u8>)` — Pong response frame
- `Close(Option<CloseFrame>)` — Close frame with status code and reason
- `Frame(Frame)` — Raw low-level frame

#### No-op Handlers

- `NoopHandler`: Default `HttpHandler` implementation that passes requests and responses through untouched.
- `NoopWebSocketHandler`: Default `WebSocketHandler` implementation that passes frames through untouched.

---

### `ProxyError` & `Result`

#### `ProxyError`

```rust
#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS error: {0}")]
    Tls(#[from] tokio_rustls::rustls::Error),

    #[error("HTTP error: {0}")]
    Hyper(#[from] hyper::Error),

    #[error("invalid HTTP: {0}")]
    Http(#[from] http::Error),

    #[error("certificate error: {0}")]
    Cert(String),

    #[error("connection failed: {0}")]
    Connection(String),

    #[error("protocol error: {0}")]
    Protocol(String),
}
```

#### `Result<T>`

```rust
pub type Result<T> = std::result::Result<T, ProxyError>;
```

---

### `decoder` Module (Feature: `decoder`)

The `hexbuffer_proxy::decoder` module provides manual and pluggable application-level body decompression and re-compression for HTTP requests and responses.

#### `DecodeHandler`

```rust
pub struct DecodeHandler;
```
An [`HttpHandler`] plugin that automatically decodes compressed `Content-Encoding` request and response bodies in the handler pipeline.

#### `pub async fn decode_request(req: Request<Body>) -> Result<Request<Body>>`
Decompresses a request body in-place according to its `Content-Encoding` header (gzip, deflate, brotli, zstd) and removes `Content-Encoding` and `Content-Length` headers. Uncompressed bodies pass through untouched.

#### `pub async fn decode_response(res: Response<Body>) -> Result<Response<Body>>`
Decompresses a response body in-place according to its `Content-Encoding` header and removes encoding headers.

#### `pub fn encode_body(body: Body, encoding: &str, charset: Option<&str>) -> Result<Body>`
Re-compresses a buffered `Body::Full` with the specified encoding (`"gzip"`, `"deflate"`, `"br"`, `"zstd"`).

---

## Usage Recipes

### 1. Request & Response Logging Handler

```rust
use std::sync::atomic::{AtomicU64, Ordering};
use async_trait::async_trait;
use http::{Request, Response};
use hexbuffer_proxy::{Body, HttpContext, HttpHandler, RequestOrResponse, Result};

pub struct Logger {
    counter: AtomicU64,
}

impl Logger {
    pub fn new() -> Self {
        Self { counter: AtomicU64::new(1) }
    }
}

#[async_trait]
impl HttpHandler for Logger {
    async fn handle_request(
        &self,
        ctx: &mut HttpContext,
        request: Request<Body>,
    ) -> Result<RequestOrResponse> {
        let id = self.counter.fetch_add(1, Ordering::Relaxed);
        ctx.id = id;
        println!("[#{id:04}] -> {} {}", request.method(), request.uri());
        Ok(RequestOrResponse::Request(request))
    }

    async fn handle_response(
        &self,
        ctx: &mut HttpContext,
        response: Response<Body>,
    ) -> Result<Response<Body>> {
        println!("[#{:04}] <- {}", ctx.id, response.status());
        Ok(response)
    }
}
```

### 2. Modifying Request Headers

```rust
#[async_trait]
impl HttpHandler for HeaderModifier {
    async fn handle_request(
        &self,
        _ctx: &mut HttpContext,
        mut request: Request<Body>,
    ) -> Result<RequestOrResponse> {
        request.headers_mut().insert("User-Agent", "CustomProxy/1.0".parse().unwrap());
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

### 3. Short-Circuiting (Blocking & Mocking Requests)

Short-circuiting skips contacting upstream servers completely:

```rust
#[async_trait]
impl HttpHandler for HostBlocker {
    async fn handle_request(
        &self,
        ctx: &mut HttpContext,
        _request: Request<Body>,
    ) -> Result<RequestOrResponse> {
        if ctx.host.contains("blocked-domain.com") {
            let res = Response::builder()
                .status(403)
                .header("Content-Type", "text/plain")
                .body(Body::Full("Blocked by Proxy".into()))
                .unwrap();
            return Ok(RequestOrResponse::Response(res));
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

### 4. Inspecting & Modifying Response Body

```rust
#[async_trait]
impl HttpHandler for HtmlInjector {
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
        let is_html = response.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("text/html"))
            .unwrap_or(false);

        if !is_html {
            return Ok(response);
        }

        let (parts, body) = response.into_parts();
        let bytes = body.into_bytes().await?;
        let mut html = String::from_utf8_lossy(&bytes).into_owned();

        html = html.replace("</body>", "<!-- Injected by hexbuffer-proxy --></body>");

        Ok(Response::from_parts(parts, Body::Full(html.into_bytes().into())))
    }
}
```

### 5. Selective TLS Interception Bypass (`should_intercept_tls`)

Bypass MITM certificate forging for hosts that use certificate pinning (e.g. Google services or native desktop applications):

```rust
struct BypassCertPinnedHosts;

#[async_trait]
impl HttpHandler for BypassCertPinnedHosts {
    async fn handle_request(
        &self,
        _ctx: &mut HttpContext,
        req: Request<Body>,
    ) -> Result<RequestOrResponse> {
        Ok(RequestOrResponse::Request(req))
    }

    async fn handle_response(
        &self,
        _ctx: &mut HttpContext,
        res: Response<Body>,
    ) -> Result<Response<Body>> {
        Ok(res)
    }

    async fn should_intercept_tls(&self, host: &str) -> bool {
        // Skip TLS MITM for specific domains (relays raw TCP)
        if host.ends_with("google.com") || host == "apple.com" {
            return false;
        }
        true
    }
}
```

### 6. Dynamic Runtime Enable / Disable Toggle

```rust
let proxy = ProxyBuilder::new()
    .with_ca(ca)
    .with_enabled(true)
    .build()?;

let proxy_control = proxy.enabled_flag();

// In another async task or UI thread:
proxy_control.store(false, std::sync::atomic::Ordering::Relaxed); // Disables TLS interception dynamically
proxy.enable();  // Convenience method to re-enable
proxy.disable(); // Convenience method to disable
```

### 7. WebSocket Inspection Handler

```rust
use hexbuffer_proxy::{Direction, WebSocketHandler, WebSocketMessage, HttpContext, Body};
use http::Request;

struct WsLogger;

#[async_trait]
impl WebSocketHandler for WsLogger {
    async fn on_upgrade(
        &self,
        _ctx: &mut HttpContext,
        request: Request<Body>,
    ) -> Request<Body> {
        println!("WebSocket Upgrade: {}", request.uri());
        request
    }

    async fn on_frame(
        &self,
        _ctx: &mut HttpContext,
        frame: WebSocketMessage,
        direction: Direction,
    ) -> Option<WebSocketMessage> {
        match direction {
            Direction::ClientToServer => println!("WS C->S: {:?}", frame),
            Direction::ServerToClient => println!("WS S->C: {:?}", frame),
        }
        Some(frame) // Return None to drop frame
    }

    async fn on_close(&self, _ctx: &mut HttpContext) {
        println!("WebSocket Connection Closed");
    }
}
```

---

## Graceful Shutdown

Handle Ctrl+C signals gracefully using `tokio::select!`:

```rust
let proxy = ProxyBuilder::new().build()?;

tokio::select! {
    res = proxy.start() => {
        if let Err(e) = res {
            eprintln!("Proxy server error: {e}");
        }
    }
    _ = tokio::signal::ctrl_c() => {
        println!("Shutting down proxy listener...");
    }
}
```

---

## CA Certificate Installation

For HTTPS interception to function without client SSL warnings, trust `cert/ca.pem` in your environment:

### macOS
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain cert/ca.pem
```

### Linux (Ubuntu/Debian)
```bash
sudo cp cert/ca.pem /usr/local/share/ca-certificates/hexbuffer-proxy-ca.crt
sudo update-ca-certificates
```

### Windows
```cmd
certutil -addstore Root cert\ca.pem
```

---

## Architecture Overview

```
Client (Browser/App)
       │
       ▼ [TCP / TLS CONNECT]
┌─────────────────────────────────────────────────────────────┐
│ hexbuffer-proxy                                             │
│                                                             │
│  1. Check `should_intercept_tls(host)` & `is_enabled()`     │
│     ├─ False ──► Raw TCP Tunneling (Passthrough)           │
│     └─ True  ──► On-the-fly CA Certificate Forging (rcgen)  │
│                                                             │
│  2. HTTP Request Pipeline (HttpHandler chain)               │
│     Handler 1 ──► Handler 2 ──► Handler 3 (handle_request)  │
│     │                                                       │
│     ├─ Short-Circuit Response ──► Return to Client          │
│     └─ Forward Request                                      │
│                                                             │
│  3. Upstream Connection (Hyper client pool, HTTP/1.1)           │
│                                                             │
│  4. HTTP Response Pipeline (Reverse HttpHandler chain)      │
│     Handler 3 ◄── Handler 2 ◄── Handler 1 (handle_response) │
│                                                             │
│  5. WebSocket Upgrade (Optional WebSocketHandler)           │
│     Frame Interception (on_frame, Direction::C2S / S2C)     │
└─────────────────────────────────────────────────────────────┘
       │
       ▼ [HTTP/1.1]
Upstream Server
```

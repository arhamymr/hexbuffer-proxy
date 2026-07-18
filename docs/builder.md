# ProxyBuilder

The `ProxyBuilder` configures and launches the proxy. Drop-in replacement for the manual accept loop.

## Quick Start

```rust
use hexbuffer_proxy::builder::ProxyBuilder;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();

    ProxyBuilder::new()
        .build()?
        .start()
        .await?;

    Ok(())
}
```

## Configuration Options

| Method | Default | Description |
|--------|---------|-------------|
| `with_addr(addr)` | `127.0.0.1:8080` | Bind address |
| `with_ca(ca)` | auto-generated | Certificate authority |
| `with_http_handler(h)` | `NoopHandler` | Primary handler (replaces existing) |
| `add_http_handler(h)` | — | Append to handler chain |
| `with_request_buffer_size(n)` | `16384` | Per-request read buffer (bytes) |

## Custom Address

```rust
ProxyBuilder::new()
    .with_addr("0.0.0.0:9090")
    .build()?
    .start()
    .await?;
```

## Single Handler

```rust
use hexbuffer_proxy::handler::{HttpHandler, HttpContext, RequestOrResponse, Body};

struct LogHandler;

#[async_trait::async_trait]
impl HttpHandler for LogHandler {
    async fn handle_request(
        &self,
        ctx: &mut HttpContext,
        req: http::Request<Body>,
    ) -> hexbuffer_proxy::error::Result<RequestOrResponse> {
        println!("→ {} {} [{}]", req.method(), req.uri(), ctx.host);
        Ok(RequestOrResponse::Request(req))
    }

    async fn handle_response(
        &self,
        ctx: &mut HttpContext,
        res: http::Response<Body>,
    ) -> hexbuffer_proxy::error::Result<http::Response<Body>> {
        println!("← {} [{}]", res.status(), ctx.host);
        Ok(res)
    }
}

ProxyBuilder::new()
    .with_http_handler(LogHandler)
    .build()?
    .start()
    .await?;
```

## Handler Stack (Chain of Responsibility)

Each handler sees the output of the previous. Short-circuit stops the chain.

```rust
ProxyBuilder::new()
    .with_http_handler(AuthHandler)      // runs 1st
    .add_http_handler(RateLimitHandler)  // runs 2nd
    .add_http_handler(LogHandler)        // runs 3rd
    .build()?
    .start()
    .await?;
```

## Short-Circuit Requests

Return `RequestOrResponse::Response(res)` to respond without contacting upstream.

```rust
struct BlockAds;

#[async_trait::async_trait]
impl HttpHandler for BlockAds {
    async fn handle_request(
        &self,
        _: &mut HttpContext,
        req: http::Request<Body>,
    ) -> hexbuffer_proxy::error::Result<RequestOrResponse> {
        if req.uri().host().map_or(false, |h| h.contains("ads")) {
            let res = http::Response::builder()
                .status(403)
                .body(Body::Full(bytes::Bytes::from("blocked")))
                .unwrap();
            return Ok(RequestOrResponse::Response(res));
        }
        Ok(RequestOrResponse::Request(req))
    }

    async fn handle_response(
        &self,
        _: &mut HttpContext,
        res: http::Response<Body>,
    ) -> hexbuffer_proxy::error::Result<http::Response<Body>> {
        Ok(res)
    }
}
```

## Custom Buffer Size

```rust
ProxyBuilder::new()
    .with_request_buffer_size(65536) // 64KB
    .build()?
    .start()
    .await?;
```

## Custom CA

```rust
use hexbuffer_proxy::ca::CertificationAuthority;

let ca = CertificationAuthority::new(); // or load from disk

ProxyBuilder::new()
    .with_ca(ca)
    .build()?
    .start()
    .await?;
```

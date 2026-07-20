use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hexbuffer_proxy::{CertificationAuthority, Body};
use http::Response;

fn bench_parse_raw_request(c: &mut Criterion) {
    let get_request_bytes = b"GET /api/v1/users?page=1&limit=20 HTTP/1.1\r\n\
Host: api.example.com\r\n\
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)\r\n\
Accept: application/json\r\n\
Authorization: Bearer token1234567890\r\n\
Connection: keep-alive\r\n\r\n";

    c.bench_function("parse_raw_request_get", |b| {
        b.iter(|| {
            let _ = black_box(get_request_bytes);
        });
    });
}

fn bench_serialize_response(c: &mut Criterion) {
    let res = Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .header("server", "hexbuffer-proxy")
        .body(Body::Full(bytes::Bytes::from(r#"{"status":"ok","count":42}"#)))
        .unwrap();

    c.bench_function("serialize_response_json", |b| {
        b.iter(|| {
            let _ = black_box(&res);
        });
    });
}

fn bench_ca_forge_certificate(c: &mut Criterion) {
    let ca = CertificationAuthority::new();
    
    // Warm up cache for "cached.example.com"
    ca.forge_certificate("cached.example.com");

    c.bench_function("ca_forge_certificate_cache_hit", |b| {
        b.iter(|| {
            let certs = ca.forge_certificate(black_box("cached.example.com"));
            black_box(certs);
        });
    });
}

criterion_group!(benches, bench_parse_raw_request, bench_serialize_response, bench_ca_forge_certificate);
criterion_main!(benches);

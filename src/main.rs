mod ca;
mod parser;
mod proxy;
mod error;
mod handler;
mod builder;

use builder::ProxyBuilder;

// tokio
use tokio_rustls::rustls::crypto::aws_lc_rs::default_provider;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = default_provider().install_default();
    let ca = ca::CertificationAuthority::new();

    ProxyBuilder::new()
        .with_ca(ca)
        .build()?
        .start()
        .await?;

    Ok(())
}

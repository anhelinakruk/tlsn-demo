mod balance_verifier;
mod connect;
mod service;
mod tls;

use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "demo=debug,salvo=info".into()),
        )
        .init();

    let swissbank_addr: SocketAddr = tokio::net::lookup_host("swissbank.tlsnotary.org:443")
        .await
        .expect("resolve swissbank.tlsnotary.org")
        .next()
        .expect("at least one address");

    let listen_addr: SocketAddr = "0.0.0.0:8444".parse().unwrap();

    service::serve(service::ServiceConfig {
        listen_addr,
        asset_dir: std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("assets"),
        cert_dir: std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".cert"),
        allowed_target: swissbank_addr,
        allowed_host: "swissbank.tlsnotary.org".into(),
    })
    .await
    .expect("server error");
}

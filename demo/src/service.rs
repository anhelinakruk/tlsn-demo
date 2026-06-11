use std::{net::SocketAddr, sync::Arc};

use salvo::{
    affix_state, async_trait, handler,
    conn::rustls::{Keycert, RustlsConfig},
    http::{
        StatusCode, StatusError,
        header::{HeaderName, HeaderValue},
    },
    prelude::{Depot, FlowCtrl, Listener, QuinnListener, Request, Response, Router, Server, TcpListener, Writer},
    serve_static::StaticDir,
    writing::Text,
};
use sha2::{Digest, Sha256};

use crate::{connect::ProxyConfig, tls};

const COOP: HeaderName = HeaderName::from_static("cross-origin-opener-policy");
const COEP: HeaderName = HeaderName::from_static("cross-origin-embedder-policy");
const CORP: HeaderName = HeaderName::from_static("cross-origin-resource-policy");

#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub listen_addr: SocketAddr,
    pub asset_dir: std::path::PathBuf,
    pub allowed_target: SocketAddr,
    pub allowed_host: String,
    pub server_cert_der: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Tls(#[from] tls::TlsError),
    #[error("page state missing from depot")]
    PageStateMissing,
}

#[async_trait]
impl Writer for ServeError {
    async fn write(self, _req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        tracing::error!(error = %self, "demo.service.request.failed");
        res.render(StatusError::internal_server_error());
    }
}

#[derive(Debug, Clone)]
pub struct PageState {
    pub cert_hash_hex: String,
    pub server_cert_der_hex: String,
}

pub async fn serve(config: ServiceConfig) -> Result<(), ServeError> {
    let server_tls = tls::generate_self_signed("localhost")?;
    let cert_hash_hex = sha256_hex(&server_tls.cert_der);

    let page_state = Arc::new(PageState {
        cert_hash_hex: cert_hash_hex.clone(),
        server_cert_der_hex: hex::encode(&config.server_cert_der),
    });

    let proxy_config = Arc::new(ProxyConfig {
        allowed_target: config.allowed_target,
        allowed_host: config.allowed_host,
        server_cert_der: config.server_cert_der,
    });

    tracing::info!(
        listen = %config.listen_addr,
        cert_sha256 = %cert_hash_hex,
        "demo.service.listening"
    );

    let rustls_config = RustlsConfig::new(
        Keycert::new()
            .cert(server_tls.cert_pem.as_bytes())
            .key(server_tls.key_pem.as_bytes()),
    );
    let acceptor = QuinnListener::new(rustls_config.clone(), config.listen_addr)
        .join(TcpListener::new(config.listen_addr).rustls(rustls_config))
        .bind()
        .await;

    let wasm_dir = config.asset_dir.join("wasm");
    let router = Router::new()
        .hoop(cross_origin_isolation)
        .hoop(affix_state::inject(page_state))
        .hoop(affix_state::inject(proxy_config))
        .push(Router::with_path("connect").goal(crate::connect::handle))
        .push(Router::with_path("favicon.ico").get(empty_no_content))
        .push(Router::with_path("zktls").get(render_index))
        .push(
            Router::with_path("assets/wasm/{**}")
                .hoop(wasm_cache_headers)
                .get(StaticDir::new([wasm_dir])),
        )
        .push(Router::with_path("assets/{**}").get(StaticDir::new([config.asset_dir])))
        .get(render_index);

    Server::new(acceptor).serve(router).await;
    Ok(())
}

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[handler]
async fn cross_origin_isolation(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    ctrl.call_next(req, depot, res).await;
    let h = res.headers_mut();
    h.insert(COOP, HeaderValue::from_static("same-origin"));
    h.insert(COEP, HeaderValue::from_static("require-corp"));
    h.insert(CORP, HeaderValue::from_static("same-origin"));
}

#[handler]
async fn wasm_cache_headers(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    ctrl.call_next(req, depot, res).await;
    res.headers_mut().insert(
        HeaderName::from_static("cache-control"),
        HeaderValue::from_static("public, max-age=3600, immutable"),
    );
}

#[handler]
async fn render_index(depot: &mut Depot, res: &mut Response) -> Result<(), ServeError> {
    let state = depot
        .obtain::<Arc<PageState>>()
        .map_err(|_| ServeError::PageStateMissing)?;
    let html = index_html(&state.cert_hash_hex, &state.server_cert_der_hex);
    res.render(Text::Html(html));
    Ok(())
}

#[handler]
async fn empty_no_content(res: &mut Response) {
    res.status_code(StatusCode::NO_CONTENT);
}

fn index_html(cert_hash_hex: &str, server_cert_der_hex: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Swiss Bank Balance Proof</title></head>
<body
  data-cert-hash="{cert_hash_hex}"
  data-server-cert-der-hex="{server_cert_der_hex}"
>
  <h1>Swiss Bank Balance Proof</h1>
  <button id="prove-btn">Prove my CHF balance</button>
  <pre id="log"></pre>
  <script type="module" src="/assets/zktls.main.mjs"></script>
</body>
</html>"#
    )
}

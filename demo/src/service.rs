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
    pub cert_dir: std::path::PathBuf,
    pub allowed_target: SocketAddr,
    pub allowed_host: String,
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
}

pub async fn serve(config: ServiceConfig) -> Result<(), ServeError> {
    let server_tls = tls::load_or_generate("localhost", &config.cert_dir)?;
    let cert_hash_hex = sha256_hex(&server_tls.cert_der);

    let page_state = Arc::new(PageState {
        cert_hash_hex: cert_hash_hex.clone(),
    });

    let proxy_config = Arc::new(ProxyConfig {
        allowed_target: config.allowed_target,
        allowed_host: config.allowed_host,
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
        .push(Router::with_path("prover").get(render_index))
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
    let html = index_html(&state.cert_hash_hex);
    res.render(Text::Html(html));
    Ok(())
}

#[handler]
async fn empty_no_content(res: &mut Response) {
    res.status_code(StatusCode::NO_CONTENT);
}

fn index_html(cert_hash_hex: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Swiss Bank Balance Proof</title>
  <style>
    :root {{
      --bg: #0f1115; --card: #181b22; --border: #2a2f3a; --muted: #8b93a7;
      --fg: #e7eaf0; --accent: #3b82f6; --ok: #22c55e; --ok-bg: #0e2a18;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0; padding: 2.5rem 1.25rem; background: var(--bg); color: var(--fg);
      font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      display: flex; justify-content: center;
    }}
    main {{ width: 100%; max-width: 560px; }}
    h1 {{ font-size: 1.5rem; margin: 0 0 .35rem; }}
    .lede {{ color: var(--muted); margin: 0 0 1.75rem; }}
    .lede code {{ color: var(--fg); background: #232733; padding: .05rem .35rem; border-radius: 4px; }}
    button {{
      appearance: none; border: 0; border-radius: 8px; cursor: pointer;
      background: var(--accent); color: #fff; font-size: 1rem; font-weight: 600;
      padding: .7rem 1.25rem; transition: opacity .15s;
    }}
    button:disabled {{ opacity: .55; cursor: progress; }}
    .card {{
      margin-top: 1.75rem; background: var(--card); border: 1px solid var(--border);
      border-radius: 12px; padding: 1.5rem; display: none;
    }}
    .card.show {{ display: block; }}
    .card.ok {{ border-color: #1f6f3f; background: var(--ok-bg); }}
    .badge {{ display: inline-flex; align-items: center; gap: .4rem; font-weight: 600; color: var(--ok); }}
    .balance {{ font-size: 2.25rem; font-weight: 700; margin: .75rem 0 .15rem; letter-spacing: -.02em; }}
    .balance .ccy {{ font-size: 1.1rem; color: var(--muted); font-weight: 600; margin-right: .4rem; vertical-align: middle; }}
    .asof {{ color: var(--muted); margin: 0 0 1rem; }}
    .note {{ font-size: .85rem; color: var(--muted); border-top: 1px solid var(--border); padding-top: .9rem; margin: 0; }}
    .note b {{ color: var(--fg); font-weight: 600; }}
    .card.err {{ border-color: #7f1d1d; background: #2a1212; }}
    .card.err .badge {{ color: #f87171; }}
    details {{ margin-top: 1.5rem; }}
    summary {{ cursor: pointer; color: var(--muted); font-size: .85rem; }}
    pre#log {{
      background: #0b0d11; border: 1px solid var(--border); border-radius: 8px;
      padding: .85rem; margin: .6rem 0 0; font-size: 12px; line-height: 1.5;
      color: #aab2c5; overflow-x: auto; white-space: pre-wrap; word-break: break-word;
    }}
  </style>
</head>
<body data-cert-hash="{cert_hash_hex}">
  <main>
    <h1>Swiss Bank Balance Proof</h1>
    <p class="lede">
      Cryptographically prove the CHF balance held at
      <code>swissbank.tlsnotary.org</code> over TLSNotary — disclosing only the
      balance and audit date. The auth token sent in the request and the account
      ID returned in the response stay hidden.
    </p>

    <button id="prove-btn">Prove my CHF balance</button>

    <section id="result" class="card" aria-live="polite">
      <span class="badge" id="result-badge">✓ Balance verified</span>
      <div class="balance"><span class="ccy">CHF</span><span id="result-balance">—</span></div>
      <p class="asof">Last audited: <span id="result-date">—</span></p>
      <p class="note">
        <b>What this proves:</b> the bank's TLS server returned this exact balance.
        The verifier checked the server's certificate and the signed transcript.
        The auth token (request) and the account ID (response) were committed to
        but never revealed.
      </p>
    </section>

    <details>
      <summary>Show technical log</summary>
      <pre id="log"></pre>
    </details>
  </main>
  <script type="module" src="/assets/prover.main.mjs"></script>
</body>
</html>"#
    )
}

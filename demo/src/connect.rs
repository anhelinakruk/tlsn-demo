use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use async_compat::Compat;
use salvo::{Error as SalvoError, async_trait, handler, http::StatusError, prelude::*, proto};
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::info;

use crate::balance_verifier::{BalanceVerifyError, verify_balance};

const MAX_PREAMBLE_BYTES: usize = 256;
// Must match MAX_FRAME_BYTES in tlsn-prover/src/wasm/prover.rs — both sides frame the same way.
const MAX_FRAME_BYTES: usize = 1 << 20;

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub allowed_target: SocketAddr,
    pub allowed_host: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("webtransport failed: {0}")]
    WebTransport(#[from] SalvoError),
    #[error("webtransport accept_bi failed: {0}")]
    AcceptBi(#[from] salvo_http3::error::StreamError),
    #[error("connect state missing from depot")]
    StateMissing,
    #[error("preamble missing newline within {0} bytes")]
    PreambleTooLong(usize),
    #[error("preamble `{0}` is not a recognised role (expected VERIFY or CONNECT host:port)")]
    PreambleUnknownRole(String),
    #[error("preamble target `{0}` is not host:port")]
    PreambleInvalidTarget(String),
    #[error("preamble port `{0}` is not a number")]
    PreambleInvalidPort(String),
    #[error("proxy target `{actual}` is not permitted (expected `{expected}`)")]
    TargetNotAllowed { actual: String, expected: String },
    #[error("failed to open tcp connection: {0}")]
    TcpConnect(#[source] std::io::Error),
    #[error("protocol message frame too large: {0} bytes")]
    FrameTooLarge(usize),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    BalanceVerify(#[from] BalanceVerifyError),
}

#[async_trait]
impl Writer for ConnectError {
    async fn write(self, _req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        tracing::warn!(error = %self, "demo.connect.handshake.failed");
        let status = match &self {
            Self::StateMissing => StatusError::internal_server_error(),
            _ => StatusError::bad_gateway(),
        };
        res.render(status);
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Role {
    Verify,
    Connect { host: String, port: u16 },
}

async fn read_role_preamble<R>(mut recv: R) -> Result<(Role, Vec<u8>), ConnectError>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::<u8>::with_capacity(MAX_PREAMBLE_BYTES);
    let mut tmp = [0u8; MAX_PREAMBLE_BYTES];
    loop {
        if buf.len() >= MAX_PREAMBLE_BYTES {
            return Err(ConnectError::PreambleTooLong(MAX_PREAMBLE_BYTES));
        }
        let n = recv.read(&mut tmp).await?;
        if n == 0 {
            return Err(ConnectError::PreambleTooLong(MAX_PREAMBLE_BYTES));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(idx) = buf.iter().position(|&b| b == b'\n') {
            let line = std::str::from_utf8(&buf[..idx])
                .map_err(|_| ConnectError::PreambleUnknownRole(String::new()))?;
            let role = parse_role(line)?;
            let leftover = buf.split_off(idx + 1);
            return Ok((role, leftover));
        }
    }
}

fn parse_role(line: &str) -> Result<Role, ConnectError> {
    if line == "VERIFY" {
        return Ok(Role::Verify);
    }
    if let Some(rest) = line.strip_prefix("CONNECT ") {
        let (host, port) = rest
            .rsplit_once(':')
            .ok_or_else(|| ConnectError::PreambleInvalidTarget(rest.to_string()))?;
        let port: u16 = port
            .parse()
            .map_err(|_| ConnectError::PreambleInvalidPort(port.to_string()))?;
        return Ok(Role::Connect {
            host: host.to_string(),
            port,
        });
    }
    Err(ConnectError::PreambleUnknownRole(line.to_string()))
}

#[handler]
pub async fn handle(req: &mut Request, depot: &mut Depot) -> Result<(), ConnectError> {
    let proxy_config = depot
        .obtain::<Arc<ProxyConfig>>()
        .map_err(|_| ConnectError::StateMissing)?
        .clone();

    let session = req.web_transport_mut().await?;
    tracing::debug!("demo.connect.session.ready");

    let verified = Arc::new(AtomicBool::new(false));

    loop {
        let accepted = match session.accept_bi().await {
            Ok(Some(accepted)) => accepted,
            Ok(None) => {
                tracing::debug!("demo.connect.session.closed");
                return Ok(());
            }
            Err(err) if verified.load(Ordering::SeqCst) => {
                tracing::debug!(%err, "demo.connect.session.ended_after_notarization");
                return Ok(());
            }
            Err(err) => return Err(err.into()),
        };
        let proto::webtransport::server::AcceptedBi::BidiStream(_, stream) = accepted else {
            tracing::warn!("demo.connect.stream.not_bidirectional");
            continue;
        };

        let proxy_config = Arc::clone(&proxy_config);
        let verified = Arc::clone(&verified);
        tokio::spawn(async move {
            let (wt_send, wt_recv) = proto::quic::BidiStream::split(stream);
            if let Err(err) = dispatch_stream(wt_recv, wt_send, &proxy_config, &verified).await {
                tracing::warn!(%err, "demo.connect.stream.failed");
            }
        });
    }
}

async fn dispatch_stream<R, W>(
    mut wt_recv: R,
    wt_send: W,
    proxy_config: &ProxyConfig,
    verified: &AtomicBool,
) -> Result<(), ConnectError>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (role, leftover) = read_role_preamble(&mut wt_recv).await?;
    match role {
        Role::Verify => {
            let joined = tokio::io::join(ChainedRead::new(leftover, wt_recv), wt_send);
            let outcome = run_notarize_stream(joined, proxy_config).await;
            verified.store(true, Ordering::SeqCst);
            outcome
        }
        Role::Connect { host, port } => {
            proxy_connect(wt_recv, wt_send, proxy_config, host, port, leftover).await
        }
    }
}

async fn run_notarize_stream<IO>(
    stream: IO,
    proxy_config: &ProxyConfig,
) -> Result<(), ConnectError>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    use futures::AsyncWriteExt as _;

    // The outer error covers MPC-level failures (the prover already learns of
    // those from the protocol). Post-session validation failures come back as the
    // inner `Err`, with the socket recovered, so we can report a clean reason to
    // the prover instead of dropping the stream (which surfaces as "unexpected
    // end of file" on its side).
    let (mut io, result) = verify_balance(create_verifier_config(proxy_config), Compat::new(stream)).await?;

    match result {
        Ok(output) => {
            info!(
                chf = %output.chf_balance,
                timestamp = %output.last_audit,
                "demo.balance.verified"
            );
            let outcome = VerificationOutcome::Success {
                chf: &output.chf_balance,
                last_audit: &output.last_audit,
            };
            write_json_frame(&mut io, &outcome).await?;
        }
        Err(err) => {
            tracing::warn!(error = %err, "demo.balance.rejected");
            let reason = err.to_string();
            let outcome = VerificationOutcome::Failure { reason: &reason };
            write_json_frame(&mut io, &outcome).await?;
        }
    }

    io.close().await?;
    Ok(())
}

fn create_verifier_config(_proxy_config: &ProxyConfig) -> tlsn::config::verifier::VerifierConfig {
    use tlsn::webpki::RootCertStore;
    tlsn::config::verifier::VerifierConfig::builder()
        .root_store(RootCertStore::mozilla())
        .build()
        .expect("verifier config")
}

async fn proxy_connect<R, W>(
    wt_recv: R,
    wt_send: W,
    proxy_config: &ProxyConfig,
    host: String,
    port: u16,
    leftover: Vec<u8>,
) -> Result<(), ConnectError>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send + 'static,
{
    if host != proxy_config.allowed_host || port != proxy_config.allowed_target.port() {
        return Err(ConnectError::TargetNotAllowed {
            actual: format!("{host}:{port}"),
            expected: format!("{}:{}", proxy_config.allowed_host, proxy_config.allowed_target.port()),
        });
    }

    let mut tcp = tokio::net::TcpStream::connect(proxy_config.allowed_target)
        .await
        .map_err(ConnectError::TcpConnect)?;
    tracing::debug!(target = %proxy_config.allowed_target, "demo.connect.proxy.tcp_connected");

    let (tcp_read, mut tcp_write) = tcp.split();
    if !leftover.is_empty() {
        tcp_write.write_all(&leftover).await?;
    }

    let (wt_to_tcp, tcp_to_wt) = tokio::join!(
        forward(wt_recv, tcp_write),
        forward(tcp_read, wt_send),
    );
    wt_to_tcp?;
    tcp_to_wt?;
    Ok(())
}

async fn forward<R, W>(mut src: R, mut dst: W) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
    loop {
        let n = src.read(&mut buf).await?;
        if n == 0 {
            dst.shutdown().await.ok();
            return Ok(());
        }
        dst.write_all(&buf[..n]).await?;
    }
}

struct ChainedRead<R> {
    buf: Vec<u8>,
    pos: usize,
    inner: R,
}

impl<R> ChainedRead<R> {
    fn new(buf: Vec<u8>, inner: R) -> Self {
        Self { buf, pos: 0, inner }
    }
}

impl<R: AsyncRead + Unpin + Send> AsyncRead for ChainedRead<R> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.buf.len() {
            let remaining = &this.buf[this.pos..];
            let n = remaining.len().min(out.remaining());
            out.put_slice(&remaining[..n]);
            this.pos += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut this.inner).poll_read(cx, out)
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "status")]
enum VerificationOutcome<'a> {
    #[serde(rename = "success")]
    Success { chf: &'a str, last_audit: &'a str },
    #[serde(rename = "failure")]
    Failure { reason: &'a str },
}

async fn write_json_frame<IO, T>(io: &mut IO, value: &T) -> Result<(), ConnectError>
where
    IO: futures::AsyncWrite + Unpin + Send,
    T: Serialize,
{
    use futures::AsyncWriteExt as _;

    let payload = serde_json::to_vec(value)?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(ConnectError::FrameTooLarge(payload.len()));
    }
    let len = u32::try_from(payload.len())
        .map_err(|_| ConnectError::FrameTooLarge(payload.len()))?;
    io.write_all(&len.to_be_bytes()).await?;
    io.write_all(&payload).await?;
    io.flush().await?;
    Ok(())
}

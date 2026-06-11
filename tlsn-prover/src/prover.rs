use std::sync::Arc;

use futures::{AsyncRead, AsyncWrite, channel::oneshot, join};
use http_body_util::{BodyExt, Empty};
use hyper::{Request, StatusCode, body::Bytes};
use tlsn::{
    Session, SessionHandle,
    config::{
        prove::ProveConfig,
        prover::ProverConfig as TlsnProverConfig,
        tls::TlsClientConfig,
        tls_commit::TlsCommitConfig,
    },
    hash::HashAlgId,
    transcript::{TranscriptCommitConfig, TranscriptCommitmentKind},
};

use crate::{
    Error,
    reveal::{RevealConfig, reveal_request, reveal_response},
    transport::{FuturesIo, Runtime},
};

#[derive(Debug, Clone)]
pub struct ProverOutput {
    pub sent: Vec<u8>,
    pub received: Vec<u8>,
    pub transcript_commitments: Vec<tlsn::transcript::TranscriptCommitment>,
    pub transcript_secrets: Vec<tlsn::transcript::TranscriptSecret>,
    pub response_body: Vec<u8>,
}

pub struct ProverConfigBundle {
    pub runtime: Arc<dyn Runtime>,
    pub tls_client_config: TlsClientConfig,
    pub tls_commit_config: TlsCommitConfig,
    pub request: Request<Empty<Bytes>>,
    pub request_reveal_config: RevealConfig,
    pub response_reveal_config: RevealConfig,
    pub hash_alg: HashAlgId,
}

#[derive(Default)]
pub struct Prover;

impl Prover {
    pub fn new() -> Self {
        Self
    }

    pub async fn prove<T, S>(
        &self,
        config: ProverConfigBundle,
        verifier_socket: T,
        server_socket: S,
    ) -> Result<(T, ProverOutput), Error>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let ProverConfigBundle {
            runtime,
            tls_client_config,
            tls_commit_config,
            request,
            request_reveal_config,
            response_reveal_config,
            hash_alg,
        } = config;

        tracing::info!("prover.setup_and_connect.start");
        let (mpc_tls_connection, prover_fut, session_handle, verifier_io_rx) =
            setup_and_connect(runtime, tls_client_config, tls_commit_config, verifier_socket, server_socket).await?;
        tracing::info!("prover.setup_and_connect.done");

        tracing::info!("prover.http_exchange.start");
        let (mut prover, response_body) =
            execute_http_exchange(mpc_tls_connection, prover_fut, request).await?;
        tracing::info!("prover.http_exchange.done");

        let prove_config = build_prove_config(&mut prover, hash_alg, &request_reveal_config, &response_reveal_config)?;

        let sent = prover.transcript().sent().to_owned();
        let received = prover.transcript().received().to_owned();
        tracing::info!("prover.generate_proof.start");
        let prover_output = generate_proof(prover, &prove_config).await?;
        tracing::info!("prover.generate_proof.done");

        session_handle.close();
        let verifier_io = verifier_io_rx
            .await
            .map_err(|_| Error::SessionDriverCancelled)
            .and_then(|inner| inner)?;

        Ok((
            verifier_io,
            ProverOutput {
                sent,
                received,
                transcript_commitments: prover_output.transcript_commitments,
                transcript_secrets: prover_output.transcript_secrets,
                response_body,
            },
        ))
    }
}

async fn setup_and_connect<T, S>(
    runtime: Arc<dyn Runtime>,
    tls_client_config: TlsClientConfig,
    tls_commit_config: TlsCommitConfig,
    verifier_socket: T,
    server_socket: S,
) -> Result<
    (
        impl AsyncRead + AsyncWrite + Send + Unpin,
        impl std::future::Future<Output = std::result::Result<tlsn::prover::Prover<tlsn::prover::state::Committed>, tlsn::Error>> + Send,
        SessionHandle,
        oneshot::Receiver<Result<T, Error>>,
    ),
    Error,
>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let mut session = Session::new(verifier_socket);
    let prover = session.new_prover(TlsnProverConfig::builder().build()?)?;
    let (driver, handle) = session.split();
    let (verifier_io_tx, verifier_io_rx) = oneshot::channel();
    runtime.spawn_detached(Box::pin(async move {
        let outcome = driver.await.map_err(Error::from);
        if verifier_io_tx.send(outcome).is_err() {
            tracing::warn!("verifier_io receiver dropped before session driver finished");
        }
    }));

    let prover = prover.commit(tls_commit_config).await?;
    let (connection, prover_future) = prover.connect(tls_client_config, server_socket).await?;
    Ok((connection, prover_future, handle, verifier_io_rx))
}

async fn execute_http_exchange<C>(
    mpc_tls_connection: C,
    prover_fut: impl std::future::Future<Output = std::result::Result<tlsn::prover::Prover<tlsn::prover::state::Committed>, tlsn::Error>> + Send,
    request: Request<Empty<Bytes>>,
) -> Result<(tlsn::prover::Prover<tlsn::prover::state::Committed>, Vec<u8>), Error>
where
    C: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(FuturesIo::new(mpc_tls_connection)).await?;

    let request_task = async move {
        let response = request_sender.send_request(request).await?;
        if response.status() != StatusCode::OK {
            return Err(Error::HttpRequestFailed(response.status().as_u16()));
        }
        Ok::<Vec<u8>, Error>(response.collect().await?.to_bytes().to_vec())
    };

    let (prover, connection_result, body) = join!(prover_fut, connection, request_task);
    Ok((prover?, { connection_result?; body? }))
}

fn build_prove_config(
    prover: &mut tlsn::prover::Prover<tlsn::prover::state::Committed>,
    hash_alg: HashAlgId,
    request_reveal_config: &RevealConfig,
    response_reveal_config: &RevealConfig,
) -> Result<ProveConfig, Error> {
    let transcript = prover.transcript();
    let mut prove_builder = ProveConfig::builder(transcript);
    prove_builder.server_identity();

    let mut commit_builder = TranscriptCommitConfig::builder(transcript);
    commit_builder.default_kind(TranscriptCommitmentKind::Hash { alg: hash_alg });

    reveal_request(transcript.sent(), &mut prove_builder, &mut commit_builder, request_reveal_config)?;
    reveal_response(transcript.received(), &mut prove_builder, &mut commit_builder, response_reveal_config)?;

    prove_builder.transcript_commit(commit_builder.build()?);
    Ok(prove_builder.build()?)
}

async fn generate_proof(
    mut prover: tlsn::prover::Prover<tlsn::prover::state::Committed>,
    prove_config: &ProveConfig,
) -> Result<tlsn::prover::ProverOutput, Error> {
    let output = prover.prove(prove_config).await?;
    tracing::info!("prover.prove.done — starting close");
    prover.close().await?;
    Ok(output)
}

use std::collections::HashMap;

use futures::{AsyncRead, AsyncWrite, channel::oneshot};
use thiserror::Error;
use tlsn::{
    Session,
    config::{tls_commit::TlsCommitProtocolConfig, verifier::VerifierConfig},
    transcript::PartialTranscript,
};
use tlsn_prover::{
    SmolRuntime,
    parser::redacted::{Body, Response},
    transport::Runtime,
};

pub const MAX_SENT_DATA: usize = 1 << 12;
pub const MAX_RECV_DATA: usize = 1 << 14;

pub struct BalanceOutput {
    pub chf_balance: String,
    pub last_audit: String,
}

#[derive(Debug, Error)]
pub enum BalanceVerifyError {
    #[error("expected server name '{expected}', got '{actual}'")]
    ServerName { expected: String, actual: String },

    #[error("missing response body field '{key}'")]
    MissingBodyField { key: String },

    #[error("missing value for field '{key}'")]
    MissingFieldValue { key: String },

    #[error("protocol policy rejected: {0}")]
    ProtocolPolicy(String),

    #[error("request policy rejected: {0}")]
    RequestPolicy(String),

    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    #[error(transparent)]
    FromUtf8(#[from] std::string::FromUtf8Error),

    #[error(transparent)]
    Parse(#[from] tlsn_prover::parser::ParseError),

    #[error(transparent)]
    Tlsn(#[from] tlsn::Error),

    #[error("session driver cancelled")]
    SessionDriverCancelled,
}

/// Runs the verifier side of the session.
///
/// The outer `Err` covers MPC-level failures (policy rejection, a cancelled
/// session driver, tlsn errors) — at that point there is no socket to talk back
/// over, and the prover already learns of the failure from the protocol. Once
/// the MPC session completes the socket is recovered, so post-session validation
/// (server name, balance extraction) is returned as the inner `Result`, letting
/// the caller report a clean reason to the prover.
pub async fn verify_balance<T>(
    config: VerifierConfig,
    socket: T,
) -> Result<(T, Result<BalanceOutput, BalanceVerifyError>), BalanceVerifyError>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let mut session = Session::new(socket);
    let verifier = session.new_verifier(config)?;
    let (driver, handle) = session.split();

    let (socket_tx, socket_rx) = oneshot::channel();
    SmolRuntime.spawn_detached(Box::pin(async move {
        let _ = socket_tx.send(driver.await.map_err(tlsn::Error::from));
    }));

    let verifier = verifier.commit().await?;
    if let Err(reason) = protocol_policy(verifier.request().protocol()) {
        verifier.reject(Some(&reason)).await?;
        return Err(BalanceVerifyError::ProtocolPolicy(reason));
    }

    let verifier = verifier.accept().await?.run().await?.verify().await?;
    if let Err(reason) = request_policy(
        verifier.request().server_identity(),
        verifier.request().reveal().is_some(),
    ) {
        let verifier = verifier.reject(Some(&reason)).await?;
        verifier.close().await?;
        return Err(BalanceVerifyError::RequestPolicy(reason));
    }

    let (output, verifier) = verifier.accept().await?;
    verifier.close().await?;
    handle.close();

    let socket = socket_rx
        .await
        .map_err(|_| BalanceVerifyError::SessionDriverCancelled)
        .and_then(|r| r.map_err(BalanceVerifyError::Tlsn))?;

    let validation = (move || {
        let server_name = output
            .server_name
            .ok_or_else(|| BalanceVerifyError::MissingBodyField { key: "server_name".into() })?;
        if server_name.to_string() != "swissbank.tlsnotary.org" {
            return Err(BalanceVerifyError::ServerName {
                expected: "swissbank.tlsnotary.org".into(),
                actual: server_name.to_string(),
            });
        }

        let transcript = output
            .transcript
            .ok_or_else(|| BalanceVerifyError::MissingBodyField { key: "transcript".into() })?;

        extract_balance(&transcript)
    })();

    Ok((socket, validation))
}

fn protocol_policy(protocol: &TlsCommitProtocolConfig) -> Result<(), String> {
    let TlsCommitProtocolConfig::Mpc(mpc) = protocol else {
        return Err("expected MPC-TLS protocol".into());
    };
    if mpc.max_sent_data() > MAX_SENT_DATA {
        return Err(format!(
            "max_sent_data {} exceeds limit {}",
            mpc.max_sent_data(),
            MAX_SENT_DATA
        ));
    }
    if mpc.max_recv_data() > MAX_RECV_DATA {
        return Err(format!(
            "max_recv_data {} exceeds limit {}",
            mpc.max_recv_data(),
            MAX_RECV_DATA
        ));
    }
    Ok(())
}

fn request_policy(server_identity_revealed: bool, reveal_present: bool) -> Result<(), String> {
    if !server_identity_revealed {
        return Err("missing required server identity reveal".into());
    }
    if !reveal_present {
        return Err("missing required transcript reveal payload".into());
    }
    Ok(())
}

fn extract_balance(transcript: &PartialTranscript) -> Result<BalanceOutput, BalanceVerifyError> {
    let received = String::from_utf8(transcript.received_unsafe().to_vec())?;
    let response: Response = received.parse()?;
    let data = transcript.received_unsafe();

    // The verifier re-parses the *redacted* transcript with the non-recursive
    // redacted parser: nested objects collapse to flat keys. The server reveals
    // only the `"CHF":…` and `"last_audit":…` pairs (the `accounts` wrapper is
    // redacted), so CHF surfaces as the top-level key `.CHF`, not `.accounts.CHF`.
    let chf_balance = body_text(&response.body, data, ".CHF")?;
    let last_audit = body_text(&response.body, data, ".last_audit")?;

    Ok(BalanceOutput {
        chf_balance: chf_balance.to_owned(),
        last_audit: last_audit.to_owned(),
    })
}

fn body_text<'a>(
    body: &HashMap<String, Body>,
    data: &'a [u8],
    key: &str,
) -> Result<&'a str, BalanceVerifyError> {
    let field = body
        .get(key)
        .ok_or_else(|| BalanceVerifyError::MissingBodyField { key: key.to_owned() })?;
    let range = match field {
        Body::KeyValue { value, .. } => value.as_ref(),
        Body::Value(range) => Some(range),
    };
    let range = range.ok_or_else(|| BalanceVerifyError::MissingFieldValue { key: key.to_owned() })?;
    Ok(std::str::from_utf8(&data[range.clone()])?)
}

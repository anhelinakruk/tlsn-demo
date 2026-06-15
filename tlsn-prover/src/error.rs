use thiserror::Error;

use crate::parser::ParseError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid DNS server name: {0}")]
    InvalidDnsName(String),
    
    #[error(transparent)]
    Parser(#[from] ParseError),

    #[error("reveal rule '{rule}' did not match any {target} in {direction}")]
    RevealRuleNotMatched {
        direction: &'static str,
        target: &'static str,
        rule: String,
    },

    #[error("reveal rule '{rule}' expected {expected} body field, got {actual}")]
    RevealStructureMismatch {
        rule: String,
        expected: &'static str,
        actual: &'static str,
    },

    #[error(transparent)]
    RequestBuild(#[from] hyper::http::Error),

    #[error(transparent)]
    Hyper(#[from] hyper::Error),

    #[error("HTTP request failed with status {0}")]
    HttpRequestFailed(u16),

    #[error("tlsn session driver cancelled")]
    SessionDriverCancelled,

    #[error(transparent)]
    Tlsn(#[from] tlsn::Error),

    #[error(transparent)]
    TlsnProverConfig(#[from] tlsn::config::prover::ProverConfigError),

    #[error(transparent)]
    TlsnProveConfig(#[from] tlsn::config::prove::ProveConfigError),

    #[error(transparent)]
    TlsnTranscriptCommitConfig(#[from] tlsn::transcript::TranscriptCommitConfigBuilderError),

    #[error(transparent)]
    TlsnTlsClientConfig(#[from] tlsn::config::tls::TlsConfigError),

    #[error(transparent)]
    TlsnMpcTlsConfig(#[from] tlsn::config::tls_commit::mpc::MpcTlsConfigError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error(transparent)]
    Utf8Str(#[from] std::str::Utf8Error),

    #[cfg(target_arch = "wasm32")]
    #[error("invalid wasm input JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[cfg(target_arch = "wasm32")]
    #[error("verifier outcome frame too large: {0} bytes")]
    FrameTooLarge(usize),

    #[cfg(target_arch = "wasm32")]
    #[error("verifier policy rejected: {0}")]
    VerifierPolicyRejected(String),
}

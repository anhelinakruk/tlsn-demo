use std::sync::Arc;

use futures::AsyncReadExt;
use http_body_util::Empty;
use hyper::{Method, Request as HttpRequest, body::Bytes};
use serde::{Deserialize, Serialize};
use tlsn::{
    config::{
        tls::TlsClientConfig,
        tls_commit::{TlsCommitConfig, mpc::MpcTlsConfig},
    },
    connection::{DnsName, ServerName},
    hash::HashAlgId,
    webpki::{CertificateDer, RootCertStore},
};
use wasm_bindgen::prelude::*;
use web_sys::WebTransportBidirectionalStream;

use super::{WasmRuntime, io::WebTransportIo};

// Must match MAX_FRAME_BYTES in demo/src/connect.rs — both sides frame the same way.
const MAX_FRAME_BYTES: usize = 1 << 20;
use crate::{
    Error,
    prover::{Prover as CoreProver, ProverConfigBundle},
    reveal::RevealConfig,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsProverInputs {
    pub server_name: String,
    pub server_cert_der: Vec<u8>,
    pub max_sent_data: usize,
    pub max_recv_data: usize,
    pub request_method: String,
    pub request_uri: String,
    pub request_headers: Vec<(String, String)>,
    pub request_reveal_config: RevealConfig,
    pub response_reveal_config: RevealConfig,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JsProverOutput {
    pub chf_balance: String,
    pub last_audit: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase")]
enum VerificationOutcome {
    #[serde(rename = "success")]
    Success { chf: String, last_audit: String },
    #[serde(rename = "failure")]
    Failure { reason: String },
}

#[wasm_bindgen]
#[derive(Default)]
pub struct Prover(CoreProver);

#[wasm_bindgen]
impl Prover {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn prove_streams(
        &self,
        inputs_json: &str,
        verifier_stream: WebTransportBidirectionalStream,
        server_stream: WebTransportBidirectionalStream,
    ) -> Result<JsValue, JsError> {
        let config = build_prover_config(inputs_json)?;
        let verifier_io = WebTransportIo::from_bidi(verifier_stream)
            .map_err(|e| JsError::new(&format!("{e:?}")))?;
        let server_io = WebTransportIo::from_bidi(server_stream)
            .map_err(|e| JsError::new(&format!("{e:?}")))?;
        let (mut verifier_io, _output) = self.0.prove(config, verifier_io, server_io).await?;
        let js_output = read_verification_outcome(&mut verifier_io).await?;
        let serializer = serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
        Ok(js_output.serialize(&serializer)?)
    }
}

fn build_prover_config(inputs_json: &str) -> Result<ProverConfigBundle, Error> {
    let inputs: JsProverInputs = serde_json::from_str(inputs_json)?;
    let dns = DnsName::try_from(inputs.server_name.as_str())
        .map_err(|err| Error::InvalidDnsName(format!("{err}")))?;
    let root_store = if inputs.server_cert_der.is_empty() {
        RootCertStore::mozilla()
    } else {
        RootCertStore { roots: vec![CertificateDer(inputs.server_cert_der)] }
    };
    let tls_client_config = TlsClientConfig::builder()
        .server_name(ServerName::Dns(dns))
        .root_store(root_store)
        .build()?;
    let mpc_config = MpcTlsConfig::builder()
        .max_sent_data(inputs.max_sent_data)
        .max_recv_data(inputs.max_recv_data)
        .build()?;
    let tls_commit_config = TlsCommitConfig::builder().protocol(mpc_config).build()?;

    let method =
        Method::from_bytes(inputs.request_method.as_bytes()).map_err(hyper::http::Error::from)?;
    let mut builder = HttpRequest::builder()
        .method(method)
        .uri(inputs.request_uri);
    for (name, value) in inputs.request_headers {
        builder = builder.header(name, value);
    }
    let request = builder.body(Empty::<Bytes>::new())?;

    Ok(ProverConfigBundle {
        runtime: Arc::new(WasmRuntime),
        tls_client_config,
        tls_commit_config,
        request,
        request_reveal_config: inputs.request_reveal_config,
        response_reveal_config: inputs.response_reveal_config,
        hash_alg: HashAlgId::POSEIDON2,
    })
}

async fn read_verification_outcome(io: &mut WebTransportIo) -> Result<JsProverOutput, Error> {
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(Error::FrameTooLarge(len));
    }

    let mut payload = vec![0u8; len];
    io.read_exact(&mut payload).await?;
    match serde_json::from_slice::<VerificationOutcome>(&payload)? {
        VerificationOutcome::Success { chf, last_audit } => {
            Ok(JsProverOutput { chf_balance: chf, last_audit })
        }
        VerificationOutcome::Failure { reason } => Err(Error::VerifierPolicyRejected(reason)),
    }
}

use std::sync::Arc;

use chrono::Datelike;

use rcgen::{
    CertificateParams, DistinguishedName, DnType, KeyPair, SanType,
};
use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("rcgen: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("no peer certificate")]
    NoPeerCert,
    #[error("invalid dns name")]
    InvalidDnsName,
}

pub struct ServerCert {
    pub cert_der: Vec<u8>,
    pub cert_pem: String,
    pub key_pem: String,
}

pub fn generate_self_signed(host: &str) -> Result<ServerCert, TlsError> {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, host);

    let now = chrono::Utc::now();
    let expire = now + chrono::Duration::days(13);

    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.subject_alt_names = vec![
        SanType::DnsName(host.try_into()?),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
    ];
    params.not_before = rcgen::date_time_ymd(
        now.year(), now.month() as u8, now.day() as u8,
    );
    params.not_after = rcgen::date_time_ymd(
        expire.year(), expire.month() as u8, expire.day() as u8,
    );

    let cert = params.self_signed(&key)?;
    Ok(ServerCert {
        cert_der: cert.der().to_vec(),
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

pub async fn fetch_server_cert_der(host: &str, port: u16) -> Result<Vec<u8>, TlsError> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect((host, port)).await?;
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| TlsError::InvalidDnsName)?;
    let tls = connector.connect(server_name, stream).await?;
    let (_, session) = tls.get_ref();
    let cert = session
        .peer_certificates()
        .and_then(|certs| certs.first())
        .ok_or(TlsError::NoPeerCert)?;
    Ok(cert.to_vec())
}

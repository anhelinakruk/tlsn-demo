use std::{fs, path::Path};

use chrono::Datelike;

use rcgen::{
    CertificateParams, DistinguishedName, DnType, KeyPair, SanType,
};

/// Regenerate once the cached cert has fewer than this many days of validity
/// left, staying clear of Chrome's 14-day `serverCertificateHashes` ceiling.
const RENEW_WHEN_DAYS_LEFT: i64 = 2;

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("rcgen: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("cert cache: {0}")]
    Cache(#[from] serde_json::Error),
    #[error("cert cache hex: {0}")]
    Hex(#[from] hex::FromHexError),
}

pub struct ServerCert {
    pub cert_der: Vec<u8>,
    pub cert_pem: String,
    pub key_pem: String,
    pub not_after: chrono::DateTime<chrono::Utc>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CachedCert {
    not_after: chrono::DateTime<chrono::Utc>,
    cert_pem: String,
    key_pem: String,
    cert_der_hex: String,
}

/// Returns a self-signed cert for `host`, reusing the one cached in `dir` when
/// it still has comfortable validity left, otherwise generating a fresh one and
/// caching it. A stable cert lets Chrome remember the user's "proceed" between
/// server restarts instead of prompting on every run.
pub fn load_or_generate(host: &str, dir: &Path) -> Result<ServerCert, TlsError> {
    let path = dir.join("server-cert.json");

    if let Some(cert) = load_cached(&path)? {
        return Ok(cert);
    }

    let cert = generate_self_signed(host)?;
    persist(&path, &cert)?;
    Ok(cert)
}

fn load_cached(path: &Path) -> Result<Option<ServerCert>, TlsError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };

    let cached: CachedCert = serde_json::from_slice(&bytes)?;
    if cached.not_after - chrono::Utc::now() < chrono::Duration::days(RENEW_WHEN_DAYS_LEFT) {
        return Ok(None);
    }

    Ok(Some(ServerCert {
        cert_der: hex::decode(&cached.cert_der_hex)?,
        cert_pem: cached.cert_pem,
        key_pem: cached.key_pem,
        not_after: cached.not_after,
    }))
}

fn persist(path: &Path, cert: &ServerCert) -> Result<(), TlsError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let cached = CachedCert {
        not_after: cert.not_after,
        cert_pem: cert.cert_pem.clone(),
        key_pem: cert.key_pem.clone(),
        cert_der_hex: hex::encode(&cert.cert_der),
    };
    fs::write(path, serde_json::to_vec_pretty(&cached)?)?;
    Ok(())
}

fn generate_self_signed(host: &str) -> Result<ServerCert, TlsError> {
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
        not_after: expire,
    })
}

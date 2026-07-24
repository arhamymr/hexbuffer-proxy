use rcgen::{
    BasicConstraints, 
    CertificateParams, 
    DistinguishedName, 
    DnType, 
    IsCa, 
    KeyPair, 
    SanType,
    ExtendedKeyUsagePurpose,
    KeyUsagePurpose,
};

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

use time::{Duration, OffsetDateTime};

/// How far back from "now" the leaf cert's `not_before` is set
/// (5 minutes — accommodates modest clock skew between client and proxy).
const NOT_BEFORE_OFFSET_SECS: i64 = 300;

/// Lifetime of a forged leaf certificate in seconds (365 days).
const TTL_SECS: i64 = 31_536_000;

/// Self-signed CA that forges per-domain TLS certificates on the fly.
///
/// On first run, generates a new CA key/cert and persists both as PEM
/// to `cert/ca.pem` and `cert/ca-key.pem`.  Subsequent runs load the
/// same key from disk; because the [`CertificateParams`] are identical
/// every run, [`CertificateParams::self_signed`] produces the *same*
/// CA cert — the browser's trust anchor survives restarts.
///
/// Use [`new`] for the default `"cert"` directory or [`new_in`] to
/// specify a custom location.
pub struct CertificationAuthority {
    ca_params: CertificateParams,
    ca_key: KeyPair,
    ca_cert_pem: String,
    cert_cache: RwLock<HashMap<String, (Vec<u8>, Vec<u8>)>>,
}

impl CertificationAuthority {
    /// Create a CA with keys persisted under `"cert/"`.
    pub fn new() -> Self {
        Self::new_in("cert")
    }

    /// Create a CA with keys persisted under a custom directory.
    ///
    /// ```ignore
    /// let ca = CertificationAuthority::new_in("/tmp/my-ca");
    /// ```
    pub fn new_in(dir: impl Into<PathBuf>) -> Self {
        let cert_dir: PathBuf = dir.into();
        let cert_path = cert_dir.join("ca.pem");
        let key_path = cert_dir.join("ca-key.pem");

        let ca_params = Self::build_ca_params();

        if cert_path.exists() && key_path.exists() {
            println!("CA certificate found on disk, loading...");

            let ca_cert_pem = std::fs::read_to_string(&cert_path)
                .expect("Failed to read CA certificate PEM");
            let key_pem = std::fs::read_to_string(&key_path)
                .expect("Failed to read CA key PEM");

            let ca_key = KeyPair::from_pem(&key_pem)
                .expect("Failed to parse CA key from PEM");

            return Self {
                ca_params,
                ca_key,
                ca_cert_pem,
                cert_cache: RwLock::new(HashMap::new()),
            };
        }

        let (ca_key, ca_cert_pem) = Self::generate_ca(&ca_params, &cert_dir);

        Self {
            ca_params,
            ca_key,
            ca_cert_pem,
            cert_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Build the fixed [`CertificateParams`] used for every CA instance.
    ///
    /// Identical on every call — when combined with the same persisted
    /// [`KeyPair`], [`CertificateParams::self_signed`] produces the
    /// **same** CA certificate deterministically across restarts.
    fn build_ca_params() -> CertificateParams {
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Hexbuffer Proxy CA");
        ca_params.distinguished_name = dn;
        ca_params
    }

    /// Generate a fresh CA key pair, self-sign a root certificate,
    /// and persist both as PEM files under `cert_dir`.
    ///
    /// Returns `(ca_key, ca_cert_pem)`.
    fn generate_ca(
        ca_params: &CertificateParams,
        cert_dir: &PathBuf,
    ) -> (KeyPair, String) {
        println!("Generating new CA certificate...");

        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        std::fs::create_dir_all(cert_dir).expect("Failed to create cert directory");

        let ca_cert_pem = ca_cert.pem();

        let cert_path = cert_dir.join("ca.pem");
        let key_path = cert_dir.join("ca-key.pem");

        std::fs::write(&cert_path, &ca_cert_pem)
            .expect("Failed to save CA certificate");
        println!("CA certificate saved to {}", cert_path.display());

        std::fs::write(&key_path, ca_key.serialize_pem())
            .expect("Failed to save CA key");
        println!("CA key saved to {}", key_path.display());

        (ca_key, ca_cert_pem)
    }

    /// Return the CA certificate as a PEM string.
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Generate (or retrieve from cache) a TLS certificate for `host`.
    ///
    /// Returns `(cert_der, key_der)` — DER-encoded leaf certificate
    /// signed by this CA, paired with the leaf's own private key DER.
    /// Certificates (and their keys) are cached per host.
    pub fn forge_certificate(&self, host: &str) -> (Vec<u8>, Vec<u8>) {
        if let Some((cert, key)) = self.cert_cache.read().unwrap().get(host) {
            return (cert.clone(), key.clone());
        }

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;

        let not_before = OffsetDateTime::now_utc() - Duration::seconds(NOT_BEFORE_OFFSET_SECS);
        params.not_before = not_before;
        params.not_after = not_before + Duration::seconds(TTL_SECS);

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        params.subject_alt_names.push(SanType::DnsName(host.to_string().try_into().unwrap()));

        let issuer = rcgen::Issuer::new(self.ca_params.clone(), &self.ca_key);
        let leaf_key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&leaf_key, &issuer).unwrap();

        let cert_der = cert.der().to_vec();
        let leaf_key_der = leaf_key.serialize_der();

        self.cert_cache
            .write()
            .unwrap()
            .insert(host.to_string(), (cert_der.clone(), leaf_key_der.clone()));

        (cert_der, leaf_key_der)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ca_creation() {
        let ca = CertificationAuthority::new();
        assert!(!ca.ca_cert_pem().is_empty());
    }

    #[test]
    fn test_forge_certificate_returns_valid_data() {
        let ca = CertificationAuthority::new();
        let (cert_der, key_der) = ca.forge_certificate("example.com");
        assert!(!cert_der.is_empty(), "cert DER should not be empty");
        assert!(!key_der.is_empty(), "key DER should not be empty");
    }

    #[test]
    fn test_forge_googlevideo_cdn_hostname() {
        let ca = CertificationAuthority::new();
        let host = "rr2---sn-xmjxajvh-02bl.googlevideo.com";
        let (cert_der, key_der) = ca.forge_certificate(host);
        assert!(!cert_der.is_empty(), "cert DER should not be empty");
        assert!(!key_der.is_empty(), "key DER should not be empty");

        // Verify we can construct a rustls ServerConfig with this cert+key
        use rustls_pki_types::{CertificateDer, PrivateKeyDer};
        use tokio_rustls::rustls::ServerConfig;
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert_der)],
                PrivateKeyDer::Pkcs8(key_der.into()),
            );
        assert!(config.is_ok(), "ServerConfig should be constructible: {:?}", config.err());
    }

    #[test]
    fn test_forge_certificate_caching() {
        let ca = CertificationAuthority::new();
        let (cert1, _) = ca.forge_certificate("example.com");
        let (cert2, _) = ca.forge_certificate("example.com");
        assert_eq!(cert1, cert2, "same host should return cached cert");
    }

    #[test]
    fn test_forge_different_hosts() {
        let ca = CertificationAuthority::new();
        let (cert1, _) = ca.forge_certificate("example.com");
        let (cert2, _) = ca.forge_certificate("other.org");
        assert_ne!(cert1, cert2, "different hosts should produce different certs");
    }

    #[test]
    fn test_forge_unique_key_per_host() {
        let ca = CertificationAuthority::new();
        let (_, key1) = ca.forge_certificate("a.example.com");
        let (_, key2) = ca.forge_certificate("b.example.com");
        assert_ne!(key1, key2, "each forged cert has its own leaf key");
    }

    // ── new_in / cert_dir tests ──

    #[test]
    fn test_new_in_creates_files_in_custom_dir() {
        let dir = std::env::temp_dir().join("ca_test_custom_dir");
        let _ = std::fs::remove_dir_all(&dir);

        let ca = CertificationAuthority::new_in(&dir);

        let cert_path = dir.join("ca.pem");
        let key_path = dir.join("ca-key.pem");

        assert!(cert_path.exists(), "ca.pem should exist in custom dir");
        assert!(key_path.exists(), "ca-key.pem should exist in custom dir");

        let cert_content = std::fs::read_to_string(&cert_path).unwrap();
        assert!(cert_content.starts_with("-----BEGIN CERTIFICATE-----"));

        let key_content = std::fs::read_to_string(&key_path).unwrap();
        assert!(key_content.starts_with("-----BEGIN PRIVATE KEY-----"));

        let (cert_der, key_der) = ca.forge_certificate("example.com");
        assert!(!cert_der.is_empty());
        assert!(!key_der.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_new_in_loads_existing_ca() {
        let dir = std::env::temp_dir().join("ca_test_reload");
        let _ = std::fs::remove_dir_all(&dir);

        // First run: generates new CA
        let ca1 = CertificationAuthority::new_in(&dir);
        let pem1 = ca1.ca_cert_pem().to_string();
        let _cert1 = ca1.forge_certificate("first.example.com").0;
        drop(ca1);

        // Second run: loads from disk — same CA cert PEM
        let ca2 = CertificationAuthority::new_in(&dir);
        assert_eq!(ca2.ca_cert_pem(), &pem1,
            "CA cert PEM should be identical across restarts");

        let (cert2, _) = ca2.forge_certificate("second.example.com");
        assert!(!cert2.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_new_in_forge_certificate_works() {
        let dir = std::env::temp_dir().join("ca_test_forge_in");
        let _ = std::fs::remove_dir_all(&dir);

        let ca = CertificationAuthority::new_in(&dir);
        let (cert_der, key_der) = ca.forge_certificate("custom-dir.example.com");
        assert!(!cert_der.is_empty(), "forged cert DER should not be empty");
        assert!(!key_der.is_empty(), "forged key DER should not be empty");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_new_in_caching_still_works() {
        let dir = std::env::temp_dir().join("ca_test_cache");
        let _ = std::fs::remove_dir_all(&dir);

        let ca = CertificationAuthority::new_in(&dir);
        let (cert1, _) = ca.forge_certificate("cached.example.com");
        let (cert2, _) = ca.forge_certificate("cached.example.com");
        assert_eq!(cert1, cert2, "same host should return cached cert with new_in");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
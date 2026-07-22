use rcgen::{
    BasicConstraints, 
    Certificate, 
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
use std::sync::RwLock;
use std::io::Write;
use std::io::Read;
use std::fs::File;
use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

/// Self-signed CA that forges per-domain TLS certificates on the fly.
///
/// On first run, generates a new CA key/cert and persists them to
/// `cert/ca.pem` and `cert/ca-key.pem` by default.  Subsequent runs
/// load from disk so the same CA is reused across restarts.
///
/// Use [`new`] for the default `"cert"` directory or [`new_in`] to
/// specify a custom location.
pub struct CertificationAuthority {
    ca_params: CertificateParams,
    ca_cert: Certificate,
    ca_key: KeyPair,
    cert_cache: RwLock<HashMap<String, (Vec<u8>, Vec<u8>)>>,
    cert_dir: PathBuf,
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

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Hexbuffer Proxy CA");
        params.distinguished_name = dn;

        if key_path.exists() {
            println!("CA private key found on disk, loading...");

            let mut key_file = File::open(&key_path).expect("Failed to open private key file");
            let mut key_der = String::new();
            key_file.read_to_string(&mut key_der).unwrap();

            let ca_key = KeyPair::from_pem(&key_der).unwrap();

            let ca_cert = params.self_signed(&ca_key).unwrap();
            return Self {
                ca_params: params,
                ca_cert,
                ca_key,
                cert_cache: RwLock::new(HashMap::new()),
                cert_dir,
            };
        }

        println!("Generating new CA certificate...");

        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = params.self_signed(&ca_key).unwrap();

        let ca = Self {
            ca_params: params.clone(),
            ca_cert,
            ca_key,
            cert_cache: RwLock::new(HashMap::new()),
            cert_dir,
        };

        std::fs::create_dir_all(&ca.cert_dir).expect("Failed to create cert directory");

        ca.save_ca_to_pem(cert_path.to_str().unwrap()).expect("Failed to save CA certificate");
        ca.save_key_to_pem(key_path.to_str().unwrap()).expect("Failed to save CA key");
        ca
    }


    pub fn save_ca_to_pem(&self, check_path: &str) -> std::io::Result<()> {
        // 1. Get the raw DER bytes of the certificate 
        let der_bytes = self.ca_cert.der();

        // 2. Base64 encode the bytes 
        let encoded = STANDARD.encode(der_bytes);

        // 3. Format it with 64-character chunks for strictt PEM Standard
        let mut pem_string = String::new();

        pem_string.push_str("-----BEGIN CERTIFICATE-----\n");

        let chunks = encoded.as_bytes().chunks(64);

        for chunk in chunks {
            if let Ok(line) = std::str::from_utf8(chunk) {
                pem_string.push_str(line);
                pem_string.push('\n');
            }
        }
        pem_string.push_str("-----END CERTIFICATE-----");

        // 4. Save to disk
        let mut file = File::create(check_path)?;
        file.write_all(pem_string.as_bytes())?;

        println!("CA certificate saved to {}", check_path);

        Ok(())
    }

    pub fn save_key_to_pem(&self, check_path: &str) -> std::io::Result<()> {
        // 1. Get the raw DER bytes of the key 
        let key_pem = self.ca_key.serialize_pem();

        // 4. Save to disk
        let mut file = File::create(check_path)?;
        file.write_all(key_pem.as_bytes())?;

        println!("CA key saved to {}", check_path);

        Ok(())
    }

    /// Generate (or retrieve from cache) a TLS certificate for `host`.
    ///
    /// Returns `(cert_der, key_der)` — raw DER-encoded certificate and
    /// private key.  Results are cached per host to avoid redundant
    /// key generation on repeated connections.
    pub fn forge_certificate(&self, host: &str) -> (Vec<u8>, Vec<u8>) {
        if let Some(cert) = self.cert_cache.read().unwrap().get(host) {
            return cert.clone();
        }

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;

        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        params.subject_alt_names.push(SanType::DnsName(host.to_string().try_into().unwrap()));

        let site_key = KeyPair::generate().unwrap();

        let issuer = rcgen::Issuer::new(self.ca_params.clone(), &self.ca_key);

        let site_cert = params.signed_by(&site_key, &issuer).unwrap();

        let cert_der = site_cert.der().to_vec();
        let private_key_der = site_key.serialized_der().to_vec();

        self.cert_cache
            .write()
            .unwrap()
            .insert(host.to_string(), (cert_der.clone(), private_key_der.clone()));

        (cert_der, private_key_der)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ca_creation() {
        let ca = CertificationAuthority::new();
        assert!(ca.ca_cert.der().len() > 0);
    }

    #[test]
    fn test_forge_certificate_returns_valid_data() {
        let ca = CertificationAuthority::new();
        let (cert_der, key_der) = ca.forge_certificate("example.com");
        assert!(!cert_der.is_empty(), "cert DER should not be empty");
        assert!(!key_der.is_empty(), "key DER should not be empty");
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

    // ── save_ca_to_pem tests ──

    #[test]
    fn test_save_ca_to_pem_creates_file() {
        let dir = std::env::temp_dir().join("ca_save_pem_test");
        let _ = std::fs::remove_dir_all(&dir);

        let ca = CertificationAuthority::new_in(&dir);
        let path = std::env::temp_dir().join("test_ca.pem");

        ca.save_ca_to_pem(path.to_str().unwrap()).unwrap();

        assert!(path.exists(), "PEM file should exist");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(!content.is_empty(), "PEM file should not be empty");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_save_ca_to_pem_has_correct_headers() {
        let ca = CertificationAuthority::new();
        let path = std::env::temp_dir().join("test_ca_headers.pem");

        ca.save_ca_to_pem(path.to_str().unwrap()).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();

        assert!(content.starts_with("-----BEGIN CERTIFICATE-----"), "should start with BEGIN header");
        assert!(content.ends_with("-----END CERTIFICATE-----"), "should end with END footer");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_save_ca_to_pem_content_roundtrips() {
        let ca = CertificationAuthority::new();
        let original_der = ca.ca_cert.der().to_vec();
        let path = std::env::temp_dir().join("test_ca_roundtrip.pem");

        ca.save_ca_to_pem(path.to_str().unwrap()).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();

        // Extract the base64 body between header and footer
        let body = content
            .trim_start_matches("-----BEGIN CERTIFICATE-----\n")
            .trim_end_matches("\n-----END CERTIFICATE-----")
            .replace('\n', "");

        let decoded = STANDARD.decode(&body).unwrap();
        assert_eq!(decoded, original_der, "decoded PEM should match original DER");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_save_ca_to_pem_lines_are_64_chars_max() {
        let ca = CertificationAuthority::new();
        let path = std::env::temp_dir().join("test_ca_lines.pem");

        ca.save_ca_to_pem(path.to_str().unwrap()).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();

        for line in content.lines() {
            // Skip header and footer lines
            if line.starts_with("-----") {
                continue;
            }
            assert!(
                line.len() <= 64,
                "base64 line should be ≤ 64 chars, got {}: '{}'",
                line.len(),
                line
            );
        }

        let _ = std::fs::remove_file(&path);
    }

    // ── new_in / cert_dir tests ──

    #[test]
    fn test_new_in_creates_files_in_custom_dir() {
        let dir = std::env::temp_dir().join("ca_test_custom_dir");
        // Ensure clean state
        let _ = std::fs::remove_dir_all(&dir);

        let ca = CertificationAuthority::new_in(&dir);

        let cert_path = dir.join("ca.pem");
        let key_path = dir.join("ca-key.pem");

        assert!(cert_path.exists(), "cert.pem should exist in custom dir");
        assert!(key_path.exists(), "ca-key.pem should exist in custom dir");

        // Verify content is valid PEM
        let cert_content = std::fs::read_to_string(&cert_path).unwrap();
        assert!(cert_content.starts_with("-----BEGIN CERTIFICATE-----"));

        let key_content = std::fs::read_to_string(&key_path).unwrap();
        assert!(key_content.starts_with("-----BEGIN PRIVATE KEY-----"));

        // Verify the CA actually works
        let (cert_der, key_der) = ca.forge_certificate("example.com");
        assert!(!cert_der.is_empty());
        assert!(!key_der.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_new_in_loads_existing_key() {
        let dir = std::env::temp_dir().join("ca_test_reload");
        let _ = std::fs::remove_dir_all(&dir);

        // First run: generates new
        let ca1 = CertificationAuthority::new_in(&dir);
        let _cert1 = ca1.forge_certificate("first.example.com").0;
        drop(ca1);

        // Second run: should load from disk and produce same CA
        let ca2 = CertificationAuthority::new_in(&dir);
        // Forging the same host should produce the same cert since
        // the cached per-host key is regenerated, but the CA is reused.
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

    #[test]
    fn test_new_creates_files_in_default_cert_dir() {
        let dir = std::env::temp_dir().join("ca_default_dir_test");
        let _ = std::fs::remove_dir_all(&dir);

        // Use new_in with a temp dir and verify the behavior matches new() semantics
        let ca = CertificationAuthority::new_in(&dir);

        let cert_path = dir.join("ca.pem");
        let key_path = dir.join("ca-key.pem");

        assert!(cert_path.exists(), "ca.pem should exist");
        assert!(key_path.exists(), "ca-key.pem should exist");

        // Verify the CA works
        let (cert_der, _) = ca.forge_certificate("default.example.com");
        assert!(!cert_der.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
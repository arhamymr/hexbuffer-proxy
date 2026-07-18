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
use std::sync::{Mutex};
use std::io::Write;
use std::io::Read;
use std::fs::File;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

pub struct CertificationAuthority {
    ca_params: CertificateParams,
    ca_cert: Certificate,
    ca_key: KeyPair,
    cert_cache: Mutex<HashMap<String, (Vec<u8>, Vec<u8>)>>,
}

impl CertificationAuthority {
    pub fn new() -> Self {
        // Check certificate on disk
        let cert_path = "cert/ca.pem";
        let key_path = "cert/ca-key.pem";

        let  mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Hexbuffer Proxy CA");
        params.distinguished_name = dn;


        // Cek certificate on disk
        if Path::new(key_path).exists() {
            println!("CA private key found on disk, loading...");

            //1. Read string private key from file
            let mut key_file = File::open(key_path).expect("Failed to open private key file");
            let mut key_der = String::new();
            key_file.read_to_string(&mut key_der).unwrap();

            // 2. Reconstruct keypair from the DER bytes 
            let ca_key = KeyPair::from_pem(&key_der).unwrap();

            // self sign it again to pupulate the certificate object 
            let ca_cert = params.self_signed(&ca_key).unwrap();
            return Self {
                ca_params: params,
                ca_cert,
                ca_key,
                cert_cache: Mutex::new(HashMap::new()),
            }
        }

        println!("Generating new CA certificate...");

        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = params.self_signed(&ca_key).unwrap();

        let ca = Self {
            ca_params: params.clone(),
            ca_cert,
            ca_key,
            cert_cache: Mutex::new(HashMap::new()),
        };

        // ensure cert directory exists before saving
        std::fs::create_dir_all("cert").expect("Failed to create cert directory");

        ca.save_ca_to_pem(cert_path).expect("Failed to save CA certificate");
        ca.save_key_to_pem(key_path).expect("Failed to save CA key");
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

    pub fn forge_certificate(&self, host: &str) -> (Vec<u8>, Vec<u8>) {
        let mut cache = self.cert_cache.lock().unwrap();

        if let Some(cert) = cache.get(host) {
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

        cache.insert(host.to_string(), (cert_der.clone(), private_key_der.clone()));

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
        let ca = CertificationAuthority::new();
        let path = std::env::temp_dir().join("test_ca.pem");

        ca.save_ca_to_pem(path.to_str().unwrap()).unwrap();

        assert!(path.exists(), "PEM file should exist");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(!content.is_empty(), "PEM file should not be empty");

        let _ = std::fs::remove_file(&path);
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
}
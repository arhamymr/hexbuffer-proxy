use rcgen::{BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, SanType};

use std::collections::HashMap;
use std::sync::{Mutex};
use std::io::Write;
use std::fs::File;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

pub struct CertificationAuthority {
    ca_cert: Certificate,
    ca_key: KeyPair,
    cert_cache: Mutex<HashMap<String, (Vec<u8>, Vec<u8>)>>,
}

impl CertificationAuthority {
    pub fn new() -> Self {
        let  mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Hexbuffer Proxy CA");

        params.distinguished_name = dn;


        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = params.self_signed(&ca_key).unwrap();

        let ca = Self {
            ca_cert,
            ca_key,
            cert_cache: Mutex::new(HashMap::new()),
        };


        ca.save_ca_to_pem("ca.pem").expect("Failed to save CA certificate");
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


    pub fn forge_certificate(&self, host: &str) -> (Vec<u8>, Vec<u8>) {
        let mut cache = self.cert_cache.lock().unwrap();

        if let Some(cert) = cache.get(host) {
            return cert.clone();
        }

        let mut params = CertificateParams::default();
        params.is_ca = IsCa::NoCa;

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        params.distinguished_name = dn;
        params.subject_alt_names.push(SanType::DnsName(host.to_string().try_into().unwrap()));

        let site_key = KeyPair::generate().unwrap();
        let site_cert = params.signed_by(&site_key, &self.ca_cert, &self.ca_key).unwrap();

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
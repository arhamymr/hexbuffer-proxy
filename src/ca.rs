use rcgen::{BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, SanType};

use std::collections::HashMap;
use std::sync::{Mutex};

pub struct CertificateAuthority {
    ca_cert: Certificate,
    ca_key: KeyPair,
    cert_cache: Mutex<HashMap<String, (Vec<u8>, Vec<u8>)>>,
}

impl CertificateAuthority {
    pub fn new() -> Self {
        let  mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Hexbuffer Proxy CA");

        params.distinguished_name = dn;


        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = params.self_signed(&ca_key).unwrap();

        Self {
            ca_cert,
            ca_key,
            cert_cache: Mutex::new(HashMap::new()),
        }
    }


    pub fn forge_certificate(&self, host: &str) -> (Vec<u8>, Vec<u8>) {
        let mut cache = self.cert_cache.lock().unwrap();

        if let Some(cert) = cache.get(host) {
            return cert.clone();
        }

        let mut params = CertificateParams::default();
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
        let ca = CertificateAuthority::new();
        assert!(ca.ca_cert.der().len() > 0);
    }

    #[test]
    fn test_forge_certificate_returns_valid_data() {
        let ca = CertificateAuthority::new();
        let (cert_der, key_der) = ca.forge_certificate("example.com");
        assert!(!cert_der.is_empty(), "cert DER should not be empty");
        assert!(!key_der.is_empty(), "key DER should not be empty");
    }

    #[test]
    fn test_forge_certificate_caching() {
        let ca = CertificateAuthority::new();
        let (cert1, _) = ca.forge_certificate("example.com");
        let (cert2, _) = ca.forge_certificate("example.com");
        assert_eq!(cert1, cert2, "same host should return cached cert");
    }

    #[test]
    fn test_forge_different_hosts() {
        let ca = CertificateAuthority::new();
        let (cert1, _) = ca.forge_certificate("example.com");
        let (cert2, _) = ca.forge_certificate("other.org");
        assert_ne!(cert1, cert2, "different hosts should produce different certs");
    }
}
//! Certificate pinning for the forwarder's upstream TLS.
//!
//! The pin lives in the rustls verifier, so it runs on every handshake and
//! nothing above TLS (connection pooling, a per-request check that a reused
//! connection skips) can bypass it. Resumption is off, so every connection
//! makes a full handshake and presents its certificate.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, RwLock};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{Resumption, WebPkiServerVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Digest, Sha256};

pub fn sha256_der(der: &[u8]) -> [u8; 32] {
    Sha256::digest(der).into()
}

/// Why the verifier last refused a certificate, with its SHA-256 fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejected {
    /// Chains to a trusted root but is not attested: re-attestation may
    /// learn it (a rotated certificate).
    Unpinned([u8; 32]),
    /// Does not chain to a trusted root for the name, whether pinned or not.
    Untrusted([u8; 32]),
}

/// The attested end-entity certificate fingerprints. It only grows.
pub struct PinSet {
    pins: RwLock<BTreeSet<[u8; 32]>>,
    last: Mutex<Option<Rejected>>,
}

impl std::fmt::Debug for PinSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinSet")
            .field("pins", &self.pins.read().map(|p| p.len()).unwrap_or(0))
            .finish_non_exhaustive()
    }
}

impl PinSet {
    pub fn new(seed: BTreeSet<[u8; 32]>) -> Arc<Self> {
        Arc::new(Self {
            pins: RwLock::new(seed),
            last: Mutex::new(None),
        })
    }

    pub fn extend(&self, more: &BTreeSet<[u8; 32]>) {
        self.pins
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .extend(more.iter().copied());
    }

    pub fn contains(&self, fp: &[u8; 32]) -> bool {
        self.pins
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains(fp)
    }

    /// Takes the last rejection, if any.
    pub fn take_rejected(&self) -> Option<Rejected> {
        self.last.lock().unwrap_or_else(|e| e.into_inner()).take()
    }

    /// Takes the last rejection; Some only when it was an unpinned,
    /// otherwise trusted certificate.
    pub fn take_unknown(&self) -> Option<[u8; 32]> {
        match self.take_rejected()? {
            Rejected::Unpinned(fp) => Some(fp),
            Rejected::Untrusted(_) => None,
        }
    }

    fn reject(&self, r: Rejected) {
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) = Some(r);
    }
}

/// WebPKI first (chain to the roots, name, validity), then the pin.
/// Handshake signature checks delegate to WebPKI.
#[derive(Debug)]
pub struct PinnedVerifier {
    webpki: Arc<WebPkiServerVerifier>,
    pins: Arc<PinSet>,
}

impl PinnedVerifier {
    pub fn new(roots: Arc<rustls::RootCertStore>, pins: Arc<PinSet>) -> Result<Self, String> {
        let webpki = WebPkiServerVerifier::builder_with_provider(roots, Arc::new(provider()))
            .build()
            .map_err(|e| format!("forwarder: certificate verifier: {e}"))?;
        Ok(Self { webpki, pins })
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let fp = sha256_der(end_entity.as_ref());
        if let Err(e) = self.webpki.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            self.pins.reject(Rejected::Untrusted(fp));
            return Err(e);
        }
        if !self.pins.contains(&fp) {
            self.pins.reject(Rejected::Unpinned(fp));
            return Err(Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.webpki.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.webpki.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.webpki.supported_verify_schemes()
    }
}

fn provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::ring::default_provider()
}

/// The operating system's trust roots; an empty store is an error.
pub fn native_roots() -> Result<Arc<rustls::RootCertStore>, String> {
    let loaded = rustls_native_certs::load_native_certs();
    let mut store = rustls::RootCertStore::empty();
    store.add_parsable_certificates(loaded.certs);
    if store.is_empty() {
        return Err(format!(
            "forwarder: no usable system trust roots ({} load errors)",
            loaded.errors.len()
        ));
    }
    Ok(Arc::new(store))
}

/// ring provider, PinnedVerifier, `resumption = Resumption::disabled()`, no ALPN (HTTP/1.1).
pub fn pinned_tls(
    roots: Arc<rustls::RootCertStore>,
    pins: Arc<PinSet>,
) -> Result<rustls::ClientConfig, String> {
    let verifier = PinnedVerifier::new(roots, pins)?;
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("forwarder: TLS versions: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    cfg.resumption = Resumption::disabled();
    cfg.alpn_protocols = Vec::new();
    cfg.enable_early_data = false;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use std::collections::BTreeSet;
    use std::sync::Arc;

    fn cert(pem: &[u8]) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(pem).unwrap()
    }

    fn roots() -> Arc<rustls::RootCertStore> {
        let mut store = rustls::RootCertStore::empty();
        store
            .add(cert(include_bytes!("../../tests/fixtures/tls/ca.pem")))
            .unwrap();
        Arc::new(store)
    }

    #[test]
    fn sha256_der_is_the_sha256_of_the_der_bytes() {
        // printf abc | shasum -a 256
        assert_eq!(
            hex::encode(sha256_der(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn the_pin_set_grows_and_reports_the_last_rejection_once() {
        let pins = PinSet::new(BTreeSet::from([[1; 32]]));
        assert!(pins.contains(&[1; 32]));
        assert!(!pins.contains(&[2; 32]));
        pins.extend(&BTreeSet::from([[2; 32]]));
        assert!(pins.contains(&[1; 32]) && pins.contains(&[2; 32]));
        assert_eq!(pins.take_unknown(), None);
        assert!(!format!("{pins:?}").is_empty());
    }

    #[test]
    fn the_verifier_checks_the_chain_and_then_the_pin() {
        let a = cert(include_bytes!("../../tests/fixtures/tls/a.pem"));
        let b = cert(include_bytes!("../../tests/fixtures/tls/b.pem"));
        let c = cert(include_bytes!("../../tests/fixtures/tls/c.pem"));
        let pins = PinSet::new(BTreeSet::from([
            sha256_der(a.as_ref()),
            sha256_der(c.as_ref()),
        ]));
        let v = PinnedVerifier::new(roots(), pins.clone()).unwrap();
        let name = ServerName::try_from("127.0.0.1").unwrap();
        let now = UnixTime::now();
        assert!(v.verify_server_cert(&a, &[], &name, &[], now).is_ok());
        assert_eq!(pins.take_rejected(), None);

        assert!(v.verify_server_cert(&b, &[], &name, &[], now).is_err());
        assert_eq!(
            pins.take_rejected(),
            Some(Rejected::Unpinned(sha256_der(b.as_ref())))
        );
        assert_eq!(pins.take_rejected(), None, "taken once");

        assert!(v.verify_server_cert(&b, &[], &name, &[], now).is_err());
        assert_eq!(pins.take_unknown(), Some(sha256_der(b.as_ref())));

        // Pinned, but self-signed: the chain check runs first and fails.
        assert!(v.verify_server_cert(&c, &[], &name, &[], now).is_err());
        assert_eq!(
            pins.take_rejected(),
            Some(Rejected::Untrusted(sha256_der(c.as_ref())))
        );
        assert!(v.verify_server_cert(&c, &[], &name, &[], now).is_err());
        assert_eq!(pins.take_unknown(), None, "untrusted is not unknown");

        // The right certificate for the wrong name.
        let other = ServerName::try_from("cloud-api.near.ai").unwrap();
        assert!(v.verify_server_cert(&a, &[], &other, &[], now).is_err());

        pins.extend(&BTreeSet::from([sha256_der(b.as_ref())]));
        assert!(v.verify_server_cert(&b, &[], &name, &[], now).is_ok());
    }

    #[test]
    fn the_client_config_never_resumes_and_offers_no_alpn() {
        let cfg = pinned_tls(roots(), PinSet::new(BTreeSet::new())).unwrap();
        assert!(cfg.alpn_protocols.is_empty());
        assert!(!cfg.enable_early_data);
        assert_eq!(
            format!("{:?}", cfg.resumption),
            format!("{:?}", rustls::client::Resumption::disabled())
        );
    }

    #[test]
    fn native_roots_load() {
        assert!(!native_roots().unwrap().is_empty());
    }
}

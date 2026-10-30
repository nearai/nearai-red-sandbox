//! The signed release manifest: `latest.json` and `latest.json.sig`.
//!
//! The signature is checked over the bytes exactly as fetched, before
//! anything is parsed: no re-serialization, no trimming of the manifest.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, VerifyingKey};

pub const MANIFEST_URL: &str =
    "https://github.com/nearai/nearai-red-sandbox/releases/latest/download/latest.json";
pub const SIGNATURE_URL: &str =
    "https://github.com/nearai/nearai-red-sandbox/releases/latest/download/latest.json.sig";
pub const MAX_MANIFEST_BYTES: u64 = 64 << 10;
pub const MAX_SIGNATURE_BYTES: u64 = 1 << 10;

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct Tarball {
    pub name: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct InstallSh {
    pub sha256: String,
}

/// No deny_unknown_fields: serde forbids it with flatten, and a later
/// release may add fields.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct SignedManifest {
    #[serde(flatten)]
    pub manifest: ironwire_update::Manifest,
    pub tarball: Tarball,
    pub install_sh: InstallSh,
    pub published: chrono::DateTime<chrono::Utc>,
}

/// Signature first (exact bytes, `verify_strict`), then parse, then the
/// spec's rules (version pattern, tarball name, lowercase hex digests).
pub fn verify(manifest: &[u8], signature: &[u8], key: &[u8; 32]) -> Result<SignedManifest, String> {
    let signature = signature.strip_suffix(b"\n").unwrap_or(signature);
    let raw = STANDARD
        .decode(signature)
        .map_err(|e| format!("latest.json.sig: signature is not base64: {e}"))?;
    let raw = <[u8; 64]>::try_from(raw.as_slice())
        .map_err(|_| format!("latest.json.sig: signature is not 64 bytes ({})", raw.len()))?;
    let key = VerifyingKey::from_bytes(key)
        .map_err(|e| format!("latest.json: the update key is not a valid Ed25519 key: {e}"))?;
    key.verify_strict(manifest, &Signature::from_bytes(&raw))
        .map_err(|_| "latest.json: signature does not verify with the update key".to_string())?;

    let m: SignedManifest =
        serde_json::from_slice(manifest).map_err(|e| format!("latest.json: {e}"))?;
    let latest = &m.manifest.latest;
    if !is_version(latest) {
        return Err(format!("latest.json: latest {latest:?} is not X.Y.Z"));
    }
    if let Some(min) = &m.manifest.minimum_supported
        && !is_version(min)
    {
        return Err(format!("latest.json: minimum_supported {min:?} is not X.Y.Z"));
    }
    let want = format!("rts-{latest}-aarch64-apple-darwin.tar.gz");
    if m.tarball.name != want {
        return Err(format!("latest.json: tarball.name {:?} is not {want:?}", m.tarball.name));
    }
    if !is_sha256(&m.tarball.sha256) {
        return Err("latest.json: tarball.sha256 is not 64 lowercase hex characters".into());
    }
    if !is_sha256(&m.install_sh.sha256) {
        return Err("latest.json: install_sh.sha256 is not 64 lowercase hex characters".into());
    }
    Ok(m)
}

/// `^[0-9]+\.[0-9]+\.[0-9]+$`.
fn is_version(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::{Signer, SigningKey};

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }
    fn public() -> [u8; 32] {
        key().verifying_key().to_bytes()
    }
    const GOOD: &str = "{\n  \"latest\": \"0.2.0\",\n  \"minimum_supported\": \"0.1.0\",\n  \"published\": \"2026-11-02T18:04:11Z\",\n  \"tarball\": {\n    \"name\": \"rts-0.2.0-aarch64-apple-darwin.tar.gz\",\n    \"sha256\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n  },\n  \"install_sh\": {\n    \"sha256\": \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"\n  }\n}\n";
    const A64: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B64: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn sig(bytes: &[u8], k: &SigningKey) -> Vec<u8> {
        STANDARD.encode(k.sign(bytes).to_bytes()).into_bytes()
    }
    fn signed(text: &str) -> Result<SignedManifest, String> {
        verify(text.as_bytes(), &sig(text.as_bytes(), &key()), &public())
    }

    #[test]
    fn the_test_digests_are_64_characters() {
        assert_eq!((A64.len(), B64.len()), (64, 64));
        assert!(GOOD.contains(A64) && GOOD.contains(B64));
    }

    #[test]
    fn a_signed_manifest_verifies_and_parses() {
        let m = verify(GOOD.as_bytes(), &sig(GOOD.as_bytes(), &key()), &public()).unwrap();
        assert_eq!(m.manifest.latest, "0.2.0");
        assert_eq!(m.manifest.minimum_supported.as_deref(), Some("0.1.0"));
        assert_eq!(m.manifest.summary, None);
        assert_eq!(m.tarball.name, "rts-0.2.0-aarch64-apple-darwin.tar.gz");
        assert_eq!(m.tarball.sha256, A64);
        assert_eq!(m.install_sh.sha256, B64);
        assert_eq!(m.published.to_rfc3339(), "2026-11-02T18:04:11+00:00");
    }

    #[test]
    fn a_manifest_without_a_floor_verifies() {
        let text = GOOD.replace("  \"minimum_supported\": \"0.1.0\",\n", "");
        assert_eq!(signed(&text).unwrap().manifest.minimum_supported, None);
    }

    #[test]
    fn a_trailing_newline_on_the_signature_is_tolerated() {
        let mut s = sig(GOOD.as_bytes(), &key());
        s.push(b'\n');
        assert!(verify(GOOD.as_bytes(), &s, &public()).is_ok());
        s.push(b'\n');
        assert!(verify(GOOD.as_bytes(), &s, &public()).is_err());
    }

    #[test]
    fn a_trailing_newline_on_the_manifest_breaks_the_signature() {
        let s = sig(GOOD.as_bytes(), &key());
        let longer = format!("{GOOD}\n");
        let e = verify(longer.as_bytes(), &s, &public()).unwrap_err();
        assert!(e.contains("signature"), "{e}");
    }

    #[test]
    fn reserialized_json_is_refused() {
        let s = sig(GOOD.as_bytes(), &key());
        let value: serde_json::Value = serde_json::from_str(GOOD).unwrap();
        let again = serde_json::to_vec(&value).unwrap();
        assert_ne!(again, GOOD.as_bytes());
        let e = verify(&again, &s, &public()).unwrap_err();
        assert!(e.contains("signature"), "{e}");
    }

    #[test]
    fn a_tampered_byte_is_refused() {
        let s = sig(GOOD.as_bytes(), &key());
        let tampered = GOOD.replace("0.2.0", "0.3.0");
        assert_ne!(tampered, GOOD);
        let e = verify(tampered.as_bytes(), &s, &public()).unwrap_err();
        assert!(e.contains("signature"), "{e}");
    }

    #[test]
    fn the_wrong_key_is_refused() {
        let s = sig(GOOD.as_bytes(), &SigningKey::from_bytes(&[8; 32]));
        let e = verify(GOOD.as_bytes(), &s, &public()).unwrap_err();
        assert!(e.contains("signature"), "{e}");
    }

    #[test]
    fn malformed_signatures_are_refused() {
        for bad in [
            b"".to_vec(),
            b"not base64!".to_vec(),
            STANDARD.encode([0u8; 63]).into_bytes(),
            STANDARD.encode([0u8; 65]).into_bytes(),
            sig(GOOD.as_bytes(), &key())[..40].to_vec(),
            STANDARD.encode([0u8; 64]).into_bytes(),
        ] {
            let e = verify(GOOD.as_bytes(), &bad, &public()).unwrap_err();
            assert!(e.contains("signature"), "{e}");
        }
    }

    #[test]
    fn signed_but_invalid_manifests_are_refused() {
        let cases: Vec<(String, &str)> = vec![
            (GOOD.replace("0.2.0", "v0.2.0"), "latest"),
            (GOOD.replace("0.2.0", "0.2"), "latest"),
            (GOOD.replace("\"0.1.0\"", "\"x\""), "minimum_supported"),
            (GOOD.replace("rts-0.2.0-", "rts-0.3.0-"), "tarball.name"),
            (GOOD.replace("rts-0.2.0-aarch64-apple-darwin.tar.gz", "../rts.tar.gz"), "tarball.name"),
            (GOOD.replace(A64, &A64.to_uppercase()), "tarball.sha256"),
            (GOOD.replace(A64, &A64[1..]), "tarball.sha256"),
            (GOOD.replace(B64, &B64.to_uppercase()), "install_sh.sha256"),
            (GOOD.replace(B64, &format!("{B64}b")), "install_sh.sha256"),
            (GOOD.replace("2026-11-02T18:04:11Z", "yesterday"), "latest.json"),
            (
                GOOD.replace(
                    &format!(",\n  \"install_sh\": {{\n    \"sha256\": \"{B64}\"\n  }}"),
                    "",
                ),
                "install_sh",
            ),
            ("not JSON at all".to_string(), "latest.json"),
        ];
        for (text, needle) in cases {
            assert_ne!(text, GOOD);
            let e = signed(&text).unwrap_err();
            assert!(e.starts_with("latest.json: "), "{e}");
            assert!(e.contains(needle), "{needle}: {e}");
            assert!(!e.contains("signature"), "{e}");
        }
    }

    #[test]
    fn unknown_fields_are_accepted() {
        let text = GOOD.replacen("{\n", "{\n  \"channel\": \"stable\",\n", 1);
        assert!(signed(&text).is_ok());
    }

    #[test]
    fn the_urls_and_caps_are_pinned() {
        assert_eq!(
            MANIFEST_URL,
            "https://github.com/nearai/nearai-red-sandbox/releases/latest/download/latest.json"
        );
        assert_eq!(SIGNATURE_URL, format!("{MANIFEST_URL}.sig"));
        assert_eq!((MAX_MANIFEST_BYTES, MAX_SIGNATURE_BYTES), (65536, 1024));
    }
}

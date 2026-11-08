//! Ephemeral proof for the app that initiates a native login.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub(super) struct Pkce {
    verifier: Zeroizing<String>,
    pub(super) state: String,
}

impl Pkce {
    pub(super) fn generate() -> Result<Self, String> {
        Ok(Self {
            verifier: Zeroizing::new(random_secret()?),
            state: random_secret()?,
        })
    }

    pub(super) fn challenge(&self) -> String {
        challenge(&self.verifier)
    }

    pub(super) fn verifier(&self) -> &str {
        &self.verifier
    }
}

fn random_secret() -> Result<String, String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    SystemRandom::new()
        .fill(bytes.as_mut())
        .map_err(|_| "Cannot prepare NEAR AI sign-in")?;
    Ok(URL_SAFE_NO_PAD.encode(bytes.as_ref()))
}

fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7636_s256_vector() {
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn attempts_have_independent_verifiers_and_state() {
        let first = Pkce::generate().unwrap();
        let second = Pkce::generate().unwrap();
        assert_eq!(first.verifier().len(), 43);
        assert_eq!(first.state.len(), 43);
        assert_ne!(first.verifier(), first.state);
        assert_ne!(first.verifier(), second.verifier());
        assert_ne!(first.state, second.state);
        assert!(!first.challenge().contains(first.verifier()));
    }
}

use super::{
    CredentialStore, InferenceCredential, LaunchCredential, LoginOptions, valid_id, valid_key,
};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const UNAVAILABLE: &str = "NEAR AI credential storage unavailable";
const INVALID: &str = "Stored NEAR AI credential is invalid; run rts login";

pub(super) struct NativeStore {
    #[cfg(not(test))]
    entry: keyring_core::Entry,
}

impl NativeStore {
    #[cfg(test)]
    pub(super) fn new() -> Result<Self, String> {
        Err(UNAVAILABLE.into())
    }

    #[cfg(not(test))]
    pub(super) fn new() -> Result<Self, String> {
        #[cfg(target_os = "macos")]
        let store = apple_native_keyring_store::keychain::Store::new().map_err(|_| UNAVAILABLE)?;
        #[cfg(target_os = "linux")]
        let store = zbus_secret_service_keyring_store::Store::new().map_err(|_| UNAVAILABLE)?;
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            use keyring_core::api::CredentialStoreApi;
            let entry = store
                .build("nearai-red-sandbox.inference", "default-v1", None)
                .map_err(|_| UNAVAILABLE)?;
            Ok(Self { entry })
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            Err(UNAVAILABLE.into())
        }
    }
}

impl CredentialStore for NativeStore {
    fn load(&self) -> Result<Option<InferenceCredential>, String> {
        #[cfg(test)]
        {
            Err(UNAVAILABLE.into())
        }
        #[cfg(not(test))]
        {
            match self.entry.get_secret() {
                Ok(bytes) => decode(&Zeroizing::new(bytes)).map(Some),
                Err(keyring_core::Error::NoEntry) => Ok(None),
                Err(_) => Err(UNAVAILABLE.into()),
            }
        }
    }

    fn load_launch(&self, options: &LoginOptions) -> Result<Option<LaunchCredential>, String> {
        #[cfg(test)]
        {
            let _ = options;
            Err(UNAVAILABLE.into())
        }
        #[cfg(not(test))]
        {
            match self.entry.get_secret() {
                Ok(bytes) => {
                    let bytes = Zeroizing::new(bytes);
                    let credential = decode_launch(&bytes)?;
                    if !credential.sponsored {
                        super::check_selection(&decode(&bytes)?, options)?;
                    }
                    Ok(Some(credential))
                }
                Err(keyring_core::Error::NoEntry) => Ok(None),
                Err(_) => Err(UNAVAILABLE.into()),
            }
        }
    }

    fn save_sponsored(&self, key: &super::HostSecret) -> Result<(), String> {
        #[cfg(test)]
        {
            let _ = key;
            Err(UNAVAILABLE.into())
        }
        #[cfg(not(test))]
        {
            let document = encode_sponsored(key)?;
            self.entry
                .set_secret(document.as_bytes())
                .map_err(|_| UNAVAILABLE)?;
            let bytes = Zeroizing::new(self.entry.get_secret().map_err(|_| UNAVAILABLE)?);
            verify_sponsored(key, &bytes)
        }
    }

    fn save(&self, credential: &InferenceCredential) -> Result<(), String> {
        #[cfg(test)]
        {
            let _ = credential;
            Err(UNAVAILABLE.into())
        }
        #[cfg(not(test))]
        {
            let document = encode(credential)?;
            self.entry
                .set_secret(document.as_bytes())
                .map_err(|_| UNAVAILABLE)?;
            let loaded = self.load()?.ok_or(UNAVAILABLE)?;
            if loaded.key.expose_secret() != credential.key.expose_secret()
                || loaded.key_id != credential.key_id
                || loaded.organization_id != credential.organization_id
                || loaded.workspace_id != credential.workspace_id
            {
                return Err("NEAR AI credential storage verification failed".into());
            }
            Ok(())
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u8,
    key: String,
    key_id: String,
    organization_id: String,
    workspace_id: String,
}
impl Drop for Document {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

pub(super) fn decode(bytes: &[u8]) -> Result<InferenceCredential, String> {
    if bytes.len() > 16384 {
        return Err(INVALID.into());
    }
    let mut document: Document = serde_json::from_slice(bytes).map_err(|_| INVALID)?;
    if document.version != 1
        || !valid_key(&document.key)
        || !valid_id(&document.key_id)
        || !valid_id(&document.organization_id)
        || !valid_id(&document.workspace_id)
    {
        return Err(INVALID.into());
    }
    Ok(InferenceCredential {
        key: std::mem::take(&mut document.key).into(),
        key_id: std::mem::take(&mut document.key_id),
        organization_id: std::mem::take(&mut document.organization_id),
        workspace_id: std::mem::take(&mut document.workspace_id),
    })
}

pub(super) fn encode(credential: &InferenceCredential) -> Result<Zeroizing<String>, String> {
    #[derive(Serialize)]
    struct Borrowed<'a> {
        version: u8,
        key: &'a str,
        key_id: &'a str,
        organization_id: &'a str,
        workspace_id: &'a str,
    }
    serde_json::to_string(&Borrowed {
        version: 1,
        key: credential.key.expose_secret(),
        key_id: &credential.key_id,
        organization_id: &credential.organization_id,
        workspace_id: &credential.workspace_id,
    })
    .map(Zeroizing::new)
    .map_err(|_| INVALID.into())
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SponsoredDocument {
    version: u8,
    kind: String,
    key: String,
}
impl Drop for SponsoredDocument {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

pub(super) fn decode_launch(bytes: &[u8]) -> Result<LaunchCredential, String> {
    if let Ok(credential) = decode(bytes) {
        return Ok(LaunchCredential {
            key: credential.key,
            sponsored: false,
        });
    }
    if bytes.len() > 16384 {
        return Err(INVALID.into());
    }
    let mut document: SponsoredDocument = serde_json::from_slice(bytes).map_err(|_| INVALID)?;
    if document.version != 2 || document.kind != "sponsored" || !valid_key(&document.key) {
        return Err(INVALID.into());
    }
    Ok(LaunchCredential {
        key: std::mem::take(&mut document.key).into(),
        sponsored: true,
    })
}

pub(super) fn encode_sponsored(key: &super::HostSecret) -> Result<Zeroizing<String>, String> {
    #[derive(Serialize)]
    struct Borrowed<'a> {
        version: u8,
        kind: &'a str,
        key: &'a str,
    }
    if !valid_key(key.expose_secret()) {
        return Err(INVALID.into());
    }
    serde_json::to_string(&Borrowed {
        version: 2,
        kind: "sponsored",
        key: key.expose_secret(),
    })
    .map(Zeroizing::new)
    .map_err(|_| INVALID.into())
}

pub(super) fn verify_sponsored(key: &super::HostSecret, bytes: &[u8]) -> Result<(), String> {
    let loaded = decode_launch(bytes)?;
    if !loaded.sponsored || loaded.key.expose_secret() != key.expose_secret() {
        return Err("NEAR AI credential storage verification failed".into());
    }
    Ok(())
}

use super::{CredentialStore, InferenceCredential, valid_id, valid_key};
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

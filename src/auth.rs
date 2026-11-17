//! Host-only NEAR AI Cloud sign-in. Session and refresh tokens never persist.

use ironwire_proxy::embed::HostSecret;
use std::time::{Duration, Instant};

mod browser;
mod cloud;
mod sponsored;
mod storage;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Provider {
    #[default]
    Github,
    Google,
}

#[derive(Clone, Debug, Default)]
pub struct LoginOptions {
    pub provider: Provider,
    pub organization: Option<String>,
    pub workspace: Option<String>,
}

pub struct InferenceCredential {
    pub key: HostSecret,
    pub organization_id: String,
    pub workspace_id: String,
    pub key_id: String,
}

impl std::fmt::Debug for InferenceCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InferenceCredential")
            .finish_non_exhaustive()
    }
}

/// Host-only active key and its source. No secret is included in debug output.
pub struct LaunchCredential {
    pub key: HostSecret,
    pub sponsored: bool,
}

impl std::fmt::Debug for LaunchCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaunchCredential")
            .field("sponsored", &self.sponsored)
            .finish_non_exhaustive()
    }
}

pub fn load_for_launch(options: &LoginOptions) -> Result<LaunchCredential, String> {
    validate_options(options)?;
    let store = storage::NativeStore::new()?;
    if let Some(credential) = store.load_launch(options)? {
        return Ok(credential);
    }
    let credential = login_with(&store, options)?;
    Ok(LaunchCredential {
        key: credential.key,
        sponsored: false,
    })
}

/// Import a regular host file. On Unix it must have no group/other permissions.
pub fn import_sponsored(path: &std::path::Path) -> Result<(), String> {
    let key = sponsored::read_key(path)?;
    storage::NativeStore::new()?.save_sponsored(&key)
}

/// An explicit sign-in always creates and stores a dedicated inference key.
pub fn login(options: &LoginOptions) -> Result<InferenceCredential, String> {
    validate_options(options)?;
    let store = storage::NativeStore::new()?;
    login_with(&store, options)
}

/// Called only by an explicit launch, after local launch preflight succeeds.
pub fn load_or_login(options: &LoginOptions) -> Result<InferenceCredential, String> {
    validate_options(options)?;
    let store = storage::NativeStore::new()?;
    load_with(&store, options, || login_with(&store, options))
}

fn login_with(
    store: &dyn CredentialStore,
    options: &LoginOptions,
) -> Result<InferenceCredential, String> {
    crate::sys::catch_termination_signals();
    login_ceremony(store, options, &|| crate::sys::take_signal().is_some())
}

/// Personal sign-in while the running session retains signal ownership.
pub fn login_during_session(
    options: &LoginOptions,
    cancelled: &dyn Fn() -> bool,
) -> Result<InferenceCredential, String> {
    validate_options(options)?;
    let store = storage::NativeStore::new()?;
    login_ceremony(&store, options, cancelled)
}

fn login_ceremony(
    store: &dyn CredentialStore,
    options: &LoginOptions,
    cancelled: &dyn Fn() -> bool,
) -> Result<InferenceCredential, String> {
    let deadline = Instant::now() + Duration::from_secs(300);
    let api = cloud::CloudApi::live_with_cancel(deadline, cancelled)?;
    let callback = browser::Callback::bind()?;
    let url = api.authorize_url(options.provider, &callback.url())?;
    check_cancelled(cancelled)?;
    crate::brand::progress::message("Opening your browser to sign in to NEAR AI Cloud…");
    browser::open(&url)?;
    callback.receive(deadline, cancelled, |session| {
        mint_and_save(store, cancelled, || api.mint(&session, options))
    })
}

fn check_cancelled(cancelled: &dyn Fn() -> bool) -> Result<(), String> {
    if cancelled() {
        return Err("NEAR AI sign-in interrupted".into());
    }
    Ok(())
}

fn mint_and_save(
    store: &dyn CredentialStore,
    cancelled: &dyn Fn() -> bool,
    mint: impl FnOnce() -> Result<InferenceCredential, String>,
) -> Result<InferenceCredential, String> {
    check_cancelled(cancelled)?;
    let credential = mint()?;
    check_cancelled(cancelled)?;
    store.save(&credential)?;
    Ok(credential)
}

trait CredentialStore {
    fn load(&self) -> Result<Option<InferenceCredential>, String>;
    fn save(&self, credential: &InferenceCredential) -> Result<(), String>;
    fn load_launch(&self, options: &LoginOptions) -> Result<Option<LaunchCredential>, String> {
        self.load()?
            .map(|credential| {
                check_selection(&credential, options)?;
                Ok(LaunchCredential {
                    key: credential.key,
                    sponsored: false,
                })
            })
            .transpose()
    }
    fn save_sponsored(&self, _: &HostSecret) -> Result<(), String> {
        Err("NEAR AI credential storage unavailable".into())
    }
}

fn load_with(
    store: &dyn CredentialStore,
    options: &LoginOptions,
    ceremony: impl FnOnce() -> Result<InferenceCredential, String>,
) -> Result<InferenceCredential, String> {
    if let Some(credential) = store.load()? {
        check_selection(&credential, options)?;
        return Ok(credential);
    }
    ceremony()
}

fn check_selection(credential: &InferenceCredential, options: &LoginOptions) -> Result<(), String> {
    if options
        .organization
        .as_ref()
        .is_some_and(|id| id != &credential.organization_id)
        || options
            .workspace
            .as_ref()
            .is_some_and(|id| id != &credential.workspace_id)
    {
        return Err("Saved NEAR AI account differs from the requested organization/workspace; run rts login with your selection".into());
    }
    Ok(())
}

fn validate_options(options: &LoginOptions) -> Result<(), String> {
    for id in [&options.organization, &options.workspace]
        .into_iter()
        .flatten()
    {
        if !valid_id(id) {
            return Err("Invalid NEAR AI organization/workspace ID".into());
        }
    }
    Ok(())
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn valid_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= 4096 && key.bytes().all(|b| b.is_ascii_graphic())
}

fn choose(items: &[String], selected: Option<&str>, kind: &str) -> Result<String, String> {
    if let Some(id) = selected {
        return items
            .iter()
            .find(|candidate| candidate.as_str() == id)
            .cloned()
            .ok_or_else(|| format!("Requested NEAR AI {kind} is unavailable or inactive"));
    }
    match items {
        [id] => Ok(id.clone()),
        [] => Err(format!(
            "No active NEAR AI {kind}; finish account setup at https://cloud.near.ai"
        )),
        _ => Err(format!(
            "Multiple NEAR AI {kind}s; rerun with --{kind} ID. Available IDs: {}",
            items.join(", ")
        )),
    }
}

#[cfg(test)]
use browser::{decode_deposit, valid_submission};

#[cfg(test)]
mod tests;

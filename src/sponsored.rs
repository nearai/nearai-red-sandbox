//! Host-only transition from a sponsored key to a personal Cloud account.

use ironwire_proxy::embed::HostSecret;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

/// Only explicit pre-inference credential/credit refusals are safe to retry.
/// Never inspect a successful stream or infer exhaustion from message text.
pub fn rejection(status: u16, body: &[u8]) -> Option<&'static str> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    match (status, value.get("error")?.get("type")?.as_str()?) {
        (401, "invalid_api_key") => Some(
            "Your sponsored API key is no longer available. Sign in to NEAR AI Cloud to continue.",
        ),
        (
            402,
            "api_key_limit_exceeded"
            | "insufficient_credits"
            | "no_credits"
            | "no_limit_configured",
        ) => Some(
            "Your included credits are used up or unavailable. Sign in to NEAR AI Cloud to continue.",
        ),
        _ => None,
    }
}

pub type Login = Arc<dyn Fn(Arc<AtomicBool>) -> Result<HostSecret, String> + Send + Sync>;

#[derive(Clone)]
pub struct Snapshot {
    pub key: HostSecret,
    pub generation: u64,
    pub sponsored: bool,
}

struct Active {
    snapshot: Snapshot,
    failed: bool,
    refreshing: bool,
}

/// One active credential per launch. Login runs off the async workers; the
/// state and notifications make simultaneous refusals share one browser ceremony.
/// No secret-bearing type here implements Debug.
pub struct Credentials {
    active: Mutex<Active>,
    changed: tokio::sync::Notify,
    login: Login,
    cancelled: Arc<AtomicBool>,
}

const LOGIN_FAILED: &str =
    "NEAR AI Cloud sign-in did not complete; run rts login and launch again.";

impl Credentials {
    pub fn new(key: HostSecret, sponsored: bool, login: Login) -> Arc<Self> {
        Arc::new(Self {
            active: Mutex::new(Active {
                snapshot: Snapshot {
                    key,
                    generation: 0,
                    sponsored,
                },
                failed: false,
                refreshing: false,
            }),
            changed: tokio::sync::Notify::new(),
            login,
            cancelled: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn snapshot(&self) -> Result<Snapshot, String> {
        let active = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if active.failed || self.cancelled.load(Ordering::SeqCst) {
            return Err(LOGIN_FAILED.into());
        }
        Ok(active.snapshot.clone())
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.changed.notify_waiters();
    }

    /// New inference waits while the browser ceremony runs. Synchronous
    /// attestation can still snapshot the last key without blocking a runtime.
    pub async fn current(&self) -> Result<Snapshot, String> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let active = self.active.lock().unwrap_or_else(|e| e.into_inner());
                if active.failed || self.cancelled.load(Ordering::SeqCst) {
                    return Err(LOGIN_FAILED.into());
                }
                if !active.refreshing {
                    return Ok(active.snapshot.clone());
                }
            }
            changed.await;
        }
    }

    pub async fn recover(self: &Arc<Self>, rejected_generation: u64) -> Result<Snapshot, String> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let start = {
                let mut active = self.active.lock().unwrap_or_else(|e| e.into_inner());
                if active.failed || self.cancelled.load(Ordering::SeqCst) {
                    return Err(LOGIN_FAILED.into());
                }
                if active.snapshot.generation != rejected_generation {
                    return Ok(active.snapshot.clone());
                }
                if !active.snapshot.sponsored {
                    return Err("Personal NEAR AI Cloud credential was refused".into());
                }
                if active.refreshing {
                    false
                } else {
                    active.refreshing = true;
                    true
                }
            };
            if start {
                let owner = self.clone();
                // This task owns completion, independently of any HTTP request
                // waiting for it. Disconnecting the initiating client cannot
                // discard a successful login or strand the active key.
                tokio::spawn(async move {
                    let login = owner.login.clone();
                    let cancelled = owner.cancelled.clone();
                    let result = tokio::task::spawn_blocking(move || login(cancelled)).await;
                    {
                        let mut active = owner.active.lock().unwrap_or_else(|e| e.into_inner());
                        active.refreshing = false;
                        match result {
                            Ok(Ok(key)) if !owner.cancelled.load(Ordering::SeqCst) => {
                                active.snapshot = Snapshot {
                                    key,
                                    generation: active.snapshot.generation + 1,
                                    sponsored: false,
                                };
                            }
                            _ => active.failed = true,
                        }
                    }
                    owner.changed.notify_waiters();
                });
            }
            changed.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn only_explicit_cloud_credential_refusals_trigger_login() {
        for (status, kind) in [
            (401, "invalid_api_key"),
            (402, "api_key_limit_exceeded"),
            (402, "insufficient_credits"),
            (402, "no_credits"),
            (402, "no_limit_configured"),
        ] {
            let body = serde_json::to_vec(&serde_json::json!({"error":{"type":kind}})).unwrap();
            assert!(rejection(status, &body).is_some());
            for status in [400, 403, 404, 429, 500, 502, 503] {
                assert!(rejection(status, &body).is_none());
            }
        }
        for body in [
            b"not json".as_slice(),
            br#"{"error":{"type":"internal_server_error"}}"#,
            br#"{"error":{"code":"api_key_limit_exceeded"}}"#,
        ] {
            assert!(rejection(401, body).is_none());
            assert!(rejection(402, body).is_none());
        }
    }

    #[tokio::test]
    async fn concurrent_refusals_share_one_login_and_personal_key_is_never_retried() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let keys = Credentials::new(
            "sponsored".to_string().into(),
            true,
            Arc::new(move |_| {
                c.fetch_add(1, Ordering::SeqCst);
                Ok("personal".to_string().into())
            }),
        );
        let old = keys.snapshot().unwrap();
        let (a, b) = tokio::join!(keys.recover(old.generation), keys.recover(old.generation));
        assert_eq!(a.unwrap().key.expose_secret(), "personal");
        assert_eq!(b.unwrap().key.expose_secret(), "personal");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let current = keys.snapshot().unwrap();
        assert!(!current.sponsored);
        assert!(keys.recover(current.generation).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn abandoned_request_does_not_discard_login_and_new_requests_wait() {
        let (started, began) = tokio::sync::oneshot::channel();
        let started = Arc::new(Mutex::new(Some(started)));
        let (release, gate) = std::sync::mpsc::channel();
        let gate = Arc::new(Mutex::new(gate));
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let keys = Credentials::new(
            "sponsored".to_string().into(),
            true,
            Arc::new(move |_| {
                count.fetch_add(1, Ordering::SeqCst);
                let _ = started.lock().unwrap().take().unwrap().send(());
                gate.lock()
                    .unwrap()
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                Ok("personal".to_string().into())
            }),
        );
        let k = keys.clone();
        let original = tokio::spawn(async move { k.recover(0).await });
        began.await.unwrap();
        assert_eq!(
            keys.snapshot().unwrap().key.expose_secret(),
            "sponsored",
            "reattest must retain a usable snapshot during login"
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), keys.current())
                .await
                .is_err()
        );
        original.abort();
        let _ = original.await;
        release.send(()).unwrap();
        let personal = tokio::time::timeout(std::time::Duration::from_secs(5), keys.recover(0))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(personal.key.expose_secret(), "personal");
        assert_eq!(
            keys.current().await.unwrap().key.expose_secret(),
            "personal"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancellation_wakes_waiters_and_late_login_cannot_activate_a_key() {
        let (started, began) = tokio::sync::oneshot::channel();
        let started = Arc::new(Mutex::new(Some(started)));
        let (release, gate) = std::sync::mpsc::channel();
        let gate = Arc::new(Mutex::new(gate));
        let (finished, done) = tokio::sync::oneshot::channel();
        let finished = Arc::new(Mutex::new(Some(finished)));
        let keys = Credentials::new(
            "sponsored".to_string().into(),
            true,
            Arc::new(move |cancelled| {
                let _ = started.lock().unwrap().take().unwrap().send(());
                gate.lock()
                    .unwrap()
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                assert!(cancelled.load(Ordering::SeqCst));
                let _ = finished.lock().unwrap().take().unwrap().send(());
                Ok("personal".to_string().into())
            }),
        );
        let k = keys.clone();
        let recover = tokio::spawn(async move { k.recover(0).await.is_err() });
        began.await.unwrap();
        keys.cancel();
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), keys.current())
                .await
                .unwrap()
                .is_err()
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), recover)
                .await
                .unwrap()
                .unwrap()
        );
        release.send(()).unwrap();
        done.await.unwrap();
        assert!(keys.snapshot().is_err());
    }

    #[tokio::test]
    async fn failed_or_cancelled_login_does_not_loop_or_leak_its_error() {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let keys = Credentials::new(
            "sponsored".to_string().into(),
            true,
            Arc::new(move |_| {
                c.fetch_add(1, Ordering::SeqCst);
                Err("secret-must-not-appear".into())
            }),
        );
        let old = keys.snapshot().unwrap();
        for _ in 0..2 {
            let error = keys.recover(old.generation).await.err().unwrap();
            assert!(!error.contains("secret-must-not-appear"));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(keys.snapshot().is_err());
        let keys = Credentials::new(
            "sponsored".to_string().into(),
            true,
            Arc::new(|_| panic!("cancelled login")),
        );
        keys.cancel();
        assert!(keys.recover(0).await.is_err());
    }
}

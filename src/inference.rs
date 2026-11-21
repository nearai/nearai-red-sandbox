//! Host-owned, per-launch NEAR AI inference proxy.
//!
//! The worker owns its runtime home through shutdown. The host credential is
//! handed directly to IronWire; configuration contains only routing policy.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use ironwire_proxy::embed::{
    CredentialFiles, EmbedOptions, HostSecret, StartupProbes, UpdateChecks,
};
use tokio::sync::oneshot;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const RUNTIME_STOP_TIMEOUT: Duration = Duration::from_secs(1);
const WORKER_STOP_TIMEOUT: Duration = Duration::from_secs(7);

/// `[capture]` settings for the embedded IronWire configuration.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Capture {
    pub enabled: bool,
    pub bodies: bool,
    pub logprobs: bool,
    pub receipts: bool,
}

/// Options controlling the embedded IronWire instance's home and capture.
#[derive(Default)]
pub struct IronWireSetup {
    /// When `Some`, IronWire uses this directory (which must be absent or
    /// empty) and keeps it on shutdown instead of creating and deleting a
    /// temporary home.
    pub home: Option<PathBuf>,
    pub capture: Capture,
    /// Optional hook applied to `EmbedOptions` after `rts`'s defaults.
    pub configure: Option<Box<dyn FnOnce(EmbedOptions) -> EmbedOptions + Send>>,
}

enum OwnedHome {
    Temp(tempfile::TempDir),
    Supplied(PathBuf),
}

impl OwnedHome {
    fn path(&self) -> &Path {
        match self {
            Self::Temp(dir) => dir.path(),
            Self::Supplied(path) => path,
        }
    }
}

/// Owns a loopback proxy and its isolated runtime home.
pub struct EmbeddedInference {
    home: PathBuf,
    provider: crate::config::ProviderConfig,
    shutdown: Option<oneshot::Sender<()>>,
    finished: mpsc::Receiver<()>,
    worker: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for EmbeddedInference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddedInference")
            .field("home", &self.home)
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}

impl EmbeddedInference {
    /// The only inference connection details OpenCode receives.
    pub fn provider(&self) -> crate::config::ProviderConfig {
        self.provider.clone()
    }
}

impl Drop for EmbeddedInference {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        // The runtime lives on another thread, so this works even when the
        // caller itself runs inside Tokio. A wedged worker retains ownership
        // of its home; the caller never deletes a still-running proxy's files.
        if self.finished.recv_timeout(WORKER_STOP_TIMEOUT).is_ok()
            && let Some(worker) = self.worker.take()
        {
            let _ = worker.join();
        }
    }
}

/// NEAR AI Cloud's production API base.
pub const NEAR_BASE_URL: &str = "https://cloud-api.near.ai/v1";

/// NEAR AI Cloud's staging API base.
pub const NEAR_STAGING_BASE_URL: &str = "https://cloud-stg-api.near.ai/v1";

/// Which NEAR AI Cloud deployment a session talks to. Each has its own API
/// base and its own pinned compose list: a build trusted for one is never
/// trusted for the other.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NearEnvironment {
    #[default]
    Production,
    Staging,
}

impl NearEnvironment {
    /// The OpenAI-compatible API base, which also serves the attestation report.
    pub fn base_url(self) -> &'static str {
        match self {
            Self::Production => NEAR_BASE_URL,
            Self::Staging => NEAR_STAGING_BASE_URL,
        }
    }
}

/// Value for each model's `x-ironwire-route` request header.
///
/// Required because the pinned IronWire revision otherwise chooses among an
/// unprobed configured catalogue by tier rather than honoring the selected ID.
pub fn route_header(model: &str) -> Result<String, String> {
    if model.is_empty()
        || !model
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b':')
    {
        return Err(
            "inference: model ID must be visible ASCII without colons or whitespace".into(),
        );
    }
    Ok(format!("nearai:{model}"))
}

fn embed_options(key: HostSecret) -> EmbedOptions {
    let mut options = EmbedOptions::default()
        .with_credentials(move |name| (name == "NEARAI_API_KEY").then(|| key.clone()))
        .with_credential_files(CredentialFiles::Off)
        .with_startup_probes(StartupProbes::Off)
        .with_update_checks(UpdateChecks::Off);
    options.token_capture_enabled = Some(false);
    options
}

fn build_embed_options(
    key: HostSecret,
    configure: Option<Box<dyn FnOnce(EmbedOptions) -> EmbedOptions + Send>>,
) -> EmbedOptions {
    let options = embed_options(key);
    match configure {
        Some(f) => f(options),
        None => options,
    }
}

fn prepare_home(supplied: Option<PathBuf>) -> Result<OwnedHome, String> {
    match supplied {
        None => {
            let home = tempfile::Builder::new()
                .prefix("rts-inference-")
                .tempdir()
                .map_err(|_| "inference: cannot create private runtime home")?;
            crate::sys::fs::restrict_dir(home.path())
                .map_err(|_| "inference: cannot restrict runtime home")?;
            Ok(OwnedHome::Temp(home))
        }
        Some(dir) => {
            match fs::symlink_metadata(&dir) {
                Ok(meta) => {
                    if !meta.is_dir() {
                        return Err("inference: runtime home must be a directory".into());
                    }
                    let mut entries = fs::read_dir(&dir)
                        .map_err(|_| "inference: cannot inspect runtime home")?;
                    if entries.next().is_some() {
                        return Err("inference: runtime home is not empty".into());
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    crate::sys::fs::create_private_dir_all(&dir)
                        .map_err(|_| "inference: cannot create private runtime home")?;
                }
                Err(_) => return Err("inference: cannot inspect runtime home".into()),
            }
            crate::sys::fs::restrict_dir(&dir)
                .map_err(|_| "inference: cannot restrict runtime home")?;
            Ok(OwnedHome::Supplied(dir))
        }
    }
}

/// Start IronWire with only its NEAR AI backend at `endpoint`, without
/// credential discovery or probes. In production `endpoint` is always the
/// loopback forwarder: no path starts IronWire at NEAR AI directly. The
/// endpoint is pinned explicitly because IronWire's environment-based URL
/// override is independent of its credential source.
pub fn start_with_endpoint(
    key: HostSecret,
    models: &[String],
    endpoint: &str,
    setup: IronWireSetup,
) -> Result<EmbeddedInference, String> {
    let IronWireSetup {
        home: supplied_home,
        capture,
        configure,
    } = setup;
    let config = runtime_config(models, endpoint, capture)?;
    let home = prepare_home(supplied_home)?;
    let mut file = crate::sys::fs::open_private(&home.path().join("config.toml"), crate::sys::fs::Create::New)
    .map_err(|_| "inference: cannot create runtime configuration")?;
    file.write_all(config.as_bytes())
        .map_err(|_| "inference: cannot write runtime configuration")?;
    drop(file);
    let home_path = home.path().to_path_buf();
    let options = build_embed_options(key, configure);
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (done_tx, finished) = mpsc::sync_channel(1);
    let (shutdown, shutdown_rx) = oneshot::channel();
    let worker = std::thread::Builder::new()
        .name("rts-inference".into())
        .spawn(move || {
            run_worker(home, options, ready_tx, shutdown_rx);
            let _ = done_tx.send(());
        })
        .map_err(|_| "inference: cannot start runtime worker")?;
    let port = match ready_rx.recv_timeout(STARTUP_TIMEOUT + Duration::from_secs(2)) {
        Ok(Ok(port)) => port,
        Ok(Err(error)) => return Err(error),
        Err(_) => return Err("inference: runtime startup did not complete".into()),
    };
    Ok(EmbeddedInference {
        home: home_path,
        provider: crate::config::ProviderConfig {
            id: crate::config::EMBEDDED_PROVIDER_ID.into(),
            base_url: format!("http://127.0.0.1:{port}/openai/v1"),
            models: models.to_vec(),
            api_key_env: None,
        },
        shutdown: Some(shutdown),
        finished,
        worker: Some(worker),
    })
}

fn run_worker(
    home: OwnedHome,
    options: EmbedOptions,
    ready: mpsc::SyncSender<Result<u16, String>>,
    shutdown: oneshot::Receiver<()>,
) {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            let _ = ready.send(Err("inference: cannot initialize runtime".into()));
            return;
        }
    };
    runtime.block_on(async {
        let proxy = match tokio::time::timeout(
            STARTUP_TIMEOUT,
            ironwire_proxy::embed::start_with_options(
                home.path(),
                Some(0),
                options,
                |_, _| {},
            ),
        )
        .await
        {
            Ok(Ok(proxy)) => proxy,
            Ok(Err(_)) => {
                let _ = ready.send(Err("inference: embedded proxy refused startup".into()));
                return;
            }
            Err(_) => {
                let _ = ready.send(Err("inference: embedded proxy startup timed out".into()));
                return;
            }
        };
        if ready.send(Ok(proxy.port())).is_ok() {
            let _ = shutdown.await;
        }
        // Drain outstanding requests first, then cancel tasks by stopping the
        // owned runtime. IronWire itself intentionally has no stream deadline.
        let _ = tokio::time::timeout(DRAIN_TIMEOUT, proxy.shutdown()).await;
    });
    runtime.shutdown_timeout(RUNTIME_STOP_TIMEOUT);
    // Temp homes are removed here; caller-supplied homes are preserved.
    drop(home);
}

fn runtime_config(models: &[String], endpoint: &str, capture: Capture) -> Result<String, String> {
    if models.is_empty() || models.iter().any(String::is_empty) {
        return Err("inference: select at least one nonempty model ID".into());
    }
    for model in models {
        let _ = route_header(model)?;
    }
    let models =
        serde_json::to_string(models).map_err(|_| "inference: cannot encode model catalogue")?;
    let endpoint =
        serde_json::to_string(endpoint).map_err(|_| "inference: cannot encode endpoint")?;
    // JSON strings/arrays are also TOML basic strings/arrays. Serializing them
    // prevents model IDs from injecting backend entries or configuration.
    Ok(format!(
        r#"[capture]
enabled = {enabled}
bodies = {bodies}
logprobs = {logprobs}
receipts = {receipts}

[updates]
check = false

[subscriptions]
cross_account_fallback = false

[[backends]]
id = "nearai"
kind = "nearai"
base_url = {endpoint}
models = {models}

[[backends]]
id = "claude-sub"
kind = "claude-subscription"
enabled = false

[[backends]]
id = "codex-sub"
kind = "codex-subscription"
enabled = false

[[backends]]
id = "anthropic-key"
kind = "anthropic-api"
enabled = false

[[backends]]
id = "openai-key"
kind = "openai-api"
enabled = false
"#,
        enabled = capture.enabled,
        bodies = capture.bodies,
        logprobs = capture.logprobs,
        receipts = capture.receipts,
    ))
}

#[cfg(test)]
#[cfg_attr(not(unix), allow(unused_imports))]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::time::{Duration, Instant};

    const DUMMY_KEY: &str = "rts-dummy-key-never-send-to-a-provider";

    #[test]
    fn only_host_nearai_credentials_are_available_and_discovery_and_captures_are_off() {
        use ironwire_proxy::embed::{CredentialFiles, StartupProbes, UpdateChecks};
        use secrecy::ExposeSecret;
        let options = embed_options(DUMMY_KEY.to_string().into());
        assert!(!format!("{options:?}").contains(DUMMY_KEY));
        assert_eq!(options.credential_files, CredentialFiles::Off);
        assert_eq!(options.startup_probes, StartupProbes::Off);
        assert_eq!(options.update_checks, UpdateChecks::Off);
        assert_eq!(options.token_capture_enabled, Some(false));
        let credentials = options.credentials.as_ref().unwrap();
        assert_eq!(
            credentials("NEARAI_API_KEY").unwrap().expose_secret(),
            DUMMY_KEY
        );
        for name in [
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "NEARAI_API_KEY_OTHER",
            "nearai_api_key",
            "",
        ] {
            assert!(
                credentials(name).is_none(),
                "unrequested credential became available"
            );
        }
    }

    #[test]
    fn near_environments_name_their_own_api_bases() {
        assert_eq!(NearEnvironment::default(), NearEnvironment::Production);
        assert_eq!(NearEnvironment::Production.base_url(), NEAR_BASE_URL);
        assert_eq!(
            NearEnvironment::Production.base_url(),
            "https://cloud-api.near.ai/v1"
        );
        assert_eq!(
            NearEnvironment::Staging.base_url(),
            "https://cloud-stg-api.near.ai/v1"
        );
    }

    #[test]
    fn unroutable_model_selections_are_rejected() {
        for models in [
            vec![],
            vec![String::new()],
            vec!["m:alias".into()],
            vec!["m\r\nheader: value".into()],
        ] {
            let error = start_with_endpoint(
                DUMMY_KEY.to_string().into(),
                &models,
                NEAR_BASE_URL,
                IronWireSetup::default(),
            )
            .unwrap_err();
            assert!(error.contains("model"));
            assert!(!error.contains(DUMMY_KEY));
        }
    }

    #[test]
    fn route_header_pins_the_model_and_rejects_ambiguous_or_injected_values() {
        assert_eq!(
            route_header("z-ai/glm-5.3-flash").unwrap(),
            "nearai:z-ai/glm-5.3-flash"
        );
        for model in [
            "",
            "m:alias",
            "m\r\nx-header: x",
            "m\n",
            "m\t",
            "m\0",
            " m",
            "m ",
            "mødel",
        ] {
            assert!(
                route_header(model).is_err(),
                "invalid route model was accepted"
            );
        }
    }

    fn assert_artifacts_contain_no_key(path: &Path) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                assert_artifacts_contain_no_key(&entry.path());
            } else {
                let bytes = fs::read(entry.path()).unwrap();
                assert!(
                    !bytes
                        .windows(DUMMY_KEY.len())
                        .any(|w| w == DUMMY_KEY.as_bytes()),
                    "credential appeared in runtime artifact"
                );
            }
        }
    }

    #[test]
    fn the_selected_model_and_host_key_reach_only_the_local_test_upstream() {
        let upstream = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        upstream.set_nonblocking(true).unwrap();
        let addr = upstream.local_addr().unwrap();
        let endpoint = format!("http://{addr}/v1");
        // A spare connection closed before any bytes, as a client's pool may
        // open: queued first, so the upstream must skip it.
        drop(std::net::TcpStream::connect(addr).unwrap());
        let received = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(15);
            // IronWire may open a spare connection and close it before
            // sending anything: skip those, bounded by the deadline, until
            // one carries a request.
            let (mut stream, mut request, header_end) = loop {
                let stream = match upstream.accept() {
                    Ok((stream, _)) => stream,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(e) => panic!("local test upstream did not receive a request: {e}"),
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut stream = BufReader::new(stream);
                let mut request = Vec::new();
                let header_end = loop {
                    if stream.read_until(b'\n', &mut request).unwrap() == 0 {
                        break None;
                    }
                    if request.ends_with(b"\r\n\r\n") {
                        break Some(request.len());
                    }
                    assert!(request.len() < 16_384);
                };
                match header_end {
                    Some(end) => break (stream, request, end),
                    // Closed before a whole request head: only an empty
                    // spare connection may be skipped.
                    None => assert!(request.is_empty(), "truncated request head"),
                }
            };
            let headers = String::from_utf8(request.clone()).unwrap();
            assert!(headers.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
            let length: usize = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap();
            assert!(length < 16_384);
            request.resize(header_end + length, 0);
            stream.read_exact(&mut request[header_end..]).unwrap();
            let body: serde_json::Value = serde_json::from_slice(&request[header_end..]).unwrap();
            let response = r#"{"id":"local-test","object":"chat.completion","model":"selected-model","choices":[{"index":0,"message":{"role":"assistant","content":"local reply"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}"#;
            write!(stream.get_mut(), "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
            (headers, body)
        });
        let inference = start_with_endpoint(
            DUMMY_KEY.to_string().into(),
            &["other-model".into(), "selected-model".into()],
            &endpoint,
            IronWireSetup::default(),
        )
        .unwrap();
        let provider = inference.provider();
        assert!(!format!("{inference:?}").contains(DUMMY_KEY));
        assert!(!format!("{provider:?}").contains(DUMMY_KEY));
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap();
        let response = client.post(format!("{}/chat/completions", provider.base_url))
            .bearer_auth(crate::config::PLACEHOLDER_API_KEY)
            .header("x-ironwire-route", route_header("selected-model").unwrap())
            .json(&serde_json::json!({"model":"selected-model", "messages":[{"role":"user","content":"local test"}], "stream":false}))
            .send().unwrap();
        assert_eq!(response.status(), 200);
        let (headers, body) = received.join().unwrap();
        assert!(
            headers
                .lines()
                .any(|line| line == format!("authorization: Bearer {DUMMY_KEY}"))
        );
        assert_eq!(body["model"], "selected-model");
        assert!(!headers.to_ascii_lowercase().contains("x-ironwire-route"));
        assert_artifacts_contain_no_key(&inference.home);
    }

    #[test]
    #[cfg(unix)]
    fn configured_models_are_available_without_discovery_and_home_is_private_and_ephemeral() {
        let models = vec![
            "z-ai/glm-5.3-flash".into(),
            "explicitly-selected-model".into(),
        ];
        let inference = start_with_endpoint(
            DUMMY_KEY.to_string().into(),
            &models,
            NEAR_BASE_URL,
            IronWireSetup::default(),
        )
        .unwrap();
        let provider = inference.provider();
        assert_eq!(provider.id, "nearai-red-embedded");
        let (_, port, path) = provider.loopback().unwrap();
        assert_ne!(port, 0);
        assert_eq!(path, "/openai/v1");
        assert_eq!(provider.models, models);
        assert_eq!(provider.api_key_env, None);
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let response: serde_json::Value = client
            .get(format!("{}/models", provider.base_url))
            .send()
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .unwrap();
        let offered: Vec<_> = response["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["id"].as_str().unwrap())
            .collect();
        assert_eq!(offered, ["z-ai/glm-5.3-flash", "explicitly-selected-model"]);
        let home = inference.home.clone();
        assert_eq!(
            fs::metadata(&home).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_artifacts_contain_no_key(&home);
        let before = Instant::now();
        drop(inference);
        assert!(before.elapsed() < Duration::from_secs(8));
        assert!(!home.exists(), "owned runtime home survives shutdown");
        assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
    }

    #[test]
    fn runtime_config_renders_requested_capture() {
        let rendered = runtime_config(
            &["z-ai/glm-5.3-flash".into()],
            "http://127.0.0.1:9999/v1",
            Capture {
                enabled: true,
                bodies: true,
                logprobs: false,
                receipts: true,
            },
        )
        .unwrap();
        assert!(rendered.contains("[capture]\nenabled = true\nbodies = true\nlogprobs = false\nreceipts = true\n"), "{rendered}");
        assert!(rendered.contains("base_url = \"http://127.0.0.1:9999/v1\""), "{rendered}");
        assert!(runtime_config(&["bad\n[backends]".into()], NEAR_BASE_URL, Capture::default()).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn a_supplied_home_survives_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let iw_home = dir.path().join("iw");
        let inference = start_with_endpoint(
            DUMMY_KEY.to_string().into(),
            &["z-ai/glm-5.3-flash".into()],
            NEAR_BASE_URL,
            IronWireSetup {
                home: Some(iw_home.clone()),
                capture: Capture::default(),
                configure: None,
            },
        )
        .unwrap();
        assert_eq!(
            fs::metadata(&iw_home).unwrap().permissions().mode() & 0o777,
            0o700
        );
        drop(inference);
        assert!(iw_home.join("config.toml").is_file());
    }

    #[test]
    fn a_nonempty_supplied_home_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let iw_home = dir.path().join("iw");
        fs::create_dir(&iw_home).unwrap();
        fs::write(iw_home.join("existing"), b"prior").unwrap();
        let err = start_with_endpoint(
            DUMMY_KEY.to_string().into(),
            &["z-ai/glm-5.3-flash".into()],
            NEAR_BASE_URL,
            IronWireSetup {
                home: Some(iw_home),
                capture: Capture::default(),
                configure: None,
            },
        )
        .unwrap_err();
        assert!(err.contains("inference: runtime home is not empty"), "{err}");
    }

    #[test]
    fn configure_is_applied_after_the_defaults() {
        let called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let called_flag = called.clone();
        let options = build_embed_options(
            DUMMY_KEY.to_string().into(),
            Some(Box::new(move |mut opts| {
                assert_eq!(opts.token_capture_enabled, Some(false));
                opts.token_capture_enabled = Some(true);
                called_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                opts
            })),
        );
        assert!(called.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(options.token_capture_enabled, Some(true));

        let started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let started_flag = started.clone();
        let inference = start_with_endpoint(
            DUMMY_KEY.to_string().into(),
            &["z-ai/glm-5.3-flash".into()],
            NEAR_BASE_URL,
            IronWireSetup {
                home: None,
                capture: Capture::default(),
                configure: Some(Box::new(move |opts| {
                    assert_eq!(opts.token_capture_enabled, Some(false));
                    started_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    opts.with_credentials(|_| Some(DUMMY_KEY.to_string().into()))
                })),
            },
        )
        .unwrap();
        assert!(started.load(std::sync::atomic::Ordering::SeqCst));
        drop(inference);
    }
}

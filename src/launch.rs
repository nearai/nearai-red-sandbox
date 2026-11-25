//! Session launch orchestration: config/flag resolution, local preflight,
//! NEAR AI sign-in, attestation, pinned forwarder, embedded IronWire, and
//! microVM session execution.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ironwire_proxy::embed::HostSecret;

use crate::brand::{self, progress::Live};
use crate::inference::IronWireSetup;
use crate::{attest, auth, config, forwarder, inference, session};

/// How `launch::run` obtains the NEAR AI inference credential.
pub enum CredentialSource {
    /// Load a saved or sponsored credential from native storage, or run the
    /// browser sign-in flow when needed.
    Native(auth::LoginOptions),
    /// Use a caller-supplied NEAR AI key without touching native storage or
    /// opening a browser sign-in.
    Supplied(HostSecret),
}

/// Complete specification for launching one sandboxed session.
pub struct LaunchSpec {
    pub config: config::OperatorConfig,
    pub attest: attest::AttestOptions,
    pub credential: CredentialSource,
    pub initial_prompt: Option<String>,
    pub no_splash: bool,
    pub session_id: Option<String>,
    pub tool_command: Option<Vec<String>>,
    pub ironwire: IronWireSetup,
    pub env: Vec<(String, String)>,
    /// The NEAR AI deployment for attestation, its pinned compose list, and
    /// inference. Staging needs `CredentialSource::Supplied` with a staging key.
    pub near: inference::NearEnvironment,
}

/// Result of a completed session launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub exit_code: i32,
    pub session_id: String,
    pub session_dir: PathBuf,
}

impl LaunchSpec {
    /// Load the session config (or defaults) and apply the CLI launch flags.
    #[allow(clippy::too_many_arguments)]
    pub fn from_cli(
        file: Option<&Path>,
        login: auth::LoginOptions,
        attest: attest::AttestOptions,
        allow: &[String],
        no_network: bool,
        cpus: Option<u32>,
        memory_mib: Option<u32>,
        no_splash: bool,
        initial_prompt: Option<String>,
    ) -> Result<Self, String> {
        let defaults = config::Defaults::from_env();
        let mut config = if let Some(file) = file {
            config::load_config(file, &defaults)?
        } else {
            config::parse_config(
                "{}",
                &std::env::current_dir().map_err(|_| "Cannot determine current directory")?,
                &defaults,
            )?
        };
        apply_network(&mut config, allow, no_network);
        apply_vm_size(&mut config, cpus, memory_mib)?;
        Ok(Self {
            config,
            attest,
            credential: CredentialSource::Native(login),
            initial_prompt,
            no_splash,
            session_id: None,
            tool_command: None,
            ironwire: IronWireSetup::default(),
            env: std::env::vars().collect(),
            near: inference::NearEnvironment::Production,
        })
    }
}

/// A private temp directory holding an empty Git config for mvmctl.
pub fn private_git_config(prefix: &str) -> Result<(tempfile::TempDir, PathBuf), String> {
    let temp = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .map_err(|_| "Cannot create a private temp directory")?;
    let empty_git_config = temp.path().join("empty.gitconfig");
    crate::sys::fs::open_private(&empty_git_config, crate::sys::fs::Create::New)
    .map_err(|_| "Cannot create an empty Git configuration")?;
    Ok((temp, empty_git_config))
}

fn local_preflight(
    cfg: &config::OperatorConfig,
    host: &dyn session::Host,
    env: &[(String, String)],
    near: inference::NearEnvironment,
) -> Result<(), String> {
    let (temp, empty_git_config) = private_git_config("rts-preflight-")?;
    let work = temp.path().join("work");
    std::fs::create_dir(&work).map_err(|_| "Cannot create preflight work directory")?;
    let backend = crate::backend::for_preflight(cfg, env, empty_git_config)?;
    // A pinned HTTPS placeholder skips the loopback-provider probe. Local
    // prerequisites must succeed before any native credential read or browser.
    let provider = config::ProviderConfig {
        base_url: near.base_url().into(),
        ..cfg.provider.clone()
    };
    backend.preflight(&crate::backend::HostCheck {
        host,
        opencode: &cfg.opencode,
        leak_seam_set: env.iter().any(|(key, _)| key == "RTS_TEST_LEAK"),
        work_dir: Some(&work),
        provider: &provider,
    })
}

/// IronWire reads this variable and would send NEAR AI traffic around the
/// pinned forwarder, so its mere presence (even empty) refuses the launch.
const IRONWIRE_ENDPOINT_OVERRIDE: &str = "IRONWIRE_NEARAI_BASE_URL";

fn check_launch(
    cfg: &config::OperatorConfig,
    env: &[(String, String)],
    opts: &attest::AttestOptions,
) -> Result<(), String> {
    if env.iter().any(|(k, _)| k == IRONWIRE_ENDPOINT_OVERRIDE) {
        return Err(format!(
            "{IRONWIRE_ENDPOINT_OVERRIDE} is set: rts pins NEAR AI's endpoint to its attested forwarder; unset it"
        ));
    }
    config::require_real_models(&cfg.provider.models)?;
    crate::network::expand(&cfg.network)?;
    if !cfg.embedded_inference && !opts.allow_unattested_provider {
        return Err("the config names an external provider (provider.id, baseURL or apiKeyEnv), which rts cannot attest; pass --allow-unattested-provider to use it anyway".into());
    }
    Ok(())
}

/// Native sign-in and its sponsored allowance are NEAR AI production only;
/// staging takes a caller-supplied staging key.
fn check_credential_environment(
    credential: &CredentialSource,
    near: inference::NearEnvironment,
) -> Result<(), String> {
    match (credential, near) {
        (CredentialSource::Native(_), inference::NearEnvironment::Staging) => Err(
            "NEAR AI staging needs a supplied staging key; native sign-in is production only"
                .into(),
        ),
        _ => Ok(()),
    }
}

/// Apply `--cpus` and `--memory` over the session file's limits.
fn apply_vm_size(
    cfg: &mut config::OperatorConfig,
    cpus: Option<u32>,
    memory_mib: Option<u32>,
) -> Result<(), String> {
    cfg.limits.resize(cpus, memory_mib)
}

/// `--no-network` clears the config's entries; otherwise `--allow-host`
/// entries follow the config's.
fn apply_network(cfg: &mut config::OperatorConfig, allow: &[String], no_network: bool) {
    if no_network {
        cfg.network.clear();
    } else {
        cfg.network.extend(allow.iter().cloned());
    }
}

/// For an allowed external provider: attestation.json says it is unattested.
fn record_unattested(
    cfg: &config::OperatorConfig,
    session_id: &str,
    opts: &attest::AttestOptions,
) -> Result<(), String> {
    let record = attest::record::AttestationRecord::create(&cfg.sessions_dir, session_id, opts)?;
    record.set_status(
        "unattested-provider",
        &format!(
            "external provider {} allowed by --allow-unattested-provider; not attested",
            cfg.provider.base_url
        ),
    );
    Ok(())
}

/// IronWire, then the forwarder: fields drop in declaration order, so
/// IronWire shuts down before its only route to NEAR AI.
struct Connected {
    _inference: inference::EmbeddedInference,
    _forwarder: forwarder::Forwarder,
}

/// After attestation verified: record it, then start the forwarder, then
/// IronWire. A failed start is recorded as "refused" naming the step.
fn start_connected<F, I>(
    record: &attest::record::AttestationRecord,
    attested: attest::Attested,
    start_forwarder: impl FnOnce(attest::Attested) -> Result<F, String>,
    start_inference: impl FnOnce(&F) -> Result<I, String>,
) -> Result<(F, I), String> {
    let path = record.path().display().to_string();
    record
        .verified(&attested)
        .map_err(|e| format!("cannot record the verified attestation in {path}: {e}"))?;
    let refuse = |step: &str, e: String| {
        let reason = format!("{step} failed to start after attestation verified: {e}");
        record.set_status("refused", &reason);
        format!("{reason} (see {path})")
    };
    let forwarder = start_forwarder(attested).map_err(|e| refuse("the pinned forwarder", e))?;
    let inference =
        start_inference(&forwarder).map_err(|e| refuse("the IronWire inference proxy", e))?;
    Ok((forwarder, inference))
}

pub(crate) fn run_connected<G>(
    cfg: &mut config::OperatorConfig,
    preflight: impl FnOnce(&config::OperatorConfig) -> Result<(), String>,
    connect: impl FnOnce(&config::OperatorConfig) -> Result<(config::ProviderConfig, G), String>,
    run: impl FnOnce(&config::OperatorConfig) -> i32,
) -> Result<i32, String> {
    let _inference = if cfg.embedded_inference {
        preflight(cfg)?;
        let (provider, inference) = connect(cfg)?;
        cfg.provider = provider;
        Some(inference)
    } else {
        None
    };
    Ok(run(cfg))
}

/// "1 model verified", "3 models verified".
fn plural(n: usize, noun: &str, verb: &str) -> String {
    format!("{n} {noun}{} {verb}", if n == 1 { "" } else { "s" })
}

struct SignInHooks<'a> {
    load_for_launch: &'a dyn Fn(&auth::LoginOptions) -> Result<auth::LaunchCredential, String>,
    login: &'a dyn Fn(&auth::LoginOptions) -> Result<auth::InferenceCredential, String>,
}

const SUPPLIED_REFUSED: &str = "the supplied NEAR AI key was refused";

/// Resolve the launch credential, attest it for the session's models, and
/// construct the forwarder's `Credentials`. With `CredentialSource::Supplied`,
/// native sign-in hooks are never called and mid-session recovery always fails
/// closed without opening a browser.
fn resolve_and_attest(
    source: &CredentialSource,
    record: &attest::record::AttestationRecord,
    models: &[String],
    progress: Option<&brand::progress::Progress>,
    sign_in: &SignInHooks<'_>,
    mut attest_key: impl FnMut(HostSecret) -> Result<attest::Attested, attest::AttestationFailure>,
) -> Result<(attest::Attested, Arc<crate::sponsored::Credentials>), String> {
    let refused = |e: String| {
        record.set_status("refused", &e);
        format!("attestation failed: {e} (see {})", record.path().display())
    };
    match source {
        CredentialSource::Supplied(key) => {
            if let Some(progress) = progress {
                let step = progress.step("sign-in", Live::Still);
                step.ok("supplied NEAR AI key");
            }
            let step = progress
                .map(|p| p.step("attestation", Live::Decode(models.join(", "))));
            let attested = attest_key(key.clone()).map_err(|error| refused(error.message()))?;
            let credentials = crate::sponsored::Credentials::new(
                key.clone(),
                false,
                Arc::new(|_| Err(SUPPLIED_REFUSED.into())),
            );
            if let Some(step) = step {
                step.ok(&format!(
                    "{} · TLS keys pinned: {}",
                    plural(models.len(), "model", "verified"),
                    attested.fingerprints.len()
                ));
            }
            Ok((attested, credentials))
        }
        CredentialSource::Native(login) => {
            // Sign-in may print its own lines (the browser notice): no animation.
            let step = progress.map(|p| p.step("sign-in", Live::Still));
            let mut credential = (sign_in.load_for_launch)(login)?;
            if let Some(step) = step {
                step.ok(if credential.sponsored {
                    "sponsored allowance"
                } else {
                    "NEAR AI Cloud"
                });
            }
            let step = progress
                .map(|p| p.step("attestation", Live::Decode(models.join(", "))));
            let attested = match attest_key(credential.key.clone()) {
                Ok(attested) => attested,
                Err(attest::AttestationFailure::CredentialRefused { .. })
                    if credential.sponsored =>
                {
                    brand::progress::message(
                        "Your sponsored API key is no longer available. Sign in to NEAR AI Cloud to continue.",
                    );
                    credential = auth::LaunchCredential {
                        key: (sign_in.login)(login)?.key,
                        sponsored: false,
                    };
                    attest_key(credential.key.clone()).map_err(|error| refused(error.message()))?
                }
                Err(error) => return Err(refused(error.message())),
            };
            let credentials = {
                let options = login.clone();
                crate::sponsored::Credentials::new(
                    credential.key,
                    credential.sponsored,
                    Arc::new(move |cancelled| {
                        auth::login_during_session(&options, &|| {
                            cancelled.load(std::sync::atomic::Ordering::SeqCst)
                        })
                        .map(|credential| credential.key)
                    }),
                )
            };
            if let Some(step) = step {
                step.ok(&format!(
                    "{} · TLS keys pinned: {}",
                    plural(models.len(), "model", "verified"),
                    attested.fingerprints.len()
                ));
            }
            Ok((attested, credentials))
        }
    }
}

/// Seconds since the Unix epoch; 0 if the clock is before it.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Run one sandboxed session according to `spec`.
pub fn run(spec: LaunchSpec) -> Result<Outcome, String> {
    let LaunchSpec {
        mut config,
        attest: attest_options,
        credential,
        initial_prompt,
        no_splash,
        session_id,
        tool_command,
        ironwire,
        env,
        near,
    } = spec;
    if initial_prompt.is_some() {
        // A source-built launcher paired with an older installed plugin must
        // fail before sign-in/VM creation, not silently leave the task unsent.
        session::check_tui_plugin(&config.plugin_dir)?;
    }
    let host_cpus = std::thread::available_parallelism()
        .map_err(|e| format!("cannot read this host's CPU count: {e}"))?
        .get() as u32;
    let host_memory_mib =
        crate::sys::host_memory_mib().ok_or("cannot read this host's physical memory")?;
    config::check_host_fit(&config.limits, host_cpus, host_memory_mib)?;
    check_launch(&config, &env, &attest_options)?;
    check_credential_environment(&credential, near)?;
    let (stdin_tty, stdout_tty) = brand::stdin_stdout_are_ttys();
    brand::splash::show(
        brand::splash_wanted(stdin_tty, stdout_tty, &env, no_splash),
        brand::Depth::from_env(&env),
    )?;
    let session_id = session_id.unwrap_or_else(session::new_session_id);
    let session_dir = config.sessions_dir.join(&session_id);
    let progress = brand::progress::Progress::new(
        brand::progress::Mode::for_stderr(&env),
        Box::new(std::io::stderr()),
        true,
    );
    brand::progress::install(progress.clone());
    // check_launch has expanded the allowlist already; this counts it the
    // same way, without resolving anything (session_body does that).
    let net = crate::network::net_label(crate::network::expand(&config.network)?.len());
    progress.header(&session_id, &net, &session_dir.join("out"));
    progress.heading("LAUNCH");
    crate::update::launch_notice(config.update_check, &session_dir.join("launcher.log"));
    let fatal = forwarder::Fatal::new();
    let mut deps = session::Deps::real(session_id.clone(), Some(fatal.clone()))?;
    deps.env = env;
    if let Some(tool_command) = tool_command {
        deps.tool_command = tool_command;
    }
    if !config.embedded_inference {
        record_unattested(&config, &session_id, &attest_options)?;
    }
    let preflight_env = deps.env.clone();
    let preflight_host = deps.host.clone();
    // The attestation policy feed's cache sits next to the update cache.
    let feed_home = crate::install::home_in(&deps.env, cfg!(windows));
    let exit_code = run_connected(
        &mut config,
        |cfg| {
            let step = progress.step("preflight", Live::Sweep);
            local_preflight(cfg, preflight_host.as_ref(), &preflight_env, near)?;
            step.ok(&format!(
                "mvm supervisor · opencode {}",
                session::OPENCODE_VERSION
            ));
            Ok(())
        },
        // Runs on the main thread, outside any Tokio runtime: attestation
        // uses blocking HTTP, and IronWire's runtime starts on its own thread
        // only after attestation succeeds.
        |cfg| {
            let record = attest::record::AttestationRecord::create(
                &cfg.sessions_dir,
                &session_id,
                &attest_options,
            )?;
            // Once per launch, before attestation and bounded to 5 s: a
            // sign-in retry attests again with the same document.
            let feed_loaded_at = unix_now();
            let (feed_doc, feed_source) =
                attest::feed::session_feed(feed_home.as_deref(), near, feed_loaded_at);
            brand::progress::message(&format!("[rts] {}", feed_source.line()));
            let sign_in = SignInHooks {
                load_for_launch: &auth::load_for_launch,
                login: &auth::login,
            };
            let (attested, credentials) = resolve_and_attest(
                &credential,
                &record,
                &cfg.provider.models,
                Some(&progress),
                &sign_in,
                |key| {
                    attest::Attestor::real(
                        near,
                        Some(key),
                        &cfg.provider.models,
                        attest_options,
                        feed_doc.as_ref(),
                        &std::collections::BTreeMap::new(),
                    )
                    .map_err(attest::AttestationFailure::Other)?
                    .attest_for_launch()
                },
            )?;
            let step = progress.step("inference", Live::Sweep);
            let (forwarder, inference) = start_connected(
                &record,
                attested,
                |seed| {
                    // Keys from the launch attestation, which passed the full
                    // policy: a re-attestation may accept a redeployed build
                    // holding one of them (issue #25). Launch stays pinned.
                    let continuity = attest::Continuity::from_attested(&seed);
                    forwarder::Forwarder::start(forwarder::ForwarderConfig {
                        credentials: Some(credentials.clone()),
                        upstream: near.base_url().into(),
                        models: cfg.provider.models.clone(),
                        roots: forwarder::pin::native_roots()?,
                        seed,
                        // BlockingHttp: the forwarder runs this on Tokio's blocking pool.
                        reattest: {
                            let credentials = credentials.clone();
                            let models = cfg.provider.models.clone();
                            let options = attest_options;
                            // The launch's document, when this session loaded it,
                            // and its line; reloaded an hour after this session's
                            // last load, or once it expires.
                            let feed = Arc::new(Mutex::new((
                                feed_doc.clone(),
                                feed_loaded_at,
                                feed_source.line(),
                            )));
                            let feed_home = feed_home.clone();
                            Arc::new(move || {
                                let snapshot = credentials.snapshot()?;
                                let doc = {
                                    let mut state = feed.lock().unwrap_or_else(|e| e.into_inner());
                                    let (doc, loaded_at, last) = &mut *state;
                                    let now = unix_now();
                                    if let Some(source) = attest::feed::refresh(
                                        doc,
                                        loaded_at,
                                        feed_home.as_deref(),
                                        near,
                                        now,
                                    ) {
                                        let line = source.line();
                                        if line != *last {
                                            brand::progress::message(&format!("[rts] {line}"));
                                            *last = line;
                                        }
                                    }
                                    doc.clone()
                                };
                                let attest = |key| {
                                    attest::Attestor::real(
                                        near,
                                        Some(key),
                                        &models,
                                        options,
                                        doc.as_ref(),
                                        &std::collections::BTreeMap::new(),
                                    )
                                    .map_err(attest::AttestationFailure::Other)?
                                    .with_continuity(continuity.clone())
                                    .attest_for_launch()
                                };
                                let warn = |attested: attest::Attested| {
                                    for entry in attested.key_continuity() {
                                        brand::progress::message(&format!(
                                            "NEAR AI redeployed to a build that is not pinned; accepted because it holds this session's attested signing key: {entry}"
                                        ));
                                    }
                                    attested
                                };
                                match attest(snapshot.key).map(warn) {
                                    Ok(attested) => Ok(attested),
                                    Err(attest::AttestationFailure::CredentialRefused { .. })
                                        if snapshot.sponsored =>
                                    {
                                        brand::progress::message("Your sponsored API key is no longer available. Sign in to NEAR AI Cloud to continue.");
                                        // Reattest runs on the forwarder's blocking pool;
                                        // share any login already pending on its runtime.
                                        let next = tokio::runtime::Handle::current()
                                            .block_on(credentials.recover(snapshot.generation))?;
                                        attest(next.key).map(warn).map_err(attest::AttestationFailure::message)
                                    }
                                    Err(error) => Err(error.message()),
                                }
                            })
                        },
                        fatal: fatal.clone(),
                        record: record.clone(),
                        max_request_bytes: 32 << 20,
                        signatures: forwarder::signature::SignaturePolicy::default(),
                        inference_log: record.session_dir().join("inference.jsonl"),
                    })
                },
                |forwarder| {
                    inference::start_with_endpoint(
                        config::PLACEHOLDER_API_KEY.to_string().into(),
                        &cfg.provider.models,
                        &forwarder.base_url(),
                        ironwire,
                    )
                },
            )?;
            step.ok(&format!(
                "IronWire {} · pinned forwarder",
                inference.provider().base_url
            ));
            Ok((
                inference.provider(),
                Connected {
                    _inference: inference,
                    _forwarder: forwarder,
                },
            ))
        },
        |cfg| session::run_session_with_prompt(cfg, deps, initial_prompt.as_deref()),
    )?;
    Ok(Outcome {
        exit_code,
        session_id,
        session_dir,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> config::OperatorConfig {
        config::parse_config(
            "{}",
            Path::new("/cfg"),
            &config::Defaults {
                mvmctl: "/bin/mvmctl".into(),
                plugin_dir: "/repo/plugin".into(),
                opencode: "opencode".into(),
                sessions_dir: "/repo/sessions".into(),
                hyperv: Default::default(),
            },
        )
        .unwrap()
    }

    fn real_models() -> config::OperatorConfig {
        let mut cfg = default_config();
        cfg.provider.models = vec!["real-model".into()];
        cfg
    }

    fn external(cfg: &mut config::OperatorConfig) {
        cfg.embedded_inference = false;
        cfg.provider.id = "fake".into();
        cfg.provider.base_url = "http://127.0.0.1:9/v1".into();
    }

    fn allow_unattested() -> attest::AttestOptions {
        attest::AttestOptions {
            allow_unattested_provider: true,
            ..Default::default()
        }
    }

    #[test]
    fn launch_spec_from_cli_matches_the_old_flag_application() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("session.json");
        std::fs::write(&cfg_path, r#"{"network":{"allow":["seed.example"]}}"#).unwrap();

        let allow = vec!["a".to_string(), "packages".to_string()];
        let spec = LaunchSpec::from_cli(
            Some(&cfg_path),
            auth::LoginOptions::default(),
            attest::AttestOptions::default(),
            &allow,
            false,
            Some(4),
            Some(8192),
            true,
            Some("hello".into()),
        )
        .unwrap();
        assert_eq!(spec.config.network, ["seed.example", "a", "packages"]);
        assert_eq!(spec.config.limits.cpus, 4);
        assert_eq!(spec.config.limits.memory_mib, 8192);
        assert_eq!(spec.config.limits.host_rss_ceiling_mib, 9216);
        assert!(spec.no_splash);
        assert_eq!(spec.initial_prompt.as_deref(), Some("hello"));
        assert!(spec.session_id.is_none());
        assert!(spec.tool_command.is_none());
        // The CLI signs in natively, which is production only.
        assert_eq!(spec.near, inference::NearEnvironment::Production);

        let no_net = LaunchSpec::from_cli(
            Some(&cfg_path),
            auth::LoginOptions::default(),
            attest::AttestOptions::default(),
            &[],
            true,
            None,
            None,
            false,
            None,
        )
        .unwrap();
        assert!(no_net.config.network.is_empty());
        assert_eq!(no_net.config.limits, default_config().limits);
    }

    #[test]
    fn staging_needs_a_supplied_key() {
        use inference::NearEnvironment::{Production, Staging};
        let native = CredentialSource::Native(auth::LoginOptions::default());
        let supplied = CredentialSource::Supplied("sk-staging-test-key".to_string().into());
        assert!(check_credential_environment(&native, Production).is_ok());
        assert!(check_credential_environment(&supplied, Production).is_ok());
        assert!(check_credential_environment(&supplied, Staging).is_ok());
        let e = check_credential_environment(&native, Staging).unwrap_err();
        assert!(e.contains("staging"), "{e}");
    }

    #[test]
    fn launch_refuses_the_retired_placeholder_model_before_credentials() {
        let none = attest::AttestOptions::default();
        let mut cfg = default_config();
        cfg.provider.models = vec![config::MODEL_ID_PLACEHOLDER.into()];
        let e = check_launch(&cfg, &[], &none).unwrap_err();
        assert!(e.contains("placeholder"), "{e}");
        assert!(check_launch(&real_models(), &[], &none).is_ok());
        // The default config names the real NEAR AI model and launches.
        assert!(check_launch(&default_config(), &[], &none).is_ok());
    }

    #[test]
    fn launch_refuses_an_ironwire_endpoint_override_even_when_empty() {
        let none = attest::AttestOptions::default();
        for value in ["https://elsewhere.example/v1", ""] {
            let env = [
                ("HOME".to_string(), "/h".to_string()),
                ("IRONWIRE_NEARAI_BASE_URL".to_string(), value.to_string()),
            ];
            let e = check_launch(&real_models(), &env, &none).unwrap_err();
            assert!(e.contains("IRONWIRE_NEARAI_BASE_URL"), "{e}");
            let e = check_launch(&real_models(), &env, &allow_unattested()).unwrap_err();
            assert!(e.contains("IRONWIRE_NEARAI_BASE_URL"), "{e}");
        }
        let env = [("IRONWIRE_NEARAI_BASE_URL_X".to_string(), "x".to_string())];
        assert!(check_launch(&real_models(), &env, &none).is_ok());
    }

    #[test]
    fn an_external_provider_needs_the_explicit_unattested_flag() {
        let mut cfg = real_models();
        external(&mut cfg);
        let e = check_launch(&cfg, &[], &attest::AttestOptions::default()).unwrap_err();
        assert!(e.contains("--allow-unattested-provider"), "{e}");
        assert!(check_launch(&cfg, &[], &allow_unattested()).is_ok());
    }

    #[test]
    fn an_allowed_external_provider_is_recorded_as_unattested() {
        let d = tempfile::tempdir().unwrap();
        let mut cfg = real_models();
        external(&mut cfg);
        cfg.sessions_dir = d.path().join("sessions");
        record_unattested(&cfg, "0123456789ab", &allow_unattested()).unwrap();
        let doc: serde_json::Value = serde_json::from_slice(
            &std::fs::read(cfg.sessions_dir.join("0123456789ab/attestation.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(doc["status"], "unattested-provider");
        assert!(
            doc["reason"]
                .as_str()
                .unwrap()
                .contains("http://127.0.0.1:9/v1"),
            "{doc}"
        );
        assert_eq!(doc["overrides"]["allow_unattested_provider"], true);
    }

    fn verified_record() -> (
        tempfile::TempDir,
        std::sync::Arc<attest::record::AttestationRecord>,
    ) {
        let d = tempfile::tempdir().unwrap();
        let record = attest::record::AttestationRecord::create(
            d.path(),
            "0123456789ab",
            &attest::AttestOptions::default(),
        )
        .unwrap();
        (d, record)
    }

    fn seed() -> attest::Attested {
        let mut a = attest::Attested::default();
        a.fingerprints.insert([0xaa; 32]);
        a
    }

    fn status(record: &attest::record::AttestationRecord) -> (String, String) {
        let doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(record.path()).unwrap()).unwrap();
        (
            doc["status"].as_str().unwrap_or_default().into(),
            doc["reason"].as_str().unwrap_or_default().into(),
        )
    }

    #[test]
    fn connect_starts_the_forwarder_with_the_verified_seed_and_then_ironwire() {
        let (_d, record) = verified_record();
        let events = std::cell::RefCell::new(vec![]);
        let (f, i) = start_connected(
            &record,
            seed(),
            |s| {
                assert_eq!(status(&record).0, "verified");
                events.borrow_mut().push("forwarder");
                Ok(s.fingerprints.len())
            },
            |f| {
                events.borrow_mut().push("inference");
                Ok(*f + 1)
            },
        )
        .unwrap();
        assert_eq!((f, i), (1, 2));
        assert_eq!(*events.borrow(), ["forwarder", "inference"]);
        assert_eq!(status(&record).0, "verified");
    }

    #[test]
    fn a_forwarder_that_fails_to_start_refuses_the_session_on_record() {
        let (_d, record) = verified_record();
        let e = start_connected::<(), ()>(
            &record,
            seed(),
            |_| Err("bind failed".into()),
            |_| panic!("IronWire must not start without the forwarder"),
        )
        .unwrap_err();
        assert!(e.contains("forwarder") && e.contains("bind failed"), "{e}");
        assert!(e.contains(&record.path().display().to_string()), "{e}");
        let (s, reason) = status(&record);
        assert_eq!(s, "refused");
        assert!(reason.contains("forwarder"), "{reason}");
    }

    #[test]
    fn an_ironwire_that_fails_to_start_refuses_the_session_on_record() {
        let (_d, record) = verified_record();
        let e = start_connected::<(), ()>(
            &record,
            seed(),
            |_| Ok(()),
            |_| Err("inference: embedded proxy refused startup".into()),
        )
        .unwrap_err();
        assert!(e.contains("IronWire"), "{e}");
        let (s, reason) = status(&record);
        assert_eq!(s, "refused");
        assert!(reason.contains("IronWire"), "{reason}");
    }

    #[test]
    #[cfg(unix)]
    fn a_verified_record_that_cannot_be_written_names_the_record() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, record) = verified_record();
        let dir = record.session_dir().to_path_buf();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let e = start_connected::<(), ()>(
            &record,
            seed(),
            |_| panic!("the forwarder must not start without a record"),
            |_| panic!("IronWire must not start without a record"),
        )
        .unwrap_err();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(e.contains(&record.path().display().to_string()), "{e}");
        assert_eq!(status(&record).0, "pending");
    }

    #[test]
    fn local_preflight_failure_stops_before_credentials_or_session() {
        let result = run_connected::<()>(
            &mut default_config(),
            |_| Err("local dependencies missing".into()),
            |_| panic!("must not access credentials"),
            |_| panic!("must not start session"),
        );
        assert_eq!(result.unwrap_err(), "local dependencies missing");
    }

    #[test]
    #[cfg(unix)]
    fn unpatched_supervisor_is_rejected_before_credentials_or_browser_login() {
        struct StockSupervisor;
        impl session::Host for StockSupervisor {
            fn run(
                &self,
                argv: &[String],
                _: std::time::Duration,
            ) -> std::io::Result<crate::mvm::RunOutput> {
                let stdout = if argv.last().map(String::as_str) == Some("--version") {
                    "2.2.2\n"
                } else {
                    "stock supervisor\n"
                };
                Ok(crate::mvm::RunOutput {
                    code: Some(0),
                    stdout: stdout.as_bytes().to_vec(),
                    ..Default::default()
                })
            }
        }
        let env = vec![("HOME".into(), "/fake/operator".into())];
        let result = run_connected::<()>(
            &mut default_config(),
            |cfg| {
                local_preflight(
                    cfg,
                    &StockSupervisor,
                    &env,
                    inference::NearEnvironment::Production,
                )
            },
            |_| panic!("must not read credentials or open browser login"),
            |_| panic!("must not start session"),
        );
        assert!(result.unwrap_err().contains("rts-vsock-drain-v1"));
    }

    #[test]
    fn explicit_external_provider_does_not_start_auth_or_embedded_inference() {
        let mut cfg = default_config();
        cfg.embedded_inference = false;
        let original = cfg.provider.clone();
        let result = run_connected::<()>(
            &mut cfg,
            |_| panic!("external path owns preflight"),
            |_| panic!("must not authenticate"),
            |cfg| {
                assert_eq!(cfg.provider, original);
                42
            },
        )
        .unwrap();
        assert_eq!(result, 42);
    }

    #[test]
    fn embedded_connection_replaces_provider_and_lives_through_session_teardown() {
        use std::cell::RefCell;
        use std::rc::Rc;
        struct Guard(Rc<RefCell<Vec<&'static str>>>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.borrow_mut().push("inference dropped");
            }
        }
        let events = Rc::new(RefCell::new(Vec::new()));
        let mut cfg = default_config();
        let result = run_connected(
            &mut cfg,
            |_| {
                events.borrow_mut().push("preflight");
                Ok(())
            },
            |_| {
                events.borrow_mut().push("authenticate and connect");
                let provider = config::ProviderConfig {
                    id: "ironwire".into(),
                    base_url: "http://127.0.0.1:43210/openai/v1".into(),
                    models: vec!["chosen".into()],
                    api_key_env: None,
                };
                Ok((provider, Guard(events.clone())))
            },
            |cfg| {
                assert_eq!(cfg.provider.base_url, "http://127.0.0.1:43210/openai/v1");
                assert_eq!(*events.borrow(), ["preflight", "authenticate and connect"]);
                events.borrow_mut().push("session and teardown");
                7
            },
        )
        .unwrap();
        assert_eq!(result, 7);
        assert_eq!(
            *events.borrow(),
            [
                "preflight",
                "authenticate and connect",
                "session and teardown",
                "inference dropped"
            ]
        );
    }

    #[test]
    fn flags_merge_with_the_config_and_bad_entries_stop_before_credentials() {
        let mut cfg = real_models();
        cfg.network = vec!["packages".into()];
        apply_network(&mut cfg, &["a.example".into()], false);
        assert_eq!(cfg.network, ["packages", "a.example"]);
        apply_network(&mut cfg, &[], true);
        assert!(cfg.network.is_empty());
        cfg.network = vec!["a.example:22".into()];
        assert!(
            check_launch(&cfg, &[], &crate::attest::AttestOptions::default())
                .unwrap_err()
                .contains("port 22")
        );
    }

    #[test]
    fn vm_size_overrides_the_session_file() {
        let mut cfg = default_config();
        apply_vm_size(&mut cfg, Some(6), Some(12288)).unwrap();
        let l = cfg.limits;
        assert_eq!(
            (l.cpus, l.memory_mib, l.host_rss_ceiling_mib),
            (6, 12288, 13312)
        );
        let mut cfg = default_config();
        apply_vm_size(&mut cfg, None, None).unwrap();
        assert_eq!(cfg.limits, default_config().limits);
    }

    #[test]
    fn a_supplied_key_skips_native_sign_in() {
        use secrecy::ExposeSecret;
        let (_d, record) = verified_record();
        let sign_in = SignInHooks {
            load_for_launch: &|_| panic!("load_for_launch must not be called for Supplied"),
            login: &|_| panic!("login must not be called for Supplied"),
        };
        let seen = std::cell::RefCell::new(String::new());
        let (attested, creds) = resolve_and_attest(
            &CredentialSource::Supplied("sk-supplied-test-key".to_string().into()),
            &record,
            &["real-model".into()],
            None,
            &sign_in,
            |key| {
                *seen.borrow_mut() = key.expose_secret().to_string();
                Ok(seed())
            },
        )
        .unwrap();
        assert_eq!(*seen.borrow(), "sk-supplied-test-key");
        assert_eq!(attested.fingerprints.len(), 1);
        let snap = creds.snapshot().unwrap();
        assert_eq!(snap.key.expose_secret(), "sk-supplied-test-key");
        assert!(!snap.sponsored);
    }

    #[test]
    fn a_refused_supplied_key_refuses_launch_without_login() {
        let (_d, record) = verified_record();
        let sign_in = SignInHooks {
            load_for_launch: &|_| panic!("load_for_launch must not be called for Supplied"),
            login: &|_| panic!("login must not be called for Supplied"),
        };
        let err = resolve_and_attest(
            &CredentialSource::Supplied("sk-bad".to_string().into()),
            &record,
            &["real-model".into()],
            None,
            &sign_in,
            |_| {
                Err(attest::AttestationFailure::CredentialRefused {
                    model: "real-model".into(),
                })
            },
        )
        .err()
        .expect("refused supplied key must fail");
        assert!(err.contains("attestation failed"), "{err}");
        let (s, _reason) = status(&record);
        assert_eq!(s, "refused");
    }

    #[tokio::test]
    async fn a_refused_supplied_key_at_reattest_ends_the_session() {
        let (_d, record) = verified_record();
        let sign_in = SignInHooks {
            load_for_launch: &|_| panic!("load_for_launch must not be called for Supplied"),
            login: &|_| panic!("login must not be called for Supplied"),
        };
        let (_attested, creds) = resolve_and_attest(
            &CredentialSource::Supplied("sk-supplied".to_string().into()),
            &record,
            &["real-model".into()],
            None,
            &sign_in,
            |_| Ok(seed()),
        )
        .unwrap();
        let snap = creds.snapshot().unwrap();
        assert!(!snap.sponsored);
        let err = creds.recover(snap.generation).await.err().expect("recovery must fail");
        assert!(!err.is_empty());
    }
}

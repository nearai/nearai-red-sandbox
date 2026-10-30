//! rts: run an opencode session whose tools execute in a throwaway mvm microVM.
//!
//!   rts launch [--config <path>] start one session (operator entry point)
//!   rts login                    sign in through the system browser
//!   rts setup [--check [--offline]]  install and check mvm, opencode and the guest image
//!   rts --version                print the version
//!   rts tool <name>              one sandboxed tool call, spawned by the plugin shim

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use rts::{attest, auth, bridge, config, forwarder, inference, session, setup};

/// `--allow-host` entries in the order given, and `--no-network`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct NetworkFlags {
    allow: Vec<String>,
    none: bool,
}

#[derive(Debug)]
enum Action {
    Help,
    Version,
    Setup(setup::SetupOptions),
    Tool(String),
    Login(auth::LoginOptions),
    Launch {
        file: Option<PathBuf>,
        login: auth::LoginOptions,
        attest: attest::AttestOptions,
        network: NetworkFlags,
    },
}

fn parse_args(args: &[&str]) -> Result<Action, String> {
    if matches!(args, ["--help" | "-h" | "help"]) {
        return Ok(Action::Help);
    }
    if matches!(args, ["--version" | "-V"]) {
        return Ok(Action::Version);
    }
    if let ["setup", flags @ ..] = args {
        return parse_setup(flags);
    }
    if let ["tool", name] = args {
        return Ok(Action::Tool((*name).into()));
    }
    let (command, flags) = args.split_first().ok_or("Expected a command")?;
    if !matches!(*command, "launch" | "login") {
        return Err("Unknown command".into());
    }
    if flags.iter().any(|flag| matches!(*flag, "--help" | "-h")) {
        return Ok(Action::Help);
    }
    let mut file = None;
    let mut login = auth::LoginOptions::default();
    let mut attest = attest::AttestOptions::default();
    let mut network = NetworkFlags::default();
    let mut seen = std::collections::HashSet::new();
    let mut flags = flags.iter();
    while let Some(&flag) = flags.next() {
        let launch_only = matches!(
            flag,
            "--config"
                | "--allow-tcb-out-of-date"
                | "--compose-policy"
                | "--allow-unattested-provider"
                | "--allow-host"
                | "--no-network"
        );
        if !matches!(
            flag,
            "--config"
                | "--provider"
                | "--organization"
                | "--workspace"
                | "--allow-tcb-out-of-date"
                | "--compose-policy"
                | "--allow-unattested-provider"
                | "--allow-host"
                | "--no-network"
        ) || (launch_only && *command != "launch")
        {
            return Err(format!("Unknown option for {command}: {flag}"));
        }
        // --allow-host is the one repeatable option.
        if flag != "--allow-host" && !seen.insert(flag) {
            return Err(format!("Duplicate option: {flag}"));
        }
        if flag == "--no-network" {
            network.none = true;
            continue;
        }
        if flag == "--allow-tcb-out-of-date" {
            attest.allow_tcb_out_of_date = true;
            continue;
        }
        if flag == "--allow-unattested-provider" {
            attest.allow_unattested_provider = true;
            continue;
        }
        let value = flags
            .next()
            .copied()
            .filter(|value| !value.is_empty() && !value.starts_with('-'))
            .ok_or_else(|| format!("{flag} needs a value"))?;
        match flag {
            "--config" => file = Some(PathBuf::from(value)),
            "--allow-host" => network.allow.push(value.into()),
            "--compose-policy" => {
                attest.compose_policy = match value {
                    "pinned" => attest::ComposePolicy::Pinned,
                    "mr-config-only" => attest::ComposePolicy::MrConfigOnly,
                    _ => return Err("--compose-policy must be pinned or mr-config-only".into()),
                }
            }
            "--provider" => {
                login.provider = match value {
                    "github" => auth::Provider::Github,
                    "google" => auth::Provider::Google,
                    _ => return Err("--provider must be github or google".into()),
                }
            }
            "--organization" | "--workspace" => {
                if value.len() > 256
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return Err(format!("{flag} needs a valid account ID"));
                }
                if flag == "--organization" {
                    login.organization = Some(value.into());
                } else {
                    login.workspace = Some(value.into());
                }
            }
            _ => unreachable!(),
        }
    }
    if network.none && !network.allow.is_empty() {
        return Err("--no-network cannot be combined with --allow-host".into());
    }
    Ok(if *command == "login" {
        Action::Login(login)
    } else {
        Action::Launch {
            file,
            login,
            attest,
            network,
        }
    })
}

fn parse_setup(flags: &[&str]) -> Result<Action, String> {
    if flags.iter().any(|flag| matches!(*flag, "--help" | "-h")) {
        return Ok(Action::Help);
    }
    let mut o = setup::SetupOptions::default();
    for &flag in flags {
        let seen = match flag {
            "--check" => std::mem::replace(&mut o.check, true),
            "--offline" => std::mem::replace(&mut o.offline, true),
            _ => return Err(format!("Unknown option for setup: {flag}")),
        };
        if seen {
            return Err(format!("Duplicate option: {flag}"));
        }
    }
    if o.offline && !o.check {
        return Err("--offline requires --check".into());
    }
    Ok(Action::Setup(o))
}

fn run_connected<G>(
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

const USAGE: &str = "usage: rts launch [--config PATH] [--provider github|google] [--organization ID] [--workspace ID]\n                  [--allow-tcb-out-of-date] [--compose-policy pinned|mr-config-only]\n                  [--allow-unattested-provider] [--allow-host ENTRY]... [--no-network]\n       rts launch --allow-host packages            # pip, npm, apk and cargo registries\n       rts launch --allow-host api.example-target.com   # one target, port 443\n       rts launch --allow-host 192.168.1.20:8080   # a service on this machine's LAN address\n       rts login [--provider github|google] [--organization ID] [--workspace ID]\n       rts setup [--check [--offline]]\n       rts --version\n       rts tool <shell|read|write|edit|glob|grep>   (request JSON on stdin)\n\nrts launch signs in to NEAR AI Cloud when needed, verifies NEAR AI's attestation report for every\nallowed model (refusing the session otherwise), and starts a private inference proxy whose only\nroute to NEAR AI is a forwarder pinned to the attested TLS certificates.\nGitHub is the default sign-in provider. Explicit external provider configs bypass sign-in and\nattestation, and need --allow-unattested-provider.\nrts setup installs mvm, opencode and the guest image, each pinned by digest, and checks them;\n--check downloads and changes nothing, and --check --offline checks only the installed rts.";

/// A private temp directory holding an empty Git config for mvmctl.
fn private_git_config(prefix: &str) -> Result<(tempfile::TempDir, PathBuf), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let temp = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .map_err(|_| "Cannot create a private temp directory")?;
    let empty_git_config = temp.path().join("empty.gitconfig");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&empty_git_config)
        .map_err(|_| "Cannot create an empty Git configuration")?;
    Ok((temp, empty_git_config))
}

fn local_preflight(cfg: &config::OperatorConfig, host: &dyn session::Host, env: &[(String, String)]) -> Result<(), String> {
    let (temp, empty_git_config) = private_git_config("rts-preflight-")?;
    let work = temp.path().join("work");
    std::fs::create_dir(&work).map_err(|_| "Cannot create preflight work directory")?;
    let supervisor = session::supervisor_path(env, rts::install::current_prefix().as_deref())?;
    let runner = rts::mvm::SpawnRunner {
        mvmctl: cfg.mvmctl.clone(),
        empty_git_config,
        extra_env: session::mvm_environment(env, &supervisor),
        remove_env: Vec::new(),
    };
    // A pinned HTTPS placeholder skips the loopback-provider probe. Local
    // prerequisites must succeed before any native credential read or browser.
    let provider = config::ProviderConfig {
        base_url: "https://cloud-api.near.ai/v1".into(),
        ..cfg.provider.clone()
    };
    session::preflight(&session::PreflightInput {
        host,
        run: &runner,
        mvmctl: &cfg.mvmctl,
        opencode: &cfg.opencode,
        leak_seam_set: env.iter().any(|(key, _)| key == "RTS_TEST_LEAK"),
        supervisor_path: Some(&supervisor),
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
    rts::network::expand(&cfg.network)?;
    if !cfg.embedded_inference && !opts.allow_unattested_provider {
        return Err("the config names an external provider (provider.id, baseURL or apiKeyEnv), which rts cannot attest; pass --allow-unattested-provider to use it anyway".into());
    }
    Ok(())
}

/// `--no-network` clears the config's entries; otherwise `--allow-host`
/// entries follow the config's.
fn apply_network(cfg: &mut config::OperatorConfig, flags: &NetworkFlags) {
    if flags.none {
        cfg.network.clear();
    } else {
        cfg.network.extend(flags.allow.iter().cloned());
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

fn launch(
    file: Option<&Path>,
    login: &auth::LoginOptions,
    attest_options: attest::AttestOptions,
    network: &NetworkFlags,
) -> Result<i32, String> {
    let defaults = config::Defaults::from_env();
    let mut cfg = if let Some(file) = file {
        config::load_config(file, &defaults)?
    } else {
        config::parse_config(
            "{}",
            &std::env::current_dir().map_err(|_| "Cannot determine current directory")?,
            &defaults,
        )?
    };
    apply_network(&mut cfg, network);
    check_launch(&cfg, &std::env::vars().collect::<Vec<_>>(), &attest_options)?;
    let session_id = session::new_session_id();
    let fatal = forwarder::Fatal::new();
    let deps = session::Deps::real(session_id.clone(), Some(fatal.clone()))?;
    if !cfg.embedded_inference {
        record_unattested(&cfg, &session_id, &attest_options)?;
    }
    let preflight_env = deps.env.clone();
    let preflight_host = deps.host.clone();
    run_connected(
        &mut cfg,
        |cfg| local_preflight(cfg, preflight_host.as_ref(), &preflight_env),
        // Runs on the main thread, outside any Tokio runtime: attestation
        // uses blocking HTTP, and IronWire's runtime starts on its own thread
        // only after attestation succeeds.
        |cfg| {
            let credential = auth::load_or_login(login)?;
            let record = attest::record::AttestationRecord::create(
                &cfg.sessions_dir,
                &session_id,
                &attest_options,
            )?;
            let refused = |e: String| {
                record.set_status("refused", &e);
                format!("attestation failed: {e} (see {})", record.path().display())
            };
            let attestor = Arc::new(
                attest::Attestor::real(
                    Some(credential.key.clone()),
                    &cfg.provider.models,
                    attest_options,
                )
                .map_err(refused)?,
            );
            let attested = attestor.attest().map_err(refused)?;
            let (forwarder, inference) = start_connected(
                &record,
                attested,
                |seed| {
                    forwarder::Forwarder::start(forwarder::ForwarderConfig {
                        upstream: inference::NEAR_BASE_URL.into(),
                        models: cfg.provider.models.clone(),
                        roots: forwarder::pin::native_roots()?,
                        seed,
                        // BlockingHttp: the forwarder runs this on Tokio's blocking pool.
                        reattest: {
                            let attestor = attestor.clone();
                            Arc::new(move || attestor.attest())
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
                        credential.key,
                        &cfg.provider.models,
                        &forwarder.base_url(),
                    )
                },
            )?;
            Ok((
                inference.provider(),
                Connected {
                    _inference: inference,
                    _forwarder: forwarder,
                },
            ))
        },
        |cfg| session::run_session(cfg, deps),
    )
}

fn setup_command(o: &setup::SetupOptions) -> Result<i32, String> {
    let env: Vec<(String, String)> = std::env::vars().collect();
    let home = env
        .iter()
        .find(|(k, _)| k == "HOME")
        .map(|(_, v)| PathBuf::from(v))
        .filter(|h| h.is_absolute())
        .ok_or("rts setup needs HOME set to an absolute path")?;
    let defaults = config::Defaults::from_env();
    let explicit_mvmctl = env.iter().any(|(k, _)| k == "RTS_MVMCTL");
    let supervisor = session::supervisor_path(&env, rts::install::current_prefix().as_deref())?;
    let rts_exe = std::env::current_exe().map_err(|e| format!("Cannot locate the running rts: {e}"))?;
    let (_temp, empty_git_config) = private_git_config("rts-setup-")?;
    let fetch = setup::HttpsFetch::new()?;
    let mvm_plain = setup::plain_mvm_runner(&defaults.mvmctl, &empty_git_config, &env);
    let mvm = rts::mvm::SpawnRunner {
        mvmctl: defaults.mvmctl.clone(),
        empty_git_config,
        extra_env: session::mvm_environment(&env, &supervisor),
        remove_env: Vec::new(),
    };
    let lines = setup::run(
        o,
        &setup::SetupContext {
            home: &home,
            defaults: &defaults,
            explicit_mvmctl,
            supervisor: &supervisor,
            rts: &rts_exe,
            fetch: &fetch,
            host: &session::RealHost,
            mvm_plain: &mvm_plain,
            mvm: &mvm,
        },
    )
    .map_err(|e| e.lines().collect::<Vec<_>>().join("\n[rts] "))?;
    for line in lines {
        println!("{line}");
    }
    Ok(0)
}

fn code(c: i32) -> ExitCode {
    ExitCode::from(u8::try_from(c).unwrap_or(1))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let action = match parse_args(&args) {
        Ok(action) => action,
        Err(error) => {
            eprintln!("[rts] {error}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let result = match action {
        Action::Launch {
            file,
            login,
            attest,
            network,
        } => launch(file.as_deref(), &login, attest, &network),
        Action::Login(options) => auth::login(&options).map(|_| {
            println!("Signed in to NEAR AI Cloud.");
            0
        }),
        Action::Tool(name) => {
            let out = bridge::run(&name);
            let _ = std::io::stdout().write_all(out.stdout.as_bytes());
            if !out.stderr.is_empty() {
                eprintln!("{}", out.stderr.trim_end());
            }
            return code(out.code);
        }
        Action::Setup(options) => setup_command(&options),
        Action::Version => {
            println!("rts {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Action::Help => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
    };
    match result {
        Ok(status) => code(status),
        Err(error) => {
            eprintln!("[rts] {error}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rts::auth::Provider;

    fn default_config() -> config::OperatorConfig {
        config::parse_config(
            "{}",
            Path::new("/cfg"),
            &config::Defaults {
                mvmctl: "/bin/mvmctl".into(),
                plugin_dir: "/repo/plugin".into(),
                opencode: "opencode".into(),
                sessions_dir: "/repo/sessions".into(),
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
        let Action::Launch { attest, .. } =
            parse_args(&["launch", "--allow-unattested-provider"]).unwrap()
        else {
            panic!("not launch")
        };
        assert_eq!(attest, allow_unattested());
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
    fn unpatched_supervisor_is_rejected_before_credentials_or_browser_login() {
        struct StockSupervisor;
        impl session::Host for StockSupervisor {
            fn run(&self, argv: &[String], _: std::time::Duration) -> std::io::Result<rts::mvm::RunOutput> {
                let stdout = if argv.last().map(String::as_str) == Some("--version") { "2.2.2\n" } else { "stock supervisor\n" };
                Ok(rts::mvm::RunOutput { code: Some(0), stdout: stdout.as_bytes().to_vec(), ..Default::default() })
            }
        }
        let env = vec![("HOME".into(), "/fake/operator".into())];
        let result = run_connected::<()>(
            &mut default_config(),
            |cfg| local_preflight(cfg, &StockSupervisor, &env),
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
    fn default_launch_and_explicit_account_flags_parse_without_side_effects() {
        let Action::Launch {
            file,
            login,
            attest,
            network,
        } = parse_args(&["launch"]).unwrap()
        else {
            panic!("not launch")
        };
        assert_eq!(file, None);
        assert_eq!(login.provider, Provider::Github);
        assert_eq!(attest, rts::attest::AttestOptions::default());
        assert_eq!(network, NetworkFlags::default());
        let Action::Launch { file, login, .. } = parse_args(&[
            "launch",
            "--workspace",
            "workspace-one",
            "--config",
            "session.json",
            "--provider",
            "google",
            "--organization",
            "org-one",
        ])
        .unwrap() else {
            panic!("not launch")
        };
        assert_eq!(file, Some("session.json".into()));
        assert_eq!(login.provider, Provider::Google);
        assert_eq!(login.organization.as_deref(), Some("org-one"));
        assert_eq!(login.workspace.as_deref(), Some("workspace-one"));
    }

    #[test]
    fn launch_attestation_overrides_parse() {
        use rts::attest::{AttestOptions, ComposePolicy};
        let Action::Launch { attest, .. } = parse_args(&[
            "launch",
            "--allow-tcb-out-of-date",
            "--compose-policy",
            "mr-config-only",
        ])
        .unwrap() else {
            panic!("not launch")
        };
        assert_eq!(
            attest,
            AttestOptions {
                allow_tcb_out_of_date: true,
                compose_policy: ComposePolicy::MrConfigOnly,
                allow_unattested_provider: false,
            }
        );
        let Action::Launch { attest, file, .. } =
            parse_args(&["launch", "--compose-policy", "pinned", "--config", "c.json"]).unwrap()
        else {
            panic!("not launch")
        };
        assert_eq!(attest, AttestOptions::default());
        assert_eq!(file, Some("c.json".into()));
    }

    #[test]
    fn login_defaults_to_github_and_can_explicitly_select_google() {
        let Action::Login(login) = parse_args(&["login"]).unwrap() else {
            panic!("not login")
        };
        assert_eq!(login.provider, Provider::Github);
        let Action::Login(login) = parse_args(&["login", "--provider", "google"]).unwrap() else {
            panic!("not login")
        };
        assert_eq!(login.provider, Provider::Google);
    }

    #[test]
    fn allow_host_repeats_and_no_network_conflicts() {
        let Action::Launch { network, .. } = parse_args(&[
            "launch",
            "--allow-host",
            "packages",
            "--allow-host",
            "a.example:8443",
        ])
        .unwrap() else {
            panic!("not launch")
        };
        assert_eq!(
            network,
            NetworkFlags {
                allow: vec!["packages".into(), "a.example:8443".into()],
                none: false
            }
        );
        let Action::Launch { network, .. } = parse_args(&["launch", "--no-network"]).unwrap()
        else {
            panic!("not launch")
        };
        assert!(network.none);
        assert!(
            parse_args(&["launch", "--no-network", "--allow-host", "a.example"])
                .unwrap_err()
                .contains("--no-network")
        );
        assert!(
            parse_args(&["launch", "--allow-host", "a.example", "--no-network"])
                .unwrap_err()
                .contains("--no-network")
        );
        assert!(
            parse_args(&["launch", "--allow-host"])
                .unwrap_err()
                .contains("needs a value")
        );
        assert!(parse_args(&["login", "--allow-host", "a.example"]).is_err());
        assert!(parse_args(&["login", "--no-network"]).is_err());
        assert!(
            parse_args(&["launch", "--no-network", "--no-network"])
                .unwrap_err()
                .contains("Duplicate")
        );
    }

    #[test]
    fn flags_merge_with_the_config_and_bad_entries_stop_before_credentials() {
        let mut cfg = real_models();
        cfg.network = vec!["packages".into()];
        apply_network(
            &mut cfg,
            &NetworkFlags {
                allow: vec!["a.example".into()],
                none: false,
            },
        );
        assert_eq!(cfg.network, ["packages", "a.example"]);
        apply_network(
            &mut cfg,
            &NetworkFlags {
                allow: vec![],
                none: true,
            },
        );
        assert!(cfg.network.is_empty());
        cfg.network = vec!["a.example:22".into()];
        assert!(
            check_launch(&cfg, &[], &rts::attest::AttestOptions::default())
                .unwrap_err()
                .contains("port 22")
        );
    }

    #[test]
    fn malformed_arguments_fail_before_config_or_credentials_are_touched() {
        for args in [
            vec!["launch", "--config"],
            vec!["login", "--config", "x"],
            vec!["login", "--provider", "other"],
            vec!["launch", "--unknown", "x"],
            vec!["launch", "--organization", "--workspace", "w"],
            vec!["login", "--provider", "github", "--provider", "google"],
            vec!["launch", "--config", "a", "--config", "b"],
            vec!["login", "--organization", "../escape"],
            vec!["launch", "--config", ""],
            vec!["launch", "--compose-policy", "other"],
            vec!["launch", "--compose-policy"],
            vec!["launch", "--compose-policy", "--allow-tcb-out-of-date"],
            vec![
                "launch",
                "--compose-policy",
                "pinned",
                "--compose-policy",
                "pinned",
            ],
            vec![
                "launch",
                "--allow-tcb-out-of-date",
                "--allow-tcb-out-of-date",
            ],
            vec!["launch", "--allow-tcb-out-of-date", "yes"],
            vec!["login", "--allow-tcb-out-of-date"],
            vec!["login", "--compose-policy", "pinned"],
            vec!["login", "--allow-unattested-provider"],
            vec!["launch", "--allow-unattested-provider", "yes"],
            vec![
                "launch",
                "--allow-unattested-provider",
                "--allow-unattested-provider",
            ],
            vec!["other"],
            vec![],
            vec!["setup", "--offline"],
            vec!["setup", "--check", "--check"],
            vec!["setup", "--config", "x"],
            vec!["setup", "extra"],
            vec!["--version", "x"],
            vec!["launch", "--allow-host", "--no-network"],
            vec!["launch", "--allow-host", ""],
        ] {
            assert!(parse_args(&args).is_err(), "accepted {args:?}");
        }
    }

    #[test]
    fn setup_and_version_parse() {
        use rts::setup::SetupOptions;
        for (args, want) in [
            (vec!["setup"], SetupOptions::default()),
            (vec!["setup", "--check"], SetupOptions { check: true, offline: false }),
            (vec!["setup", "--check", "--offline"], SetupOptions { check: true, offline: true }),
            (vec!["setup", "--offline", "--check"], SetupOptions { check: true, offline: true }),
        ] {
            assert!(matches!(parse_args(&args), Ok(Action::Setup(o)) if o == want), "{args:?}");
        }
        for args in [vec!["--version"], vec!["-V"]] {
            assert!(matches!(parse_args(&args), Ok(Action::Version)), "{args:?}");
        }
        assert!(matches!(parse_args(&["setup", "--help"]), Ok(Action::Help)));
        let e = parse_args(&["setup", "--offline"]).unwrap_err();
        assert!(e.contains("--offline requires --check"), "{e}");
        assert!(USAGE.contains("rts setup [--check [--offline]]") && USAGE.contains("rts --version"));
    }

    #[test]
    fn help_and_plugin_tool_dispatch_do_not_need_authentication() {
        for args in [
            vec!["--help"],
            vec!["help"],
            vec!["launch", "--help"],
            vec!["login", "-h"],
        ] {
            assert!(matches!(parse_args(&args), Ok(Action::Help)));
        }
        assert!(matches!(parse_args(&["tool", "read"]), Ok(Action::Tool(name)) if name == "read"));
    }
}

//! rts: run an opencode session whose tools execute in a throwaway mvm microVM.
//!
//!   rts launch [--config <path>] start one session (operator entry point)
//!   rts login                    sign in through the system browser
//!   rts tool <name>              one sandboxed tool call, spawned by the plugin shim

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use rts::{auth, bridge, config, inference, session};

#[derive(Debug)]
enum Action {
    Help,
    Tool(String),
    Login(auth::LoginOptions),
    Launch {
        file: Option<PathBuf>,
        login: auth::LoginOptions,
    },
}

fn parse_args(args: &[&str]) -> Result<Action, String> {
    if matches!(args, ["--help" | "-h" | "help"]) {
        return Ok(Action::Help);
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
    let mut seen = std::collections::HashSet::new();
    let mut flags = flags.iter();
    while let Some(&flag) = flags.next() {
        if !matches!(
            flag,
            "--config" | "--provider" | "--organization" | "--workspace"
        ) || (flag == "--config" && *command != "launch")
        {
            return Err(format!("Unknown option for {command}: {flag}"));
        }
        if !seen.insert(flag) {
            return Err(format!("Duplicate option: {flag}"));
        }
        let value = flags
            .next()
            .copied()
            .filter(|value| !value.is_empty() && !value.starts_with('-'))
            .ok_or_else(|| format!("{flag} needs a value"))?;
        match flag {
            "--config" => file = Some(PathBuf::from(value)),
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
    Ok(if *command == "login" {
        Action::Login(login)
    } else {
        Action::Launch { file, login }
    })
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

const USAGE: &str = "usage: rts launch [--config PATH] [--provider github|google] [--organization ID] [--workspace ID]\n       rts login [--provider github|google] [--organization ID] [--workspace ID]\n       rts tool <shell|read|write|edit|glob|grep>   (request JSON on stdin)\n\nrts launch signs in to NEAR AI Cloud when needed and starts a private inference proxy.\nGitHub is the default sign-in provider. Explicit external provider configs bypass sign-in.";

fn local_preflight(cfg: &config::OperatorConfig) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let temp = tempfile::Builder::new()
        .prefix("rts-preflight-")
        .tempdir()
        .map_err(|_| "Cannot create private preflight directory")?;
    let empty_git_config = temp.path().join("empty.gitconfig");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&empty_git_config)
        .map_err(|_| "Cannot create preflight Git configuration")?;
    let work = temp.path().join("work");
    std::fs::create_dir(&work).map_err(|_| "Cannot create preflight work directory")?;
    let runner = rts::mvm::SpawnRunner {
        mvmctl: cfg.mvmctl.clone(),
        empty_git_config,
        extra_env: Default::default(),
    };
    // A pinned HTTPS placeholder skips the loopback-provider probe. Local
    // prerequisites must succeed before any native credential read or browser.
    let provider = config::ProviderConfig {
        base_url: "https://cloud-api.near.ai/v1".into(),
        ..cfg.provider.clone()
    };
    session::preflight(&session::PreflightInput {
        host: &session::RealHost,
        run: &runner,
        opencode: &cfg.opencode,
        leak_seam_set: std::env::var_os("RTS_TEST_LEAK").is_some(),
        work_dir: Some(&work),
        provider: &provider,
    })
}

fn launch(file: Option<&Path>, login: &auth::LoginOptions) -> Result<i32, String> {
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
    let deps = session::Deps::real()?;
    run_connected(
        &mut cfg,
        local_preflight,
        |cfg| {
            let credential = auth::load_or_login(login)?;
            let inference = inference::start(credential.key, &cfg.provider.models)?;
            Ok((inference.provider(), inference))
        },
        |cfg| session::run_session(cfg, deps),
    )
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
        Action::Launch { file, login } => launch(file.as_deref(), &login),
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
                repo: "/repo".into(),
                mvmctl: "/bin/mvmctl".into(),
            },
        )
        .unwrap()
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
        let Action::Launch { file, login } = parse_args(&["launch"]).unwrap() else {
            panic!("not launch")
        };
        assert_eq!(file, None);
        assert_eq!(login.provider, Provider::Github);
        let Action::Launch { file, login } = parse_args(&[
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
            vec!["other"],
            vec![],
        ] {
            assert!(parse_args(&args).is_err(), "accepted {args:?}");
        }
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

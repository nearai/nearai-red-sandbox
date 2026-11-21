//! rts: run an opencode session whose tools execute in a throwaway mvm microVM.
//!
//!   rts launch [--config <path>] start one session (operator entry point)
//!   rts login                    sign in through the system browser
//!   rts setup [--check [--offline]]  install and check mvm, opencode and the guest image
//!   rts update [--check | --force]  install the newest signed release
//!   rts --version                print the version
//!   rts tool <name>              one sandboxed tool call, spawned by the plugin shim

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use rts::{attest, auth, bridge, config, launch, setup};
#[cfg(unix)]
use rts::session;

/// `--allow-host` entries in the order given, and `--no-network`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct NetworkFlags {
    allow: Vec<String>,
    none: bool,
}

/// `--cpus` and `--memory`, overriding the session file's limits.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct VmSize {
    cpus: Option<u32>,
    memory_mib: Option<u32>,
}

/// Operator-supplied task text; never part of the persistent session configuration.
#[derive(Debug)]
enum PromptSource {
    Text(String),
    File(PathBuf),
}

const MAX_PROMPT_BYTES: usize = 64 * 1024;

impl PromptSource {
    fn read(&self) -> Result<String, String> {
        use std::io::Read;
        let text = match self {
            Self::Text(text) => text.clone(),
            Self::File(path) => {
                // Nonblocking open makes a mistaken FIFO path fail rather than
                // hanging before we can verify the opened object is a file.
                let file = rts::sys::fs::open_read_nonblocking(path)
                    .map_err(|e| format!("cannot read prompt file {}: {e}", path.display()))?;
                if !file.metadata().map_err(|e| format!("cannot inspect prompt file {}: {e}", path.display()))?.is_file() {
                    return Err(format!("prompt file {} must be a regular file", path.display()));
                }
                let mut bytes = Vec::new();
                file.take((MAX_PROMPT_BYTES + 1) as u64).read_to_end(&mut bytes)
                    .map_err(|e| format!("cannot read prompt file {}: {e}", path.display()))?;
                if bytes.len() > MAX_PROMPT_BYTES {
                    return Err(format!("initial prompt must be at most {MAX_PROMPT_BYTES} bytes"));
                }
                String::from_utf8(bytes).map_err(|_| "prompt file must contain UTF-8 text".to_string())?
            }
        };
        if text.len() > MAX_PROMPT_BYTES {
            return Err(format!("initial prompt must be at most {MAX_PROMPT_BYTES} bytes"));
        }
        if text.trim().is_empty() {
            return Err("initial prompt must not be empty or whitespace-only".into());
        }
        if text.contains('\0') {
            return Err("initial prompt must not contain NUL bytes".into());
        }
        Ok(text)
    }
}

#[derive(Debug)]
enum Action {
    Help,
    Version,
    Setup(setup::SetupOptions),
    Update(rts::update::apply::UpdateOptions),
    Tool(String),
    Login(auth::LoginOptions),
    Trial(PathBuf),
    Launch {
        file: Option<PathBuf>,
        login: auth::LoginOptions,
        attest: attest::AttestOptions,
        network: NetworkFlags,
        vm: VmSize,
        no_splash: bool,
        prompt: Option<PromptSource>,
    },
}

fn parse_args(args: &[&str]) -> Result<Action, String> {
    if matches!(args, ["--help" | "-h" | "help"]) {
        return Ok(Action::Help);
    }
    if matches!(args, ["--version" | "-V"]) {
        return Ok(Action::Version);
    }
    if let ["trial", "--key-file", path] = args {
        if path.is_empty() || path.starts_with('-') {
            return Err("trial --key-file needs a path".into());
        }
        return Ok(Action::Trial(PathBuf::from(path)));
    }
    if let ["setup", flags @ ..] = args {
        return parse_setup(flags);
    }
    if let ["update", flags @ ..] = args {
        return parse_update(flags);
    }
    if let ["tool", name] = args {
        return Ok(Action::Tool((*name).into()));
    }
    let (command, flags) = args.split_first().ok_or("Expected a command")?;
    if !matches!(*command, "launch" | "login") {
        return Err("Unknown command".into());
    }
    let mut file = None;
    let mut login = auth::LoginOptions::default();
    let mut attest = attest::AttestOptions::default();
    let mut network = NetworkFlags::default();
    let mut vm = VmSize::default();
    let mut no_splash = false;
    let mut prompt = None;
    let mut seen = std::collections::HashSet::new();
    let mut flags = flags.iter();
    while let Some(&flag) = flags.next() {
        if matches!(flag, "--help" | "-h") { return Ok(Action::Help); }
        let launch_only = matches!(
            flag,
            "--config"
                | "--allow-tcb-out-of-date"
                | "--compose-policy"
                | "--allow-unattested-provider"
                | "--allow-host"
                | "--no-network"
                | "--no-splash"
                | "--cpus"
                | "--memory"
                | "--prompt"
                | "--prompt-file"
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
                | "--no-splash"
                | "--cpus"
                | "--memory"
                | "--prompt"
                | "--prompt-file"
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
        if flag == "--no-splash" {
            no_splash = true;
            continue;
        }
        let value = flags
            .next()
            .copied()
            .filter(|value| !value.is_empty() && (flag == "--prompt" || !value.starts_with('-')))
            .ok_or_else(|| format!("{flag} needs a value"))?;
        match flag {
            "--config" => file = Some(PathBuf::from(value)),
            "--prompt" | "--prompt-file" => {
                if prompt.is_some() {
                    return Err("--prompt and --prompt-file cannot be combined".into());
                }
                prompt = Some(if flag == "--prompt" {
                    PromptSource::Text(value.into())
                } else {
                    PromptSource::File(PathBuf::from(value))
                });
            }
            "--allow-host" => network.allow.push(value.into()),
            "--cpus" => {
                vm.cpus = Some(
                    value
                        .parse::<u32>()
                        .ok()
                        .filter(|n| *n >= 1 && value.bytes().all(|b| b.is_ascii_digit()))
                        .ok_or("--cpus must be a whole number of at least 1")?,
                )
            }
            "--memory" => vm.memory_mib = Some(config::parse_memory(value)?),
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
            vm,
            no_splash,
            prompt,
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

fn parse_update(flags: &[&str]) -> Result<Action, String> {
    if flags.iter().any(|flag| matches!(*flag, "--help" | "-h")) {
        return Ok(Action::Help);
    }
    let mut o = rts::update::apply::UpdateOptions::default();
    for &flag in flags {
        let seen = match flag {
            "--check" => std::mem::replace(&mut o.check, true),
            "--force" => std::mem::replace(&mut o.force, true),
            _ => return Err(format!("Unknown option for update: {flag}")),
        };
        if seen {
            return Err(format!("Duplicate option: {flag}"));
        }
    }
    if o.check && o.force {
        return Err("--check and --force cannot be combined".into());
    }
    Ok(Action::Update(o))
}

const USAGE: &str = "usage: rts launch [--config PATH] [--provider github|google] [--organization ID] [--workspace ID]\n                  [--allow-tcb-out-of-date] [--compose-policy pinned|mr-config-only]\n                  [--allow-unattested-provider] [--allow-host ENTRY]... [--no-network] [--no-splash]\n                  [--cpus N] [--memory SIZE] [--prompt TEXT | --prompt-file PATH]\n       rts launch --prompt \"Review /in and save findings to /out/report.md\"\n       rts launch --prompt-file ./handoff.md       # submit a UTF-8 task file\n       rts launch --allow-host packages            # pip, npm, apk and cargo registries\n       rts launch --allow-host api.example-target.com   # one target, port 443\n       rts launch --allow-host 192.168.1.20:8080   # a service on this machine's LAN address\n       rts launch --cpus 4 --memory 8G             # a bigger VM (default 2 vCPUs, 2048 MiB)\n       rts trial --key-file PATH   # import your individual sponsored allowance\n       rts login [--provider github|google] [--organization ID] [--workspace ID]\n       rts setup [--check [--offline]]\n       rts update [--check | --force]\n       rts --version\n       rts tool <shell|read|write|edit|glob|grep>   (request JSON on stdin)\n\nrts launch signs in to NEAR AI Cloud when needed, verifies NEAR AI's attestation report for every\nallowed model (refusing the session otherwise), and starts a private inference proxy whose only\nroute to NEAR AI is a forwarder pinned to the attested TLS certificates.\nGitHub is the default sign-in provider. Explicit external provider configs bypass sign-in and\nattestation, and need --allow-unattested-provider. --no-splash skips the opening splash, which\nis drawn only on an interactive terminal without NO_COLOR or TERM=dumb; any key skips it too.\nThe guest has no network unless the session file's network.allow or --allow-host names entries\n(HOST, HOST:PORT, IP:PORT or [IPv6]:PORT, port 443 by default, or the preset packages);\n--no-network drops them all. TCP only, and every connection is logged. A session stops with\nsession-limit after limits.sessionHours (default 24), network-lost when the attached\nmvmctl machine run that keeps egress up exits, and network-mismatch when mvm pinned an address\nrts did not validate; /out is exported and the VM removed in every case.\n--cpus and --memory (MiB, or with an M or G suffix) override limits.cpus and limits.memoryMiB,\nup to this host's CPU count and RAM; the host RSS watchdog follows memory unless the session\nfile sets limits.hostRssCeilingMiB.\n--prompt or --prompt-file submits one initial task after the sandbox plugin is verified,\nthen leaves OpenCode interactive. Prompt files are relative to the invoking directory,\nmust be UTF-8 and at most 64 KiB; empty/whitespace-only or NUL-containing text is refused.\nrts setup installs mvm, opencode and the guest image, each pinned by digest, and checks them;\n--check downloads and changes nothing, and --check --offline checks only the installed rts.\nrts update installs the newest signed release over a curl install; --check only reports.";

#[cfg(not(unix))]
fn setup_command(_o: &setup::SetupOptions) -> Result<i32, String> {
    Err("rts setup is not supported on this OS yet".into())
}

#[cfg(unix)]
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
    let (_temp, empty_git_config) = launch::private_git_config("rts-setup-")?;
    let fetch = setup::HttpsFetch::new()?;
    let mvm_plain = setup::plain_mvm_runner(&defaults.mvmctl, &empty_git_config, &env);
    let flavor = rts::backend::mvm::Flavor::host();
    let shim_dir = empty_git_config.parent().map(|p| p.join("sudo-shim")).ok_or("the setup Git configuration has no parent directory")?;
    let mvm = rts::mvm::SpawnRunner {
        mvmctl: defaults.mvmctl.clone(),
        empty_git_config,
        extra_env: rts::backend::mvm::MvmBackend::mvmctl_environment(flavor, &env, Some(&supervisor), &shim_dir)?,
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
            vm,
            no_splash,
            prompt,
        } => {
            let initial_prompt = prompt.as_ref().map(PromptSource::read).transpose();
            match initial_prompt {
                Ok(prompt) => launch::LaunchSpec::from_cli(
                    file.as_deref(),
                    login,
                    attest,
                    &network.allow,
                    network.none,
                    vm.cpus,
                    vm.memory_mib,
                    no_splash,
                    prompt,
                )
                .and_then(launch::run)
                .map(|outcome| outcome.exit_code),
                Err(error) => Err(error),
            }
        }
        Action::Trial(path) => auth::import_sponsored(&path).map(|_| {
            println!("Sponsored API key saved. Run rts launch to start; NEAR AI Cloud sign-in will be offered when its allowance runs out or the key is revoked.");
            0
        }),
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
        Action::Update(options) => rts::update::apply::command(&options),
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
    use std::path::Path;

    fn allow_unattested() -> attest::AttestOptions {
        attest::AttestOptions {
            allow_unattested_provider: true,
            ..Default::default()
        }
    }

    #[test]
    fn launch_accepts_an_initial_prompt_or_prompt_file() {
        assert!(parse_args(&["launch", "--prompt", "Inspect /in and report in /out"]).is_ok());
        assert!(parse_args(&["launch", "--prompt-file", "handoff.md"]).is_ok());
    }

    #[test]
    fn prompt_options_are_launch_only_exclusive_and_not_repeatable() {
        for flags in [
            vec!["launch", "--prompt", "one", "--prompt", "two"],
            vec!["launch", "--prompt-file", "a", "--prompt-file", "b"],
            vec!["launch", "--prompt", "one", "--prompt-file", "b"],
            vec!["launch", "--prompt-file", "b", "--prompt", "one"],
            vec!["login", "--prompt", "one"],
            vec!["login", "--prompt-file", "a"],
            vec!["launch", "--prompt"],
            vec!["launch", "--prompt-file"],
        ] {
            assert!(parse_args(&flags).is_err(), "accepted {flags:?}");
        }
        let Action::Launch { prompt: Some(source), .. } = parse_args(&["launch", "--prompt", "- review /in"]).unwrap() else { panic!("missing prompt") };
        assert_eq!(source.read().unwrap(), "- review /in");
        let Action::Launch { prompt: Some(source), .. } = parse_args(&["launch", "--prompt", "--help"]).unwrap() else { panic!("prompt was interpreted as a flag") };
        assert_eq!(source.read().unwrap(), "--help");
    }

    #[test]
    fn prompt_file_and_inline_text_preserve_exact_utf8_and_newlines() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("handoff.md");
        let text = "  Examine 'quoted' $(literal) `literal` ☃\r\nThen save to /out.\n";
        std::fs::write(&file, text).unwrap();
        assert_eq!(PromptSource::File(file.clone()).read().unwrap(), text);
        assert_eq!(PromptSource::Text(text.into()).read().unwrap(), text);
        // Keep relative CLI paths relative to the invoking directory, not --config.
        let Action::Launch { prompt: Some(PromptSource::File(path)), .. } = parse_args(&["launch", "--config", "/elsewhere/session.json", "--prompt-file", "handoff.md"]).unwrap() else { panic!("missing prompt file") };
        assert_eq!(path, Path::new("handoff.md"));
    }

    #[test]
    #[cfg(unix)]
    fn invalid_prompt_content_and_paths_fail_before_launch() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("prompt");
        for text in ["", " \t\n", "bad\0prompt"] {
            assert!(PromptSource::Text(text.into()).read().is_err());
            std::fs::write(&file, text).unwrap();
            assert!(PromptSource::File(file.clone()).read().is_err());
        }
        assert!(PromptSource::Text("x".repeat(MAX_PROMPT_BYTES + 1)).read().unwrap_err().contains("at most"));
        assert_eq!(PromptSource::Text("x".repeat(MAX_PROMPT_BYTES)).read().unwrap().len(), MAX_PROMPT_BYTES);
        std::fs::write(&file, vec![b'x'; MAX_PROMPT_BYTES + 1]).unwrap();
        assert!(PromptSource::File(file.clone()).read().unwrap_err().contains("at most"));
        std::fs::write(&file, [0xff]).unwrap();
        assert!(PromptSource::File(file).read().unwrap_err().contains("UTF-8"));
        assert!(PromptSource::File(dir.path().join("missing")).read().is_err());
        assert!(PromptSource::File(dir.path().to_path_buf()).read().unwrap_err().contains("regular file"));
        let fifo = dir.path().join("fifo");
        let cpath = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
        assert!(PromptSource::File(fifo).read().unwrap_err().contains("regular file"));
    }

    #[test]
    fn allow_unattested_provider_flag_parses() {
        let Action::Launch { attest, .. } =
            parse_args(&["launch", "--allow-unattested-provider"]).unwrap()
        else {
            panic!("not launch")
        };
        assert_eq!(attest, allow_unattested());
    }

    #[test]
    fn trial_import_requires_a_key_file_and_never_accepts_a_key_on_argv() {
        assert!(
            matches!(parse_args(&["trial", "--key-file", "/private/key"]).unwrap(), Action::Trial(path) if path == Path::new("/private/key"))
        );
        for args in [
            vec!["trial"],
            vec!["trial", "--key-file"],
            vec!["trial", "secret"],
            vec!["trial", "--key", "secret"],
            vec!["trial", "--key-file", "a", "extra"],
        ] {
            assert!(parse_args(&args).is_err());
        }
    }

    #[test]
    fn default_launch_and_explicit_account_flags_parse_without_side_effects() {
        let Action::Launch {
            file,
            login,
            attest,
            network,
            ..
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
    fn no_splash_is_a_launch_only_switch() {
        let Action::Launch { no_splash, .. } = parse_args(&["launch"]).unwrap() else {
            panic!("not launch")
        };
        assert!(!no_splash);
        let Action::Launch { no_splash, file, .. } =
            parse_args(&["launch", "--no-splash", "--config", "c.json"]).unwrap()
        else {
            panic!("not launch")
        };
        assert!(no_splash);
        assert_eq!(file, Some("c.json".into()));
        for args in [
            vec!["login", "--no-splash"],
            vec!["launch", "--no-splash", "--no-splash"],
            vec!["launch", "--no-splash", "yes"],
        ] {
            assert!(parse_args(&args).is_err(), "accepted {args:?}");
        }
        assert!(USAGE.contains("[--no-splash]") && USAGE.contains("--no-splash skips"));
    }

    #[test]
    fn cpus_and_memory_are_launch_only_and_override_the_session_file() {
        let Action::Launch { vm, .. } = parse_args(&["launch"]).unwrap() else {
            panic!("not launch")
        };
        assert_eq!(vm, VmSize::default());
        let Action::Launch { vm, .. } =
            parse_args(&["launch", "--cpus", "4", "--memory", "8G"]).unwrap()
        else {
            panic!("not launch")
        };
        assert_eq!(vm, VmSize { cpus: Some(4), memory_mib: Some(8192) });
        for args in [
            vec!["login", "--cpus", "2"],
            vec!["login", "--memory", "4G"],
            vec!["launch", "--cpus", "2", "--cpus", "3"],
            vec!["launch", "--memory", "4G", "--memory", "8G"],
            vec!["launch", "--cpus", "0"],
            vec!["launch", "--cpus", "two"],
            vec!["launch", "--cpus", "1.5"],
            vec!["launch", "--cpus"],
            vec!["launch", "--memory", "1T"],
            vec!["launch", "--memory", "32"],
            vec!["launch", "--memory"],
        ] {
            assert!(parse_args(&args).is_err(), "accepted {args:?}");
        }

        assert!(USAGE.contains("[--cpus N] [--memory SIZE]"));
        assert!(USAGE.contains("rts launch --cpus 4 --memory 8G"));
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
    fn help_lists_the_network_flags_and_examples() {
        for want in [
            "--allow-host ENTRY",
            "--no-network",
            "--allow-host packages",
            "--allow-host api.example-target.com",
            "192.168.1.20:8080",
            "network.allow",
            "limits.sessionHours",
            "network-lost",
            "network-mismatch",
            "session-limit",
        ] {
            assert!(USAGE.contains(want), "USAGE lacks {want:?}");
        }
    }

    #[test]
    fn update_parses_its_flags() {
        use rts::update::apply::UpdateOptions;
        for (args, want) in [
            (vec!["update"], UpdateOptions::default()),
            (vec!["update", "--check"], UpdateOptions { check: true, force: false }),
            (vec!["update", "--force"], UpdateOptions { check: false, force: true }),
        ] {
            assert!(matches!(parse_args(&args), Ok(Action::Update(o)) if o == want), "{args:?}");
        }
        for (args, want) in [
            (vec!["update", "--check", "--force"], "--check and --force cannot be combined"),
            (vec!["update", "--force", "--check"], "--check and --force cannot be combined"),
            (vec!["update", "--check", "--check"], "Duplicate option: --check"),
            (vec!["update", "--yes"], "Unknown option for update: --yes"),
        ] {
            assert_eq!(parse_args(&args).unwrap_err(), want, "{args:?}");
        }
        assert!(matches!(parse_args(&["update", "--help"]), Ok(Action::Help)));
        assert!(matches!(parse_args(&["update", "-h"]), Ok(Action::Help)));
        assert!(USAGE.contains("rts update [--check | --force]"));
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

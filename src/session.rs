//! One sandboxed opencode session: preflight, orphan sweep, VM lifecycle,
//! isolated opencode launch, plugin handshake, host RSS ceiling, and a
//! teardown (export /out, then remove the VM) that runs exactly once.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::config::{OperatorConfig, PLACEHOLDER_API_KEY, ProviderConfig};
use crate::copy::CopyLimits;
use crate::mvm::{MvmSandbox, RunOutput, Runner, SpawnRunner, StateDir, list_machines, run_captured, tail};
use crate::protocol::{new_nonce, random_hex};
use crate::sandbox::{CopyOutResult, CreateSpec, Exec, ExecOptions, Sandbox, sv};
use crate::sys;
use crate::terminal::Terminal;

pub const OPENCODE_VERSION: &str = "2.1.4";

/// Runs a command on the host. A trait so tests can stand in for
/// `opencode --version`, `ps` and `pgrep`.
pub trait Host: Send + Sync {
    fn run(&self, argv: &[String], timeout: Duration) -> io::Result<RunOutput>;
}

pub struct RealHost;

impl Host for RealHost {
    fn run(&self, argv: &[String], timeout: Duration) -> io::Result<RunOutput> {
        let (prog, args) = argv.split_first().ok_or_else(|| io::Error::other("empty argv"))?;
        let mut cmd = Command::new(prog);
        cmd.args(args);
        run_captured(cmd, timeout)
    }
}

// --- opencode config ---

pub fn opencode_config(plugin_dir: &Path, plugin_options: &Value, p: &ProviderConfig) -> Value {
    let models: serde_json::Map<String, Value> = p.models.iter().map(|m| {
        let model = if p.id == "nearai-red-embedded" {
            // Invalid route values must fail closed rather than silently use a
            // different backend or model. Embedded startup validates these IDs.
            let route = crate::inference::route_header(m).unwrap_or_else(|_| "invalid".into());
            json!({ "name": m, "tool_call": true, "headers": { "x-ironwire-route": route } })
        } else {
            json!({ "name": m, "tool_call": true })
        };
        (m.clone(), model)
    }).collect();
    let api_key = match &p.api_key_env {
        Some(k) => format!("{{env:{k}}}"),
        None => PLACEHOLDER_API_KEY.to_string(),
    };
    json!({
        "$schema": "https://opencode.ai/config.json",
        // v1 tuple form; v2.1.4 normalizes it to { package, options } (core/src/config/normalize.ts).
        "plugin": [[plugin_dir.to_string_lossy(), plugin_options]],
        "provider": {
            &p.id: {
                "npm": "@ai-sdk/openai-compatible",
                "name": p.id,
                "options": { "baseURL": p.base_url, "apiKey": api_key },
                "models": models,
            }
        },
        "model": format!("{}/{}", p.id, p.models[0]),
        // A provider policy (deny every other provider) behind the plugin's model transform.
        "enabled_providers": [p.id],
        "share": "disabled",
    })
}

pub fn write_opencode_config(dir: &Path, plugin_dir: &Path, plugin_options: &Value, p: &ProviderConfig) -> Result<PathBuf, String> {
    // v2.1.4 skips a plugin configured as a file path with only a warning.
    if !plugin_dir.is_dir() {
        return Err(format!("plugin path must be a directory: {}", plugin_dir.display()));
    }
    fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let file = dir.join("opencode.json");
    let text = serde_json::to_string_pretty(&opencode_config(plugin_dir, plugin_options, p)).unwrap() + "\n";
    write_private(&file, text.as_bytes()).map_err(|e| format!("writing {}: {e}", file.display()))?;
    Ok(file)
}

fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new().create(true).truncate(true).write(true).mode(0o600).open(path)?.write_all(data)
}

// --- session layout ---

#[derive(Debug, Clone)]
pub struct SessionPaths {
    pub id: String,
    pub machine: String,
    /// Runtime state lives under the system temp dir, outside the
    /// operator's home and this repo: opencode walks up from its cwd loading
    /// opencode.json, .opencode/, .claude/ and .agents/ from every ancestor.
    pub runtime: PathBuf,
    pub home: PathBuf,
    pub xdg_config: PathBuf,
    pub xdg_data: PathBuf,
    pub xdg_cache: PathBuf,
    pub xdg_state: PathBuf,
    pub config_dir: PathBuf,
    pub work: PathBuf,
    pub ready_file: PathBuf,
    pub empty_git_config: PathBuf,
    /// Shared with every `rts tool` process: exec lock and unavailable marker.
    pub state_dir: PathBuf,
    /// Kept results: sessions/<id>/out and sessions/<id>/tools.jsonl.
    pub session_dir: PathBuf,
    pub out_dir: PathBuf,
    pub audit_file: PathBuf,
    pub log_file: PathBuf,
}

pub fn session_paths(id: &str, sessions_dir: &Path, runtime: &Path) -> SessionPaths {
    let xdg = runtime.join("xdg");
    let session_dir = sessions_dir.join(id);
    SessionPaths {
        id: id.into(),
        machine: format!("rts-{id}"),
        runtime: runtime.into(),
        home: runtime.join("home"),
        config_dir: xdg.join("config/opencode"),
        xdg_config: xdg.join("config"),
        xdg_data: xdg.join("data"),
        xdg_cache: xdg.join("cache"),
        xdg_state: xdg.join("state"),
        work: runtime.join("work"),
        ready_file: runtime.join("ready"),
        empty_git_config: runtime.join("empty.gitconfig"),
        state_dir: runtime.join("state"),
        out_dir: session_dir.join("out"),
        audit_file: session_dir.join("tools.jsonl"),
        log_file: session_dir.join("launcher.log"),
        session_dir,
    }
}

pub fn prepare_session_dirs(p: &SessionPaths) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    for d in [&p.home, &p.xdg_config, &p.xdg_data, &p.xdg_cache, &p.xdg_state, &p.config_dir, &p.work, &p.state_dir, &p.session_dir] {
        fs::DirBuilder::new().recursive(true).mode(0o700).create(d)?;
    }
    fs::write(&p.empty_git_config, "")
}

pub struct Launch {
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: PathBuf,
}

pub fn opencode_launch(p: &SessionPaths, opencode: &str, base_env: impl IntoIterator<Item = (String, String)>) -> Launch {
    opencode_launch_with_key(p, opencode, base_env, None)
}

pub fn opencode_launch_with_key(p: &SessionPaths, opencode: &str, base_env: impl IntoIterator<Item = (String, String)>, direct_key: Option<&str>) -> Launch {
    let mut env: Vec<(String, String)> = base_env
        .into_iter()
        // Only terminal/runtime essentials and the explicitly selected direct
        // provider key pass to OpenCode. Host credentials stay on the host.
        .filter(|(k, _)| matches!(k.as_str(), "PATH" | "TERM" | "COLORTERM" | "LANG" | "TMPDIR" | "USER" | "LOGNAME" | "SHELL" | "DISPLAY" | "WAYLAND_DISPLAY" | "NO_COLOR") || k.starts_with("LC_") || direct_key == Some(k.as_str()))
        .collect();
    for (k, v) in [
        ("HOME", &p.home),
        ("XDG_CONFIG_HOME", &p.xdg_config),
        ("XDG_DATA_HOME", &p.xdg_data),
        ("XDG_CACHE_HOME", &p.xdg_cache),
        ("XDG_STATE_HOME", &p.xdg_state),
    ] {
        env.push((k.into(), v.to_string_lossy().into_owned()));
    }
    Launch { argv: sv(&[opencode, "--standalone"]), env, cwd: p.work.clone() }
}

// --- preflight ---

const ANCESTOR_CONFIG: [&str; 5] = ["opencode.json", "opencode.jsonc", ".opencode", ".claude", ".agents"];

pub fn ancestor_config(dir: &Path) -> Vec<PathBuf> {
    let start = std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf());
    start.ancestors().flat_map(|d| ANCESTOR_CONFIG.iter().map(move |n| d.join(n))).filter(|p| p.symlink_metadata().is_ok()).collect()
}

fn version_in(text: &str) -> Option<&str> {
    text.split_whitespace().map(|w| w.trim_start_matches('v')).find(|w| w.starts_with(|c: char| c.is_ascii_digit()) && w.matches('.').count() >= 2)
}

/// A plain HTTP/1.1 GET on loopback. Returns the status and body text.
pub fn http_get(host: &str, port: u16, path: &str, timeout: Duration) -> io::Result<(u16, String)> {
    let addr = (host, port).to_socket_addrs()?.next().ok_or_else(|| io::Error::other("no address"))?;
    let mut s = TcpStream::connect_timeout(&addr, timeout)?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    write!(s, "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nAccept: application/json\r\nConnection: close\r\n\r\n")?;
    let mut buf = vec![];
    s.take(4 * 1024 * 1024).read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text.split_whitespace().nth(1).and_then(|c| c.parse().ok()).ok_or_else(|| io::Error::other("not an HTTP response"))?;
    let body = text.split_once("\r\n\r\n").map_or(String::new(), |(_, b)| b.to_string());
    Ok((status, body))
}

/// For a loopback provider (IronWire), check it answers and offers every
/// configured model, so a session never starts against a dead endpoint.
pub fn check_provider(p: &ProviderConfig) -> Result<(), String> {
    let Some((host, port, base)) = p.loopback() else { return Ok(()) };
    let url = format!("http://{host}:{port}{base}/models");
    let (status, body) = http_get(&host, port, &format!("{base}/models"), Duration::from_secs(5))
        .map_err(|e| format!("inference endpoint {url} is not answering ({e}). Start IronWire (`ironwire serve`) or fix provider.baseURL"))?;
    if status != 200 {
        return Err(format!("inference endpoint {url} answered HTTP {status}. Check `ironwire status`"));
    }
    let missing: Vec<&str> = p.models.iter().map(String::as_str).filter(|m| !body.contains(&format!("\"{m}\""))).collect();
    if !missing.is_empty() {
        return Err(format!(
            "inference endpoint {url} does not offer {}. Check that IronWire's NEAR AI backend has a key (`ironwire status`)",
            missing.join(", ")
        ));
    }
    Ok(())
}

pub struct PreflightInput<'a> {
    pub host: &'a dyn Host,
    pub run: &'a dyn Runner,
    pub opencode: &'a str,
    pub leak_seam_set: bool,
    pub work_dir: Option<&'a Path>,
    pub provider: &'a ProviderConfig,
}

pub fn preflight(o: &PreflightInput) -> Result<(), String> {
    if o.leak_seam_set {
        return Err("RTS_TEST_LEAK is set; refusing to start a real session".into());
    }
    let r = o
        .host
        .run(&sv(&[o.opencode, "--version"]), Duration::from_secs(30))
        .map_err(|e| format!("opencode {OPENCODE_VERSION} required, but {} --version failed: {e}", o.opencode))?;
    if r.code != Some(0) {
        return Err(format!("opencode {OPENCODE_VERSION} required, but {} --version failed: {}", o.opencode, tail(&r.stderr)));
    }
    let out = String::from_utf8_lossy(&r.stdout);
    let found = version_in(&out).unwrap_or(if out.trim().is_empty() { "nothing" } else { out.trim() });
    if found != OPENCODE_VERSION {
        return Err(format!("opencode {OPENCODE_VERSION} required, found {found}"));
    }
    let doctor = o.run.run(&sv(&["doctor"]), Duration::from_secs(60)).map_err(|e| format!("mvmctl doctor failed: {e}"))?;
    if doctor.code != Some(0) {
        let t = tail(&doctor.stderr);
        return Err(format!("mvmctl doctor failed: {}", if t.is_empty() { format!("exit {:?}", doctor.code) } else { t }));
    }
    if let Some(w) = o.work_dir {
        let found = ancestor_config(w);
        if !found.is_empty() {
            return Err(format!("opencode would load config from an ancestor of its working directory: {}", join_paths(&found)));
        }
    }
    check_provider(o.provider)
}

fn join_paths(p: &[PathBuf]) -> String {
    p.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
}

/// A machine-name prefix is not proof that its session has died. Until the
/// harness records verifiable ownership/liveness, preserve every discovered
/// machine rather than deleting another launcher's active guest.
pub fn sweep_orphans(run: &Arc<dyn Runner>, log: &mut dyn FnMut(&str)) -> Result<Vec<String>, String> {
    let names = list_machines(run.as_ref()).map_err(|e| e.to_string())?;
    for name in &names {
        log(&format!("preserving machine {name}: session ownership and liveness are unverified; inspect it before manual cleanup"));
    }
    Ok(vec![])
}

// --- handshake ---

/// Wait until the ready file holds `nonce`. `gone` reports whether the
/// process that should write it has exited.
pub fn wait_for_ready(file: &Path, nonce: &str, deadline: Duration, poll: Duration, gone: &mut dyn FnMut() -> bool) -> Result<(), String> {
    let end = Instant::now() + deadline;
    loop {
        let last = fs::read_to_string(file).ok();
        if last.as_deref() == Some(nonce) {
            return Ok(());
        }
        if gone() {
            return Err("opencode exited before the plugin reported ready".into());
        }
        if Instant::now() >= end {
            return Err(match last {
                None => "plugin did not report ready".into(),
                Some(_) => "plugin did not report ready (ready file holds a different nonce)".into(),
            });
        }
        thread::sleep(poll.min(end.saturating_duration_since(Instant::now())));
    }
}

// --- host RSS ceiling (GHSA-x85r-49ww-2pxq) ---

/// mvm v0.22.0 writes this PID file; inspect has no PID and the supervisor
/// receives its VM identity over stdin, so its argv cannot identify the VM.
fn supervisor_pid_file(name: &str, env: &[(String, String)]) -> Result<PathBuf, String> {
    let get = |key: &str| env.iter().find(|(k, v)| k == key && !v.is_empty()).map(|(_, v)| PathBuf::from(v));
    let root = get("MVM_HOME").or_else(|| get("HOME").map(|h| h.join(".mvm")))
        .ok_or_else(|| "cannot monitor HVF supervisor: neither HOME nor MVM_HOME is set".to_string())?;
    Ok(root.join("vms").join(name).join("hvf.pid"))
}

struct Supervisor {
    pid: u32,
    pid_file: PathBuf,
}

impl Supervisor {
    fn discover(name: &str, env: &[(String, String)]) -> Result<Self, String> {
        let pid_file = supervisor_pid_file(name, env)?;
        let pid = fs::read_to_string(&pid_file).ok().and_then(|s| s.trim().parse::<u32>().ok())
            .filter(|&pid| pid > 0 && pid <= i32::MAX as u32)
            .ok_or_else(|| format!("cannot monitor HVF supervisor: missing or invalid PID in {}", pid_file.display()))?;
        Ok(Self { pid, pid_file })
    }

    fn sample(&self, host: &dyn Host, ceiling_mib: u64) -> Result<u64, String> {
        let current = fs::read_to_string(&self.pid_file).ok().and_then(|s| s.trim().parse::<u32>().ok());
        if current != Some(self.pid) {
            return Err("cannot monitor HVF supervisor: PID file changed or disappeared".into());
        }
        let rss = host_rss_mib(host, self.pid).ok_or_else(|| format!("cannot monitor HVF supervisor: PID {} is gone, has the wrong executable, or has no RSS sample", self.pid))?;
        if rss > ceiling_mib {
            return Err(format!("host RSS {rss} MiB over the {ceiling_mib} MiB ceiling (pid {} via {})", self.pid, self.pid_file.display()));
        }
        Ok(rss)
    }
}

pub fn host_rss_mib(host: &dyn Host, pid: u32) -> Option<u64> {
    let command = host.run(&sv(&["ps", "-o", "comm=", "-p", &pid.to_string()]), Duration::from_secs(5)).ok()?;
    let executable = String::from_utf8_lossy(&command.stdout);
    if command.code != Some(0) || Path::new(executable.trim()).file_name()?.to_str()? != "mvm-hvf-supervisor" {
        return None;
    }
    let r = host.run(&sv(&["ps", "-o", "rss=", "-p", &pid.to_string()]), Duration::from_secs(5)).ok()?;
    let kib: u64 = String::from_utf8_lossy(&r.stdout).trim().parse().ok()?;
    (r.code == Some(0) && kib > 0).then_some(kib.div_ceil(1024))
}

// --- the session ---

pub struct Deps {
    pub host: Arc<dyn Host>,
    /// None: mvmctl from the config, with the operator's HOME.
    pub runner: Option<Arc<dyn Runner>>,
    pub env: Vec<(String, String)>,
    /// The `rts` binary the plugin shim spawns for each tool call.
    pub rts: PathBuf,
}

impl Deps {
    pub fn real() -> Result<Self, String> {
        Ok(Self {
            host: Arc::new(RealHost),
            runner: None,
            env: std::env::vars().collect(),
            rts: std::env::current_exe().map_err(|e| format!("cannot locate the rts binary: {e}"))?,
        })
    }
}

struct Logger {
    id: String,
    file: PathBuf,
}

impl Logger {
    fn log(&self, m: &str) {
        eprintln!("[rts {}] {m}", self.id);
        let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&self.file) {
            let _ = writeln!(f, "{secs} {m}");
        }
    }
}

struct Live<'a> {
    log: &'a Logger,
    sb: &'a MvmSandbox,
    paths: &'a SessionPaths,
    machine_attempted: bool,
    machine_created: bool,
    child: Option<Child>,
}

impl Live<'_> {
    fn teardown(&mut self, why: &str) {
        self.log.log(&format!("teardown: {why}"));
        if let Some(mut c) = self.child.take() {
            // Terminal::spawn gives OpenCode its own session and process group.
            // Stop descendants too, even if the group leader already exited.
            sys::send_signal(-(c.id() as i32), sys::SIGTERM);
            let end = Instant::now() + Duration::from_secs(10);
            while c.try_wait().ok().flatten().is_none() && Instant::now() < end {
                thread::sleep(Duration::from_millis(100));
            }
            sys::send_signal(-(c.id() as i32), sys::SIGKILL);
            let _ = c.wait();
            self.log.log("teardown: opencode stopped");
        }
        if !self.machine_attempted {
            return;
        }
        let state = StateDir(self.paths.state_dir.clone());
        let quiesced = state.quiesce(Duration::from_secs(10));
        if let Err(e) = &quiesced {
            self.log.log(&format!("teardown: EXPORT SKIPPED: cannot quiesce tools: {e}"));
        }
        if self.machine_created && quiesced.is_ok() {
            // copyOut runs on the launcher's own handle, which is not yet marked removed.
            match self.sb.copy_out("/out", &self.paths.out_dir) {
                Ok(CopyOutResult::Exported { files, bytes }) => {
                    self.log.log(&format!("teardown: exported {files} files, {bytes} bytes to {}", self.paths.out_dir.display()))
                }
                Ok(CopyOutResult::NothingToExport) => self.log.log("teardown: nothing to export"),
                Err(e) => self.log.log(&format!("teardown: EXPORT FAILED: {e}")),
            }
        }
        match self.sb.remove() {
            Ok(()) => self.log.log(&format!("teardown: removed {}", self.paths.machine)),
            Err(e) => self.log.log(&format!("teardown: MACHINE REMOVAL FAILED: {e}")),
        }
    }
}

/// Run one session. Returns opencode's exit code, or 1 when the session
/// was refused or failed.
pub fn run_session(cfg: &OperatorConfig, deps: Deps) -> i32 {
    let id = random_hex(6);
    let runtime = std::env::temp_dir().join(format!("rts-{id}-{}", random_hex(4)));
    let p = session_paths(&id, &cfg.sessions_dir, &runtime);
    let log = Logger { id: id.clone(), file: p.log_file.clone() };
    if let Err(e) = prepare_session_dirs(&p) {
        log.log(&format!("cannot create session directories: {e}"));
        return 1;
    }
    log.log(&format!("session {id}: results in {}, runtime in {}", p.session_dir.display(), p.runtime.display()));

    let operator_home = deps.env.iter().find(|(k, _)| k == "HOME").map(|(_, v)| v.clone()).unwrap_or_default();
    let run: Arc<dyn Runner> = deps.runner.clone().unwrap_or_else(|| {
        Arc::new(SpawnRunner {
            mvmctl: cfg.mvmctl.clone(),
            empty_git_config: p.empty_git_config.clone(),
            extra_env: [("HOME".to_string(), operator_home.clone())].into(),
        })
    });
    // The launcher's handle does not share the state dir's marker: teardown
    // marks every tool process's view unavailable first, then still exports.
    let sb = match MvmSandbox::new(&p.machine, Box::new(run.clone())) {
        Ok(sb) => sb.with_copy_limits(CopyLimits::default()),
        Err(e) => {
            log.log(&e.to_string());
            return 1;
        }
    };
    sys::catch_termination_signals();
    let mut live = Live { log: &log, sb: &sb, paths: &p, machine_attempted: false, machine_created: false, child: None };
    let code = match session_body(cfg, &deps, &run, &operator_home, &mut live) {
        Ok(code) => code,
        Err(e) => {
            log.log(&e);
            1
        }
    };
    // Refuse later tool calls; teardown waits for the active exec lock before export.
    StateDir(p.state_dir.clone()).mark("session ended");
    live.teardown("session ended");
    code
}

fn interrupted(log: &Logger) -> Option<String> {
    sys::take_signal().map(|s| {
        let name = if s == sys::SIGINT { "SIGINT" } else { "SIGTERM" };
        log.log(&format!("received {name}"));
        format!("interrupted by {name}")
    })
}

fn session_body(cfg: &OperatorConfig, deps: &Deps, run: &Arc<dyn Runner>, operator_home: &str, live: &mut Live) -> Result<i32, String> {
    let p = live.paths;
    let leak_seam_set = deps.env.iter().any(|(k, _)| k == "RTS_TEST_LEAK");
    preflight(&PreflightInput {
        host: deps.host.as_ref(),
        run: run.as_ref(),
        opencode: &cfg.opencode,
        leak_seam_set,
        work_dir: Some(&p.work),
        provider: &cfg.provider,
    })?;
    sweep_orphans(run, &mut |m| live.log.log(m))?;
    if let Some(why) = interrupted(live.log) {
        return Err(why);
    }

    live.machine_attempted = true;
    // A signal during create only sets a flag: create finishes, then teardown removes it.
    live.sb
        .create(&CreateSpec { name: &p.machine, image: &cfg.image, memory_mib: cfg.limits.memory_mib, cpus: cfg.limits.cpus })
        .map_err(|e| e.to_string())?;
    live.machine_created = true;
    live.log.log(&format!("created {}", p.machine));
    let mk = live.sb.exec(&sv(&["mkdir", "-p", "/in", "/out"]), &ExecOptions::new(30_000, 4096)).map_err(|e| e.to_string())?;
    if mk.exit_code != 0 {
        return Err("could not create /in and /out in the guest".into());
    }
    if let Some(inputs) = &cfg.inputs_dir {
        live.sb.copy_in(inputs, "/in").map_err(|e| e.to_string())?;
        live.log.log(&format!("copied {} to /in", inputs.display()));
    }
    if let Some(why) = interrupted(live.log) {
        return Err(format!("{why} before opencode started"));
    }

    let supervisor = Supervisor::discover(&p.machine, &deps.env)?;
    supervisor.sample(deps.host.as_ref(), cfg.limits.host_rss_ceiling_mib)?;
    live.log.log(&format!("sampling host RSS of pid {} (found via {})", supervisor.pid, supervisor.pid_file.display()));

    let nonce = new_nonce();
    let plugin_options = json!({
        "machine": p.machine,
        "nonce": nonce,
        "readyFile": p.ready_file,
        "auditFile": p.audit_file,
        "provider": cfg.provider.id,
        "rts": deps.rts,
        "bridge": {
            "machine": p.machine,
            "mvmctl": cfg.mvmctl,
            "emptyGitConfig": p.empty_git_config,
            "stateDir": p.state_dir,
            "timeoutMs": cfg.limits.tool_timeout_ms,
            "maxOutputBytes": cfg.limits.max_output_bytes,
            "mvmHome": operator_home,
        },
    });
    write_opencode_config(&p.config_dir, &cfg.plugin_dir, &plugin_options, &cfg.provider)?;
    // opencode loads opencode.json, AGENTS.md and .opencode/ from its cwd.
    if fs::read_dir(&p.work).map_err(|e| e.to_string())?.next().is_some() {
        return Err(format!("work directory is not empty: {}", p.work.display()));
    }
    let found = ancestor_config(&p.work);
    if !found.is_empty() {
        return Err(format!("opencode would load config from: {}", join_paths(&found)));
    }
    let launch = opencode_launch_with_key(p, &cfg.opencode, deps.env.iter().cloned(), cfg.provider.api_key_env.as_deref());
    let mut command = Command::new(&launch.argv[0]);
    command
        .args(&launch.argv[1..])
        .current_dir(&launch.cwd)
        .env_clear()
        .envs(launch.env.iter().map(|(k, v)| (k, v)));
    let (child, mut terminal) = Terminal::spawn(&mut command)
        .map_err(|e| format!("starting {} failed: {e}", cfg.opencode))?;
    let child = live.child.insert(child);

    let mut signalled = None;
    let mut transport_error = None;
    wait_for_ready(&p.ready_file, &nonce, Duration::from_millis(cfg.limits.handshake_ms), Duration::from_millis(10), &mut || {
        // Output is visible during startup, but Terminal has no input path
        // until the exact nonce has authenticated the plugin.
        if transport_error.is_none() {
            transport_error = terminal.pump().err().map(|e| format!("terminal relay failed: {e}"));
        }
        if signalled.is_none() {
            signalled = interrupted(live.log);
        }
        transport_error.is_some() || signalled.is_some() || child.try_wait().ok().flatten().is_some()
    })
    .map_err(|e| transport_error.or(signalled).unwrap_or_else(|| format!("refusing the session: {e}")))?;
    terminal.enable_input().map_err(|e| format!("enabling terminal input failed: {e}"))?;
    live.log.log("plugin ready; session running");

    let mut next_sample = Instant::now();
    loop {
        terminal.pump().map_err(|e| format!("terminal relay failed: {e}"))?;
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            return Ok(status.code().unwrap_or(1));
        }
        if let Some(why) = interrupted(live.log) {
            return Err(why);
        }
        if Instant::now() >= next_sample {
            next_sample = Instant::now() + Duration::from_secs(5);
            supervisor.sample(deps.host.as_ref(), cfg.limits.host_rss_ceiling_mib)?;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Defaults, parse_config};
    use crate::testutil::tempdir;
    use std::net::TcpListener;
    use std::sync::Mutex;

    fn provider() -> ProviderConfig {
        ProviderConfig { id: "ironwire".into(), base_url: "http://127.0.0.1:8463/openai/v1".into(), models: vec!["z-ai/glm-5.3-flash".into()], api_key_env: None }
    }

    fn out(code: i32, stdout: &str, stderr: &str) -> RunOutput {
        RunOutput { code: Some(code), stdout: stdout.into(), stderr: stderr.into(), killed: false }
    }

    type Script = Box<dyn Fn(&[String]) -> RunOutput + Send + Sync>;
    struct Fake {
        calls: Mutex<Vec<String>>,
        reply: Script,
    }
    impl Fake {
        fn new(reply: impl Fn(&[String]) -> RunOutput + Send + Sync + 'static) -> Arc<Self> {
            Arc::new(Self { calls: Mutex::new(vec![]), reply: Box::new(reply) })
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }
    impl Host for Fake {
        fn run(&self, argv: &[String], _: Duration) -> io::Result<RunOutput> {
            self.calls.lock().unwrap().push(argv.join(" "));
            Ok((self.reply)(argv))
        }
    }
    impl Runner for Fake {
        fn run(&self, argv: &[String], _: Duration) -> io::Result<RunOutput> {
            self.calls.lock().unwrap().push(argv.join(" "));
            Ok((self.reply)(argv))
        }
    }

    #[test]
    fn the_generated_config_loads_the_plugin_directory_with_its_options() {
        let c = opencode_config(Path::new("/repo/plugin"), &json!({ "nonce": "n" }), &provider());
        assert_eq!(c["plugin"], json!([["/repo/plugin", { "nonce": "n" }]]));
        assert_eq!(c["model"], "ironwire/z-ai/glm-5.3-flash");
        assert_eq!(c["enabled_providers"], json!(["ironwire"]));
        assert_eq!(c["provider"]["ironwire"]["options"]["baseURL"], "http://127.0.0.1:8463/openai/v1");
        assert!(c.get("mcp").is_none());
    }

    #[test]
    fn the_api_key_is_a_placeholder_for_ironwire_and_an_env_reference_otherwise() {
        let c = opencode_config(Path::new("/p"), &json!({}), &provider());
        assert_eq!(c["provider"]["ironwire"]["options"]["apiKey"], PLACEHOLDER_API_KEY);
        let direct = ProviderConfig { id: "nearai".into(), base_url: "https://cloud-api.near.ai/v1".into(), api_key_env: Some("NEARAI_API_KEY".into()), ..provider() };
        let c = opencode_config(Path::new("/p"), &json!({}), &direct);
        assert_eq!(c["provider"]["nearai"]["options"]["apiKey"], "{env:NEARAI_API_KEY}");
    }

    #[test]
    fn the_plugin_path_must_be_a_directory() {
        let d = tempdir("sess");
        fs::write(d.join("index.ts"), "").unwrap();
        let e = write_opencode_config(&d.join("cfg"), &d.join("index.ts"), &json!({}), &provider()).unwrap_err();
        assert!(e.contains("must be a directory"));
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn opencode_runs_with_home_and_all_four_xdg_dirs_in_the_session_an_empty_cwd_and_standalone() {
        let p = session_paths("0123456789ab", Path::new("/s"), Path::new("/tmp/rts-x"));
        let env = [("HOME", "/Users/op"), ("XDG_CONFIG_HOME", "/Users/op/.config"), ("OPENCODE_CONFIG", "/evil"), ("RTS_TEST_LEAK", "shell"), ("PATH", "/bin")];
        let l = opencode_launch(&p, "opencode", env.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        assert_eq!(l.argv, sv(&["opencode", "--standalone"]));
        assert_eq!(l.cwd, PathBuf::from("/tmp/rts-x/work"));
        let get = |k: &str| l.env.iter().filter(|(n, _)| n == k).map(|(_, v)| v.as_str()).collect::<Vec<_>>();
        assert_eq!(get("HOME"), ["/tmp/rts-x/home"]);
        assert_eq!(get("XDG_CONFIG_HOME"), ["/tmp/rts-x/xdg/config"]);
        assert_eq!(get("XDG_DATA_HOME"), ["/tmp/rts-x/xdg/data"]);
        assert_eq!(get("XDG_CACHE_HOME"), ["/tmp/rts-x/xdg/cache"]);
        assert_eq!(get("XDG_STATE_HOME"), ["/tmp/rts-x/xdg/state"]);
        assert!(get("OPENCODE_CONFIG").is_empty() && get("RTS_TEST_LEAK").is_empty());
        assert_eq!(get("PATH"), ["/bin"]);
        assert_eq!(p.machine, "rts-0123456789ab");
        assert_eq!(p.audit_file, PathBuf::from("/s/0123456789ab/tools.jsonl"));
    }

    fn healthy(argv: &[String]) -> RunOutput {
        if argv.last().map(String::as_str) == Some("--version") { out(0, "2.1.4\n", "") } else { out(0, "", "") }
    }

    /// A one-shot HTTP server on loopback answering with `response`.
    fn serve(response: &'static str) -> ProviderConfig {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut s, _)) = l.accept() {
                // Read the whole request first: closing with unread bytes sends a reset.
                let (mut req, mut buf) = (vec![], [0u8; 1024]);
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => req.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = s.write_all(response.as_bytes());
                let _ = s.shutdown(std::net::Shutdown::Write);
            }
        });
        ProviderConfig { base_url: format!("http://127.0.0.1:{port}/openai/v1"), ..provider() }
    }

    fn pre(f: &Arc<Fake>, leak: bool, work: Option<&Path>, provider: &ProviderConfig) -> Result<(), String> {
        preflight(&PreflightInput { host: f.as_ref(), run: f.as_ref(), opencode: "opencode", leak_seam_set: leak, work_dir: work, provider })
    }

    const MODELS_OK: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"object\":\"list\",\"data\":[{\"id\":\"z-ai/glm-5.3-flash\"}]}";

    #[test]
    fn preflight_requires_opencode_2_1_4() {
        let f = Fake::new(|a| if a.last().map(String::as_str) == Some("--version") { out(0, "opencode 2.2.0\n", "") } else { out(0, "", "") });
        assert!(pre(&f, false, None, &serve(MODELS_OK)).unwrap_err().contains("required, found 2.2.0"));
    }

    #[test]
    fn preflight_refuses_when_mvmctl_doctor_fails() {
        let f = Fake::new(|a| if a[0] == "doctor" { out(1, "", "hvf unavailable") } else { healthy(a) });
        assert!(pre(&f, false, None, &serve(MODELS_OK)).unwrap_err().contains("mvmctl doctor failed: hvf unavailable"));
    }

    #[test]
    fn preflight_refuses_when_the_leak_seam_is_set() {
        let f = Fake::new(healthy);
        assert!(pre(&f, true, None, &provider()).unwrap_err().contains("RTS_TEST_LEAK"));
        assert!(f.calls().is_empty());
    }

    #[test]
    fn preflight_refuses_when_an_ancestor_of_the_work_dir_holds_opencode_config() {
        let d = tempdir("sess");
        fs::create_dir_all(d.join("a/b/work")).unwrap();
        fs::write(d.join("a/opencode.json"), "{}").unwrap();
        let f = Fake::new(healthy);
        let e = pre(&f, false, Some(&d.join("a/b/work")), &serve(MODELS_OK)).unwrap_err();
        assert!(e.contains("a/opencode.json"), "{e}");
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn preflight_passes_when_ironwire_offers_the_model() {
        pre(&Fake::new(healthy), false, None, &serve(MODELS_OK)).unwrap();
    }

    #[test]
    fn preflight_refuses_when_ironwire_is_down_or_lacks_the_model() {
        // Nothing listens on port 1; a freed ephemeral port could be reused by a parallel test.
        let dead = ProviderConfig { base_url: "http://127.0.0.1:1/openai/v1".into(), ..provider() };
        assert!(pre(&Fake::new(healthy), false, None, &dead).unwrap_err().contains("ironwire serve"));
        let other = serve("HTTP/1.1 200 OK\r\n\r\n{\"data\":[{\"id\":\"some/other-model\"}]}");
        assert!(pre(&Fake::new(healthy), false, None, &other).unwrap_err().contains("does not offer z-ai/glm-5.3-flash"));
        let err = serve("HTTP/1.1 503 Service Unavailable\r\n\r\n");
        assert!(pre(&Fake::new(healthy), false, None, &err).unwrap_err().contains("HTTP 503"));
    }

    #[test]
    fn the_orphan_sweep_preserves_machines_with_unverified_ownership_and_liveness() {
        let f = Fake::new(|a| match a.join(" ").as_str() {
            "machine ps" => out(0, "rts-0123456789ab\nkeepme\nrts-xyz\n", ""),
            _ => out(0, "", ""),
        });
        let run: Arc<dyn Runner> = f.clone();
        let mut messages = vec![];
        let removed = sweep_orphans(&run, &mut |m| messages.push(m.to_string())).unwrap();
        assert!(removed.is_empty());
        assert!(!f.calls().iter().any(|c| c.starts_with("machine rm")), "an active session could own this VM");
        assert!(messages.iter().any(|m| m.contains("rts-0123456789ab") && m.contains("unverified")));
    }

    #[test]
    fn the_handshake_needs_the_exact_nonce_in_time() {
        let d = tempdir("sess");
        let f = d.join("ready");
        let ms = Duration::from_millis;
        assert_eq!(wait_for_ready(&f, "abc", ms(150), ms(20), &mut || false).unwrap_err(), "plugin did not report ready");
        fs::write(&f, "other").unwrap();
        assert!(wait_for_ready(&f, "abc", ms(150), ms(20), &mut || false).unwrap_err().contains("different nonce"));
        assert!(wait_for_ready(&f, "abc", ms(5000), ms(20), &mut || true).unwrap_err().contains("exited before"));
        let f2 = f.clone();
        let t = thread::spawn(move || {
            thread::sleep(ms(100));
            fs::write(f2, "abc").unwrap();
        });
        wait_for_ready(&f, "abc", ms(5000), ms(20), &mut || false).unwrap();
        t.join().unwrap();
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn rss_sampling_refuses_a_pid_that_is_not_the_hvf_supervisor() {
        let f = Fake::new(|a| match a.get(2).map(String::as_str) {
            Some("comm=") => out(0, "/usr/bin/unrelated\n", ""),
            Some("rss=") => out(0, "102400\n", ""),
            _ => out(1, "", "unexpected ps invocation"),
        });
        assert_eq!(host_rss_mib(f.as_ref(), 42), None);
    }

    #[test]
    fn rss_monitor_uses_the_vm_pid_file_and_refuses_lost_or_over_limit_samples() {
        let d = tempdir("rss-monitor");
        let pid_file = d.join("vms/rts-0123456789ab/hvf.pid");
        fs::create_dir_all(pid_file.parent().unwrap()).unwrap();
        fs::write(&pid_file, "42\n").unwrap();
        let env = vec![("MVM_HOME".into(), d.to_string_lossy().into_owned()), ("HOME".into(), "/unused".into())];
        let supervisor = Supervisor::discover("rts-0123456789ab", &env).unwrap();
        let healthy = Fake::new(|a| match a.get(2).map(String::as_str) {
            Some("comm=") => out(0, "/opt/mvm/mvm-hvf-supervisor\n", ""),
            Some("rss=") => out(0, "102401\n", ""),
            _ => out(1, "", "unexpected ps invocation"),
        });
        assert_eq!(supervisor.sample(healthy.as_ref(), 101).unwrap(), 101);
        assert!(supervisor.sample(healthy.as_ref(), 100).unwrap_err().contains("over the 100 MiB ceiling"));
        let unreadable = Fake::new(|_| out(1, "", "process exited"));
        assert!(supervisor.sample(unreadable.as_ref(), 101).is_err());
        fs::write(&pid_file, "43\n").unwrap();
        assert!(supervisor.sample(healthy.as_ref(), 101).unwrap_err().contains("PID file changed"));
        fs::remove_file(&pid_file).unwrap();
        assert!(supervisor.sample(healthy.as_ref(), 101).is_err());
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn teardown_waits_for_an_inflight_tool_before_export() {
        use std::sync::mpsc;
        let d = tempdir("quiesce");
        let p = session_paths("0123456789ab", &d.join("sessions"), &d.join("runtime"));
        prepare_session_dirs(&p).unwrap();
        let lock = OpenOptions::new().create(true).truncate(false).write(true).open(p.state_dir.join("exec.lock")).unwrap();
        lock.lock().unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (export_tx, export_rx) = mpsc::channel();
        let f = Fake::new(move |a| {
            if a.get(1).map(String::as_str) == Some("exec") {
                export_tx.send(()).unwrap();
                out(0, "NONE\n", &format!("\nRTS_EXIT_{} 0 5 0\n", a[8]))
            } else { out(0, "", "") }
        });
        let worker = thread::spawn(move || {
            let log = Logger { id: p.id.clone(), file: p.log_file.clone() };
            let sb = MvmSandbox::new(&p.machine, Box::new(f)).unwrap();
            let mut live = Live { log: &log, sb: &sb, paths: &p, machine_attempted: true, machine_created: true, child: None };
            started_tx.send(()).unwrap();
            live.teardown("test");
        });
        started_rx.recv().unwrap();
        let exported_while_locked = export_rx.recv_timeout(Duration::from_millis(150)).is_ok();
        drop(lock);
        worker.join().unwrap();
        fs::remove_dir_all(d).unwrap();
        assert!(!exported_while_locked, "export ran before the active tool released the exec lock");
    }


    fn session_cfg(sessions: &Path, plugin: &Path, provider: ProviderConfig) -> OperatorConfig {
        let mut c = parse_config(r#"{ "provider": { "models": ["z-ai/glm-5.3-flash"] } }"#, Path::new("/"), &Defaults { repo: "/repo".into(), mvmctl: "/x/mvmctl".into() }).unwrap();
        c.sessions_dir = sessions.into();
        c.plugin_dir = plugin.into();
        c.provider = provider;
        c
    }

    #[test]
    fn a_session_refuses_before_any_vm_exists_when_opencode_is_the_wrong_version() {
        let d = tempdir("sess");
        let f = Fake::new(|a| if a.last().map(String::as_str) == Some("--version") { out(0, "1.0.0", "") } else { out(0, "", "") });
        let deps = Deps { host: f.clone(), runner: Some(f.clone()), env: vec![], rts: "/x/rts".into() };
        assert_eq!(run_session(&session_cfg(&d, &d, serve(MODELS_OK)), deps), 1);
        assert!(!f.calls().iter().any(|c| c.starts_with("machine")), "{:?}", f.calls());
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn a_session_refuses_before_opencode_when_supervisor_cannot_be_monitored() {
        let d = tempdir("rss-fail-closed");
        let sessions = d.join("sessions");
        let f = Fake::new(|a| match a.get(1).map(String::as_str) {
            Some("exec") => out(0, "", &format!("\nRTS_EXIT_{} 0 0 0\n", a[8])),
            _ => healthy(a),
        });
        let deps = Deps {
            host: f.clone(), runner: Some(f.clone()),
            env: vec![("MVM_HOME".into(), d.join("mvm").to_string_lossy().into_owned())],
            rts: "/x/rts".into(),
        };
        let mut cfg = session_cfg(&sessions, &d, serve(MODELS_OK));
        cfg.opencode = "/nonexistent-opencode-rss-test".into();
        assert_eq!(run_session(&cfg, deps), 1);
        let session = fs::read_dir(&sessions).unwrap().next().unwrap().unwrap().path();
        let log = fs::read_to_string(session.join("launcher.log")).unwrap();
        fs::remove_dir_all(d).unwrap();
        assert!(log.contains("cannot monitor HVF supervisor"), "{log}");
        assert!(!log.contains("starting /nonexistent"), "opencode was started without RSS protection");
    }

    #[test]
    fn a_session_removes_the_machine_when_create_fails_and_never_starts_opencode() {
        let d = tempdir("sess");
        let f = Fake::new(|a| match a.join(" ") {
            s if s.starts_with("machine create") => out(1, "", "image pull failed"),
            _ => healthy(a),
        });
        let deps = Deps { host: f.clone(), runner: Some(f.clone()), env: vec![], rts: "/x/rts".into() };
        assert_eq!(run_session(&session_cfg(&d, &d, serve(MODELS_OK)), deps), 1);
        let calls = f.calls();
        assert!(calls.iter().any(|c| c.starts_with("machine rm rts-") && c.ends_with(" --force --yes")), "{calls:?}");
        assert!(!calls.iter().any(|c| c.starts_with("machine exec")), "{calls:?}");
        let session = fs::read_dir(&d).unwrap().next().unwrap().unwrap().path();
        let log = fs::read_to_string(session.join("launcher.log")).unwrap();
        assert!(log.contains("image pull failed") && log.contains("teardown: removed"), "{log}");
        fs::remove_dir_all(d).unwrap();
    }
}

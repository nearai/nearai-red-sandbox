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

use crate::config::{EMBEDDED_PROVIDER_ID, OperatorConfig, PLACEHOLDER_API_KEY, ProviderConfig, model_display_name};
use crate::copy::CopyLimits;
use crate::mvm::{MvmSandbox, RunOutput, Runner, SpawnRunner, StateDir, list_machines, run_captured, tail};
use crate::protocol::{new_nonce, random_hex};
use crate::sandbox::{CopyOutResult, CreateSpec, Exec, ExecOptions, Sandbox, sv};
use crate::sys;
use crate::terminal::Terminal;
use crate::brand::progress::Live as Shown;

pub const OPENCODE_VERSION: &str = "2.2.2";
pub const PRODUCT_NAME: &str = "NEAR AI Red";
pub const TERMINAL_TITLE: &str = "NEAR AI Red SandBox";
/// The terminal UI plugin directory inside the plugin shim.
pub const BRANDING_PLUGIN: &str = "branding";

const INIT_GUEST_STORAGE: &str = r#"set -eu
tmp=$1; input=$2; output=$3
refuse() { echo 'unexpected guest input/output layout' >&2; exit 1; }
[ -d "$tmp" ] && [ ! -L "$tmp" ] || refuse
[ -L "$input" ] && [ "$(readlink "$input")" = "$tmp/rts/in" ] || refuse
[ -L "$output" ] && [ "$(readlink "$output")" = "$tmp/rts/out" ] || refuse
for dir in "$tmp/rts" "$tmp/rts/in" "$tmp/rts/out"; do
  [ ! -L "$dir" ] || refuse
  if [ -e "$dir" ]; then [ -d "$dir" ] || refuse; fi
done
for dir in "$tmp/rts" "$tmp/rts/in" "$tmp/rts/out"; do
  if [ ! -d "$dir" ]; then mkdir -- "$dir"; fi
  [ -d "$dir" ] && [ ! -L "$dir" ] || refuse
done"#;

/// Prepare the writable input and output directories of a newly created guest.
/// The image root is read-only and its exact links point into per-VM /tmp.
/// Refuse other layouts before creating anything or copying operator inputs.
pub fn initialize_guest_storage(sb: &dyn Exec) -> Result<(), String> {
    let mk = sb.exec(&crate::files::script(INIT_GUEST_STORAGE, &["/tmp", "/in", "/out"]), &ExecOptions::new(30_000, 4096)).map_err(|e| e.to_string())?;
    if mk.exit_code != 0 {
        return Err(format!("could not initialize guest input/output storage: {}", String::from_utf8_lossy(&mk.stderr).trim()));
    }
    Ok(())
}

/// Install only launcher-generated files into a new private guest directory.
/// mkdir (without -p) refuses a preexisting namespace before writing any token.
pub fn install_canary_files(sb: &dyn Exec, registry: &crate::canary::Registry) -> Result<(), String> {
    let manifest = registry.manifest_path();
    let dir = manifest.rsplit_once('/').ok_or("invalid canary manifest path")?.0;
    let result = sb.exec(&crate::files::script("mkdir -m 700 -- \"$1\"", &[dir]), &ExecOptions::new(30_000, 4096))
        .map_err(|e| e.to_string())?;
    if result.exit_code != 0 {
        return Err("could not create fresh managed guest canary directory".into());
    }
    for (path, data) in registry.guest_files() {
        crate::files::guest_write(sb, &path, &data).map_err(|_| "could not install managed guest canary files".to_string())?;
    }
    Ok(())
}

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

/// `embedded` is `OperatorConfig::embedded_inference`: only rts's own,
/// attested NEAR AI inference is shown as NEAR AI Red.
pub fn opencode_config(plugin_dir: &Path, plugin_options: &Value, p: &ProviderConfig, embedded: bool) -> Value {
    // Match the bundled proxy's admission policy, not OpenCode's generic
    // 200k fallback or a model catalog's larger advertised window.
    let context = ironwire_upstream::openai_chat::nearai_capabilities().context_tokens;
    let models: serde_json::Map<String, Value> = p.models.iter().map(|m| {
        let mut model = if p.id == EMBEDDED_PROVIDER_ID {
            // Invalid route values must fail closed rather than silently use a
            // different backend or model. Embedded startup validates these IDs.
            let route = crate::inference::route_header(m).unwrap_or_else(|_| "invalid".into());
            json!({ "name": model_display_name(m), "tool_call": true, "headers": { "x-ironwire-route": route } })
        } else {
            json!({ "name": model_display_name(m), "tool_call": true })
        };
        if embedded {
            // OpenCode prefers input to context when deciding to compact.
            model["limit"] = json!({ "context": context, "input": context, "output": 16_384 });
        }
        (m.clone(), model)
    }).collect();
    let api_key = match &p.api_key_env {
        Some(k) => format!("{{env:{k}}}"),
        None => PLACEHOLDER_API_KEY.to_string(),
    };
    let mut config = json!({
        "$schema": "https://opencode.ai/config.json",
        // v1 tuple form; v2.2.2 normalizes it to { package, options } (core/src/config/normalize.ts).
        "plugin": [[plugin_dir.to_string_lossy(), plugin_options]],
        "provider": {
            &p.id: {
                "npm": "@ai-sdk/openai-compatible",
                // An external provider keeps its own ID as its name.
                "name": if embedded { PRODUCT_NAME } else { p.id.as_str() },
                "options": { "baseURL": p.base_url, "apiKey": api_key },
                "models": models,
            }
        },
        "model": format!("{}/{}", p.id, p.models[0]),
        // A provider policy (deny every other provider) behind the plugin's model transform.
        "enabled_providers": [p.id],
        "share": "disabled",
        // opencode is pinned by rts setup; never check for or offer updates.
        "autoupdate": false,
    });
    if embedded {
        // OpenCode 2.2.2 compacts at input - buffer. Reserve one reply plus
        // headroom for tool results and the proxy's byte-based token estimate.
        config["compaction"] = json!({ "auto": true, "buffer": 32_768 });
    }
    config
}

pub fn write_opencode_config(dir: &Path, plugin_dir: &Path, plugin_options: &Value, p: &ProviderConfig, embedded: bool) -> Result<PathBuf, String> {
    // v2.2.2 skips a plugin configured as a file path with only a warning.
    if !plugin_dir.is_dir() {
        return Err(format!("plugin path must be a directory: {}", plugin_dir.display()));
    }
    fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    // Embed the context in rts so installed releases need no additional asset.
    // Reuse the bridge's effective network mode instead of inferring it from
    // the host's connectivity (inference works even in an offline guest).
    let network = if plugin_options["bridge"]["proxy"].as_bool() == Some(true) {
        "Network access is enabled only for the operator's launch-time allowlist. \
         Shell calls supply HTTP_PROXY, HTTPS_PROXY and ALL_PROXY for the guest proxy. \
         Use proxy-aware clients; direct outbound connections are blocked. \
         Destinations cannot be added from inside this session. If a required \
         destination is blocked, ask the operator to relaunch with the appropriate --allow-host entry."
    } else {
        "Network access is disabled for this session. Downloads, package registries, \
         and remote targets are unreachable from guest tools. If the task requires \
         them, ask the operator to relaunch with an appropriate --allow-host entry \
         or supply the necessary files as inputs."
    };
    let mut context = format!("{}\n## Session network policy\n\n{network}\n", include_str!("sandbox-context.md"));
    if let Some(manifest) = plugin_options["canaryManifest"].as_str() {
        context.push_str(&format!(
            "\n## Synthetic canaries\n\nThe operator enabled managed canaries. Read the value-free manifest at {manifest} for IDs, placements and paths. \
             Host canary contents stay outside the guest; guest decoys are synthetic, not real credentials. \
             Tool-result notices report exact token matches in returned text and redact their values. \
             Investigate why submitted code collected a decoy; an intentional control read also triggers a notice. \
             Notices do not prove external exfiltration. No match is not proof of no access: suppressed, encoded, partial or truncated contents are not covered. \
             Export scanning runs after the agent exits; the operator reviews canaries.jsonl and canary-summary.json.\n"
        ));
    }
    let instructions = dir.join("sandbox-context.md");
    write_private(&instructions, context.as_bytes()).map_err(|e| format!("writing {}: {e}", instructions.display()))?;
    let instructions = fs::canonicalize(&instructions).map_err(|e| format!("resolving {}: {e}", instructions.display()))?;
    let mut config = opencode_config(plugin_dir, plugin_options, p, embedded);
    // An absolute path is required: OpenCode's empty cwd is separate from
    // this private config directory. These instructions augment its prompt.
    config["instructions"] = json!([instructions]);
    let file = dir.join("opencode.json");
    let text = serde_json::to_string_pretty(&config).unwrap() + "\n";
    write_private(&file, text.as_bytes()).map_err(|e| format!("writing {}: {e}", file.display()))?;
    Ok(file)
}

/// opencode's terminal UI reads its own config, `cli.json` beside
/// opencode.json; the server's `plugin` list does not load TUI plugins.
/// The TUI plugin draws the home footer and optionally submits the launcher's
/// initial task. It never installs tools, MCP servers, or model transforms.
pub fn tui_config(plugin_dir: &Path, model_display: &str, attested: bool) -> Value {
    json!({
        // rts sets the window title; opencode would overwrite it on every route change.
        "terminal": { "title": false },
        "theme": { "name": crate::brand::theme::THEME_NAME },
        "plugins": [{
            "package": plugin_dir.join(BRANDING_PLUGIN).to_string_lossy(),
            "options": { "model": model_display, "attested": attested },
        }],
    })
}

pub fn write_tui_config(dir: &Path, plugin_dir: &Path, model_display: &str, attested: bool) -> Result<PathBuf, String> {
    write_tui_config_with_prompt(dir, plugin_dir, model_display, attested, None)
}

pub fn check_tui_plugin(plugin_dir: &Path) -> Result<(), String> {
    // v2.2.2 marks a directory without a tui entry "unsupported" and says so
    // only in /plugins, so refuse a broken install here instead.
    let branding = plugin_dir.join(BRANDING_PLUGIN);
    let missing: Vec<&str> = ["tui.tsx", "footer.ts", "startup.ts"].into_iter().filter(|f| !branding.join(f).is_file()).collect();
    if !missing.is_empty() {
        return Err(format!(
            "branding plugin {} is missing {}; reinstall rts or fix pluginDir",
            branding.display(),
            missing.join(" and ")
        ));
    }
    Ok(())
}

fn write_tui_config_with_prompt(dir: &Path, plugin_dir: &Path, model_display: &str, attested: bool, prompt_file: Option<&Path>) -> Result<PathBuf, String> {
    check_tui_plugin(plugin_dir)?;
    fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let file = dir.join("cli.json");
    let mut config = tui_config(plugin_dir, model_display, attested);
    if let Some(path) = prompt_file {
        config["plugins"][0]["options"]["initialPromptFile"] = json!(path);
    }
    let text = serde_json::to_string_pretty(&config).unwrap() + "\n";
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
    /// The attached `machine run`'s stdout and stderr (0600, never shown).
    pub attach_log: PathBuf,
    /// `{"network": ...}`: the allowlist, its resolution and the probes.
    pub session_record: PathBuf,
    /// This VM's entries from mvm's signed audit log, copied at teardown.
    pub network_audit: PathBuf,
    /// OpenCode's preserved data store (`session_dir/opencode`).
    pub opencode_data: PathBuf,
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
        attach_log: session_dir.join("mvm-attach.log"),
        session_record: session_dir.join("session.json"),
        network_audit: session_dir.join("network.jsonl"),
        opencode_data: session_dir.join("opencode"),
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

/// Publish a complete private payload atomically. The TUI can begin reading as
/// soon as this rename happens; it must never observe partial JSON.
fn publish_initial_prompt(file: &Path, text: &str, provider: &ProviderConfig) -> Result<(), String> {
    let payload = json!({ "text": text, "providerID": provider.id, "modelID": provider.models[0] });
    let pending = file.with_extension("pending");
    write_private(&pending, serde_json::to_string(&payload).unwrap().as_bytes())
        .map_err(|e| format!("cannot prepare initial prompt: {e}"))?;
    fs::rename(&pending, file).map_err(|e| format!("cannot publish initial prompt: {e}"))
}

fn initial_prompt_ack(file: &Path) -> Result<Option<String>, String> {
    let bytes = match fs::read(file) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read initial prompt acknowledgement: {e}")),
    };
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| "invalid initial prompt acknowledgement")?;
    if value["status"] == "error" {
        // Never echo arbitrary plugin/provider error text into launcher.log.
        return Err("OpenCode could not submit the initial prompt".into());
    }
    let id = value["sessionID"].as_str().filter(|s| !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'));
    match (value["status"].as_str(), id) {
        (Some("submitted"), Some(id)) => Ok(Some(id.into())),
        _ => Err("invalid initial prompt acknowledgement".into()),
    }
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

pub const SUPERVISOR_FIX_VERSION: &str = "rts-vsock-drain-v1";
pub const SUPERVISOR_PROBE: &str = "--rts-vsock-drain-fix-version";
pub const SUPERVISOR_CONTRACT_PROBE: &str = "--contract-version";
pub const SUPERVISOR_CONTRACT: &str = "mvm-hvf-supervisor contract-version=4";
const SUPERVISOR_INSTALL: &str = "Run rts setup; from a source checkout, run scripts/build-patched-mvm-supervisor.sh to install the patched mvm v0.22.0 supervisor in ~/.local/share/nearai-red-sandbox/mvm-hvf-supervisor, or set MVM_HVF_SUPERVISOR_PATH to its absolute path";

/// Resolve only the supplied operator environment and install prefix, never
/// ambient process state. An explicit override must be usable; an empty
/// override cannot fall back. Then the installed supervisor, then HOME's.
pub fn supervisor_path(env: &[(String, String)], prefix: Option<&Path>) -> Result<PathBuf, String> {
    let get = |key: &str| env.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());
    let path = if let Some(path) = get("MVM_HVF_SUPERVISOR_PATH") {
        PathBuf::from(path)
    } else if let Some(installed) = prefix.map(crate::install::prefix_supervisor).filter(|p| p.is_file()) {
        installed
    } else {
        let home = get("HOME").filter(|v| !v.is_empty())
            .ok_or_else(|| format!("Cannot locate patched HVF supervisor without HOME. {SUPERVISOR_INSTALL}"))?;
        crate::install::home_supervisor(Path::new(home))
    };
    if !path.is_absolute() {
        return Err(format!("MVM_HVF_SUPERVISOR_PATH and HOME must select an absolute supervisor path. {SUPERVISOR_INSTALL}"));
    }
    Ok(path)
}

/// Use the exact probed supervisor for doctor and every VM lifecycle command.
pub fn mvm_environment(env: &[(String, String)], supervisor: &Path) -> std::collections::HashMap<String, String> {
    let mut result: std::collections::HashMap<String, String> = env.iter()
        .filter(|(key, _)| matches!(key.as_str(), "HOME" | "MVM_HOME"))
        .cloned().collect();
    result.insert("MVM_HVF_SUPERVISOR_PATH".into(), supervisor.to_string_lossy().into_owned());
    result
}

pub struct PreflightInput<'a> {
    pub host: &'a dyn Host,
    pub run: &'a dyn Runner,
    /// Named in the error when `run` cannot find mvmctl.
    pub mvmctl: &'a Path,
    pub opencode: &'a str,
    pub leak_seam_set: bool,
    pub supervisor_path: Option<&'a Path>,
    pub work_dir: Option<&'a Path>,
    pub provider: &'a ProviderConfig,
}

pub fn preflight(o: &PreflightInput) -> Result<(), String> {
    if o.leak_seam_set {
        return Err("RTS_TEST_LEAK is set; refusing to start a real session".into());
    }
    check_opencode(o.host, o.opencode)?;
    let supervisor = o.supervisor_path.filter(|p| p.is_absolute() && p.to_str().is_some())
        .ok_or_else(|| format!("An absolute patched HVF supervisor path is required ({SUPERVISOR_FIX_VERSION}). {SUPERVISOR_INSTALL}"))?;
    check_supervisor_marker(o.host, supervisor)?;
    let doctor = o.run.run(&sv(&["doctor"]), Duration::from_secs(60)).map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            format!("mvmctl not found at {}; run rts setup", o.mvmctl.display())
        } else {
            format!("mvmctl doctor failed: {e}")
        }
    })?;
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

/// `stdout` is exactly `expected`, optionally followed by one newline.
fn exact_line(stdout: &[u8], expected: &str) -> bool {
    stdout == expected.as_bytes() || stdout == format!("{expected}\n").as_bytes()
}

/// The supervisor at `path` prints exactly SUPERVISOR_FIX_VERSION for
/// SUPERVISOR_PROBE within 5 s and exits 0.
pub fn check_supervisor_marker(host: &dyn Host, path: &Path) -> Result<(), String> {
    let probe = host.run(&[path.to_string_lossy().into_owned(), SUPERVISOR_PROBE.into()], Duration::from_secs(5))
        .map_err(|_| format!("Cannot verify patched HVF supervisor ({SUPERVISOR_FIX_VERSION}). {SUPERVISOR_INSTALL}"))?;
    if probe.killed || probe.code != Some(0) || !exact_line(&probe.stdout, SUPERVISOR_FIX_VERSION) {
        return Err(format!("HVF supervisor must report {SUPERVISOR_FIX_VERSION}; its copy-out fix could not be verified. {SUPERVISOR_INSTALL}"));
    }
    Ok(())
}

/// The supervisor at `path` prints exactly SUPERVISOR_CONTRACT for
/// SUPERVISOR_CONTRACT_PROBE within 5 s and exits 0.
pub fn check_supervisor_contract(host: &dyn Host, path: &Path) -> Result<(), String> {
    let probe = host.run(&[path.to_string_lossy().into_owned(), SUPERVISOR_CONTRACT_PROBE.into()], Duration::from_secs(5))
        .map_err(|_| format!("Cannot verify the HVF supervisor contract ({SUPERVISOR_CONTRACT}). {SUPERVISOR_INSTALL}"))?;
    if probe.killed || probe.code != Some(0) || !exact_line(&probe.stdout, SUPERVISOR_CONTRACT) {
        return Err(format!("HVF supervisor must report {SUPERVISOR_CONTRACT}. {SUPERVISOR_INSTALL}"));
    }
    Ok(())
}

/// `opencode --version` must report exactly OPENCODE_VERSION.
pub fn check_opencode(host: &dyn Host, opencode: &str) -> Result<(), String> {
    let r = host
        .run(&sv(&[opencode, "--version"]), Duration::from_secs(30))
        .map_err(|e| format!("opencode {OPENCODE_VERSION} required, but {opencode} --version failed: {e}; run rts setup"))?;
    if r.code != Some(0) {
        return Err(format!("opencode {OPENCODE_VERSION} required, but {opencode} --version failed: {}; run rts setup", tail(&r.stderr)));
    }
    let out = String::from_utf8_lossy(&r.stdout);
    let found = version_in(&out).unwrap_or(if out.trim().is_empty() { "nothing" } else { out.trim() });
    if found != OPENCODE_VERSION {
        return Err(format!("opencode {OPENCODE_VERSION} required, found {found}; run rts setup"));
    }
    Ok(())
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
/// mvm's state root: `MVM_HOME`, or else `HOME/.mvm`. An empty value counts
/// as unset.
pub fn mvm_root(env: &[(String, String)]) -> Result<PathBuf, String> {
    let get = |key: &str| env.iter().find(|(k, v)| k == key && !v.is_empty()).map(|(_, v)| PathBuf::from(v));
    get("MVM_HOME").or_else(|| get("HOME").map(|h| h.join(".mvm")))
        .ok_or_else(|| "neither HOME nor MVM_HOME is set".to_string())
}

fn supervisor_pid_file(name: &str, env: &[(String, String)]) -> Result<PathBuf, String> {
    let root = mvm_root(env).map_err(|e| format!("cannot monitor HVF supervisor: {e}"))?;
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

/// The basename of `pid`'s executable from `ps -o comm=` (macOS prints a
/// full path), or None if `ps` fails or prints nothing.
fn process_name(host: &dyn Host, pid: u32) -> Option<String> {
    let command = host.run(&sv(&["ps", "-o", "comm=", "-p", &pid.to_string()]), Duration::from_secs(5)).ok()?;
    if command.code != Some(0) {
        return None;
    }
    let executable = String::from_utf8_lossy(&command.stdout);
    Some(Path::new(executable.trim()).file_name()?.to_str()?.to_string())
}

pub fn host_rss_mib(host: &dyn Host, pid: u32) -> Option<u64> {
    if process_name(host, pid)? != "mvm-hvf-supervisor" {
        return None;
    }
    let r = host.run(&sv(&["ps", "-o", "rss=", "-p", &pid.to_string()]), Duration::from_secs(5)).ok()?;
    let kib: u64 = String::from_utf8_lossy(&r.stdout).trim().parse().ok()?;
    (r.code == Some(0) && kib > 0).then_some(kib.div_ceil(1024))
}

// --- network processes ---

const ENDPOINT: &str = "mvm-network-endpoint";
const NETWORK_PROCESSES: [&str; 2] = [ENDPOINT, "mvm-hvf-supervisor"];

/// The children of the attached `machine run` (`attach_pid`) that are mvm's
/// network endpoint or HVF supervisor, by `pgrep -P` and `ps -o comm=`.
/// Refuses unless an endpoint is among them: without it the network path
/// cannot be confirmed, or confirmed gone at teardown.
pub fn network_children(host: &dyn Host, attach_pid: u32) -> Result<Vec<u32>, String> {
    let fail = |why: String| format!("cannot find the network processes of mvmctl machine run (pid {attach_pid}): {why}");
    let r = host.run(&sv(&["pgrep", "-P", &attach_pid.to_string()]), Duration::from_secs(5)).map_err(|e| fail(format!("pgrep failed: {e}")))?;
    if r.killed || r.code != Some(0) {
        return Err(fail(format!("pgrep exit {:?}", r.code)));
    }
    let mut kept = vec![];
    let mut endpoint = false;
    for pid in String::from_utf8_lossy(&r.stdout).split_whitespace() {
        let pid: u32 = pid.parse().ok().filter(|&p| p > 0 && p <= i32::MAX as u32).ok_or_else(|| fail(format!("pgrep printed {pid:?}")))?;
        if let Some(name) = process_name(host, pid).filter(|n| NETWORK_PROCESSES.contains(&n.as_str())) {
            endpoint |= name == ENDPOINT;
            kept.push(pid);
        }
    }
    if !endpoint {
        return Err(fail(format!("no {ENDPOINT} among its children")));
    }
    Ok(kept)
}

// --- the session ---

/// The wall clock the session limit is measured with; tests inject one.
pub type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// `Some(stop reason)` once `hours` of wall-clock time have passed since
/// `boot`. A clock that steps back before boot reads as no time passed.
pub fn session_limit(boot: SystemTime, now: SystemTime, hours: u32) -> Option<String> {
    let elapsed = now.duration_since(boot).unwrap_or(Duration::ZERO);
    (elapsed >= Duration::from_secs(u64::from(hours) * 3600)).then(|| format!("session-limit: {hours}h since boot"))
}

pub struct Deps {
    pub host: Arc<dyn Host>,
    /// None: mvmctl from the config, with the operator's HOME.
    pub runner: Option<Arc<dyn Runner>>,
    pub env: Vec<(String, String)>,
    /// Command prefix the plugin shim spawns as `tool_command ++ [<tool>]`.
    pub tool_command: Vec<String>,
    /// Chosen by the caller when it writes into sessions/<id>/ before the
    /// session starts (attestation.json); None picks a fresh one.
    pub session_id: Option<String>,
    /// Raised by the attested forwarder; the session ends when it is set.
    pub fatal: Option<Arc<crate::forwarder::Fatal>>,
    /// Resolves allowlisted names on the host before launch.
    pub resolver: Arc<dyn crate::network::Resolver>,
    /// Measures `limits.sessionHours` from boot. `Deps::real` uses `SystemTime::now`.
    pub clock: Clock,
}

impl Deps {
    pub fn real(session_id: String, fatal: Option<Arc<crate::forwarder::Fatal>>) -> Result<Self, String> {
        Ok(Self {
            host: Arc::new(RealHost),
            runner: None,
            env: std::env::vars().collect(),
            tool_command: vec![
                std::env::current_exe()
                    .map_err(|e| format!("cannot locate the rts binary: {e}"))?
                    .to_string_lossy()
                    .into_owned(),
                "tool".into(),
            ],
            session_id: Some(session_id),
            fatal,
            resolver: Arc::new(crate::network::SystemResolver),
            clock: Arc::new(SystemTime::now),
        })
    }
}

/// The forwarder's fatal reason, once raised.
pub fn stop_reason(fatal: Option<&crate::forwarder::Fatal>) -> Option<String> {
    fatal.and_then(crate::forwarder::Fatal::reason)
}

/// 12 lowercase hex characters from the OS.
pub fn new_session_id() -> String {
    random_hex(6)
}

struct Logger {
    id: String,
    file: PathBuf,
}

impl Logger {
    fn log(&self, m: &str) {
        crate::brand::progress::log_line(&self.id, m);
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
    host: &'a dyn Host,
    machine_attempted: bool,
    machine_created: bool,
    child: Option<Child>,
    /// The attach process's endpoint and supervisor, checked after removal.
    network_pids: Vec<u32>,
    /// mvm's audit directory, read at teardown into `network.jsonl`.
    audit_dir: Option<PathBuf>,
    canaries: Option<crate::canary::Registry>,
    monitoring_failed: bool,
    canary_setup_complete: bool,
}

/// Return true for incomplete coverage or persistence/cleanup failure.
fn finish_canaries(registry: &crate::canary::Registry, paths: &SessionPaths, export_complete: bool, setup_complete: bool, log: &Logger) -> bool {
    let tool_failed = paths.state_dir.join("canary-monitoring-failed").exists();
    let scan = if export_complete {
        if paths.out_dir.exists() { registry.scan_exports(&paths.out_dir) } else { Ok(0) }
    } else {
        Err("export did not complete; canary export scan skipped".into())
    };
    let summary = registry.summary();
    // Values are per-session runtime state, never retained with exported reports.
    // Cleanup status participates in the persisted result, not just the exit code.
    let cleanup_ok = fs::remove_dir_all(paths.runtime.join("canaries")).is_ok();
    if !cleanup_ok { log.log("canaries: FAILED to remove private token runtime directory"); }
    let mut failed = !setup_complete || tool_failed || scan.is_err() || summary.is_err() || !cleanup_ok;
    let text = summary.as_deref().unwrap_or("canary observation summary unavailable");
    let status = if failed { "incomplete" } else { "complete" };
    let record = json!({
        "status": status,
        "setup": if setup_complete { "complete" } else { "incomplete" },
        "tokenCleanup": if cleanup_ok { "complete" } else { "failed" },
        "exportScan": if scan.is_ok() { "complete" } else { "incomplete" },
        "exportObservations": scan.as_ref().ok(),
        "toolMonitoring": if tool_failed { "incomplete" } else { "complete" },
        "summary": text,
        "limits": "Exact token matches only; no match is not proof of no access. Exported files retain their original bytes.",
    });
    if write_private(&paths.session_dir.join("canary-summary.json"), &(record.to_string() + "\n").into_bytes()).is_err() {
        log.log("canaries: FAILED to persist session summary");
        failed = true;
    }
    let status = if failed { "incomplete" } else { "complete" };
    log.log(&format!("canaries: {status}; {text}"));
    if scan.is_err() { log.log("canaries: export scanning incomplete; do not interpret missing events as clean"); }
    failed
}

fn copy_tree_preserving_mode(src: &Path, dst: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let meta = fs::symlink_metadata(src)?;
    if meta.is_dir() {
        let mode = meta.permissions().mode() & 0o777;
        fs::DirBuilder::new().recursive(true).mode(mode).create(dst)?;
        fs::set_permissions(dst, fs::Permissions::from_mode(mode))?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            copy_tree_preserving_mode(&entry.path(), &dst.join(entry.file_name()))?;
        }
    } else if meta.is_file() {
        let mode = meta.permissions().mode() & 0o777;
        fs::copy(src, dst)?;
        fs::set_permissions(dst, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

fn keep_opencode_data(paths: &SessionPaths, log: &Logger) {
    let src = paths.xdg_data.join("opencode");
    let dst = &paths.opencode_data;
    match fs::symlink_metadata(&src) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => {
            log.log("opencode data: unexpected non-directory; not kept");
            return;
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            log.log("opencode data: none to keep");
            return;
        }
        Err(e) => {
            log.log(&format!("opencode data: cannot inspect store: {e}"));
            return;
        }
    }
    if fs::rename(&src, dst).is_ok() {
        log.log("opencode data: kept");
        return;
    }
    match copy_tree_preserving_mode(&src, dst) {
        Ok(()) => {
            let _ = fs::remove_dir_all(&src);
            log.log("opencode data: kept");
        }
        Err(e) => {
            log.log(&format!("opencode data: FAILED to keep store: {e}"));
        }
    }
}

impl Live<'_> {
    fn teardown(&mut self, why: &str) {
        crate::brand::progress::teardown();
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
        keep_opencode_data(self.paths, self.log);
        if !self.machine_attempted {
            return;
        }
        let state = StateDir(self.paths.state_dir.clone());
        let quiesced = state.quiesce(Duration::from_secs(10));
        if let Err(e) = &quiesced {
            self.log.log(&format!("teardown: EXPORT SKIPPED: cannot quiesce tools: {e}"));
        }
        let mut export_complete = false;
        if self.machine_created && quiesced.is_ok() {
            // copyOut runs on the launcher's own handle, which is not yet marked removed.
            match self.sb.copy_out("/out", &self.paths.out_dir) {
                Ok(CopyOutResult::Exported { files, bytes }) => {
                    export_complete = true;
                    self.log.log(&format!("teardown: exported {files} files, {bytes} bytes to {}", self.paths.out_dir.display()))
                }
                Ok(CopyOutResult::NothingToExport) => {
                    export_complete = true;
                    self.log.log("teardown: nothing to export");
                }
                Err(e) => self.log.log(&format!("teardown: EXPORT FAILED: {e}")),
            }
        }
        if let Some(registry) = &self.canaries {
            self.monitoring_failed = finish_canaries(registry, self.paths, export_complete, self.canary_setup_complete, self.log);
        }
        match self.sb.remove() {
            Ok(()) => self.log.log(&format!("teardown: removed {}", self.paths.machine)),
            Err(e) => self.log.log(&format!("teardown: MACHINE REMOVAL FAILED: {e}")),
        }
        // Both run after export and removal, so neither can stop them.
        for &pid in &self.network_pids {
            if let Some(name) = process_name(self.host, pid).filter(|n| NETWORK_PROCESSES.contains(&n.as_str())) {
                self.log.log(&format!("teardown: NETWORK PROCESS REMAINED: pid {pid} ({name}); killed"));
                let _ = self.host.run(&sv(&["kill", "-KILL", &pid.to_string()]), Duration::from_secs(5));
            }
        }
        if let Some(dir) = &self.audit_dir {
            match crate::network::extract_audit(dir, &self.paths.machine, &self.paths.network_audit) {
                Ok(n) => self.log.log(&format!("teardown: copied {n} network audit entries to {}", self.paths.network_audit.display())),
                Err(e) => self.log.log(&format!("teardown: NETWORK AUDIT FAILED: {e}")),
            }
        }
    }
}

/// Run one session. Returns opencode's exit code, or 1 when the session
/// was refused or failed.
pub fn run_session(cfg: &OperatorConfig, deps: Deps) -> i32 {
    run_session_with_prompt(cfg, deps, None)
}

/// Submit operator task text only after the sandbox plugin has authenticated.
/// Prompt text stays out of process arguments and durable session metadata.
pub fn run_session_with_prompt(cfg: &OperatorConfig, deps: Deps, initial_prompt: Option<&str>) -> i32 {
    let id = deps.session_id.clone().unwrap_or_else(new_session_id);
    let runtime = std::env::temp_dir().join(format!("rts-{id}-{}", random_hex(4)));
    let p = session_paths(&id, &cfg.sessions_dir, &runtime);
    let log = Logger { id: id.clone(), file: p.log_file.clone() };
    if let Err(e) = prepare_session_dirs(&p) {
        log.log(&format!("cannot create session directories: {e}"));
        return 1;
    }
    log.log(&format!("session {id}: results in {}, runtime in {}", p.session_dir.display(), p.runtime.display()));

    if deps.tool_command.is_empty() || deps.tool_command[0].is_empty() {
        log.log("tool command must not be empty");
        return 1;
    }
    let install_prefix = deps
        .tool_command
        .first()
        .map(Path::new)
        .and_then(crate::install::install_prefix);
    let supervisor = match supervisor_path(&deps.env, install_prefix.as_deref()) {
        Ok(path) => path,
        Err(error) => {
            log.log(&error);
            return 1;
        }
    };
    let operator_home = deps.env.iter().find(|(k, _)| k == "HOME").map(|(_, v)| v.clone()).unwrap_or_default();
    let run: Arc<dyn Runner> = deps.runner.clone().unwrap_or_else(|| {
        Arc::new(SpawnRunner {
            mvmctl: cfg.mvmctl.clone(),
            empty_git_config: p.empty_git_config.clone(),
            extra_env: mvm_environment(&deps.env, &supervisor),
            remove_env: Vec::new(),
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
    let mut live = Live { log: &log, sb: &sb, paths: &p, host: deps.host.as_ref(), machine_attempted: false, machine_created: false, child: None, network_pids: vec![], audit_dir: None, canaries: None, monitoring_failed: false, canary_setup_complete: false };
    let code = match session_body(cfg, &deps, &run, &operator_home, &supervisor, &mut live, initial_prompt) {
        Ok(code) => code,
        Err(e) => {
            log.log(&e);
            1
        }
    };
    // Refuse later tool calls; teardown waits for the active exec lock before export.
    StateDir(p.state_dir.clone()).mark("session ended");
    live.teardown("session ended");
    if live.monitoring_failed { 1 } else { code }
}

fn interrupted(log: &Logger) -> Option<String> {
    sys::take_signal().map(|s| {
        let name = if s == sys::SIGINT { "SIGINT" } else { "SIGTERM" };
        log.log(&format!("received {name}"));
        format!("interrupted by {name}")
    })
}

fn stopped(deps: &Deps, log: &Logger) -> Option<String> {
    stop_reason(deps.fatal.as_deref()).inspect(|why| log.log(&format!("stopping: {why}")))
}

type Pinned = std::collections::BTreeMap<String, std::collections::BTreeSet<std::net::IpAddr>>;

fn write_session_record(p: &SessionPaths, plan: &crate::network::Plan, probes: &[crate::network::Probe], pinned: &Pinned) -> Result<(), String> {
    let text = serde_json::to_string_pretty(&json!({ "network": plan.record(probes, pinned) })).unwrap() + "\n";
    write_private(&p.session_record, text.as_bytes()).map_err(|e| format!("writing {}: {e}", p.session_record.display()))
}

/// How long to wait for mvm's audit log to show a pin for every name.
const PIN_WAIT: Duration = Duration::from_secs(10);

/// Read this VM's pins from mvm's audit log in `audit_dir` until every name
/// in `plan` has one, or until [`PIN_WAIT`] has passed on `clock`. A plan
/// with no names reads nothing. A missing log counts as no pins yet, and
/// ends the session if it is still missing at the deadline; an unreadable
/// or malformed one ends it at once.
fn wait_for_pins(plan: &crate::network::Plan, audit_dir: &Path, machine: &str, clock: &Clock) -> Result<Pinned, String> {
    let names = plan.pinning_names();
    if names.is_empty() {
        return Ok(Pinned::new());
    }
    let deadline = clock() + PIN_WAIT;
    let log = audit_dir.join("local.jsonl");
    loop {
        let found = log.is_file();
        let pinned = if found {
            crate::network::read_pinned(audit_dir, machine).map_err(|e| format!("network-mismatch: {e}"))?
        } else {
            Pinned::new()
        };
        if names.iter().all(|n| pinned.get(*n).is_some_and(|ips| !ips.is_empty())) {
            return Ok(pinned);
        }
        if clock() >= deadline {
            if !found {
                return Err(format!("network-mismatch: mvm audit log never appeared at {}, so its pinned addresses cannot be checked", log.display()));
            }
            return Ok(pinned);
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// The options opencode passes to the sandbox plugin (plugin/index.ts).
pub fn plugin_options(p: &SessionPaths, cfg: &OperatorConfig, tool_command: &[String], nonce: &str, operator_home: &str) -> Value {
    let mut bridge = json!({
        "machine": p.machine,
        "mvmctl": cfg.mvmctl,
        "emptyGitConfig": p.empty_git_config,
        "stateDir": p.state_dir,
        "timeoutMs": cfg.limits.tool_timeout_ms,
        "maxOutputBytes": cfg.limits.max_output_bytes,
        "mvmHome": operator_home,
    });
    // Only a network session carries the key, so a no-network bridge is unchanged.
    if !cfg.network.is_empty() {
        bridge["proxy"] = json!(true);
    }
    if !cfg.canaries.is_empty() {
        bridge["canaryRegistry"] = json!(p.runtime.join("canaries/registry.json"));
    }
    json!({
        "machine": p.machine,
        "nonce": nonce,
        "readyFile": p.ready_file,
        "auditFile": p.audit_file,
        "provider": cfg.provider.id,
        "models": cfg.provider.models,
        "toolCommand": tool_command,
        "bridge": bridge,
    })
}

fn session_body(cfg: &OperatorConfig, deps: &Deps, run: &Arc<dyn Runner>, operator_home: &str, supervisor: &Path, live: &mut Live, initial_prompt: Option<&str>) -> Result<i32, String> {
    let p = live.paths;
    let leak_seam_set = deps.env.iter().any(|(k, _)| k == "RTS_TEST_LEAK");
    let step = crate::brand::progress::step("host check", Shown::Sweep);
    preflight(&PreflightInput {
        host: deps.host.as_ref(),
        run: run.as_ref(),
        mvmctl: &cfg.mvmctl,
        opencode: &cfg.opencode,
        leak_seam_set,
        supervisor_path: Some(supervisor),
        work_dir: Some(&p.work),
        provider: &cfg.provider,
    })?;
    // Every launch, with or without an allowlist, before any machine command.
    let root = mvm_root(&deps.env)?;
    crate::network::check_mvm_host(&deps.env, &root)?;
    step.ok("opencode, mvm, supervisor and provider");
    let step = crate::brand::progress::step("allowlist", Shown::Sweep);
    let plan = crate::network::plan(&cfg.network, deps.resolver.as_ref())?;
    write_session_record(p, &plan, &[], &Pinned::new())?;
    step.ok(&plan.allowlist_line());
    sweep_orphans(run, &mut |m| live.log.log(m))?;
    if let Some(why) = interrupted(live.log).or_else(|| stopped(deps, live.log)) {
        return Err(why);
    }

    live.machine_attempted = true;
    live.audit_dir = Some(root.join("audit"));
    let hosts = plan.allow_hosts();
    let egress = (!plan.is_empty()).then(|| crate::sandbox::Egress { allow_hosts: &hosts, attach_log: &p.attach_log, session_hours: cfg.limits.session_hours });
    // Read before create, so this limit ends no later than the attach `--ttl`.
    let boot = (deps.clock)();
    let limit = || session_limit(boot, (deps.clock)(), cfg.limits.session_hours);
    let step = crate::brand::progress::step("microVM", Shown::Decode(p.machine.clone()));
    // A signal during create only sets a flag: create finishes, then teardown removes it.
    live.sb
        .create(&CreateSpec { name: &p.machine, image: &cfg.image, memory_mib: cfg.limits.memory_mib, cpus: cfg.limits.cpus, egress })
        .map_err(|e| e.to_string())?;
    live.machine_created = true;
    live.log.log(&format!("created {}", p.machine));
    if !plan.is_empty() {
        let attach = live.sb.attach_pid().ok_or("network machine has no attached mvmctl machine run")?;
        live.network_pids = network_children(live.host, attach)?;
    }
    step.ok(&format!("{} · {} MiB · {} vCPU · {}", p.machine, cfg.limits.memory_mib, cfg.limits.cpus, plan.net_label()));
    let step = crate::brand::progress::step("probes", Shown::Sweep);
    let probes = crate::network::run_probes(live.sb, &plan)?;
    step.ok(&crate::network::probes_line(&plan, &probes));
    // mvm resolved each name again when its endpoint started. Its audit log
    // shows those pins only once the guest has used a name, which the probes
    // just did, so the check runs here: before anything else runs in the guest.
    // An empty plan has no egress to pin, and no status line for it.
    let pin_line = plan.pinned_line();
    let step = pin_line.as_ref().map(|_| crate::brand::progress::step("pinned IPs", Shown::Sweep));
    let pinned = wait_for_pins(&plan, &root.join("audit"), &p.machine, &deps.clock)?;
    write_session_record(p, &plan, &probes, &pinned)?;
    crate::network::check_pinned(&plan, &pinned)?;
    if let (Some(step), Some(line)) = (step, pin_line) {
        step.ok(&line);
    }
    live.log.log(&plan.startup_line());
    initialize_guest_storage(live.sb)?;
    if let Some(inputs) = &cfg.inputs_dir {
        let step = crate::brand::progress::step("copy in", Shown::Sweep);
        live.sb.copy_in(inputs, "/in").map_err(|e| e.to_string())?;
        live.log.log(&format!("copied {} to /in", inputs.display()));
        step.ok(&format!("{} → /in", inputs.display()));
    }
    if !cfg.canaries.is_empty() {
        let registry = match crate::canary::Registry::create(&cfg.canaries, &p.runtime.join("canaries"), &p.session_dir.join("canaries.jsonl")) {
            Ok(registry) => registry,
            Err(error) => {
                // Creation can fail after generating some host-only markers.
                if p.runtime.join("canaries").exists() {
                    fs::remove_dir_all(p.runtime.join("canaries")).map_err(|_| "canary setup failed and private token cleanup failed".to_string())?;
                }
                return Err(error);
            }
        };
        live.canaries = Some(registry);
        let registry = live.canaries.as_ref().expect("just set");
        install_canary_files(live.sb, registry)?;
        live.canary_setup_complete = true;
        live.log.log(&format!("canaries: {} synthetic markers; guest manifest {}", cfg.canaries.len(), registry.manifest_path()));
    }
    if let Some(why) = interrupted(live.log).or_else(|| stopped(deps, live.log)).or_else(|| live.sb.network_lost()).or_else(limit) {
        return Err(format!("{why} before opencode started"));
    }

    let supervisor = Supervisor::discover(&p.machine, &deps.env)?;
    supervisor.sample(deps.host.as_ref(), cfg.limits.host_rss_ceiling_mib)?;
    live.log.log(&format!("sampling host RSS of pid {} (found via {})", supervisor.pid, supervisor.pid_file.display()));

    let nonce = new_nonce();
    let mut plugin_options = plugin_options(p, cfg, &deps.tool_command, &nonce, operator_home);
    if let Some(registry) = &live.canaries {
        plugin_options["canaryManifest"] = json!(registry.manifest_path());
    }
    write_opencode_config(&p.config_dir, &cfg.plugin_dir, &plugin_options, &cfg.provider, cfg.embedded_inference)?;
    // run_connected reaches the session for embedded inference only after
    // attestation verified; an external provider is recorded unattested.
    let prompt_file = p.config_dir.join("initial-prompt.json");
    write_tui_config_with_prompt(&p.config_dir, &cfg.plugin_dir, &model_display_name(&cfg.provider.models[0]), cfg.embedded_inference, initial_prompt.map(|_| prompt_file.as_path()))?;
    crate::brand::theme::install(&cfg.plugin_dir, &p.config_dir)?;
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
    crate::brand::progress::hand_off();
    let (child, mut terminal) = Terminal::spawn(&mut command)
        .map_err(|e| format!("starting {} failed: {e}", cfg.opencode))?;
    terminal.set_title(TERMINAL_TITLE);
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
            signalled = interrupted(live.log).or_else(|| stopped(deps, live.log)).or_else(|| live.sb.network_lost()).or_else(limit);
        }
        transport_error.is_some() || signalled.is_some() || child.try_wait().ok().flatten().is_some()
    })
    .map_err(|e| transport_error.or(signalled).unwrap_or_else(|| format!("refusing the session: {e}")))?;
    if let Some(text) = initial_prompt {
        // Publishing this file is the authorization signal to the TUI plugin.
        // It is deliberately absent until the exact server-plugin nonce passes.
        publish_initial_prompt(&prompt_file, text, &cfg.provider)?;
        let deadline = Instant::now() + Duration::from_millis(cfg.limits.handshake_ms);
        let ack = prompt_file.with_file_name("initial-prompt.json.ack");
        loop {
            terminal.pump().map_err(|e| format!("terminal relay failed: {e}"))?;
            if let Some(why) = interrupted(live.log).or_else(|| stopped(deps, live.log)).or_else(|| live.sb.network_lost()).or_else(limit) {
                return Err(why);
            }
            if let Some(id) = initial_prompt_ack(&ack)? {
                live.log.log(&format!("initial prompt submitted to OpenCode session {id}"));
                break;
            }
            if child.try_wait().map_err(|e| e.to_string())?.is_some() {
                return Err("OpenCode exited before acknowledging the initial prompt".into());
            }
            if Instant::now() >= deadline {
                return Err("OpenCode did not acknowledge the initial prompt before the handshake timeout".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    terminal.enable_input().map_err(|e| format!("enabling terminal input failed: {e}"))?;
    live.log.log("plugin ready; session running");

    let mut next_sample = Instant::now();
    loop {
        terminal.pump().map_err(|e| format!("terminal relay failed: {e}"))?;
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            return Ok(status.code().unwrap_or(1));
        }
        if let Some(why) = interrupted(live.log).or_else(|| stopped(deps, live.log)).or_else(|| live.sb.network_lost()).or_else(limit) {
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

    #[test]
    fn mvm_root_prefers_mvm_home_and_ignores_empty_values() {
        let env = |v: &[(&str, &str)]| v.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect::<Vec<_>>();
        assert_eq!(mvm_root(&env(&[("MVM_HOME", ""), ("HOME", "/h")])).unwrap(), PathBuf::from("/h/.mvm"));
        assert_eq!(mvm_root(&env(&[("MVM_HOME", "/m"), ("HOME", "/h")])).unwrap(), PathBuf::from("/m"));
        assert!(mvm_root(&env(&[])).is_err());
        assert!(mvm_root(&env(&[("MVM_HOME", ""), ("HOME", "")])).is_err());
    }

    #[test]
    fn plugin_options_carry_the_exact_model_allowlist() {
        let mut cfg = parse_config("{}", Path::new("/cfg"), &Defaults { mvmctl: "/m".into(), plugin_dir: "/r/plugin".into(), opencode: "opencode".into(), sessions_dir: "/r/sessions".into() }).unwrap();
        cfg.provider.models = vec!["m-one".into(), "m-two".into()];
        let p = session_paths("0123456789ab", Path::new("/s"), Path::new("/rt"));
        let cmd = sv(&["/x/rts", "tool"]);
        let o = plugin_options(&p, &cfg, &cmd, &"ab".repeat(12), "/home/op");
        assert_eq!(o["models"], serde_json::json!(["m-one", "m-two"]));
        assert_eq!(o["provider"], serde_json::json!(cfg.provider.id));
        assert_eq!(o["bridge"]["machine"], serde_json::json!("rts-0123456789ab"));
        assert_eq!(o["bridge"].get("proxy"), None);
        cfg.network = vec!["a.example".into()];
        let o = plugin_options(&p, &cfg, &cmd, &"ab".repeat(12), "/home/op");
        assert_eq!(o["bridge"].get("proxy"), Some(&serde_json::json!(true)));
    }

    #[test]
    fn plugin_options_carry_the_configured_tool_command() {
        let cfg = parse_config("{}", Path::new("/cfg"), &Defaults { mvmctl: "/m".into(), plugin_dir: "/r/plugin".into(), opencode: "opencode".into(), sessions_dir: "/r/sessions".into() }).unwrap();
        let p = session_paths("0123456789ab", Path::new("/s"), Path::new("/rt"));
        let cmd = sv(&["/x/gateway", "red-team", "tool"]);
        let o = plugin_options(&p, &cfg, &cmd, &"ab".repeat(12), "/home/op");
        assert_eq!(o["toolCommand"], serde_json::json!(["/x/gateway", "red-team", "tool"]));
        assert_eq!(o.get("rts"), None);
    }

    fn provider() -> ProviderConfig {
        ProviderConfig { id: "ironwire".into(), base_url: "http://127.0.0.1:8463/openai/v1".into(), models: vec!["z-ai/glm-5.3-flash".into()], api_key_env: None }
    }

    /// Run the real initialization command against a miniature guest filesystem.
    struct StorageGuest {
        root: tempfile::TempDir,
    }

    impl StorageGuest {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            fs::create_dir(root.path().join("tmp")).unwrap();
            for name in ["in", "out"] {
                std::os::unix::fs::symlink(root.path().join("tmp/rts").join(name), root.path().join(name)).unwrap();
            }
            Self { root }
        }

        fn path(&self, path: &str) -> PathBuf {
            self.root.path().join(path)
        }
    }

    impl Exec for StorageGuest {
        fn exec(&self, argv: &[String], opts: &ExecOptions) -> crate::sandbox::Result<crate::sandbox::ExecResult> {
            let argv = argv.iter().map(|arg| match arg.as_str() {
                "/tmp" | "/in" | "/out" => self.path(&arg[1..]).to_string_lossy().into_owned(),
                _ => arg.clone(),
            }).collect::<Vec<_>>();
            crate::testutil::HostShell::default().exec(&argv, opts)
        }
    }

    #[test]
    fn guest_storage_initializes_dangling_image_links_without_replacing_them() {
        let guest = StorageGuest::new();
        assert!(!guest.path("in").exists());
        initialize_guest_storage(&guest).unwrap();
        for name in ["in", "out"] {
            let target = guest.path(&format!("tmp/rts/{name}"));
            assert_eq!(fs::read_link(guest.path(name)).unwrap(), target);
            assert!(target.is_dir());
            fs::write(guest.path(name).join("probe"), name).unwrap();
            assert_eq!(fs::read_to_string(target.join("probe")).unwrap(), name);
        }
        initialize_guest_storage(&guest).unwrap();
        assert_eq!(fs::read_to_string(guest.path("in/probe")).unwrap(), "in");
    }

    #[test]
    fn guest_storage_refuses_unexpected_image_links_and_plain_directories() {
        for name in ["in", "out"] {
            for redirect in [false, true] {
                let guest = StorageGuest::new();
                fs::create_dir_all(guest.path("tmp/rts/in")).unwrap();
                fs::create_dir_all(guest.path("tmp/rts/out")).unwrap();
                fs::remove_file(guest.path(name)).unwrap();
                if redirect {
                    fs::create_dir(guest.path("unexpected")).unwrap();
                    std::os::unix::fs::symlink(guest.path("unexpected"), guest.path(name)).unwrap();
                } else {
                    fs::create_dir(guest.path(name)).unwrap();
                }
                assert!(initialize_guest_storage(&guest).is_err(), "accepted {name}, redirect={redirect}");
            }
        }
    }

    #[test]
    fn guest_storage_refuses_redirected_or_non_directory_writable_components() {
        for component in ["tmp", "tmp/rts", "tmp/rts/in", "tmp/rts/out"] {
            for redirect in [false, true] {
                let guest = StorageGuest::new();
                let path = guest.path(component);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                if path.is_dir() {
                    fs::remove_dir(&path).unwrap();
                }
                if redirect {
                    fs::create_dir(guest.path("unexpected")).unwrap();
                    std::os::unix::fs::symlink(guest.path("unexpected"), &path).unwrap();
                } else {
                    fs::write(&path, "occupied").unwrap();
                }
                assert!(initialize_guest_storage(&guest).is_err(), "accepted {component}, redirect={redirect}");
                if redirect {
                    assert!(fs::read_dir(guest.path("unexpected")).unwrap().next().is_none(), "wrote through {component}");
                } else {
                    assert_eq!(fs::read_to_string(&path).unwrap(), "occupied");
                }
            }
        }
    }

    fn out(code: i32, stdout: &str, stderr: &str) -> RunOutput {
        RunOutput { code: Some(code), stdout: stdout.into(), stderr: stderr.into(), killed: false }
    }

    type Script = Box<dyn Fn(&[String]) -> RunOutput + Send + Sync>;
    type ExitWhen = Arc<dyn Fn() -> bool + Send + Sync>;
    /// Host and mvmctl in one. Once `machine start` or `attach` has run,
    /// `machine ps` answers from a running flag that they set and
    /// `machine rm` clears; every other command goes to `reply`.
    struct Fake {
        calls: Arc<Mutex<Vec<String>>>,
        reply: Script,
        running: std::sync::atomic::AtomicBool,
        started: std::sync::atomic::AtomicBool,
        /// When the attached `machine run` reports that it has exited.
        exit_when: Mutex<ExitWhen>,
    }
    impl Fake {
        fn new(reply: impl Fn(&[String]) -> RunOutput + Send + Sync + 'static) -> Arc<Self> {
            Arc::new(Self { calls: Arc::new(Mutex::new(vec![])), reply: Box::new(reply), running: Default::default(), started: Default::default(), exit_when: Mutex::new(Arc::new(|| false)) })
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
        fn exit_when(&self, f: impl Fn() -> bool + Send + Sync + 'static) {
            *self.exit_when.lock().unwrap() = Arc::new(f);
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
            use std::sync::atomic::Ordering;
            let line = argv.join(" ");
            self.calls.lock().unwrap().push(line.clone());
            if line.starts_with("machine start ") {
                self.running.store(true, Ordering::SeqCst);
                self.started.store(true, Ordering::SeqCst);
            } else if line.starts_with("machine rm ") {
                self.running.store(false, Ordering::SeqCst);
            } else if line == "machine ps" && self.started.load(Ordering::SeqCst) {
                let running = if self.running.load(Ordering::SeqCst) { "rts-0123456789ab running\n" } else { "" };
                return Ok(out(0, &format!("NAME STATUS\n{running}"), ""));
            }
            Ok((self.reply)(argv))
        }
        fn attach(&self, argv: &[String], _log: &Path) -> io::Result<Box<dyn crate::mvm::Attached>> {
            self.calls.lock().unwrap().push(format!("attach {}", argv.join(" ")));
            self.running.store(true, std::sync::atomic::Ordering::SeqCst);
            self.started.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(Box::new(FakeAttached { calls: self.calls.clone(), exit_when: self.exit_when.lock().unwrap().clone() }))
        }
    }
    /// A held `mvmctl machine run` with pid 4242.
    struct FakeAttached {
        calls: Arc<Mutex<Vec<String>>>,
        exit_when: ExitWhen,
    }
    impl crate::mvm::Attached for FakeAttached {
        fn pid(&self) -> u32 {
            4242
        }
        fn exited(&mut self) -> Option<String> {
            (self.exit_when)().then(|| "exit status: 1".into())
        }
        fn terminate(&mut self, _: Duration) {
            self.calls.lock().unwrap().push("terminate".into());
        }
    }
    /// For sessions with no allowlist: the resolver must never be asked.
    struct NoResolve;
    impl crate::network::Resolver for NoResolve {
        fn resolve(&self, name: &str) -> io::Result<Vec<std::net::IpAddr>> {
            panic!("resolver asked for {name} in a session with no allowlist")
        }
    }
    /// Every name fails to resolve.
    struct NoSuchHost;
    impl crate::network::Resolver for NoSuchHost {
        fn resolve(&self, _: &str) -> io::Result<Vec<std::net::IpAddr>> {
            Err(io::Error::other("nodename nor servname provided"))
        }
    }

    #[test]
    fn the_generated_config_loads_the_plugin_directory_with_its_options() {
        let c = opencode_config(Path::new("/repo/plugin"), &json!({ "nonce": "n" }), &provider(), false);
        assert_eq!(c["plugin"], json!([["/repo/plugin", { "nonce": "n" }]]));
        assert_eq!(c["model"], "ironwire/z-ai/glm-5.3-flash");
        assert_eq!(c["enabled_providers"], json!(["ironwire"]));
        assert_eq!(c["provider"]["ironwire"]["options"]["baseURL"], "http://127.0.0.1:8463/openai/v1");
        assert!(c.get("mcp").is_none());
    }

    #[test]
    fn managed_canary_setup_failure_is_not_complete_coverage() {
        let d = tempdir("canary-setup-failure");
        let p = session_paths("0123456789ab", &d.join("sessions"), &d.join("runtime"));
        prepare_session_dirs(&p).unwrap();
        let specs = [crate::canary::CanarySpec { id: "decoy".into(), placement: crate::canary::Placement::Guest }];
        let registry = crate::canary::Registry::create(&specs, &p.runtime.join("canaries"), &p.session_dir.join("canaries.jsonl")).unwrap();
        let guest = crate::testutil::Recorder::new(|_, _| crate::testutil::reply(1, b"", b"mkdir failed"));
        assert!(install_canary_files(&guest, &registry).is_err());
        let log = Logger { id: p.id.clone(), file: p.log_file.clone() };
        assert!(finish_canaries(&registry, &p, true, false, &log));
        let result: Value = serde_json::from_slice(&fs::read(p.session_dir.join("canary-summary.json")).unwrap()).unwrap();
        assert_eq!(result["status"], "incomplete");
        assert_eq!(result["setup"], "incomplete");
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn managed_canary_cleanup_failure_is_persisted_as_incomplete() {
        let d = tempdir("canary-cleanup-failure");
        let p = session_paths("0123456789ab", &d.join("sessions"), &d.join("runtime"));
        prepare_session_dirs(&p).unwrap();
        let specs = [crate::canary::CanarySpec { id: "host-key".into(), placement: crate::canary::Placement::Host }];
        let registry = crate::canary::Registry::create(&specs, &p.runtime.join("canaries"), &p.session_dir.join("canaries.jsonl")).unwrap();
        fs::rename(p.runtime.join("canaries"), p.runtime.join("saved-canaries")).unwrap();
        fs::write(p.runtime.join("canaries"), "blocks directory cleanup").unwrap();
        let log = Logger { id: p.id.clone(), file: p.log_file.clone() };
        assert!(finish_canaries(&registry, &p, true, true, &log));
        let result: Value = serde_json::from_slice(&fs::read(p.session_dir.join("canary-summary.json")).unwrap()).unwrap();
        assert_eq!(result["status"], "incomplete");
        assert_eq!(result["tokenCleanup"], "failed");
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn managed_canary_summary_write_failure_logs_incomplete() {
        let d = tempdir("canary-summary-failure");
        let p = session_paths("0123456789ab", &d.join("sessions"), &d.join("runtime"));
        prepare_session_dirs(&p).unwrap();
        let specs = [crate::canary::CanarySpec { id: "host-key".into(), placement: crate::canary::Placement::Host }];
        let registry = crate::canary::Registry::create(&specs, &p.runtime.join("canaries"), &p.session_dir.join("canaries.jsonl")).unwrap();
        fs::create_dir(p.session_dir.join("canary-summary.json")).unwrap();
        let log = Logger { id: p.id.clone(), file: p.log_file.clone() };
        assert!(finish_canaries(&registry, &p, true, true, &log));
        let logged = fs::read_to_string(&p.log_file).unwrap();
        assert!(logged.contains("canaries: incomplete;"));
        assert!(!logged.contains("canaries: complete;"));
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn managed_canary_teardown_scans_exports_and_removes_values() {
        let d = tempdir("canary-summary");
        let p = session_paths("0123456789ab", &d.join("sessions"), &d.join("runtime"));
        prepare_session_dirs(&p).unwrap();
        let specs = [crate::canary::CanarySpec { id: "decoy".into(), placement: crate::canary::Placement::Guest }];
        let registry = crate::canary::Registry::create(&specs, &p.runtime.join("canaries"), &p.session_dir.join("canaries.jsonl")).unwrap();
        let (_, token) = registry.guest_files().into_iter().find(|(name, _)| name.ends_with(".token")).unwrap();
        fs::create_dir(&p.out_dir).unwrap();
        fs::write(p.out_dir.join("collected.bin"), &token).unwrap();
        let log = Logger { id: p.id.clone(), file: p.log_file.clone() };
        assert!(!finish_canaries(&registry, &p, true, true, &log));
        let result: Value = serde_json::from_slice(&fs::read(p.session_dir.join("canary-summary.json")).unwrap()).unwrap();
        assert_eq!(result["status"], "complete");
        assert_eq!(result["exportObservations"], 1);
        assert!(!p.runtime.join("canaries").exists());
        assert_eq!(fs::read(p.out_dir.join("collected.bin")).unwrap(), token);
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn managed_canary_teardown_reports_incomplete_monitoring() {
        for tool_failed in [false, true] {
            let d = tempdir("canary-incomplete");
            let p = session_paths("0123456789ab", &d.join("sessions"), &d.join("runtime"));
            prepare_session_dirs(&p).unwrap();
            let specs = [crate::canary::CanarySpec { id: "host-key".into(), placement: crate::canary::Placement::Host }];
            let registry = crate::canary::Registry::create(&specs, &p.runtime.join("canaries"), &p.session_dir.join("canaries.jsonl")).unwrap();
            if tool_failed { fs::write(p.state_dir.join("canary-monitoring-failed"), "failed").unwrap(); }
            let log = Logger { id: p.id.clone(), file: p.log_file.clone() };
            assert!(finish_canaries(&registry, &p, tool_failed, true, &log));
            let result: Value = serde_json::from_slice(&fs::read(p.session_dir.join("canary-summary.json")).unwrap()).unwrap();
            assert_eq!(result["status"], "incomplete");
            assert_eq!(result["exportScan"], if tool_failed { "complete" } else { "incomplete" });
            assert!(!p.runtime.join("canaries").exists());
            fs::remove_dir_all(d).unwrap();
        }
    }

    #[test]
    fn managed_canary_plugin_options_are_opt_in_and_contain_no_values() {
        let d = tempdir("canary-options");
        let p = session_paths("0123456789ab", &d, &d.join("runtime"));
        let mut cfg = session_cfg(&d, &d, provider());
        let cmd = sv(&["/x/rts", "tool"]);
        let disabled = plugin_options(&p, &cfg, &cmd, "nonce", "/host");
        assert!(disabled["bridge"].get("canaryRegistry").is_none());
        cfg.canaries = vec![crate::canary::CanarySpec { id: "decoy".into(), placement: crate::canary::Placement::Guest }];
        let enabled = plugin_options(&p, &cfg, &cmd, "nonce", "/host");
        assert_eq!(enabled["bridge"]["canaryRegistry"], json!(p.runtime.join("canaries/registry.json")));
        assert!(!enabled.to_string().contains("RTS_CANARY_"));
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn managed_canary_context_explains_observations_and_manifest() {
        let d = tempdir("canary-instructions");
        let plugin = d.join("plugin");
        fs::create_dir_all(&plugin).unwrap();
        let opts = json!({ "canaryManifest": "/tmp/rts/canaries-test/manifest.json" });
        let file = write_opencode_config(&d.join("cfg"), &plugin, &opts, &provider(), false).unwrap();
        let config: Value = serde_json::from_str(&fs::read_to_string(file).unwrap()).unwrap();
        let context = fs::read_to_string(config["instructions"][0].as_str().unwrap()).unwrap();
        assert!(context.contains("/tmp/rts/canaries-test/manifest.json"));
        assert!(context.contains("exact token matches"));
        assert!(context.contains("not proof"));
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn written_config_loads_private_sandbox_context_with_the_session_network_mode() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempdir("sess-instructions");
        let plugin = d.join("plugin");
        fs::create_dir_all(&plugin).unwrap();
        for network in [false, true] {
            let dir = d.join(if network { "online" } else { "offline" });
            let file = write_opencode_config(&dir, &plugin, &json!({ "bridge": { "proxy": network } }), &provider(), false).unwrap();
            let config: Value = serde_json::from_str(&fs::read_to_string(file).unwrap()).unwrap();
            let instructions = config["instructions"].as_array().expect("sandbox instructions must be loaded");
            assert_eq!(instructions.len(), 1);
            let path = Path::new(instructions[0].as_str().unwrap());
            assert!(path.is_absolute() && path.starts_with(fs::canonicalize(&dir).unwrap()));
            assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
            let prompt = fs::read_to_string(path).unwrap();
            assert!(prompt.contains("/in") && prompt.contains("/out"));
            assert_eq!(prompt.contains("Network access is disabled for this session."), !network);
            assert_eq!(prompt.contains("Network access is enabled only for the operator's launch-time allowlist."), network);
        }
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn the_api_key_is_a_placeholder_for_ironwire_and_an_env_reference_otherwise() {
        let c = opencode_config(Path::new("/p"), &json!({}), &provider(), false);
        assert_eq!(c["provider"]["ironwire"]["options"]["apiKey"], PLACEHOLDER_API_KEY);
        let direct = ProviderConfig { id: "nearai".into(), base_url: "https://cloud-api.near.ai/v1".into(), api_key_env: Some("NEARAI_API_KEY".into()), ..provider() };
        let c = opencode_config(Path::new("/p"), &json!({}), &direct, false);
        assert_eq!(c["provider"]["nearai"]["options"]["apiKey"], "{env:NEARAI_API_KEY}");
    }

    #[test]
    fn the_embedded_provider_and_its_models_get_display_names_but_keep_their_ids() {
        let embedded = ProviderConfig {
            id: "nearai-red-embedded".into(),
            models: vec!["deepseek-ai/DeepSeek-V4.1-Flash-1017-abliterated".into(), "z-ai/glm-5.3-flash".into()],
            ..provider()
        };
        let c = opencode_config(Path::new("/p"), &json!({}), &embedded, true);
        let p = &c["provider"]["nearai-red-embedded"];
        assert_eq!(p["name"], "NEAR AI Red");
        let deepseek = &p["models"]["deepseek-ai/DeepSeek-V4.1-Flash-1017-abliterated"];
        assert_eq!(deepseek["name"], "DeepSeek V4.1 Flash Abliterated");
        assert_eq!(deepseek["headers"]["x-ironwire-route"], "nearai:deepseek-ai/DeepSeek-V4.1-Flash-1017-abliterated");
        assert_eq!(p["models"]["z-ai/glm-5.3-flash"]["name"], "glm-5.3-flash");
        assert_eq!(c["model"], "nearai-red-embedded/deepseek-ai/DeepSeek-V4.1-Flash-1017-abliterated");
        assert_eq!(c["enabled_providers"], json!(["nearai-red-embedded"]));
        // The name follows embedded inference, not the ID: a config that
        // somehow carried the embedded ID to an external endpoint is not NEAR AI Red.
        let c = opencode_config(Path::new("/p"), &json!({}), &embedded, false);
        assert_eq!(c["provider"]["nearai-red-embedded"]["name"], "nearai-red-embedded");
        // An external provider is not NEAR AI Red; it keeps its own ID as its name.
        let c = opencode_config(Path::new("/p"), &json!({}), &provider(), false);
        assert_eq!(c["provider"]["ironwire"]["name"], "ironwire");
        assert_eq!(c["provider"]["ironwire"]["models"]["z-ai/glm-5.3-flash"]["name"], "glm-5.3-flash");
    }

    #[test]
    fn embedded_context_limits_match_the_proxy_and_compact_before_admission_fails() {
        let p = ProviderConfig { id: EMBEDDED_PROVIDER_ID.into(), ..provider() };
        let c = opencode_config(Path::new("/p"), &json!({}), &p, true);
        let capacity = u64::from(ironwire_upstream::openai_chat::nearai_capabilities().context_tokens);
        for model in c["provider"][EMBEDDED_PROVIDER_ID]["models"].as_object().unwrap().values() {
            assert_eq!(model["limit"]["context"], capacity);
            // OpenCode prefers input over context; override inherited catalog limits too.
            assert_eq!(model["limit"]["input"], capacity);
            let output = model["limit"]["output"].as_u64().unwrap();
            let buffer = c["compaction"]["buffer"].as_u64().unwrap();
            assert!(output > 0 && buffer >= 2 * output && buffer < capacity);
            // The 142,386-token conversation from the incident must already be due
            // for compaction, with room for both a reply and estimation overhead.
            assert!(142_386 > capacity - buffer);
        }
        assert_eq!(c["compaction"]["auto"], true);
    }

    #[test]
    fn external_context_limits_are_not_replaced_with_embedded_capacity() {
        for id in ["ironwire", EMBEDDED_PROVIDER_ID] {
            let p = ProviderConfig { id: id.into(), ..provider() };
            let c = opencode_config(Path::new("/p"), &json!({}), &p, false);
            assert!(c.get("compaction").is_none());
            for model in c["provider"][id]["models"].as_object().unwrap().values() {
                assert!(model.get("limit").is_none());
            }
        }
    }

    #[test]
    fn opencode_never_checks_for_or_offers_its_own_updates() {
        // rts pins opencode; the "/update to install" notice would offer a
        // version the launcher refuses. Measured in the stage 2 spike
        // (2026-10-30): "autoupdate": false removes the notice and the check.
        for embedded in [true, false] {
            let c = opencode_config(Path::new("/p"), &json!({}), &provider(), embedded);
            assert_eq!(c["autoupdate"], json!(false));
        }
    }

    #[test]
    fn the_tui_config_loads_only_the_branding_plugin_and_turns_off_opencode_titles() {
        let c = tui_config(Path::new("/repo/plugin"), "DeepSeek V4.1 Flash Abliterated", true);
        assert_eq!(c["terminal"], json!({ "title": false }));
        // The shipped theme, which session_body copies to <config>/themes/.
        assert_eq!(c["theme"], json!({ "name": "nearai-red" }));
        assert_eq!(
            c["plugins"],
            json!([{ "package": "/repo/plugin/branding", "options": { "model": "DeepSeek V4.1 Flash Abliterated", "attested": true } }])
        );
        assert_eq!(tui_config(Path::new("/p"), "m", false)["plugins"][0]["options"]["attested"], false);
    }

    #[test]
    fn writing_the_config_writes_a_private_cli_json_and_needs_the_branding_plugin() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempdir("sess-cli");
        let plugin = d.join("plugin");
        fs::create_dir_all(&plugin).unwrap();
        let e = write_tui_config(&d.join("cfg"), &plugin, "m", true).unwrap_err();
        assert!(e.contains(&plugin.join("branding").display().to_string()) && e.contains("reinstall rts or fix pluginDir"), "{e}");
        fs::create_dir_all(plugin.join("branding")).unwrap();
        fs::write(plugin.join("branding/tui.tsx"), "").unwrap();
        // tui.tsx imports footer.ts; one without the other is a broken install.
        let e = write_tui_config(&d.join("cfg"), &plugin, "m", true).unwrap_err();
        assert!(e.contains("footer.ts"), "{e}");
        fs::write(plugin.join("branding/footer.ts"), "").unwrap();
        let e = write_tui_config(&d.join("cfg"), &plugin, "m", true).unwrap_err();
        assert!(e.contains("startup.ts"), "{e}");
        fs::write(plugin.join("branding/startup.ts"), "").unwrap();
        let file = write_tui_config(&d.join("cfg"), &plugin, "m", true).unwrap();
        assert_eq!(file, d.join("cfg/cli.json"));
        assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        let v: Value = serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
        assert_eq!(v, tui_config(&plugin, "m", true));
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn the_initial_prompt_handoff_is_private_and_not_in_configuration_or_argv() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempdir("prompt-handoff");
        let plugin = Path::new(env!("CARGO_MANIFEST_DIR")).join("plugin");
        let prompt_file = d.join("initial-prompt.json");
        let config = write_tui_config_with_prompt(&d, &plugin, "m", true, Some(&prompt_file)).unwrap();
        let v: Value = serde_json::from_slice(&fs::read(config).unwrap()).unwrap();
        assert_eq!(v["plugins"][0]["options"]["initialPromptFile"], json!(prompt_file));
        assert!(!prompt_file.exists(), "writing TUI configuration must not release the prompt");
        let text = "secret task 'quoted'\r\n☃\t$(literal)";
        publish_initial_prompt(&prompt_file, text, &provider()).unwrap();
        assert_eq!(fs::metadata(&prompt_file).unwrap().permissions().mode() & 0o777, 0o600);
        let v: Value = serde_json::from_slice(&fs::read(&prompt_file).unwrap()).unwrap();
        assert_eq!(v, json!({ "text": text, "providerID": provider().id, "modelID": provider().models[0] }));
        assert!(!prompt_file.with_extension("pending").exists());
        let paths = session_paths("0123456789ab", &d, &d);
        assert_eq!(opencode_launch(&paths, "opencode", Vec::new()).argv, sv(&["opencode", "--standalone"]));
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn initial_prompt_acknowledgement_requires_success_and_sanitizes_errors() {
        let d = tempdir("prompt-ack");
        let file = d.join("prompt.ack");
        assert_eq!(initial_prompt_ack(&file).unwrap(), None);
        fs::write(&file, r#"{"status":"submitted","sessionID":"ses_123-abc"}"#).unwrap();
        assert_eq!(initial_prompt_ack(&file).unwrap(), Some("ses_123-abc".into()));
        for value in [
            json!({ "status": "error", "message": "secret prompt content" }),
            json!({ "status": "submitted", "sessionID": "injected\nlog" }),
            json!({ "status": "submitted" }),
            json!({ "status": "pending", "sessionID": "ses_1" }),
        ] {
            fs::write(&file, value.to_string()).unwrap();
            let error = initial_prompt_ack(&file).unwrap_err();
            assert!(!error.contains("secret") && !error.contains("injected"));
        }
        fs::write(&file, b"not json").unwrap();
        assert!(initial_prompt_ack(&file).is_err());
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn the_plugin_path_must_be_a_directory() {
        let d = tempdir("sess");
        fs::write(d.join("index.ts"), "").unwrap();
        let e = write_opencode_config(&d.join("cfg"), &d.join("index.ts"), &json!({}), &provider(), false).unwrap_err();
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
        match argv.last().map(String::as_str) {
            Some("--version") => out(0, "2.2.2\n", ""),
            Some("--rts-vsock-drain-fix-version") => out(0, "rts-vsock-drain-v1\n", ""),
            _ => out(0, "", ""),
        }
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
        preflight(&PreflightInput { host: f.as_ref(), run: f.as_ref(), mvmctl: Path::new("/m/mvmctl"), opencode: "opencode", leak_seam_set: leak, supervisor_path: Some(Path::new("/fake/mvm-hvf-supervisor")), work_dir: work, provider })
    }

    const MODELS_OK: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"object\":\"list\",\"data\":[{\"id\":\"z-ai/glm-5.3-flash\"}]}";

    #[test]
    fn preflight_refuses_an_unpatched_supervisor_before_doctor() {
        let f = Fake::new(|a| if a.last().map(String::as_str) == Some(SUPERVISOR_PROBE) { out(0, "", "") } else { healthy(a) });
        let external = ProviderConfig { base_url: "https://cloud-api.near.ai/v1".into(), ..provider() };
        let error = pre(&f, false, None, &external).unwrap_err();
        assert!(error.contains("rts-vsock-drain-v1"), "{error}");
        assert!(!f.calls().iter().any(|a| a == "doctor"));
    }

    #[test]
    fn supervisor_selection_uses_only_the_operator_environment_and_never_falls_back_from_an_override() {
        let env = vec![("HOME".into(), "/operator home".into())];
        let selected = supervisor_path(&env, None).unwrap();
        assert_eq!(selected, Path::new("/operator home/.local/share/nearai-red-sandbox/mvm-hvf-supervisor"));
        let mut explicit = env.clone();
        explicit.push(("MVM_HVF_SUPERVISOR_PATH".into(), "/patched path/supervisor".into()));
        assert_eq!(supervisor_path(&explicit, None).unwrap(), Path::new("/patched path/supervisor"));
        explicit.last_mut().unwrap().1 = "relative/supervisor".into();
        assert!(supervisor_path(&explicit, None).unwrap_err().contains("absolute"));
        explicit.last_mut().unwrap().1.clear();
        assert!(supervisor_path(&explicit, None).is_err());
        assert!(supervisor_path(&[], None).unwrap_err().contains("HOME"));
        assert!(supervisor_path(&[("HOME".into(), "relative".into())], None).is_err());
        assert_eq!(supervisor_path(&[("MVM_HVF_SUPERVISOR_PATH".into(), "/explicit/supervisor".into())], None).unwrap(), Path::new("/explicit/supervisor"));

        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("prefix");
        let installed = prefix.join("libexec/nearai-red-sandbox/mvm-hvf-supervisor");
        fs::create_dir_all(installed.parent().unwrap()).unwrap();
        fs::write(&installed, b"").unwrap();
        assert_eq!(supervisor_path(&env, Some(&prefix)).unwrap(), installed);
        let mut explicit = env.clone();
        explicit.push(("MVM_HVF_SUPERVISOR_PATH".into(), "/patched path/supervisor".into()));
        assert_eq!(supervisor_path(&explicit, Some(&prefix)).unwrap(), Path::new("/patched path/supervisor"));
        explicit.last_mut().unwrap().1.clear();
        assert!(supervisor_path(&explicit, Some(&prefix)).is_err());
        let bare = dir.path().join("bare");
        fs::create_dir_all(&bare).unwrap();
        assert_eq!(supervisor_path(&env, Some(&bare)).unwrap(), Path::new("/operator home/.local/share/nearai-red-sandbox/mvm-hvf-supervisor"));
    }

    #[test]
    fn missing_prerequisites_name_rts_setup() {
        struct VersionHost(fn() -> io::Result<RunOutput>);
        impl Host for VersionHost {
            fn run(&self, _: &[String], _: Duration) -> io::Result<RunOutput> { (self.0)() }
        }
        for host in [
            VersionHost(|| Err(io::Error::new(io::ErrorKind::NotFound, "no such file"))),
            VersionHost(|| Ok(out(1, "", "boom"))),
            VersionHost(|| Ok(out(0, "2.1.4\n", ""))),
        ] {
            let error = check_opencode(&host, "opencode").unwrap_err();
            assert!(error.ends_with("; run rts setup"), "{error}");
        }
        assert!(check_opencode(&VersionHost(|| Ok(out(0, "2.2.2\n", ""))), "opencode").is_ok());

        let external = ProviderConfig { base_url: "https://cloud-api.near.ai/v1".into(), ..provider() };
        let f = Fake::new(|a| if a.last().map(String::as_str) == Some(SUPERVISOR_PROBE) { out(0, "stock", "") } else { healthy(a) });
        let error = preflight(&PreflightInput { host: f.as_ref(), run: f.as_ref(), mvmctl: Path::new("/m/mvmctl"), opencode: "opencode", leak_seam_set: false,
            supervisor_path: Some(Path::new("/s/supervisor")), work_dir: None, provider: &external }).unwrap_err();
        assert!(error.contains("rts setup") && error.contains("scripts/build-patched-mvm-supervisor.sh"), "{error}");

        struct MissingMvmctl;
        impl Runner for MissingMvmctl {
            fn run(&self, _: &[String], _: Duration) -> io::Result<RunOutput> {
                Err(io::Error::new(io::ErrorKind::NotFound, "No such file or directory"))
            }
        }
        let f = Fake::new(healthy);
        let error = preflight(&PreflightInput { host: f.as_ref(), run: &MissingMvmctl, mvmctl: Path::new("/h/.local/mvm/v0.22.0/mvmctl"), opencode: "opencode", leak_seam_set: false,
            supervisor_path: Some(Path::new("/s/supervisor")), work_dir: None, provider: &external }).unwrap_err();
        assert_eq!(error, "mvmctl not found at /h/.local/mvm/v0.22.0/mvmctl; run rts setup");
    }

    #[test]
    fn mvm_commands_receive_the_same_selected_supervisor_and_operator_home() {
        let env = vec![("HOME".into(), "/operator".into()), ("MVM_HOME".into(), "/vm state".into()),
            ("MVM_HVF_SUPERVISOR_PATH".into(), "/override with spaces/supervisor".into()), ("SECRET".into(), "do not forward".into())];
        let selected = supervisor_path(&env, None).unwrap();
        let passed = mvm_environment(&env, &selected);
        assert_eq!(passed["MVM_HVF_SUPERVISOR_PATH"], selected.to_str().unwrap());
        assert_eq!(passed["HOME"], "/operator");
        assert_eq!(passed["MVM_HOME"], "/vm state");
        assert!(!passed.contains_key("SECRET"));
    }

    #[test]
    fn preflight_requires_the_exact_supervisor_marker_with_success_and_a_bounded_probe() {
        struct ProbeHost { output: RunOutput, calls: Mutex<Vec<(Vec<String>, Duration)>> }
        impl Host for ProbeHost {
            fn run(&self, argv: &[String], timeout: Duration) -> io::Result<RunOutput> {
                self.calls.lock().unwrap().push((argv.to_vec(), timeout));
                Ok(if argv.last().map(String::as_str) == Some(SUPERVISOR_PROBE) { self.output.clone() } else { healthy(argv) })
            }
        }
        let external = ProviderConfig { base_url: "https://cloud-api.near.ai/v1".into(), ..provider() };
        let path = Path::new("/patched supervisor/with spaces;$shell");
        for (output, valid) in [
            (out(0, "rts-vsock-drain-v1", ""), true),
            (out(0, "rts-vsock-drain-v1\n", ""), true),
            (out(0, " rts-vsock-drain-v1\n", ""), false),
            (out(0, "rts-vsock-drain-v1\nextra", ""), false),
            (out(1, "rts-vsock-drain-v1\n", "secret diagnostic"), false),
            (RunOutput { killed: true, ..out(0, "rts-vsock-drain-v1", "") }, false),
        ] {
            let host = ProbeHost { output, calls: Mutex::new(vec![]) };
            let runner = Fake::new(healthy);
            let result = preflight(&PreflightInput { host: &host, run: runner.as_ref(), mvmctl: Path::new("/m/mvmctl"), opencode: "opencode", leak_seam_set: false,
                supervisor_path: Some(path), work_dir: None, provider: &external });
            let calls = host.calls.lock().unwrap();
            assert_eq!(calls[1], (vec![path.to_str().unwrap().into(), SUPERVISOR_PROBE.into()], Duration::from_secs(5)));
            if valid {
                result.unwrap();
                assert_eq!(runner.calls(), ["doctor"]);
            } else {
                let error = result.unwrap_err();
                assert!(error.contains("scripts/build-patched-mvm-supervisor.sh"), "{error}");
                assert!(!error.contains("secret diagnostic"));
                assert!(runner.calls().is_empty());
            }
        }
    }

    #[test]
    fn the_supervisor_contract_must_be_exact_successful_and_bounded() {
        struct ProbeHost { output: RunOutput, calls: Mutex<Vec<(Vec<String>, Duration)>> }
        impl Host for ProbeHost {
            fn run(&self, argv: &[String], timeout: Duration) -> io::Result<RunOutput> {
                self.calls.lock().unwrap().push((argv.to_vec(), timeout));
                Ok(self.output.clone())
            }
        }
        let path = Path::new("/patched supervisor/with spaces;$shell");
        for (output, valid) in [
            (out(0, "mvm-hvf-supervisor contract-version=4", ""), true),
            (out(0, "mvm-hvf-supervisor contract-version=4\n", ""), true),
            (out(0, "mvm-hvf-supervisor contract-version=3\n", ""), false),
            (out(0, " mvm-hvf-supervisor contract-version=4\n", ""), false),
            (out(0, "mvm-hvf-supervisor contract-version=4\n\n", ""), false),
            (out(1, "mvm-hvf-supervisor contract-version=4\n", "secret diagnostic"), false),
            (RunOutput { killed: true, ..out(0, "mvm-hvf-supervisor contract-version=4", "") }, false),
        ] {
            let host = ProbeHost { output, calls: Mutex::new(vec![]) };
            let result = check_supervisor_contract(&host, path);
            assert_eq!(*host.calls.lock().unwrap(), [(vec![path.to_str().unwrap().into(), SUPERVISOR_CONTRACT_PROBE.into()], Duration::from_secs(5))]);
            if valid {
                result.unwrap();
            } else {
                let error = result.unwrap_err();
                assert!(error.contains("contract-version=4") && error.contains("rts setup"), "{error}");
                assert!(!error.contains("secret diagnostic"));
            }
        }
    }

    #[test]
    fn preflight_refuses_missing_relative_or_unexecutable_supervisors() {
        let external = ProviderConfig { base_url: "https://cloud-api.near.ai/v1".into(), ..provider() };
        for path in [None, Some(Path::new("relative/supervisor"))] {
            let f = Fake::new(healthy);
            let error = preflight(&PreflightInput { host: f.as_ref(), run: f.as_ref(), mvmctl: Path::new("/m/mvmctl"), opencode: "opencode", leak_seam_set: false,
                supervisor_path: path, work_dir: None, provider: &external }).unwrap_err();
            assert!(error.contains("absolute"), "{error}");
            assert_eq!(f.calls(), ["opencode --version"]);
        }
        struct MissingHost;
        impl Host for MissingHost {
            fn run(&self, argv: &[String], _: Duration) -> io::Result<RunOutput> {
                if argv.last().map(String::as_str) == Some(SUPERVISOR_PROBE) {
                    Err(io::Error::new(io::ErrorKind::NotFound, "private diagnostic"))
                } else { Ok(healthy(argv)) }
            }
        }
        let f = Fake::new(healthy);
        let error = preflight(&PreflightInput { host: &MissingHost, run: f.as_ref(), mvmctl: Path::new("/m/mvmctl"), opencode: "opencode", leak_seam_set: false,
            supervisor_path: Some(Path::new("/missing/supervisor")), work_dir: None, provider: &external }).unwrap_err();
        assert!(error.contains("rts-vsock-drain-v1") && !error.contains("private diagnostic"), "{error}");
        assert!(f.calls().is_empty());
    }

    #[test]
    fn external_sessions_refuse_an_unpatched_supervisor_before_any_vm_command() {
        let d = tempdir("unpatched");
        let f = Fake::new(|a| if a.last().map(String::as_str) == Some(SUPERVISOR_PROBE) { out(0, "stock", "") } else { healthy(a) });
        let deps = Deps { host: f.clone(), runner: Some(f.clone()), env: vec![("HOME".into(), "/fake/home".into())], tool_command: sv(&["/x/rts", "tool"]), session_id: None, fatal: None, resolver: Arc::new(NoResolve), clock: Arc::new(SystemTime::now) };
        let external = ProviderConfig { base_url: "https://cloud-api.near.ai/v1".into(), ..provider() };
        assert_eq!(run_session(&session_cfg(&d, &d, external), deps), 1);
        assert_eq!(f.calls(), ["opencode --version", "/fake/home/.local/share/nearai-red-sandbox/mvm-hvf-supervisor --rts-vsock-drain-fix-version"]);
        fs::remove_dir_all(d).unwrap();
    }

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
            let sb = MvmSandbox::new(&p.machine, Box::new(f.clone())).unwrap();
            let mut live = Live { log: &log, sb: &sb, paths: &p, host: f.as_ref(), machine_attempted: true, machine_created: true, child: None, network_pids: vec![], audit_dir: None, canaries: None, monitoring_failed: false, canary_setup_complete: false };
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
        let mut c = parse_config(r#"{ "provider": { "models": ["z-ai/glm-5.3-flash"] } }"#, Path::new("/"), &Defaults { mvmctl: "/x/mvmctl".into(), plugin_dir: "/repo/plugin".into(), opencode: "opencode".into(), sessions_dir: "/repo/sessions".into() }).unwrap();
        c.sessions_dir = sessions.into();
        c.plugin_dir = plugin.into();
        c.provider = provider;
        c
    }

    #[test]
    fn a_session_refuses_before_any_vm_exists_when_opencode_is_the_wrong_version() {
        let d = tempdir("sess");
        let f = Fake::new(|a| if a.last().map(String::as_str) == Some("--version") { out(0, "1.0.0", "") } else { out(0, "", "") });
        let deps = Deps { host: f.clone(), runner: Some(f.clone()), env: vec![("HOME".into(), "/fake/home".into())], tool_command: sv(&["/x/rts", "tool"]), session_id: None, fatal: None, resolver: Arc::new(NoResolve), clock: Arc::new(SystemTime::now) };
        assert_eq!(run_session(&session_cfg(&d, &d, serve(MODELS_OK)), deps), 1);
        assert!(!f.calls().iter().any(|c| c.starts_with("machine")), "{:?}", f.calls());
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn a_session_uses_the_id_its_caller_chose() {
        let d = tempdir("sess-id");
        let f = Fake::new(|a| if a.last().map(String::as_str) == Some("--version") { out(0, "1.0.0", "") } else { out(0, "", "") });
        let deps = Deps { host: f.clone(), runner: Some(f.clone()), env: vec![], tool_command: sv(&["/x/rts", "tool"]), session_id: Some("0123456789ab".into()), fatal: None, resolver: Arc::new(NoResolve), clock: Arc::new(SystemTime::now) };
        assert_eq!(run_session(&session_cfg(&d, &d, serve(MODELS_OK)), deps), 1);
        let log = fs::read_to_string(d.join("0123456789ab/launcher.log"));
        let entries: Vec<_> = fs::read_dir(&d).unwrap().map(|e| e.unwrap().file_name()).collect();
        fs::remove_dir_all(&d).unwrap();
        assert!(log.unwrap().contains("session 0123456789ab"), "{entries:?}");
        assert_eq!(entries, vec![std::ffi::OsString::from("0123456789ab")]);
    }

    #[test]
    fn a_raised_fatal_stops_the_session() {
        let f = crate::forwarder::Fatal::new();
        assert_eq!(stop_reason(None), None);
        assert_eq!(stop_reason(Some(&f)), None);
        f.raise("signature-failed: x");
        assert_eq!(stop_reason(Some(&f)).as_deref(), Some("signature-failed: x"));
    }

    #[test]
    fn new_session_ids_are_twelve_lowercase_hex() {
        let a = new_session_id();
        assert_eq!(a.len(), 12);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()), "{a}");
        assert_ne!(a, new_session_id());
    }

    #[test]
    fn a_session_refuses_before_opencode_when_supervisor_cannot_be_monitored() {
        let d = tempdir("rss-fail-closed");
        let sessions = d.join("sessions");
        let f = Fake::new(|a| match a.get(1).map(String::as_str) {
            Some("exec") if a.join(" ").contains("reachable-direct") => exec_out(a, "RTS_PROBE unreachable\n"),
            Some("exec") => out(0, "", &format!("\nRTS_EXIT_{} 0 0 0\n", a[8])),
            _ => healthy(a),
        });
        let deps = Deps {
            host: f.clone(), runner: Some(f.clone()),
            env: vec![("HOME".into(), "/fake/home".into()), ("MVM_HOME".into(), d.join("mvm").to_string_lossy().into_owned())],
            tool_command: sv(&["/x/rts", "tool"]),
            session_id: None,
            fatal: None,
            resolver: Arc::new(NoResolve),
            clock: Arc::new(SystemTime::now),
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
        let deps = Deps { host: f.clone(), runner: Some(f.clone()), env: vec![("HOME".into(), "/fake/home".into())], tool_command: sv(&["/x/rts", "tool"]), session_id: None, fatal: None, resolver: Arc::new(NoResolve), clock: Arc::new(SystemTime::now) };
        assert_eq!(run_session(&session_cfg(&d, &d, serve(MODELS_OK)), deps), 1);
        let calls = f.calls();
        assert!(calls.iter().any(|c| c.starts_with("machine rm rts-") && c.ends_with(" --force --yes")), "{calls:?}");
        assert!(!calls.iter().any(|c| c.starts_with("machine exec")), "{calls:?}");
        let session = fs::read_dir(&d).unwrap().next().unwrap().unwrap().path();
        let log = fs::read_to_string(session.join("launcher.log")).unwrap();
        assert!(log.contains("image pull failed") && log.contains("teardown: removed"), "{log}");
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn session_paths_place_the_network_files_in_the_session_dir() {
        let p = session_paths("0123456789ab", Path::new("/s"), Path::new("/rt"));
        assert_eq!(p.attach_log, PathBuf::from("/s/0123456789ab/mvm-attach.log"));
        assert_eq!(p.session_record, PathBuf::from("/s/0123456789ab/session.json"));
        assert_eq!(p.network_audit, PathBuf::from("/s/0123456789ab/network.jsonl"));
    }

    #[test]
    fn network_children_keeps_the_endpoint_and_supervisor_and_needs_an_endpoint() {
        let reply = |endpoint: &'static str| move |a: &[String]| match a.join(" ").as_str() {
            "pgrep -P 4242" => out(0, "4243\n4244\n4245\n", ""),
            "ps -o comm= -p 4243" => out(0, endpoint, ""),
            "ps -o comm= -p 4244" => out(0, "mvm-hvf-supervisor\n", ""),
            "ps -o comm= -p 4245" => out(0, "/bin/zsh\n", ""),
            _ => out(1, "", ""),
        };
        let f = Fake::new(reply("/opt/mvm/bin/mvm-network-endpoint\n"));
        assert_eq!(network_children(f.as_ref(), 4242).unwrap(), vec![4243, 4244]);
        let f = Fake::new(reply("/bin/sleep\n"));
        assert!(network_children(f.as_ref(), 4242).unwrap_err().contains("mvm-network-endpoint"));
        let f = Fake::new(|_| out(1, "", ""));
        assert!(network_children(f.as_ref(), 4242).is_err());
    }

    /// A `machine exec` reply: `stdout` and a valid trailer.
    fn exec_out(a: &[String], stdout: &str) -> RunOutput {
        out(0, stdout, &format!("\nRTS_EXIT_{} 0 {} 0\n", a[8], stdout.len()))
    }

    /// Replies for a session that runs up to opencode. An entry probe
    /// prints `probe` as its last line and then runs `on_probe`. After
    /// `machine rm`, the attach process's children are gone.
    fn net_reply(probe: &'static str, on_probe: impl Fn() + Send + Sync + 'static) -> impl Fn(&[String]) -> RunOutput + Send + Sync + 'static {
        let gone = std::sync::atomic::AtomicBool::new(false);
        move |a| {
            use std::sync::atomic::Ordering;
            let line = a.join(" ");
            match line.as_str() {
                l if l.starts_with("machine rm ") => {
                    gone.store(true, Ordering::SeqCst);
                    out(0, "", "")
                }
                "pgrep -P 4242" => out(0, "4243\n4244\n", ""),
                "ps -o comm= -p 4243" if !gone.load(Ordering::SeqCst) => out(0, "/opt/mvm/bin/mvm-network-endpoint\n", ""),
                "ps -o comm= -p 4244" if !gone.load(Ordering::SeqCst) => out(0, "/opt/mvm/bin/mvm-hvf-supervisor\n", ""),
                l if l.starts_with("ps -o comm= -p ") => out(1, "", ""),
                "ps -o rss= -p 4244" => out(0, "1000\n", ""),
                _ if a.get(1).map(String::as_str) == Some("exec") => {
                    if line.contains("reachable-direct") {
                        exec_out(a, "RTS_PROBE unreachable\n")
                    } else if line.contains("RTS_PROBE connected") {
                        let r = exec_out(a, &format!("{probe}\n"));
                        on_probe();
                        r
                    } else if line.contains("echo NONE") {
                        exec_out(a, "NONE\n")
                    } else {
                        exec_out(a, "")
                    }
                }
                _ => healthy(a),
            }
        }
    }

    const OUR_FLOW: &str = r#"{"entry":{"event":"host.flow.allowed","labels":{"vm_name":"rts-0123456789ab","target":"198.51.100.7:8443"}},"sig":"s1"}"#;
    const OTHER_FLOW: &str = r#"{"entry":{"event":"host.flow.allowed","labels":{"vm_name":"rts-ffffffffffff"}},"sig":"s2"}"#;

    struct NetSession {
        d: PathBuf,
        mvm: PathBuf,
        session: PathBuf,
        cfg: OperatorConfig,
    }

    /// An MVM_HOME holding this VM's hvf.pid (4244) and an audit log, and a
    /// config whose opencode does not exist, so the session stops after the
    /// probes and the RSS check.
    fn net_session(name: &str, network: &[&str]) -> NetSession {
        let d = tempdir(name);
        let mvm = d.join("mvm");
        fs::create_dir_all(mvm.join("vms/rts-0123456789ab")).unwrap();
        fs::write(mvm.join("vms/rts-0123456789ab/hvf.pid"), "4244\n").unwrap();
        fs::create_dir_all(mvm.join("audit")).unwrap();
        fs::write(mvm.join("audit/local.jsonl"), format!("{OTHER_FLOW}\n{OUR_FLOW}\n")).unwrap();
        let mut cfg = session_cfg(&d.join("sessions"), &d, serve(MODELS_OK));
        // An installed plugin carries the branding TUI files; without them
        // the launcher refuses the session before the code under test runs.
        fs::create_dir_all(cfg.plugin_dir.join("branding")).unwrap();
        for f in ["tui.tsx", "footer.ts", "startup.ts"] {
            fs::write(cfg.plugin_dir.join("branding").join(f), "").unwrap();
        }
        // and the shipped opencode theme, which session_body installs.
        let theme = cfg.plugin_dir.join(crate::brand::theme::THEME_FILE);
        fs::create_dir_all(theme.parent().unwrap()).unwrap();
        fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join("plugin").join(crate::brand::theme::THEME_FILE), &theme).unwrap();
        cfg.opencode = "/nonexistent-opencode".into();
        cfg.network = network.iter().map(|s| s.to_string()).collect();
        NetSession { session: d.join("sessions/0123456789ab"), d, mvm, cfg }
    }

    fn net_deps(f: &Arc<Fake>, mvm: &Path, resolver: Arc<dyn crate::network::Resolver>, extra: &[(&str, &str)]) -> Deps {
        let mut env: Vec<(String, String)> = vec![("HOME".into(), "/fake/home".into()), ("MVM_HOME".into(), mvm.to_string_lossy().into_owned()), ("PATH".into(), "/usr/bin:/bin".into())];
        env.extend(extra.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        Deps { host: f.clone(), runner: Some(f.clone()), env, tool_command: sv(&["/x/rts", "tool"]), session_id: Some("0123456789ab".into()), fatal: None, resolver, clock: Arc::new(SystemTime::now) }
    }

    fn read_log(s: &NetSession) -> String {
        fs::read_to_string(s.session.join("launcher.log")).unwrap_or_default()
    }

    fn position(calls: &[String], pred: impl Fn(&str) -> bool) -> Option<usize> {
        calls.iter().position(|c| pred(c))
    }

    #[test]
    fn a_session_with_a_proxy_variable_is_refused_before_any_machine_command() {
        let s = net_session("net-proxy", &[]);
        let f = Fake::new(net_reply("RTS_PROBE connected", || {}));
        assert_eq!(run_session(&s.cfg, net_deps(&f, &s.mvm, Arc::new(NoResolve), &[("https_proxy", "http://p:3128")])), 1);
        let (calls, log) = (f.calls(), read_log(&s));
        fs::remove_dir_all(&s.d).unwrap();
        assert!(!calls.iter().any(|c| c.starts_with("machine") || c.starts_with("attach")), "{calls:?}");
        assert!(log.contains("https_proxy"), "{log}");
    }

    #[test]
    fn an_unresolvable_entry_refuses_before_any_machine_command() {
        let s = net_session("net-unresolvable", &["nowhere.example"]);
        let f = Fake::new(net_reply("RTS_PROBE connected", || {}));
        assert_eq!(run_session(&s.cfg, net_deps(&f, &s.mvm, Arc::new(NoSuchHost), &[])), 1);
        let (calls, log) = (f.calls(), read_log(&s));
        fs::remove_dir_all(&s.d).unwrap();
        assert!(!calls.iter().any(|c| c.starts_with("machine") || c.starts_with("attach")), "{calls:?}");
        assert!(log.contains("nowhere.example") && log.contains("does not resolve"), "{log}");
    }

    #[test]
    fn a_no_network_session_runs_the_deny_all_probe_and_records_it() {
        let s = net_session("net-none", &[]);
        let f = Fake::new(net_reply("RTS_PROBE connected", || {}));
        assert_eq!(run_session(&s.cfg, net_deps(&f, &s.mvm, Arc::new(NoResolve), &[])), 1);
        let (calls, log) = (f.calls(), read_log(&s));
        let record = fs::read_to_string(s.session.join("session.json"));
        let audit_exists = s.session.join("network.jsonl").is_file();
        fs::remove_dir_all(&s.d).unwrap();
        let record: Value = serde_json::from_str(&record.unwrap()).unwrap();
        assert_eq!(record, json!({"network": {"allow": [], "expanded": [], "resolved": {}, "pinned": {}, "probes": [{"target": "1.1.1.1:443", "result": "unreachable"}]}}));
        assert!(log.contains("network: none"), "{log}");
        assert!(calls.iter().any(|c| c == "machine start rts-0123456789ab"), "{calls:?}");
        assert!(!calls.iter().any(|c| c.contains("machine run") || c.contains("--allow-host")), "{calls:?}");
        assert!(calls.iter().any(|c| c.contains("reachable-direct")), "deny-all probe did not run: {calls:?}");
        assert!(audit_exists, "network.jsonl was not written");
    }

    #[test]
    fn a_network_session_creates_with_allow_hosts_probes_and_logs_the_startup_line() {
        let s = net_session("net-one", &["198.51.100.7:8443"]);
        let f = Fake::new(net_reply("RTS_PROBE connected", || {}));
        assert_eq!(run_session(&s.cfg, net_deps(&f, &s.mvm, Arc::new(NoResolve), &[])), 1);
        let (calls, log) = (f.calls(), read_log(&s));
        let record = fs::read_to_string(s.session.join("session.json"));
        let audit = fs::read_to_string(s.session.join("network.jsonl"));
        fs::remove_dir_all(&s.d).unwrap();
        let create = calls.iter().find(|c| c.starts_with("machine create ")).expect("no create");
        assert!(create.ends_with("--allow-host 198.51.100.7:8443"), "{create}");
        assert!(calls.contains(&"attach machine run --name rts-0123456789ab --ttl 24h".to_string()), "{calls:?}");
        assert!(!calls.iter().any(|c| c.starts_with("machine start")), "{calls:?}");
        for c in &calls {
            for flag in ["--net", "--peer", "--gpu", "--grants-file", "--policy"] {
                assert!(!c.split(' ').any(|w| w == flag), "{c}");
            }
        }
        let record: Value = serde_json::from_str(&record.unwrap()).unwrap();
        assert_eq!(record["network"]["probes"], json!([{"target": "198.51.100.7:8443", "result": "connected"}]));
        assert_eq!(record["network"]["allow"], json!(["198.51.100.7:8443"]));
        assert!(log.contains("network: 1 host allowed (198.51.100.7:8443); TCP only; every connection is logged"), "{log}");
        let rm = position(&calls, |c| c.starts_with("machine rm rts-0123456789ab")).expect("no rm");
        let term = position(&calls, |c| c == "terminate").expect("attach not terminated");
        assert!(rm < term, "{calls:?}");
        assert!(!log.contains("NETWORK PROCESS REMAINED"), "{log}");
        assert_eq!(audit.unwrap(), format!("{OUR_FLOW}\n"));
        assert!(log.contains("teardown: copied 1 network audit entries to "), "{log}");
    }

    #[test]
    fn a_lost_attach_before_opencode_ends_the_session_with_network_lost_and_still_exports_and_removes() {
        let s = net_session("net-lost-early", &["198.51.100.7:8443"]);
        let lost = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flip = lost.clone();
        let f = Fake::new(net_reply("RTS_PROBE connected", move || flip.store(true, std::sync::atomic::Ordering::SeqCst)));
        let seen = lost.clone();
        f.exit_when(move || seen.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(run_session(&s.cfg, net_deps(&f, &s.mvm, Arc::new(NoResolve), &[])), 1);
        let (calls, log) = (f.calls(), read_log(&s));
        fs::remove_dir_all(&s.d).unwrap();
        assert!(log.contains("network-lost") && log.contains("teardown: removed"), "{log}");
        assert!(!log.contains("sampling host RSS") && !log.contains("starting "), "{log}");
        let probe = position(&calls, |c| c.contains("RTS_PROBE connected")).expect("no probe");
        let export = position(&calls, |c| c.contains("echo NONE")).expect("no export");
        assert!(probe < export, "{calls:?}");
        assert!(calls.iter().any(|c| c.starts_with("machine rm rts-0123456789ab")), "{calls:?}");
    }

    #[test]
    fn a_failed_plugin_handshake_never_publishes_the_initial_prompt() {
        use std::os::unix::fs::PermissionsExt;
        let mut s = net_session("prompt-no-handshake", &[]);
        let started = s.d.join("config-path");
        let script = s.d.join("opencode-stand-in");
        fs::write(&script, format!("#!/bin/sh\nprintf '%s' \"$XDG_CONFIG_HOME/opencode\" > '{}'; exec /bin/sleep 30\n", started.display())).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        s.cfg.opencode = script.to_string_lossy().into_owned();
        s.cfg.limits.handshake_ms = 250;
        let f = Fake::new(net_reply("RTS_PROBE connected", || {}));
        assert_eq!(run_session_with_prompt(&s.cfg, net_deps(&f, &s.mvm, Arc::new(NoResolve), &[]), Some("private initial task")), 1);
        let config = fs::read_to_string(&started).expect("OpenCode stand-in must have started");
        assert!(!Path::new(&config).join("initial-prompt.json").exists());
        assert!(!Path::new(&config).join("initial-prompt.pending").exists());
        let log = read_log(&s);
        assert!(log.contains("plugin did not report ready"), "{log}");
        assert!(!log.contains("private initial task"));
        fs::remove_dir_all(&s.d).unwrap();
    }

    #[test]
    fn a_lost_attach_during_the_handshake_ends_the_session_with_network_lost() {
        use std::os::unix::fs::PermissionsExt;
        let mut s = net_session("net-lost-handshake", &["198.51.100.7:8443"]);
        let started = s.d.join("started");
        let script = s.d.join("opencode-stand-in");
        fs::write(&script, format!("#!/bin/sh\n/usr/bin/touch '{}'; exec /bin/sleep 30\n", started.display())).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        s.cfg.opencode = script.to_string_lossy().into_owned();
        let f = Fake::new(net_reply("RTS_PROBE connected", || {}));
        let marker = started.clone();
        f.exit_when(move || marker.exists());
        let begun = Instant::now();
        assert_eq!(run_session(&s.cfg, net_deps(&f, &s.mvm, Arc::new(NoResolve), &[])), 1);
        let elapsed = begun.elapsed();
        let (calls, log) = (f.calls(), read_log(&s));
        let was_started = started.exists();
        fs::remove_dir_all(&s.d).unwrap();
        assert!(was_started, "the opencode stand-in never ran: {log}");
        assert!(elapsed < Duration::from_millis(s.cfg.limits.handshake_ms / 2), "took {elapsed:?}");
        assert!(log.contains("network-lost") && !log.contains("plugin ready"), "{log}");
        assert!(log.contains("teardown: opencode stopped"), "{log}");
        assert!(calls.iter().any(|c| c.starts_with("machine rm rts-0123456789ab")), "{calls:?}");
    }

    /// Every name resolves to 198.51.100.7.
    struct ResolvesTo7;
    impl crate::network::Resolver for ResolvesTo7 {
        fn resolve(&self, _: &str) -> io::Result<Vec<std::net::IpAddr>> {
            Ok(vec!["198.51.100.7".parse().unwrap()])
        }
    }

    const TARGET: &str = "api.example-target.com";

    /// A network session for TARGET whose mvm audit log holds `lines`.
    fn pinned_session(name: &str, lines: &[String]) -> NetSession {
        let s = net_session(name, &[TARGET]);
        fs::write(s.mvm.join("audit/local.jsonl"), lines.join("\n") + "\n").unwrap();
        s
    }

    fn pin_flow(vm: &str, ips: &str) -> String {
        format!(r#"{{"entry":{{"event":"host.flow.allowed","labels":{{"vm_name":"{vm}","target":"{TARGET}:443","resolved_ips":"{ips}"}}}}}}"#)
    }

    #[test]
    fn matching_pinned_ips_are_recorded_and_the_session_proceeds() {
        let s = pinned_session("net-pin-ok", &[pin_flow("rts-0123456789ab", "198.51.100.7")]);
        let f = Fake::new(net_reply("RTS_PROBE connected", || {}));
        assert_eq!(run_session(&s.cfg, net_deps(&f, &s.mvm, Arc::new(ResolvesTo7), &[])), 1);
        let log = read_log(&s);
        let record = fs::read_to_string(s.session.join("session.json"));
        fs::remove_dir_all(&s.d).unwrap();
        assert!(!log.contains("network-mismatch"), "{log}");
        assert!(log.contains("network: 1 host allowed (api.example-target.com)"), "{log}");
        assert!(log.contains("sampling host RSS"), "{log}");
        let record: Value = serde_json::from_str(&record.unwrap()).unwrap();
        assert_eq!(record["network"]["resolved"], json!({ TARGET: ["198.51.100.7"] }));
        assert_eq!(record["network"]["pinned"], json!({ TARGET: ["198.51.100.7"] }));
    }

    #[test]
    fn a_pinned_lan_ip_ends_the_session_with_network_mismatch_and_still_exports_and_removes() {
        let s = pinned_session(
            "net-pin-lan",
            &[pin_flow("rts-0123456789ab", "192.168.1.10"), pin_flow("rts-ffffffffffff", "198.51.100.7")],
        );
        let f = Fake::new(net_reply("RTS_PROBE connected", || {}));
        assert_eq!(run_session(&s.cfg, net_deps(&f, &s.mvm, Arc::new(ResolvesTo7), &[])), 1);
        let (calls, log) = (f.calls(), read_log(&s));
        let record = fs::read_to_string(s.session.join("session.json"));
        fs::remove_dir_all(&s.d).unwrap();
        assert!(log.contains("network-mismatch") && log.contains("192.168.1.10") && log.contains(TARGET), "{log}");
        assert!(!log.contains("network: 1 host allowed") && !log.contains("sampling host RSS"), "{log}");
        assert!(log.contains("teardown: removed"), "{log}");
        assert!(calls.iter().any(|c| c.contains("echo NONE")), "no export: {calls:?}");
        assert!(calls.iter().any(|c| c.starts_with("machine rm rts-0123456789ab")), "{calls:?}");
        let record: Value = serde_json::from_str(&record.unwrap()).unwrap();
        assert_eq!(record["network"]["pinned"], json!({ TARGET: ["192.168.1.10"] }));
    }

    #[test]
    fn a_name_mvm_never_pinned_ends_the_session_with_network_mismatch_after_the_wait() {
        let s = pinned_session("net-pin-none", &[OTHER_FLOW.to_string()]);
        let f = Fake::new(net_reply("RTS_PROBE connected", || {}));
        // Each read of the clock is one second later, so the 10 s wait ends in a few polls.
        let ticks = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let start = SystemTime::now();
        let mut deps = net_deps(&f, &s.mvm, Arc::new(ResolvesTo7), &[]);
        deps.clock = Arc::new(move || start + Duration::from_secs(ticks.fetch_add(1, std::sync::atomic::Ordering::SeqCst)));
        let begun = Instant::now();
        assert_eq!(run_session(&s.cfg, deps), 1);
        let elapsed = begun.elapsed();
        let (calls, log) = (f.calls(), read_log(&s));
        fs::remove_dir_all(&s.d).unwrap();
        assert!(elapsed < Duration::from_secs(8), "took {elapsed:?}");
        assert!(log.contains("network-mismatch") && log.contains("no pinned address") && log.contains(TARGET), "{log}");
        assert!(!log.contains("sampling host RSS"), "{log}");
        assert!(calls.iter().any(|c| c.starts_with("machine rm rts-0123456789ab")), "{calls:?}");
    }

    #[test]
    fn a_missing_mvm_audit_log_ends_the_session_naming_the_log() {
        let s = pinned_session("net-pin-nolog", &[]);
        fs::remove_file(s.mvm.join("audit/local.jsonl")).unwrap();
        let f = Fake::new(net_reply("RTS_PROBE connected", || {}));
        let ticks = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let start = SystemTime::now();
        let mut deps = net_deps(&f, &s.mvm, Arc::new(ResolvesTo7), &[]);
        deps.clock = Arc::new(move || start + Duration::from_secs(ticks.fetch_add(1, std::sync::atomic::Ordering::SeqCst)));
        assert_eq!(run_session(&s.cfg, deps), 1);
        let (calls, log) = (f.calls(), read_log(&s));
        fs::remove_dir_all(&s.d).unwrap();
        assert!(log.contains("network-mismatch") && log.contains("audit log never appeared"), "{log}");
        assert!(calls.iter().any(|c| c.starts_with("machine rm rts-0123456789ab")), "{calls:?}");
    }

    #[test]
    fn a_failed_probe_refuses_and_tears_down() {
        let s = net_session("net-probe-fail", &["198.51.100.7:8443"]);
        let f = Fake::new(net_reply("RTS_PROBE refused HTTP/1.1 403 Forbidden", || {}));
        assert_eq!(run_session(&s.cfg, net_deps(&f, &s.mvm, Arc::new(NoResolve), &[])), 1);
        let (calls, log) = (f.calls(), read_log(&s));
        let record = fs::read_to_string(s.session.join("session.json"));
        fs::remove_dir_all(&s.d).unwrap();
        assert!(log.contains("network probe 198.51.100.7:8443 failed"), "{log}");
        assert!(!log.contains("network: 1 host allowed"), "{log}");
        assert!(calls.iter().any(|c| c.starts_with("machine rm rts-0123456789ab")), "{calls:?}");
        let record: Value = serde_json::from_str(&record.unwrap()).unwrap();
        assert_eq!(record["network"]["probes"], json!([]));
    }

    #[test]
    fn teardown_kills_a_lingering_endpoint_and_reports_audit_failure_without_blocking_removal() {
        let d = tempdir("net-linger");
        let p = session_paths("0123456789ab", &d.join("sessions"), &d.join("runtime"));
        prepare_session_dirs(&p).unwrap();
        let f = Fake::new(|a| match a.join(" ").as_str() {
            "ps -o comm= -p 4243" => out(0, "/opt/mvm/bin/mvm-network-endpoint\n", ""),
            "ps -o comm= -p 4245" => out(0, "/bin/zsh\n", ""),
            _ => out(0, "", ""),
        });
        let log = Logger { id: p.id.clone(), file: p.log_file.clone() };
        let sb = MvmSandbox::new(&p.machine, Box::new(f.clone())).unwrap();
        let mut live = Live {
            log: &log, sb: &sb, paths: &p, host: f.as_ref(),
            machine_attempted: true, machine_created: false, child: None,
            network_pids: vec![4243, 4245], audit_dir: Some(d.join("no-such-audit")),
            canaries: None, monitoring_failed: false, canary_setup_complete: false,
        };
        live.teardown("test");
        let text = fs::read_to_string(&p.log_file).unwrap();
        let calls = f.calls();
        fs::remove_dir_all(&d).unwrap();
        assert!(text.contains("teardown: NETWORK PROCESS REMAINED: pid 4243 (mvm-network-endpoint); killed"), "{text}");
        assert!(!text.contains("pid 4245"), "{text}");
        assert!(text.contains("teardown: NETWORK AUDIT FAILED: "), "{text}");
        assert!(text.contains("teardown: removed rts-0123456789ab"), "{text}");
        let rm = position(&calls, |c| c.starts_with("machine rm ")).expect("no rm");
        let kill = position(&calls, |c| c == "kill -KILL 4243").expect("no kill");
        assert!(rm < kill, "{calls:?}");
        assert!(!calls.iter().any(|c| c == "kill -KILL 4245"), "{calls:?}");
    }

    // --- session time limit (Task 9a) ---

    const T0: Duration = Duration::from_secs(1_800_000_000);

    /// Boot reads the clock first; every later read is `later` after it.
    fn jump_clock(later: Duration) -> Clock {
        let first = std::sync::atomic::AtomicBool::new(true);
        Arc::new(move || UNIX_EPOCH + T0 + if first.swap(false, std::sync::atomic::Ordering::SeqCst) { Duration::ZERO } else { later })
    }

    #[test]
    fn the_session_limit_is_reached_at_exactly_its_hours_since_boot() {
        let boot = UNIX_EPOCH + T0;
        let h = Duration::from_secs(3600);
        assert_eq!(session_limit(boot, boot, 24), None);
        assert_eq!(session_limit(boot, boot + 24 * h - Duration::from_secs(1), 24), None);
        assert_eq!(session_limit(boot, boot + 24 * h, 24).as_deref(), Some("session-limit: 24h since boot"));
        assert!(session_limit(boot, boot + 2 * h, 1).is_some());
        // A clock that steps back before boot has not used up the limit.
        assert_eq!(session_limit(boot, boot - h, 24), None);
    }

    #[test]
    fn a_session_past_its_limit_stops_with_session_limit_and_tears_down_in_order() {
        let s = net_session("limit-passed", &[]);
        let f = Fake::new(net_reply("RTS_PROBE connected", || {}));
        let mut deps = net_deps(&f, &s.mvm, Arc::new(NoResolve), &[]);
        deps.clock = jump_clock(Duration::from_secs(24 * 3600));
        assert_eq!(run_session(&s.cfg, deps), 1);
        let (calls, log) = (f.calls(), read_log(&s));
        fs::remove_dir_all(&s.d).unwrap();
        assert!(log.contains("session-limit: 24h since boot before opencode started"), "{log}");
        assert!(!log.contains("sampling host RSS"), "{log}");
        assert!(log.contains("teardown: removed rts-0123456789ab"), "{log}");
        let export = position(&calls, |c| c.contains("echo NONE")).expect("no export");
        let rm = position(&calls, |c| c.starts_with("machine rm rts-0123456789ab")).expect("no rm");
        assert!(export < rm, "{calls:?}");
    }

    #[test]
    fn a_network_session_past_its_limit_stops_with_session_limit_and_stops_the_attach_after_rm() {
        let s = net_session("limit-passed-net", &["198.51.100.7:8443"]);
        let f = Fake::new(net_reply("RTS_PROBE connected", || {}));
        let mut deps = net_deps(&f, &s.mvm, Arc::new(NoResolve), &[]);
        deps.clock = jump_clock(Duration::from_secs(25 * 3600));
        assert_eq!(run_session(&s.cfg, deps), 1);
        let (calls, log) = (f.calls(), read_log(&s));
        fs::remove_dir_all(&s.d).unwrap();
        assert!(calls.contains(&"attach machine run --name rts-0123456789ab --ttl 24h".to_string()), "{calls:?}");
        assert!(log.contains("session-limit: 24h since boot"), "{log}");
        let export = position(&calls, |c| c.contains("echo NONE")).expect("no export");
        let rm = position(&calls, |c| c.starts_with("machine rm rts-0123456789ab")).expect("no rm");
        let term = position(&calls, |c| c == "terminate").expect("attach not terminated");
        assert!(export < rm && rm < term, "{calls:?}");
    }

    #[test]
    fn a_session_within_its_limit_is_not_stopped() {
        let s = net_session("limit-within", &[]);
        let f = Fake::new(net_reply("RTS_PROBE connected", || {}));
        let mut deps = net_deps(&f, &s.mvm, Arc::new(NoResolve), &[]);
        deps.clock = jump_clock(Duration::from_secs(24 * 3600 - 1));
        assert_eq!(run_session(&s.cfg, deps), 1);
        let log = read_log(&s);
        fs::remove_dir_all(&s.d).unwrap();
        assert!(!log.contains("session-limit"), "{log}");
        // It got past the pre-opencode check, to the missing opencode.
        assert!(log.contains("sampling host RSS"), "{log}");
        assert!(log.contains("/nonexistent-opencode"), "{log}");
    }

    #[test]
    fn a_session_limit_reached_during_the_handshake_ends_the_session() {
        use std::os::unix::fs::PermissionsExt;
        let mut s = net_session("limit-handshake", &[]);
        let started = s.d.join("started");
        let script = s.d.join("opencode-stand-in");
        fs::write(&script, format!("#!/bin/sh\n/usr/bin/touch '{}'; exec /bin/sleep 30\n", started.display())).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        s.cfg.opencode = script.to_string_lossy().into_owned();
        let f = Fake::new(net_reply("RTS_PROBE connected", || {}));
        let mut deps = net_deps(&f, &s.mvm, Arc::new(NoResolve), &[]);
        let marker = started.clone();
        deps.clock = Arc::new(move || UNIX_EPOCH + T0 + if marker.exists() { Duration::from_secs(24 * 3600) } else { Duration::ZERO });
        let begun = Instant::now();
        assert_eq!(run_session(&s.cfg, deps), 1);
        let elapsed = begun.elapsed();
        let (calls, log) = (f.calls(), read_log(&s));
        let was_started = started.exists();
        fs::remove_dir_all(&s.d).unwrap();
        assert!(was_started, "the opencode stand-in never ran: {log}");
        assert!(elapsed < Duration::from_millis(s.cfg.limits.handshake_ms / 2), "took {elapsed:?}");
        assert!(log.contains("session-limit: 24h since boot") && !log.contains("plugin ready"), "{log}");
        assert!(log.contains("teardown: opencode stopped"), "{log}");
        assert!(calls.iter().any(|c| c.starts_with("machine rm rts-0123456789ab")), "{calls:?}");
    }

    #[test]
    fn teardown_keeps_the_opencode_data_store() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempdir("keep-opencode-store");
        let p = session_paths("0123456789ab", &d.join("sessions"), &d.join("runtime"));
        prepare_session_dirs(&p).unwrap();
        let src_dir = p.xdg_data.join("opencode");
        fs::create_dir_all(&src_dir).unwrap();
        let db = src_dir.join("opencode.db");
        write_private(&db, b"sqlite-bytes").unwrap();
        assert_eq!(fs::metadata(&db).unwrap().permissions().mode() & 0o777, 0o600);

        let f = Fake::new(|_| out(0, "", ""));
        let run: Arc<dyn Runner> = f.clone();
        let sb = MvmSandbox::new(&p.machine, Box::new(run)).unwrap();
        let log = Logger { id: p.id.clone(), file: p.log_file.clone() };
        let mut live = Live {
            log: &log,
            sb: &sb,
            paths: &p,
            host: f.as_ref(),
            machine_attempted: true,
            machine_created: true,
            child: None,
            network_pids: vec![],
            audit_dir: None,
            canaries: None,
            monitoring_failed: false,
            canary_setup_complete: false,
        };
        live.teardown("done");

        let kept = p.opencode_data.join("opencode.db");
        assert_eq!(fs::read(&kept).unwrap(), b"sqlite-bytes");
        assert_eq!(fs::metadata(&kept).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(!src_dir.exists());
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn teardown_without_an_opencode_store_still_exports() {
        let d = tempdir("no-opencode-store");
        let p = session_paths("0123456789ab", &d.join("sessions"), &d.join("runtime"));
        prepare_session_dirs(&p).unwrap();
        let f = Fake::new(|_| out(0, "", ""));
        let run: Arc<dyn Runner> = f.clone();
        let sb = MvmSandbox::new(&p.machine, Box::new(run)).unwrap();
        let log = Logger { id: p.id.clone(), file: p.log_file.clone() };
        let mut live = Live {
            log: &log,
            sb: &sb,
            paths: &p,
            host: f.as_ref(),
            machine_attempted: true,
            machine_created: true,
            child: None,
            network_pids: vec![],
            audit_dir: None,
            canaries: None,
            monitoring_failed: false,
            canary_setup_complete: false,
        };
        live.teardown("done");

        let calls = f.calls();
        let logged = fs::read_to_string(&p.log_file).unwrap();
        assert!(logged.contains("opencode data: none to keep"), "{logged}");
        assert!(calls.iter().any(|c| c.starts_with("machine rm rts-0123456789ab")), "{calls:?}");
        assert!(calls.iter().any(|c| c.contains("/out")), "{calls:?}");
        fs::remove_dir_all(d).unwrap();
    }
}

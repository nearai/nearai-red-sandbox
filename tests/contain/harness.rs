//! Shared setup for the real-mvm suite. Every test skips, printing why,
//! when mvmctl is missing or `mvmctl doctor` fails; the opencode tests also
//! skip when opencode 2.1.4 is not on PATH (or at RTS_OPENCODE).

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::Duration;

use rts::config::DEFAULT_IMAGE;
use rts::mvm::{MvmSandbox, Runner, SpawnRunner};
use rts::protocol::random_hex;
use rts::sandbox::{CreateSpec, ExecOptions, Sandbox};
use rts::session::{OPENCODE_VERSION, initialize_guest_storage};
use serde_json::{Value, json};

pub struct Harness {
    pub mvmctl: PathBuf,
    pub image: String,
    pub run: Arc<dyn Runner>,
    pub empty_git_config: PathBuf,
}

pub fn limits() -> ExecOptions {
    ExecOptions::new(120_000, 65_536)
}

fn probe() -> Result<Harness, String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let mvmctl = std::env::var_os("RTS_MVMCTL").map(PathBuf::from).unwrap_or_else(|| Path::new(&home).join(".local/mvm/v0.22.0/mvmctl"));
    if !mvmctl.exists() {
        return Err(format!("mvmctl not found at {} (set RTS_MVMCTL)", mvmctl.display()));
    }
    let scratch = std::env::temp_dir().join(format!("rts-contain-{}", random_hex(6)));
    fs::create_dir_all(&scratch).map_err(|e| e.to_string())?;
    let empty_git_config = scratch.join("empty.gitconfig");
    fs::write(&empty_git_config, "").map_err(|e| e.to_string())?;
    let run: Arc<dyn Runner> = Arc::new(SpawnRunner { mvmctl: mvmctl.clone(), empty_git_config: empty_git_config.clone(), extra_env: Default::default() });
    let r = run.run(&["doctor".to_string()], Duration::from_secs(60)).map_err(|e| format!("mvmctl doctor could not run: {e}"))?;
    if r.code != Some(0) {
        return Err(format!("mvmctl doctor failed: {}", String::from_utf8_lossy(&r.stderr).trim()));
    }
    let image = std::env::var("RTS_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.into());
    Ok(Harness { mvmctl, image, run, empty_git_config })
}

/// The harness, or None (with the reason printed once) when mvm is not usable here.
pub fn mvm() -> Option<&'static Harness> {
    static H: OnceLock<Result<Harness, String>> = OnceLock::new();
    match H.get_or_init(probe) {
        Ok(h) => Some(h),
        Err(why) => {
            eprintln!("[contain] skipping real-mvm test: {why}");
            None
        }
    }
}

pub fn opencode() -> Option<String> {
    let oc = std::env::var("RTS_OPENCODE").unwrap_or_else(|_| "opencode".into());
    let ok = Command::new(&oc).arg("--version").stdin(Stdio::null()).output().is_ok_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains(OPENCODE_VERSION));
    if !ok {
        eprintln!("[contain] skipping opencode test: {oc} --version is not {OPENCODE_VERSION}");
    }
    ok.then_some(oc)
}

/// A machine removed when dropped, so a failing test still cleans up.
pub struct Machine(pub MvmSandbox);

impl Drop for Machine {
    fn drop(&mut self) {
        if let Err(e) = self.0.remove() {
            eprintln!("[contain] removing {} failed: {e}", self.0.name);
        }
    }
}

impl std::ops::Deref for Machine {
    type Target = MvmSandbox;
    fn deref(&self) -> &MvmSandbox {
        &self.0
    }
}

pub fn fresh_machine(h: &Harness) -> Machine {
    let name = format!("rts-{}", random_hex(6));
    let m = Machine(MvmSandbox::new(&name, Box::new(h.run.clone())).unwrap());
    m.create(&CreateSpec { name: &name, image: &h.image, memory_mib: 512, cpus: 1 }).expect("machine create");
    initialize_guest_storage(&m.0).expect("guest input/output storage");
    m
}

pub fn tempdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rts-{tag}-{}", random_hex(6)));
    fs::create_dir_all(&d).unwrap();
    d
}

/// The options `rts tool` needs for a machine, as the launcher writes them.
pub fn bridge_options(h: &Harness, machine: &str, state_dir: &Path) -> Value {
    json!({
        "machine": machine,
        "mvmctl": h.mvmctl,
        "emptyGitConfig": h.empty_git_config,
        "stateDir": state_dir,
        "timeoutMs": 120_000,
        "maxOutputBytes": 65_536,
        "mvmHome": std::env::var("HOME").unwrap_or_default(),
    })
}

/// One call through the built `rts tool` binary: exactly what the plugin shim spawns.
pub fn rts_tool(options: &Value, tool: &str, input: Value) -> (i32, String, String) {
    let mut p = Command::new(env!("CARGO_BIN_EXE_rts"))
        .args(["tool", tool])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    p.stdin.take().unwrap().write_all(json!({ "options": options, "input": input }).to_string().as_bytes()).unwrap();
    let o = p.wait_with_output().unwrap();
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned(), String::from_utf8_lossy(&o.stderr).into_owned())
}

/// A stand-in for IronWire's OpenAI façade that only answers /models, so a
/// launcher preflight passes without inference.
pub fn fake_ironwire(model: &str) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let body = json!({ "object": "list", "data": [{ "id": model, "object": "model" }] }).to_string();
    thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut s = s;
            let (mut req, mut buf) = (vec![], [0u8; 1024]);
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => req.extend_from_slice(&buf[..n]),
                }
            }
            let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        }
    });
    format!("http://127.0.0.1:{port}/openai/v1")
}

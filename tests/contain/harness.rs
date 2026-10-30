//! Shared setup for the real-mvm suite. Explicitly requested real-VM tests
//! fail when the patched supervisor or mvmctl prerequisites are unavailable.
//! Requested OpenCode tests fail when opencode 2.2.2 is unavailable on PATH
//! (or at RTS_OPENCODE); missing prerequisites never count as validation.

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
use rts::session::{Host, RealHost, OPENCODE_VERSION, SUPERVISOR_FIX_VERSION, initialize_guest_storage, mvm_environment, supervisor_path};
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

fn patched_runner(mvmctl: PathBuf, empty_git_config: PathBuf, env: &[(String, String)], host: &dyn Host) -> Result<SpawnRunner, String> {
    let supervisor = supervisor_path(env, None)?;
    let executable = supervisor.to_str().ok_or("patched supervisor path is not valid UTF-8")?;
    let install = "Run scripts/build-patched-mvm-supervisor.sh or set MVM_HVF_SUPERVISOR_PATH to an absolute patched supervisor path";
    let output = host.run(&[executable.into(), "--rts-vsock-drain-fix-version".into()], Duration::from_secs(5))
        .map_err(|_| format!("Cannot probe the patched supervisor ({SUPERVISOR_FIX_VERSION}). {install}"))?;
    if output.killed || output.code != Some(0)
        || !(output.stdout == SUPERVISOR_FIX_VERSION.as_bytes() || output.stdout == format!("{SUPERVISOR_FIX_VERSION}\n").as_bytes())
    {
        return Err(format!("Containment requires supervisor {SUPERVISOR_FIX_VERSION}. {install}"));
    }
    Ok(SpawnRunner { mvmctl, empty_git_config, extra_env: mvm_environment(env, &supervisor), remove_env: Vec::new() })
}

fn probe() -> Result<Harness, String> {
    let env: Vec<(String, String)> = std::env::vars().collect();
    let home = env.iter().find(|(key, _)| key == "HOME").map(|(_, value)| value.as_str()).unwrap_or_default();
    let mvmctl = std::env::var_os("RTS_MVMCTL").map(PathBuf::from).unwrap_or_else(|| Path::new(&home).join(".local/mvm/v0.22.0/mvmctl"));
    let scratch = std::env::temp_dir().join(format!("rts-contain-{}", random_hex(6)));
    fs::create_dir_all(&scratch).map_err(|e| e.to_string())?;
    let empty_git_config = scratch.join("empty.gitconfig");
    fs::write(&empty_git_config, "").map_err(|e| e.to_string())?;
    let runner = patched_runner(mvmctl.clone(), empty_git_config.clone(), &env, &RealHost)?;
    if !mvmctl.exists() {
        return Err(format!("mvmctl not found at {} (set RTS_MVMCTL)", mvmctl.display()));
    }
    let run: Arc<dyn Runner> = Arc::new(runner);
    let r = run.run(&["doctor".to_string()], Duration::from_secs(60)).map_err(|e| format!("mvmctl doctor could not run: {e}"))?;
    if r.code != Some(0) {
        return Err(format!("mvmctl doctor failed: {}", String::from_utf8_lossy(&r.stderr).trim()));
    }
    let image = std::env::var("RTS_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.into());
    Ok(Harness { mvmctl, image, run, empty_git_config })
}

/// Ignored tests run only by explicit request, so missing prerequisites must fail
/// the test rather than report a successful skip. Keep Option for existing callers.
pub fn mvm() -> Option<&'static Harness> {
    static H: OnceLock<Result<Harness, String>> = OnceLock::new();
    match H.get_or_init(probe) {
        Ok(h) => Some(h),
        Err(why) => panic!("[contain] real-mvm prerequisites failed: {why}"),
    }
}

pub fn opencode() -> Option<String> {
    let oc = std::env::var("RTS_OPENCODE").unwrap_or_else(|_| "opencode".into());
    checked_opencode(oc, &RealHost)
}

fn checked_opencode(oc: String, host: &dyn Host) -> Option<String> {
    let ok = host.run(&[oc.clone(), "--version".into()], Duration::from_secs(30)).is_ok_and(|o| {
        let text = String::from_utf8_lossy(&o.stdout);
        let version = text.split_whitespace().map(|word| word.trim_start_matches('v'))
            .find(|word| word.starts_with(|c: char| c.is_ascii_digit()));
        !o.killed && o.code == Some(0) && version == Some(OPENCODE_VERSION)
    });
    if !ok {
        panic!("[contain] opencode prerequisite failed: {oc} --version must report {OPENCODE_VERSION}; install the pinned version or set RTS_OPENCODE");
    }
    Some(oc)
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
    m.create(&CreateSpec { name: &name, image: &h.image, memory_mib: 512, cpus: 1, egress: None }).expect("machine create");
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

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeHost { output: rts::mvm::RunOutput, calls: std::sync::Mutex<Vec<(Vec<String>, Duration)>> }
    impl Host for FakeHost {
        fn run(&self, argv: &[String], timeout: Duration) -> std::io::Result<rts::mvm::RunOutput> {
            self.calls.lock().unwrap().push((argv.to_vec(), timeout));
            Ok(self.output.clone())
        }
    }

    #[test]
    fn default_and_explicit_supervisors_are_probed_and_forwarded_to_every_vm_command() {
        for override_path in [None, Some("/explicit supervisor/mvm-hvf-supervisor")] {
            let mut env = vec![("HOME".into(), "/operator home".into()), ("MVM_HOME".into(), "/vm state".into())];
            if let Some(path) = override_path { env.push(("MVM_HVF_SUPERVISOR_PATH".into(), path.into())); }
            let selected = supervisor_path(&env, None).unwrap();
            let host = FakeHost { output: rts::mvm::RunOutput { code: Some(0), stdout: b"rts-vsock-drain-v1\n".to_vec(), ..Default::default() }, calls: Default::default() };
            let runner = patched_runner("/fake/mvmctl".into(), "/fake/gitconfig".into(), &env, &host).unwrap();
            assert_eq!(runner.extra_env["MVM_HVF_SUPERVISOR_PATH"], selected.to_str().unwrap());
            assert_eq!(runner.extra_env["HOME"], "/operator home");
            assert_eq!(runner.extra_env["MVM_HOME"], "/vm state");
            assert_eq!(*host.calls.lock().unwrap(), [(vec![selected.to_str().unwrap().into(), "--rts-vsock-drain-fix-version".into()], Duration::from_secs(5))]);
        }
    }

    #[test]
    fn supervisor_probe_rejects_wrong_markers_failures_and_timeouts() {
        for (code, marker, killed) in [(0, "stock", false), (0, "rts-vsock-drain-v1\nextra", false), (1, "rts-vsock-drain-v1\n", false), (0, "rts-vsock-drain-v1\n", true)] {
            let host = FakeHost { output: rts::mvm::RunOutput { code: Some(code), stdout: marker.as_bytes().to_vec(), killed, ..Default::default() }, calls: Default::default() };
            let env = vec![("HOME".into(), "/fake/operator".into())];
            let error = patched_runner("/fake/mvmctl".into(), "/fake/gitconfig".into(), &env, &host).err().expect("must reject supervisor");
            assert!(error.contains(SUPERVISOR_FIX_VERSION), "{error}");
        }
    }

    #[test]
    fn the_pinned_opencode_is_accepted_with_a_bounded_argv_probe() {
        let host = FakeHost { output: rts::mvm::RunOutput { code: Some(0), stdout: b"2.2.2\n".to_vec(), ..Default::default() }, calls: Default::default() };
        let path = "/fake path/opencode";
        assert_eq!(checked_opencode(path.into(), &host), Some(path.into()));
        assert_eq!(*host.calls.lock().unwrap(), [(vec![path.into(), "--version".into()], Duration::from_secs(30))]);
    }

    #[test]
    fn missing_or_wrong_opencode_fails_explicitly_without_running_a_vm() {
        struct MissingHost;
        impl Host for MissingHost {
            fn run(&self, _: &[String], _: Duration) -> std::io::Result<rts::mvm::RunOutput> {
                Err(std::io::Error::new(std::io::ErrorKind::NotFound, "missing opencode"))
            }
        }
        assert!(std::panic::catch_unwind(|| checked_opencode("/fake/opencode".into(), &MissingHost)).is_err(), "missing opencode must fail the requested test");
        for (code, version, killed) in [(0, "2.2.0\n", false), (0, "2.2.20\n", false), (1, "2.2.2\n", false), (0, "2.2.2\n", true)] {
            let host = FakeHost { output: rts::mvm::RunOutput { code: Some(code), stdout: version.as_bytes().to_vec(), killed, ..Default::default() }, calls: Default::default() };
            assert!(std::panic::catch_unwind(|| checked_opencode("/fake/opencode".into(), &host)).is_err(), "wrong opencode {version:?} must fail the requested test");
        }
    }

    #[test]
    fn explicitly_requested_real_vm_test_fails_without_the_patched_supervisor() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["exec::a_nonzero_exit_is_reported_and_does_not_poison_the_machine", "--exact", "--ignored", "--nocapture"])
            .env("MVM_HVF_SUPERVISOR_PATH", "/nonexistent-rts-supervisor")
            .env("RTS_MVMCTL", "/nonexistent-rts-mvmctl")
            .output().unwrap();
        assert!(!output.status.success(), "an explicitly requested real-VM test passed without running: {}", String::from_utf8_lossy(&output.stdout));
        let diagnostic = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        assert!(diagnostic.contains(SUPERVISOR_FIX_VERSION), "{diagnostic}");
    }
}

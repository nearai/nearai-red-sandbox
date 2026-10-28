//! MvmSandbox: the v1 Sandbox backend. Shells out to mvmctl v0.22.0 with
//! argv only; nothing goes through a host shell.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use crate::copy::{CopyLimits, copy_in_via, copy_out_via};
use crate::protocol::{WrapOptions, is_poisoned, new_nonce, parse_result, wrap_argv};
use crate::sandbox::{CopyOutResult, CreateSpec, Error, Exec, ExecOptions, ExecResult, Result, Sandbox, sv};

/// Host backstop on top of the guest-side limit. If it fires, the exec
/// client was killed from the host, which poisons the machine.
pub const BACKSTOP: Duration = Duration::from_secs(30);
/// Lifecycle commands (create, start, rm, ps) get this long.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(180);
/// Never buffer more than this from one mvmctl stream, whatever the guest does.
const MAX_CAPTURE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub struct RunOutput {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub killed: bool,
}

pub trait Runner: Send + Sync {
    fn run(&self, argv: &[String], timeout: Duration) -> io::Result<RunOutput>;
}

impl<R: Runner + ?Sized> Runner for std::sync::Arc<R> {
    fn run(&self, argv: &[String], timeout: Duration) -> io::Result<RunOutput> {
        (**self).run(argv, timeout)
    }
}

pub fn is_machine_name(name: &str) -> bool {
    name.len() == 16
        && name.starts_with("rts-")
        && name[4..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `^[a-z0-9./-]+@sha256:[0-9a-f]{64}$`
pub fn is_image_ref(image: &str) -> bool {
    let Some((name, digest)) = image.split_once("@sha256:") else { return false };
    !name.is_empty()
        && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"./-".contains(&b))
        && digest.len() == 64
        && digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn read_capped(mut r: impl Read, cap: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => break,
            // Keep draining past the cap so the child never blocks.
            Ok(n) => {
                let room = cap.saturating_sub(out.len());
                out.extend_from_slice(&buf[..n.min(room)]);
            }
        }
    }
    out
}

/// Runs mvmctl with stdin from /dev/null, argv only, and
/// GIT_CONFIG_GLOBAL pointed at an empty file.
pub struct SpawnRunner {
    pub mvmctl: PathBuf,
    pub empty_git_config: PathBuf,
    pub extra_env: HashMap<String, String>,
}

impl Runner for SpawnRunner {
    fn run(&self, argv: &[String], timeout: Duration) -> io::Result<RunOutput> {
        let mut cmd = Command::new(&self.mvmctl);
        cmd.args(argv).envs(&self.extra_env).env("GIT_CONFIG_GLOBAL", &self.empty_git_config);
        run_captured(cmd, timeout)
    }
}

/// Run a host command with stdin from /dev/null in its own process group,
/// capture at most 16 MiB of each stream, and kill the whole group at the
/// deadline.
pub fn run_captured(mut cmd: Command, timeout: Duration) -> io::Result<RunOutput> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Own process group, so a timeout kills the command and anything it started.
        .process_group(0)
        .spawn()?;
    let pgid = child.id() as i32;
    let out = child.stdout.take().unwrap();
    let err = child.stderr.take().unwrap();
    let t_out = thread::spawn(move || read_capped(out, MAX_CAPTURE_BYTES));
    let t_err = thread::spawn(move || read_capped(err, MAX_CAPTURE_BYTES));
    let deadline = Instant::now() + timeout;
    let mut killed = false;
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if Instant::now() >= deadline {
            killed = true;
            crate::sys::send_signal(-pgid, crate::sys::SIGKILL);
            let _ = child.kill();
            break child.wait()?;
        }
        thread::sleep(Duration::from_millis(20));
    };
    let stdout = t_out.join().unwrap_or_default();
    let stderr = t_err.join().unwrap_or_default();
    Ok(RunOutput { code: if killed { None } else { status.code() }, stdout, stderr, killed })
}

pub(crate) fn tail(b: &[u8]) -> String {
    let t = String::from_utf8_lossy(b);
    let lines: Vec<&str> = t.trim().lines().collect();
    let s = lines[lines.len().saturating_sub(3)..].join(" | ");
    s.chars().take(500).collect()
}

fn ps_names(text: &str) -> Vec<String> {
    text.split_whitespace().map(String::from).collect()
}

/// Machine names from `machine ps`, restricted to ones this harness creates.
pub fn list_machines(run: &dyn Runner) -> Result<Vec<String>> {
    let r = run.run(&sv(&["machine", "ps"]), CONTROL_TIMEOUT).map_err(|e| Error::Other(format!("machine ps failed: {e}")))?;
    if r.code != Some(0) {
        return Err(Error::Other(format!("machine ps failed: {}", tail(&r.stderr))));
    }
    Ok(ps_names(&String::from_utf8_lossy(&r.stdout)).into_iter().filter(|n| is_machine_name(n)).collect())
}

/// Shared between the launcher and every tool-bridge process for one
/// session: an exec lock, so one exec reaches the machine at a time, and an
/// "unavailable" marker, so a poisoned or torn-down machine refuses every
/// later call from any process.
#[derive(Debug, Clone)]
pub struct StateDir(pub PathBuf);

impl StateDir {
    fn marker(&self) -> PathBuf {
        self.0.join("unavailable")
    }
    pub fn dead_reason(&self) -> Option<String> {
        fs::read_to_string(self.marker()).ok().map(|s| if s.is_empty() { "unavailable".into() } else { s })
    }
    pub fn mark(&self, reason: &str) {
        let _ = fs::create_dir_all(&self.0);
        if !self.marker().exists() {
            let _ = fs::write(self.marker(), reason);
        }
    }
    fn lock(&self) -> io::Result<File> {
        fs::create_dir_all(&self.0)?;
        let f = OpenOptions::new().create(true).truncate(false).write(true).open(self.0.join("exec.lock"))?;
        f.lock()?;
        Ok(f)
    }
}

pub struct MvmSandbox {
    pub name: String,
    run: Box<dyn Runner>,
    state: Option<StateDir>,
    dead: Mutex<Option<String>>,
    serial: Mutex<()>,
    copy_limits: CopyLimits,
}

impl MvmSandbox {
    pub fn new(name: &str, run: Box<dyn Runner>) -> Result<Self> {
        if !is_machine_name(name) {
            return Err(Error::Other(format!("machine name must match rts-<12 hex chars>: {name:?}")));
        }
        Ok(Self { name: name.into(), run, state: None, dead: Mutex::new(None), serial: Mutex::new(()), copy_limits: CopyLimits::default() })
    }

    /// Share the exec lock and the unavailable marker through a directory.
    pub fn with_state(mut self, dir: StateDir) -> Self {
        self.state = Some(dir);
        self
    }

    pub fn with_copy_limits(mut self, l: CopyLimits) -> Self {
        self.copy_limits = l;
        self
    }

    pub fn unavailable(&self) -> bool {
        self.dead_reason().is_some()
    }

    fn dead_reason(&self) -> Option<String> {
        if let Some(r) = self.dead.lock().unwrap().clone() {
            return Some(r);
        }
        self.state.as_ref().and_then(|s| s.dead_reason())
    }

    fn mark_unavailable(&self, reason: &str) -> Error {
        let mut d = self.dead.lock().unwrap();
        if d.is_none() {
            *d = Some(self.state.as_ref().and_then(|s| s.dead_reason()).unwrap_or_else(|| reason.into()));
        }
        if let Some(s) = &self.state {
            s.mark(reason);
        }
        Error::Unavailable(d.clone().unwrap())
    }

    fn control(&self, argv: &[String], what: &str) -> Result<RunOutput> {
        let r = self.run.run(argv, CONTROL_TIMEOUT).map_err(|e| Error::Other(format!("{what} failed: {e}")))?;
        if r.killed {
            return Err(Error::Other(format!("{what} timed out")));
        }
        if r.code != Some(0) {
            let t = tail(&r.stderr);
            return Err(Error::Other(format!("{what} failed: {}", if t.is_empty() { format!("exit {:?}", r.code) } else { t })));
        }
        Ok(r)
    }
}

impl Exec for MvmSandbox {
    fn exec(&self, argv: &[String], o: &ExecOptions) -> Result<ExecResult> {
        if let Some(r) = self.dead_reason() {
            return Err(Error::Unavailable(r));
        }
        // One exec at a time per machine: mvm journals each exec, and a
        // poisoned machine must stop every queued call from reaching it.
        let _guard = self.serial.lock().unwrap();
        let _file_lock = match &self.state {
            Some(s) => Some(s.lock().map_err(|e| Error::Other(format!("exec lock: {e}")))?),
            None => None,
        };
        if let Some(r) = self.dead_reason() {
            return Err(Error::Unavailable(r));
        }
        let nonce = new_nonce();
        let timeout_sec = o.timeout_ms.div_ceil(1000).max(1);
        let wrapped = wrap_argv(argv, &WrapOptions { nonce: &nonce, timeout_sec, max_output_bytes: o.max_output_bytes, workdir: o.workdir.as_deref() })
            .map_err(Error::Other)?;
        let mut full = sv(&["machine", "exec", &self.name, "--"]);
        full.extend(wrapped);
        let r = match self.run.run(&full, Duration::from_secs(timeout_sec) + BACKSTOP) {
            Ok(r) => r,
            Err(e) => return Err(self.mark_unavailable(&format!("mvmctl exec failed to run: {e}"))),
        };
        if let Some(r) = self.dead_reason() {
            return Err(Error::Unavailable(r)); // torn down mid-exec
        }
        if r.killed {
            return Err(self.mark_unavailable("exec exceeded the host backstop; machine is lost"));
        }
        let parsed = parse_result(&r.stdout, &r.stderr, &nonce);
        match (parsed, r.code) {
            (Some(p), Some(0)) => Ok(p),
            (parsed, code) => {
                if is_poisoned(&String::from_utf8_lossy(&r.stderr)) {
                    Err(self.mark_unavailable("machine refused exec (no durable finish)"))
                } else if parsed.is_none() {
                    Err(self.mark_unavailable(&format!("exec returned no valid trailer (mvmctl exit {code:?})")))
                } else {
                    Err(self.mark_unavailable(&format!("mvmctl exec exited {code:?}")))
                }
            }
        }
    }
}

impl Sandbox for MvmSandbox {
    fn create(&self, spec: &CreateSpec) -> Result<()> {
        if spec.name != self.name {
            return Err(Error::Other(format!("create name {} does not match sandbox {}", spec.name, self.name)));
        }
        if !is_image_ref(spec.image) {
            return Err(Error::Other(format!("image must be digest-pinned: {:?}", spec.image)));
        }
        if spec.cpus < 1 || spec.memory_mib < 64 {
            return Err("cpus must be at least 1 and memory at least 64 MiB".into());
        }
        if let Some(r) = self.dead_reason() {
            return Err(Error::Unavailable(r));
        }
        let (cpus, mem) = (spec.cpus.to_string(), format!("{}M", spec.memory_mib));
        self.control(
            &sv(&["machine", "create", &self.name, "--image", spec.image, "--profile", "dev", "--cpus", &cpus, "--memory", &mem]),
            "machine create",
        )?;
        self.control(&sv(&["machine", "start", &self.name]), "machine start")?;
        Ok(())
    }

    fn copy_in(&self, host_dir: &Path, guest_dir: &str) -> Result<()> {
        copy_in_via(self, host_dir, guest_dir)
    }

    /// Treats the guest as hostile; see copy.rs and untar.rs.
    fn copy_out(&self, guest_dir: &str, host_dir: &Path) -> Result<CopyOutResult> {
        copy_out_via(self, guest_dir, host_dir, &self.copy_limits)
    }

    fn remove(&self) -> Result<()> {
        self.mark_unavailable("sandbox removed");
        let rm = self.run.run(&sv(&["machine", "rm", &self.name, "--force", "--yes"]), CONTROL_TIMEOUT);
        let ps = self.control(&sv(&["machine", "ps"]), "machine ps after rm")?;
        if ps_names(&String::from_utf8_lossy(&ps.stdout)).contains(&self.name) {
            let detail = match rm {
                Ok(r) if r.code != Some(0) => format!(" (rm: {})", tail(&r.stderr)),
                Err(e) => format!(" (rm: {e})"),
                _ => String::new(),
            };
            return Err(Error::Other(format!("machine still present after rm: {}{detail}", self.name)));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::wrap_argv;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const NAME: &str = "rts-0123456789ab";
    const IMAGE: &str = "docker.io/library/alpine@sha256:e311ae748be7f56ae5cba304bc488f0786df68ee507513f654a5cc8597cffb42";

    type Reply = Box<dyn Fn(&[String]) -> RunOutput + Send + Sync>;
    struct Fake {
        calls: Arc<Mutex<Vec<(Vec<String>, Duration)>>>,
        reply: Reply,
    }
    impl Runner for Fake {
        fn run(&self, argv: &[String], t: Duration) -> io::Result<RunOutput> {
            self.calls.lock().unwrap().push((argv.to_vec(), t));
            Ok((self.reply)(argv))
        }
    }
    fn fake(reply: impl Fn(&[String]) -> RunOutput + Send + Sync + 'static) -> (Box<Fake>, Arc<Mutex<Vec<(Vec<String>, Duration)>>>) {
        let calls = Arc::new(Mutex::new(vec![]));
        (Box::new(Fake { calls: calls.clone(), reply: Box::new(reply) }), calls)
    }
    fn out(code: i32, stdout: &str, stderr: &str) -> RunOutput {
        RunOutput { code: Some(code), stdout: stdout.into(), stderr: stderr.into(), killed: false }
    }
    // For `machine exec`, argv[8] is the nonce.
    fn trailer(argv: &[String], status: u32, o: u64, e: u64) -> String {
        format!("\nRTS_EXIT_{} {status} {o} {e}\n", argv[8])
    }
    fn opts() -> ExecOptions {
        ExecOptions::new(120_000, 65536)
    }
    fn argvs(c: &Arc<Mutex<Vec<(Vec<String>, Duration)>>>) -> Vec<Vec<String>> {
        c.lock().unwrap().iter().map(|(a, _)| a.clone()).collect()
    }
    const FORBIDDEN: [&str; 4] = ["--net", "--allow-host", "--peer", "--gpu"];

    #[test]
    fn create_issues_exact_lines_and_no_network_flag() {
        let (f, calls) = fake(|_| out(0, "", ""));
        let sb = MvmSandbox::new(NAME, f).unwrap();
        sb.create(&CreateSpec { name: NAME, image: IMAGE, memory_mib: 2048, cpus: 2 }).unwrap();
        assert_eq!(
            argvs(&calls),
            vec![
                sv(&["machine", "create", NAME, "--image", IMAGE, "--profile", "dev", "--cpus", "2", "--memory", "2048M"]),
                sv(&["machine", "start", NAME]),
            ]
        );
        for a in argvs(&calls) {
            for flag in FORBIDDEN {
                assert!(!a.contains(&flag.to_string()));
            }
        }
    }

    #[test]
    fn create_refuses_unpinned_image_and_runs_nothing() {
        let (f, calls) = fake(|_| out(0, "", ""));
        let sb = MvmSandbox::new(NAME, f).unwrap();
        for img in ["alpine:latest", "Error: no such image", "Alpine@sha256:00"] {
            let e = sb.create(&CreateSpec { name: NAME, image: img, memory_mib: 2048, cpus: 2 }).unwrap_err();
            assert!(e.to_string().contains("image must be digest-pinned"));
        }
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn create_refuses_other_name_and_reports_failures() {
        let (f, calls) = fake(|a| if a[1] == "start" { out(1, "", "bad image") } else { out(0, "", "") });
        let sb = MvmSandbox::new(NAME, f).unwrap();
        assert!(sb.create(&CreateSpec { name: "rts-ffffffffffff", image: IMAGE, memory_mib: 2048, cpus: 2 }).is_err());
        assert!(calls.lock().unwrap().is_empty());
        let e = sb.create(&CreateSpec { name: NAME, image: IMAGE, memory_mib: 2048, cpus: 2 }).unwrap_err();
        assert_eq!(e.to_string(), "machine start failed: bad image");
    }

    #[test]
    fn machine_names() {
        assert!(is_machine_name(NAME));
        for bad in ["web", "-rf", "rts-0123456789AB", "rts-0123456789a", "rts-0123456789abc"] {
            assert!(!is_machine_name(bad), "{bad}");
            assert!(MvmSandbox::new(bad, fake(|_| out(0, "", "")).0).is_err());
        }
    }

    #[test]
    fn exec_sends_wrapped_argv_and_returns_parsed() {
        let (f, calls) = fake(|a| out(0, "ok\n", &trailer(a, 0, 3, 0)));
        let sb = MvmSandbox::new(NAME, f).unwrap();
        let r = sb.exec(&sv(&["true"]), &opts()).unwrap();
        let (sent, t) = calls.lock().unwrap()[0].clone();
        let nonce = sent[8].clone();
        let mut want = sv(&["machine", "exec", NAME, "--"]);
        want.extend(wrap_argv(&sv(&["true"]), &WrapOptions { nonce: &nonce, timeout_sec: 120, max_output_bytes: 65536, workdir: None }).unwrap());
        assert_eq!(sent, want);
        assert_eq!(t, Duration::from_secs(150));
        assert_eq!(r.stdout, b"ok\n");
        assert_eq!((r.exit_code, r.stdout_bytes, r.truncated), (0, 3, false));
    }

    #[test]
    fn fresh_nonce_workdir_and_rounding() {
        let (f, calls) = fake(|a| out(0, "", &trailer(a, 0, 0, 0)));
        let sb = MvmSandbox::new(NAME, f).unwrap();
        sb.exec(&sv(&["true"]), &ExecOptions { workdir: Some("/in".into()), ..opts() }).unwrap();
        sb.exec(&sv(&["true"]), &ExecOptions::new(1, 10)).unwrap();
        let a = argvs(&calls);
        assert_ne!(a[0][8], a[1][8]);
        assert_eq!(a[0][11], "/in");
        assert_eq!(a[1][9], "1");
    }

    fn assert_dead_after_first(reply: impl Fn(&[String]) -> RunOutput + Send + Sync + 'static) {
        let (f, calls) = fake(reply);
        let sb = MvmSandbox::new(NAME, f).unwrap();
        assert!(matches!(sb.exec(&sv(&["true"]), &opts()), Err(Error::Unavailable(_))));
        assert!(sb.unavailable());
        let e = sb.exec(&sv(&["true"]), &opts()).unwrap_err();
        assert!(e.to_string().starts_with("sandbox unavailable"));
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn poisoned_machine_is_unavailable_for_good() {
        assert_dead_after_first(|_| out(1, "", "Error: machine input sequence 1 has no durable finish; refuse exec and checkpoint"));
    }

    #[test]
    fn no_valid_trailer_is_unavailable() {
        assert_dead_after_first(|_| out(0, "hi", &format!("\nRTS_EXIT_{} 0 2 0\n", "0".repeat(24))));
    }

    #[test]
    fn nonzero_mvmctl_exit_is_unavailable_even_with_trailer() {
        assert_dead_after_first(|a| out(2, "", &trailer(a, 0, 0, 0)));
    }

    #[test]
    fn host_backstop_kill_is_unavailable() {
        assert_dead_after_first(|_| RunOutput { code: None, killed: true, ..Default::default() });
    }

    #[test]
    fn guest_stderr_mentioning_poison_text_is_fine() {
        let (f, _) = fake(|a| out(0, "", &format!("grep: no durable finish{}", trailer(a, 0, 0, 23))));
        let sb = MvmSandbox::new(NAME, f).unwrap();
        assert_eq!(sb.exec(&sv(&["true"]), &opts()).unwrap().exit_code, 0);
        assert!(!sb.unavailable());
    }

    #[test]
    fn runner_error_is_unavailable() {
        struct Broken;
        impl Runner for Broken {
            fn run(&self, _: &[String], _: Duration) -> io::Result<RunOutput> {
                Err(io::Error::other("spawn failed"))
            }
        }
        let sb = MvmSandbox::new(NAME, Box::new(Broken)).unwrap();
        assert!(matches!(sb.exec(&sv(&["true"]), &opts()), Err(Error::Unavailable(_))));
    }

    #[test]
    fn execs_are_serialized() {
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max = Arc::new(AtomicUsize::new(0));
        let (i, m) = (in_flight.clone(), max.clone());
        let (f, calls) = fake(move |a| {
            let now = i.fetch_add(1, Ordering::SeqCst) + 1;
            m.fetch_max(now, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(5));
            i.fetch_sub(1, Ordering::SeqCst);
            out(0, "", &trailer(a, 0, 0, 0))
        });
        let sb = Arc::new(MvmSandbox::new(NAME, f).unwrap());
        let hs: Vec<_> = (0..3).map(|_| { let s = sb.clone(); thread::spawn(move || s.exec(&sv(&["x"]), &opts()).unwrap()) }).collect();
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(max.load(Ordering::SeqCst), 1);
        assert_eq!(calls.lock().unwrap().len(), 3);
    }

    #[test]
    fn remove_force_removes_confirms_and_kills_later_execs() {
        let (f, calls) = fake(|a| if a[1] == "ps" { out(0, "NAME STATUS\nweb running\n", "") } else { out(0, "", "") });
        let sb = MvmSandbox::new(NAME, f).unwrap();
        sb.remove().unwrap();
        assert_eq!(argvs(&calls), vec![sv(&["machine", "rm", NAME, "--force", "--yes"]), sv(&["machine", "ps"])]);
        assert!(matches!(sb.exec(&sv(&["true"]), &opts()), Err(Error::Unavailable(_))));
        assert_eq!(calls.lock().unwrap().len(), 2);
    }

    #[test]
    fn remove_fails_when_ps_still_lists_it() {
        let (f, _) = fake(|a| if a[1] == "ps" { out(0, &format!("NAME STATUS\n{NAME} running\n"), "") } else { out(0, "", "") });
        let e = MvmSandbox::new(NAME, f).unwrap().remove().unwrap_err();
        assert!(e.to_string().contains("machine still present"));
    }

    #[test]
    fn state_dir_shares_unavailability_across_instances() {
        let dir = crate::testutil::tempdir("state");
        let (f1, _) = fake(|_| out(1, "", "no durable finish"));
        let a = MvmSandbox::new(NAME, f1).unwrap().with_state(StateDir(dir.clone()));
        assert!(a.exec(&sv(&["true"]), &opts()).is_err());
        // A second process attaching to the same machine refuses without running anything.
        let (f2, calls2) = fake(|a| out(0, "", &trailer(a, 0, 0, 0)));
        let b = MvmSandbox::new(NAME, f2).unwrap().with_state(StateDir(dir.clone()));
        let e = b.exec(&sv(&["true"]), &opts()).unwrap_err();
        assert!(e.to_string().contains("no durable finish"));
        assert!(calls2.lock().unwrap().is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn teardown_marker_refuses_tool_calls_from_other_processes() {
        let dir = crate::testutil::tempdir("state");
        StateDir(dir.clone()).mark("sandbox removed");
        let (f, calls) = fake(|a| out(0, "", &trailer(a, 0, 0, 0)));
        let sb = MvmSandbox::new(NAME, f).unwrap().with_state(StateDir(dir.clone()));
        assert_eq!(sb.exec(&sv(&["true"]), &opts()).unwrap_err().to_string(), "sandbox unavailable: sandbox removed");
        assert!(calls.lock().unwrap().is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn list_machines_filters_rts_names() {
        let (f, _) = fake(|_| out(0, "NAME STATUS\nrts-aaaaaaaaaaaa running\nweb stopped\nrts-short x\nrts-bbbbbbbbbbbb stopped\n", ""));
        assert_eq!(list_machines(f.as_ref()).unwrap(), sv(&["rts-aaaaaaaaaaaa", "rts-bbbbbbbbbbbb"]));
    }

    #[test]
    fn spawn_runner_captures_and_kills_on_timeout() {
        let r = SpawnRunner { mvmctl: "/bin/sh".into(), empty_git_config: "/dev/null".into(), extra_env: HashMap::new() };
        let o = r.run(&sv(&["-c", "echo $GIT_CONFIG_GLOBAL; echo e >&2; exit 4"]), Duration::from_secs(5)).unwrap();
        assert_eq!((o.code, o.stdout.as_slice(), o.stderr.as_slice(), o.killed), (Some(4), &b"/dev/null\n"[..], &b"e\n"[..], false));
        let t = Instant::now();
        let o = r.run(&sv(&["-c", "sleep 10"]), Duration::from_millis(200)).unwrap();
        assert!(o.killed && o.code.is_none() && t.elapsed() < Duration::from_secs(5));
    }
}

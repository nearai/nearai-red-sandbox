//! MvmSandbox: the v1 Sandbox backend. Shells out to mvmctl v0.22.0 with
//! argv only; nothing goes through a host shell.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
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
/// `--ttl` for the attached `machine run`: the session's wall-clock limit
/// (`limits.sessionHours`, at most mvm v0.22.0's inclusive 30-day MAX_TTL).
pub fn attach_ttl(hours: u32) -> String {
    format!("{hours}h")
}
/// How often create polls `machine ps` while a network machine boots.
const BOOT_POLL: Duration = Duration::from_millis(500);
/// How long remove gives the attached run between SIGTERM and SIGKILL.
const ATTACH_GRACE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Default)]
pub struct RunOutput {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub killed: bool,
}

/// A background mvmctl process that rts holds for the life of a machine
/// (`machine run` for a network machine, tinylabscom/mvm#4860).
pub trait Attached: Send {
    fn pid(&self) -> u32;
    /// `Some(status)` once the process has exited, and on every later call.
    fn exited(&mut self) -> Option<String>;
    /// SIGTERM, up to `grace` to exit, then SIGKILL; reaps it.
    fn terminate(&mut self, grace: Duration);
}

pub trait Runner: Send + Sync {
    fn run(&self, argv: &[String], timeout: Duration) -> io::Result<RunOutput>;
    /// Start mvmctl in the background with stdout and stderr appended to
    /// `log`. Runners that cannot do this refuse.
    fn attach(&self, argv: &[String], log: &Path) -> io::Result<Box<dyn Attached>> {
        let _ = (argv, log);
        Err(io::Error::new(io::ErrorKind::Unsupported, "this runner cannot start an attached mvmctl"))
    }
}

impl<R: Runner + ?Sized> Runner for std::sync::Arc<R> {
    fn run(&self, argv: &[String], timeout: Duration) -> io::Result<RunOutput> {
        (**self).run(argv, timeout)
    }
    fn attach(&self, argv: &[String], log: &Path) -> io::Result<Box<dyn Attached>> {
        (**self).attach(argv, log)
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
/// GIT_CONFIG_GLOBAL pointed at an empty file. The child inherits the
/// environment of rts plus `extra_env`, minus every name in `remove_env`.
pub struct SpawnRunner {
    pub mvmctl: PathBuf,
    pub empty_git_config: PathBuf,
    pub extra_env: HashMap<String, String>,
    pub remove_env: Vec<String>,
}

impl SpawnRunner {
    /// The mvmctl command for `argv`, before stdio and spawning.
    pub fn command(&self, argv: &[String]) -> Command {
        let mut cmd = Command::new(&self.mvmctl);
        cmd.args(argv).envs(&self.extra_env).env("GIT_CONFIG_GLOBAL", &self.empty_git_config);
        // Last, so a removed name wins over both the parent and extra_env.
        for name in &self.remove_env {
            cmd.env_remove(name);
        }
        cmd
    }
}

impl Runner for SpawnRunner {
    fn run(&self, argv: &[String], timeout: Duration) -> io::Result<RunOutput> {
        run_captured(self.command(argv), timeout)
    }

    /// Same environment as `run`, stdin from /dev/null, both streams to a
    /// 0600 log, and its own process group so the operator's Ctrl-C never
    /// reaches it.
    fn attach(&self, argv: &[String], log: &Path) -> io::Result<Box<dyn Attached>> {
        let file = crate::sys::fs::open_private(log, crate::sys::fs::Create::Append)?;
        // The owner-only mode above applies only to a new file.
        crate::sys::fs::restrict_file(&file)?;
        let mut cmd = self.command(argv);
        cmd.stdin(Stdio::null()).stdout(Stdio::from(file.try_clone()?)).stderr(Stdio::from(file));
        let child = crate::sys::own_process_group(&mut cmd).spawn()?;
        Ok(Box::new(SpawnedAttach { child, status: None }))
    }
}

/// A spawned attached mvmctl, leader of its own process group.
struct SpawnedAttach {
    child: Child,
    status: Option<String>,
}

impl Attached for SpawnedAttach {
    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn exited(&mut self) -> Option<String> {
        if self.status.is_none() {
            self.status = match self.child.try_wait() {
                Ok(Some(s)) => Some(s.to_string()),
                Ok(None) => None,
                // Cannot tell: fail closed and treat it as gone.
                Err(e) => Some(format!("wait failed: {e}")),
            };
        }
        self.status.clone()
    }

    fn terminate(&mut self, grace: Duration) {
        // Once reaped, its pid (and so its group id) may belong to someone
        // else: signal the group only while the leader is unreaped.
        if self.exited().is_some() {
            return;
        }
        let pgid = self.child.id();
        crate::sys::signal_group(pgid, crate::sys::SIGTERM);
        let deadline = Instant::now() + grace;
        while Instant::now() < deadline {
            if self.exited().is_some() {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        crate::sys::signal_group(pgid, crate::sys::SIGKILL);
        let _ = self.child.kill();
        self.status = Some(match self.child.wait() {
            Ok(s) => s.to_string(),
            Err(e) => format!("wait failed: {e}"),
        });
    }
}

/// Run a host command with stdin from /dev/null in its own process group,
/// capture at most 16 MiB of each stream, and kill the whole group at the
/// deadline.
pub fn run_captured(mut cmd: Command, timeout: Duration) -> io::Result<RunOutput> {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    // Own process group, so a timeout kills the command and anything it started.
    let mut child = crate::sys::own_process_group(&mut cmd).spawn()?;
    let pgid = child.id();
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
            crate::sys::signal_group(pgid, crate::sys::SIGKILL);
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

/// Whether `machine ps` lists `name` as running: a line whose first field
/// is the name and which says `running`.
/// Whether `log`, from byte `offset` on, has a line starting with `prefix`.
fn log_has_line_from(log: &Path, offset: u64, prefix: &str) -> bool {
    use std::io::{Seek, SeekFrom};
    let Ok(mut f) = File::open(log) else { return false };
    let mut text = String::new();
    if f.seek(SeekFrom::Start(offset)).is_err() || f.take(1 << 20).read_to_string(&mut text).is_err() {
        return false;
    }
    text.lines().any(|l| l.starts_with(prefix))
}

fn ps_running(text: &str, name: &str) -> bool {
    text.lines().any(|l| l.split_whitespace().next() == Some(name) && l.contains("running"))
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
    /// Stop queued tools and wait for an active exec to finish before export.
    /// Holding the returned lock keeps teardown serialized with every bridge.
    pub fn quiesce(&self, timeout: Duration) -> io::Result<File> {
        fs::create_dir_all(&self.0)?;
        if !self.marker().exists() {
            fs::write(self.marker(), "session ended")?;
        }
        let f = OpenOptions::new().create(true).truncate(false).write(true).open(self.0.join("exec.lock"))?;
        let deadline = Instant::now() + timeout;
        loop {
            match f.try_lock() {
                Ok(()) => return Ok(f),
                Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                Err(std::fs::TryLockError::WouldBlock) => return Err(io::Error::new(io::ErrorKind::TimedOut, "active tool did not finish before teardown deadline")),
                Err(std::fs::TryLockError::Error(e)) => return Err(e),
            }
        }
    }

    pub(crate) fn lock(&self) -> io::Result<File> {
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
    /// The attached `machine run` of a network machine, held from spawn
    /// until `remove` terminates it.
    attach: Mutex<Option<Box<dyn Attached>>>,
    launch: Launch,
}

/// How create waits for a network machine's attached `machine run` to boot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Launch {
    /// Poll `machine ps` until it shows the machine running (mvm 0.22, HVF).
    #[default]
    PollPs,
    /// mvm 0.28 (Firecracker): a `machine ps` between run's start and its
    /// TTL step makes run fail ("machine is not registered") and exit, so
    /// wait for run's own `attached to machine <name>;` line, then one
    /// `machine ps`, the TTL read back from `registry` (mvm's
    /// `share/vm-names.json`; the entry's `vm_dir` must be `vm_dir`), and
    /// the run still alive.
    AttachLine { registry: PathBuf, vm_dir: PathBuf },
}

/// The keys of a `vm-names.json` entry as mvm 0.28.0-rts.2 writes them. A
/// registry with any other shape is read as "no TTL".
pub(crate) const REGISTRY_ENTRY_KEYS: [&str; 11] = [
    "vm_dir", "network", "guest_ip", "slot_index", "registered_at", "expires_at",
    "auto_resume", "paused", "readiness", "last_readiness_change_at", "last_active",
];

/// The TTL mvm recorded for `name` in `registry_text` (`vm-names.json`),
/// read strictly: `{"vms": {...}}` and nothing else at the top, an entry
/// with exactly [`REGISTRY_ENTRY_KEYS`], `vm_dir` equal to `vm_dir`, and an
/// `expires_at` of the form `YYYY-MM-DDTHH:MM:SSZ` after `now` and at most
/// `session_hours` (plus a minute of clock slack) from it.
pub(crate) fn registry_expiry(registry_text: &str, name: &str, vm_dir: &Path, now: chrono::DateTime<chrono::Utc>, session_hours: u32) -> std::result::Result<chrono::DateTime<chrono::Utc>, String> {
    let no_ttl = |why: String| format!("no TTL backstop recorded for {name}: {why}");
    let v: serde_json::Value = serde_json::from_str(registry_text).map_err(|e| no_ttl(format!("the mvm registry is not JSON: {e}")))?;
    let top = v.as_object().filter(|o| o.len() == 1).ok_or_else(|| no_ttl("the mvm registry is not {\"vms\": {...}}".into()))?;
    let entry = top.get("vms").and_then(|v| v.as_object()).ok_or_else(|| no_ttl("the mvm registry has no vms object".into()))?
        .get(name).and_then(|e| e.as_object()).ok_or_else(|| no_ttl("the machine is not in the mvm registry".into()))?;
    let mut keys: Vec<&str> = entry.keys().map(String::as_str).collect();
    let mut known = REGISTRY_ENTRY_KEYS.to_vec();
    keys.sort_unstable();
    known.sort_unstable();
    if keys != known {
        return Err(no_ttl(format!("the registry entry has keys {keys:?}, not mvm 0.28's {known:?}")));
    }
    if entry.get("vm_dir").and_then(|d| d.as_str()).map(Path::new) != Some(vm_dir) {
        return Err(no_ttl(format!("the registry entry's vm_dir is not {}", vm_dir.display())));
    }
    let raw = entry.get("expires_at").and_then(|e| e.as_str()).ok_or_else(|| no_ttl("expires_at is not a timestamp".into()))?;
    let expires = chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%SZ")
        .map_err(|_| no_ttl(format!("expires_at {raw:?} is not YYYY-MM-DDTHH:MM:SSZ")))?
        .and_utc();
    let latest = now + chrono::Duration::hours(i64::from(session_hours)) + chrono::Duration::minutes(1);
    if expires <= now || expires > latest {
        return Err(no_ttl(format!("expires_at {raw} is not within {session_hours}h from now")));
    }
    Ok(expires)
}

impl MvmSandbox {
    pub fn new(name: &str, run: Box<dyn Runner>) -> Result<Self> {
        if !is_machine_name(name) {
            return Err(Error::Other(format!("machine name must match rts-<12 hex chars>: {name:?}")));
        }
        Ok(Self { name: name.into(), run, state: None, dead: Mutex::new(None), serial: Mutex::new(()), copy_limits: CopyLimits::default(), attach: Mutex::new(None), launch: Launch::default() })
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

    pub fn with_launch(mut self, l: Launch) -> Self {
        self.launch = l;
        self
    }

    /// The pid of the held attached `machine run`, if any.
    pub fn attach_pid(&self) -> Option<u32> {
        self.attach.lock().unwrap().as_ref().map(|a| a.pid())
    }

    /// `Some` once a held attached `machine run` has exited: the network
    /// path for this machine is gone, and so is the session.
    pub fn network_lost(&self) -> Option<String> {
        let mut a = self.attach.lock().unwrap();
        let status = a.as_mut()?.exited()?;
        Some(format!("network-lost: mvmctl machine run exited ({status})"))
    }

    /// Start the attached `machine run` and wait for it, as `launch` says.
    fn attached_start(&self, log: &Path, session_hours: u32) -> Result<()> {
        match &self.launch {
            Launch::PollPs => self.attached_start_poll_ps(log, session_hours),
            Launch::AttachLine { registry, vm_dir } => self.attached_start_line(log, session_hours, registry, vm_dir),
        }
    }

    /// [`Launch::AttachLine`]: start the attached `machine run` (once more
    /// if it exits before printing its attached line), never polling
    /// `machine ps` meanwhile; then confirm once, read the TTL back, and
    /// require the run still alive.
    fn attached_start_line(&self, log: &Path, session_hours: u32, registry: &Path, vm_dir: &Path) -> Result<()> {
        let ttl = attach_ttl(session_hours);
        let argv = sv(&["machine", "run", "--name", &self.name, "--ttl", &ttl]);
        let refused = || Error::Other(format!("machine run exited before boot (see {})", log.display()));
        let marker = format!("attached to machine {};", self.name);
        for _ in 0..2 {
            // Only what this attempt appends counts.
            let offset = fs::metadata(log).map(|m| m.len()).unwrap_or(0);
            let a = self.run.attach(&argv, log).map_err(|e| Error::Other(format!("machine run failed to start: {e} (see {})", log.display())))?;
            *self.attach.lock().unwrap() = Some(a);
            let deadline = Instant::now() + CONTROL_TIMEOUT;
            let attached = loop {
                if log_has_line_from(log, offset, &marker) {
                    break true;
                }
                if self.attach.lock().unwrap().as_mut().and_then(|a| a.exited()).is_some() {
                    break false;
                }
                if Instant::now() >= deadline {
                    return Err(refused());
                }
                thread::sleep(BOOT_POLL);
            };
            if !attached {
                continue; // exited before attaching: start it once more
            }
            let ps = self.control(&sv(&["machine", "ps"]), "machine ps")?;
            if !ps_running(&String::from_utf8_lossy(&ps.stdout), &self.name) {
                return Err(Error::Other(format!("machine run attached, but machine ps does not show {} running (see {})", self.name, log.display())));
            }
            let text = fs::read_to_string(registry).map_err(|e| Error::Other(format!("no TTL backstop recorded for {}: reading {}: {e}", self.name, registry.display())))?;
            registry_expiry(&text, &self.name, vm_dir, chrono::Utc::now(), session_hours).map_err(Error::Other)?;
            if let Some(status) = self.attach.lock().unwrap().as_mut().and_then(|a| a.exited()) {
                return Err(Error::Other(format!("machine run exited ({status}) after it attached (see {})", log.display())));
            }
            return Ok(());
        }
        Err(refused())
    }

    /// [`Launch::PollPs`]: start the attached `machine run` (once more if
    /// it exits before boot) and wait until `machine ps` shows the machine
    /// running.
    fn attached_start_poll_ps(&self, log: &Path, session_hours: u32) -> Result<()> {
        let ttl = attach_ttl(session_hours);
        let argv = sv(&["machine", "run", "--name", &self.name, "--ttl", &ttl]);
        let refused = || Error::Other(format!("machine run exited before boot (see {})", log.display()));
        for _ in 0..2 {
            let a = self.run.attach(&argv, log).map_err(|e| Error::Other(format!("machine run failed to start: {e} (see {})", log.display())))?;
            // Held at once, so remove() terminates it on every path.
            *self.attach.lock().unwrap() = Some(a);
            let deadline = Instant::now() + CONTROL_TIMEOUT;
            loop {
                if self.attach.lock().unwrap().as_mut().and_then(|a| a.exited()).is_some() {
                    break; // exited before boot: start it once more
                }
                let ps = self.control(&sv(&["machine", "ps"]), "machine ps")?;
                if ps_running(&String::from_utf8_lossy(&ps.stdout), &self.name) {
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err(refused());
                }
                thread::sleep(BOOT_POLL);
            }
        }
        Err(refused())
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
        if spec.egress.as_ref().is_some_and(|e| e.allow_hosts.is_empty()) {
            return Err("a network machine needs at least one allowed host".into());
        }
        if let Some(e) = spec.egress.as_ref().filter(|e| !(1..=crate::config::MAX_SESSION_HOURS).contains(&e.session_hours)) {
            return Err(Error::Other(format!("session limit must be 1 to {} hours, not {}", crate::config::MAX_SESSION_HOURS, e.session_hours)));
        }
        if let Some(r) = self.dead_reason() {
            return Err(Error::Unavailable(r));
        }
        let (cpus, mem) = (spec.cpus.to_string(), format!("{}M", spec.memory_mib));
        let mut argv = sv(&["machine", "create", &self.name, "--image", spec.image, "--profile", "dev", "--cpus", &cpus, "--memory", &mem]);
        for h in spec.egress.iter().flat_map(|e| e.allow_hosts) {
            argv.extend(sv(&["--allow-host", h.as_str()]));
        }
        self.control(&argv, "machine create")?;
        match &spec.egress {
            None => {
                self.control(&sv(&["machine", "start", &self.name]), "machine start")?;
                Ok(())
            }
            Some(e) => self.attached_start(e.attach_log, e.session_hours),
        }
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
        // rm does not stop an attached machine run, so it goes second.
        if let Some(mut a) = self.attach.lock().unwrap().take() {
            a.terminate(ATTACH_GRACE);
        }
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::protocol::wrap_argv;
    use std::sync::Arc;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::io::Write;
    use crate::sandbox::Egress;

    const NAME: &str = "rts-0123456789ab";
    const IMAGE: &str = "docker.io/library/alpine@sha256:e311ae748be7f56ae5cba304bc488f0786df68ee507513f654a5cc8597cffb42";

    type Calls = Arc<Mutex<Vec<(Vec<String>, Duration)>>>;
    type Reply = Box<dyn Fn(&[String]) -> RunOutput + Send + Sync>;
    struct Fake {
        calls: Calls,
        reply: Reply,
    }
    impl Runner for Fake {
        fn run(&self, argv: &[String], t: Duration) -> io::Result<RunOutput> {
            self.calls.lock().unwrap().push((argv.to_vec(), t));
            Ok((self.reply)(argv))
        }
    }
    fn fake(reply: impl Fn(&[String]) -> RunOutput + Send + Sync + 'static) -> (Box<Fake>, Calls) {
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
    fn argvs(c: &Calls) -> Vec<Vec<String>> {
        c.lock().unwrap().iter().map(|(a, _)| a.clone()).collect()
    }
    const FORBIDDEN: [&str; 5] = ["--net", "--peer", "--gpu", "--grants-file", "--policy"];

    #[test]
    fn create_issues_exact_lines_and_no_network_flag() {
        let (f, calls) = fake(|_| out(0, "", ""));
        let sb = MvmSandbox::new(NAME, f).unwrap();
        sb.create(&CreateSpec { name: NAME, image: IMAGE, memory_mib: 2048, cpus: 2, egress: None }).unwrap();
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
            assert!(!a.contains(&"--allow-host".to_string()), "{a:?}");
        }
    }

    type Attaches = Arc<Mutex<Vec<(Vec<String>, PathBuf)>>>;

    /// Stands in for a held `mvmctl machine run`. `exit_at_once` makes every
    /// attach exit before boot; otherwise it exits when `exited_flag` is set.
    struct FakeAttached {
        pid: u32,
        exits: Arc<AtomicUsize>,
        exited_flag: Arc<AtomicBool>,
        terminated: Arc<AtomicBool>,
        calls: Calls,
    }
    impl Attached for FakeAttached {
        fn pid(&self) -> u32 {
            self.pid
        }
        fn exited(&mut self) -> Option<String> {
            if self.exited_flag.load(Ordering::SeqCst) {
                self.exits.fetch_add(1, Ordering::SeqCst);
                Some("exit status: 1".into())
            } else {
                None
            }
        }
        fn terminate(&mut self, grace: Duration) {
            self.terminated.store(true, Ordering::SeqCst);
            self.calls.lock().unwrap().push((sv(&["terminate"]), grace));
        }
    }
    struct AttachFake {
        inner: Fake,
        attaches: Attaches,
        /// Appended to the log at each attach, as mvmctl prints it.
        script: Option<String>,
        exit_at_once: bool,
        exited_flag: Arc<AtomicBool>,
        terminated: Arc<AtomicBool>,
        exits: Arc<AtomicUsize>,
    }
    impl Runner for AttachFake {
        fn run(&self, argv: &[String], t: Duration) -> io::Result<RunOutput> {
            self.inner.run(argv, t)
        }
        fn attach(&self, argv: &[String], log: &Path) -> io::Result<Box<dyn Attached>> {
            self.attaches.lock().unwrap().push((argv.to_vec(), log.to_path_buf()));
            if let Some(lines) = &self.script {
                fs::OpenOptions::new().append(true).create(true).open(log)?.write_all(lines.as_bytes())?;
            }
            let flag = if self.exit_at_once { Arc::new(AtomicBool::new(true)) } else { self.exited_flag.clone() };
            Ok(Box::new(FakeAttached {
                pid: 4242,
                exits: self.exits.clone(),
                exited_flag: flag,
                terminated: self.terminated.clone(),
                calls: self.inner.calls.clone(),
            }))
        }
    }
    struct AttachHandles {
        calls: Calls,
        attaches: Attaches,
        exited_flag: Arc<AtomicBool>,
        terminated: Arc<AtomicBool>,
    }
    fn fake_with_attach(exit_at_once: bool, reply: impl Fn(&[String]) -> RunOutput + Send + Sync + 'static) -> (Box<AttachFake>, AttachHandles) {
        let calls: Calls = Arc::new(Mutex::new(vec![]));
        let h = AttachHandles {
            calls: calls.clone(),
            attaches: Arc::new(Mutex::new(vec![])),
            exited_flag: Arc::new(AtomicBool::new(false)),
            terminated: Arc::new(AtomicBool::new(false)),
        };
        let f = AttachFake {
            inner: Fake { calls, reply: Box::new(reply) },
            attaches: h.attaches.clone(),
            script: None,
            exit_at_once,
            exited_flag: h.exited_flag.clone(),
            terminated: h.terminated.clone(),
            exits: Arc::new(AtomicUsize::new(0)),
        };
        (Box::new(f), h)
    }
    fn running_ps(a: &[String]) -> RunOutput {
        if a[1] == "ps" { out(0, &format!("NAME STATUS\n{NAME} running\n"), "") } else { out(0, "", "") }
    }

    #[test]
    fn create_with_egress_passes_each_allow_host_and_attaches_instead_of_start() {
        let hosts = crate::network::test_allow_hosts(&["198.51.100.7:443", "198.51.100.8:8443"]);
        let (f, h) = fake_with_attach(false, running_ps);
        let sb = MvmSandbox::new(NAME, f).unwrap();
        let log = Path::new("/s/mvm-attach.log");
        sb.create(&CreateSpec { name: NAME, image: IMAGE, memory_mib: 2048, cpus: 2, egress: Some(Egress { allow_hosts: &hosts, attach_log: log, session_hours: 24 }) }).unwrap();
        let calls = argvs(&h.calls);
        assert_eq!(
            calls[0],
            sv(&["machine", "create", NAME, "--image", IMAGE, "--profile", "dev", "--cpus", "2", "--memory", "2048M", "--allow-host", "198.51.100.7:443", "--allow-host", "198.51.100.8:8443"])
        );
        assert!(!calls.iter().any(|a| a.get(1).map(String::as_str) == Some("start")));
        assert_eq!(h.attaches.lock().unwrap().clone(), vec![(sv(&["machine", "run", "--name", NAME, "--ttl", "24h"]), log.to_path_buf())]);
        for a in calls.iter().chain(h.attaches.lock().unwrap().iter().map(|(a, _)| a)) {
            for flag in FORBIDDEN {
                assert!(!a.contains(&flag.to_string()), "{a:?}");
            }
        }
        assert_eq!(sb.attach_pid(), Some(4242));
        assert_eq!(sb.network_lost(), None);
    }

    /// `vm-names.json` as mvm 0.28.0-rts.2 wrote it on a Linux host during
    /// `machine run --name rts-0123456789ab --ttl 1h`. Its shape is mvm's,
    /// not a contract: a bump that changes it must fail these tests.
    const VM_NAMES_CAPTURED: &str = include_str!("../tests/fixtures/mvm-0.28/vm-names.json");
    const CAPTURED_VM_DIR: &str = "/home/rts/.mvm-live3/vms/rts-0123456789ab";

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&chrono::Utc)
    }

    #[test]
    fn the_captured_registry_gives_the_ttl_and_pins_its_shape() {
        let now = at("2026-11-22T07:08:20Z");
        let e = registry_expiry(VM_NAMES_CAPTURED, NAME, Path::new(CAPTURED_VM_DIR), now, 1).unwrap();
        assert_eq!(e, at("2026-11-22T08:08:13Z"));
        // The captured entry's exact key set; any other shape is no TTL.
        let v: serde_json::Value = serde_json::from_str(VM_NAMES_CAPTURED).unwrap();
        let mut keys: Vec<&str> = v["vms"][NAME].as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut known = REGISTRY_ENTRY_KEYS.to_vec();
        known.sort_unstable();
        assert_eq!(keys, known);
    }

    #[test]
    fn anything_but_a_known_future_ttl_for_this_machine_is_refused() {
        let now = at("2026-11-22T07:08:20Z");
        let ok = |t: &str| registry_expiry(t, NAME, Path::new(CAPTURED_VM_DIR), now, 1);
        let edit = |f: &dyn Fn(&mut serde_json::Value)| {
            let mut v: serde_json::Value = serde_json::from_str(VM_NAMES_CAPTURED).unwrap();
            f(&mut v);
            v.to_string()
        };
        let cases: Vec<(&str, String)> = vec![
            ("no entry", edit(&|v| v["vms"] = serde_json::json!({}))),
            ("null expiry", edit(&|v| v["vms"][NAME]["expires_at"] = serde_json::Value::Null)),
            ("numeric expiry", edit(&|v| v["vms"][NAME]["expires_at"] = 1.into())),
            ("offset, not Z", edit(&|v| v["vms"][NAME]["expires_at"] = "2026-11-22T09:08:13+01:00".into())),
            ("garbage", edit(&|v| v["vms"][NAME]["expires_at"] = "soon".into())),
            ("past", edit(&|v| v["vms"][NAME]["expires_at"] = "2026-11-22T07:08:19Z".into())),
            ("beyond the session", edit(&|v| v["vms"][NAME]["expires_at"] = "2026-11-22T08:30:00Z".into())),
            ("other vm dir", edit(&|v| v["vms"][NAME]["vm_dir"] = "/elsewhere/vms/rts-0123456789ab".into())),
            ("unknown key", edit(&|v| v["vms"][NAME]["ttl_policy"] = "x".into())),
            ("missing key", edit(&|v| { v["vms"][NAME].as_object_mut().unwrap().remove("readiness"); })),
            ("extra top level", edit(&|v| v["version"] = 2.into())),
            ("not json", "{".into()),
        ];
        for (what, text) in cases {
            let e = ok(&text).expect_err(what);
            assert!(e.contains("TTL"), "{what}: {e}");
        }
        assert!(ok(VM_NAMES_CAPTURED).is_ok());
    }

    /// The Firecracker launch: a fake attach that writes mvm 0.28's lines
    /// to the log and a registry with this machine's TTL.
    struct LaunchRig {
        dir: tempfile::TempDir,
        lines: String,
        log: PathBuf,
        registry: PathBuf,
        vm_dir: PathBuf,
    }
    impl LaunchRig {
        fn new(lines: &str, expires_in: Option<chrono::Duration>) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let log = dir.path().join("mvm-attach.log");
            // What an earlier attempt left: never this attempt's line.
            fs::write(&log, "attached to machine rts-0123456789ab; from before\n").unwrap();
            let vm_dir = dir.path().join("vms").join(NAME);
            let registry = dir.path().join("share/vm-names.json");
            fs::create_dir_all(registry.parent().unwrap()).unwrap();
            let mut v: serde_json::Value = serde_json::from_str(VM_NAMES_CAPTURED).unwrap();
            v["vms"][NAME]["vm_dir"] = vm_dir.display().to_string().into();
            v["vms"][NAME]["expires_at"] = match expires_in {
                Some(d) => (chrono::Utc::now() + d).format("%Y-%m-%dT%H:%M:%SZ").to_string().into(),
                None => serde_json::Value::Null,
            };
            fs::write(&registry, v.to_string()).unwrap();
            LaunchRig { dir, lines: lines.into(), log, registry, vm_dir }
        }
        fn sandbox(&self, mut f: Box<AttachFake>) -> MvmSandbox {
            f.script = Some(self.lines.clone());
            MvmSandbox::new(NAME, f).unwrap().with_launch(Launch::AttachLine { registry: self.registry.clone(), vm_dir: self.vm_dir.clone() })
        }
        fn spec<'a>(&'a self, hosts: &'a [crate::network::AllowHost]) -> CreateSpec<'a> {
            CreateSpec { name: NAME, image: IMAGE, memory_mib: 2048, cpus: 2, egress: Some(Egress { allow_hosts: hosts, attach_log: &self.log, session_hours: 1 }) }
        }
    }
    const ATTACHED: &str = "started machine rts-0123456789ab\nattached to machine rts-0123456789ab; press Ctrl-C to detach (it keeps running)\n";

    #[test]
    fn a_firecracker_launch_waits_for_the_attached_line_never_polling_ps_first() {
        let hosts = crate::network::test_allow_hosts(&["198.51.100.7:443"]);
        let r = LaunchRig::new(ATTACHED, Some(chrono::Duration::minutes(59)));
        let (f, h) = fake_with_attach(false, running_ps);
        let sb = r.sandbox(f);
        sb.create(&r.spec(&hosts)).unwrap();
        let calls = argvs(&h.calls);
        let ps: Vec<usize> = calls.iter().enumerate().filter(|(_, a)| a[1] == "ps").map(|(i, _)| i).collect();
        // Exactly one `machine ps`, after the attach was started.
        assert_eq!(ps.len(), 1, "{calls:?}");
        assert_eq!(h.attaches.lock().unwrap().len(), 1);
        assert_eq!(sb.network_lost(), None);
        drop(r.dir);
    }

    #[test]
    fn a_firecracker_launch_without_a_ttl_or_the_attached_line_is_refused() {
        let hosts = crate::network::test_allow_hosts(&["198.51.100.7:443"]);
        // The run attached, but the registry holds no TTL: no backstop, no session.
        let r = LaunchRig::new(ATTACHED, None);
        let (f, _h) = fake_with_attach(false, running_ps);
        let e = r.sandbox(f).create(&r.spec(&hosts)).unwrap_err().to_string();
        assert!(e.contains("TTL"), "{e}");
        // The race's signature: started, then the TTL error, then exit; twice.
        let raced = "started machine rts-0123456789ab\nError: machine \"rts-0123456789ab\" is not registered\n";
        let r = LaunchRig::new(raced, Some(chrono::Duration::minutes(59)));
        let (f, h) = fake_with_attach(true, running_ps);
        let e = r.sandbox(f).create(&r.spec(&hosts)).unwrap_err().to_string();
        assert!(e.contains("exited before boot"), "{e}");
        assert_eq!(h.attaches.lock().unwrap().len(), 2, "retried once");
        assert!(!argvs(&h.calls).iter().any(|a| a[1] == "ps"), "polled ps during the launch");
        // A line for another machine, or the name as a prefix, is not ours.
        for other in ["attached to machine rts-0123456789abc; x\n", "attached to machine rts-000000000000; x\n"] {
            let r = LaunchRig::new(other, Some(chrono::Duration::minutes(59)));
            let (f, _h) = fake_with_attach(true, running_ps);
            let e = r.sandbox(f).create(&r.spec(&hosts)).unwrap_err().to_string();
            assert!(e.contains("exited before boot"), "{other}: {e}");
        }
    }

    #[test]
    fn a_firecracker_run_that_exits_after_the_confirm_is_refused() {
        let hosts = crate::network::test_allow_hosts(&["198.51.100.7:443"]);
        let r = LaunchRig::new(ATTACHED, Some(chrono::Duration::minutes(59)));
        let exited = Arc::new(AtomicBool::new(false));
        let flag = exited.clone();
        // `machine ps` is the confirm; the run exits right after it.
        let (mut f, _h) = fake_with_attach(false, move |a| {
            if a[1] == "ps" {
                flag.store(true, Ordering::SeqCst);
            }
            running_ps(a)
        });
        f.exited_flag = exited;
        let e = r.sandbox(f).create(&r.spec(&hosts)).unwrap_err().to_string();
        assert!(e.contains("exited") && e.contains("after"), "{e}");
    }

    #[test]
    fn hvf_keeps_polling_machine_ps() {
        // The default launch is byte-for-byte the mvm 0.22 flow.
        assert!(matches!(MvmSandbox::new(NAME, fake(|_| out(0, "", "")).0).unwrap().launch, Launch::PollPs));
    }

    #[test]
    fn attach_ttl_is_the_session_limit_in_hours() {
        assert_eq!(attach_ttl(24), "24h");
        assert_eq!(attach_ttl(1), "1h");
        assert_eq!(attach_ttl(720), "720h");
    }

    #[test]
    fn create_with_egress_refuses_a_session_limit_outside_1_to_720_hours_and_runs_nothing() {
        let hosts = crate::network::test_allow_hosts(&["198.51.100.7:443"]);
        for hours in [0, 721] {
            let (f, h) = fake_with_attach(false, running_ps);
            let sb = MvmSandbox::new(NAME, f).unwrap();
            let log = Path::new("/s/mvm-attach.log");
            assert!(sb.create(&CreateSpec { name: NAME, image: IMAGE, memory_mib: 2048, cpus: 2, egress: Some(Egress { allow_hosts: &hosts, attach_log: log, session_hours: hours }) }).is_err());
            assert!(h.calls.lock().unwrap().is_empty());
            assert!(h.attaches.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn create_with_egress_refuses_an_empty_allowlist_and_runs_nothing() {
        let (f, h) = fake_with_attach(false, running_ps);
        let sb = MvmSandbox::new(NAME, f).unwrap();
        let log = Path::new("/s/mvm-attach.log");
        assert!(sb.create(&CreateSpec { name: NAME, image: IMAGE, memory_mib: 2048, cpus: 2, egress: Some(Egress { allow_hosts: &[], attach_log: log, session_hours: 24 }) }).is_err());
        assert!(h.calls.lock().unwrap().is_empty());
        assert!(h.attaches.lock().unwrap().is_empty());
    }

    #[test]
    fn an_attach_that_exits_before_boot_is_retried_once_then_refused() {
        let hosts = crate::network::test_allow_hosts(&["198.51.100.7:443"]);
        let (f, h) = fake_with_attach(true, |a| if a[1] == "ps" { out(0, "NAME STATUS\n", "") } else { out(0, "", "") });
        let sb = MvmSandbox::new(NAME, f).unwrap();
        let log = Path::new("/s/mvm-attach.log");
        let e = sb.create(&CreateSpec { name: NAME, image: IMAGE, memory_mib: 2048, cpus: 2, egress: Some(Egress { allow_hosts: &hosts, attach_log: log, session_hours: 24 }) }).unwrap_err().to_string();
        let attaches = h.attaches.lock().unwrap().clone();
        assert_eq!(attaches.len(), 2);
        assert!(attaches.iter().all(|(_, l)| l == log), "both runs append to the same log");
        assert!(e.contains("before boot") && e.contains("/s/mvm-attach.log"), "{e}");
        assert!(!e.contains("exit status"), "the error carries no attach output: {e}");
    }

    #[test]
    fn ps_running_needs_the_name_as_first_field_and_running() {
        assert!(ps_running(&format!("NAME STATUS\n{NAME} running\n"), NAME));
        assert!(!ps_running(&format!("NAME STATUS\n{NAME} stopped\n"), NAME));
        assert!(!ps_running(&format!("NAME STATUS\nweb running {NAME}\n"), NAME));
        assert!(!ps_running(&format!("NAME STATUS\n{NAME}x running\n"), NAME));
    }

    #[test]
    fn a_dead_attach_is_network_lost_and_remove_terminates_it_after_rm() {
        let hosts = crate::network::test_allow_hosts(&["198.51.100.7:443"]);
        let booted = Arc::new(AtomicBool::new(false));
        let b = booted.clone();
        // ps shows it running until rm has run.
        let (f, h) = fake_with_attach(false, move |a| match a[1].as_str() {
            "rm" => {
                b.store(true, Ordering::SeqCst);
                out(0, "", "")
            }
            "ps" if !b.load(Ordering::SeqCst) => out(0, &format!("NAME STATUS\n{NAME} running\n"), ""),
            "ps" => out(0, "NAME STATUS\n", ""),
            _ => out(0, "", ""),
        });
        let sb = MvmSandbox::new(NAME, f).unwrap();
        let log = Path::new("/s/mvm-attach.log");
        sb.create(&CreateSpec { name: NAME, image: IMAGE, memory_mib: 2048, cpus: 2, egress: Some(Egress { allow_hosts: &hosts, attach_log: log, session_hours: 24 }) }).unwrap();
        assert_eq!(sb.network_lost(), None);
        h.exited_flag.store(true, Ordering::SeqCst);
        let lost = sb.network_lost().unwrap();
        assert!(lost.starts_with("network-lost: mvmctl machine run exited ("), "{lost}");
        assert_eq!(sb.network_lost(), Some(lost));
        h.calls.lock().unwrap().clear();
        sb.remove().unwrap();
        assert!(h.terminated.load(Ordering::SeqCst));
        let order: Vec<(Vec<String>, Duration)> = h.calls.lock().unwrap().clone();
        assert_eq!(
            order,
            vec![
                (sv(&["machine", "rm", NAME, "--force", "--yes"]), CONTROL_TIMEOUT),
                (sv(&["terminate"]), Duration::from_secs(5)),
                (sv(&["machine", "ps"]), CONTROL_TIMEOUT),
            ]
        );
    }

    #[test]
    fn remove_terminates_the_attach_even_when_rm_fails() {
        let hosts = crate::network::test_allow_hosts(&["198.51.100.7:443"]);
        let (f, h) = fake_with_attach(false, |a| match a[1].as_str() {
            "rm" => out(1, "", "rm broke"),
            "ps" => out(0, &format!("NAME STATUS\n{NAME} running\n"), ""),
            _ => out(0, "", ""),
        });
        let sb = MvmSandbox::new(NAME, f).unwrap();
        let log = Path::new("/s/mvm-attach.log");
        sb.create(&CreateSpec { name: NAME, image: IMAGE, memory_mib: 2048, cpus: 2, egress: Some(Egress { allow_hosts: &hosts, attach_log: log, session_hours: 24 }) }).unwrap();
        assert!(sb.remove().is_err());
        assert!(h.terminated.load(Ordering::SeqCst));
    }

    #[test]
    fn the_default_runner_attach_is_unsupported() {
        let (f, _) = fake(|_| out(0, "", ""));
        let e = f.attach(&sv(&["machine", "run"]), Path::new("/s/log")).err().unwrap();
        assert_eq!(e.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn create_refuses_unpinned_image_and_runs_nothing() {
        let (f, calls) = fake(|_| out(0, "", ""));
        let sb = MvmSandbox::new(NAME, f).unwrap();
        for img in ["alpine:latest", "Error: no such image", "Alpine@sha256:00"] {
            let e = sb.create(&CreateSpec { name: NAME, image: img, memory_mib: 2048, cpus: 2, egress: None }).unwrap_err();
            assert!(e.to_string().contains("image must be digest-pinned"));
        }
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn create_refuses_other_name_and_reports_failures() {
        let (f, calls) = fake(|a| if a[1] == "start" { out(1, "", "bad image") } else { out(0, "", "") });
        let sb = MvmSandbox::new(NAME, f).unwrap();
        assert!(sb.create(&CreateSpec { name: "rts-ffffffffffff", image: IMAGE, memory_mib: 2048, cpus: 2, egress: None }).is_err());
        assert!(calls.lock().unwrap().is_empty());
        let e = sb.create(&CreateSpec { name: NAME, image: IMAGE, memory_mib: 2048, cpus: 2, egress: None }).unwrap_err();
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
    fn quiesce_is_bounded_and_stops_later_tools_when_an_exec_is_stuck() {
        let dir = crate::testutil::tempdir("quiesce-deadline");
        let state = StateDir(dir.clone());
        let active = state.lock().unwrap();
        let start = Instant::now();
        let err = state.quiesce(Duration::from_millis(50)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(2));
        let (runner, calls) = fake(|_| panic!("a stopped tool must never run mvmctl"));
        let tool = MvmSandbox::new(NAME, runner).unwrap().with_state(state);
        assert!(matches!(tool.exec(&sv(&["true"]), &opts()), Err(Error::Unavailable(_))));
        assert!(calls.lock().unwrap().is_empty());
        drop(active);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn list_machines_filters_rts_names() {
        let (f, _) = fake(|_| out(0, "NAME STATUS\nrts-aaaaaaaaaaaa running\nweb stopped\nrts-short x\nrts-bbbbbbbbbbbb stopped\n", ""));
        assert_eq!(list_machines(f.as_ref()).unwrap(), sv(&["rts-aaaaaaaaaaaa", "rts-bbbbbbbbbbbb"]));
    }

    #[test]
    fn spawn_runner_removes_named_variables_from_the_child() {
        let mut extra_env = HashMap::new();
        extra_env.insert("RTS_REMOVED_TEST_VAR".to_string(), "set".to_string());
        let r = SpawnRunner {
            mvmctl: "/bin/sh".into(),
            empty_git_config: "/dev/null".into(),
            extra_env,
            remove_env: vec!["RTS_REMOVED_TEST_VAR".into()],
        };
        let cmd = r.command(&sv(&["-c", "true"]));
        assert!(cmd.get_envs().any(|(k, v)| k == "RTS_REMOVED_TEST_VAR" && v.is_none()));
        let o = r.run(&sv(&["-c", "echo ${RTS_REMOVED_TEST_VAR-unset}"]), Duration::from_secs(5)).unwrap();
        assert_eq!(o.stdout, b"unset\n");
    }

    #[test]
    fn spawn_runner_captures_and_kills_on_timeout() {
        let r = SpawnRunner { mvmctl: "/bin/sh".into(), empty_git_config: "/dev/null".into(), extra_env: HashMap::new(), remove_env: Vec::new() };
        let o = r.run(&sv(&["-c", "echo $GIT_CONFIG_GLOBAL; echo e >&2; exit 4"]), Duration::from_secs(5)).unwrap();
        assert_eq!((o.code, o.stdout.as_slice(), o.stderr.as_slice(), o.killed), (Some(4), &b"/dev/null\n"[..], &b"e\n"[..], false));
        let t = Instant::now();
        let o = r.run(&sv(&["-c", "sleep 10"]), Duration::from_millis(200)).unwrap();
        assert!(o.killed && o.code.is_none() && t.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn spawn_runner_attach_writes_both_streams_to_a_0600_log_in_its_own_group() {
        let d = crate::testutil::tempdir("attach");
        let log = d.join("mvm-attach.log");
        // A pre-existing, wider file is narrowed to 0600.
        fs::write(&log, "").unwrap();
        fs::set_permissions(&log, fs::Permissions::from_mode(0o644)).unwrap();
        let r = SpawnRunner { mvmctl: "/bin/sh".into(), empty_git_config: "/dev/null".into(), extra_env: HashMap::new(), remove_env: Vec::new() };
        let mut a = r.attach(&sv(&["-c", "echo out; echo err >&2; sleep 30"]), &log).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let t = fs::read_to_string(&log).unwrap();
            if t.contains("out\n") && t.contains("err\n") {
                break;
            }
            assert!(Instant::now() < deadline, "log never got both streams: {t:?}");
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(fs::metadata(&log).unwrap().permissions().mode() & 0o777, 0o600);
        let pgid = Command::new("ps").args(["-o", "pgid=", "-p", &a.pid().to_string()]).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&pgid.stdout).trim(), a.pid().to_string());
        assert_eq!(a.exited(), None);
        let t = Instant::now();
        a.terminate(Duration::from_secs(2));
        assert!(t.elapsed() < Duration::from_secs(4));
        let first = a.exited();
        assert!(first.is_some());
        assert_eq!(a.exited(), first, "the exit status is kept");
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn spawn_runner_attach_appends_and_removes_named_variables() {
        let d = crate::testutil::tempdir("attach-env");
        let log = d.join("mvm-attach.log");
        fs::write(&log, "earlier\n").unwrap();
        let mut extra_env = HashMap::new();
        extra_env.insert("RTS_ATTACH_KEPT".to_string(), "kept".to_string());
        extra_env.insert("RTS_ATTACH_REMOVED".to_string(), "set".to_string());
        let r = SpawnRunner { mvmctl: "/bin/sh".into(), empty_git_config: "/dev/null".into(), extra_env, remove_env: vec!["RTS_ATTACH_REMOVED".into()] };
        let mut a = r.attach(&sv(&["-c", "echo $RTS_ATTACH_KEPT ${RTS_ATTACH_REMOVED-unset} $GIT_CONFIG_GLOBAL"]), &log).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while a.exited().is_none() {
            assert!(Instant::now() < deadline, "attach did not exit");
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(fs::read_to_string(&log).unwrap(), "earlier\nkept unset /dev/null\n");
        a.terminate(Duration::from_millis(100));
        fs::remove_dir_all(d).unwrap();
    }
}

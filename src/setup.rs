//! `rts setup` downloads: fetch over an exact GitHub host allowlist, check the
//! pinned digest, unpack into a temp directory beside the target, and rename
//! it into place. Nothing unverified or partially unpacked is ever left at
//! the target path. Then `run` signs and checks mvm, probes the supervisor,
//! checks opencode and pulls the guest image.

use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;

use sha2::{Digest, Sha256};
use url::Url;

use crate::config::{DEFAULT_IMAGE, Defaults};
use crate::install::{MVM_VERSION, mvm_dir, opencode_dir};
use crate::mvm::{RunOutput, Runner, SpawnRunner, tail};
use crate::session::{Host, OPENCODE_VERSION, SUPERVISOR_FIX_VERSION, check_opencode, check_supervisor_contract, check_supervisor_marker};

pub const ALLOWED_HOSTS: [&str; 3] = ["github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"];
pub const MAX_REDIRECTS: usize = 5;

const CHUNK: usize = 64 * 1024;
const UNPACK_TIMEOUT: Duration = Duration::from_secs(600);
const TEMP_PREFIX: &str = ".rts-setup-";

/// `url` parsed, when it is `https`, its host is exactly one of
/// `ALLOWED_HOSTS` (not a suffix match), it names no port other than 443 and
/// it carries no userinfo.
pub fn allowed_url(url: &str) -> Result<Url, String> {
    let u = Url::parse(url).map_err(|e| format!("{url}: not a valid URL: {e}"))?;
    if u.scheme() != "https" {
        return Err(format!("{url}: only https downloads are allowed"));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(format!("{url}: a download URL may not carry a user name or password"));
    }
    // `Url` drops the scheme's default port, so `:443` reads as None here.
    if let Some(port) = u.port() {
        return Err(format!("{url}: port {port} is not allowed (only 443)"));
    }
    match u.host() {
        Some(url::Host::Domain(h)) if ALLOWED_HOSTS.contains(&h) => Ok(u),
        _ => Err(format!("{url}: host is not one of {}", ALLOWED_HOSTS.join(", "))),
    }
}

/// One fetch, no redirects followed: the caller checks each hop.
pub enum Hop {
    Redirect(String),
    Body(Box<dyn Read + Send>),
}

pub trait Fetch: Send + Sync {
    fn get(&self, url: &Url) -> Result<Hop, String>;
}

pub struct HttpsFetch {
    client: reqwest::blocking::Client,
}

impl HttpsFetch {
    /// No redirects followed (`download` checks each hop), https only,
    /// 30 s to connect, 600 s per request including the body.
    pub fn new() -> Result<Self, String> {
        Self::with_timeouts(Duration::from_secs(30), Duration::from_secs(600))
    }

    /// As `new`, with `connect` to connect and `total` per request
    /// including the body.
    pub fn with_timeouts(connect: Duration, total: Duration) -> Result<Self, String> {
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(connect)
            .timeout(total)
            .https_only(true)
            .build()
            .map_err(|e| format!("building the HTTPS client: {e}"))?;
        Ok(Self { client })
    }
}

impl Fetch for HttpsFetch {
    fn get(&self, url: &Url) -> Result<Hop, String> {
        let resp = self.client.get(url.clone()).send().map_err(|e| format!("GET {url}: {e}; check the network and re-run rts setup"))?;
        let status = resp.status();
        if status.is_redirection() {
            let location = resp.headers().get(reqwest::header::LOCATION).map(|v| v.to_str().map_err(|_| format!("GET {url}: {status} with a non-ASCII Location"))).transpose()?;
            return redirect_target(url, location).map(Hop::Redirect);
        }
        if status.is_success() {
            return Ok(Hop::Body(Box::new(resp)));
        }
        Err(format!("GET {url}: HTTP {status}; check the network and re-run rts setup"))
    }
}

/// A redirect's `Location`, resolved against the URL that returned it.
fn redirect_target(url: &Url, location: Option<&str>) -> Result<String, String> {
    let loc = location.ok_or_else(|| format!("GET {url}: redirect without a Location header"))?;
    url.join(loc).map(String::from).map_err(|e| format!("GET {url}: bad redirect Location {loc:?}: {e}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Downloaded {
    pub sha256: String,
    pub bytes: u64,
}

/// Fetch `url`, following at most `MAX_REDIRECTS` redirects, each checked with
/// `allowed_url` before it is fetched, and stream the body into `out` and a
/// SHA-256, refusing more than `max_bytes`.
pub fn download(f: &dyn Fetch, url: &str, max_bytes: u64, out: &mut dyn Write) -> Result<Downloaded, String> {
    let mut current = allowed_url(url)?;
    let mut redirects = 0;
    let mut body = loop {
        match f.get(&current)? {
            Hop::Body(b) => break b,
            Hop::Redirect(to) => {
                redirects += 1;
                if redirects > MAX_REDIRECTS {
                    return Err(format!("{url}: more than {MAX_REDIRECTS} redirects"));
                }
                current = allowed_url(&to).map_err(|e| format!("{url} redirected to a URL that is not allowed: {e}"))?;
            }
        }
    };
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut total: u64 = 0;
    loop {
        let n = match body.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("reading {url}: {e}; re-run rts setup")),
        };
        total += n as u64;
        if total > max_bytes {
            return Err(format!("{url} exceeds {max_bytes} bytes"));
        }
        hasher.update(&buf[..n]);
        out.write_all(&buf[..n]).map_err(|e| format!("writing the download of {url}: {e}"))?;
    }
    Ok(Downloaded { sha256: hex(&hasher.finalize()), bytes: total })
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unpack {
    TarGzStrip1,
    Zip,
}

#[derive(Debug, Clone)]
pub struct Component {
    pub name: &'static str,
    pub version: &'static str,
    pub url: String,
    pub sha256: String,
    pub max_bytes: u64,
    pub unpack: Unpack,
    pub binary: &'static str,
}

pub fn mvm() -> Component {
    Component {
        name: "mvm",
        version: MVM_VERSION,
        url: format!("https://github.com/tinylabscom/mvm/releases/download/v{MVM_VERSION}/mvmctl-aarch64-apple-darwin.tar.gz"),
        sha256: "1f2c80b253add28c3856080e3f3a10aa1163f1aef0a7d413ded15100bdcd0c69".into(),
        max_bytes: 64 << 20,
        unpack: Unpack::TarGzStrip1,
        binary: "mvmctl",
    }
}

pub fn opencode() -> Component {
    Component {
        name: "opencode",
        version: OPENCODE_VERSION,
        url: format!("https://github.com/anomalyco/opencode/releases/download/v{OPENCODE_VERSION}/opencode-darwin-arm64.zip"),
        sha256: "c1c901a6379d667b7a30a3eea5a8f6e93416dba43e889e834771f6fb174f35c9".into(),
        max_bytes: 256 << 20,
        unpack: Unpack::Zip,
        binary: "opencode",
    }
}

/// Download, check the digest, unpack into `<parent>/.rts-setup-XXXX/unpacked`,
/// check `binary`, rename to `target`.
/// Errs when `target` exists: the caller decides to skip or refuse it.
pub fn install_component(c: &Component, target: &Path, f: &dyn Fetch, host: &dyn Host) -> Result<(), String> {
    let label = format!("{} {}", c.name, c.version);
    let parent = target.parent().ok_or_else(|| format!("{label}: {} has no parent directory", target.display()))?;
    if parent.exists() {
        remove_stale_temp_dirs(parent).map_err(|e| format!("{label}: {e}"))?;
    } else {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().recursive(true).mode(0o700).create(parent).map_err(|e| format!("{label}: creating {}: {e}", parent.display()))?;
    }
    let exists = || fs::symlink_metadata(target).is_ok();
    if exists() {
        return Err(format!("{} already exists", target.display()));
    }
    let tmp = tempfile::Builder::new()
        .prefix(TEMP_PREFIX)
        .tempdir_in(parent)
        .map_err(|e| format!("{label}: creating a temp directory in {}: {e}", parent.display()))?;
    let download_path = tmp.path().join("download");
    let unpacked = tmp.path().join("unpacked");

    let got = {
        let mut file = fs::File::create(&download_path).map_err(|e| format!("{label}: creating {}: {e}", download_path.display()))?;
        let d = download(f, &c.url, c.max_bytes, &mut file).map_err(|e| format!("{label}: {e}; nothing was installed"))?;
        file.sync_all().map_err(|e| format!("{label}: writing {}: {e}", download_path.display()))?;
        d
    };
    if !got.sha256.eq_ignore_ascii_case(&c.sha256) {
        let _ = fs::remove_file(&download_path);
        return Err(format!("{label}: sha256 mismatch for {}: expected {}, got {}; nothing was installed", c.url, c.sha256, got.sha256));
    }

    fs::create_dir(&unpacked).map_err(|e| format!("{label}: creating {}: {e}", unpacked.display()))?;
    let (dl, un) = (download_path.to_string_lossy().into_owned(), unpacked.to_string_lossy().into_owned());
    let argv: Vec<String> = match c.unpack {
        Unpack::TarGzStrip1 => vec!["/usr/bin/tar".into(), "-xzf".into(), dl, "-C".into(), un, "--strip-components".into(), "1".into()],
        Unpack::Zip => vec!["/usr/bin/ditto".into(), "-x".into(), "-k".into(), dl, un],
    };
    let tool = argv[0].clone();
    let out = host.run(&argv, UNPACK_TIMEOUT).map_err(|e| format!("{label}: running {tool}: {e}; nothing was installed"))?;
    if out.killed || out.code != Some(0) {
        let how = if out.killed { "was killed".to_string() } else { format!("exited with {:?}", out.code) };
        return Err(format!("{label}: {tool} {how} unpacking {}: {}; nothing was installed", c.url, tail(&out.stderr)));
    }

    let binary = unpacked.join(c.binary);
    if !fs::symlink_metadata(&binary).map(|m| m.is_file()).unwrap_or(false) {
        return Err(format!("{label}: {} does not contain a regular file {}; nothing was installed", c.url, c.binary));
    }
    if exists() {
        return Err(format!("{} already exists", target.display()));
    }
    fs::rename(&unpacked, target).map_err(|e| format!("{label}: moving {} to {}: {e}; nothing was installed", unpacked.display(), target.display()))?;
    // `tmp` drops here and removes the download.
    Ok(())
}

/// Remove `.rts-setup-*` directories (never files or symlinks) a killed run
/// left in `parent`.
fn remove_stale_temp_dirs(parent: &Path) -> Result<(), String> {
    let entries = fs::read_dir(parent).map_err(|e| format!("reading {}: {e}", parent.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("reading {}: {e}", parent.display()))?;
        if !entry.file_name().to_string_lossy().starts_with(TEMP_PREFIX) {
            continue;
        }
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if is_dir {
            let path = entry.path();
            fs::remove_dir_all(&path).map_err(|e| format!("removing the stale {}: {e}; remove it and re-run rts setup", path.display()))?;
        }
    }
    Ok(())
}

// --- rts setup ---

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SetupOptions {
    /// Run every check; download nothing and run no mutating command.
    pub check: bool,
    /// With `check`: only the installed `rts` layout, no mvmctl at all.
    pub offline: bool,
}

pub struct SetupContext<'a> {
    pub home: &'a Path,
    pub defaults: &'a Defaults,
    /// `RTS_MVMCTL` is set: verify it, never download.
    pub explicit_mvmctl: bool,
    /// From `supervisor_path(env, prefix)`.
    pub supervisor: &'a Path,
    /// The running `rts`.
    pub rts: &'a Path,
    pub fetch: &'a dyn Fetch,
    /// opencode, the supervisor, tar, ditto, codesign.
    pub host: &'a dyn Host,
    /// mvmctl with only HOME and MVM_HOME: `--version` and `env sign`.
    pub mvm_plain: &'a dyn Runner,
    /// mvmctl with `mvm_environment(env, supervisor)`: doctor and image.
    pub mvm: &'a dyn Runner,
}

const VERSION_TIMEOUT: Duration = Duration::from_secs(30);
const SIGN_TIMEOUT: Duration = Duration::from_secs(120);
const DOCTOR_TIMEOUT: Duration = Duration::from_secs(60);
const INSPECT_TIMEOUT: Duration = Duration::from_secs(60);
const PULL_TIMEOUT: Duration = Duration::from_secs(1800);
const CODESIGN_TIMEOUT: Duration = Duration::from_secs(30);

/// Ok: one summary line per component ("<name> <version> <path>"). Err:
/// every failure, one per line.
pub fn run(o: &SetupOptions, c: &SetupContext) -> Result<Vec<String>, String> {
    run_with(o, c, (&mvm(), &opencode()))
}

/// The environment for `mvm_plain`: only HOME and MVM_HOME from `env`, never
/// MVM_HVF_SUPERVISOR_PATH, so `env sign` cannot re-sign the supervisor.
pub fn plain_mvm_env(env: &[(String, String)]) -> std::collections::HashMap<String, String> {
    env.iter().filter(|(k, _)| matches!(k.as_str(), "HOME" | "MVM_HOME")).cloned().collect()
}

/// The runner for `mvmctl env sign` and other plain mvmctl calls. It sets
/// only `plain_mvm_env` and removes MVM_HVF_SUPERVISOR_PATH from the child,
/// so an override exported in the operator's shell never reaches mvmctl.
pub fn plain_mvm_runner(mvmctl: &Path, empty_git_config: &Path, env: &[(String, String)]) -> SpawnRunner {
    SpawnRunner {
        mvmctl: mvmctl.to_path_buf(),
        empty_git_config: empty_git_config.to_path_buf(),
        extra_env: plain_mvm_env(env),
        remove_env: vec!["MVM_HVF_SUPERVISOR_PATH".to_string()],
    }
}

/// `mvmctl --version` prints exactly `mvmctl <MVM_VERSION>`.
pub fn verify_mvm(mvm: &dyn Runner) -> Result<(), String> {
    let r = succeeded(mvm.run(&["--version".to_string()], VERSION_TIMEOUT), "mvmctl --version", VERSION_TIMEOUT)?;
    let out = String::from_utf8_lossy(&r.stdout);
    let found = out.trim();
    if found != format!("mvmctl {MVM_VERSION}") {
        return Err(format!("mvmctl --version printed {found:?}, expected \"mvmctl {MVM_VERSION}\""));
    }
    Ok(())
}

/// The command ran, was not killed and exited 0.
fn succeeded(r: io::Result<RunOutput>, what: &str, timeout: Duration) -> Result<RunOutput, String> {
    let out = r.map_err(|e| format!("{what} could not run: {e}"))?;
    if out.killed {
        return Err(format!("{what} did not finish within {} s", timeout.as_secs()));
    }
    if out.code != Some(0) {
        let t = tail(&out.stderr);
        return Err(format!("{what} exited with {:?}{}", out.code, if t.is_empty() { String::new() } else { format!(": {t}") }));
    }
    Ok(out)
}

fn exists(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok()
}

/// Collects summary lines; outside `--check` the first failure ends the run.
struct Steps {
    check: bool,
    lines: Vec<String>,
    failures: Vec<String>,
}

impl Steps {
    /// Ok(true) when the step passed, Ok(false) when it failed under `--check`.
    fn record(&mut self, r: Result<Option<String>, String>) -> Result<bool, String> {
        match r {
            Ok(line) => {
                self.lines.extend(line);
                Ok(true)
            }
            Err(e) if self.check => {
                self.failures.push(e);
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }
    fn finish(self) -> Result<Vec<String>, String> {
        if self.failures.is_empty() { Ok(self.lines) } else { Err(self.failures.join("\n")) }
    }
}

/// `run` with the two components supplied, so tests serve fixtures.
pub(crate) fn run_with(o: &SetupOptions, c: &SetupContext, components: (&Component, &Component)) -> Result<Vec<String>, String> {
    if o.offline {
        if !o.check {
            return Err("--offline requires --check".into());
        }
        return offline_check(c);
    }
    let (mvm_c, opencode_c) = components;
    let mut steps = Steps { check: o.check, lines: Vec::new(), failures: Vec::new() };
    let mvm_ok = steps.record(mvm_step(o.check, c, mvm_c))?;
    if !o.check {
        steps.record(
            succeeded(c.mvm_plain.run(&sv(&["env", "sign"]), SIGN_TIMEOUT), "mvmctl env sign", SIGN_TIMEOUT)
                .map(|_| None)
                .map_err(|e| format!("mvm {MVM_VERSION}: {e}; fix the problem it reports and re-run rts setup")),
        )?;
    }
    // A missing or wrong mvmctl already failed above; running it again only repeats that.
    if mvm_ok {
        steps.record(
            succeeded(c.mvm.run(&sv(&["doctor"]), DOCTOR_TIMEOUT), &format!("{} doctor", c.defaults.mvmctl.display()), DOCTOR_TIMEOUT)
                .map(|_| None)
                .map_err(|e| format!("mvm {MVM_VERSION}: {e}; fix the problems it reports and re-run rts setup")),
        )?;
    }
    steps.record(supervisor_step(c))?;
    steps.record(opencode_step(o.check, c, opencode_c))?;
    if mvm_ok {
        steps.record(image_step(o.check, c))?;
    }
    steps.finish()
}

fn mvm_step(check: bool, c: &SetupContext, comp: &Component) -> Result<Option<String>, String> {
    let label = format!("{} {}", comp.name, comp.version);
    let line = Some(format!("{label} {}", c.defaults.mvmctl.display()));
    if c.explicit_mvmctl {
        verify_mvm(c.mvm_plain).map_err(|e| {
            format!("{label}: RTS_MVMCTL={} is not mvm {MVM_VERSION} ({e}); point RTS_MVMCTL at mvmctl {MVM_VERSION} or unset it and re-run rts setup", c.defaults.mvmctl.display())
        })?;
        return Ok(line);
    }
    let dir = mvm_dir(c.home);
    if exists(&dir) {
        verify_mvm(c.mvm_plain).map_err(|e| format!("{label}: {} exists but is not mvm {MVM_VERSION} ({e}); remove it and re-run rts setup", dir.display()))?;
        return Ok(line);
    }
    if check {
        return Err(format!("{label}: not installed at {}; run rts setup", dir.display()));
    }
    install_component(comp, &dir, c.fetch, c.host)?;
    verify_mvm(c.mvm_plain).map_err(|e| format!("{label}: the copy just installed at {} does not verify ({e}); remove it and re-run rts setup", dir.display()))?;
    Ok(line)
}

fn supervisor_step(c: &SetupContext) -> Result<Option<String>, String> {
    let path = c.supervisor;
    check_supervisor_marker(c.host, path)
        .and_then(|()| check_supervisor_contract(c.host, path))
        .map_err(|e| format!("supervisor {}: {e}", path.display()))?;
    Ok(Some(format!("mvm-hvf-supervisor {SUPERVISOR_FIX_VERSION} {}", path.display())))
}

fn opencode_step(check: bool, c: &SetupContext, comp: &Component) -> Result<Option<String>, String> {
    let label = format!("{} {}", comp.name, comp.version);
    let dir = opencode_dir(c.home);
    let bin = dir.join(comp.binary);
    let bin_s = bin.to_string_lossy();
    let line = Some(format!("{label} {}", bin.display()));
    // check_opencode's own advice is "run rts setup", which would not help here.
    let reason = |e: String| e.trim_end_matches("; run rts setup").to_string();
    if exists(&dir) {
        check_opencode(c.host, &bin_s)
            .map_err(|e| format!("{label}: {} exists but is not opencode {OPENCODE_VERSION} ({}); remove it and re-run rts setup", dir.display(), reason(e)))?;
        return Ok(line);
    }
    if check {
        return Err(format!("{label}: not installed at {}; run rts setup", bin.display()));
    }
    install_component(comp, &dir, c.fetch, c.host)?;
    check_opencode(c.host, &bin_s)
        .map_err(|e| format!("{label}: the copy just installed at {} does not verify ({}); remove it and re-run rts setup", dir.display(), reason(e)))?;
    Ok(line)
}

fn image_step(check: bool, c: &SetupContext) -> Result<Option<String>, String> {
    let line = Some(format!("guest-image {DEFAULT_IMAGE} (mvm image cache)"));
    let inspect = c.mvm.run(&sv(&["image", "inspect", DEFAULT_IMAGE]), INSPECT_TIMEOUT);
    if matches!(&inspect, Ok(r) if !r.killed && r.code == Some(0)) {
        return Ok(line);
    }
    if check {
        let why = succeeded(inspect, "mvmctl image inspect", INSPECT_TIMEOUT).err().unwrap_or_default();
        return Err(format!("guest image {DEFAULT_IMAGE}: not in mvm's image cache ({why}); run rts setup"));
    }
    succeeded(c.mvm.run(&sv(&["image", "pull", DEFAULT_IMAGE]), PULL_TIMEOUT), "mvmctl image pull", PULL_TIMEOUT)
        .map_err(|e| format!("guest image {DEFAULT_IMAGE}: {e}; check the network and re-run rts setup"))?;
    Ok(line)
}

/// `--check --offline`: the plugin's files, both supervisor probes, and the
/// signatures of `rts` and the supervisor. No mvmctl, no network.
fn offline_check(c: &SetupContext) -> Result<Vec<String>, String> {
    let mut steps = Steps { check: true, lines: Vec::new(), failures: Vec::new() };
    let plugin = &c.defaults.plugin_dir;
    let missing: Vec<String> = ["package.json", "index.ts", "branding/tui.tsx", "branding/footer.ts", crate::brand::theme::THEME_FILE]
        .iter()
        .map(|f| plugin.join(f))
        .filter(|p| !fs::metadata(p).map(|m| m.is_file()).unwrap_or(false))
        .map(|p| format!("plugin: {} is missing or not a file; reinstall rts", p.display()))
        .collect();
    steps.record(if missing.is_empty() { Ok(Some(format!("plugin {} {}", env!("CARGO_PKG_VERSION"), plugin.display()))) } else { Err(missing.join("\n")) })?;
    steps.record(supervisor_step(c))?;
    for (name, path, fix) in [("rts", c.rts, "reinstall rts"), ("supervisor", c.supervisor, "reinstall rts, or rebuild it with scripts/build-patched-mvm-supervisor.sh")] {
        let p = path.to_string_lossy();
        let r = succeeded(c.host.run(&sv(&["/usr/bin/codesign", "--verify", "--strict", &p]), CODESIGN_TIMEOUT), "codesign --verify --strict", CODESIGN_TIMEOUT)
            .map(|_| Some(format!("{name} signature {p}")))
            .map_err(|e| format!("{name} {p}: {e}; {fix}"));
        steps.record(r)?;
    }
    steps.finish()
}

fn sv(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

#[cfg(test)]
enum FakeHop {
    Body(Vec<u8>),
    Redirect(String),
}

/// A `Fetch` that answers from a table and records every URL it was asked for.
#[cfg(test)]
#[derive(Default)]
pub struct FakeFetch {
    hops: std::sync::Mutex<std::collections::HashMap<String, FakeHop>>,
    calls: std::sync::Mutex<Vec<String>>,
}

#[cfg(test)]
impl FakeFetch {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn body(&self, url: &str, bytes: Vec<u8>) {
        self.hops.lock().unwrap().insert(url.to_string(), FakeHop::Body(bytes));
    }
    pub fn redirect(&self, url: &str, to: &str) {
        self.hops.lock().unwrap().insert(url.to_string(), FakeHop::Redirect(to.to_string()));
    }
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

#[cfg(test)]
impl Fetch for FakeFetch {
    fn get(&self, url: &Url) -> Result<Hop, String> {
        self.calls.lock().unwrap().push(url.as_str().to_string());
        match self.hops.lock().unwrap().get(url.as_str()) {
            Some(FakeHop::Body(b)) => Ok(Hop::Body(Box::new(io::Cursor::new(b.clone())))),
            Some(FakeHop::Redirect(to)) => Ok(Hop::Redirect(to.clone())),
            None => Err(format!("FakeFetch: no response for {url}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mvm::RunOutput;
    use crate::session::RealHost;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::process::Command;

    fn sha256_hex(b: &[u8]) -> String {
        hex(&Sha256::digest(b))
    }

    fn run(cmd: &mut Command) {
        let out = cmd.output().unwrap();
        assert!(out.status.success(), "{cmd:?}: {}", String::from_utf8_lossy(&out.stderr));
    }

    /// A tar.gz of `top/<binary>` (a two-line shell script), built with the real tar.
    fn tarball(dir: &Path, binary: &str) -> Vec<u8> {
        let src = dir.join("src-tar");
        fs::create_dir_all(src.join("top")).unwrap();
        let bin = src.join("top").join(binary);
        fs::write(&bin, "#!/bin/sh\necho fixture\n").unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        let out = dir.join("fixture.tar.gz");
        run(Command::new("/usr/bin/tar").arg("-czf").arg(&out).arg("-C").arg(&src).arg("top"));
        fs::read(out).unwrap()
    }

    /// A zip holding one entry, `opencode`, built with the real ditto.
    fn zip(dir: &Path) -> Vec<u8> {
        let src = dir.join("src-zip");
        fs::create_dir_all(&src).unwrap();
        let bin = src.join("opencode");
        fs::write(&bin, "#!/bin/sh\necho fixture\n").unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        let out = dir.join("fixture.zip");
        run(Command::new("/usr/bin/ditto").args(["-c", "-k"]).arg(&bin).arg(&out));
        fs::read(out).unwrap()
    }

    struct Rig {
        _dir: tempfile::TempDir,
        parent: PathBuf,
        target: PathBuf,
        fetch: FakeFetch,
        c: Component,
        digest: String,
    }

    fn rig_with(archive: impl FnOnce(&Path) -> Vec<u8>, name: &'static str, unpack: Unpack, binary: &'static str) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let bytes = archive(dir.path());
        let digest = sha256_hex(&bytes);
        let url = format!("https://github.com/x/{name}");
        let fetch = FakeFetch::new();
        fetch.body(&url, bytes);
        let parent = dir.path().join("home/.local/mvm");
        let target = parent.join("v0.22.0");
        let c = Component { name, version: "0.0.1", url, sha256: digest.clone(), max_bytes: 1 << 20, unpack, binary };
        Rig { _dir: dir, parent, target, fetch, c, digest }
    }

    fn tar_rig() -> Rig {
        rig_with(|d| tarball(d, "mvmctl"), "mvm", Unpack::TarGzStrip1, "mvmctl")
    }

    fn leftovers(parent: &Path) -> Vec<String> {
        let Ok(rd) = fs::read_dir(parent) else { return Vec::new() };
        rd.map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).filter(|n| n.starts_with(TEMP_PREFIX)).collect()
    }

    #[test]
    fn allowed_urls_are_exact() {
        for ok in ["https://github.com/a/b", "https://objects.githubusercontent.com/x", "https://release-assets.githubusercontent.com/x?sig=1", "https://github.com:443/a"] {
            assert!(allowed_url(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://github.com/a",
            "https://evil.example/a",
            "https://github.com.evil.example/a",
            "https://evilgithub.com/a",
            "https://sub.github.com/a",
            "https://github.com:8443/a",
            "https://u:p@github.com/a",
            "https://u@github.com/a",
            "https://github.com./a",
            "https://140.82.112.3/a",
            "file:///etc/passwd",
            "not a url",
        ] {
            let e = allowed_url(bad).unwrap_err();
            assert!(e.contains(bad), "{bad}: {e}");
        }
    }

    #[test]
    fn the_first_url_is_checked_before_it_is_fetched() {
        let f = FakeFetch::new();
        f.body("http://github.com/x/mvm", b"x".to_vec());
        assert!(download(&f, "http://github.com/x/mvm", 1 << 20, &mut Vec::new()).is_err());
        assert!(f.calls().is_empty());
    }

    #[test]
    fn a_redirect_to_an_unlisted_host_fails_before_it_is_fetched() {
        let f = FakeFetch::new();
        f.redirect("https://github.com/x/mvm", "https://evil.example/m");
        f.body("https://evil.example/m", b"x".to_vec());
        let e = download(&f, "https://github.com/x/mvm", 1 << 20, &mut Vec::new()).unwrap_err();
        assert!(e.contains("evil.example"), "{e}");
        assert_eq!(f.calls(), ["https://github.com/x/mvm"]);
    }

    #[test]
    fn redirects_within_the_allowlist_are_followed_up_to_five() {
        let f = FakeFetch::new();
        // r0 -> r1 -> ... -> r5 alternate between two allowed hosts; r5 is the body.
        for i in 0..MAX_REDIRECTS {
            let host = |j: usize| if j.is_multiple_of(2) { "github.com" } else { "release-assets.githubusercontent.com" };
            f.redirect(&format!("https://{}/r{i}", host(i)), &format!("https://{}/r{}", host(i + 1), i + 1));
        }
        f.body("https://release-assets.githubusercontent.com/r5", b"hello".to_vec());
        let mut out = Vec::new();
        let d = download(&f, "https://github.com/r0", 1 << 20, &mut out).unwrap();
        assert_eq!(out, b"hello");
        assert_eq!(d, Downloaded { sha256: sha256_hex(b"hello"), bytes: 5 });
        assert_eq!(f.calls().len(), 6);

        let f = FakeFetch::new();
        for i in 0..=MAX_REDIRECTS {
            f.redirect(&format!("https://github.com/r{i}"), &format!("https://github.com/r{}", i + 1));
        }
        f.body("https://github.com/r6", b"hello".to_vec());
        let e = download(&f, "https://github.com/r0", 1 << 20, &mut Vec::new()).unwrap_err();
        assert!(e.contains("redirects"), "{e}");
        assert!(!f.calls().contains(&"https://github.com/r6".to_string()), "{:?}", f.calls());
    }

    #[test]
    fn an_oversized_body_fails() {
        let f = FakeFetch::new();
        f.body("https://github.com/x/big", vec![7; 1025]);
        let mut out = Vec::new();
        let e = download(&f, "https://github.com/x/big", 1024, &mut out).unwrap_err();
        assert!(e.contains("exceeds 1024 bytes") && e.contains("https://github.com/x/big"), "{e}");
        assert!(out.len() <= 1024);

        f.body("https://github.com/x/fits", vec![7; 1024]);
        assert_eq!(download(&f, "https://github.com/x/fits", 1024, &mut Vec::new()).unwrap().bytes, 1024);
    }

    #[test]
    fn a_large_body_is_hashed_across_chunks() {
        let body: Vec<u8> = (0..(3 * CHUNK + 17)).map(|i| (i % 251) as u8).collect();
        let f = FakeFetch::new();
        f.body("https://github.com/x/large", body.clone());
        let mut out = Vec::new();
        let d = download(&f, "https://github.com/x/large", 1 << 20, &mut out).unwrap();
        assert_eq!(out, body);
        assert_eq!(d.sha256, sha256_hex(&body));
    }

    #[test]
    fn a_relative_location_is_resolved_against_the_url() {
        let u = Url::parse("https://github.com/a/b/c").unwrap();
        assert_eq!(redirect_target(&u, Some("/x/y")).unwrap(), "https://github.com/x/y");
        assert_eq!(redirect_target(&u, Some("https://objects.githubusercontent.com/z?s=1")).unwrap(), "https://objects.githubusercontent.com/z?s=1");
        let e = redirect_target(&u, None).unwrap_err();
        assert!(e.contains("https://github.com/a/b/c") && e.contains("Location"), "{e}");
    }

    #[test]
    fn the_https_client_builds() {
        assert!(HttpsFetch::new().is_ok());
    }

    #[test]
    fn a_digest_mismatch_deletes_the_download_and_installs_nothing() {
        let mut r = tar_rig();
        r.c.sha256 = "00".repeat(32);
        let e = install_component(&r.c, &r.target, &r.fetch, &RealHost).unwrap_err();
        assert!(e.contains(&"00".repeat(32)) && e.contains(&r.digest) && e.contains("sha256 mismatch") && e.contains(&r.c.url), "{e}");
        assert!(e.contains("nothing was installed"), "{e}");
        assert!(!r.target.exists());
        assert_eq!(leftovers(&r.parent), Vec::<String>::new());
    }

    #[test]
    fn a_tarball_is_unpacked_flat_and_renamed_into_place() {
        let r = tar_rig();
        install_component(&r.c, &r.target, &r.fetch, &RealHost).unwrap();
        let bin = r.target.join("mvmctl");
        let meta = fs::symlink_metadata(&bin).unwrap();
        assert!(meta.is_file());
        assert_ne!(meta.permissions().mode() & 0o111, 0, "not executable");
        assert!(!r.target.join("top").exists());
        assert_eq!(leftovers(&r.parent), Vec::<String>::new());
        assert_eq!(fs::metadata(&r.parent).unwrap().permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn a_zip_is_unpacked_with_ditto() {
        let r = rig_with(zip, "opencode", Unpack::Zip, "opencode");
        install_component(&r.c, &r.target, &r.fetch, &RealHost).unwrap();
        assert!(fs::symlink_metadata(r.target.join("opencode")).unwrap().is_file());
        assert_eq!(leftovers(&r.parent), Vec::<String>::new());
    }

    /// tar writes a partial file into the unpack directory, then is killed.
    struct KillingHost;
    impl Host for KillingHost {
        fn run(&self, argv: &[String], _timeout: Duration) -> io::Result<RunOutput> {
            assert_eq!(argv[0], "/usr/bin/tar");
            assert_eq!(argv[3], "-C");
            fs::write(Path::new(&argv[4]).join("partial"), b"half").unwrap();
            Ok(RunOutput { code: None, stdout: Vec::new(), stderr: b"tar: interrupted".to_vec(), killed: true })
        }
    }

    #[test]
    fn an_interrupted_unpack_leaves_no_partial_version() {
        let r = tar_rig();
        let e = install_component(&r.c, &r.target, &r.fetch, &KillingHost).unwrap_err();
        assert!(e.contains("tar: interrupted"), "{e}");
        assert!(!r.target.exists());
        assert_eq!(leftovers(&r.parent), Vec::<String>::new());
    }

    #[test]
    fn a_failing_unpack_reports_the_tools_stderr() {
        let r = tar_rig();
        let f = FakeFetch::new();
        let mut c = r.c.clone();
        f.body(&c.url, b"not a tarball".to_vec());
        c.sha256 = sha256_hex(b"not a tarball");
        let e = install_component(&c, &r.target, &f, &RealHost).unwrap_err();
        assert!(e.contains("/usr/bin/tar") && e.contains("nothing was installed"), "{e}");
        assert!(!r.target.exists());
        assert_eq!(leftovers(&r.parent), Vec::<String>::new());
    }

    #[test]
    fn a_stale_temp_dir_from_a_killed_run_is_removed() {
        let r = tar_rig();
        fs::create_dir_all(r.parent.join(".rts-setup-old/unpacked")).unwrap();
        fs::write(r.parent.join(".rts-setup-old/unpacked/mvmctl"), b"stale").unwrap();
        fs::write(r.parent.join("keep-me"), b"keep").unwrap();
        fs::write(r.parent.join(".rts-setup-a-file"), b"not a directory").unwrap();
        install_component(&r.c, &r.target, &r.fetch, &RealHost).unwrap();
        assert!(!r.parent.join(".rts-setup-old").exists());
        assert!(r.parent.join("keep-me").exists());
        assert!(r.parent.join(".rts-setup-a-file").exists());
        assert!(r.target.join("mvmctl").is_file());
    }

    #[test]
    fn an_archive_without_the_binary_is_refused() {
        let r = rig_with(|d| tarball(d, "other"), "mvm", Unpack::TarGzStrip1, "mvmctl");
        let e = install_component(&r.c, &r.target, &r.fetch, &RealHost).unwrap_err();
        assert!(e.contains("mvmctl") && e.contains(&r.c.url), "{e}");
        assert!(!r.target.exists());
        assert_eq!(leftovers(&r.parent), Vec::<String>::new());
    }

    #[test]
    fn an_existing_target_is_not_replaced() {
        let r = tar_rig();
        fs::create_dir_all(&r.target).unwrap();
        fs::write(r.target.join("mine"), b"x").unwrap();
        let e = install_component(&r.c, &r.target, &r.fetch, &RealHost).unwrap_err();
        assert!(e.contains(&format!("{} already exists", r.target.display())), "{e}");
        assert!(r.target.join("mine").exists());
        assert!(r.fetch.calls().is_empty(), "downloaded anyway");
    }

    #[test]
    fn the_pinned_components_match_the_spec() {
        let (m, o) = (mvm(), opencode());
        assert_eq!(m.url, "https://github.com/tinylabscom/mvm/releases/download/v0.22.0/mvmctl-aarch64-apple-darwin.tar.gz");
        assert_eq!(o.url, "https://github.com/anomalyco/opencode/releases/download/v2.2.2/opencode-darwin-arm64.zip");
        assert_eq!(m.sha256, "1f2c80b253add28c3856080e3f3a10aa1163f1aef0a7d413ded15100bdcd0c69");
        assert_eq!(o.sha256, "c1c901a6379d667b7a30a3eea5a8f6e93416dba43e889e834771f6fb174f35c9");
        assert!(allowed_url(&m.url).is_ok() && allowed_url(&o.url).is_ok());
        assert_eq!((m.max_bytes, o.max_bytes), (64 << 20, 256 << 20));
        assert_eq!((m.name, m.version, m.unpack, m.binary), ("mvm", "0.22.0", Unpack::TarGzStrip1, "mvmctl"));
        assert_eq!((o.name, o.version, o.unpack, o.binary), ("opencode", "2.2.2", Unpack::Zip, "opencode"));
    }

    // --- rts setup: checks, order and modes ---

    use crate::config::{DEFAULT_IMAGE, Defaults};
    use crate::install::{mvm_dir, opencode_dir};
    use crate::mvm::Runner;
    use crate::session::{SUPERVISOR_CONTRACT_PROBE, SUPERVISOR_PROBE};
    use std::sync::{Arc, Mutex};

    type Log = Arc<Mutex<Vec<String>>>;
    type Answer = Box<dyn Fn(&[String]) -> io::Result<RunOutput> + Send + Sync>;

    fn out(code: i32, stdout: &str, stderr: &str) -> RunOutput {
        RunOutput { code: Some(code), stdout: stdout.into(), stderr: stderr.into(), killed: false }
    }

    /// A `Host` and a `Runner` that answers from a closure, recording each argv
    /// in its own list and, tagged, in a log shared with the other seams.
    struct Recorder {
        tag: &'static str,
        answer: Answer,
        calls: Mutex<Vec<Vec<String>>>,
        log: Log,
    }

    impl Recorder {
        fn new(tag: &'static str, log: &Log, answer: impl Fn(&[String]) -> io::Result<RunOutput> + Send + Sync + 'static) -> Self {
            Self { tag, answer: Box::new(answer), calls: Mutex::new(Vec::new()), log: log.clone() }
        }
        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
        fn record(&self, argv: &[String]) -> io::Result<RunOutput> {
            self.calls.lock().unwrap().push(argv.to_vec());
            // The unpack tools' argv names temp paths; log only the tool.
            let shown = if argv[0] == "/usr/bin/tar" || argv[0] == "/usr/bin/ditto" { argv[0].clone() } else { argv.join(" ") };
            self.log.lock().unwrap().push(format!("{} {shown}", self.tag));
            (self.answer)(argv)
        }
    }

    impl Host for Recorder {
        fn run(&self, argv: &[String], _timeout: Duration) -> io::Result<RunOutput> {
            self.record(argv)
        }
    }

    impl Runner for Recorder {
        fn run(&self, argv: &[String], _timeout: Duration) -> io::Result<RunOutput> {
            self.record(argv)
        }
    }

    /// A `FakeFetch` that also writes each URL to the shared log.
    struct LoggedFetch {
        inner: FakeFetch,
        log: Log,
    }

    impl Fetch for LoggedFetch {
        fn get(&self, url: &Url) -> Result<Hop, String> {
            self.log.lock().unwrap().push(format!("fetch {url}"));
            self.inner.get(url)
        }
    }

    /// Runs the real unpack tools; answers the supervisor probes, `opencode
    /// --version` and codesign as a healthy install would.
    fn host_ok(a: &[String]) -> io::Result<RunOutput> {
        match a[0].as_str() {
            "/usr/bin/tar" | "/usr/bin/ditto" => RealHost.run(a, Duration::from_secs(600)),
            "/usr/bin/codesign" => Ok(out(0, "", "")),
            _ => Ok(match a.last().map(String::as_str) {
                Some(SUPERVISOR_PROBE) => out(0, "rts-vsock-drain-v1\n", ""),
                Some(SUPERVISOR_CONTRACT_PROBE) => out(0, "mvm-hvf-supervisor contract-version=4\n", ""),
                Some("--version") => out(0, "2.2.2\n", ""),
                _ => panic!("unexpected host call {a:?}"),
            }),
        }
    }

    fn plain_ok(a: &[String]) -> io::Result<RunOutput> {
        Ok(match a.iter().map(String::as_str).collect::<Vec<_>>()[..] {
            ["--version"] => out(0, "mvmctl 0.22.0\n", ""),
            ["env", "sign"] => out(0, "", ""),
            _ => panic!("unexpected mvm_plain call {a:?}"),
        })
    }

    /// Doctor passes; the image is not cached; a pull succeeds.
    fn mvm_ok(a: &[String]) -> io::Result<RunOutput> {
        Ok(match a.iter().map(String::as_str).collect::<Vec<_>>()[..] {
            ["doctor"] => out(0, "", ""),
            ["image", "inspect", _] => out(1, "", "not cached"),
            ["image", "pull", _] => out(0, "", ""),
            _ => panic!("unexpected mvm call {a:?}"),
        })
    }

    fn mvm_cached(a: &[String]) -> io::Result<RunOutput> {
        if a.get(1).map(String::as_str) == Some("inspect") { Ok(out(0, "", "")) } else { mvm_ok(a) }
    }

    struct SetupRig {
        _dir: tempfile::TempDir,
        home: PathBuf,
        supervisor: PathBuf,
        rts: PathBuf,
        defaults: Defaults,
        explicit_mvmctl: bool,
        components: (Component, Component),
        log: Log,
        fetch: LoggedFetch,
    }

    struct Seams {
        host: Recorder,
        plain: Recorder,
        mvm: Recorder,
    }

    impl SetupRig {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let fixtures = dir.path().join("fixtures");
            fs::create_dir_all(&fixtures).unwrap();
            let (tgz, zipped) = (tarball(&fixtures, "mvmctl"), zip(&fixtures));
            let fetch = FakeFetch::new();
            let mvm_c = Component { url: "https://github.com/fixture/mvm.tar.gz".into(), sha256: sha256_hex(&tgz), max_bytes: 1 << 20, ..mvm() };
            let oc_c = Component { url: "https://github.com/fixture/opencode.zip".into(), sha256: sha256_hex(&zipped), max_bytes: 1 << 20, ..opencode() };
            fetch.body(&mvm_c.url, tgz);
            fetch.body(&oc_c.url, zipped);
            let home = dir.path().join("home");
            fs::create_dir_all(&home).unwrap();
            let plugin = dir.path().join("plugin");
            fs::create_dir_all(&plugin).unwrap();
            fs::write(plugin.join("package.json"), "{}").unwrap();
            fs::write(plugin.join("index.ts"), "").unwrap();
            fs::create_dir_all(plugin.join("branding")).unwrap();
            fs::write(plugin.join("branding/tui.tsx"), "").unwrap();
            fs::write(plugin.join("branding/footer.ts"), "").unwrap();
            fs::create_dir_all(plugin.join("branding/theme")).unwrap();
            fs::write(plugin.join(crate::brand::theme::THEME_FILE), "{}").unwrap();
            let defaults = Defaults {
                mvmctl: mvm_dir(&home).join("mvmctl"),
                plugin_dir: plugin,
                opencode: "opencode".into(),
                sessions_dir: home.join("sessions"),
            };
            let log: Log = Arc::default();
            SetupRig {
                supervisor: dir.path().join("libexec/mvm-hvf-supervisor"),
                rts: dir.path().join("bin/rts"),
                home,
                defaults,
                explicit_mvmctl: false,
                components: (mvm_c, oc_c),
                fetch: LoggedFetch { inner: fetch, log: log.clone() },
                log,
                _dir: dir,
            }
        }

        fn seams(
            &self,
            host: impl Fn(&[String]) -> io::Result<RunOutput> + Send + Sync + 'static,
            plain: impl Fn(&[String]) -> io::Result<RunOutput> + Send + Sync + 'static,
            mvm: impl Fn(&[String]) -> io::Result<RunOutput> + Send + Sync + 'static,
        ) -> Seams {
            self.log.lock().unwrap().clear();
            Seams { host: Recorder::new("host", &self.log, host), plain: Recorder::new("plain", &self.log, plain), mvm: Recorder::new("mvm", &self.log, mvm) }
        }

        fn run(&self, o: SetupOptions, s: &Seams) -> Result<Vec<String>, String> {
            let ctx = SetupContext {
                home: &self.home,
                defaults: &self.defaults,
                explicit_mvmctl: self.explicit_mvmctl,
                supervisor: &self.supervisor,
                rts: &self.rts,
                fetch: &self.fetch,
                host: &s.host,
                mvm_plain: &s.plain,
                mvm: &s.mvm,
            };
            run_with(&o, &ctx, (&self.components.0, &self.components.1))
        }

        fn log(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }

        fn fetches(&self) -> Vec<String> {
            self.fetch.inner.calls()
        }

        fn opencode(&self) -> PathBuf {
            opencode_dir(&self.home).join("opencode")
        }
    }

    fn has_word(calls: &[Vec<String>], word: &str) -> bool {
        calls.iter().any(|a| a.iter().any(|w| w == word))
    }

    #[test]
    fn a_fresh_setup_installs_signs_checks_and_pulls_in_order() {
        let r = SetupRig::new();
        let s = r.seams(host_ok, plain_ok, mvm_ok);
        let lines = r.run(SetupOptions::default(), &s).unwrap();
        let sup = r.supervisor.display().to_string();
        let oc = r.opencode().display().to_string();
        assert_eq!(
            r.log(),
            [
                format!("fetch {}", r.components.0.url),
                "host /usr/bin/tar".into(),
                "plain --version".into(),
                "plain env sign".into(),
                "mvm doctor".into(),
                format!("host {sup} --rts-vsock-drain-fix-version"),
                format!("host {sup} --contract-version"),
                format!("fetch {}", r.components.1.url),
                "host /usr/bin/ditto".into(),
                format!("host {oc} --version"),
                format!("mvm image inspect {DEFAULT_IMAGE}"),
                format!("mvm image pull {DEFAULT_IMAGE}"),
            ]
        );
        assert!(!has_word(&s.mvm.calls(), "sign"), "env sign went to the supervisor-pinned runner");
        assert_eq!(lines.len(), 4, "{lines:?}"); // mvm, supervisor, opencode, image
        assert!(lines[0].contains("mvm 0.22.0") && lines[0].contains(".local/mvm/v0.22.0"), "{lines:?}");
        assert!(lines[1].contains("rts-vsock-drain-v1") && lines[1].contains(&sup), "{lines:?}");
        assert!(lines[2].contains("opencode 2.2.2") && lines[2].contains(&oc), "{lines:?}");
        assert!(lines[3].contains(DEFAULT_IMAGE), "{lines:?}");
        assert!(mvm_dir(&r.home).join("mvmctl").is_file() && r.opencode().is_file());
    }

    #[test]
    fn a_correct_install_is_skipped() {
        let r = SetupRig::new();
        r.run(SetupOptions::default(), &r.seams(host_ok, plain_ok, mvm_ok)).unwrap();
        let fetched = r.fetches().len();
        let s = r.seams(host_ok, plain_ok, mvm_cached);
        let lines = r.run(SetupOptions::default(), &s).unwrap();
        assert_eq!(r.fetches().len(), fetched, "downloaded again");
        assert!(!r.log().iter().any(|l| l.starts_with("fetch") || l.contains("/usr/bin/tar") || l.contains("/usr/bin/ditto")), "{:?}", r.log());
        assert!(!has_word(&s.mvm.calls(), "pull"));
        assert_eq!(lines.len(), 4, "{lines:?}");
    }

    #[test]
    fn env_sign_never_sees_the_supervisor_override() {
        let env: Vec<(String, String)> = vec![
            ("HOME".into(), "/h".into()),
            ("MVM_HOME".into(), "/m".into()),
            ("MVM_HVF_SUPERVISOR_PATH".into(), "/s".into()),
            ("SECRET".into(), "x".into()),
        ];
        let e = plain_mvm_env(&env);
        assert_eq!(e.len(), 2);
        assert!(!e.contains_key("MVM_HVF_SUPERVISOR_PATH"));
        assert_eq!((e["HOME"].as_str(), e["MVM_HOME"].as_str()), ("/h", "/m"));
        // a_fresh_setup_installs_signs_checks_and_pulls_in_order also checks
        // that ["env", "sign"] went to mvm_plain, never to mvm.
    }

    #[test]
    fn the_plain_runner_removes_an_inherited_supervisor_override() {
        let env: Vec<(String, String)> = vec![("HOME".into(), "/h".into()), ("MVM_HVF_SUPERVISOR_PATH".into(), "/s".into())];
        let r = plain_mvm_runner(Path::new("/bin/mvmctl"), Path::new("/g"), &env);
        let cmd = r.command(&["env".to_string(), "sign".to_string()]);
        let envs: Vec<_> = cmd.get_envs().map(|(k, v)| (k.to_os_string(), v.map(|v| v.to_os_string()))).collect();
        assert!(envs.contains(&("MVM_HVF_SUPERVISOR_PATH".into(), None)), "{envs:?}");
        assert!(envs.contains(&("HOME".into(), Some("/h".into()))), "{envs:?}");
    }

    #[test]
    fn a_missing_or_old_supervisor_marker_fails_with_the_fix() {
        let r = SetupRig::new();
        for bad in [out(0, "", ""), out(0, "rts-vsock-drain-v0\n", ""), out(1, "rts-vsock-drain-v1\n", "")] {
            let s = r.seams(move |a| if a.last().map(String::as_str) == Some(SUPERVISOR_PROBE) { Ok(bad.clone()) } else { host_ok(a) }, plain_ok, mvm_ok);
            let e = r.run(SetupOptions::default(), &s).unwrap_err();
            assert!(e.contains("rts-vsock-drain-v1") && e.contains("rts setup") && e.contains(&r.supervisor.display().to_string()), "{e}");
            assert!(!r.log().iter().any(|l| l.contains("opencode") || l.contains("image")), "went on after the failure: {:?}", r.log());
        }
        let s = r.seams(
            |a| if a.last().map(String::as_str) == Some(SUPERVISOR_CONTRACT_PROBE) { Ok(out(0, "mvm-hvf-supervisor contract-version=3\n", "")) } else { host_ok(a) },
            plain_ok,
            mvm_ok,
        );
        let e = r.run(SetupOptions::default(), &s).unwrap_err();
        assert!(e.contains("contract-version=4") && e.contains("rts setup"), "{e}");
    }

    #[test]
    fn a_wrong_opencode_version_fails() {
        let r = SetupRig::new();
        fs::create_dir_all(opencode_dir(&r.home)).unwrap();
        fs::write(r.opencode(), "old").unwrap();
        let s = r.seams(|a| if a.last().map(String::as_str) == Some("--version") { Ok(out(0, "2.1.4\n", "")) } else { host_ok(a) }, plain_ok, mvm_ok);
        let e = r.run(SetupOptions::default(), &s).unwrap_err();
        assert!(e.contains("2.2.2") && e.contains("2.1.4") && e.contains(&opencode_dir(&r.home).display().to_string()), "{e}");
        assert!(e.contains("remove it and re-run rts setup"), "{e}");
        assert!(!r.fetches().contains(&r.components.1.url), "{:?}", r.fetches());
        assert_eq!(fs::read(r.opencode()).unwrap(), b"old");
    }

    #[test]
    fn an_existing_mvm_that_does_not_verify_is_refused_not_replaced() {
        let r = SetupRig::new();
        let dir = mvm_dir(&r.home);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("mvmctl"), "mine").unwrap();
        let s = r.seams(host_ok, |a| if a == ["--version"] { Ok(out(0, "mvmctl 0.21.0\n", "")) } else { plain_ok(a) }, mvm_ok);
        let e = r.run(SetupOptions::default(), &s).unwrap_err();
        assert!(e.contains("remove it") && e.contains(&dir.display().to_string()) && e.contains("0.21.0"), "{e}");
        assert_eq!(fs::read(dir.join("mvmctl")).unwrap(), b"mine");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        assert!(r.fetches().is_empty());
        assert!(!has_word(&s.plain.calls(), "sign"));
    }

    #[test]
    fn an_explicit_mvmctl_is_verified_never_downloaded() {
        let mut r = SetupRig::new();
        r.explicit_mvmctl = true;
        r.defaults.mvmctl = PathBuf::from("/opt/custom/mvmctl");
        let s = r.seams(host_ok, plain_ok, mvm_ok);
        let lines = r.run(SetupOptions::default(), &s).unwrap();
        assert!(lines[0].contains("/opt/custom/mvmctl"), "{lines:?}");
        assert!(!r.fetches().contains(&r.components.0.url));
        assert!(!mvm_dir(&r.home).exists());

        let s = r.seams(host_ok, |a| if a == ["--version"] { Ok(out(0, "mvmctl 0.21.0\n", "")) } else { plain_ok(a) }, mvm_ok);
        let e = r.run(SetupOptions::default(), &s).unwrap_err();
        assert!(e.contains("RTS_MVMCTL") && e.contains("/opt/custom/mvmctl"), "{e}");
    }

    #[test]
    fn check_makes_no_network_calls_and_changes_nothing() {
        let r = SetupRig::new();
        let s = r.seams(host_ok, plain_ok, mvm_ok);
        let e = r.run(SetupOptions { check: true, offline: false }, &s).unwrap_err();
        assert!(r.fetches().is_empty());
        for calls in [s.plain.calls(), s.mvm.calls()] {
            assert!(!has_word(&calls, "sign") && !has_word(&calls, "pull"), "{calls:?}");
        }
        assert!(e.lines().count() >= 2 && e.contains("run rts setup"), "{e}"); // every failure reported, not just the first
        assert!(e.contains("mvm 0.22.0") && e.contains("opencode 2.2.2"), "{e}");
        assert!(!r.home.join(".local").exists());
    }

    #[test]
    fn check_reports_an_uncached_image_and_passes_a_complete_install() {
        let r = SetupRig::new();
        r.run(SetupOptions::default(), &r.seams(host_ok, plain_ok, mvm_ok)).unwrap();
        let check = SetupOptions { check: true, offline: false };
        let s = r.seams(host_ok, plain_ok, mvm_ok);
        let e = r.run(check, &s).unwrap_err();
        assert!(e.contains(DEFAULT_IMAGE) && e.contains("run rts setup") && e.lines().count() == 1, "{e}");
        assert!(!has_word(&s.mvm.calls(), "pull") && !has_word(&s.plain.calls(), "sign"));

        let s = r.seams(host_ok, plain_ok, mvm_cached);
        assert_eq!(r.run(check, &s).unwrap().len(), 4);
        assert!(r.log().contains(&"mvm doctor".to_string()), "{:?}", r.log());
        assert!(r.fetches().len() == 2, "{:?}", r.fetches());
    }

    #[test]
    fn offline_check_reads_only_the_installed_layout() {
        let r = SetupRig::new();
        let offline = SetupOptions { check: true, offline: true };
        let s = r.seams(host_ok, plain_ok, mvm_ok);
        r.run(offline, &s).unwrap();
        assert!(s.mvm.calls().is_empty() && s.plain.calls().is_empty() && r.fetches().is_empty());
        let sup = r.supervisor.display().to_string();
        let programs: Vec<String> = s.host.calls().iter().map(|a| a[0].clone()).collect();
        assert_eq!(programs, [sup.as_str(), sup.as_str(), "/usr/bin/codesign", "/usr/bin/codesign"]);
        let calls = s.host.calls();
        assert_eq!(calls[2], ["/usr/bin/codesign", "--verify", "--strict", r.rts.to_str().unwrap()]);
        assert_eq!(calls[3], ["/usr/bin/codesign", "--verify", "--strict", sup.as_str()]);

        fs::remove_file(r.defaults.plugin_dir.join("index.ts")).unwrap();
        let s = r.seams(host_ok, plain_ok, mvm_ok);
        let e = r.run(offline, &s).unwrap_err();
        assert!(e.contains(&r.defaults.plugin_dir.join("index.ts").display().to_string()), "{e}");
        fs::remove_file(r.defaults.plugin_dir.join("branding/tui.tsx")).unwrap();
        let s = r.seams(host_ok, plain_ok, mvm_ok);
        let e = r.run(offline, &s).unwrap_err();
        assert!(e.contains(&r.defaults.plugin_dir.join("branding/tui.tsx").display().to_string()), "{e}");
        fs::remove_file(r.defaults.plugin_dir.join("branding/footer.ts")).unwrap();
        let s = r.seams(host_ok, plain_ok, mvm_ok);
        let e = r.run(offline, &s).unwrap_err();
        assert!(e.contains(&r.defaults.plugin_dir.join("branding/footer.ts").display().to_string()), "{e}");
        fs::remove_file(r.defaults.plugin_dir.join(crate::brand::theme::THEME_FILE)).unwrap();
        let s = r.seams(host_ok, plain_ok, mvm_ok);
        let e = r.run(offline, &s).unwrap_err();
        assert!(e.contains("branding/theme/nearai-red.json"), "{e}");

        let s = r.seams(|a| if a[0] == "/usr/bin/codesign" { Ok(out(1, "", "invalid signature")) } else { host_ok(a) }, plain_ok, mvm_ok);
        let e = r.run(offline, &s).unwrap_err();
        assert!(e.contains(r.rts.to_str().unwrap()) && e.contains(&sup) && e.contains("invalid signature"), "{e}");
        assert!(s.mvm.calls().is_empty() && s.plain.calls().is_empty());
    }
}

//! `rts update`: install the newest signed release over a curl install by
//! running that release's own `install.sh`, pinned by the signed manifest.
//!
//! Nothing runs before its digest is checked: the manifest's signature is
//! verified over the exact fetched bytes, `install.sh` must match the signed
//! `install_sh.sha256`, and the installer is handed the signed tarball digest
//! (`RTS_TARBALL_SHA256`), which `install.sh` checks next to `SHA256SUMS`.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use ironwire_update::{UpdateStatus, evaluate};

use super::manifest::{self, MANIFEST_URL};
use super::{Channel, UPDATE_KEY, channel};
use crate::session::{Host, RealHost};
use crate::setup::{Fetch, HttpsFetch, download};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UpdateOptions {
    pub check: bool,
    pub force: bool,
}

pub const RELEASE_DOWNLOAD: &str = "https://github.com/nearai/nearai-red-sandbox/releases/download";
pub const MAX_INSTALL_SH_BYTES: u64 = 64 << 10;
pub const TEAM_REQUIREMENT: &str = r#"anchor apple generic and certificate leaf[subject.OU] = "KXSWJN7WY8""#;
/// Each post-install check (codesign, `--version`).
const CHECK_TIMEOUT: Duration = Duration::from_secs(30);

/// Runs install.sh with inherited stdio and no timeout.
pub trait Installer {
    /// `set` is added to the inherited environment after `remove` is removed. Returns the exit code.
    fn run(&self, script: &Path, set: &[(String, String)], remove: &[&str]) -> Result<i32, String>;
}

pub struct BashInstaller;

impl Installer for BashInstaller {
    fn run(&self, script: &Path, set: &[(String, String)], remove: &[&str]) -> Result<i32, String> {
        let mut cmd = Command::new("/bin/bash");
        cmd.arg(script);
        for k in remove {
            cmd.env_remove(k);
        }
        cmd.envs(set.iter().map(|(k, v)| (k, v)));
        let status = cmd.status().map_err(|e| format!("running /bin/bash {}: {e}", script.display()))?;
        status
            .code()
            .ok_or_else(|| format!("/bin/bash {} was killed by a signal", script.display()))
    }
}

pub struct UpdateContext<'a> {
    pub current: &'a str,
    pub channel: &'a Channel,
    pub key: Option<[u8; 32]>,
    pub fetch: &'a dyn Fetch,
    /// codesign and --version, 30 s each.
    pub host: &'a dyn Host,
    pub installer: &'a dyn Installer,
    /// Parent for the private stage directory.
    pub temp_dir: &'a Path,
    /// Progress lines that must appear before install.sh runs (command passes println!).
    pub say: &'a dyn Fn(&str),
}

/// The spec's steps 1-8. Ok lines are printed by `command`.
pub fn run(o: &UpdateOptions, c: &UpdateContext) -> Result<Vec<String>, String> {
    // 1. Who owns this install.
    if *c.channel == Channel::Homebrew {
        return Err("rts was installed with Homebrew: run brew upgrade rts".into());
    }
    let Some(key) = c.key else {
        return Err("this build has no update key; install a release".into());
    };
    let Channel::Release { prefix } = c.channel else {
        return Err("this is a source build; install a release".into());
    };

    // 2. The signed manifest.
    let signed = manifest::fetch(c.fetch, &key)
        .map_err(|e| format!("fetching the update manifest {MANIFEST_URL}: {e}"))?;
    let latest = signed.manifest.latest.as_str();
    let current = c.current;

    // 3-4. Compare; --check stops here.
    match evaluate(current, &signed.manifest, c.channel.method()) {
        UpdateStatus::Available { .. } => {
            if o.check {
                return Ok(vec![format!("rts {latest} is available (you have {current}): run rts update")]);
            }
        }
        UpdateStatus::Unsupported { minimum_supported, .. } => {
            if o.check {
                return Ok(vec![format!(
                    "rts {current} is older than the oldest supported release, {minimum_supported}, and may not work: run rts update to install {latest}"
                )]);
            }
        }
        UpdateStatus::UpToDate => {
            if o.check {
                return Ok(vec![format!("rts {current} is up to date (latest release {latest})")]);
            }
            if !o.force {
                return Err(format!(
                    "rts {latest} is not newer than the running {current}; pass --force to reinstall it"
                ));
            }
        }
        UpdateStatus::Unknown => {
            return Err(format!(
                "cannot compare the running version {current:?} with the latest release {latest:?}; install a release with the curl installer"
            ));
        }
    }

    // 5. The versioned install.sh, checked against the signed digest before it touches disk.
    let url = format!("{RELEASE_DOWNLOAD}/v{latest}/install.sh");
    let mut script = Vec::new();
    let got = download(c.fetch, &url, MAX_INSTALL_SH_BYTES, &mut script)
        .map_err(|e| format!("downloading install.sh for rts {latest}: {e}"))?;
    let want = &signed.install_sh.sha256;
    if got.sha256 != *want {
        return Err(format!(
            "install.sh from {url} has sha256 {}, but the signed update manifest says {want}; refusing to run it",
            got.sha256
        ));
    }
    // Explicitly 0700: tempfile's directories otherwise follow the umask.
    let stage = tempfile::Builder::new()
        .prefix("rts-update-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(c.temp_dir)
        .map_err(|e| format!("creating a private directory under {}: {e}", c.temp_dir.display()))?;
    let path = stage.path().join("install.sh");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut f| f.write_all(&script))
        .map_err(|e| format!("writing {}: {e}", path.display()))?;

    // 6. Run it.
    let prefix_text = prefix.display().to_string();
    (c.say)(&format!("installing rts {latest} over {current} to {prefix_text}"));
    let set = [
        ("RTS_VERSION".to_string(), latest.to_string()),
        ("RTS_INSTALL_PREFIX".to_string(), prefix_text.clone()),
        ("RTS_TARBALL_SHA256".to_string(), signed.tarball.sha256.clone()),
    ];
    let status = c.installer.run(&path, &set, &["RTS_RELEASE_BASE"]);
    drop(stage);
    match status {
        Ok(0) => {}
        Ok(n) => return Err(format!("install.sh for rts {latest} exited {n}; see its output above")),
        Err(e) => return Err(format!("install.sh for rts {latest}: {e}")),
    }

    // 7. The new binary: Developer ID signature for the team, then its version.
    let rts = prefix.join("bin/rts");
    let rts_text = rts.display().to_string();
    let failed = |check: &str, detail: String| {
        format!("rts {latest} was installed to {prefix_text} but {check} failed: {detail}; reinstall with the curl installer")
    };
    let argv = [
        "/usr/bin/codesign".to_string(),
        "--verify".to_string(),
        "--strict".to_string(),
        format!("-R={TEAM_REQUIREMENT}"),
        rts_text.clone(),
    ];
    let out = c
        .host
        .run(&argv, CHECK_TIMEOUT)
        .map_err(|e| failed("the code signature check", format!("running /usr/bin/codesign: {e}")))?;
    if out.code != Some(0) {
        let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(failed(
            "the code signature check",
            format!("/usr/bin/codesign exited {} ({detail})", exit_text(out.code, out.killed)),
        ));
    }
    let out = c
        .host
        .run(&[rts_text.clone(), "--version".to_string()], CHECK_TIMEOUT)
        .map_err(|e| failed("the version check", format!("running {rts_text} --version: {e}")))?;
    let reported = String::from_utf8_lossy(&out.stdout);
    let reported = reported.strip_suffix('\n').unwrap_or(&reported);
    let expected = format!("rts {latest}");
    if out.code != Some(0) || reported != expected {
        return Err(failed(
            "the version check",
            format!("{rts_text} --version printed {reported:?} (exit {}), expected {expected:?}", exit_text(out.code, out.killed)),
        ));
    }

    // 8.
    Ok(vec![format!("rts updated from {current} to {latest} ({rts_text})")])
}

fn exit_text(code: Option<i32>, killed: bool) -> String {
    match code {
        Some(n) => n.to_string(),
        None if killed => "timed out".into(),
        None => "signal".into(),
    }
}

/// Real wiring: current_exe -> channel, UPDATE_KEY, HttpsFetch::new(), RealHost, BashInstaller, std::env::temp_dir().
pub fn command(o: &UpdateOptions) -> Result<i32, String> {
    let exe = std::env::current_exe().map_err(|e| format!("finding the running rts: {e}"))?;
    let ch = channel(&exe);
    let fetch = HttpsFetch::new()?;
    let temp = std::env::temp_dir();
    let say = |s: &str| println!("{s}");
    let lines = run(
        o,
        &UpdateContext {
            current: env!("CARGO_PKG_VERSION"),
            channel: &ch,
            key: UPDATE_KEY,
            fetch: &fetch,
            host: &RealHost,
            installer: &BashInstaller,
            temp_dir: &temp,
            say: &say,
        },
    )?;
    for line in lines {
        println!("{line}");
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mvm::RunOutput;
    use crate::setup::FakeFetch;
    use crate::update::manifest::{MANIFEST_URL, SIGNATURE_URL};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    const INSTALL_SH: &[u8] = b"#!/bin/bash\necho fake\n";
    const INSTALL_SH_URL: &str = "https://github.com/nearai/nearai-red-sandbox/releases/download/v0.2.0/install.sh";
    const TARBALL_SHA: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn sha256_hex(b: &[u8]) -> String {
        Sha256::digest(b).iter().map(|b| format!("{b:02x}")).collect()
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    fn manifest_text(latest: &str) -> String {
        format!(
            "{{\n  \"latest\": \"{latest}\",\n  \"published\": \"2026-11-02T18:04:11Z\",\n  \"tarball\": {{\n    \"name\": \"rts-{latest}-aarch64-apple-darwin.tar.gz\",\n    \"sha256\": \"{TARBALL_SHA}\"\n  }},\n  \"install_sh\": {{\n    \"sha256\": \"{}\"\n  }}\n}}\n",
            sha256_hex(INSTALL_SH)
        )
    }

    /// Serves the signed 0.2.0 manifest and `served` at the versioned install.sh URL.
    fn serving(served: &[u8]) -> FakeFetch {
        let text = manifest_text("0.2.0");
        let f = FakeFetch::new();
        f.body(SIGNATURE_URL, STANDARD.encode(key().sign(text.as_bytes()).to_bytes()).into_bytes());
        f.body(MANIFEST_URL, text.into_bytes());
        f.body(INSTALL_SH_URL, served.to_vec());
        f
    }

    #[derive(Debug, Clone)]
    struct Call {
        script: PathBuf,
        set: Vec<(String, String)>,
        remove: Vec<String>,
        bytes: Vec<u8>,
    }

    struct FakeInstaller {
        code: i32,
        calls: Mutex<Vec<Call>>,
        events: Arc<Mutex<Vec<String>>>,
    }

    impl Installer for FakeInstaller {
        fn run(&self, script: &Path, set: &[(String, String)], remove: &[&str]) -> Result<i32, String> {
            self.events.lock().unwrap().push("installer".into());
            self.calls.lock().unwrap().push(Call {
                script: script.to_path_buf(),
                set: set.to_vec(),
                remove: remove.iter().map(|s| s.to_string()).collect(),
                bytes: std::fs::read(script).unwrap(),
            });
            Ok(self.code)
        }
    }

    struct FakeHost {
        codesign: i32,
        version: String,
        calls: Mutex<Vec<Vec<String>>>,
    }

    impl crate::session::Host for FakeHost {
        fn run(&self, argv: &[String], _: Duration) -> io::Result<RunOutput> {
            self.calls.lock().unwrap().push(argv.to_vec());
            let (code, stdout) = if argv[0] == "/usr/bin/codesign" {
                (self.codesign, Vec::new())
            } else {
                (0, self.version.clone().into_bytes())
            };
            Ok(RunOutput { code: Some(code), stdout, stderr: b"detail".to_vec(), killed: false })
        }
    }

    struct Rig {
        _dir: tempfile::TempDir,
        prefix: PathBuf,
        temp: PathBuf,
        channel: Channel,
        fetch: FakeFetch,
        host: FakeHost,
        installer: FakeInstaller,
        events: Arc<Mutex<Vec<String>>>,
        current: String,
        key: Option<[u8; 32]>,
    }

    impl Rig {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let prefix = dir.path().join("prefix");
            std::fs::create_dir_all(prefix.join("bin")).unwrap();
            std::fs::write(prefix.join("bin/rts"), b"").unwrap();
            std::fs::create_dir_all(prefix.join("share/nearai-red-sandbox/plugin")).unwrap();
            let temp = dir.path().join("tmp");
            std::fs::create_dir(&temp).unwrap();
            let events = Arc::new(Mutex::new(Vec::new()));
            Rig {
                channel: Channel::Release { prefix: prefix.clone() },
                prefix,
                temp,
                _dir: dir,
                fetch: serving(INSTALL_SH),
                host: FakeHost { codesign: 0, version: "rts 0.2.0\n".into(), calls: Mutex::new(Vec::new()) },
                installer: FakeInstaller { code: 0, calls: Mutex::new(Vec::new()), events: Arc::clone(&events) },
                events,
                current: "0.1.0".into(),
                key: Some(key().verifying_key().to_bytes()),
            }
        }

        fn run(&self, o: UpdateOptions) -> Result<Vec<String>, String> {
            let events = Arc::clone(&self.events);
            let say = move |s: &str| events.lock().unwrap().push(format!("say: {s}"));
            run(
                &o,
                &UpdateContext {
                    current: &self.current,
                    channel: &self.channel,
                    key: self.key,
                    fetch: &self.fetch,
                    host: &self.host,
                    installer: &self.installer,
                    temp_dir: &self.temp,
                    say: &say,
                },
            )
        }

        fn installs(&self) -> Vec<Call> {
            self.installer.calls.lock().unwrap().clone()
        }
        fn host_calls(&self) -> Vec<Vec<String>> {
            self.host.calls.lock().unwrap().clone()
        }
        fn rts(&self) -> String {
            self.prefix.join("bin/rts").display().to_string()
        }
    }

    const PLAIN: UpdateOptions = UpdateOptions { check: false, force: false };
    const CHECK: UpdateOptions = UpdateOptions { check: true, force: false };
    const FORCE: UpdateOptions = UpdateOptions { check: false, force: true };

    #[test]
    fn homebrew_is_refused_with_the_brew_command() {
        let mut r = Rig::new();
        r.channel = Channel::Homebrew;
        assert_eq!(r.run(PLAIN).unwrap_err(), "rts was installed with Homebrew: run brew upgrade rts");
        assert_eq!(r.run(CHECK).unwrap_err(), "rts was installed with Homebrew: run brew upgrade rts");
        assert!(r.fetch.calls().is_empty());
    }

    #[test]
    fn a_keyless_build_is_refused() {
        let mut r = Rig::new();
        r.key = None;
        assert_eq!(r.run(PLAIN).unwrap_err(), "this build has no update key; install a release");
        r.channel = Channel::Source;
        assert_eq!(r.run(CHECK).unwrap_err(), "this build has no update key; install a release");
        assert!(r.fetch.calls().is_empty());
    }

    #[test]
    fn a_source_build_is_refused() {
        let mut r = Rig::new();
        r.channel = Channel::Source;
        let e = r.run(PLAIN).unwrap_err();
        assert!(e.contains("install a release"), "{e}");
        assert!(r.fetch.calls().is_empty());
        assert!(r.installs().is_empty());
    }

    #[test]
    fn check_only_reports() {
        let r = Rig::new();
        let lines = r.run(CHECK).unwrap();
        assert!(lines.iter().any(|l| l.contains("0.2.0")), "{lines:?}");
        assert_eq!(r.fetch.calls(), vec![MANIFEST_URL.to_string(), SIGNATURE_URL.to_string()]);
        assert!(r.installs().is_empty());
        assert!(r.host_calls().is_empty());

        let mut r = Rig::new();
        r.current = "0.2.0".into();
        assert_eq!(r.run(CHECK).unwrap(), vec!["rts 0.2.0 is up to date (latest release 0.2.0)".to_string()]);
        assert!(r.installs().is_empty());
    }

    #[test]
    fn not_newer_is_refused_unless_forced() {
        let mut r = Rig::new();
        r.current = "0.2.0".into();
        let e = r.run(PLAIN).unwrap_err();
        assert!(e.contains("--force"), "{e}");
        assert!(e.contains("0.2.0"), "{e}");
        assert!(r.installs().is_empty());

        // A downgrade is refused the same way.
        r.current = "0.3.0".into();
        let e = r.run(PLAIN).unwrap_err();
        assert!(e.contains("--force"), "{e}");
        assert!(r.installs().is_empty());

        r.current = "0.2.0".into();
        r.run(FORCE).unwrap();
        assert_eq!(r.installs().len(), 1);
    }

    #[test]
    fn an_unreadable_version_is_refused_even_forced() {
        let mut r = Rig::new();
        r.current = "dev".into();
        assert!(r.run(PLAIN).is_err());
        assert!(r.run(FORCE).is_err());
        assert!(r.run(CHECK).is_err());
        assert!(r.installs().is_empty());
    }

    #[test]
    fn an_install_sh_digest_mismatch_runs_nothing() {
        let mut r = Rig::new();
        let evil = b"#!/bin/bash\necho evil\n";
        r.fetch = serving(evil);
        let e = r.run(PLAIN).unwrap_err();
        assert!(e.contains("install.sh"), "{e}");
        assert!(e.contains(&sha256_hex(evil)), "{e}");
        assert!(e.contains(&sha256_hex(INSTALL_SH)), "{e}");
        assert!(r.installs().is_empty());
        assert!(r.host_calls().is_empty());
        assert_eq!(std::fs::read_dir(&r.temp).unwrap().count(), 0);
        // Nothing was announced either: the announcement precedes only a run.
        assert!(r.events.lock().unwrap().is_empty());
    }

    #[test]
    fn an_oversized_install_sh_is_refused() {
        let mut r = Rig::new();
        r.fetch = serving(&vec![b'#'; (MAX_INSTALL_SH_BYTES + 1) as usize]);
        let e = r.run(PLAIN).unwrap_err();
        assert!(e.contains(INSTALL_SH_URL), "{e}");
        assert!(r.installs().is_empty());
    }

    #[test]
    fn the_installer_gets_the_signed_tarball_digest_and_no_release_base() {
        let r = Rig::new();
        r.run(PLAIN).unwrap();
        let calls = r.installs();
        assert_eq!(calls.len(), 1);
        let c = &calls[0];
        assert_eq!(
            c.set,
            vec![
                ("RTS_VERSION".to_string(), "0.2.0".to_string()),
                ("RTS_INSTALL_PREFIX".to_string(), r.prefix.display().to_string()),
                ("RTS_TARBALL_SHA256".to_string(), TARBALL_SHA.to_string()),
            ]
        );
        assert_eq!(c.remove, vec!["RTS_RELEASE_BASE".to_string()]);
        assert_eq!(c.bytes, INSTALL_SH);
        assert_eq!(c.script.file_name().unwrap(), "install.sh");
        assert!(c.script.starts_with(&r.temp));
        assert!(!c.script.parent().unwrap().exists(), "the stage directory is left behind");
        assert_eq!(std::fs::read_dir(&r.temp).unwrap().count(), 0);
        assert_eq!(
            r.fetch.calls(),
            vec![MANIFEST_URL.to_string(), SIGNATURE_URL.to_string(), INSTALL_SH_URL.to_string()]
        );
    }

    #[test]
    fn the_stage_directory_and_script_are_private() {
        use std::os::unix::fs::PermissionsExt;
        struct Modes(Mutex<Option<(u32, u32)>>);
        impl Installer for Modes {
            fn run(&self, script: &Path, _: &[(String, String)], _: &[&str]) -> Result<i32, String> {
                let m = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
                *self.0.lock().unwrap() = Some((m(script.parent().unwrap()), m(script)));
                Ok(0)
            }
        }
        let r = Rig::new();
        let modes = Modes(Mutex::new(None));
        let say = |_: &str| {};
        run(
            &PLAIN,
            &UpdateContext {
                current: &r.current,
                channel: &r.channel,
                key: r.key,
                fetch: &r.fetch,
                host: &r.host,
                installer: &modes,
                temp_dir: &r.temp,
                say: &say,
            },
        )
        .unwrap();
        assert_eq!(*modes.0.lock().unwrap(), Some((0o700, 0o600)));
    }

    #[test]
    fn a_failing_install_sh_is_reported() {
        let mut r = Rig::new();
        r.installer.code = 3;
        let e = r.run(PLAIN).unwrap_err();
        assert!(e.contains("exited 3"), "{e}");
        assert!(e.contains("0.2.0"), "{e}");
        assert!(r.host_calls().is_empty());
    }

    #[test]
    fn the_post_install_code_signature_is_required() {
        let mut r = Rig::new();
        r.run(PLAIN).unwrap();
        let calls = r.host_calls();
        assert_eq!(
            calls[0],
            vec![
                "/usr/bin/codesign".to_string(),
                "--verify".to_string(),
                "--strict".to_string(),
                format!("-R={TEAM_REQUIREMENT}"),
                r.rts(),
            ]
        );
        assert_eq!(calls[1], vec![r.rts(), "--version".to_string()]);
        assert_eq!(TEAM_REQUIREMENT, r#"anchor apple generic and certificate leaf[subject.OU] = "KXSWJN7WY8""#);

        r.host.codesign = 3;
        r.host.calls.lock().unwrap().clear();
        let e = r.run(PLAIN).unwrap_err();
        assert!(e.contains("was installed to"), "{e}");
        assert!(e.contains("code signature"), "{e}");
        assert!(e.contains(&r.prefix.display().to_string()), "{e}");
        // The version is not trusted from a binary whose signature failed.
        assert_eq!(r.host_calls().len(), 1);
    }

    #[test]
    fn the_installed_version_must_match() {
        let mut r = Rig::new();
        r.host.version = "rts 0.1.9\n".into();
        let e = r.run(PLAIN).unwrap_err();
        assert!(e.contains("was installed to"), "{e}");
        assert!(e.contains("0.1.9") && e.contains("0.2.0"), "{e}");

        r.host.version = "rts 0.2.0 extra\n".into();
        assert!(r.run(PLAIN).is_err());
    }

    #[test]
    fn success_names_both_versions() {
        let r = Rig::new();
        let lines = r.run(PLAIN).unwrap();
        assert_eq!(lines.last().unwrap(), &format!("rts updated from 0.1.0 to 0.2.0 ({})", r.rts()));
    }

    #[test]
    fn the_version_being_installed_is_announced_first() {
        let announce = |r: &Rig, current: &str| format!("say: installing rts 0.2.0 over {current} to {}", r.prefix.display());
        let r = Rig::new();
        r.run(PLAIN).unwrap();
        assert_eq!(*r.events.lock().unwrap(), vec![announce(&r, "0.1.0"), "installer".to_string()]);

        let mut r = Rig::new();
        r.current = "0.2.0".into();
        r.run(FORCE).unwrap();
        assert_eq!(*r.events.lock().unwrap(), vec![announce(&r, "0.2.0"), "installer".to_string()]);
    }

    #[test]
    fn a_bad_manifest_signature_names_the_url_and_runs_nothing() {
        let r = Rig::new();
        r.fetch.body(SIGNATURE_URL, STANDARD.encode(SigningKey::from_bytes(&[8; 32]).sign(manifest_text("0.2.0").as_bytes()).to_bytes()).into_bytes());
        let e = r.run(PLAIN).unwrap_err();
        assert!(e.contains(MANIFEST_URL), "{e}");
        assert!(e.contains("signature"), "{e}");
        assert!(r.installs().is_empty());
        assert_eq!(r.fetch.calls(), vec![MANIFEST_URL.to_string(), SIGNATURE_URL.to_string()]);
    }
}

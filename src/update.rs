//! Update notices and `rts update`: the compiled-in update key, the
//! install channel and the launch check.

pub mod apply;
pub mod manifest;

use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use ironwire_update::{CheckedAt, UpdateStatus, evaluate, load_cache, save_cache, should_check};

use crate::install::{install_prefix, prefix_plugin, update_cache};
use crate::setup::{Fetch, HttpsFetch};

/// 64 hex characters (either case) to 32 bytes. Panics otherwise, which is a
/// compile error when evaluated for [`UPDATE_KEY`].
pub const fn parse_key_hex(hex: &str) -> [u8; 32] {
    let hex = hex.as_bytes();
    if hex.len() != 64 {
        panic!("RTS_UPDATE_PUBLIC_KEY_HEX must be 64 hex characters");
    }
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("RTS_UPDATE_PUBLIC_KEY_HEX must be 64 hex characters"),
    }
}

/// The Ed25519 public key that signs `latest.json`, from the build-time
/// environment. None for a build without it, which then behaves as a source
/// build. A malformed value fails const evaluation: a compile error.
pub const UPDATE_KEY: Option<[u8; 32]> = match option_env!("RTS_UPDATE_PUBLIC_KEY_HEX") {
    Some(hex) => Some(parse_key_hex(hex)),
    None => None,
};

/// Who owns this install, and therefore who may update it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Channel {
    /// A curl (install.sh) install under this prefix.
    Release { prefix: PathBuf },
    Homebrew,
    Source,
}

/// Homebrew when `install_prefix(exe)` is `<..>/Cellar/<name>/<version>`;
/// Release when the prefix holds `share/nearai-red-sandbox/plugin` as a
/// directory; Source otherwise. `install_prefix` canonicalizes, so a
/// Homebrew `bin/rts` symlink resolves into its keg.
pub fn channel(exe: &Path) -> Channel {
    let Some(prefix) = install_prefix(exe) else {
        return Channel::Source;
    };
    let cellar = prefix.parent().and_then(Path::parent).and_then(Path::file_name);
    if cellar.is_some_and(|n| n == "Cellar") {
        Channel::Homebrew
    } else if prefix_plugin(&prefix).is_dir() {
        Channel::Release { prefix }
    } else {
        Channel::Source
    }
}

impl Channel {
    /// Homebrew -> Homebrew, Release -> ShellInstaller, Source -> Unmanaged.
    pub fn method(&self) -> ironwire_update::InstallMethod {
        use ironwire_update::InstallMethod;
        match self {
            Self::Homebrew => InstallMethod::Homebrew,
            Self::Release { .. } => InstallMethod::ShellInstaller,
            Self::Source => InstallMethod::Unmanaged,
        }
    }
}

/// The whole launch check, network included, never holds launch longer.
pub const LAUNCH_TIMEOUT: Duration = Duration::from_secs(3);
/// Any non-empty value disables the launch check (not `rts update`).
pub const OPT_OUT_ENV: &str = "RTS_NO_UPDATE_CHECK";

/// `OPT_OUT_ENV` present with a non-empty value.
pub fn opted_out(env: &[(String, String)]) -> bool {
    env.iter().any(|(k, v)| k == OPT_OUT_ENV && !v.is_empty())
}

pub struct LaunchCheck<'a> {
    /// `env!("CARGO_PKG_VERSION")`.
    pub current: &'a str,
    pub channel: &'a Channel,
    pub key: Option<[u8; 32]>,
    /// config `updateCheck` && !opted_out(env).
    pub enabled: bool,
    /// HOME, only when absolute.
    pub home: Option<&'a Path>,
    pub now: chrono::DateTime<chrono::Utc>,
    pub timeout: Duration,
    pub fetch: Arc<dyn Fetch>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct LaunchOutcome {
    pub notice: Option<String>,
    /// For launcher.log only.
    pub log: Vec<String>,
}

/// Skips, touching nothing, unless the channel is Release or Homebrew, the
/// build has a key, the check is enabled and HOME is known. Otherwise
/// fetches when due (at most daily; a cache time in the future counts as
/// due) on a worker bounded by `timeout`, saves the cache (keeping the
/// previous status on failure) and returns the notice for the current
/// status, re-evaluated against the running version.
pub fn launch_check(c: &LaunchCheck) -> LaunchOutcome {
    let mut out = LaunchOutcome::default();
    let (Some(key), Some(home)) = (c.key, c.home) else {
        return out;
    };
    if !c.enabled || !matches!(c.channel, Channel::Release { .. } | Channel::Homebrew) {
        return out;
    }
    let path = update_cache(home);
    let cache = load_cache(&path);
    if cache.is_none() && path.exists() {
        out.log.push(format!("{} is unreadable; checking anyway", path.display()));
    }
    let due = should_check(true, cache.as_ref(), c.now) || cache.as_ref().is_some_and(|k| k.at > c.now);
    let previous = cache.map(|k| k.status);
    let status = if due {
        let status = match fetch_within(Arc::clone(&c.fetch), key, c.timeout) {
            Ok(m) => evaluate(c.current, &m.manifest, c.channel.method()),
            Err(e) => {
                out.log.push(e);
                previous.unwrap_or(UpdateStatus::Unknown)
            }
        };
        if let Err(e) = save(&path, &CheckedAt { at: c.now, status: status.clone() }) {
            out.log.push(format!("writing {}: {e}", path.display()));
        }
        status
    } else {
        previous.unwrap_or(UpdateStatus::Unknown)
    };
    out.notice = notice(c.current, &status, c.channel);
    out
}

/// `manifest::fetch` on a worker thread; the deadline holds whatever the
/// HTTP layer does. On timeout the worker finishes on its own and its
/// result is dropped.
fn fetch_within(f: Arc<dyn Fetch>, key: [u8; 32], timeout: Duration) -> Result<manifest::SignedManifest, String> {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("rts-update-check".into())
        .spawn(move || {
            let _ = tx.send(manifest::fetch(&*f, &key));
        })
        .map_err(|e| format!("starting the update check: {e}"))?;
    match rx.recv_timeout(timeout) {
        Ok(r) => r,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(format!("timed out after {}", human(timeout))),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err("the update check stopped without a result".into()),
    }
}

fn human(d: Duration) -> String {
    if d.subsec_nanos() == 0 { format!("{} s", d.as_secs()) } else { format!("{} ms", d.as_millis()) }
}

/// The cache parent is created 0700 first: `save_cache` would use the
/// umask's mode, and install.sh requires 0700 there.
fn save(path: &Path, checked: &CheckedAt) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(parent)?;
    }
    save_cache(path, checked)
}

/// The spec's notice table; None for UpToDate and Unknown, and for the
/// Source channel. The status is re-evaluated against `current` first, so a
/// cached notice disappears once the operator has updated. IronWire's
/// `upgrade_command` is never shown.
pub fn notice(current: &str, status: &UpdateStatus, channel: &Channel) -> Option<String> {
    let command = match channel {
        Channel::Release { .. } => "rts update",
        Channel::Homebrew => "brew upgrade rts",
        Channel::Source => return None,
    };
    let m = match status {
        UpdateStatus::Available { latest, .. } => {
            ironwire_update::Manifest { latest: latest.clone(), minimum_supported: None, summary: None }
        }
        UpdateStatus::Unsupported { latest, minimum_supported, .. } => ironwire_update::Manifest {
            latest: latest.clone(),
            minimum_supported: Some(minimum_supported.clone()),
            summary: None,
        },
        UpdateStatus::UpToDate | UpdateStatus::Unknown => return None,
    };
    match evaluate(current, &m, channel.method()) {
        UpdateStatus::Available { latest, .. } => {
            Some(format!("rts {latest} is available (you have {current}): run {command}"))
        }
        UpdateStatus::Unsupported { latest, minimum_supported, .. } => Some(format!(
            "rts {current} is older than the oldest supported release, {minimum_supported}, and may not work: run {command} to install {latest}"
        )),
        UpdateStatus::UpToDate | UpdateStatus::Unknown => None,
    }
}

/// Create the parent 0700, append `<unix secs> update check: <line>` per
/// line (the `session::Logger` format); errors ignored. No lines, no file.
pub fn append_log(log_file: &Path, lines: &[String]) {
    if lines.is_empty() {
        return;
    }
    if let Some(parent) = log_file.parent()
        && std::fs::DirBuilder::new().recursive(true).mode(0o700).create(parent).is_err()
    {
        return;
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(log_file) {
        for line in lines {
            let _ = writeln!(f, "{secs} update check: {line}");
        }
    }
}

/// Real wiring for `rts launch`: the environment, HOME, `current_exe`,
/// [`UPDATE_KEY`], an HTTPS client bounded by [`LAUNCH_TIMEOUT`] and the
/// clock. Prints the notice to stderr and logs failures to `log_file`.
/// Builds no client when the check is skipped.
pub fn launch_notice(update_check: bool, log_file: &Path) {
    let env: Vec<(String, String)> = std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        .collect();
    let enabled = update_check && !opted_out(&env);
    let home = env.iter().find(|(k, _)| k == "HOME").map(|(_, v)| PathBuf::from(v)).filter(|p| p.is_absolute());
    if !enabled || UPDATE_KEY.is_none() || home.is_none() {
        return;
    }
    let channel = std::env::current_exe().map(|e| channel(&e)).unwrap_or(Channel::Source);
    if channel == Channel::Source {
        return;
    }
    let fetch = match HttpsFetch::with_timeouts(LAUNCH_TIMEOUT, LAUNCH_TIMEOUT) {
        Ok(f) => f,
        Err(e) => return append_log(log_file, &[e]),
    };
    let outcome = launch_check(&LaunchCheck {
        current: env!("CARGO_PKG_VERSION"),
        channel: &channel,
        key: UPDATE_KEY,
        enabled,
        home: home.as_deref(),
        now: chrono::Utc::now(),
        timeout: LAUNCH_TIMEOUT,
        fetch: Arc::new(fetch),
    });
    if let Some(n) = &outcome.notice {
        crate::brand::progress::message(&format!("[rts] {n}"));
    }
    append_log(log_file, &outcome.log);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const REPO_KEY: &str = "9b4a81b8bd017898c36871c6bd1cb890faf95b6e378e72eb99b9c15841f02ac9";

    #[test]
    fn key_hex_parses_both_cases() {
        let want: [u8; 32] = hex::decode(REPO_KEY).unwrap().try_into().unwrap();
        assert_eq!(parse_key_hex(REPO_KEY), want);
        assert_eq!(parse_key_hex(&REPO_KEY.to_uppercase()), want);
    }

    #[test]
    #[should_panic(expected = "RTS_UPDATE_PUBLIC_KEY_HEX")]
    fn a_short_key_panics() {
        parse_key_hex(&REPO_KEY[1..]);
    }

    #[test]
    #[should_panic(expected = "RTS_UPDATE_PUBLIC_KEY_HEX")]
    fn a_long_key_panics() {
        parse_key_hex(&format!("{REPO_KEY}0"));
    }

    #[test]
    #[should_panic(expected = "RTS_UPDATE_PUBLIC_KEY_HEX")]
    fn a_non_hex_key_panics() {
        parse_key_hex(&format!("{}g", &REPO_KEY[1..]));
    }

    fn touch(p: &Path) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, b"").unwrap();
    }

    #[test]
    fn channels_follow_the_layout() {
        let t = tempfile::tempdir().unwrap();
        let t = t.path();

        let keg = t.join("Cellar/rts/0.1.0");
        touch(&keg.join("bin/rts"));
        std::fs::create_dir_all(keg.join("share/nearai-red-sandbox/plugin")).unwrap();
        assert_eq!(channel(&keg.join("bin/rts")), Channel::Homebrew);

        std::fs::create_dir_all(t.join("brew/bin")).unwrap();
        std::os::unix::fs::symlink(keg.join("bin/rts"), t.join("brew/bin/rts")).unwrap();
        assert_eq!(channel(&t.join("brew/bin/rts")), Channel::Homebrew);

        let local = t.join("home/.local");
        touch(&local.join("bin/rts"));
        std::fs::create_dir_all(local.join("share/nearai-red-sandbox/plugin")).unwrap();
        let release = channel(&local.join("bin/rts"));
        assert_eq!(release, Channel::Release { prefix: std::fs::canonicalize(&local).unwrap() });

        // A plugin path that is a file, not a directory, is no release layout.
        let odd = t.join("odd");
        touch(&odd.join("bin/rts"));
        touch(&odd.join("share/nearai-red-sandbox/plugin"));
        assert_eq!(channel(&odd.join("bin/rts")), Channel::Source);

        touch(&t.join("usr/bin/rts"));
        assert_eq!(channel(&t.join("usr/bin/rts")), Channel::Source);
        touch(&t.join("target/debug/rts"));
        assert_eq!(channel(&t.join("target/debug/rts")), Channel::Source);
        assert_eq!(channel(&t.join("missing/bin/rts")), Channel::Source);

        use ironwire_update::InstallMethod;
        assert_eq!(Channel::Homebrew.method(), InstallMethod::Homebrew);
        assert_eq!(release.method(), InstallMethod::ShellInstaller);
        assert_eq!(Channel::Source.method(), InstallMethod::Unmanaged);
    }

    mod launch {
        use super::super::*;
        use crate::install::update_cache;
        use crate::setup::{FakeFetch, Fetch, Hop};
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;
        use chrono::{DateTime, Utc};
        use ed25519_dalek::{Signer, SigningKey};
        use ironwire_update::{CheckedAt, UpdateStatus, load_cache, save_cache};
        use std::os::unix::fs::PermissionsExt;
        use std::sync::Arc;
        use std::time::{Duration, Instant};
        use url::Url;

        const AVAILABLE: &str = "rts 0.2.0 is available (you have 0.1.0): run rts update";

        fn key(seed: u8) -> SigningKey {
            SigningKey::from_bytes(&[seed; 32])
        }
        fn t0() -> DateTime<Utc> {
            DateTime::from_timestamp(1_800_000_000, 0).unwrap()
        }
        fn release() -> Channel {
            Channel::Release { prefix: "/p".into() }
        }

        fn manifest_text(latest: &str, minimum: Option<&str>) -> String {
            let floor = minimum.map(|m| format!("  \"minimum_supported\": \"{m}\",\n")).unwrap_or_default();
            format!(
                "{{\n  \"latest\": \"{latest}\",\n{floor}  \"published\": \"2026-11-02T18:04:11Z\",\n  \"tarball\": {{\n    \"name\": \"rts-{latest}-aarch64-apple-darwin.tar.gz\",\n    \"sha256\": \"{a}\"\n  }},\n  \"install_sh\": {{\n    \"sha256\": \"{b}\"\n  }}\n}}\n",
                a = "a".repeat(64),
                b = "b".repeat(64),
            )
        }

        /// A FakeFetch serving `latest` (and `minimum`) signed by `signer`.
        fn serving(latest: &str, minimum: Option<&str>, signer: &SigningKey) -> Arc<FakeFetch> {
            let text = manifest_text(latest, minimum);
            let sig = STANDARD.encode(signer.sign(text.as_bytes()).to_bytes());
            let f = Arc::new(FakeFetch::new());
            f.body(manifest::MANIFEST_URL, text.into_bytes());
            f.body(manifest::SIGNATURE_URL, sig.into_bytes());
            f
        }

        fn check<'a>(home: &'a Path, channel: &'a Channel, fetch: Arc<dyn Fetch>) -> LaunchCheck<'a> {
            LaunchCheck {
                current: "0.1.0",
                channel,
                key: Some(key(7).verifying_key().to_bytes()),
                enabled: true,
                home: Some(home),
                now: t0(),
                timeout: Duration::from_millis(200),
                fetch,
            }
        }

        fn cached(home: &Path) -> Option<CheckedAt> {
            load_cache(&update_cache(home))
        }

        fn available(latest: &str) -> UpdateStatus {
            UpdateStatus::Available { latest: latest.into(), summary: None, upgrade_command: None }
        }

        #[test]
        fn a_newer_release_prints_the_notice_and_caches_it() {
            let t = tempfile::tempdir().unwrap();
            let ch = release();
            let f = serving("0.2.0", None, &key(7));
            let out = launch_check(&check(t.path(), &ch, f.clone()));
            assert_eq!(out.notice.as_deref(), Some(AVAILABLE));
            assert_eq!(out.log, Vec::<String>::new());
            let c = cached(t.path()).unwrap();
            assert_eq!(c.at, t0());
            assert!(matches!(c.status, UpdateStatus::Available { ref latest, .. } if latest == "0.2.0"), "{:?}", c.status);
        }

        #[test]
        fn homebrew_is_told_to_use_brew() {
            let t = tempfile::tempdir().unwrap();
            let ch = Channel::Homebrew;
            let out = launch_check(&check(t.path(), &ch, serving("0.2.0", None, &key(7))));
            assert_eq!(
                out.notice.as_deref(),
                Some("rts 0.2.0 is available (you have 0.1.0): run brew upgrade rts")
            );
        }

        #[test]
        fn the_floor_gets_the_stronger_warning() {
            let t = tempfile::tempdir().unwrap();
            let ch = release();
            let c = LaunchCheck { current: "0.0.9", ..check(t.path(), &ch, serving("0.2.0", Some("0.1.0"), &key(7))) };
            assert_eq!(
                launch_check(&c).notice.as_deref(),
                Some("rts 0.0.9 is older than the oldest supported release, 0.1.0, and may not work: run rts update to install 0.2.0")
            );

            let t = tempfile::tempdir().unwrap();
            let ch = Channel::Homebrew;
            let c = LaunchCheck { current: "0.0.9", ..check(t.path(), &ch, serving("0.2.0", Some("0.1.0"), &key(7))) };
            assert_eq!(
                launch_check(&c).notice.as_deref(),
                Some("rts 0.0.9 is older than the oldest supported release, 0.1.0, and may not work: run brew upgrade rts to install 0.2.0")
            );
        }

        #[test]
        fn up_to_date_prints_nothing() {
            for current in ["0.2.0", "0.3.0"] {
                let t = tempfile::tempdir().unwrap();
                let ch = release();
                let f = serving("0.2.0", None, &key(7));
                let out = launch_check(&LaunchCheck { current, ..check(t.path(), &ch, f.clone()) });
                assert_eq!(out, LaunchOutcome::default(), "{current}");
                assert_eq!(f.calls().len(), 2);
            }
        }

        #[test]
        fn checks_are_at_most_daily() {
            let t = tempfile::tempdir().unwrap();
            let ch = release();
            let f = serving("0.2.0", None, &key(7));
            assert_eq!(launch_check(&check(t.path(), &ch, f.clone())).notice.as_deref(), Some(AVAILABLE));
            assert_eq!(f.calls().len(), 2);

            let later = LaunchCheck { now: t0() + chrono::Duration::hours(1), ..check(t.path(), &ch, f.clone()) };
            assert_eq!(launch_check(&later).notice.as_deref(), Some(AVAILABLE));
            assert_eq!(f.calls().len(), 2);

            let next_day = LaunchCheck { now: t0() + chrono::Duration::hours(25), ..check(t.path(), &ch, f.clone()) };
            assert_eq!(launch_check(&next_day).notice.as_deref(), Some(AVAILABLE));
            assert_eq!(f.calls().len(), 4);
        }

        #[test]
        fn a_future_cache_time_counts_as_due() {
            let t = tempfile::tempdir().unwrap();
            let ch = release();
            let at = t0() + chrono::Duration::days(30);
            save_cache(&update_cache(t.path()), &CheckedAt { at, status: UpdateStatus::UpToDate }).unwrap();
            let f = serving("0.2.0", None, &key(7));
            assert_eq!(launch_check(&check(t.path(), &ch, f.clone())).notice.as_deref(), Some(AVAILABLE));
            assert_eq!(f.calls().len(), 2);
            assert_eq!(cached(t.path()).unwrap().at, t0());
        }

        #[test]
        fn a_stale_cached_notice_disappears_after_updating() {
            let t = tempfile::tempdir().unwrap();
            let ch = release();
            let at = t0() - chrono::Duration::hours(1);
            save_cache(&update_cache(t.path()), &CheckedAt { at, status: available("0.2.0") }).unwrap();
            let f = Arc::new(FakeFetch::new());
            let out = launch_check(&LaunchCheck { current: "0.2.0", ..check(t.path(), &ch, f.clone()) });
            assert_eq!(out, LaunchOutcome::default());
            assert_eq!(f.calls(), Vec::<String>::new());
        }

        #[test]
        fn a_failure_keeps_the_previous_status() {
            let t = tempfile::tempdir().unwrap();
            let ch = release();
            let at = t0() - chrono::Duration::hours(25);
            save_cache(&update_cache(t.path()), &CheckedAt { at, status: available("0.2.0") }).unwrap();
            let f = Arc::new(FakeFetch::new());
            let out = launch_check(&check(t.path(), &ch, f.clone()));
            assert_eq!(out.notice.as_deref(), Some(AVAILABLE));
            assert_eq!(out.log.len(), 1, "{:?}", out.log);
            assert!(out.log[0].contains("latest.json"), "{:?}", out.log);
            let c = cached(t.path()).unwrap();
            assert_eq!(c.at, t0());
            assert_eq!(c.status, available("0.2.0"));
        }

        #[test]
        fn a_bad_signature_is_logged_not_shown() {
            let t = tempfile::tempdir().unwrap();
            let ch = release();
            let out = launch_check(&check(t.path(), &ch, serving("0.2.0", None, &key(8))));
            assert_eq!(out.notice, None);
            assert_eq!(out.log.len(), 1, "{:?}", out.log);
            assert!(out.log[0].contains("signature"), "{:?}", out.log);
            assert_eq!(cached(t.path()).unwrap().status, UpdateStatus::Unknown);
        }

        struct Slow(Duration);
        impl Fetch for Slow {
            fn get(&self, _: &Url) -> Result<Hop, String> {
                std::thread::sleep(self.0);
                Err("slow".into())
            }
        }

        #[test]
        fn a_slow_fetch_never_holds_the_launch() {
            let t = tempfile::tempdir().unwrap();
            let ch = release();
            let start = Instant::now();
            let out = launch_check(&check(t.path(), &ch, Arc::new(Slow(Duration::from_secs(10)))));
            assert!(start.elapsed() < Duration::from_secs(2), "{:?}", start.elapsed());
            assert_eq!(out.notice, None);
            assert_eq!(out.log.len(), 1, "{:?}", out.log);
            assert!(out.log[0].contains("timed out"), "{:?}", out.log);
            assert_eq!(cached(t.path()).unwrap().at, t0());
        }

        #[test]
        fn opting_out_reads_nothing_and_fetches_nothing() {
            let t = tempfile::tempdir().unwrap();
            let home = t.path();
            let (rel, source) = (release(), Channel::Source);
            let f = serving("0.2.0", None, &key(7));
            let variants = |f: &Arc<FakeFetch>| {
                vec![
                    LaunchCheck { enabled: false, ..check(home, &rel, f.clone()) },
                    check(home, &source, f.clone()),
                    LaunchCheck { key: None, ..check(home, &rel, f.clone()) },
                    LaunchCheck { home: None, ..check(home, &rel, f.clone()) },
                ]
            };
            for c in variants(&f) {
                assert_eq!(launch_check(&c), LaunchOutcome::default());
            }
            assert_eq!(f.calls(), Vec::<String>::new());
            assert!(!update_cache(home).exists());
            assert!(!home.join(".local").exists());

            let path = update_cache(home);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"{ not a cache").unwrap();
            for c in variants(&f) {
                assert_eq!(launch_check(&c), LaunchOutcome::default());
            }
            assert_eq!(f.calls(), Vec::<String>::new());
            assert_eq!(std::fs::read(&path).unwrap(), b"{ not a cache");
        }

        #[test]
        fn the_cache_directory_is_private() {
            let t = tempfile::tempdir().unwrap();
            let ch = release();
            launch_check(&check(t.path(), &ch, serving("0.2.0", None, &key(7))));
            let dir = t.path().join(".local/share/nearai-red-sandbox");
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "{mode:o}");
            assert!(update_cache(t.path()).is_file());
        }

        #[test]
        fn opted_out_env() {
            let env = |v: Option<&str>| -> Vec<(String, String)> {
                let mut e = vec![("HOME".to_string(), "/h".to_string())];
                if let Some(v) = v {
                    e.push((OPT_OUT_ENV.to_string(), v.to_string()));
                }
                e
            };
            assert_eq!(OPT_OUT_ENV, "RTS_NO_UPDATE_CHECK");
            assert!(opted_out(&env(Some("1"))));
            assert!(opted_out(&env(Some("yes"))));
            assert!(!opted_out(&env(Some(""))));
            assert!(!opted_out(&env(None)));
        }

        #[test]
        fn the_log_goes_to_launcher_log() {
            let t = tempfile::tempdir().unwrap();
            let file = t.path().join("s/abc/launcher.log");
            append_log(&file, &["x".to_string()]);
            let mode = std::fs::metadata(t.path().join("s/abc")).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "{mode:o}");
            let text = std::fs::read_to_string(&file).unwrap();
            let lines: Vec<&str> = text.lines().collect();
            assert_eq!(lines.len(), 1, "{text:?}");
            let (secs, rest) = lines[0].split_once(' ').unwrap();
            assert!(!secs.is_empty() && secs.bytes().all(|b| b.is_ascii_digit()), "{text:?}");
            assert_eq!(rest, "update check: x");
            assert!(text.ends_with('\n'));
        }

        #[test]
        fn an_empty_log_creates_nothing() {
            let t = tempfile::tempdir().unwrap();
            append_log(&t.path().join("s/abc/launcher.log"), &[]);
            assert!(!t.path().join("s").exists());
        }

        #[test]
        fn the_launch_budget_is_three_seconds() {
            assert_eq!(LAUNCH_TIMEOUT, Duration::from_secs(3));
        }
    }

    #[test]
    fn a_cellar_that_is_not_the_grandparent_is_not_homebrew() {
        // <t>/Cellar/bin/rts: the prefix is <t>/Cellar, whose grandparent is not Cellar.
        let t = tempfile::tempdir().unwrap();
        let prefix = t.path().join("Cellar");
        touch(&prefix.join("bin/rts"));
        assert_eq!(channel(&prefix.join("bin/rts")), Channel::Source);
    }
}

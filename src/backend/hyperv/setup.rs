//! `rts setup` on Windows: install the pinned guest kernel and initramfs
//! into the guest directory (`%LOCALAPPDATA%\nearai-red-sandbox\hyperv`,
//! owner-only), then OpenCode's pinned Windows build. Each file is fetched over setup's GitHub host allowlist,
//! checked against its pin, and renamed into place; a file already there
//! with the right digest is left alone. HCS reads the files from that
//! owner-only directory itself (checked live).

use std::io::Write;
use std::path::Path;

use super::backend::{INITRD_FILE, INITRD_SHA256, KERNEL_FILE, KERNEL_SHA256};
use crate::session::Host;
use crate::setup::{Component, Fetch, ReleaseArchive, download, install_opencode};
use crate::untar::{ExtractLimits, extract_tar};

/// Where the guest files are published: the hyperv-guest-v1 release, made
/// by .github/workflows/hyperv-guest.yml from guest/hyperv on a signed tag
/// (owner decision). The pins, not the release, decide what is accepted.
pub const GUEST_RELEASE: &str =
    "https://github.com/nearai/nearai-red-sandbox/releases/download/hyperv-guest-v1";

/// (file, pinned sha256, size cap)
pub fn guest_files() -> [(&'static str, &'static str, u64); 2] {
    [
        (KERNEL_FILE, KERNEL_SHA256, 32 << 20),
        (INITRD_FILE, INITRD_SHA256, 128 << 20),
    ]
}

fn digest(p: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    std::fs::read(p)
        .ok()
        .map(|b| hex::encode(Sha256::digest(b)))
}

/// OpenCode's part of `rts setup` on Windows: the home it is installed
/// under (`opencode_dir(home)`, as on Unix), what runs its `--version`, and
/// the pinned release asset.
pub struct OpenCode<'a> {
    pub home: &'a Path,
    pub host: &'a dyn Host,
    pub component: &'a Component,
}

/// `rts setup` on Windows: the guest files, then OpenCode. Refuses a host
/// that cannot run the sandbox (Windows Home, or Hyper-V missing) before
/// downloading anything. With `check`, only reports what is in place.
pub fn run(
    check: bool,
    env: &[(String, String)],
    product_type: u32,
    hyperv_problem: Option<&str>,
    f: &dyn Fetch,
    base: &str,
    opencode: &OpenCode,
) -> Result<Vec<String>, String> {
    run_with(
        check,
        env,
        product_type,
        hyperv_problem,
        f,
        base,
        &guest_files(),
        opencode,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_with(
    check: bool,
    env: &[(String, String)],
    product_type: u32,
    hyperv_problem: Option<&str>,
    f: &dyn Fetch,
    base: &str,
    files: &[(&str, &str, u64)],
    opencode: &OpenCode,
) -> Result<Vec<String>, String> {
    if let Some(why) = super::backend::edition_problem(product_type) {
        return Err(why.into());
    }
    if let Some(why) = hyperv_problem {
        return Err(why.into());
    }
    let dir = super::backend::guest_dir(env)
        .ok_or("cannot find the rts guest directory (LOCALAPPDATA is not set)")?;
    let oc = |check| install_opencode(check, opencode.home, opencode.host, f, opencode.component);
    if !check {
        let mut lines = install(f, base, &dir, files)?;
        lines.extend(oc(false)?);
        return Ok(lines);
    }
    let mut lines = vec![];
    let mut failures = vec![];
    let missing: Vec<&str> = files
        .iter()
        .filter(|(name, pin, _)| digest(&dir.join(name)).as_deref() != Some(*pin))
        .map(|(name, _, _)| *name)
        .collect();
    failures.extend(
        files
            .iter()
            .filter(|(n, _, _)| !missing.contains(n))
            .filter_map(|(n, _, _)| hcs_cannot_read(&dir.join(n)))
            .map(|e| format!("{e}; run rts setup")),
    );
    for (name, _, _) in files.iter().filter(|(name, _, _)| !missing.contains(name)) {
        lines.push(format!("{name}: ok"));
    }
    if !missing.is_empty() {
        failures.push(format!(
            "{} missing or not as pinned; run rts setup",
            missing.join(", ")
        ));
    }
    match oc(true) {
        Ok(line) => lines.extend(line),
        Err(e) => failures.push(e),
    }
    if failures.is_empty() {
        Ok(lines)
    } else {
        Err(failures.join("\n"))
    }
}

/// Install every guest file from `base` into `dir`; one line per file.
pub fn install_guest(f: &dyn Fetch, base: &str, dir: &Path) -> Result<Vec<String>, String> {
    install(f, base, dir, &guest_files())
}

/// The Hyper-V service (vmcompute, as SYSTEM) opens the kernel and
/// initramfs itself: with only the user's entry it fails with access
/// denied (checked live), so the guest directory also lets SYSTEM read.
#[cfg_attr(not(windows), allow(dead_code))]
const HCS_READER: &str = "S-1-5-18";

/// Create (or fix) the guest directory: this user's, plus read for SYSTEM,
/// inherited by the files in it.
pub(super) fn guest_dir_create(dir: &Path) -> Result<(), String> {
    crate::sys::fs::create_private_dir_all(dir)
        .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    #[cfg(windows)]
    crate::sys::fs::restrict_dir_with_readers(dir, &[HCS_READER])
        .map_err(|e| format!("cannot set the permissions of {}: {e}", dir.display()))?;
    Ok(())
}

/// A new guest file in the guest directory, with the permissions that
/// directory passes down (Windows), or owner-only (elsewhere).
fn new_guest_file(path: &Path) -> std::io::Result<std::fs::File> {
    if cfg!(windows) {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
    } else {
        crate::sys::fs::open_private(path, crate::sys::fs::Create::New)
    }
}

/// Why the Hyper-V service could not read `file`, or None.
fn hcs_cannot_read(file: &Path) -> Option<String> {
    #[cfg(windows)]
    {
        match crate::sys::fs::dacl(file) {
            Ok(Some(aces)) if crate::sys::fs::grants_read_execute(&aces, &[HCS_READER]) => None,
            Ok(_) => Some(format!(
                "{} is not readable by the Hyper-V service (SYSTEM)",
                file.display()
            )),
            Err(e) => Some(format!(
                "cannot read the permissions of {}: {e}",
                file.display()
            )),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = file;
        None
    }
}

fn install(
    f: &dyn Fetch,
    base: &str,
    dir: &Path,
    files: &[(&str, &str, u64)],
) -> Result<Vec<String>, String> {
    guest_dir_create(dir)?;
    let mut lines = vec![];
    for (name, pin, max) in files {
        let target = dir.join(name);
        if digest(&target).as_deref() == Some(*pin) {
            // One written before the guest directory let SYSTEM read.
            #[cfg(windows)]
            crate::sys::fs::inherit_from_parent(&target)
                .map_err(|e| format!("cannot set the permissions of {}: {e}", target.display()))?;
            lines.push(format!("{name}: already installed"));
            continue;
        }
        let tmp = dir.join(format!(
            ".rts-setup-{name}.{}",
            crate::protocol::random_hex(6)
        ));
        let result = (|| {
            let mut out = new_guest_file(&tmp)
                .map_err(|e| format!("cannot create {}: {e}", tmp.display()))?;
            let got = download(f, &format!("{base}/{name}"), *max, &mut out)?;
            out.flush().map_err(|e| format!("writing {name}: {e}"))?;
            drop(out);
            if got.sha256 != *pin {
                return Err(format!(
                    "{name}: the download does not match its pinned digest; nothing was installed"
                ));
            }
            std::fs::rename(&tmp, &target)
                .map_err(|e| format!("cannot install {}: {e}", target.display()))?;
            Ok(got.bytes)
        })();
        match result {
            Ok(bytes) => lines.push(format!(
                "{name}: installed ({bytes} bytes, sha256 {})",
                &pin[..12]
            )),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(e);
            }
        }
    }
    Ok(lines)
}

// --- an embedder's prefix (the Gateway app): the Windows release archive ---

/// What an embedder's prefix takes from the Windows rts release archive:
/// the egress proxy and the plugin (the embedder is rts itself).
#[cfg_attr(not(windows), allow(dead_code))] // called by run_in_prefix, Windows-only
const RELEASE_OWNED: [&str; 2] = [
    "libexec/nearai-red-sandbox",
    "share/nearai-red-sandbox/plugin",
];
/// The verified archive, kept in the prefix: `--check` compares the
/// installed files with it, and a repair needs no download.
#[cfg_attr(not(windows), allow(dead_code))] // called by run_in_prefix, Windows-only
const KEPT_ARCHIVE: &str = "rts-release.tar";
#[cfg_attr(not(windows), allow(dead_code))] // called by run_in_prefix, Windows-only
const RELEASE_MAX_BYTES: u64 = 256 << 20;
#[cfg_attr(not(windows), allow(dead_code))] // called by run_in_prefix, Windows-only
const RELEASE_LIMITS: ExtractLimits = ExtractLimits {
    max_bytes: 256 << 20,
    max_entries: 2000,
};

/// An embedder's prefix and the pinned release it takes its files from.
/// `private` refuses a prefix wider than its owner
/// (`sys::fs::check_owner_only_dir` on Windows).
pub struct Prefix<'a> {
    pub dir: &'a Path,
    pub release: &'a ReleaseArchive,
    pub private: &'a dyn Fn(&Path) -> Result<(), String>,
}

/// `rts setup` into an embedder's prefix on Windows (`setup::run_in_prefix`
/// there): the release archive's proxy and plugin, the pinned guest files
/// under `share\nearai-red-sandbox\hyperv`, and OpenCode. With `check`, only
/// verifies, offline.
#[cfg(windows)]
pub fn run_in_prefix(
    check: bool,
    prefix: &Path,
    release: &ReleaseArchive,
    f: &dyn Fetch,
    host: &dyn Host,
) -> Result<Vec<String>, String> {
    use windows_sys::Win32::System::SystemInformation::GetProductInfo;
    let mut product_type = 0u32;
    // SAFETY: a plain query with a valid out-pointer.
    unsafe { GetProductInfo(10, 0, 0, 0, &mut product_type) };
    let hyperv = super::hcs::available().err().map(|e| e.to_string());
    let private = |p: &Path| crate::sys::fs::check_owner_only_dir(p);
    let p = Prefix {
        dir: prefix,
        release,
        private: &private,
    };
    prefix_with(
        check,
        product_type,
        hyperv.as_deref(),
        f,
        GUEST_RELEASE,
        &guest_files(),
        &p,
        host,
        &crate::setup::opencode_windows(),
    )
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(windows), allow(dead_code))] // called by run_in_prefix, Windows-only
fn prefix_with(
    check: bool,
    product_type: u32,
    hyperv_problem: Option<&str>,
    f: &dyn Fetch,
    base: &str,
    files: &[(&str, &str, u64)],
    p: &Prefix,
    host: &dyn Host,
    opencode: &Component,
) -> Result<Vec<String>, String> {
    if let Some(why) = super::backend::edition_problem(product_type) {
        return Err(why.into());
    }
    if let Some(why) = hyperv_problem {
        return Err(why.into());
    }
    match std::fs::symlink_metadata(p.dir) {
        Ok(m) if m.is_dir() => (p.private)(p.dir)?,
        Ok(_) => return Err(format!("{} is not a directory", p.dir.display())),
        Err(_) if check => {
            return Err(format!(
                "the rts runtime {} is not set up; run rts setup",
                p.dir.display()
            ));
        }
        Err(_) => crate::sys::fs::create_private_dir_all(p.dir)
            .map_err(|e| format!("cannot create {}: {e}", p.dir.display()))?,
    }
    let guest = crate::install::prefix_hyperv(p.dir);
    if !check {
        let mut lines = vec![install_release(p, f)?];
        lines.extend(install(f, base, &guest, files)?);
        lines.extend(install_opencode(false, p.dir, host, f, opencode)?);
        return Ok(lines);
    }
    let mut lines = vec![];
    let mut failures = vec![];
    let mut record = |r: Result<Option<String>, String>| match r {
        Ok(line) => lines.extend(line),
        Err(e) => failures.push(e),
    };
    record(verify_release(p).map(Some));
    let missing: Vec<&str> = files
        .iter()
        .filter(|(n, pin, _)| digest(&guest.join(n)).as_deref() != Some(*pin))
        .map(|(n, _, _)| *n)
        .collect();
    record(if missing.is_empty() {
        Ok(None)
    } else {
        Err(format!(
            "{} missing or not as pinned; run rts setup",
            missing.join(", ")
        ))
    });
    for (n, _, _) in files.iter().filter(|(n, _, _)| !missing.contains(n)) {
        if let Some(e) = hcs_cannot_read(&guest.join(n)) {
            record(Err(format!("{e}; run rts setup")));
        }
    }
    record(install_opencode(true, p.dir, host, f, opencode));
    if failures.is_empty() {
        Ok(lines)
    } else {
        Err(failures.join("\n"))
    }
}

/// The kept archive, when it is the pinned one.
#[cfg_attr(not(windows), allow(dead_code))] // called by run_in_prefix, Windows-only
fn kept_release(p: &Prefix) -> Option<Vec<u8>> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(p.dir.join(KEPT_ARCHIVE)).ok()?;
    (<[u8; 32]>::from(Sha256::digest(&bytes)) == p.release.sha256).then_some(bytes)
}

/// The installed proxy and plugin, compared byte for byte with the kept,
/// pinned archive (unpacked again with the untar rules). Offline.
#[cfg_attr(not(windows), allow(dead_code))] // called by run_in_prefix, Windows-only
pub(super) fn verify_release(p: &Prefix) -> Result<String, String> {
    let short = &hex::encode(p.release.sha256)[..12];
    let bytes = kept_release(p).ok_or_else(|| {
        format!(
            "rts release {short}: not installed in {}; run rts setup",
            p.dir.display()
        )
    })?;
    let stage = stage_in(p.dir)?;
    let unpacked = stage.path().join("unpacked");
    extract_tar(&bytes, &unpacked, RELEASE_LIMITS)
        .map_err(|e| format!("rts release {short}: {e}; run rts setup"))?;
    for rel in RELEASE_OWNED {
        same_tree(&unpacked.join(rel), &p.dir.join(rel))
            .map_err(|e| format!("rts release {short}: {e}; run rts setup"))?;
    }
    Ok(format!("rts release {short}: ok"))
}

#[cfg_attr(not(windows), allow(dead_code))] // called by run_in_prefix, Windows-only
fn stage_in(dir: &Path) -> Result<tempfile::TempDir, String> {
    crate::setup::remove_stale_temp_dirs(dir)?;
    tempfile::Builder::new()
        .prefix(crate::setup::TEMP_PREFIX)
        .tempdir_in(dir)
        .map_err(|e| format!("cannot create a temp directory in {}: {e}", dir.display()))
}

/// Every file of `want` in `have` with the same bytes, and nothing else.
#[cfg_attr(not(windows), allow(dead_code))] // called by run_in_prefix, Windows-only
fn same_tree(want: &Path, have: &Path) -> Result<(), String> {
    let walk =
        |root: &Path| -> Result<std::collections::BTreeMap<std::path::PathBuf, bool>, String> {
            let mut out = std::collections::BTreeMap::new();
            let mut todo = vec![root.to_path_buf()];
            while let Some(d) = todo.pop() {
                for e in std::fs::read_dir(&d)
                    .map_err(|e| format!("cannot read {}: {e}", d.display()))?
                {
                    let e = e.map_err(|e| e.to_string())?;
                    let m = std::fs::symlink_metadata(e.path()).map_err(|e| e.to_string())?;
                    let rel = e.path().strip_prefix(root).unwrap().to_path_buf();
                    if m.is_dir() {
                        todo.push(e.path());
                        out.insert(rel, true);
                    } else if m.is_file() {
                        out.insert(rel, false);
                    } else {
                        return Err(format!(
                            "{} is neither a file nor a directory",
                            e.path().display()
                        ));
                    }
                }
            }
            Ok(out)
        };
    let (w, h) = (
        walk(want)?,
        walk(have).map_err(|e| format!("{e} (not installed?)"))?,
    );
    for (rel, is_dir) in &w {
        match h.get(rel) {
            None => return Err(format!("{} is missing", have.join(rel).display())),
            Some(d) if d != is_dir => {
                return Err(format!("{} has the wrong type", have.join(rel).display()));
            }
            _ => {}
        }
        if !is_dir && std::fs::read(want.join(rel)).ok() != std::fs::read(have.join(rel)).ok() {
            return Err(format!(
                "{} does not match the release",
                have.join(rel).display()
            ));
        }
    }
    if let Some(extra) = h.keys().find(|rel| !w.contains_key(*rel)) {
        return Err(format!(
            "{} is not part of the release",
            have.join(extra).display()
        ));
    }
    Ok(())
}

/// Install the release's proxy and plugin into the prefix: from the kept
/// archive when it is the pinned one, else downloaded and checked against
/// the pin before anything is unpacked; unpacked with the untar rules,
/// then swapped in (the earlier install is restored on failure).
#[cfg_attr(not(windows), allow(dead_code))] // called by run_in_prefix, Windows-only
pub(super) fn install_release(p: &Prefix, f: &dyn Fetch) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let short = hex::encode(p.release.sha256)[..12].to_string();
    let label = format!("rts release {short}");
    if verify_release(p).is_ok() {
        return Ok(format!("{label}: already installed"));
    }
    let stage = stage_in(p.dir)?;
    let bytes = match kept_release(p) {
        Some(b) => b,
        None => {
            let mut buf = Vec::new();
            download(f, &p.release.url, RELEASE_MAX_BYTES, &mut buf)
                .map_err(|e| format!("{label}: {e}; nothing was installed"))?;
            if <[u8; 32]>::from(Sha256::digest(&buf)) != p.release.sha256 {
                return Err(format!(
                    "{label}: sha256 mismatch for {}; nothing was installed",
                    p.release.url
                ));
            }
            buf
        }
    };
    let unpacked = stage.path().join("unpacked");
    extract_tar(&bytes, &unpacked, RELEASE_LIMITS)
        .map_err(|e| format!("{label}: {e}; nothing was installed"))?;
    let proxy = unpacked
        .join("libexec/nearai-red-sandbox")
        .join(super::EGRESS_EXE);
    if !std::fs::symlink_metadata(&proxy).is_ok_and(|m| m.is_file()) {
        return Err(format!(
            "{label}: the archive has no libexec/nearai-red-sandbox/rts-egress.exe; nothing was installed"
        ));
    }
    if !std::fs::symlink_metadata(unpacked.join("share/nearai-red-sandbox/plugin/index.ts"))
        .is_ok_and(|m| m.is_file())
    {
        return Err(format!(
            "{label}: the archive has no share/nearai-red-sandbox/plugin; nothing was installed"
        ));
    }
    let mut swapped: Vec<&str> = Vec::new();
    for rel in RELEASE_OWNED {
        if let Err(e) = crate::setup::swap_into_prefix(p.dir, stage.path(), rel) {
            for prev in swapped.iter().rev() {
                let (dst, backup) = (p.dir.join(prev), stage.path().join("old").join(prev));
                let _ = std::fs::remove_dir_all(&dst);
                if backup.exists() {
                    let _ = std::fs::rename(&backup, &dst);
                }
            }
            return Err(format!("{label}: {e}; the earlier install was restored"));
        }
        swapped.push(rel);
    }
    let kept = p.dir.join(KEPT_ARCHIVE);
    let mut out = crate::sys::fs::open_private(&kept, crate::sys::fs::Create::Truncate)
        .map_err(|e| format!("{label}: keeping the archive: {e}"))?;
    out.write_all(&bytes)
        .map_err(|e| format!("{label}: keeping the archive: {e}"))?;
    Ok(format!("{label}: installed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::FakeFetch;
    use sha2::{Digest, Sha256};

    const BASE: &str = "https://github.com/nearai/nearai-red-sandbox/releases/download/t";

    fn pin(b: &[u8]) -> String {
        hex::encode(Sha256::digest(b))
    }

    #[test]
    fn files_are_fetched_checked_and_installed_once() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("hyperv");
        let f = FakeFetch::new();
        f.body(&format!("{BASE}/a"), b"kernel".to_vec());
        f.body(&format!("{BASE}/b"), b"initrd".to_vec());
        let (pa, pb) = (pin(b"kernel"), pin(b"initrd"));
        let files = [("a", pa.as_str(), 1024), ("b", pb.as_str(), 1024)];
        let lines = install(&f, BASE, &dir, &files).unwrap();
        assert!(
            lines.iter().all(|l| l.contains("installed (6 bytes")),
            "{lines:?}"
        );
        assert_eq!(std::fs::read(dir.join("a")).unwrap(), b"kernel");
        assert_eq!(f.calls().len(), 2);
        let again = install(&f, BASE, &dir, &files).unwrap();
        assert!(
            again.iter().all(|l| l.ends_with("already installed")),
            "{again:?}"
        );
        assert_eq!(f.calls().len(), 2, "nothing refetched");
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers.len(), 2, "{leftovers:?}");
    }

    #[test]
    fn a_swapped_download_installs_nothing_and_keeps_the_old_file() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("hyperv");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a"), b"old").unwrap();
        let f = FakeFetch::new();
        f.body(&format!("{BASE}/a"), b"evil".to_vec());
        let p = pin(b"kernel");
        let e = install(&f, BASE, &dir, &[("a", p.as_str(), 1024)]).unwrap_err();
        assert!(e.contains("pinned digest"), "{e}");
        assert_eq!(std::fs::read(dir.join("a")).unwrap(), b"old");
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            1,
            "no temp file left"
        );
    }

    #[test]
    fn the_size_cap_and_the_host_allowlist_apply() {
        let d = tempfile::tempdir().unwrap();
        let f = FakeFetch::new();
        f.body(&format!("{BASE}/a"), vec![0; 2048]);
        let p = pin(&[0; 2048]);
        assert!(
            install(&f, BASE, d.path(), &[("a", p.as_str(), 1024)])
                .unwrap_err()
                .contains("exceeds")
        );
        assert!(
            install(
                &f,
                "https://evil.example/x",
                d.path(),
                &[("a", p.as_str(), 4096)]
            )
            .is_err()
        );
    }

    #[test]
    fn setup_refuses_windows_home_and_a_host_without_hyper_v_before_downloading() {
        let f = FakeFetch::new();
        let env = vec![("RTS_HV_DIR".to_string(), "/nonexistent".to_string())];
        let (home, host) = (
            tempfile::tempdir().unwrap(),
            WindowsHost {
                calls: Default::default(),
            },
        );
        let component = opencode_component(b"zip");
        let oc = OpenCode {
            home: home.path(),
            host: &host,
            component: &component,
        };
        let e = run(false, &env, 101, None, &f, BASE, &oc).unwrap_err();
        assert!(e.contains("Windows Home is not supported"), "{e}");
        let e = run(
            false,
            &env,
            0x30,
            Some("Hyper-V is not available"),
            &f,
            BASE,
            &oc,
        )
        .unwrap_err();
        assert!(e.contains("Hyper-V is not available"), "{e}");
        assert!(f.calls().is_empty());
    }

    #[test]
    fn setup_check_reports_without_downloading() {
        let d = tempfile::tempdir().unwrap();
        let f = FakeFetch::new();
        let env = vec![(
            "RTS_HV_DIR".to_string(),
            d.path().to_string_lossy().into_owned(),
        )];
        let (home, host) = (
            tempfile::tempdir().unwrap(),
            WindowsHost {
                calls: Default::default(),
            },
        );
        let component = opencode_component(b"zip");
        let oc = OpenCode {
            home: home.path(),
            host: &host,
            component: &component,
        };
        let e = run(true, &env, 0x30, None, &f, BASE, &oc).unwrap_err();
        assert!(
            e.contains(KERNEL_FILE) && e.contains("run rts setup"),
            "{e}"
        );
        assert!(f.calls().is_empty());
    }

    /// Answers `opencode --version` as 2.2.2 and plays tar.exe by writing
    /// `opencode.exe` into the unpack directory (argv: tar -xf ZIP -C DIR).
    struct WindowsHost {
        calls: std::sync::Mutex<Vec<Vec<String>>>,
    }

    impl crate::session::Host for WindowsHost {
        fn run(
            &self,
            argv: &[String],
            _t: std::time::Duration,
        ) -> std::io::Result<crate::mvm::RunOutput> {
            self.calls.lock().unwrap().push(argv.to_vec());
            let ok = |stdout: &str| crate::mvm::RunOutput {
                code: Some(0),
                stdout: stdout.into(),
                stderr: vec![],
                killed: false,
            };
            if argv[0].ends_with("tar.exe") {
                assert_eq!(&argv[1..2], ["-xf"]);
                assert_eq!(argv[3], "-C");
                std::fs::write(Path::new(&argv[4]).join("opencode.exe"), b"exe").unwrap();
                return Ok(ok(""));
            }
            assert_eq!(
                argv.last().map(String::as_str),
                Some("--version"),
                "{argv:?}"
            );
            Ok(ok("2.2.2\n"))
        }
    }

    fn opencode_component(zip: &[u8]) -> crate::setup::Component {
        crate::setup::Component {
            url: format!("{BASE}/opencode-windows-x64.zip"),
            sha256: pin(zip),
            ..crate::setup::opencode_windows()
        }
    }

    #[test]
    fn opencode_for_windows_is_the_pinned_release_asset() {
        let c = crate::setup::opencode_windows();
        assert_eq!(
            c.url,
            "https://github.com/anomalyco/opencode/releases/download/v2.2.2/opencode-windows-x64.zip"
        );
        assert_eq!(
            c.sha256,
            "e604e66cc13128fe36db7c68c7b0ed31c10b2ce759dd3d702eae080dc140bed5"
        );
        assert_eq!(
            (c.binary, c.unpack),
            ("opencode.exe", crate::setup::Unpack::ZipWindows)
        );
    }

    #[test]
    fn setup_installs_opencode_into_the_home_once_and_checks_its_version() {
        let (home, guest) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let env = vec![(
            "RTS_HV_DIR".to_string(),
            guest.path().to_string_lossy().into_owned(),
        )];
        let zip = b"zip bytes".to_vec();
        let component = opencode_component(&zip);
        let f = FakeFetch::new();
        f.body(&component.url, zip);
        let host = WindowsHost {
            calls: Default::default(),
        };
        let oc = OpenCode {
            home: home.path(),
            host: &host,
            component: &component,
        };
        let lines = run_with(false, &env, 0x30, None, &f, BASE, &[], &oc).unwrap();
        let exe = crate::install::opencode_dir(home.path()).join("opencode.exe");
        assert_eq!(std::fs::read(&exe).unwrap(), b"exe");
        assert!(
            lines.contains(&format!("opencode 2.2.2 {}", exe.display())),
            "{lines:?}"
        );
        assert_eq!(f.calls().len(), 1);
        // A second run checks the installed copy and downloads nothing.
        let again = run_with(false, &env, 0x30, None, &f, BASE, &[], &oc).unwrap();
        assert_eq!(again, lines);
        assert_eq!(f.calls().len(), 1);
        assert!(
            host.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|a| a[0].ends_with("tar.exe"))
                .count()
                == 1
        );
    }

    #[test]
    fn setup_check_reports_missing_opencode_and_guest_files_together_without_downloading() {
        let (home, guest) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let env = vec![(
            "RTS_HV_DIR".to_string(),
            guest.path().to_string_lossy().into_owned(),
        )];
        let component = opencode_component(b"zip");
        let f = FakeFetch::new();
        let host = WindowsHost {
            calls: Default::default(),
        };
        let oc = OpenCode {
            home: home.path(),
            host: &host,
            component: &component,
        };
        let e = run_with(true, &env, 0x30, None, &f, BASE, &guest_files(), &oc).unwrap_err();
        assert!(
            e.contains(KERNEL_FILE) && e.contains("opencode 2.2.2: not installed"),
            "{e}"
        );
        assert!(f.calls().is_empty() && host.calls.lock().unwrap().is_empty());
    }

    // --- an embedder's prefix: the Windows rts release archive ---

    fn release_tar(proxy: &[u8]) -> Vec<u8> {
        use crate::untar::fixture::{dir, file, tar};
        tar(&[
            dir("bin"),
            file("bin/rts.exe", b"rts"),
            dir("libexec"),
            dir("libexec/nearai-red-sandbox"),
            file("libexec/nearai-red-sandbox/rts-egress.exe", proxy),
            dir("share"),
            dir("share/nearai-red-sandbox"),
            dir("share/nearai-red-sandbox/plugin"),
            file("share/nearai-red-sandbox/plugin/package.json", b"{}"),
            file(
                "share/nearai-red-sandbox/plugin/index.ts",
                b"export default {}",
            ),
        ])
    }

    struct PrefixRig {
        _tmp: tempfile::TempDir,
        prefix: std::path::PathBuf,
        f: FakeFetch,
        host: WindowsHost,
        opencode: crate::setup::Component,
        release: crate::setup::ReleaseArchive,
    }

    fn prefix_rig(archive: Vec<u8>, pin: Option<[u8; 32]>) -> PrefixRig {
        let tmp = tempfile::tempdir().unwrap();
        let prefix = tmp.path().join("runtime");
        let f = FakeFetch::new();
        let url = format!("{BASE}/rts-windows.tar");
        let digest: [u8; 32] = Sha256::digest(&archive).into();
        f.body(&url, archive);
        let zip = b"zip".to_vec();
        let opencode = opencode_component(&zip);
        f.body(&opencode.url, zip);
        PrefixRig {
            _tmp: tmp,
            prefix,
            f,
            host: WindowsHost {
                calls: Default::default(),
            },
            opencode,
            release: crate::setup::ReleaseArchive {
                url,
                sha256: pin.unwrap_or(digest),
            },
        }
    }

    fn private_ok(_: &Path) -> Result<(), String> {
        Ok(())
    }

    fn run_prefix(
        r: &PrefixRig,
        check: bool,
        private: &dyn Fn(&Path) -> Result<(), String>,
    ) -> Result<Vec<String>, String> {
        let p = Prefix {
            dir: &r.prefix,
            release: &r.release,
            private,
        };
        prefix_with(check, 0x30, None, &r.f, BASE, &[], &p, &r.host, &r.opencode)
    }

    #[test]
    fn a_release_installs_the_proxy_and_plugin_and_check_compares_them_with_the_kept_archive() {
        let r = prefix_rig(release_tar(b"proxy"), None);
        let lines = run_prefix(&r, false, &private_ok).unwrap();
        let proxy = crate::install::prefix_egress(&r.prefix);
        assert_eq!(std::fs::read(&proxy).unwrap(), b"proxy");
        assert!(
            crate::install::prefix_plugin(&r.prefix)
                .join("index.ts")
                .is_file()
        );
        // Only the owned parts: rts.exe stays out of an embedder's prefix.
        assert!(!r.prefix.join("bin").exists());
        assert!(
            lines.iter().any(|l| l.starts_with("rts release")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.starts_with("opencode 2.2.2")),
            "{lines:?}"
        );
        let fetched = r.f.calls().len();
        // --check is offline and passes on the untouched install.
        run_prefix(&r, true, &private_ok).unwrap();
        // A second install finds it in place and downloads nothing more.
        run_prefix(&r, false, &private_ok).unwrap();
        assert_eq!(r.f.calls().len(), fetched);
        // A changed proxy fails --check.
        std::fs::write(&proxy, b"tampered").unwrap();
        let e = run_prefix(&r, true, &private_ok).unwrap_err();
        assert!(
            e.contains("rts-egress.exe") && e.contains("run rts setup"),
            "{e}"
        );
        // And an install repairs it from the kept archive.
        run_prefix(&r, false, &private_ok).unwrap();
        assert_eq!(std::fs::read(&proxy).unwrap(), b"proxy");
        // A file the archive does not have fails --check too.
        std::fs::write(
            crate::install::prefix_plugin(&r.prefix).join("extra.ts"),
            b"x",
        )
        .unwrap();
        let e = run_prefix(&r, true, &private_ok).unwrap_err();
        assert!(e.contains("extra.ts"), "{e}");
    }

    #[test]
    fn a_wrong_pin_installs_nothing() {
        let r = prefix_rig(release_tar(b"proxy"), Some([7; 32]));
        let e = run_prefix(&r, false, &private_ok).unwrap_err();
        assert!(
            e.contains("sha256") && e.contains("nothing was installed"),
            "{e}"
        );
        assert!(!crate::install::prefix_egress(&r.prefix).exists());
        assert!(!crate::install::prefix_plugin(&r.prefix).exists());
    }

    #[test]
    fn a_prefix_wider_than_its_owner_is_refused_before_anything_is_fetched() {
        let r = prefix_rig(release_tar(b"proxy"), None);
        std::fs::create_dir_all(&r.prefix).unwrap();
        let wider =
            |_: &Path| -> Result<(), String> { Err("it grants access to S-1-5-32-545".into()) };
        for check in [false, true] {
            let e = run_prefix(&r, check, &wider).unwrap_err();
            assert!(e.contains("S-1-5-32-545"), "{e}");
        }
        assert!(r.f.calls().is_empty());
    }

    #[test]
    fn an_archive_without_the_proxy_or_with_a_link_installs_nothing() {
        use crate::untar::fixture::{dir, file, tar, typed};
        let no_proxy = tar(&[
            dir("share"),
            dir("share/nearai-red-sandbox"),
            dir("share/nearai-red-sandbox/plugin"),
            file("share/nearai-red-sandbox/plugin/index.ts", b"x"),
        ]);
        let mut link = typed("libexec/nearai-red-sandbox/rts-egress.exe", b'2');
        link.linkname = "/etc/passwd".into();
        let linked = tar(&[dir("libexec"), dir("libexec/nearai-red-sandbox"), link]);
        for (archive, why) in [(no_proxy, "rts-egress.exe"), (linked, "rejected")] {
            let r = prefix_rig(archive, None);
            let e = run_prefix(&r, false, &private_ok).unwrap_err();
            assert!(
                e.contains(why) && e.contains("nothing was installed"),
                "{e}"
            );
            assert!(!crate::install::prefix_egress(&r.prefix).exists());
            assert!(!crate::install::prefix_plugin(&r.prefix).exists());
        }
    }

    #[test]
    fn check_on_a_prefix_never_set_up_reports_it_without_creating_anything() {
        let r = prefix_rig(release_tar(b"proxy"), None);
        let e = run_prefix(&r, true, &private_ok).unwrap_err();
        assert!(e.contains("run rts setup"), "{e}");
        assert!(!r.prefix.exists());
        assert!(r.f.calls().is_empty());
    }

    /// The archive scripts/package-windows.sh built (RTS_RELEASE_TAR, read
    /// only by this test): it passes the untar rules and installs into a
    /// prefix as a pinned release.
    #[test]
    #[ignore = "needs RTS_RELEASE_TAR (windows-check sets it)"]
    fn a_built_release_archive_installs_into_a_prefix() {
        let archive =
            std::fs::read(std::env::var("RTS_RELEASE_TAR").expect("RTS_RELEASE_TAR")).unwrap();
        let r = prefix_rig(archive, None);
        let lines = run_prefix(&r, false, &private_ok).unwrap();
        assert!(
            crate::install::prefix_egress(&r.prefix).is_file(),
            "{lines:?}"
        );
        assert!(
            crate::install::prefix_plugin(&r.prefix)
                .join("index.ts")
                .is_file()
        );
        run_prefix(&r, true, &private_ok).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn guest_files_are_readable_by_the_hyper_v_service_and_check_says_when_not() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("hyperv");
        let f = FakeFetch::new();
        f.body(&format!("{BASE}/k"), b"kernel".to_vec());
        let files = [("k", pin(b"kernel"), 64u64)];
        let files: Vec<(&str, &str, u64)> =
            files.iter().map(|(n, p, m)| (*n, p.as_str(), *m)).collect();
        install(&f, BASE, &dir, &files).unwrap();
        let file = dir.join("k");
        assert_eq!(hcs_cannot_read(&file), None);
        let dir_aces = crate::sys::fs::dacl(&dir).unwrap().unwrap();
        assert!(crate::sys::fs::grants_read_execute(
            &dir_aces,
            &[HCS_READER]
        ));
        assert_eq!(
            crate::sys::fs::owner_only_problem(
                Some(&dir_aces),
                &crate::sys::fs::current_user_sid().unwrap()
            ),
            None
        );
        // A user-only copy (as an earlier setup wrote it) fails the check...
        let out = std::process::Command::new("icacls")
            .arg(&file)
            .args(["/inheritance:r", "/grant:r"])
            .arg(format!(
                "*{}:(F)",
                crate::sys::fs::current_user_sid().unwrap()
            ))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(hcs_cannot_read(&file).unwrap().contains("SYSTEM"));
        // ...and setup repairs it without downloading again.
        install(&f, BASE, &dir, &files).unwrap();
        assert_eq!(hcs_cannot_read(&file), None);
        assert_eq!(f.calls().len(), 1);
    }

    #[test]
    fn the_real_guest_files_are_pinned() {
        let files = guest_files();
        assert_eq!(files.map(|(n, _, _)| n), [KERNEL_FILE, INITRD_FILE]);
        assert!(
            files
                .iter()
                .all(|(_, p, _)| p.len() == 64 && p.bytes().all(|b| b.is_ascii_hexdigit()))
        );
    }
}

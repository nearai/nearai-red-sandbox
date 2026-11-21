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
use crate::setup::{Component, Fetch, download, install_opencode};

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

fn install(
    f: &dyn Fetch,
    base: &str,
    dir: &Path,
    files: &[(&str, &str, u64)],
) -> Result<Vec<String>, String> {
    crate::sys::fs::create_private_dir_all(dir)
        .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let mut lines = vec![];
    for (name, pin, max) in files {
        let target = dir.join(name);
        if digest(&target).as_deref() == Some(*pin) {
            lines.push(format!("{name}: already installed"));
            continue;
        }
        let tmp = dir.join(format!(
            ".rts-setup-{name}.{}",
            crate::protocol::random_hex(6)
        ));
        let result = (|| {
            let mut out = crate::sys::fs::open_private(&tmp, crate::sys::fs::Create::New)
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

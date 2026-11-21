//! Host checks for the Firecracker/KVM flavor of the mvm backend.
//!
//! rts runs no root VMs. mvm v0.22.0 launches Firecracker through `sudo`
//! whenever mvmctl is not root (mvm-backends `fc/daemon.rs`
//! `sudo_prefix_for_euid`), and stops it the same way. A workload VM has no
//! TAP device, so with `/dev/kvm` open to the user, sudo buys nothing. rts
//! therefore puts a `sudo` that never elevates first on mvmctl's PATH, and
//! checks the running VMM's uid before OpenCode starts.
//!
//! These compile on every Unix so they are tested on macOS too; only
//! `Flavor::host()` selects them, on Linux.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::session::Host;

/// The KVM device mvm opens for Firecracker.
pub const KVM_DEVICE: &str = "/dev/kvm";

/// The one-time admin step when the user cannot open `/dev/kvm`.
pub const KVM_FIX: &str = "add yourself to the kvm group (sudo usermod -aG kvm \"$USER\"), log out and back in, and launch again";

/// `device` exists and this user can open it for reading and writing.
pub fn check_kvm(device: &Path) -> Result<(), String> {
    let c = std::ffi::CString::new(device.as_os_str().as_encoded_bytes())
        .map_err(|_| format!("{} is not a valid path", device.display()))?;
    // SAFETY: `c` is a valid NUL-terminated string for the call's duration.
    if unsafe { libc::access(c.as_ptr(), libc::R_OK | libc::W_OK) } == 0 {
        return Ok(());
    }
    let why = std::io::Error::last_os_error();
    Err(format!(
        "{} is not readable and writable by this user ({why}); rts needs KVM and refuses hosts without it. To fix: {KVM_FIX}",
        device.display()
    ))
}

/// A `sudo` that runs its command as the caller. It drops the options mvm
/// passes (`-n`, `-E`, ...) and refuses any that would pick another user,
/// group or prompt, so nothing it runs gains privilege.
pub const SUDO_SHIM: &str = r#"#!/bin/sh
# rts: run the command as the invoking user. rts runs no root VMs.
while [ $# -gt 0 ]; do
  case $1 in
    --) shift; break ;;
    -n|-E|-H|-k|-b|--non-interactive|--preserve-env|--preserve-env=*|--set-home) shift ;;
    -*) echo "rts sudo shim: refusing sudo option $1" >&2; exit 1 ;;
    *) break ;;
  esac
done
[ $# -gt 0 ] || { echo "rts sudo shim: no command" >&2; exit 1; }
exec "$@"
"#;

/// Write [`SUDO_SHIM`] as `dir/sudo` (0700; `dir` is created 0700 if
/// missing) and return `dir`, to put first on mvmctl's PATH.
pub fn install_sudo_shim(dir: &Path) -> Result<PathBuf, String> {
    use std::os::unix::fs::DirBuilderExt;
    if !dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| format!("creating {}: {e}", dir.display()))?;
    }
    let path = dir.join("sudo");
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(&path)
        .map_err(|e| format!("creating {}: {e}", path.display()))?;
    f.write_all(SUDO_SHIM.as_bytes())
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("writing {}: {e}", path.display()))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    Ok(dir.to_path_buf())
}

/// mvmctl's environment on Firecracker: HOME and MVM_HOME from the
/// operator, PATH with `shim_dir` first, and no standby pool.
pub fn firecracker_environment(
    env: &[(String, String)],
    shim_dir: &Path,
) -> std::collections::HashMap<String, String> {
    let mut result: std::collections::HashMap<String, String> = env
        .iter()
        .filter(|(key, _)| matches!(key.as_str(), "HOME" | "MVM_HOME"))
        .cloned()
        .collect();
    let inherited = env
        .iter()
        .find(|(k, _)| k == "PATH")
        .map(|(_, v)| v.as_str())
        .filter(|v| !v.is_empty())
        .unwrap_or("/usr/local/bin:/usr/bin:/bin");
    result.insert("PATH".into(), format!("{}:{inherited}", shim_dir.display()));
    // mvm 0.28 keeps a standby pool by default: a detached `pool refill` and
    // idle Firecracker processes that outlive `machine rm`. A sandbox session
    // must leave nothing running, so turn both off.
    result.insert("MVM_RESIDENCY".into(), "cold".into());
    result.insert("MVM_FC_IDLE_POOL".into(), "0".into());
    result
}

/// The VMM `pid` runs as `uid`, and `uid` is not root.
pub fn check_vmm_uid(host: &dyn Host, pid: u32, uid: u32) -> Result<(), String> {
    let r = host
        .run(
            &[
                "ps".into(),
                "-o".into(),
                "uid=".into(),
                "-p".into(),
                pid.to_string(),
            ],
            Duration::from_secs(5),
        )
        .map_err(|e| format!("cannot read the uid of VMM pid {pid}: {e}"))?;
    let found: Option<u32> = (r.code == Some(0) && !r.killed)
        .then(|| String::from_utf8_lossy(&r.stdout).trim().parse().ok())
        .flatten();
    match found {
        Some(0) => Err(format!(
            "VMM pid {pid} runs as root; rts does not run root VMs"
        )),
        Some(u) if u == uid => Ok(()),
        Some(u) => Err(format!(
            "VMM pid {pid} runs as uid {u}, not this user's uid {uid}"
        )),
        None => Err(format!("cannot read the uid of VMM pid {pid}")),
    }
}

/// This process's real uid.
pub fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mvm::RunOutput;
    use std::process::Command;

    #[test]
    fn kvm_access_needs_read_and_write() {
        let d = tempfile::tempdir().unwrap();
        let dev = d.path().join("kvm");
        let e = check_kvm(&dev).unwrap_err();
        assert!(e.contains("usermod -aG kvm"), "{e}");
        fs::write(&dev, "").unwrap();
        fs::set_permissions(&dev, fs::Permissions::from_mode(0o600)).unwrap();
        check_kvm(&dev).unwrap();
        if current_uid() != 0 {
            fs::set_permissions(&dev, fs::Permissions::from_mode(0o400)).unwrap();
            assert!(check_kvm(&dev).is_err());
        }
    }

    /// Run the just-written shim. On Linux, exec of a file fails with
    /// ETXTBSY while another test thread's fork still holds a write fd to
    /// it (until that child execs), so retry briefly.
    fn run_shim(sudo: &Path, args: &[&str]) -> std::process::Output {
        for _ in 0..50 {
            match Command::new(sudo).args(args).output() {
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                r => return r.unwrap(),
            }
        }
        panic!("{} stayed busy", sudo.display());
    }

    fn shim(d: &Path) -> PathBuf {
        install_sudo_shim(&d.join("bin")).unwrap().join("sudo")
    }

    #[test]
    fn the_sudo_shim_runs_the_command_as_the_caller() {
        let d = tempfile::tempdir().unwrap();
        let sudo = shim(d.path());
        assert_eq!(
            fs::metadata(&sudo).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(d.path().join("bin"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        for args in [
            &["id", "-u"][..],
            &["-n", "id", "-u"],
            &["-n", "-E", "--", "id", "-u"],
        ] {
            let o = run_shim(&sudo, args);
            assert!(
                o.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&o.stderr)
            );
            assert_eq!(
                String::from_utf8_lossy(&o.stdout).trim(),
                current_uid().to_string(),
                "{args:?}"
            );
        }
    }

    #[test]
    fn the_sudo_shim_refuses_options_that_pick_a_user_or_prompt() {
        let d = tempfile::tempdir().unwrap();
        let sudo = shim(d.path());
        for args in [
            &["-u", "root", "id"][..],
            &["-S", "id"],
            &["-g", "wheel", "id"],
            &["-i"],
            &[],
        ] {
            let o = run_shim(&sudo, args);
            assert_eq!(o.status.code(), Some(1), "{args:?}");
            assert!(o.stdout.is_empty(), "{args:?} ran something");
        }
    }

    #[test]
    fn the_sudo_shim_is_never_overwritten() {
        let d = tempfile::tempdir().unwrap();
        shim(d.path());
        assert!(install_sudo_shim(&d.path().join("bin")).is_err());
    }

    #[test]
    fn firecracker_environment_puts_the_shim_first_and_forwards_only_home() {
        let env = vec![
            ("HOME".into(), "/h".into()),
            ("MVM_HOME".into(), "/m".into()),
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("MVM_HVF_SUPERVISOR_PATH".into(), "/s".into()),
            ("SECRET".into(), "x".into()),
        ];
        let e = firecracker_environment(&env, Path::new("/rt/bin"));
        assert_eq!(e.len(), 5, "{e:?}");
        // No standby pool, refill or idle VMM may outlive a session.
        assert_eq!(
            (e["MVM_RESIDENCY"].as_str(), e["MVM_FC_IDLE_POOL"].as_str()),
            ("cold", "0")
        );
        assert_eq!(e["PATH"], "/rt/bin:/usr/bin:/bin");
        assert_eq!((e["HOME"].as_str(), e["MVM_HOME"].as_str()), ("/h", "/m"));
        let bare = firecracker_environment(&[], Path::new("/rt/bin"));
        assert_eq!(bare["PATH"], "/rt/bin:/usr/local/bin:/usr/bin:/bin");
    }

    struct Ps(&'static str, i32);
    impl Host for Ps {
        fn run(&self, argv: &[String], _: Duration) -> std::io::Result<RunOutput> {
            assert_eq!(argv.join(" "), "ps -o uid= -p 4244");
            Ok(RunOutput {
                code: Some(self.1),
                stdout: self.0.into(),
                ..Default::default()
            })
        }
    }

    #[test]
    fn a_root_or_foreign_vmm_is_refused() {
        check_vmm_uid(&Ps("  501\n", 0), 4244, 501).unwrap();
        assert!(
            check_vmm_uid(&Ps("0\n", 0), 4244, 501)
                .unwrap_err()
                .contains("runs as root")
        );
        assert!(
            check_vmm_uid(&Ps("0\n", 0), 4244, 0)
                .unwrap_err()
                .contains("runs as root")
        );
        assert!(
            check_vmm_uid(&Ps("502\n", 0), 4244, 501)
                .unwrap_err()
                .contains("uid 502")
        );
        assert!(check_vmm_uid(&Ps("", 1), 4244, 501).is_err());
        assert!(check_vmm_uid(&Ps("x\n", 0), 4244, 501).is_err());
    }
}

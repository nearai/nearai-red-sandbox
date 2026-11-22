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

/// The argument mvm 0.28 starts a VM-lifetime `mvm-network-endpoint` with,
/// followed by the VM's state directory (`VM_LIFETIME_FLAG` in mvm-vmm's
/// `host/network_endpoint_spawn.rs`).
pub const ENDPOINT_STATE_DIR_FLAG: &str = "--vm-state-dir";

/// One host process, as `/proc/<pid>` describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessEntry {
    pub pid: u32,
    pub ppid: u32,
    /// The real uid.
    pub uid: u32,
    /// The basename of `exe`, without the kernel's ` (deleted)` suffix.
    pub exe: String,
    /// `cmdline`, split at NUL.
    pub argv: Vec<String>,
}

/// Every process under `proc_root` (`/proc`) whose `exe`, `status` and
/// `cmdline` this user can read. The rest (other users' processes, kernel
/// threads, ones that exited meanwhile) are skipped.
pub fn list_processes(proc_root: &Path) -> Vec<ProcessEntry> {
    let Ok(dir) = fs::read_dir(proc_root) else {
        return Vec::new();
    };
    let mut procs: Vec<ProcessEntry> = dir
        .flatten()
        .filter_map(|entry| {
            let pid: u32 = entry.file_name().to_str()?.parse().ok()?;
            let p = entry.path();
            let exe = fs::read_link(p.join("exe")).ok()?;
            let exe = exe.to_str()?;
            let exe = exe.strip_suffix(" (deleted)").unwrap_or(exe);
            let exe = Path::new(exe).file_name()?.to_str()?.to_string();
            let status = fs::read_to_string(p.join("status")).ok()?;
            let field = |key: &str| -> Option<u32> {
                status
                    .lines()
                    .find_map(|l| l.strip_prefix(key))?
                    .split_whitespace()
                    .next()?
                    .parse()
                    .ok()
            };
            let (ppid, uid) = (field("PPid:")?, field("Uid:")?);
            let cmdline = fs::read(p.join("cmdline")).ok()?;
            let body = cmdline.strip_suffix(&[0]).unwrap_or(&cmdline);
            let argv = body
                .split(|&b| b == 0)
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect();
            Some(ProcessEntry {
                pid,
                ppid,
                uid,
                exe,
                argv,
            })
        })
        .collect();
    procs.sort_by_key(|p| p.pid);
    procs
}

/// The egress processes mvm started for the Firecracker VM whose state
/// directory is `state_dir`: the VM-lifetime `mvm-network-endpoint` keeper
/// (started with `--vm-state-dir <state_dir>` and detached with setsid, so
/// soon not a child of `machine run`), then the endpoints it runs.
///
/// Fail-closed: refuses unless exactly one endpoint names `state_dir` as
/// that argument, and it runs as `uid`.
pub fn firecracker_endpoints(
    procs: &[ProcessEntry],
    state_dir: &Path,
    uid: u32,
) -> Result<Vec<u32>, String> {
    const ENDPOINT: &str = crate::session::ENDPOINT;
    let fail = |why: String| {
        format!(
            "cannot find the network endpoint of the VM at {}: {why}",
            state_dir.display()
        )
    };
    let keepers: Vec<&ProcessEntry> = procs
        .iter()
        .filter(|p| {
            p.exe == ENDPOINT
                && p.argv
                    .windows(2)
                    .any(|w| w[0] == ENDPOINT_STATE_DIR_FLAG && Path::new(&w[1]) == state_dir)
        })
        .collect();
    let keeper = match keepers.as_slice() {
        [] => {
            return Err(fail(format!(
                "no {ENDPOINT} {ENDPOINT_STATE_DIR_FLAG} {} is running",
                state_dir.display()
            )));
        }
        [one] => *one,
        many => {
            let pids: Vec<u32> = many.iter().map(|p| p.pid).collect();
            return Err(fail(format!(
                "{} endpoints claim it (pids {pids:?})",
                many.len()
            )));
        }
    };
    if keeper.uid != uid {
        return Err(fail(format!(
            "{ENDPOINT} pid {} runs as uid {}, not this user's uid {uid}",
            keeper.pid, keeper.uid
        )));
    }
    let mut pids = vec![keeper.pid];
    pids.extend(
        procs
            .iter()
            .filter(|p| p.ppid == keeper.pid && p.exe == ENDPOINT && p.uid == uid)
            .map(|p| p.pid),
    );
    Ok(pids)
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

    /// `/proc` on rts-linux while the allowlist invariant ran (mvm
    /// 0.28.0-rts.2, Firecracker): `machine run`, the VM-lifetime endpoint
    /// keeper (already reparented from `machine run` in other samples), its
    /// endpoint child, and the VMM in its own systemd scope.
    fn captured() -> Vec<ProcessEntry> {
        let p = |pid, ppid, exe: &str, argv: &[&str]| ProcessEntry {
            pid,
            ppid,
            uid: 1000,
            exe: exe.into(),
            argv: argv.iter().map(|a| a.to_string()).collect(),
        };
        let bin = "/home/rts/.local/mvm/v0.28.0-rts.2";
        vec![
            p(
                52114,
                52016,
                "mvmctl",
                &[
                    &format!("{bin}/mvmctl"),
                    "machine",
                    "run",
                    "--name",
                    "rts-3d90ff83e6c6",
                    "--ttl",
                    "1h",
                ],
            ),
            p(
                53971,
                1,
                "mvm-network-endpoint",
                &[
                    &format!("{bin}/mvm-network-endpoint"),
                    "--vm-state-dir",
                    "/home/rts/.mvm-live2/vms/rts-3d90ff83e6c6",
                ],
            ),
            p(
                53973,
                53971,
                "mvm-network-endpoint",
                &[&format!("{bin}/mvm-network-endpoint")],
            ),
            p(
                54022,
                1,
                "firecracker",
                &[
                    &format!("{bin}/firecracker/firecracker"),
                    "--api-sock",
                    "/home/rts/.mvm-live2/vms/rts-3d90ff83e6c6/fc.socket",
                ],
            ),
        ]
    }

    const STATE_DIR: &str = "/home/rts/.mvm-live2/vms/rts-3d90ff83e6c6";

    #[test]
    fn the_endpoint_is_found_by_its_vm_state_dir_not_its_parent() {
        let procs = captured();
        assert_eq!(
            firecracker_endpoints(&procs, Path::new(STATE_DIR), 1000).unwrap(),
            [53971, 53973]
        );
        // A trailing slash names the same directory.
        assert_eq!(
            firecracker_endpoints(&procs, Path::new(&format!("{STATE_DIR}/")), 1000).unwrap(),
            [53971, 53973]
        );
    }

    #[test]
    fn no_endpoint_for_this_vm_is_refused() {
        let procs = captured();
        let e = firecracker_endpoints(
            &procs,
            Path::new("/home/rts/.mvm-live2/vms/rts-000000000000"),
            1000,
        )
        .unwrap_err();
        assert!(e.contains("no mvm-network-endpoint"), "{e}");
        // The state dir in another argument position, or a prefix of it, is not a claim.
        let mut prefix = captured();
        prefix[1].argv[2] = format!("{STATE_DIR}-other");
        assert!(firecracker_endpoints(&prefix, Path::new(STATE_DIR), 1000).is_err());
        let mut elsewhere = captured();
        elsewhere[1].argv = vec!["mvm-network-endpoint".into(), STATE_DIR.into()];
        assert!(firecracker_endpoints(&elsewhere, Path::new(STATE_DIR), 1000).is_err());
        // Another program carrying the flag is not an endpoint.
        let mut impostor = captured();
        impostor[1].exe = "sh".into();
        assert!(firecracker_endpoints(&impostor, Path::new(STATE_DIR), 1000).is_err());
    }

    #[test]
    fn two_endpoints_or_another_users_endpoint_are_refused() {
        let mut two = captured();
        let mut second = two[1].clone();
        second.pid = 60000;
        two.push(second);
        let e = firecracker_endpoints(&two, Path::new(STATE_DIR), 1000).unwrap_err();
        assert!(e.contains("53971") && e.contains("60000"), "{e}");
        let mut foreign = captured();
        foreign[1].uid = 0;
        let e = firecracker_endpoints(&foreign, Path::new(STATE_DIR), 1000).unwrap_err();
        assert!(e.contains("uid 0"), "{e}");
        // A child running as another user is not counted as ours.
        let mut child = captured();
        child[2].uid = 1001;
        assert_eq!(
            firecracker_endpoints(&child, Path::new(STATE_DIR), 1000).unwrap(),
            [53971]
        );
    }

    #[test]
    fn processes_are_read_from_proc_and_unreadable_ones_skipped() {
        let d = tempfile::tempdir().unwrap();
        let proc_dir = |pid: &str, exe: &str, status: &str, cmdline: &[u8]| {
            let p = d.path().join(pid);
            fs::create_dir_all(&p).unwrap();
            std::os::unix::fs::symlink(exe, p.join("exe")).unwrap();
            fs::write(p.join("status"), status).unwrap();
            fs::write(p.join("cmdline"), cmdline).unwrap();
        };
        proc_dir(
            "53971",
            "/opt/mvm/mvm-network-endpoint (deleted)",
            "Name:\tmvm-network-end\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\n",
            b"/opt/mvm/mvm-network-endpoint\0--vm-state-dir\0/s/vms/a b\0\0",
        );
        // No exe link (another user's, or a kernel thread): skipped.
        fs::create_dir_all(d.path().join("2")).unwrap();
        fs::create_dir_all(d.path().join("self")).unwrap();
        let procs = list_processes(d.path());
        assert_eq!(
            procs,
            [ProcessEntry {
                pid: 53971,
                ppid: 1,
                uid: 1000,
                exe: "mvm-network-endpoint".into(),
                argv: vec![
                    "/opt/mvm/mvm-network-endpoint".into(),
                    "--vm-state-dir".into(),
                    "/s/vms/a b".into(),
                    String::new()
                ],
            }]
        );
    }
}

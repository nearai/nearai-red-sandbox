//! Invariants every backend must hold, checked for each flavor against a
//! recording fake mvmctl and host. The live counterparts, which boot real
//! machines through the same `Backend` API, are `tests/contain/invariants.rs`.
//!
//! - Attestation before inference: the launch preflight issues no machine
//!   command, and a failed attestation stops the launch before any machine
//!   exists.
//! - No route except the allowlist: a machine without an allowlist is
//!   created without egress, and one with an allowlist gets exactly its
//!   entries.
//! - The egress path and the VMM must be confirmed, or the session ends.

use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use super::mvm::{Flavor, MvmBackend};
use super::{Backend, HostCheck};
use crate::config::{Defaults, OperatorConfig, ProviderConfig, parse_config};
use crate::mvm::{RunOutput, Runner};
use crate::sandbox::{CreateSpec, Egress, sv};
use crate::session::{self, Deps, Host};

const MACHINE: &str = "rts-0123456789ab";
const IMAGE: &str =
    "example.invalid/guest@sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// mvmctl and the host in one: records every argv, answers healthy.
struct Rec {
    calls: Mutex<Vec<String>>,
}

impl Rec {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
    fn answer(&self, argv: &[String]) -> io::Result<RunOutput> {
        self.calls.lock().unwrap().push(argv.join(" "));
        let uid = format!("{}\n", super::kvm::current_uid());
        let stdout = match (argv.join(" ").as_str(), argv.last().map(String::as_str)) {
            (_, Some("--version")) => "2.2.2\n",
            (_, Some(session::SUPERVISOR_PROBE)) => session::SUPERVISOR_FIX_VERSION,
            // The Firecracker VMM of `rig`'s fc.pid, running as this user.
            ("readlink /proc/4244/exe", _) => "/usr/bin/firecracker\n",
            ("ps -o uid= -p 4244", _) => &uid,
            _ => "",
        };
        Ok(RunOutput {
            code: Some(0),
            stdout: stdout.into(),
            ..Default::default()
        })
    }
}

impl Runner for Rec {
    fn run(&self, argv: &[String], _: Duration) -> io::Result<RunOutput> {
        self.answer(argv)
    }
}

impl Host for Rec {
    fn run(&self, argv: &[String], _: Duration) -> io::Result<RunOutput> {
        self.answer(argv)
    }
}

struct Rig {
    rec: Arc<Rec>,
    backend: MvmBackend,
    cfg: OperatorConfig,
    _dir: tempfile::TempDir,
}

fn rig(flavor: Flavor) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let rec = Arc::new(Rec {
        calls: Mutex::new(vec![]),
    });
    let cfg = parse_config(
        r#"{ "provider": { "models": ["m"] } }"#,
        Path::new("/cfg"),
        &Defaults {
            mvmctl: "/m/mvmctl".into(),
            plugin_dir: "/p".into(),
            opencode: "opencode".into(),
            sessions_dir: "/s".into(),
        },
    )
    .unwrap();
    let env = vec![
        ("HOME".into(), "/fake/home".into()),
        ("MVM_HOME".into(), dir.path().to_string_lossy().into_owned()),
    ];
    let deps = Deps {
        host: rec.clone(),
        runner: Some(rec.clone()),
        env,
        tool_command: sv(&["/x/rts", "tool"]),
        session_id: None,
        fatal: None,
        resolver: Arc::new(crate::network::SystemResolver),
        clock: Arc::new(SystemTime::now),
    };
    let paths = session::session_paths(
        "0123456789ab",
        &dir.path().join("s"),
        &dir.path().join("rt"),
    );
    // A file this user can open stands in for /dev/kvm.
    let fc_pid = dir.path().join("vms").join(MACHINE).join("fc.pid");
    std::fs::create_dir_all(fc_pid.parent().unwrap()).unwrap();
    std::fs::write(&fc_pid, "4244\n").unwrap();
    let kvm = dir.path().join("kvm");
    std::fs::write(&kvm, "").unwrap();
    let backend = MvmBackend::for_session_flavor(flavor, &cfg, &deps, &paths)
        .unwrap()
        .with_kvm(&kvm);
    Rig {
        rec,
        backend,
        cfg,
        _dir: dir,
    }
}

fn provider() -> ProviderConfig {
    ProviderConfig {
        id: "p".into(),
        base_url: "https://example.invalid/v1".into(),
        models: vec!["m".into()],
        api_key_env: None,
    }
}

fn is_machine_command(c: &str) -> bool {
    c.starts_with("machine ") || c.starts_with("attach ")
}

/// Run `check` once per flavor, naming the flavor on failure.
fn each_flavor(check: impl Fn(Flavor)) {
    for flavor in [Flavor::Hvf, Flavor::Firecracker] {
        check(flavor);
    }
}

#[test]
fn a_failed_attestation_stops_the_launch_before_any_machine_exists() {
    each_flavor(|flavor| {
        let mut r = rig(flavor);
        let backend = &r.backend;
        let rec = r.rec.clone();
        let p = provider();
        let result = crate::launch::run_connected::<()>(
            &mut r.cfg,
            |_| {
                backend.preflight(&HostCheck {
                    host: rec.as_ref(),
                    opencode: "opencode",
                    leak_seam_set: false,
                    work_dir: None,
                    provider: &p,
                })
            },
            |_| Err("attestation failed: quote did not verify".into()),
            |_| panic!("{flavor:?}: the session started without attestation"),
        );
        assert_eq!(
            result.unwrap_err(),
            "attestation failed: quote did not verify",
            "{flavor:?}"
        );
        let calls = r.rec.calls();
        assert!(
            calls.iter().any(|c| c.starts_with("doctor")),
            "{flavor:?}: preflight did not run: {calls:?}"
        );
        assert!(
            !calls.iter().any(|c| is_machine_command(c)),
            "{flavor:?}: machine command before attestation: {calls:?}"
        );
    });
}

#[test]
fn a_machine_without_an_allowlist_is_created_without_egress() {
    each_flavor(|flavor| {
        let r = rig(flavor);
        let m = r.backend.machine(MACHINE).unwrap();
        m.create(&CreateSpec {
            name: MACHINE,
            image: IMAGE,
            memory_mib: 512,
            cpus: 1,
            egress: None,
        })
        .unwrap();
        let calls = r.rec.calls();
        let create = calls
            .iter()
            .find(|c| c.starts_with("machine create "))
            .unwrap_or_else(|| panic!("{flavor:?}: {calls:?}"));
        assert!(!create.contains("--allow-host"), "{flavor:?}: {create}");
        assert!(
            !calls.iter().any(|c| c.starts_with("attach ")),
            "{flavor:?}: a no-network machine got a network run: {calls:?}"
        );
    });
}

#[test]
fn a_machine_with_an_allowlist_gets_exactly_its_entries() {
    each_flavor(|flavor| {
        let r = rig(flavor);
        let hosts = crate::network::test_allow_hosts(&["198.51.100.7:443", "198.51.100.8:8443"]);
        let log = r._dir.path().join("attach.log");
        let m = r.backend.machine(MACHINE).unwrap();
        // The recording runner cannot hold an attached `machine run`, so
        // create stops there; the create argv is what this checks.
        let _ = m.create(&CreateSpec {
            name: MACHINE,
            image: IMAGE,
            memory_mib: 512,
            cpus: 1,
            egress: Some(Egress {
                allow_hosts: &hosts,
                attach_log: &log,
                session_hours: 1,
            }),
        });
        let calls = r.rec.calls();
        let create = calls
            .iter()
            .find(|c| c.starts_with("machine create "))
            .unwrap_or_else(|| panic!("{flavor:?}: {calls:?}"));
        let allowed: Vec<&str> = create
            .split(" --allow-host ")
            .skip(1)
            .map(|s| s.split(' ').next().unwrap())
            .collect();
        assert_eq!(
            allowed,
            ["198.51.100.7:443", "198.51.100.8:8443"],
            "{flavor:?}: {create}"
        );
    });
}

#[test]
fn an_unconfirmed_egress_path_or_vmm_refuses_the_session() {
    each_flavor(|flavor| {
        let r = rig(flavor);
        let m = r.backend.machine(MACHINE).unwrap();
        assert!(
            m.track_network().is_err(),
            "{flavor:?}: egress path accepted without an attached run"
        );
        let _ = std::fs::remove_file(
            r._dir
                .path()
                .join("vms")
                .join(MACHINE)
                .join(flavor.pid_file()),
        );
        let e = m
            .monitor()
            .err()
            .unwrap_or_else(|| panic!("{flavor:?}: VMM accepted without a PID file"));
        assert!(e.starts_with("cannot monitor "), "{flavor:?}: {e}");
    });
}

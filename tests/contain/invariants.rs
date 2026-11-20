//! Backend invariants on a real machine. Each test drives this host's
//! backend flavor (HVF on macOS, Firecracker on Linux) through the same
//! `rts::backend` API a session uses, so the suite runs unchanged on every
//! backend. The fake-runner counterparts, run for every flavor on any
//! host, are `src/backend/invariants.rs`.
//!
//!     cargo test --test contain invariants:: -- --ignored --test-threads=1

use std::fs;
use std::path::PathBuf;

use rts::backend::mvm::{Flavor, MvmBackend};
use rts::backend::{Backend, Machine};
use rts::config::{Defaults, parse_config};
use rts::network::{Probe, SystemResolver, probe_argv, run_probes};
use rts::protocol::random_hex;
use rts::sandbox::{CopyOutResult, CreateSpec, Egress, ExecOptions, sv};
use rts::session::{
    Deps, SessionPaths, initialize_guest_storage, prepare_session_dirs, session_paths,
};

use crate::harness::{NETWORK_TEST_HOURS, mvm, tempdir};
use rts::config::DEFAULT_IMAGE;
use std::path::Path;

/// A machine removed when dropped, so a failing test still cleans up.
struct Guest(Box<dyn Machine>);

impl Drop for Guest {
    fn drop(&mut self) {
        if let Err(e) = self.0.remove() {
            eprintln!("[contain] removing an invariants machine failed: {e}");
        }
    }
}

struct Rig {
    backend: Box<dyn Backend>,
    paths: SessionPaths,
    dir: PathBuf,
    image: String,
}

/// mvmctl and the guest image. On HVF, the containment harness, which also
/// probes the patched supervisor. On other flavors, which have no
/// supervisor, `RTS_MVMCTL` (or where setup installs it) and `RTS_IMAGE`.
fn prerequisites() -> (PathBuf, String) {
    if Flavor::host() == Flavor::Hvf {
        let h = mvm().expect("real-mvm prerequisites");
        return (h.mvmctl.clone(), h.image.clone());
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let mvmctl = std::env::var_os("RTS_MVMCTL")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(&home).join(".local/mvm/v0.22.0/mvmctl"));
    assert!(
        mvmctl.is_file(),
        "[contain] mvmctl not found at {} (set RTS_MVMCTL)",
        mvmctl.display()
    );
    (
        mvmctl,
        std::env::var("RTS_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.into()),
    )
}

/// This host's backend for a fresh session id, built as a session builds it.
fn rig() -> Rig {
    let (mvmctl, image) = prerequisites();
    let dir = tempdir("inv");
    let id = random_hex(6);
    let paths = session_paths(&id, &dir.join("sessions"), &dir.join("runtime"));
    prepare_session_dirs(&paths).unwrap();
    let defaults = Defaults {
        mvmctl,
        plugin_dir: dir.join("plugin"),
        opencode: "opencode".into(),
        sessions_dir: dir.join("sessions"),
    };
    let cfg = parse_config("{}", &dir, &defaults).unwrap();
    let deps = Deps::real(id, None).unwrap();
    let backend: Box<dyn Backend> =
        Box::new(MvmBackend::for_session_flavor(Flavor::host(), &cfg, &deps, &paths).unwrap());
    eprintln!("[contain] invariants on {:?}", Flavor::host());
    Rig {
        backend,
        paths,
        dir,
        image,
    }
}

fn create(r: &Rig, egress: Option<Egress>) -> Guest {
    let m = Guest(r.backend.machine(&r.paths.machine).unwrap());
    m.0.create(&CreateSpec {
        name: &r.paths.machine,
        image: &r.image,
        memory_mib: 512,
        cpus: 1,
        egress,
    })
    .expect("machine create");
    initialize_guest_storage(m.0.as_ref()).expect("guest input/output storage");
    m
}

fn last_line(m: &Guest, argv: &[String]) -> String {
    let r = m.0.exec(argv, &ExecOptions::new(30_000, 4096)).unwrap();
    String::from_utf8_lossy(&r.stdout)
        .trim_end()
        .rsplit('\n')
        .next()
        .unwrap_or("")
        .to_string()
}

#[test]
#[ignore = "real mvm"]
fn invariant_no_allowlist_means_no_route_out() {
    let r = rig();
    let m = create(&r, None);
    let plan = rts::network::plan(&[], &SystemResolver).unwrap();
    assert_eq!(
        run_probes(m.0.as_ref(), &plan).unwrap(),
        [Probe {
            target: "1.1.1.1:443".into(),
            result: "unreachable".into()
        }]
    );
    let links =
        m.0.exec(&sv(&["ip", "-o", "link"]), &ExecOptions::new(30_000, 4096))
            .unwrap();
    let text = String::from_utf8_lossy(&links.stdout);
    let names: Vec<&str> = text
        .lines()
        .filter_map(|l| l.split(':').nth(1))
        .map(str::trim)
        .collect();
    assert_eq!(names, ["lo"], "the guest has a network device");
    drop(m);
    fs::remove_dir_all(&r.dir).unwrap();
}

#[test]
#[ignore = "real mvm"]
fn invariant_the_allowlist_is_exact_and_pinned() {
    let r = rig();
    let plan = rts::network::plan(&["pypi.org".to_string()], &SystemResolver).unwrap();
    let hosts = plan.allow_hosts();
    let m = create(
        &r,
        Some(Egress {
            allow_hosts: &hosts,
            attach_log: &r.paths.attach_log,
            session_hours: NETWORK_TEST_HOURS,
        }),
    );
    m.0.track_network().expect("the egress path is confirmed");
    assert_eq!(
        run_probes(m.0.as_ref(), &plan).unwrap(),
        [Probe {
            target: "pypi.org:443".into(),
            result: "connected".into()
        }]
    );
    let pins =
        m.0.wait_for_pins(
            &plan,
            &(std::sync::Arc::new(std::time::SystemTime::now) as rts::session::Clock),
        )
        .unwrap();
    rts::network::check_pinned(&plan, &pins).unwrap();
    for target in ["example.com:443", "pypi.org:80", "169.254.169.254:80"] {
        let line = last_line(&m, &probe_argv(target));
        assert!(
            line.starts_with("RTS_PROBE refused"),
            "{target} was not refused: {line:?}"
        );
    }
    assert_eq!(m.0.network_lost(), None);
    drop(m);
    fs::remove_dir_all(&r.dir).unwrap();
}

#[test]
#[ignore = "real mvm"]
fn invariant_no_host_files_except_the_in_copy_and_the_out_export() {
    let r = rig();
    let token = random_hex(16);
    let sentinel = r.dir.join("host-sentinel");
    fs::write(&sentinel, &token).unwrap();
    let inputs = r.dir.join("inputs");
    fs::create_dir_all(&inputs).unwrap();
    fs::write(inputs.join("given.txt"), "copied in\n").unwrap();
    let m = create(&r, None);
    m.0.copy_in(&inputs, "/in").unwrap();
    let opts = ExecOptions::new(30_000, 4096);
    let given = m.0.exec(&sv(&["cat", "/in/given.txt"]), &opts).unwrap();
    assert_eq!(String::from_utf8_lossy(&given.stdout), "copied in\n");
    // Host-only paths: this test's private directory and what is in it.
    for host_path in [
        sentinel.to_str().unwrap(),
        r.dir.to_str().unwrap(),
        inputs.to_str().unwrap(),
    ] {
        let seen = m.0.exec(&sv(&["test", "-e", host_path]), &opts).unwrap();
        assert_ne!(seen.exit_code, 0, "the guest sees host path {host_path}");
    }
    let write =
        m.0.exec(&sv(&["sh", "-c", "echo result > /out/result.txt"]), &opts)
            .unwrap();
    assert_eq!(write.exit_code, 0);
    let out = r.dir.join("exported");
    assert!(matches!(
        m.0.copy_out("/out", &out).unwrap(),
        CopyOutResult::Exported { files: 1, .. }
    ));
    assert_eq!(
        fs::read_to_string(out.join("result.txt")).unwrap(),
        "result\n"
    );
    assert_eq!(
        fs::read_to_string(&sentinel).unwrap(),
        token,
        "the host sentinel changed"
    );
    drop(m);
    fs::remove_dir_all(&r.dir).unwrap();
}

#[test]
#[ignore = "real mvm"]
fn invariant_the_vmm_is_confirmed_and_held_to_the_rss_ceiling() {
    let r = rig();
    let m = create(&r, None);
    let monitor = m.0.monitor().expect("the VMM is confirmed");
    let rss = monitor.sample(u64::MAX).unwrap();
    assert!(rss > 0, "{}", monitor.describe());
    assert!(monitor.sample(0).unwrap_err().contains("ceiling"));
    drop(m);
    fs::remove_dir_all(&r.dir).unwrap();
}

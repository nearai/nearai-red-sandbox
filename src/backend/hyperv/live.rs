//! Live checks on a Windows host with Hyper-V: boot rts's kernel and
//! initramfs from rts's own document, reach the agent with `HvConnect`, run
//! commands through `GuestExec`. Ignored by default; run with
//! RTS_HV_KERNEL and RTS_HV_INITRD set and `--ignored`.

use std::time::{Duration, Instant};

use super::doc::{EXEC_PORT, VmSpec, document, new_vm_id, service_id};
use super::exec::GuestExec;
use super::hcs::ComputeSystem;
use super::hvsock::HvConnect;
use crate::sandbox::{Error, Exec, ExecOptions};

fn user_sid() -> String {
    let out = std::process::Command::new("whoami")
        .arg("/user")
        .arg("/fo")
        .arg("csv")
        .arg("/nh")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    text.trim()
        .rsplit(',')
        .next()
        .unwrap()
        .trim_matches('"')
        .to_string()
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

#[test]
#[ignore = "boots a Hyper-V VM"]
fn a_guest_boots_with_only_loopback_and_runs_commands_over_hvsocket() {
    let kernel = std::env::var("RTS_HV_KERNEL").expect("RTS_HV_KERNEL");
    let initrd = std::env::var("RTS_HV_INITRD").expect("RTS_HV_INITRD");
    let sid = user_sid();
    let id = new_vm_id();
    let pipe = format!(r"\\.\pipe\rts-live-{}-com1", &id[..8]);
    let doc = document(&VmSpec {
        kernel: &kernel,
        initrd: &initrd,
        memory_mib: 1024,
        cpus: 2,
        com_pipe: &pipe,
        user_sid: &sid,
    });
    let vm = ComputeSystem::create(&id, &doc.to_string()).unwrap();
    let t0 = Instant::now();
    vm.start().unwrap();
    eprintln!("[hv-live] started {id}");
    let props = vm.properties("{}").unwrap();
    assert!(props.contains(r#""State":"Running""#), "{props}");

    // The agent listens once init has run: poll with a short connect timeout.
    let connect = HvConnect::new(&id, &service_id(EXEC_PORT), Duration::from_secs(2)).unwrap();
    let mut ready = None;
    let mut last = String::new();
    for _ in 0..120 {
        let probe = GuestExec::new(
            HvConnect::new(&id, &service_id(EXEC_PORT), Duration::from_secs(2)).unwrap(),
            Duration::from_secs(10),
        );
        match probe.exec(&s(&["true"]), &ExecOptions::new(5_000, 1024)) {
            Ok(_) => {
                ready = Some(t0.elapsed());
                break;
            }
            Err(e) => last = e.to_string(),
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let ready = ready.unwrap_or_else(|| panic!("the guest agent never answered: {last}"));
    eprintln!(
        "[hv-live] agent answered {} ms after start",
        ready.as_millis()
    );

    let g = GuestExec::new(connect, Duration::from_secs(30));
    let r = g
        .exec(
            &s(&["sh", "-c", "id -u; ls /sys/class/net; echo e >&2; exit 3"]),
            &ExecOptions::new(10_000, 1 << 20),
        )
        .unwrap();
    assert_eq!(r.exit_code, 3);
    assert_eq!(String::from_utf8_lossy(&r.stdout), "1000\nlo\n");
    assert_eq!(r.stderr, b"e\n");
    let r = g
        .exec(&s(&["sleep", "5"]), &ExecOptions::new(1_000, 1024))
        .unwrap();
    assert!(r.timed_out, "{r:?}");
    let r = g
        .exec(
            &s(&["sh", "-c", "head -c 2000000 /dev/zero"]),
            &ExecOptions::new(30_000, 1000),
        )
        .unwrap();
    assert_eq!(
        (r.stdout.len(), r.stdout_bytes, r.truncated),
        (1000, 2_000_000, true)
    );

    vm.terminate().unwrap();
    let e = g
        .exec(&s(&["true"]), &ExecOptions::new(5_000, 1024))
        .unwrap_err();
    assert!(matches!(e, Error::Unavailable(_)), "{e}");
    eprintln!("[hv-live] after terminate: {e}");
}

#[test]
#[ignore = "boots a Hyper-V VM"]
fn print_the_statistics_and_memory_properties() {
    let kernel = std::env::var("RTS_HV_KERNEL").expect("RTS_HV_KERNEL");
    let initrd = std::env::var("RTS_HV_INITRD").expect("RTS_HV_INITRD");
    let sid = user_sid();
    let id = new_vm_id();
    let pipe = format!(r"\\.\pipe\rts-live-{}-com1", &id[..8]);
    let doc = document(&VmSpec {
        kernel: &kernel,
        initrd: &initrd,
        memory_mib: 1024,
        cpus: 2,
        com_pipe: &pipe,
        user_sid: &sid,
    });
    let vm = ComputeSystem::create(&id, &doc.to_string()).unwrap();
    vm.start().unwrap();
    let g = GuestExec::new(
        HvConnect::new(&id, &service_id(EXEC_PORT), Duration::from_secs(2)).unwrap(),
        Duration::from_secs(30),
    );
    for _ in 0..40 {
        if g.exec(
            &s(&[
                "sh",
                "-c",
                "head -c 200000000 /dev/zero > /tmp/x; ls -l /tmp/x",
            ]),
            &ExecOptions::new(30_000, 4096),
        )
        .is_ok()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    for q in [
        r#"{"PropertyTypes":["Statistics"]}"#,
        r#"{"PropertyTypes":["Memory"]}"#,
    ] {
        let out = vm.properties(q).unwrap_or_else(|e| e.to_string());
        if let Ok(path) = std::env::var("RTS_HV_PROPS_OUT") {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .unwrap();
            writeln!(f, "{out}").unwrap();
        }
    }
    vm.terminate().unwrap();
}

#[test]
#[ignore = "boots a Hyper-V VM"]
fn record_what_a_vm_without_a_com_port_does_and_what_enumerate_returns() {
    use super::exec::Connect as _;
    use crate::hvexec::serve::TryClone as _;
    let kernel = std::env::var("RTS_HV_KERNEL").expect("RTS_HV_KERNEL");
    let initrd = std::env::var("RTS_HV_INITRD").expect("RTS_HV_INITRD");
    let out = std::env::var("RTS_HV_PROPS_OUT").expect("RTS_HV_PROPS_OUT");
    let mut log = String::new();
    let sid = user_sid();
    let id = new_vm_id();
    let mut doc = document(&VmSpec {
        kernel: &kernel,
        initrd: &initrd,
        memory_mib: 1024,
        cpus: 2,
        com_pipe: "unused",
        user_sid: &sid,
    });
    doc["VirtualMachine"]["Devices"]
        .as_object_mut()
        .unwrap()
        .remove("ComPorts");
    let vm = ComputeSystem::create(&id, &doc.to_string()).unwrap();
    vm.start().unwrap();
    let c = HvConnect::new(&id, &service_id(EXEC_PORT), Duration::from_secs(1)).unwrap();
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(10) {
        let state = vm
            .properties("{}")
            .map(|p| {
                p.split("\"State\":")
                    .nth(1)
                    .map(|x| x[..x.find(',').or(x.find('}')).unwrap_or(x.len())].to_string())
                    .unwrap_or(p)
            })
            .unwrap_or_else(|e| format!("err {e}"));
        let conn = c
            .connect(Duration::from_secs(1))
            .map(|s| {
                let _ = s.shutdown_stream();
                "connected".to_string()
            })
            .unwrap_or_else(|e| format!("{e}"));
        log.push_str(&format!(
            "{:>5} ms state={state} connect={conn}\n",
            t0.elapsed().as_millis()
        ));
        std::thread::sleep(Duration::from_millis(1000));
    }
    log.push_str(&format!(
        "enumerate(rts) => {:?}\n",
        super::hcs::enumerate(r#"{"Owners":["rts"]}"#)
    ));
    log.push_str(&format!(
        "enumerate(all) => {:?}\n",
        super::hcs::enumerate("{}")
    ));
    let _ = vm.terminate();
    std::fs::write(out, log).unwrap();
}

#[test]
#[ignore = "boots a Hyper-V VM"]
fn a_machine_copies_in_and_out_has_no_route_out_and_is_monitored() {
    use super::machine::{GuestImage, HcsHost, HyperVMachine};
    use crate::backend::Machine;
    use crate::sandbox::{CopyOutResult, CreateSpec, Sandbox};
    use sha2::{Digest, Sha256};
    let kernel = std::path::PathBuf::from(std::env::var("RTS_HV_KERNEL").expect("RTS_HV_KERNEL"));
    let initrd = std::path::PathBuf::from(std::env::var("RTS_HV_INITRD").expect("RTS_HV_INITRD"));
    let digest = |p: &std::path::Path| hex::encode(Sha256::digest(std::fs::read(p).unwrap()));
    let image = GuestImage {
        kernel_sha256: digest(&kernel),
        initrd_sha256: digest(&initrd),
        kernel,
        initrd,
        user_sid: user_sid(),
        pipe_prefix: r"\\.\pipe\rts-live-".into(),
        vm_ids: std::env::temp_dir().join("rts-live-vms"),
    };
    let m = HyperVMachine::new("rts-live00000001", HcsHost, image);
    let t0 = Instant::now();
    m.create(&CreateSpec {
        name: "rts-live00000001",
        image: "unused",
        memory_mib: 1024,
        cpus: 2,
        egress: None,
    })
    .unwrap();
    eprintln!(
        "[hv-live] machine ready {} ms after create",
        t0.elapsed().as_millis()
    );

    crate::session::initialize_guest_storage(&m).unwrap();
    let host = tempfile::tempdir().unwrap();
    let input = host.path().join("in");
    std::fs::create_dir_all(input.join("sub")).unwrap();
    std::fs::write(input.join("sub").join("task.txt"), b"from the host\n").unwrap();
    m.copy_in(&input, "/in").unwrap();
    let r = m
        .exec(
            &s(&[
                "sh",
                "-c",
                "cat /in/sub/task.txt; echo report > /out/report.md",
            ]),
            &ExecOptions::new(10_000, 4096),
        )
        .unwrap();
    assert_eq!(
        (r.exit_code, r.stdout.as_slice()),
        (0, b"from the host\n".as_slice())
    );
    let out = host.path().join("out");
    let copied = m.copy_out("/out", &out).unwrap();
    assert_eq!(copied, CopyOutResult::Exported { files: 1, bytes: 7 });
    assert_eq!(std::fs::read(out.join("report.md")).unwrap(), b"report\n");

    let plan = crate::network::plan(&[], &crate::network::SystemResolver).unwrap();
    let probes = crate::network::run_probes(&m, &plan).unwrap();
    assert_eq!(probes.len(), 1);
    assert_eq!(probes[0].result, "unreachable", "{probes:?}");
    let links = m
        .exec(
            &s(&["ls", "/sys/class/net"]),
            &ExecOptions::new(10_000, 4096),
        )
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&links.stdout)
            .split_whitespace()
            .collect::<Vec<_>>(),
        ["lo"]
    );

    let mon = m.monitor().unwrap();
    assert_eq!(mon.sample(4096), Ok(1024));
    assert!(mon.sample(512).is_err());
    m.remove().unwrap();
    assert!(mon.sample(4096).is_err());
    assert!(m.exec(&s(&["true"]), &ExecOptions::new(1000, 64)).is_err());
}

#[test]
#[ignore = "boots a Hyper-V VM"]
fn a_guest_connection_to_its_loopback_proxy_reaches_the_host_listener() {
    use super::doc::EGRESS_PORT;
    use super::hvsock::HvListener;
    use crate::hvexec::serve::TryClone as _;
    use std::io::{BufRead, BufReader, Write};
    let kernel = std::env::var("RTS_HV_KERNEL").expect("RTS_HV_KERNEL");
    let initrd = std::env::var("RTS_HV_INITRD").expect("RTS_HV_INITRD");
    let sid = user_sid();
    let id = new_vm_id();
    let pipe = format!(r"\\.\pipe\rts-live-{}-com1", &id[..8]);
    let doc = document(&VmSpec {
        kernel: &kernel,
        initrd: &initrd,
        memory_mib: 1024,
        cpus: 2,
        com_pipe: &pipe,
        user_sid: &sid,
    });
    let vm = ComputeSystem::create(&id, &doc.to_string()).unwrap();
    let listener = HvListener::bind(&id, &service_id(EGRESS_PORT)).unwrap();
    vm.start().unwrap();
    let host = std::thread::spawn(move || {
        let mut conn = listener.accept().unwrap();
        let mut reader = BufReader::new(conn.try_clone_stream().unwrap());
        let mut first = String::new();
        reader.read_line(&mut first).unwrap();
        conn.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .unwrap();
        first
    });
    let g = GuestExec::new(
        HvConnect::new(&id, &service_id(EXEC_PORT), Duration::from_secs(2)).unwrap(),
        Duration::from_secs(30),
    );
    let mut out = None;
    for _ in 0..40 {
        let probe = GuestExec::new(
            HvConnect::new(&id, &service_id(EXEC_PORT), Duration::from_secs(2)).unwrap(),
            Duration::from_secs(10),
        );
        if probe
            .exec(&s(&["true"]), &ExecOptions::new(5_000, 64))
            .is_ok()
        {
            out = Some(
                g.exec(
                    &s(&["sh", "-c", r"printf 'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n' | nc -w 3 127.0.0.1 1080 | head -1"]),
                    &ExecOptions::new(15_000, 4096),
                )
                .unwrap(),
            );
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let out = out.expect("the guest agent never answered");
    let first = host
        .join()
        .expect("the host listener never got the guest's connection");
    assert_eq!(first, "CONNECT example.com:443 HTTP/1.1\r\n");
    assert!(
        String::from_utf8_lossy(&out.stdout).starts_with("HTTP/1.1 200"),
        "{out:?}"
    );
    vm.terminate().unwrap();
}

/// Child half of the kill test: hold a VM until killed.
#[test]
#[ignore = "boots a Hyper-V VM; run by a_killed_rts_process_takes_its_vm_down"]
fn child_holds_a_vm_until_killed() {
    use crate::backend::Backend;
    use crate::sandbox::CreateSpec;
    let Ok(out) = std::env::var("RTS_HV_HOLD_OUT") else {
        return;
    };
    let env: Vec<(String, String)> = std::env::vars().collect();
    let backend = super::backend::HyperVBackend::windows(&env).unwrap();
    let m = backend.machine("rts-killtest0001").unwrap();
    m.create(&CreateSpec {
        name: "rts-killtest0001",
        image: "unused",
        memory_mib: 512,
        cpus: 1,
        egress: None,
    })
    .unwrap();
    let dir = super::backend::guest_dir(&env).unwrap().join("vms");
    let ids: Vec<String> = super::machine::recorded_vms(&dir)
        .into_iter()
        .filter(|(_, n)| n == "rts-killtest0001")
        .map(|(i, _)| i)
        .collect();
    std::fs::write(&out, ids.join("\n")).unwrap();
    std::thread::sleep(Duration::from_secs(600));
}

#[test]
#[ignore = "boots a Hyper-V VM"]
fn a_killed_rts_process_takes_its_vm_down() {
    use super::machine::{HcsHost, VmHost};
    use super::props::VmState;
    use crate::backend::Backend;
    let out = std::env::temp_dir().join(format!("rts-hold-{}", new_vm_id()));
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "backend::hyperv::live::child_holds_a_vm_until_killed",
            "--exact",
            "--ignored",
            "--nocapture",
        ])
        .env("RTS_HV_HOLD_OUT", &out)
        .spawn()
        .unwrap();
    let t0 = Instant::now();
    while !out.exists() && t0.elapsed() < Duration::from_secs(90) {
        std::thread::sleep(Duration::from_millis(200));
    }
    std::thread::sleep(Duration::from_millis(200));
    let id = std::fs::read_to_string(&out)
        .expect("the child never reported its VM")
        .trim()
        .to_string();
    assert!(super::doc::parse_guid(&id).is_some(), "{id:?}");
    let host = HcsHost;
    let before = host.open(&id).unwrap().expect("the child's VM exists");
    assert_eq!(before.state().unwrap(), VmState::Running);
    drop(before);
    // TerminateProcess: no destructor or remove() runs in the child.
    child.kill().unwrap();
    child.wait().unwrap();
    let t1 = Instant::now();
    // Wait for a definite answer: gone, or Stopped. While it tears down,
    // HCS answers HCS_E_INVALID_STATE, which proves nothing either way.
    let mut seen = vec![];
    let gone = loop {
        let now = match host.open(&id).unwrap() {
            None => Some("no longer exists".to_string()),
            Some(vm) => match vm.state() {
                Ok(VmState::Stopped(exit)) => Some(format!("is stopped ({exit})")),
                other => {
                    seen.push(format!("{other:?}").chars().take(80).collect::<String>());
                    None
                }
            },
        };
        if let Some(g) = now {
            break g;
        }
        assert!(
            t1.elapsed() < Duration::from_secs(30),
            "the VM outlived its rts process: {seen:?}"
        );
        std::thread::sleep(Duration::from_millis(250));
    };
    eprintln!(
        "[hv-live] {} ms after the kill the VM {gone} (on the way: {:?})",
        t1.elapsed().as_millis(),
        seen.first()
    );
    // The id the child recorded is stale now: the sweep drops it quietly.
    let env: Vec<(String, String)> = std::env::vars().collect();
    let backend = super::backend::HyperVBackend::windows(&env).unwrap();
    let mut lines = vec![];
    backend.sweep(&mut |l| lines.push(l.to_string())).unwrap();
    assert!(lines.iter().all(|l| !l.contains(&id)), "{lines:?}");
    let dir = super::backend::guest_dir(&env).unwrap().join("vms");
    assert!(
        super::machine::recorded_vms(&dir)
            .iter()
            .all(|(i, _)| i != &id)
    );
    let _ = std::fs::remove_file(out);
}

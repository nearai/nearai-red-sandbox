//! Guest egress against real mvm: the allowlist lets exactly its entries
//! out through mvm's proxy, everything else (the host's loopback and LAN,
//! cloud metadata, other names and ports) is refused and audited, and a
//! lost attached `machine run` is noticed and leaves no network process.

use std::fs;
use std::io::{ErrorKind, Read};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rts::mvm::list_machines;
use rts::network::{Plan, Probe, SystemResolver, extract_audit, probe_argv, read_pinned, run_probes};
use rts::sandbox::{Exec, ExecOptions, Sandbox, sv};
use rts::session::{Host, RealHost, mvm_root, network_children};
use serde_json::{Value, json};

use crate::harness::{Machine, bridge_options, bridge_options_with, fake_ironwire, fake_ironwire_counted, fresh_machine, fresh_network_machine, mvm, opencode, rts_tool, tempdir};

/// The guest proxy probe's last stdout line for `target`.
fn probe_line(m: &Machine, target: &str) -> String {
    let r = m.exec(&probe_argv(target), &ExecOptions::new(30_000, 4096)).unwrap();
    assert!(!r.timed_out, "probe {target} timed out");
    let out = String::from_utf8_lossy(&r.stdout);
    out.trim_end().rsplit('\n').next().unwrap_or("").to_string()
}

/// The probe ran (the guest has `nc`) and the proxy did not connect.
fn assert_refused(m: &Machine, target: &str) {
    let line = probe_line(m, target);
    assert!(line.starts_with("RTS_PROBE refused"), "{target} was not refused: {line:?}");
}

/// A direct TCP connect from the guest, bypassing the proxy, fails.
fn assert_no_direct_route(m: &Machine, host: &str, port: u16) {
    let r = m.exec(&sv(&["nc", "-w", "5", host, &port.to_string()]), &ExecOptions::new(30_000, 4096)).unwrap();
    assert_ne!(r.exit_code, 0, "the guest connected directly to {host}:{port}");
}

fn listener(addr: &str) -> (TcpListener, u16) {
    let l = TcpListener::bind((addr, 0)).unwrap();
    l.set_nonblocking(true).unwrap();
    let port = l.local_addr().unwrap().port();
    (l, port)
}

fn assert_accepted_nothing(l: &TcpListener, what: &str) {
    match l.accept() {
        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
        Ok((_, peer)) => panic!("{what} accepted a connection from {peer}"),
        Err(e) => panic!("{what}: accept failed: {e}"),
    }
}

/// The host's LAN address. A test that needs one fails without it.
fn lan_address() -> String {
    for iface in ["en0", "en1"] {
        let o = Command::new("ipconfig").args(["getifaddr", iface]).output().unwrap();
        let addr = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if o.status.success() && !addr.is_empty() {
            return addr;
        }
    }
    panic!("no LAN address on en0 or en1: the LAN refusal cannot be tested");
}

fn audit_dir() -> std::path::PathBuf {
    let env: Vec<(String, String)> = std::env::vars().collect();
    mvm_root(&env).unwrap().join("audit")
}

/// This machine's lines of mvm's audit log, copied as a session copies them.
fn audit_lines(name: &str, dir: &Path) -> Vec<Value> {
    let out = dir.join("network.jsonl");
    let n = extract_audit(&audit_dir(), name, &out).unwrap();
    let text = fs::read_to_string(&out).unwrap();
    let lines: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(lines.len(), n);
    for l in &lines {
        assert_eq!(l["entry"]["labels"]["vm_name"], json!(name), "{l}");
    }
    lines
}

fn has_event(lines: &[Value], event: &str, target: &str) -> bool {
    lines.iter().any(|l| l["entry"]["event"] == json!(event) && l["entry"]["labels"]["target"] == json!(target))
}

fn assert_gone(h: &crate::harness::Harness, name: &str) {
    assert!(!list_machines(h.run.as_ref()).unwrap().contains(&name.to_string()), "{name} is still listed");
}

fn comm(pid: u32) -> Option<String> {
    let o = RealHost.run(&sv(&["ps", "-o", "comm=", "-p", &pid.to_string()]), Duration::from_secs(5)).unwrap();
    let text = String::from_utf8_lossy(&o.stdout).trim().to_string();
    (o.code == Some(0) && !text.is_empty()).then(|| text.rsplit('/').next().unwrap().to_string())
}

/// The audit's pins for this plan, polled for up to 10 s as a session does.
fn pinned(plan: &Plan, name: &str) -> std::collections::BTreeMap<String, std::collections::BTreeSet<std::net::IpAddr>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let p = read_pinned(&audit_dir(), name).unwrap();
        if plan.pinning_names().iter().all(|n| p.get(*n).is_some_and(|s| !s.is_empty())) || Instant::now() >= deadline {
            return p;
        }
        thread::sleep(Duration::from_millis(200));
    }
}

#[test]
#[ignore = "real mvm"]
fn no_allowlist_reaches_nothing_and_the_deny_all_probe_passes() {
    let Some(h) = mvm() else { return };
    let m = fresh_machine(h);
    let name = m.name.clone();
    let plan = rts::network::plan(&[], &SystemResolver).unwrap();
    assert_eq!(run_probes(&*m, &plan).unwrap(), [Probe { target: "1.1.1.1:443".into(), result: "unreachable".into() }]);
    let line = probe_line(&m, "pypi.org:443");
    assert!(line.starts_with("RTS_PROBE") && line != "RTS_PROBE connected", "{line:?}");
    drop(m);
    assert_gone(h, &name);
}

#[test]
#[ignore = "real mvm"]
fn one_allowed_host_connects_and_everything_else_is_refused_and_logged() {
    let Some(h) = mvm() else { return };
    let lan = lan_address();
    let (local, local_port) = listener("127.0.0.1");
    let (on_lan, lan_port) = listener(&lan);
    let (m, plan, dir) = fresh_network_machine(h, &["pypi.org"]);
    let name = m.name.clone();
    assert_eq!(run_probes(&*m, &plan).unwrap(), [Probe { target: "pypi.org:443".into(), result: "connected".into() }]);
    // Task 9b on real mvm: what mvm pinned matches what rts validated.
    let pins = pinned(&plan, &name);
    eprintln!("[contain] pinned for {name}: {pins:?}");
    rts::network::check_pinned(&plan, &pins).unwrap();
    let local_target = format!("127.0.0.1:{local_port}");
    let lan_target = format!("{lan}:{lan_port}");
    let refused = ["example.com:443", "pypi.org:80", &local_target, &lan_target, "169.254.169.254:80"];
    for t in refused {
        assert_refused(&m, t);
    }
    assert_no_direct_route(&m, &lan, lan_port);
    assert_no_direct_route(&m, "169.254.169.254", 80);
    assert_accepted_nothing(&local, "the host loopback listener");
    assert_accepted_nothing(&on_lan, "the host LAN listener");
    drop(m);
    assert_gone(h, &name);
    let lines = audit_lines(&name, &dir);
    for l in &lines {
        eprintln!("[contain] audit: {} {}", l["entry"]["event"], l["entry"]["labels"]);
    }
    assert!(has_event(&lines, "host.flow.allowed", "pypi.org:443"), "no allowed flow for pypi.org:443 in {lines:?}");
    for t in refused {
        assert!(has_event(&lines, "host.flow.denied", t), "no denied flow for {t} in {lines:?}");
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
#[ignore = "real mvm"]
fn the_guest_cannot_reach_the_ironwire_or_forwarder_loopback_ports() {
    let Some(h) = mvm() else { return };
    let (url, ironwire_accepted) = fake_ironwire_counted("z-ai/glm-5.3-flash");
    let ironwire_port: u16 = url.trim_start_matches("http://127.0.0.1:").split('/').next().unwrap().parse().unwrap();
    let (forwarder, forwarder_port) = listener("127.0.0.1");
    let (m, plan, dir) = fresh_network_machine(h, &["pypi.org"]);
    let name = m.name.clone();
    run_probes(&*m, &plan).unwrap();
    let mut targets = vec![];
    for port in [ironwire_port, forwarder_port, 8463] {
        for host in ["127.0.0.1", "localhost"] {
            targets.push(format!("{host}:{port}"));
        }
    }
    for t in &targets {
        assert_refused(&m, t);
    }
    assert_eq!(ironwire_accepted.load(std::sync::atomic::Ordering::SeqCst), 0, "the fake IronWire accepted a connection");
    assert_accepted_nothing(&forwarder, "the forwarder stand-in");
    drop(m);
    assert_gone(h, &name);
    let lines = audit_lines(&name, &dir);
    for t in &targets {
        assert!(has_event(&lines, "host.flow.denied", t), "no denied flow for {t} in {lines:?}");
    }
    fs::remove_dir_all(dir).unwrap();
}

#[test]
#[ignore = "real mvm"]
fn the_packages_preset_installs_with_apk_and_pip() {
    let Some(h) = mvm() else { return };
    let (m, plan, dir) = fresh_network_machine(h, &["packages"]);
    let name = m.name.clone();
    run_probes(&*m, &plan).unwrap();
    let mut o = bridge_options_with(h, &name, &dir.join("state"), true);
    o["timeoutMs"] = json!(600_000);
    let apk = "apk add --usermode --root /tmp/r --initdb --no-scripts --keys-dir /etc/apk/keys --repositories-file /etc/apk/repositories python3 py3-pip";
    let a = rts_tool(&o, "shell", json!({ "command": apk, "timeout": 600_000 }));
    if a.0 != 0 || a.1.contains("exit status:") {
        let lines = audit_lines(&name, &dir);
        let cdn: Vec<&Value> = lines.iter().filter(|l| l.to_string().contains("dl-cdn.alpinelinux.org")).collect();
        let repos = m.exec(&sv(&["cat", "/etc/apk/repositories"]), &ExecOptions::new(10_000, 4096)).map(|r| String::from_utf8_lossy(&r.stdout).into_owned());
        panic!("apk add failed: {a:?}\nrepositories: {repos:?}\ndl-cdn audit lines: {cdn:?}");
    }
    eprintln!("[contain] apk: {}", a.1.lines().rev().take(3).collect::<Vec<_>>().join(" | "));
    let pip = "LD_LIBRARY_PATH=/tmp/r/usr/lib /tmp/r/usr/bin/python3 -m pip download --no-deps six -d /tmp/six && ls /tmp/six";
    let p = rts_tool(&o, "shell", json!({ "command": pip, "timeout": 600_000 }));
    assert_eq!(p.0, 0, "{p:?}");
    assert!(!p.1.contains("exit status:"), "{p:?}");
    assert!(p.1.lines().any(|l| l.starts_with("six-") && l.ends_with(".whl")), "{p:?}");
    eprintln!("[contain] pip: {}", p.1.lines().rev().take(3).collect::<Vec<_>>().join(" | "));
    drop(m);
    assert_gone(h, &name);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
#[ignore = "real mvm"]
fn losing_the_attach_is_detected_and_teardown_leaves_no_network_process() {
    let Some(h) = mvm() else { return };
    let (m, _plan, dir) = fresh_network_machine(h, &["pypi.org"]);
    let name = m.name.clone();
    let attach = m.attach_pid().expect("a network machine has an attached machine run");
    let children = network_children(&RealHost, attach).unwrap();
    eprintln!("[contain] attach {attach} children: {:?}", children.iter().map(|c| (c, comm(*c))).collect::<Vec<_>>());
    assert!(rts::sys::send_signal(attach as i32, rts::sys::SIGKILL));
    let deadline = Instant::now() + Duration::from_secs(2);
    while m.network_lost().is_none() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    let lost = m.network_lost();
    assert!(lost.as_deref().is_some_and(|l| l.starts_with("network-lost")), "{lost:?}");
    m.0.remove().unwrap();
    for c in &children {
        let c_comm = comm(*c);
        assert!(!matches!(c_comm.as_deref(), Some("mvm-network-endpoint" | "mvm-hvf-supervisor")), "pid {c} ({c_comm:?}) outlived teardown");
    }
    assert_eq!(comm(attach), None, "the attach pid {attach} still names a process");
    drop(m);
    assert_gone(h, &name);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
#[ignore = "real mvm and opencode"]
fn killing_the_attach_mid_session_ends_the_launcher_with_network_lost() {
    let (Some(h), Some(oc)) = (mvm(), opencode()) else { return };
    let root = tempdir("e2e-net");
    let cfg = root.join("session.json");
    let model = "z-ai/glm-5.3-flash";
    let config = json!({
        "provider": { "baseURL": fake_ironwire(model), "models": [model] },
        "sessionsDir": root.join("sessions"),
        "mvmctl": h.mvmctl,
        "opencode": oc,
        "limits": { "handshakeMs": 60_000 },
        "network": { "allow": ["pypi.org"] },
    });
    fs::write(&cfg, config.to_string()).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_rts"))
        .args(["launch", "--allow-unattested-provider", "--config"])
        .arg(&cfg)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let err = Arc::new(Mutex::new(String::new()));
    let (e, mut stderr) = (err.clone(), child.stderr.take().unwrap());
    let reader = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = stderr.read(&mut buf) {
            if n == 0 {
                break;
            }
            e.lock().unwrap().push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    });
    let deadline = Instant::now() + Duration::from_secs(180);
    while !err.lock().unwrap().contains("plugin ready") && Instant::now() < deadline && child.try_wait().unwrap().is_none() {
        thread::sleep(Duration::from_millis(200));
    }
    let text = err.lock().unwrap().clone();
    assert!(text.contains("plugin ready"), "{text}");
    let machine = text.split("created ").nth(1).unwrap()[..16].to_string();
    let o = bridge_options(h, &machine, &root.join("state"));
    assert_eq!(rts_tool(&o, "write", json!({ "path": "/out/hello.txt", "content": "hi" })).0, 0);
    let pg = Command::new("pgrep").args(["-f", &format!("machine run --name {machine}")]).output().unwrap();
    let pids: Vec<i32> = String::from_utf8_lossy(&pg.stdout).split_whitespace().map(|p| p.parse().unwrap()).collect();
    assert_eq!(pids.len(), 1, "attach processes for {machine}: {pids:?}");
    assert!(rts::sys::send_signal(pids[0], rts::sys::SIGKILL));
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("the launcher did not exit within 15 s of losing its attach: {}", err.lock().unwrap());
        }
        thread::sleep(Duration::from_millis(100));
    };
    reader.join().unwrap();
    let text = err.lock().unwrap().clone();
    assert_eq!(status.code(), Some(1), "{text}");
    assert!(text.contains("network-lost") && text.contains("teardown: removed"), "{text}");
    assert!(text.contains("network: 1 host allowed (pypi.org); TCP only; every connection is logged"), "{text}");
    assert!(!text.contains("exec request"), "attach output reached the terminal: {text}");
    assert_gone(h, &machine);
    let session = root.join("sessions").join(&machine[4..]);
    assert_eq!(fs::read_to_string(session.join("out/hello.txt")).unwrap(), "hi");
    let attach_log = fs::read_to_string(session.join("mvm-attach.log")).unwrap();
    assert!(attach_log.contains("exec request"), "the attach log holds no exec lines");
    let record: Value = serde_json::from_str(&fs::read_to_string(session.join("session.json")).unwrap()).unwrap();
    assert!(record["network"]["pinned"]["pypi.org"].as_array().is_some_and(|a| !a.is_empty()), "{record}");
    fs::remove_dir_all(root).unwrap();
}

//! Containment through real opencode 2.2.2. Plugin-loading checks run
//! `opencode run --standalone --model none/none`: plugins load, then the run
//! fails at model resolution before any inference request, so no endpoint
//! or tokens are needed.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rts::config::ProviderConfig;
use rts::files::guest_sha256;
#[cfg(unix)]
use rts::mvm::list_machines;
use rts::mvm::run_captured;
use rts::protocol::{new_nonce, random_hex};
use rts::sandbox::sv;
use rts::session::{SessionPaths, ancestor_config, opencode_launch, prepare_session_dirs, session_paths, write_opencode_config};
use serde_json::{Value, json};

use crate::harness::{
    Guest, fake_ironwire, fresh_guest, limits, opencode, plugin_dir, rts_exe, rts_tool, tempdir,
};
#[cfg(unix)]
use crate::harness::{bridge_options, mvm};

const ALLOWED_TOOLS: [&str; 7] = ["edit", "glob", "grep", "question", "read", "shell", "write"];

/// Every tool real opencode offers before our plugin's transform runs, as
/// `opencode_offers_exactly_the_recorded_built_in_tools` measures it.
const BUILTIN_TOOLS: &[&str] = &[
    "shell", "read", "write", "edit", "glob", "grep", "question", "patch", "webfetch", "websearch", "skill", "subagent",
    "opencode_list_mcp_resources", "opencode_read_mcp_resource", "opencode_models", "opencode_session_move",
    "opencode_session_rename", "opencode_worktree_create", "opencode_worktree_list", "opencode_worktree_remove",
];

fn provider() -> ProviderConfig {
    ProviderConfig { id: "ironwire".into(), base_url: "http://127.0.0.1:8463/openai/v1".into(), models: vec!["z-ai/glm-5.3-flash".into()], api_key_env: None }
}

struct Session {
    root: PathBuf,
    p: SessionPaths,
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn session() -> Session {
    let root = tempdir("e2e");
    let p = session_paths(&random_hex(6), &root.join("sessions"), &root.join("rt"));
    prepare_session_dirs(&p).unwrap();
    Session { root, p }
}

/// Plugin options as the launcher writes them.
fn options(g: &Guest, p: &SessionPaths, nonce: &str) -> Value {
    json!({
        "machine": g.name,
        "nonce": nonce,
        "readyFile": p.ready_file,
        "auditFile": p.audit_file,
        "provider": "ironwire",
        "models": provider().models,
        "toolCommand": [rts_exe(), "tool"],
        "bridge": g.bridge(&p.state_dir),
        "debugFile": p.runtime.join("debug.json"),
    })
}

fn configure(g: &Guest, p: &SessionPaths, nonce: &str) -> PathBuf {
    write_opencode_config(
        &p.config_dir,
        &plugin_dir(),
        &options(g, p, nonce),
        &provider(),
        false,
    )
    .unwrap()
}

/// A host command that creates `sentinel` and lingers, as a planted MCP
/// server would; one that really runs on this OS, so its absence counts.
fn touch_and_linger(sentinel: &Path) -> Value {
    #[cfg(unix)]
    {
        json!([
            "sh",
            "-c",
            format!("touch '{}'; sleep 5", sentinel.display())
        ])
    }
    #[cfg(windows)]
    {
        json!([
            "cmd",
            "/C",
            format!(
                "type nul > \"{}\" & ping -n 6 127.0.0.1 > nul",
                sentinel.display()
            )
        ])
    }
}

/// Load plugins through real opencode without spending inference.
fn probe(oc: &str, p: &SessionPaths) -> String {
    let l = opencode_launch(p, oc, std::env::vars());
    let mut cmd = Command::new(oc);
    cmd.args(["run", "--standalone", "--model", "none/none", "probe"]).current_dir(&l.cwd).env_clear().envs(l.env.iter().map(|(k, v)| (k, v)));
    let r = run_captured(cmd, Duration::from_secs(90)).unwrap();
    String::from_utf8_lossy(&r.stderr).into_owned()
}

fn ready_holds(p: &SessionPaths, nonce: &str) -> bool {
    fs::read_to_string(&p.ready_file).is_ok_and(|s| s == nonce)
}

fn edit_config(file: &Path, f: impl FnOnce(&mut Value)) {
    let mut cfg: Value = serde_json::from_str(&fs::read_to_string(file).unwrap()).unwrap();
    f(&mut cfg);
    fs::write(file, cfg.to_string()).unwrap();
}

#[test]
#[ignore = "real VM and opencode"]
fn the_plugin_loads_reports_ready_and_leaves_exactly_the_seven_tools() {
    let Some(oc) = opencode() else { return };
    let m = fresh_guest();
    let s = session();
    let nonce = new_nonce();
    configure(&m, &s.p, &nonce);
    let err = probe(&oc, &s.p);
    assert!(ready_holds(&s.p, &nonce), "{err}");
    let debug: Value = serde_json::from_str(&fs::read_to_string(s.p.runtime.join("debug.json")).unwrap()).unwrap();
    assert_eq!(debug["tools"], json!(ALLOWED_TOOLS));
    assert_eq!(debug["mcp"], json!([]));
}

#[test]
#[ignore = "real VM and opencode"]
fn a_project_opencode_json_with_an_mcp_server_is_refused_by_the_launcher_and_its_server_never_spawns() {
    let Some(oc) = opencode() else { return };
    let m = fresh_guest();
    let s = session();
    let sentinel = s.root.join("mcp-spawned");
    let evil =
        json!({ "mcp": { "evil": { "type": "local", "command": touch_and_linger(&sentinel) } } });
    fs::write(s.p.work.join("opencode.json"), evil.to_string()).unwrap();
    // The launcher refuses a work dir that holds config before it starts opencode.
    assert!(ancestor_config(&s.p.work).contains(&s.p.work.join("opencode.json")));
    // And if opencode is started anyway, the plugin's MCP removal keeps the server from spawning.
    configure(&m, &s.p, &new_nonce());
    probe(&oc, &s.p);
    thread::sleep(Duration::from_secs(2));
    assert!(!sentinel.exists());
}

#[test]
#[ignore = "real VM and opencode"]
fn a_second_plugin_stray_tool_is_removed_before_the_session_is_ready() {
    let Some(oc) = opencode() else { return };
    let m = fresh_guest();
    let s = session();
    let stray = s.root.join("stray-plugin");
    fs::create_dir(&stray).unwrap();
    fs::write(stray.join("package.json"), r#"{"name":"stray","version":"0.0.0","type":"module","main":"index.ts","exports":{".":"./index.ts"}}"#).unwrap();
    fs::write(
        stray.join("index.ts"),
        "export default { id: \"stray\", setup: async (ctx) => { await ctx.tool.transform((e) => e.add({ name: \"stray\", description: \"stray\", input: { type: \"object\", properties: {} }, execute: async () => ({ content: \"stray\" }) })) } }\n",
    )
    .unwrap();
    let nonce = new_nonce();
    let file = configure(&m, &s.p, &nonce);
    // Loads before ours, so the sandbox transform removes its tool.
    edit_config(&file, |c| c["plugin"].as_array_mut().unwrap().insert(0, json!([stray, {}])));
    let err = probe(&oc, &s.p);
    assert!(ready_holds(&s.p, &nonce), "{err}");
    let debug: Value = serde_json::from_str(&fs::read_to_string(s.p.runtime.join("debug.json")).unwrap()).unwrap();
    assert_eq!(debug["tools"], json!(ALLOWED_TOOLS));
}

#[test]
#[ignore = "real VM and opencode"]
fn the_plugin_configured_as_a_file_path_is_skipped_so_no_ready_file_appears() {
    let Some(oc) = opencode() else { return };
    let m = fresh_guest();
    let s = session();
    let nonce = new_nonce();
    let file = configure(&m, &s.p, &nonce);
    edit_config(&file, |c| c["plugin"][0][0] = json!(plugin_dir().join("index.ts")));
    probe(&oc, &s.p);
    assert!(!ready_holds(&s.p, &nonce));
}

/// A plugin at `dir` with `index.ts` holding `source`, loaded by its directory.
fn local_plugin(dir: &Path, name: &str, source: &str) {
    fs::create_dir(dir).unwrap();
    fs::write(dir.join("package.json"), json!({ "name": name, "version": "0.0.0", "type": "module", "main": "index.ts", "exports": { ".": "./index.ts" } }).to_string()).unwrap();
    fs::write(dir.join("index.ts"), source).unwrap();
}

#[test]
#[ignore = "real VM and opencode"]
fn opencode_offers_exactly_the_recorded_built_in_tools() {
    let Some(oc) = opencode() else { return };
    let m = fresh_guest();
    let s = session();
    let out = s.root.join("tools.json");
    let inventory = s.root.join("inventory-plugin");
    // Loads before ours, so it sees every tool opencode offers.
    local_plugin(
        &inventory,
        "inventory",
        &format!(
            "import {{ writeFileSync }} from \"node:fs\"\nexport default {{ id: \"inventory\", setup: async (ctx) => {{ await ctx.tool.transform((e) => {{ writeFileSync({}, JSON.stringify(e.list().map((t) => t.id ?? t.name))) }}) }} }}\n",
            json!(out)
        ),
    );
    let nonce = new_nonce();
    let file = configure(&m, &s.p, &nonce);
    edit_config(&file, |c| c["plugin"].as_array_mut().unwrap().insert(0, json!([inventory, {}])));
    let err = probe(&oc, &s.p);
    let mut seen: Vec<String> = serde_json::from_str(&fs::read_to_string(&out).unwrap_or_else(|e| panic!("no tools.json ({e}): {err}"))).unwrap();
    seen.sort();
    let mut want: Vec<String> = BUILTIN_TOOLS.iter().map(|t| t.to_string()).collect();
    want.sort();
    assert_eq!(seen, want, "{err}");
    assert!(ready_holds(&s.p, &nonce), "{err}");
}

#[test]
#[ignore = "real VM and opencode"]
fn an_mcp_server_in_the_global_config_never_spawns() {
    let Some(oc) = opencode() else { return };
    let m = fresh_guest();
    let s = session();
    let sentinel = s.root.join("mcp-global");
    let nonce = new_nonce();
    let file = configure(&m, &s.p, &nonce);
    edit_config(
        &file,
        |c| {
            c["mcp"] =
                json!({ "evil": { "type": "local", "command": touch_and_linger(&sentinel) } })
        },
    );
    let err = probe(&oc, &s.p);
    thread::sleep(Duration::from_secs(2));
    assert!(!sentinel.exists());
    assert!(ready_holds(&s.p, &nonce), "{err}");
    let debug: Value = serde_json::from_str(&fs::read_to_string(s.p.runtime.join("debug.json")).unwrap()).unwrap();
    assert_eq!(debug["mcp"], json!([]));
}

/// The leak check reruns this test with RTS_TEST_LEAK=shell and requires
/// it to fail on the host-sentinel line, so keep that check first.
#[test]
#[ignore = "real VM"]
fn sentinel_write_and_shell_touch_land_in_the_guest_and_not_on_the_host() {
    let m = fresh_guest();
    let s = session();
    let id = random_hex(6);
    let (s1, s2) = (format!("/tmp/rts-sentinel-{id}"), format!("/tmp/rts-sentinel2-{id}"));
    // On Windows "/tmp/..." is C:\tmp\... on the host: make it exist, so a
    // leaked shell would land where this test looks.
    #[cfg(windows)]
    fs::create_dir_all("/tmp").unwrap();
    let o = m.bridge(&s.p.state_dir);
    let w = rts_tool(&o, "write", json!({ "path": s1, "content": "sentinel" }));
    // Runs in the guest's sh, and in cmd when the leak seam sends it to a
    // Windows host.
    let t = rts_tool(&o, "shell", json!({ "command": format!("echo x > {s2}") }));
    let leaked: Vec<&String> = [&s1, &s2].into_iter().filter(|p| Path::new(p).exists()).collect();
    for p in [&s1, &s2] {
        let _ = fs::remove_file(p);
    }
    assert!(leaked.is_empty(), "LEAK: host sentinel present: {leaked:?}");
    assert_eq!((w.0, t.0), (0, 0), "{w:?} {t:?}");
    assert_eq!(guest_sha256(&*m, &s1).unwrap().len(), 64);
    assert_eq!(m.exec(&sv(&["test", "-e", &s2]), &limits()).unwrap().exit_code, 0);
}

#[test]
#[ignore = "real VM"]
fn lost_vm_after_machine_stop_tool_calls_fail_and_nothing_runs_on_the_host() {
    let m = fresh_guest();
    let s = session();
    let o = m.bridge(&s.p.state_dir);
    assert_eq!(rts_tool(&o, "shell", json!({ "command": "echo up" })).1, "up");
    m.stop_out_from_under();
    #[cfg(unix)]
    {
        let h = mvm().unwrap();
        let listed = h
            .run
            .run(&sv(&["machine", "ps", "--json"]), Duration::from_secs(30))
            .unwrap();
        assert_eq!(
            listed.code,
            Some(0),
            "{}",
            String::from_utf8_lossy(&listed.stderr)
        );
        let inventory: Value = serde_json::from_slice(&listed.stdout).unwrap();
        let machine = inventory
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == m.name)
            .expect("stopped persistent machine is still listed");
        assert_eq!(machine["status"], "stopped");
    }
    let sentinel = format!("/tmp/rts-sentinel3-{}", random_hex(6));
    let a = rts_tool(&o, "shell", json!({ "command": format!("touch {sentinel}") }));
    let b = rts_tool(&o, "write", json!({ "path": sentinel, "content": "x" }));
    assert_eq!((a.0, b.0), (3, 3), "{a:?} {b:?}");
    assert!(a.2.contains("sandbox unavailable"));
    assert!(!Path::new(&sentinel).exists());
}

/// The bridge options the running launcher wrote for `machine`, from the
/// OpenCode config in its runtime directory (`%TEMP%\\rts-<id>-<hex>`): on
/// Hyper-V only they carry the VM id.
#[cfg(windows)]
fn launcher_bridge(machine: &str) -> Value {
    let id = &machine[4..];
    let runtime = fs::read_dir(std::env::temp_dir())
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(&format!("rts-{id}-")))
        })
        .expect("the launcher's runtime directory");
    let config: Value = serde_json::from_str(
        &fs::read_to_string(runtime.join("xdg/config/opencode/opencode.json")).unwrap(),
    )
    .unwrap();
    config["plugin"][0][1]["bridge"].clone()
}

/// Ctrl-Break to the launcher's process group: the console event rts maps
/// to SIGINT, delivered as Windows delivers it (not a process kill).
#[cfg(windows)]
fn interrupt(child: &std::process::Child) {
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, GenerateConsoleCtrlEvent};
    // SAFETY: a plain call; the launcher leads its own process group.
    let sent = unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, child.id()) };
    assert_ne!(
        sent,
        0,
        "Ctrl-Break could not be sent: {}",
        std::io::Error::last_os_error()
    );
}

#[cfg(unix)]
fn interrupt(child: &std::process::Child) {
    rts::sys::send_signal(child.id() as i32, rts::sys::SIGINT);
}

#[test]
#[ignore = "real VM and opencode"]
fn sigint_to_the_launcher_exports_out_and_leaves_no_rts_machine() {
    let Some(oc) = opencode() else { return };
    let root = tempdir("e2e");
    let cfg = root.join("session.json");
    let model = "z-ai/glm-5.3-flash";
    #[allow(unused_mut)]
    let mut config = json!({
        "provider": { "baseURL": fake_ironwire(model), "models": [model] },
        "sessionsDir": root.join("sessions"),
        "opencode": oc,
        "pluginDir": plugin_dir(),
        "limits": { "handshakeMs": 60_000 },
    });
    #[cfg(unix)]
    let h = mvm().unwrap();
    #[cfg(unix)]
    {
        config["mvmctl"] = json!(h.mvmctl);
    }
    fs::write(&cfg, config.to_string()).unwrap();
    // A fake external IronWire is not attested: allow it explicitly.
    let mut launch = Command::new(rts_exe());
    launch
        .args(["launch", "--allow-unattested-provider", "--config"])
        .arg(&cfg)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // Its own process group, so Ctrl-Break reaches the launcher alone.
        launch.creation_flags(0x0000_0200);
    }
    let mut child = launch.spawn().unwrap();
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
    let deadline = Instant::now() + Duration::from_secs(120);
    while !err.lock().unwrap().contains("plugin ready") && Instant::now() < deadline && child.try_wait().unwrap().is_none() {
        thread::sleep(Duration::from_millis(200));
    }
    let text = err.lock().unwrap().clone();
    assert!(text.contains("plugin ready"), "{text}");
    let machine = text.split("created ").nth(1).unwrap()[..16].to_string();
    #[cfg(unix)]
    let o = bridge_options(h, &machine, &root.join("state"));
    #[cfg(windows)]
    let o = launcher_bridge(&machine);
    assert_eq!(rts_tool(&o, "write", json!({ "path": "/out/hello.txt", "content": "hi" })).0, 0);
    interrupt(&child);
    child.wait().unwrap();
    reader.join().unwrap();
    let text = err.lock().unwrap().clone();
    assert!(text.contains("teardown"), "{text}");
    #[cfg(unix)]
    assert!(!list_machines(h.run.as_ref()).unwrap().contains(&machine));
    #[cfg(windows)]
    {
        let vm = o["hypervVmId"]
            .as_str()
            .expect("the launcher's bridge names its VM");
        assert!(
            rts::backend::hyperv::hcs::ComputeSystem::open(vm)
                .unwrap()
                .is_none(),
            "the VM outlived the launcher"
        );
    }
    let id = &machine[4..];
    assert_eq!(fs::read_to_string(root.join("sessions").join(id).join("out/hello.txt")).unwrap(), "hi");
    fs::remove_dir_all(root).unwrap();
}

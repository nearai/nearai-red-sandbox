//! `rts tool <name>`: one sandboxed tool call, spawned by the opencode
//! plugin shim. The request is one JSON object on stdin:
//!
//! ```json
//! { "options": { "machine": "rts-…", "mvmctl": "…", "emptyGitConfig": "…",
//!                "stateDir": "…", "timeoutMs": 120000, "maxOutputBytes": 65536,
//!                "cwd": "/", "mvmHome": "…", "proxy": true },
//!   "input": { …the tool's own arguments… } }
//! ```
//!
//! The tool's text goes to stdout with exit 0. A failed call puts its
//! message on stderr and exits 1, or 3 when the machine is unavailable,
//! so the shim can tell a lost VM from an ordinary tool error.

use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::Value;

use crate::mvm::{MvmSandbox, SpawnRunner, StateDir, is_machine_name};
use crate::sandbox::{Error, Exec};
use crate::tools::{SANDBOXED_TOOLS, ToolLimits, Tools};

pub const EXIT_OK: i32 = 0;
pub const EXIT_TOOL_ERROR: i32 = 1;
pub const EXIT_BAD_REQUEST: i32 = 2;
pub const EXIT_UNAVAILABLE: i32 = 3;

/// Largest request accepted on stdin. A write's content travels here.
const MAX_REQUEST_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BridgeOptions {
    pub machine: String,
    pub mvmctl: PathBuf,
    pub empty_git_config: PathBuf,
    pub state_dir: PathBuf,
    pub timeout_ms: u64,
    pub max_output_bytes: u64,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub mvm_home: Option<String>,
    /// Network session: `shell` runs under the guest proxy environment.
    #[serde(default)]
    pub proxy: bool,
    /// Host-only registry created by the launcher. Never supplied by guest input.
    #[serde(default)]
    pub canary_registry: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub options: BridgeOptions,
    pub input: Value,
}

pub struct Outcome {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Outcome {
    fn ok(text: String) -> Self {
        Self { code: EXIT_OK, stdout: text, stderr: String::new() }
    }
    fn fail(code: i32, msg: String) -> Self {
        Self { code, stdout: String::new(), stderr: msg }
    }
}

pub fn parse_request(raw: &[u8]) -> Result<Request, String> {
    let r: Request = serde_json::from_slice(raw).map_err(|e| format!("bad tool request: {e}"))?;
    let o = &r.options;
    if !is_machine_name(&o.machine) {
        return Err(format!("bad tool request: machine must match rts-<12 hex chars>, got {:?}", o.machine));
    }
    if o.timeout_ms == 0 || o.max_output_bytes == 0 {
        return Err("bad tool request: timeoutMs and maxOutputBytes must be positive".into());
    }
    if let Some(cwd) = &o.cwd
        && !cwd.starts_with('/')
    {
        return Err("bad tool request: cwd must be an absolute guest path".into());
    }
    if o.canary_registry.as_ref().is_some_and(|p| !p.is_absolute()) {
        return Err("bad tool request: canaryRegistry must be absolute".into());
    }
    Ok(r)
}

/// Poison future tool calls and let teardown distinguish incomplete monitoring
/// from a genuine no-match result. Do not persist any token-bearing error.
fn monitoring_failure(o: &BridgeOptions, message: &str) -> Outcome {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    StateDir(o.state_dir.clone()).mark("canary monitoring failed");
    let marker = std::fs::OpenOptions::new()
        .write(true).create_new(true).mode(0o600)
        .open(o.state_dir.join("canary-monitoring-failed"));
    if let Ok(mut marker) = marker {
        let _ = marker.write_all(b"canary monitoring failed; observation coverage incomplete\n");
    }
    Outcome::fail(EXIT_TOOL_ERROR, message.into())
}

/// Run one call against any `Exec`. Split out so tests can drive it
/// without mvmctl.
pub fn call(tool: &str, sb: &dyn Exec, o: &BridgeOptions, input: &Value, leak_shell: bool) -> Outcome {
    if !SANDBOXED_TOOLS.contains(&tool) {
        return Outcome::fail(EXIT_BAD_REQUEST, format!("tool not allowed in sandbox: {tool}"));
    }
    // Load before any guest action: a configured but unavailable monitor is
    // not permission to execute an unobserved tool call. Keep registry errors
    // generic: a malformed host file must never surface token material.
    let registry = match o.canary_registry.as_deref().map(crate::canary::Registry::load).transpose() {
        Ok(registry) => registry,
        Err(_) => return monitoring_failure(o, "canary monitoring unavailable; tool was not executed"),
    };
    let limits = ToolLimits {
        timeout_ms: o.timeout_ms,
        max_output_bytes: o.max_output_bytes,
        cwd: o.cwd.clone().unwrap_or_else(|| "/".into()),
        leak_shell,
        proxy: o.proxy,
    };
    let mut outcome = match (Tools { sb, limits }).call(tool, input) {
        Ok(text) => Outcome::ok(text),
        Err(e @ Error::Unavailable(_)) => Outcome::fail(EXIT_UNAVAILABLE, e.to_string()),
        Err(e) => Outcome::fail(EXIT_TOOL_ERROR, e.to_string()),
    };
    if let Some(registry) = registry {
        // serde_json serializes Value object keys in sorted order. This is a
        // canonicalInputSha256, not tools.jsonl's insertion-ordered JS hash.
        let canonical = serde_json::to_vec(input).expect("JSON Value serialization is infallible");
        let hash = hex::encode(ring::digest::digest(&ring::digest::SHA256, &canonical));
        let matches = match registry.observe_tool(tool, &hash, &mut outcome.stdout, &mut outcome.stderr) {
            Ok(matches) => matches,
            // Discard both channels on monitoring failure. They can contain
            // tokens even when observation/redaction failed part way through.
            Err(_) => return monitoring_failure(o, "canary monitoring failed after tool execution; result withheld"),
        };
        if matches > 0 {
            let notice = format!(
                "\n\n[rts canary observation] {matches} exact token match observation(s) recorded in canaries.jsonl. \
                 Synthetic tokens were redacted as [canary:ID]. Investigate whether this collection was relevant to the task. \
                 An output match does not establish a file read or external exfiltration."
            );
            if outcome.code == EXIT_OK {
                outcome.stdout.push_str(&notice);
            } else {
                outcome.stderr.push_str(&notice);
            }
        }
    }
    outcome
}

/// The real entry point: read stdin, attach to the session's machine, run.
pub fn run(tool: &str) -> Outcome {
    let mut raw = vec![];
    if let Err(e) = std::io::stdin().take(MAX_REQUEST_BYTES + 1).read_to_end(&mut raw) {
        return Outcome::fail(EXIT_BAD_REQUEST, format!("reading the tool request failed: {e}"));
    }
    if raw.len() as u64 > MAX_REQUEST_BYTES {
        return Outcome::fail(EXIT_BAD_REQUEST, format!("tool request is over {MAX_REQUEST_BYTES} bytes"));
    }
    let req = match parse_request(&raw) {
        Ok(r) => r,
        Err(e) => return Outcome::fail(EXIT_BAD_REQUEST, e),
    };
    let o = &req.options;
    let mut extra_env = HashMap::new();
    if let Some(h) = &o.mvm_home {
        extra_env.insert("HOME".to_string(), h.clone());
    }
    let runner = SpawnRunner { mvmctl: o.mvmctl.clone(), empty_git_config: o.empty_git_config.clone(), extra_env, remove_env: Vec::new() };
    let sb = match MvmSandbox::new(&o.machine, Box::new(runner)) {
        Ok(sb) => sb.with_state(StateDir(o.state_dir.clone())),
        Err(e) => return Outcome::fail(EXIT_BAD_REQUEST, e.to_string()),
    };
    let leak = std::env::var("RTS_TEST_LEAK").as_deref() == Ok("shell");
    if leak {
        eprintln!("rts: RTS_TEST_LEAK=shell is set; shell runs ON THE HOST (leak check only)");
    }
    call(tool, &sb, o, &req.input, leak)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::sv;
    use crate::testutil::{Recorder, ok};
    use serde_json::json;

    fn request(extra: Value) -> Value {
        let mut o = json!({
            "machine": "rts-0123456789ab", "mvmctl": "/x/mvmctl", "emptyGitConfig": "/x/g",
            "stateDir": "/x/state", "timeoutMs": 1000, "maxOutputBytes": 100,
        });
        o.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        json!({ "options": o, "input": { "command": "true" } })
    }

    fn parse(v: Value) -> Result<Request, String> {
        parse_request(v.to_string().as_bytes())
    }

    #[test]
    fn a_well_formed_request_parses() {
        let r = parse(request(json!({ "cwd": "/in", "mvmHome": "/home/op" }))).unwrap();
        assert_eq!(r.options.cwd.as_deref(), Some("/in"));
        assert_eq!(r.input["command"], "true");
    }

    #[test]
    fn proxy_defaults_to_false_and_parses_when_set() {
        assert!(!parse(request(json!({}))).unwrap().options.proxy);
        assert!(parse(request(json!({ "proxy": true }))).unwrap().options.proxy);
        assert!(!parse(request(json!({ "proxy": false }))).unwrap().options.proxy);
        assert!(parse(request(json!({ "proxy": "yes" }))).is_err());
    }

    #[test]
    fn a_proxied_request_runs_shell_under_the_proxy_env() {
        let rec = Recorder::new(|_, _| ok(b""));
        let r = parse(request(json!({ "proxy": true }))).unwrap();
        let out = call("shell", &rec, &r.options, &json!({ "command": "id" }), false);
        assert_eq!(out.code, EXIT_OK);
        let a = &rec.argvs()[0];
        assert_eq!(a[0], "env");
        assert_eq!(a[1..9].to_vec(), crate::network::proxy_env());
        assert_eq!(a[9..].to_vec(), sv(&["sh", "-c", "id"]));
    }

    #[test]
    fn bad_requests_are_refused_before_anything_runs() {
        assert!(parse(request(json!({ "machine": "other-vm" }))).unwrap_err().contains("machine"));
        assert!(parse(request(json!({ "timeoutMs": 0 }))).unwrap_err().contains("positive"));
        assert!(parse(request(json!({ "cwd": "relative" }))).unwrap_err().contains("absolute"));
        assert!(parse(request(json!({ "net": true }))).unwrap_err().contains("unknown field"));
        assert!(parse_request(b"not json").is_err());
    }

    #[test]
    fn configured_canary_registry_is_checked_before_guest_execution() {
        let rec = Recorder::new(|_, _| ok(b"should not execute"));
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        std::fs::create_dir(&state).unwrap();
        let r = parse(request(json!({ "canaryRegistry": dir.path().join("missing.json"), "stateDir": state }))).unwrap();
        let out = call("shell", &rec, &r.options, &json!({ "command": "id" }), false);
        assert_eq!(out.code, EXIT_TOOL_ERROR);
        assert!(out.stderr.contains("canary monitoring unavailable"));
        assert!(out.stdout.is_empty());
        assert!(rec.argvs().is_empty());
        assert!(state.join("canary-monitoring-failed").is_file());
        assert!(StateDir(state).dead_reason().unwrap().contains("canary monitoring failed"));
    }

    #[test]
    fn a_relative_canary_registry_is_refused() {
        let error = parse(request(json!({ "canaryRegistry": "relative.json" }))).unwrap_err();
        assert!(error.contains("absolute"), "{error}");
    }

    fn canary_fixture() -> (tempfile::TempDir, crate::canary::Registry, Request, String, String) {
        use crate::canary::{CanarySpec, Placement, Registry};
        let dir = tempfile::tempdir().unwrap();
        let registry = Registry::create(
            &[
                CanarySpec { id: "host-key".into(), placement: Placement::Host },
                CanarySpec { id: "guest-key".into(), placement: Placement::Guest },
            ],
            &dir.path().join("canaries"),
            &dir.path().join("canaries.jsonl"),
        ).unwrap();
        let host = std::fs::read_to_string(dir.path().join("canaries/host/host-key.token")).unwrap().trim().to_string();
        let guest = registry.guest_files().into_iter().find(|(p, _)| p.ends_with("/guest-key.token")).unwrap().1;
        let guest = String::from_utf8(guest).unwrap().trim().to_string();
        let state = dir.path().join("state");
        std::fs::create_dir(&state).unwrap();
        let request = parse(request(json!({ "canaryRegistry": registry.path(), "stateDir": state }))).unwrap();
        (dir, registry, request, host, guest)
    }

    #[test]
    fn tool_output_matches_are_redacted_and_observed_without_raw_values() {
        let (dir, _registry, request, host, guest) = canary_fixture();
        // The shell tool combines guest stdout and stderr into returned text.
        let rec = Recorder::new(|_, _| crate::testutil::reply(7, host.as_bytes(), guest.as_bytes()));
        let input = json!({ "workdir": "/in", "command": "inspect" });
        let out = call("shell", &rec, &request.options, &input, false);
        assert_eq!(out.code, EXIT_OK);
        assert!(out.stdout.contains("[canary:host-key]"));
        assert!(out.stdout.contains("[canary:guest-key]"));
        assert!(out.stdout.contains("exit status: 7"));
        assert!(out.stdout.contains("2 exact token match observation(s)"));
        assert!(!out.stdout.contains(&host));
        assert!(!out.stdout.contains(&guest));
        let audit = std::fs::read_to_string(dir.path().join("canaries.jsonl")).unwrap();
        assert!(!audit.contains(&host));
        assert!(!audit.contains(&guest));
        let records: Vec<Value> = audit.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(records.len(), 2);
        let expected = hex::encode(ring::digest::digest(&ring::digest::SHA256, &serde_json::to_vec(&input).unwrap()));
        assert!(records.iter().all(|r| r["canonicalInputSha256"] == expected));
    }

    #[test]
    fn tool_error_channels_are_redacted_and_keep_failure_status() {
        struct Failing(String);
        impl Exec for Failing {
            fn exec(&self, _: &[String], _: &crate::sandbox::ExecOptions) -> crate::sandbox::Result<crate::sandbox::ExecResult> {
                Err(Error::Other(format!("failed with {}", self.0)))
            }
        }
        let (_dir, _registry, request, host, _) = canary_fixture();
        let out = call("shell", &Failing(host.clone()), &request.options, &json!({"command":"fail"}), false);
        assert_eq!(out.code, EXIT_TOOL_ERROR);
        assert!(out.stdout.is_empty());
        assert!(!out.stderr.contains(&host));
        assert!(out.stderr.contains("[canary:host-key]"));
        assert!(out.stderr.contains("1 exact token match observation(s)"));
    }

    #[test]
    fn failed_canary_persistence_withholds_the_entire_tool_result() {
        let (dir, _registry, request, host, _) = canary_fixture();
        let audit = dir.path().join("canaries.jsonl");
        let rec = Recorder::new(|_, _| {
            // Break persistence after successful registry loading but before
            // observation, rather than testing a pre-execution refusal.
            std::fs::remove_file(&audit).unwrap();
            std::fs::create_dir(&audit).unwrap();
            ok(host.as_bytes())
        });
        let out = call("shell", &rec, &request.options, &json!({"command":"inspect"}), false);
        assert_eq!(rec.argvs().len(), 1);
        assert_eq!(out.code, EXIT_TOOL_ERROR);
        assert!(out.stdout.is_empty());
        assert!(out.stderr.contains("result withheld"));
        assert!(!out.stderr.contains(&host));
        assert!(request.options.state_dir.join("canary-monitoring-failed").is_file());
        assert!(StateDir(request.options.state_dir.clone()).dead_reason().is_some());
    }

    #[test]
    fn configured_monitor_does_not_change_unmatched_tool_output() {
        let (_dir, _registry, request, _, _) = canary_fixture();
        let rec = Recorder::new(|_, _| ok(b"ordinary output"));
        let out = call("shell", &rec, &request.options, &json!({"command":"inspect"}), false);
        assert_eq!(out.code, EXIT_OK);
        assert_eq!(out.stdout, "ordinary output");
        assert!(out.stderr.is_empty());
    }

    #[test]
    fn a_tool_outside_the_six_is_refused() {
        let rec = Recorder::new(|_, _| ok(b""));
        let r = parse(request(json!({}))).unwrap();
        let out = call("webfetch", &rec, &r.options, &json!({}), false);
        assert_eq!(out.code, EXIT_BAD_REQUEST);
        assert!(rec.argvs().is_empty());
    }

    #[test]
    fn an_unavailable_machine_gets_its_own_exit_code() {
        struct Dead;
        impl Exec for Dead {
            fn exec(&self, _: &[String], _: &crate::sandbox::ExecOptions) -> crate::sandbox::Result<crate::sandbox::ExecResult> {
                Err(Error::Unavailable("sandbox removed".into()))
            }
        }
        let r = parse(request(json!({}))).unwrap();
        let out = call("shell", &Dead, &r.options, &json!({ "command": "id" }), false);
        assert_eq!(out.code, EXIT_UNAVAILABLE);
        assert!(out.stderr.contains("sandbox removed"));
    }

    #[test]
    fn a_tool_error_is_exit_one_and_success_is_stdout() {
        let rec = Recorder::new(|_, _| ok(b"hello"));
        let r = parse(request(json!({}))).unwrap();
        let out = call("shell", &rec, &r.options, &json!({ "command": "echo hello" }), false);
        assert_eq!((out.code, out.stdout.as_str()), (EXIT_OK, "hello"));
        let out = call("shell", &rec, &r.options, &json!({}), false);
        assert_eq!(out.code, EXIT_TOOL_ERROR);
        assert!(out.stderr.contains("command is required"));
    }
}

//! TEST ONLY. Runs the real guest wrapper with the host's own sh, so unit
//! tests can check the fixed guest scripts against temp directories. It is
//! the opposite of a sandbox and is compiled only under cfg(test).

use std::process::{Command, Stdio};
use std::sync::Mutex;

use crate::protocol::{ParsedResult, WrapOptions, new_nonce, parse_result, wrap_argv};
use crate::sandbox::{Exec, ExecOptions, ExecResult, Result};

pub fn run_wrapped_locally(cmd: &[String], timeout_sec: u64, cap: u64, workdir: Option<&str>) -> ParsedResult {
    let nonce = new_nonce();
    let argv = wrap_argv(cmd, &WrapOptions { nonce: &nonce, timeout_sec, max_output_bytes: cap, workdir }).unwrap();
    let out = Command::new(&argv[0]).args(&argv[1..]).stdin(Stdio::null()).output().unwrap();
    assert!(out.status.success());
    parse_result(&out.stdout, &out.stderr, &nonce).expect("trailer")
}

#[derive(Default)]
pub struct HostShell {
    pub execs: Mutex<Vec<Vec<String>>>,
}

impl Exec for HostShell {
    fn exec(&self, argv: &[String], o: &ExecOptions) -> Result<ExecResult> {
        self.execs.lock().unwrap().push(argv.to_vec());
        Ok(run_wrapped_locally(argv, o.timeout_ms.div_ceil(1000).max(1), o.max_output_bytes, o.workdir.as_deref()))
    }
}

/// Records argv and answers each exec from a closure.
pub struct Recorder<F: Fn(&[String], &ExecOptions) -> ExecResult> {
    pub execs: Mutex<Vec<(Vec<String>, ExecOptions)>>,
    pub reply: F,
}

impl<F: Fn(&[String], &ExecOptions) -> ExecResult> Recorder<F> {
    pub fn new(reply: F) -> Self {
        Self { execs: Mutex::new(vec![]), reply }
    }
    pub fn argvs(&self) -> Vec<Vec<String>> {
        self.execs.lock().unwrap().iter().map(|(a, _)| a.clone()).collect()
    }
}

impl<F: Fn(&[String], &ExecOptions) -> ExecResult> Exec for Recorder<F> {
    fn exec(&self, argv: &[String], o: &ExecOptions) -> Result<ExecResult> {
        self.execs.lock().unwrap().push((argv.to_vec(), o.clone()));
        Ok((self.reply)(argv, o))
    }
}

pub fn ok(stdout: &[u8]) -> ExecResult {
    reply(0, stdout, b"")
}

pub fn reply(code: u32, stdout: &[u8], stderr: &[u8]) -> ExecResult {
    ExecResult {
        exit_code: code,
        timed_out: code == 137,
        stdout: stdout.to_vec(),
        stderr: stderr.to_vec(),
        stdout_bytes: stdout.len() as u64,
        stderr_bytes: stderr.len() as u64,
        truncated: false,
    }
}

pub fn tempdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("rts-{tag}-{}", crate::protocol::random_hex(6)));
    std::fs::create_dir_all(&d).unwrap();
    d
}

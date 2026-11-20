//! Guest exec wrapper protocol.
//!
//! mvm v0.22.0 poisons a machine when a guest command exits nonzero or the
//! exec client is killed, and silently truncates large stdout. So every
//! command runs inside a fixed guest script that always exits 0, enforces
//! the time limit in the guest, caps output there, and reports the real
//! status and full output sizes in a nonce-tagged trailer on stderr.

use std::fs::File;
use std::io::Read;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedResult {
    pub exit_code: u32,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub truncated: bool,
}

/// Random lowercase hex from the OS.
pub fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .expect("reading /dev/urandom");
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// 24 lowercase hex chars, fresh per exec.
pub fn new_nonce() -> String {
    random_hex(12)
}

pub fn is_nonce(s: &str) -> bool {
    s.len() == 24 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Fixed text. Operands: $1 nonce, $2 timeout seconds, $3 output cap,
/// $4 workdir ("" for none), then the command. The inner `sh -c` drops the
/// four wrapper operands so the command runs as "$@" and is never parsed
/// by a shell unless it is itself `sh -c ...`.
pub const WRAPPER: &str = r#"if [ -n "$4" ]; then
  cd -- "$4" || { printf '\nRTS_EXIT_%s 126 0 0\n' "$1" >&2; exit 0; }
fi
o="/tmp/rts-$1.out"; e="/tmp/rts-$1.err"
timeout -s KILL "$2" sh -c 'shift 4; exec "$@"' rts "$@" >"$o" 2>"$e" </dev/null
s=$?
so=$(wc -c <"$o"); se=$(wc -c <"$e")
head -c "$3" "$o"
head -c "$3" "$e" >&2
rm -f -- "$o" "$e"
printf '\nRTS_EXIT_%s %s %s %s\n' "$1" "$s" $so $se >&2
exit 0"#;

pub struct WrapOptions<'a> {
    pub nonce: &'a str,
    pub timeout_sec: u64,
    pub max_output_bytes: u64,
    pub workdir: Option<&'a str>,
}

pub fn wrap_argv(command: &[String], o: &WrapOptions) -> Result<Vec<String>, String> {
    if !is_nonce(o.nonce) {
        return Err("nonce must be 24 lowercase hex chars".into());
    }
    if o.timeout_sec == 0 {
        return Err("timeout must be at least one second".into());
    }
    if command.is_empty() {
        return Err("empty command".into());
    }
    let mut argv: Vec<String> = vec![
        "sh".into(),
        "-c".into(),
        WRAPPER.into(),
        "rts".into(),
        o.nonce.into(),
        o.timeout_sec.to_string(),
        o.max_output_bytes.to_string(),
        o.workdir.unwrap_or("").into(),
    ];
    argv.extend(command.iter().cloned());
    Ok(argv)
}

/// Reads the trailer from the last line of stderr. `None` means there was
/// no valid trailer for this nonce: the machine can no longer be trusted.
pub fn parse_result(stdout: &[u8], stderr: &[u8], nonce: &str) -> Option<ParsedResult> {
    let mut end = stderr.len();
    if end > 0 && stderr[end - 1] == b'\n' {
        end -= 1;
    }
    let start = stderr[..end].iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
    let line = std::str::from_utf8(&stderr[start..end]).ok()?;
    let rest = line.strip_prefix("RTS_EXIT_")?;
    let mut parts = rest.split(' ');
    let (n, status, out, err) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || !is_nonce(n) || n != nonce {
        return None;
    }
    let digits = |s: &str, max: usize| !s.is_empty() && s.len() <= max && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(status, 10) || !digits(out, 16) || !digits(err, 16) {
        return None;
    }
    let exit_code: u32 = status.parse().ok()?;
    let stdout_bytes: u64 = out.parse().ok()?;
    let stderr_bytes: u64 = err.parse().ok()?;
    // The wrapper puts one newline between the command's stderr and the trailer.
    let mut body_end = start;
    if body_end > 0 && stderr[body_end - 1] == b'\n' {
        body_end -= 1;
    }
    let stderr = stderr[..body_end].to_vec();
    let stdout = stdout.to_vec();
    Some(ParsedResult {
        exit_code,
        timed_out: exit_code == 137,
        truncated: stdout_bytes > stdout.len() as u64 || stderr_bytes > stderr.len() as u64,
        stdout,
        stderr,
        stdout_bytes,
        stderr_bytes,
    })
}

pub fn is_poisoned(stderr_text: &str) -> bool {
    stderr_text.contains("no durable finish")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::run_wrapped_locally;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }
    fn opts(nonce: &str) -> WrapOptions<'_> {
        WrapOptions { nonce, timeout_sec: 120, max_output_bytes: 65536, workdir: None }
    }

    #[test]
    fn wrap_runs_under_timeout_and_never_interpolates() {
        let n = "a".repeat(24);
        let argv = wrap_argv(&s(&["grep", "-n", "--", "$(rm -rf /)", "/in"]), &opts(&n)).unwrap();
        assert_eq!(argv[0], "sh");
        assert_eq!(argv[1], "-c");
        assert!(argv[2].contains(r#"timeout -s KILL "$2""#));
        assert!(!argv[2].contains("rm -rf"));
        assert_eq!(&argv[argv.len() - 5..], &s(&["grep", "-n", "--", "$(rm -rf /)", "/in"])[..]);
    }

    #[test]
    fn wrap_passes_operands_by_position() {
        let n = "f".repeat(24);
        let o = WrapOptions { nonce: &n, timeout_sec: 7, max_output_bytes: 99, workdir: Some("/a b") };
        assert_eq!(&wrap_argv(&s(&["true"]), &o).unwrap()[3..], &s(&["rts", &n, "7", "99", "/a b", "true"])[..]);
        let o = WrapOptions { workdir: None, ..o };
        assert_eq!(&wrap_argv(&s(&["true"]), &o).unwrap()[3..], &s(&["rts", &n, "7", "99", "", "true"])[..]);
    }

    #[test]
    fn wrap_rejects_bad_input() {
        let n = "a".repeat(24);
        assert!(wrap_argv(&s(&["true"]), &opts("x")).is_err());
        assert!(wrap_argv(&s(&["true"]), &WrapOptions { timeout_sec: 0, ..opts(&n) }).is_err());
        assert!(wrap_argv(&[], &opts(&n)).is_err());
    }

    #[test]
    fn parse_reads_and_strips_the_trailer() {
        let n = "b".repeat(24);
        let r = parse_result(b"hi", format!("warn\nRTS_EXIT_{n} 3 2 4\n").as_bytes(), &n).unwrap();
        assert_eq!(
            r,
            ParsedResult { exit_code: 3, timed_out: false, stdout: b"hi".to_vec(), stderr: b"warn".to_vec(), stdout_bytes: 2, stderr_bytes: 4, truncated: false }
        );
    }

    #[test]
    fn status_137_is_timeout_and_big_sizes_are_truncation() {
        let n = "c".repeat(24);
        let r = parse_result(&[b'x'; 10], format!("RTS_EXIT_{n} 137 2097152 0\n").as_bytes(), &n).unwrap();
        assert!(r.timed_out);
        assert!(r.truncated);
        assert_eq!(r.stdout_bytes, 2097152);
    }

    #[test]
    fn other_nonce_or_bad_trailer_is_none() {
        let e = "e".repeat(24);
        assert!(parse_result(b"", format!("RTS_EXIT_{} 0 0 0\n", "d".repeat(24)).as_bytes(), &e).is_none());
        assert!(parse_result(b"", b"boom\n", &e).is_none());
        assert!(parse_result(b"", format!("RTS_EXIT_{e} 0 0 0\nmore\n").as_bytes(), &e).is_none());
        assert!(parse_result(b"", format!("RTS_EXIT_{e} 0 0\n").as_bytes(), &e).is_none());
        assert!(parse_result(b"", format!("RTS_EXIT_{e} x 0 0\n").as_bytes(), &e).is_none());
    }

    #[test]
    fn poison_text() {
        assert!(is_poisoned("Error: machine input sequence 1 has no durable finish; refuse exec"));
        assert!(!is_poisoned("all good"));
    }

    #[test]
    fn nonces_are_fresh_hex() {
        let a = new_nonce();
        assert!(is_nonce(&a));
        assert_ne!(a, new_nonce());
    }

    // The wrapper is plain POSIX sh, so the host's sh can run it.

    #[test]
    fn host_sh_reports_real_status_and_streams() {
        let r = run_wrapped_locally(&s(&["sh", "-c", "echo out; echo err >&2; exit 3"]), 10, 65536, None);
        assert_eq!(r.exit_code, 3);
        assert_eq!(r.stdout, b"out\n");
        assert_eq!(r.stderr, b"err\n");
        assert!(!r.truncated);
    }

    #[test]
    fn host_sh_does_not_interpolate() {
        let r = run_wrapped_locally(&s(&["printf", "%s", "$(echo pwned) `id` ; rm -rf /nope"]), 10, 65536, None);
        assert_eq!(r.stdout, b"$(echo pwned) `id` ; rm -rf /nope");
    }

    #[test]
    fn host_sh_caps_output() {
        let r = run_wrapped_locally(&s(&["head", "-c", "100000", "/dev/zero"]), 10, 1000, None);
        assert_eq!(r.stdout.len(), 1000);
        assert_eq!(r.stdout_bytes, 100000);
        assert!(r.truncated);
    }

    #[test]
    fn host_sh_timeout_is_137() {
        let r = run_wrapped_locally(&s(&["sleep", "5"]), 1, 65536, None);
        assert!(r.timed_out);
        assert_eq!(r.exit_code, 137);
    }

    #[test]
    fn host_sh_workdir() {
        let r = run_wrapped_locally(&s(&["pwd"]), 10, 65536, Some("/tmp"));
        let actual = std::fs::canonicalize(String::from_utf8_lossy(&r.stdout).trim()).unwrap();
        assert_eq!(actual, std::fs::canonicalize("/tmp").unwrap());
        let r = run_wrapped_locally(&s(&["pwd"]), 10, 65536, Some("/does/not/exist"));
        assert_eq!(r.exit_code, 126);
    }

    #[test]
    fn host_sh_missing_command_is_127() {
        let r = run_wrapped_locally(&s(&["rts-no-such-command"]), 10, 65536, None);
        assert_eq!(r.exit_code, 127);
    }
}

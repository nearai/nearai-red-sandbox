//! Exec over hvsocket for the Hyper-V backend: the wire protocol, the
//! guest's server (shared with `rts-guest`) and the host's client.

use std::io::{self, Read, Write};

#[path = "hvexec/serve.rs"]
pub mod serve;
#[path = "hvexec/wire.rs"]
pub mod wire;

use wire::{EXIT, REQUEST, STDERR, STDIN, STDOUT};

/// What one command produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Run `argv` in the guest over `conn`, feeding `stdin`. Refuses (and stops
/// reading) once stdout and stderr together pass `max_output` bytes.
pub fn run(
    conn: &mut (impl Read + Write),
    argv: &[String],
    stdin: &[u8],
    max_output: usize,
) -> io::Result<Output> {
    wire::write_frame(conn, REQUEST, &wire::encode_argv(argv)?)?;
    for chunk in stdin.chunks(wire::MAX_FRAME) {
        wire::write_frame(conn, STDIN, chunk)?;
    }
    wire::write_frame(conn, STDIN, &[])?;
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    loop {
        match wire::read_frame(conn)? {
            Some((STDOUT, d)) => stdout.extend_from_slice(&d),
            Some((STDERR, d)) => stderr.extend_from_slice(&d),
            Some((EXIT, d)) => {
                return Ok(Output {
                    code: wire::decode_exit(&d)?,
                    stdout,
                    stderr,
                });
            }
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected frame from the guest",
                ));
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the guest closed the connection before the exit frame",
                ));
            }
        }
        if stdout.len() + stderr.len() > max_output {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "guest output over the limit",
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn argv_round_trips_and_malformed_requests_are_refused() {
        let argv = s(&["sh", "-c", "echo 'a b'", ""]);
        assert_eq!(
            wire::decode_argv(&wire::encode_argv(&argv).unwrap()).unwrap(),
            argv
        );
        assert!(wire::encode_argv(&[]).is_err());
        let mut p = wire::encode_argv(&argv).unwrap();
        p.push(0);
        assert!(wire::decode_argv(&p).is_err(), "trailing bytes");
        assert!(wire::decode_argv(&p[..p.len() - 3]).is_err(), "truncated");
        assert!(wire::decode_argv(&[0, 0, 0, 0]).is_err(), "empty argv");
        let mut bad_utf8 = 1u32.to_be_bytes().to_vec();
        bad_utf8.extend_from_slice(&1u32.to_be_bytes());
        bad_utf8.push(0xff);
        assert!(wire::decode_argv(&bad_utf8).is_err());
    }

    #[test]
    fn frames_are_bounded_and_truncation_is_an_error() {
        let mut buf = Vec::new();
        assert!(wire::write_frame(&mut buf, STDOUT, &vec![0; wire::MAX_FRAME + 1]).is_err());
        wire::write_frame(&mut buf, STDOUT, b"hi").unwrap();
        assert_eq!(
            wire::read_frame(&mut Cursor::new(&buf)).unwrap(),
            Some((STDOUT, b"hi".to_vec()))
        );
        assert_eq!(
            wire::read_frame(&mut Cursor::new(Vec::<u8>::new())).unwrap(),
            None
        );
        assert!(wire::read_frame(&mut Cursor::new(&buf[..3])).is_err());
        assert!(wire::read_frame(&mut Cursor::new(&buf[..6])).is_err());
        let mut huge = vec![STDOUT];
        huge.extend_from_slice(&((wire::MAX_FRAME + 1) as u32).to_be_bytes());
        assert!(wire::read_frame(&mut Cursor::new(huge)).is_err());
    }

    #[cfg(unix)]
    fn pair() -> (
        std::os::unix::net::UnixStream,
        std::thread::JoinHandle<io::Result<()>>,
    ) {
        let (host, guest) = std::os::unix::net::UnixStream::pair().unwrap();
        (host, std::thread::spawn(move || serve::serve(guest)))
    }

    #[cfg(unix)]
    #[test]
    fn a_command_runs_with_its_stdin_output_and_exit_code() {
        let (mut host, guest) = pair();
        let out = run(
            &mut host,
            &s(&["sh", "-c", "cat; echo err >&2; exit 3"]),
            b"from host",
            1 << 20,
        )
        .unwrap();
        guest.join().unwrap().unwrap();
        assert_eq!(
            out,
            Output {
                code: 3,
                stdout: b"from host".to_vec(),
                stderr: b"err\n".to_vec()
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_argv_is_never_parsed_by_a_shell() {
        let (mut host, guest) = pair();
        let out = run(&mut host, &s(&["echo", "$(id)", ";", "x"]), b"", 1 << 20).unwrap();
        guest.join().unwrap().unwrap();
        assert_eq!(out.stdout, b"$(id) ; x\n");
    }

    #[cfg(unix)]
    #[test]
    fn large_output_streams_in_frames_and_the_limit_is_enforced() {
        let (mut host, guest) = pair();
        let out = run(
            &mut host,
            &s(&["head", "-c", "300000", "/dev/zero"]),
            b"",
            1 << 20,
        )
        .unwrap();
        guest.join().unwrap().unwrap();
        assert_eq!((out.code, out.stdout.len()), (0, 300000));
        let (mut host, _guest) = pair();
        assert!(
            run(
                &mut host,
                &s(&["head", "-c", "300000", "/dev/zero"]),
                b"",
                100000
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_missing_program_and_a_signal_report_exit_codes() {
        let (mut host, guest) = pair();
        let out = run(
            &mut host,
            &s(&["/nonexistent-rts-guest-test"]),
            b"",
            1 << 20,
        )
        .unwrap();
        guest.join().unwrap().unwrap();
        assert_eq!(out.code, 127);
        assert!(String::from_utf8_lossy(&out.stderr).contains("cannot run"));
        let (mut host, guest) = pair();
        let out = run(&mut host, &s(&["sh", "-c", "kill -9 $$"]), b"", 1 << 20).unwrap();
        guest.join().unwrap().unwrap();
        assert_eq!(out.code, 137);
    }
}

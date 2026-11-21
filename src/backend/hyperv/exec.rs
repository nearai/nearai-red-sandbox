//! Guest exec for the Hyper-V backend: the same guest wrapper, nonce
//! trailer and fail-closed rules as mvm (`protocol::wrap_argv` and
//! `parse_result`), carried by `hvexec` over one connection per command.
//! The connection comes from a `Connect`, so the transport (hvsocket on
//! Windows, a socket pair in tests) and its direction can change without
//! touching these rules.

use std::io::{self, Read, Write};
use std::sync::Mutex;
use std::time::Duration;

use crate::hvexec;
use crate::hvexec::serve::TryClone;
use crate::protocol::{WrapOptions, new_nonce, parse_result, wrap_argv};
use crate::sandbox::{Error, Exec, ExecOptions, ExecResult, Result};

/// A fresh connection to the guest agent whose reads fail once `deadline`
/// passes without data (the host backstop).
pub trait Connect: Send + Sync {
    type Stream: Read + Write + Send + TryClone + 'static;
    fn connect(&self, deadline: Duration) -> io::Result<Self::Stream>;
}

/// Bytes the guest may send beyond the wrapper's per-stream cap: framing
/// and the trailer.
const SLACK: u64 = 64 * 1024;

pub struct GuestExec<C: Connect> {
    connect: C,
    /// Added to the command's own timeout before the host gives up.
    backstop: Duration,
    serial: Mutex<()>,
    dead: Mutex<Option<String>>,
}

impl<C: Connect> GuestExec<C> {
    pub fn new(connect: C, backstop: Duration) -> Self {
        Self {
            connect,
            backstop,
            serial: Mutex::new(()),
            dead: Mutex::new(None),
        }
    }

    /// Why the machine can no longer run commands, once it cannot.
    pub fn dead_reason(&self) -> Option<String> {
        self.dead.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn mark_unavailable(&self, reason: &str) -> Error {
        let mut dead = self.dead.lock().unwrap_or_else(|e| e.into_inner());
        Error::Unavailable(dead.get_or_insert_with(|| reason.to_string()).clone())
    }
}

impl<C: Connect> Exec for GuestExec<C> {
    fn exec(&self, argv: &[String], o: &ExecOptions) -> Result<ExecResult> {
        // One exec at a time, so a lost machine stops every queued call.
        let _serial = self.serial.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(r) = self.dead_reason() {
            return Err(Error::Unavailable(r));
        }
        let nonce = new_nonce();
        let timeout_sec = o.timeout_ms.div_ceil(1000).max(1);
        let wrapped = wrap_argv(
            argv,
            &WrapOptions {
                nonce: &nonce,
                timeout_sec,
                max_output_bytes: o.max_output_bytes,
                workdir: o.workdir.as_deref(),
            },
        )
        .map_err(Error::Other)?;
        // A request must fit one frame. Refusing it here, before anything is
        // sent, is an ordinary error: the machine is fine.
        let size: usize = wrapped.iter().map(|a| a.len() + 4).sum::<usize>() + 4;
        if crate::hvexec::wire::encode_argv(&wrapped).is_err() {
            return Err(Error::Other(format!(
                "command too large for the guest channel ({size} bytes; at most {} per command)",
                crate::hvexec::wire::MAX_FRAME
            )));
        }
        let deadline = Duration::from_secs(timeout_sec) + self.backstop;
        let mut conn = match self.connect.connect(deadline) {
            Ok(c) => c,
            Err(e) => {
                return Err(self.mark_unavailable(&format!("cannot reach the guest agent: {e}")));
            }
        };
        // The wrapper caps stdout and stderr each at max_output_bytes.
        let limit = o.max_output_bytes.saturating_mul(2).saturating_add(SLACK);
        // The per-read timeout alone cannot stop a guest that keeps sending
        // small frames: a watchdog shuts the stream down at the wall-clock
        // deadline, which fails the read below.
        let killer = match conn.try_clone_stream() {
            Ok(k) => k,
            Err(e) => return Err(self.mark_unavailable(&format!("guest exec failed: {e}"))),
        };
        let expired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (done, wait) = std::sync::mpsc::channel::<()>();
        let watchdog = {
            let expired = expired.clone();
            std::thread::spawn(move || {
                if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) = wait.recv_timeout(deadline)
                {
                    expired.store(true, std::sync::atomic::Ordering::SeqCst);
                    let _ = killer.shutdown_stream();
                }
            })
        };
        let ran = hvexec::run(
            &mut conn,
            &wrapped,
            b"",
            usize::try_from(limit).unwrap_or(usize::MAX),
        );
        drop(done);
        let _ = watchdog.join();
        if expired.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(self.mark_unavailable("exec exceeded the host backstop; machine is lost"));
        }
        let out = match ran {
            Ok(out) => out,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(
                    self.mark_unavailable("exec exceeded the host backstop; machine is lost")
                );
            }
            Err(e) => return Err(self.mark_unavailable(&format!("guest exec failed: {e}"))),
        };
        if out.code != 0 {
            // The wrapper always exits 0; anything else is not the wrapper.
            return Err(self.mark_unavailable(&format!("guest wrapper exited {}", out.code)));
        }
        match parse_result(&out.stdout, &out.stderr, &nonce) {
            Some(parsed) => Ok(parsed),
            None => Err(self.mark_unavailable("exec returned no valid trailer")),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Serves each connection with the real guest server, on this host.
    struct Local;

    impl Connect for Local {
        type Stream = UnixStream;
        fn connect(&self, deadline: Duration) -> io::Result<UnixStream> {
            let (host, guest) = UnixStream::pair()?;
            std::thread::spawn(move || hvexec::serve::serve(guest));
            host.set_read_timeout(Some(deadline))?;
            Ok(host)
        }
    }

    /// A guest that accepts and then never answers.
    struct Silent(Mutex<Vec<UnixStream>>);

    impl Connect for Silent {
        type Stream = UnixStream;
        fn connect(&self, deadline: Duration) -> io::Result<UnixStream> {
            let (host, guest) = UnixStream::pair()?;
            self.0.lock().unwrap().push(guest);
            host.set_read_timeout(Some(deadline))?;
            Ok(host)
        }
    }

    /// A guest that answers with a well-formed exit but no wrapper trailer.
    struct NoTrailer;

    impl Connect for NoTrailer {
        type Stream = UnixStream;
        fn connect(&self, _: Duration) -> io::Result<UnixStream> {
            let (host, mut guest) = UnixStream::pair()?;
            std::thread::spawn(move || {
                let _ = hvexec::wire::read_frame(&mut guest);
                let _ = hvexec::wire::write_frame(&mut guest, hvexec::wire::STDOUT, b"forged\n");
                let _ = hvexec::wire::write_frame(
                    &mut guest,
                    hvexec::wire::EXIT,
                    &hvexec::wire::encode_exit(0),
                );
                let _ = std::io::copy(&mut guest, &mut std::io::sink());
            });
            Ok(host)
        }
    }

    /// A guest that keeps the connection busy with a small frame every
    /// 100 ms and never finishes, so no single read ever times out.
    struct Trickle;

    impl Connect for Trickle {
        type Stream = UnixStream;
        fn connect(&self, deadline: Duration) -> io::Result<UnixStream> {
            let (host, mut guest) = UnixStream::pair()?;
            std::thread::spawn(move || {
                let _ = hvexec::wire::read_frame(&mut guest);
                while hvexec::wire::write_frame(&mut guest, hvexec::wire::STDOUT, b".").is_ok() {
                    std::thread::sleep(Duration::from_millis(100));
                }
            });
            host.set_read_timeout(Some(deadline))?;
            Ok(host)
        }
    }

    struct Refused(AtomicUsize);

    impl Connect for Refused {
        type Stream = UnixStream;
        fn connect(&self, _: Duration) -> io::Result<UnixStream> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::new(io::ErrorKind::ConnectionRefused, "no agent"))
        }
    }

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn a_command_runs_through_the_guest_wrapper() {
        let g = GuestExec::new(Local, Duration::from_secs(30));
        let mut o = ExecOptions::new(10_000, 1 << 20);
        o.workdir = Some("/".into());
        let r = g
            .exec(&s(&["sh", "-c", "pwd; echo err >&2; exit 4"]), &o)
            .unwrap();
        assert_eq!((r.exit_code, r.timed_out), (4, false));
        assert_eq!(r.stdout, b"/\n");
        assert_eq!(r.stderr, b"err\n");
        assert!(g.dead_reason().is_none());
    }

    #[test]
    fn the_guest_side_timeout_and_output_cap_apply() {
        let g = GuestExec::new(Local, Duration::from_secs(30));
        let r = g
            .exec(&s(&["sleep", "5"]), &ExecOptions::new(1000, 1 << 20))
            .unwrap();
        assert!(r.timed_out, "{r:?}");
        let r = g
            .exec(
                &s(&["sh", "-c", "head -c 5000 /dev/zero"]),
                &ExecOptions::new(10_000, 100),
            )
            .unwrap();
        assert_eq!(
            (r.stdout.len(), r.stdout_bytes, r.truncated),
            (100, 5000, true)
        );
    }

    #[test]
    fn a_guest_that_stops_answering_is_lost_after_the_backstop() {
        let g = GuestExec::new(Silent(Mutex::new(vec![])), Duration::from_millis(200));
        let start = std::time::Instant::now();
        let e = g
            .exec(&s(&["true"]), &ExecOptions::new(1000, 1 << 20))
            .unwrap_err();
        assert!(matches!(e, Error::Unavailable(_)), "{e}");
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(matches!(
            g.exec(&s(&["true"]), &ExecOptions::new(1000, 1 << 20)),
            Err(Error::Unavailable(_))
        ));
    }

    #[test]
    fn a_guest_that_trickles_output_is_lost_at_the_wall_clock_backstop() {
        let g = GuestExec::new(Trickle, Duration::from_millis(500));
        let start = std::time::Instant::now();
        let e = g
            .exec(&s(&["true"]), &ExecOptions::new(1000, 1 << 20))
            .unwrap_err();
        assert!(
            matches!(&e, Error::Unavailable(r) if r.contains("backstop")),
            "{e}"
        );
        let took = start.elapsed();
        assert!(
            took >= Duration::from_millis(1500) && took < Duration::from_secs(4),
            "{took:?}"
        );
    }

    #[test]
    fn an_oversized_command_is_an_ordinary_error_and_the_machine_stays_usable() {
        let g = GuestExec::new(Local, Duration::from_secs(30));
        let big = "x".repeat(100 * 1024);
        let e = g
            .exec(&s(&["echo", &big]), &ExecOptions::new(5_000, 1 << 20))
            .unwrap_err();
        assert!(
            matches!(&e, Error::Other(m) if m.contains("too large")),
            "{e}"
        );
        assert!(g.dead_reason().is_none());
        let r = g
            .exec(
                &s(&["echo", "still here"]),
                &ExecOptions::new(5_000, 1 << 20),
            )
            .unwrap();
        assert_eq!(r.stdout, b"still here\n");
    }

    #[test]
    fn a_reply_without_the_nonce_trailer_is_never_trusted() {
        let g = GuestExec::new(NoTrailer, Duration::from_secs(5));
        let e = g
            .exec(&s(&["true"]), &ExecOptions::new(1000, 1 << 20))
            .unwrap_err();
        assert!(
            matches!(&e, Error::Unavailable(r) if r.contains("trailer")),
            "{e}"
        );
    }

    #[test]
    fn an_unreachable_agent_marks_the_machine_unavailable_for_good() {
        let g = GuestExec::new(Refused(AtomicUsize::new(0)), Duration::from_secs(5));
        assert!(matches!(
            g.exec(&s(&["true"]), &ExecOptions::new(1000, 1)),
            Err(Error::Unavailable(_))
        ));
        assert!(matches!(
            g.exec(&s(&["true"]), &ExecOptions::new(1000, 1)),
            Err(Error::Unavailable(_))
        ));
        assert_eq!(
            g.connect.0.load(Ordering::SeqCst),
            1,
            "no reconnect after the machine is lost"
        );
    }
}

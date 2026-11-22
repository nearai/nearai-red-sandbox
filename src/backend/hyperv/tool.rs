//! `rts tool` on Windows: a separate process for each tool call reaches
//! the session's VM over hvsocket (connect only; it never opens an HCS
//! handle, which would hold the VM past rts). It follows the session's
//! state directory exactly as the mvm path does: a machine marked
//! unavailable is refused without connecting, each exec holds the shared
//! exec lock (so teardown can quiesce every tool), and a lost machine is
//! marked for every later tool process.

use super::exec::{Connect, GuestExec};
use crate::mvm::StateDir;
use crate::sandbox::{Error, Exec, ExecOptions, ExecResult, Result};

pub struct ToolExec<C: Connect> {
    exec: GuestExec<C>,
    state: StateDir,
}

impl<C: Connect> ToolExec<C> {
    pub fn new(connect: C, state: StateDir) -> Self {
        Self {
            exec: GuestExec::new(connect, super::machine::BACKSTOP),
            state,
        }
    }
}

impl<C: Connect> Exec for ToolExec<C> {
    fn exec(&self, argv: &[String], o: &ExecOptions) -> Result<ExecResult> {
        if let Some(r) = self.state.dead_reason() {
            return Err(Error::Unavailable(r));
        }
        let _lock = self
            .state
            .lock()
            .map_err(|e| Error::Other(format!("exec lock: {e}")))?;
        // Teardown may have marked it while we waited for the lock.
        if let Some(r) = self.state.dead_reason() {
            return Err(Error::Unavailable(r));
        }
        let r = self.exec.exec(argv, o);
        if let Err(Error::Unavailable(reason)) = &r {
            self.state.mark(reason);
        }
        r
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::sandbox::sv;
    use std::io;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// The real guest server on this host; counts connections.
    struct Local(std::sync::Arc<AtomicUsize>);

    impl Connect for Local {
        type Stream = UnixStream;
        fn connect(&self, deadline: Duration) -> io::Result<UnixStream> {
            self.0.fetch_add(1, Ordering::SeqCst);
            let (host, guest) = UnixStream::pair()?;
            std::thread::spawn(move || crate::hvexec::serve::serve(guest));
            host.set_read_timeout(Some(deadline))?;
            Ok(host)
        }
    }

    struct Gone;

    impl Connect for Gone {
        type Stream = UnixStream;
        fn connect(&self, _: Duration) -> io::Result<UnixStream> {
            Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no such VM",
            ))
        }
    }

    #[test]
    fn a_tool_command_runs_in_the_guest_under_the_shared_lock() {
        let d = tempfile::tempdir().unwrap();
        let t = ToolExec::new(
            Local(std::sync::Arc::new(AtomicUsize::new(0))),
            StateDir(d.path().to_path_buf()),
        );
        let r = t
            .exec(
                &sv(&["sh", "-c", "echo ok"]),
                &ExecOptions::new(5_000, 4096),
            )
            .unwrap();
        assert_eq!(r.stdout, b"ok\n");
        assert!(
            d.path().join("exec.lock").exists(),
            "the exec took the session's lock"
        );
    }

    #[test]
    fn a_session_marked_unavailable_is_refused_without_connecting() {
        let d = tempfile::tempdir().unwrap();
        let state = StateDir(d.path().to_path_buf());
        state.mark("session ended");
        let connects = std::sync::Arc::new(AtomicUsize::new(0));
        let t = ToolExec::new(Local(connects.clone()), StateDir(d.path().to_path_buf()));
        let e = t
            .exec(&sv(&["true"]), &ExecOptions::new(5_000, 64))
            .unwrap_err();
        assert!(
            matches!(&e, Error::Unavailable(r) if r.contains("session ended")),
            "{e}"
        );
        assert_eq!(connects.load(Ordering::SeqCst), 0, "nothing connected");
    }

    #[test]
    fn a_lost_machine_is_marked_for_every_later_tool() {
        let d = tempfile::tempdir().unwrap();
        let t = ToolExec::new(Gone, StateDir(d.path().to_path_buf()));
        assert!(matches!(
            t.exec(&sv(&["true"]), &ExecOptions::new(1_000, 64)),
            Err(Error::Unavailable(_))
        ));
        assert!(
            StateDir(d.path().to_path_buf())
                .dead_reason()
                .unwrap()
                .contains("guest agent")
        );
    }

    #[test]
    fn teardown_waits_for_an_active_tool_then_stops_the_rest() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().to_path_buf();
        let t = std::sync::Arc::new(ToolExec::new(
            Local(std::sync::Arc::new(AtomicUsize::new(0))),
            StateDir(dir.clone()),
        ));
        let busy = {
            let t = t.clone();
            std::thread::spawn(move || {
                t.exec(
                    &sv(&["sh", "-c", "sleep 1; echo done"]),
                    &ExecOptions::new(5_000, 64),
                )
            })
        };
        std::thread::sleep(Duration::from_millis(200));
        let started = std::time::Instant::now();
        let _held = StateDir(dir.clone())
            .quiesce(Duration::from_secs(10))
            .unwrap();
        assert!(
            started.elapsed() >= Duration::from_millis(500),
            "quiesce waited for the active exec"
        );
        assert_eq!(busy.join().unwrap().unwrap().stdout, b"done\n");
        assert!(matches!(
            t.exec(&sv(&["true"]), &ExecOptions::new(1_000, 64)),
            Err(Error::Unavailable(_))
        ));
    }
}

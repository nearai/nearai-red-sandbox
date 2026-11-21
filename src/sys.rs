//! Host-OS calls std does not expose. On Unix: sending a signal other than
//! SIGKILL, catching SIGINT/SIGTERM, physical memory, and process groups;
//! libc is already linked by std on macOS and Linux, so this needs no crate.
//! On Windows these are not implemented yet: each fails closed (no signal
//! sent, no memory figure, so a launch refuses) rather than pretending.

use std::sync::atomic::{AtomicI32, Ordering};

pub mod fs;

pub const SIGINT: i32 = 2;
pub const SIGKILL: i32 = 9;
pub const SIGTERM: i32 = 15;

#[cfg(unix)]
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
    fn signal(sig: i32, handler: usize) -> usize;
}

/// Send `sig` to a process, or to a whole process group when `pid` is negative.
#[cfg(windows)]
pub fn send_signal(_pid: i32, _sig: i32) -> bool {
    false
}

/// Send `sig` to a process, or to a whole process group when `pid` is negative.
#[cfg(unix)]
pub fn send_signal(pid: i32, sig: i32) -> bool {
    // SAFETY: kill(2) has no memory-safety preconditions.
    unsafe { kill(pid, sig) == 0 }
}

static LAST_SIGNAL: AtomicI32 = AtomicI32::new(0);

#[cfg(unix)]
extern "C" fn on_signal(sig: i32) {
    // Only an atomic store: async-signal-safe.
    LAST_SIGNAL.store(sig, Ordering::SeqCst);
}

/// Route SIGINT and SIGTERM to a flag the launcher polls, instead of
/// letting them kill the launcher before teardown runs. Windows: not yet
/// (a console control handler); Ctrl-C ends the launcher there.
#[cfg(windows)]
pub fn catch_termination_signals() {}

/// Route SIGINT and SIGTERM to a flag the launcher polls, instead of
/// letting them kill the launcher before teardown runs.
#[cfg(unix)]
pub fn catch_termination_signals() {
    // SAFETY: the handler only performs an atomic store.
    unsafe {
        signal(SIGINT, on_signal as *const () as usize);
        signal(SIGTERM, on_signal as *const () as usize);
    }
}

/// The last SIGINT/SIGTERM received, if any, cleared on read.
pub fn take_signal() -> Option<i32> {
    match LAST_SIGNAL.swap(0, Ordering::SeqCst) {
        0 => None,
        s => Some(s),
    }
}

/// Physical memory in MiB. Windows: not yet, so a launch refuses there.
#[cfg(windows)]
pub fn host_memory_mib() -> Option<u64> {
    None
}

/// Run `cmd` as the leader of its own process group (Unix), so a timeout
/// or teardown can signal it and everything it started.
pub fn own_process_group(cmd: &mut std::process::Command) -> &mut std::process::Command {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0)
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NEW_PROCESS_GROUP: the operator's Ctrl-C does not reach it.
        // Killing its descendants needs a job object, which is not here yet.
        cmd.creation_flags(0x0000_0200)
    }
}

/// Send `sig` to the process group led by `pid` (Unix). Windows: false.
pub fn signal_group(pid: u32, sig: i32) -> bool {
    send_signal(-(pid as i32), sig)
}

/// Physical memory in MiB, from sysconf (macOS and Linux).
#[cfg(unix)]
pub fn host_memory_mib() -> Option<u64> {
    // SAFETY: sysconf only reads system configuration values.
    let (pages, page) = unsafe { (libc::sysconf(libc::_SC_PHYS_PAGES), libc::sysconf(libc::_SC_PAGESIZE)) };
    if pages <= 0 || page <= 0 {
        return None;
    }
    Some((pages as u64).checked_mul(page as u64)? / (1024 * 1024))
}

#[cfg(all(test, unix))]
mod memory_tests {
    #[test]
    fn host_memory_is_read_in_mib() {
        let mib = super::host_memory_mib().expect("sysconf reports physical memory");
        // Any machine that runs this has between 512 MiB and 64 TiB.
        assert!((512..64 * 1024 * 1024).contains(&mib), "{mib}");
    }
}

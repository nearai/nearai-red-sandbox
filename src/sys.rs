//! The two libc calls std does not expose: sending a signal other than
//! SIGKILL, and catching SIGINT/SIGTERM. libc is already linked by std on
//! macOS and Linux, so this needs no crate.

use std::sync::atomic::{AtomicI32, Ordering};

pub const SIGINT: i32 = 2;
pub const SIGKILL: i32 = 9;
pub const SIGTERM: i32 = 15;

unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
    fn signal(sig: i32, handler: usize) -> usize;
}

/// Send `sig` to a process, or to a whole process group when `pid` is negative.
pub fn send_signal(pid: i32, sig: i32) -> bool {
    // SAFETY: kill(2) has no memory-safety preconditions.
    unsafe { kill(pid, sig) == 0 }
}

static LAST_SIGNAL: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_signal(sig: i32) {
    // Only an atomic store: async-signal-safe.
    LAST_SIGNAL.store(sig, Ordering::SeqCst);
}

/// Route SIGINT and SIGTERM to a flag the launcher polls, instead of
/// letting them kill the launcher before teardown runs.
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

/// Physical memory in MiB, from sysconf (macOS and Linux).
pub fn host_memory_mib() -> Option<u64> {
    // SAFETY: sysconf only reads system configuration values.
    let (pages, page) = unsafe { (libc::sysconf(libc::_SC_PHYS_PAGES), libc::sysconf(libc::_SC_PAGESIZE)) };
    if pages <= 0 || page <= 0 {
        return None;
    }
    Some((pages as u64).checked_mul(page as u64)? / (1024 * 1024))
}

#[cfg(test)]
mod memory_tests {
    #[test]
    fn host_memory_is_read_in_mib() {
        let mib = super::host_memory_mib().expect("sysconf reports physical memory");
        // Any machine that runs this has between 512 MiB and 64 TiB.
        assert!((512..64 * 1024 * 1024).contains(&mib), "{mib}");
    }
}

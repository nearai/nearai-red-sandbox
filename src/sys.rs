//! Host-OS calls std does not expose. On Unix: sending a signal other than
//! SIGKILL, catching SIGINT/SIGTERM, physical memory, and process groups;
//! libc is already linked by std on macOS and Linux, so this needs no crate.
//! On Windows, physical memory and console control events are read through
//! windows-sys; signals are not sent (job objects end process trees there),
//! so `send_signal` and `signal_group` fail closed.

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

/// The signal a console control event stands for: Ctrl-C and Ctrl-Break
/// are SIGINT; closing the console, logoff and shutdown are SIGTERM.
#[cfg(windows)]
fn ctrl_signal(event: u32) -> Option<i32> {
    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
    };
    match event {
        CTRL_C_EVENT | CTRL_BREAK_EVENT => Some(SIGINT),
        CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => Some(SIGTERM),
        _ => None,
    }
}

/// How long the close, logoff and shutdown events hold the console handler.
/// Windows ends the process when the handler returns (or after about five
/// seconds), so it waits here while the launcher tears down; the launcher
/// exiting first ends the process, and this thread with it.
#[cfg(windows)]
const CLOSE_GRACE: std::time::Duration = std::time::Duration::from_millis(4500);

/// Set once the console is closing (close, logoff or shutdown); never cleared.
static CLOSING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether Windows is closing this console: teardown then has only seconds,
/// so it skips its grace periods. Always false on Unix.
pub fn closing() -> bool {
    CLOSING.load(Ordering::SeqCst)
}

/// Record a console control event on the flags; the signal it stands for.
#[cfg(windows)]
fn record_ctrl(event: u32) -> Option<i32> {
    let sig = ctrl_signal(event)?;
    if sig == SIGTERM {
        CLOSING.store(true, Ordering::SeqCst);
    }
    LAST_SIGNAL.store(sig, Ordering::SeqCst);
    Some(sig)
}

#[cfg(windows)]
unsafe extern "system" fn on_ctrl(event: u32) -> windows_sys::core::BOOL {
    let Some(sig) = record_ctrl(event) else {
        return 0;
    };
    if sig == SIGTERM {
        std::thread::sleep(CLOSE_GRACE);
    }
    1
}

/// Route Ctrl-C, Ctrl-Break and console close, logoff and shutdown to the
/// flag the launcher polls, instead of letting them end the launcher before
/// teardown runs. In ConPTY raw mode Ctrl-C reaches OpenCode as a keystroke,
/// not as an event. Returns whether the handler was installed.
#[cfg(windows)]
pub fn catch_termination_signals() -> bool {
    // SAFETY: the handler only stores to an atomic and sleeps.
    unsafe { windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(on_ctrl), 1) != 0 }
}

/// Route SIGINT and SIGTERM to a flag the launcher polls, instead of
/// letting them kill the launcher before teardown runs. Returns true.
#[cfg(unix)]
pub fn catch_termination_signals() -> bool {
    // SAFETY: the handler only performs an atomic store.
    unsafe {
        signal(SIGINT, on_signal as *const () as usize);
        signal(SIGTERM, on_signal as *const () as usize);
    }
    true
}

/// The last SIGINT/SIGTERM received, if any, cleared on read.
pub fn take_signal() -> Option<i32> {
    match LAST_SIGNAL.swap(0, Ordering::SeqCst) {
        0 => None,
        s => Some(s),
    }
}

/// Physical memory in MiB, from GlobalMemoryStatusEx.
#[cfg(windows)]
pub fn host_memory_mib() -> Option<u64> {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    // SAFETY: MEMORYSTATUSEX is plain data; dwLength is set as the API requires.
    let mut status: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
    // SAFETY: the pointer is to a struct we own, sized in dwLength.
    if unsafe { GlobalMemoryStatusEx(&mut status) } == 0 || status.ullTotalPhys == 0 {
        return None;
    }
    Some(status.ullTotalPhys / (1024 * 1024))
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

#[cfg(test)]
mod memory_tests {
    #[test]
    fn host_memory_is_read_in_mib() {
        let mib = super::host_memory_mib().expect("the OS reports physical memory");
        // Any machine that runs this has between 512 MiB and 64 TiB.
        assert!((512..64 * 1024 * 1024).contains(&mib), "{mib}");
    }
}

#[cfg(all(test, windows))]
mod ctrl_tests {
    use super::*;
    use windows_sys::Win32::System::Console::{
        CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
    };

    #[test]
    fn console_events_map_to_the_signals_the_session_polls() {
        assert_eq!(ctrl_signal(CTRL_C_EVENT), Some(SIGINT));
        assert_eq!(ctrl_signal(CTRL_BREAK_EVENT), Some(SIGINT));
        for close in [CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT] {
            assert_eq!(ctrl_signal(close), Some(SIGTERM));
        }
        assert_eq!(ctrl_signal(42), None);
    }

    #[test]
    fn the_handler_is_registered_and_ctrl_break_sets_the_flag_instead_of_ending_the_process() {
        assert!(
            catch_termination_signals(),
            "SetConsoleCtrlHandler must succeed"
        );
        let _ = take_signal();
        // SAFETY: called as Windows would call it, with an event code.
        assert_ne!(
            unsafe { on_ctrl(CTRL_BREAK_EVENT) },
            0,
            "handled, so the default handler does not end the process"
        );
        assert_eq!(take_signal(), Some(SIGINT));
        assert_eq!(
            unsafe { on_ctrl(42) },
            0,
            "an unknown event is left to the next handler"
        );
        // One test: these share the process-wide flags.
        assert_eq!(record_ctrl(CTRL_C_EVENT), Some(SIGINT));
        assert!(!closing(), "Ctrl-C is not a console close");
        assert_eq!(record_ctrl(CTRL_CLOSE_EVENT), Some(SIGTERM));
        assert_eq!(take_signal(), Some(SIGTERM));
        assert!(
            closing(),
            "teardown must know Windows allows only seconds, even after the signal is taken"
        );
    }
}

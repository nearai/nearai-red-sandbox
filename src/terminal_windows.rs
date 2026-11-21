//! The Windows side of `terminal`: OpenCode runs under a pseudo-console
//! (ConPTY) inside a kill-on-close job object. As on Unix, nothing from
//! operator input reaches the child until the plugin's nonce handshake has
//! succeeded, and the launcher pumps the transport itself: every read is
//! preceded by a check that it will not block, so no reader thread outlives
//! the session (the close-time drain below is bounded).

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::os::windows::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_BROKEN_PIPE, HANDLE, INVALID_HANDLE_VALUE,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::Console::{
    CONSOLE_MODE, CONSOLE_SCREEN_BUFFER_INFO, COORD, ClosePseudoConsole, CreatePseudoConsole,
    DISABLE_NEWLINE_AUTO_RETURN, ENABLE_PROCESSED_OUTPUT, ENABLE_VIRTUAL_TERMINAL_INPUT,
    ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, GetConsoleOutputCP,
    GetConsoleScreenBufferInfo, GetNumberOfConsoleInputEvents, GetStdHandle, HPCON, INPUT_RECORD,
    KEY_EVENT, ReadConsoleInputW, ResizePseudoConsole, STD_HANDLE, STD_INPUT_HANDLE,
    STD_OUTPUT_HANDLE, SetConsoleMode, SetConsoleOutputCP,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Pipes::{CreatePipe, PeekNamedPipe};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetExitCodeProcess, INFINITE,
    InitializeProcThreadAttributeList, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROCESS_INFORMATION,
    ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject,
};

const BUFFER_LIMIT: usize = 64 * 1024;
const PIPE_BUFFER: u32 = 64 * 1024;
const UTF8: u32 = 65001;
/// How long closing waits for the pseudo-console's last output.
const CLOSE_DRAIN: Duration = Duration::from_secs(2);
const DEFAULT_SIZE: (i16, i16) = (80, 24);

/// OpenCode's process. Its whole tree lives in a job object that only this
/// value holds, with kill-on-close: dropping it (or rts dying) ends OpenCode
/// and everything it started, which on Unix the process group did.
pub struct Child {
    process: OwnedHandle,
    job: OwnedHandle,
    pid: u32,
}

impl Child {
    pub fn id(&self) -> u32 {
        self.pid
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.wait_ms(0)
    }

    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        self.wait_ms(INFINITE)?
            .ok_or_else(|| io::Error::other("wait returned without an exit"))
    }

    /// End OpenCode and every process in its job.
    pub fn kill(&mut self) -> io::Result<()> {
        // SAFETY: a job handle this value owns.
        if unsafe { TerminateJobObject(self.job.as_raw_handle(), 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn wait_ms(&self, ms: u32) -> io::Result<Option<ExitStatus>> {
        let process = self.process.as_raw_handle();
        // SAFETY: a process handle this value owns.
        match unsafe { WaitForSingleObject(process, ms) } {
            WAIT_OBJECT_0 => {
                let mut code = 0u32;
                // SAFETY: as above; the out-pointer is ours.
                if unsafe { GetExitCodeProcess(process, &mut code) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(Some(ExitStatus::from_raw(code)))
            }
            WAIT_TIMEOUT => Ok(None),
            _ => Err(io::Error::last_os_error()),
        }
    }
}

/// Stop OpenCode and everything it started. Closing the pseudo-console
/// (dropping the Terminal) already asked it to exit; this waits up to
/// `grace` for that, then ends the whole job.
pub fn stop_tree(child: &mut Child, grace: Duration) {
    let end = std::time::Instant::now() + grace;
    while child.try_wait().ok().flatten().is_none() && std::time::Instant::now() < end {
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// The operator's console modes and output code page, restored on drop.
struct Saved {
    input_mode: Option<CONSOLE_MODE>,
    output_mode: Option<CONSOLE_MODE>,
    output_cp: Option<u32>,
}

pub struct Terminal {
    hpc: HPCON,
    to_pty: Option<OwnedHandle>,
    from_pty: Option<OwnedHandle>,
    input: OwnedHandle,
    output: OwnedHandle,
    input_console: bool,
    output_console: bool,
    size: (i16, i16),
    enabled: bool,
    input_eof: bool,
    output_eof: bool,
    input_queue: Vec<u8>,
    output_queue: Vec<u8>,
    high_surrogate: Option<u16>,
    saved: Saved,
}

impl Terminal {
    /// Start `command` under a new pseudo-console relayed to this process's
    /// console. The child's environment is exactly the variables set on
    /// `command` (none are inherited), as the session always clears it.
    pub fn spawn(command: &mut Command) -> io::Result<(Child, Self)> {
        Self::spawn_with_io(
            command,
            std_handle(STD_INPUT_HANDLE)?,
            std_handle(STD_OUTPUT_HANDLE)?,
        )
    }

    fn spawn_with_io(
        command: &Command,
        input: OwnedHandle,
        output: OwnedHandle,
    ) -> io::Result<(Child, Self)> {
        let input_mode = console_mode(&input);
        let output_mode = console_mode(&output);
        let mut terminal = Self {
            hpc: 0,
            to_pty: None,
            from_pty: None,
            input,
            output,
            input_console: input_mode.is_some(),
            output_console: output_mode.is_some(),
            size: DEFAULT_SIZE,
            enabled: false,
            input_eof: false,
            output_eof: false,
            input_queue: vec![],
            output_queue: vec![],
            high_surrogate: None,
            saved: Saved {
                input_mode,
                output_mode: None,
                output_cp: None,
            },
        };
        if let Some(mode) = output_mode {
            // ConPTY emits UTF-8 with VT sequences; the operator's console
            // has to render both. Restored on drop.
            let h = terminal.output.as_raw_handle();
            // SAFETY: a console output handle we own.
            unsafe {
                terminal.saved.output_cp = Some(GetConsoleOutputCP());
                terminal.saved.output_mode = Some(mode);
                SetConsoleOutputCP(UTF8);
                SetConsoleMode(
                    h,
                    mode | ENABLE_PROCESSED_OUTPUT
                        | ENABLE_VIRTUAL_TERMINAL_PROCESSING
                        | DISABLE_NEWLINE_AUTO_RETURN,
                );
            }
        }
        terminal.size = terminal.outer_size().unwrap_or(DEFAULT_SIZE);
        let (pty_in, to_pty) = pipe()?;
        let (from_pty, pty_out) = pipe()?;
        let coord = COORD {
            X: terminal.size.0,
            Y: terminal.size.1,
        };
        let mut hpc: HPCON = 0;
        // SAFETY: both pipe ends are valid; ConPTY duplicates them. Flags 0:
        // PSEUDOCONSOLE_INHERIT_CURSOR would wait for a cursor reply that
        // the closed input path cannot deliver.
        let hr = unsafe {
            CreatePseudoConsole(
                coord,
                pty_in.as_raw_handle(),
                pty_out.as_raw_handle(),
                0,
                &mut hpc,
            )
        };
        if hr < 0 {
            return Err(io::Error::from_raw_os_error(hr));
        }
        terminal.hpc = hpc;
        terminal.to_pty = Some(to_pty);
        terminal.from_pty = Some(from_pty);
        drop((pty_in, pty_out));
        let child = spawn_in_job(command, hpc)?;
        Ok((child, terminal))
    }

    /// Queue an OSC 0 window title ahead of any child output. Control
    /// characters are dropped so the title cannot end the escape early.
    pub fn set_title(&mut self, title: &str) {
        let clean: String = title.chars().filter(|c| !c.is_control()).collect();
        self.output_queue
            .extend_from_slice(format!("\x1b]0;{clean}\x07").as_bytes());
    }

    /// Called only after readiness verification. A console input switches to
    /// raw VT input, so Ctrl-C reaches OpenCode as a keystroke; input queued
    /// before this is read now, as TCSANOW preserves it on Unix.
    pub fn enable_input(&mut self) -> io::Result<()> {
        if self.enabled {
            return Ok(());
        }
        if self.input_console {
            // SAFETY: a console input handle we own.
            if unsafe { SetConsoleMode(self.input.as_raw_handle(), ENABLE_VIRTUAL_TERMINAL_INPUT) }
                == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        self.enabled = true;
        Ok(())
    }

    /// Bounded queues and per-tick I/O keep signal and monitor checks
    /// responsive; nothing here blocks on a read.
    pub fn pump(&mut self) -> io::Result<()> {
        self.resize()?;
        let mut buf = [0u8; 4096];
        if !self.output_eof && self.output_queue.len() < BUFFER_LIMIT {
            match self
                .from_pty
                .as_ref()
                .map(|h| read_available(h, &mut buf))
                .transpose()?
            {
                Some(Some(n)) => self.output_queue.extend_from_slice(&buf[..n]),
                Some(None) | None => self.output_eof = true,
            }
        }
        write_some(&self.output, &mut self.output_queue)?;
        if self.enabled && !self.input_eof && self.input_queue.len() < BUFFER_LIMIT {
            if self.input_console {
                self.read_console_keys()?;
            } else {
                match read_available(&self.input, &mut buf)? {
                    Some(n) => self.input_queue.extend_from_slice(&buf[..n]),
                    None => self.input_eof = true,
                }
            }
        }
        if self.enabled
            && !self.output_eof
            && let Some(to_pty) = &self.to_pty
        {
            write_some(to_pty, &mut self.input_queue)?;
        }
        Ok(())
    }

    /// Key-down characters from the console input (with VT input on, keys
    /// such as arrows arrive as escape sequences); other events are dropped.
    fn read_console_keys(&mut self) -> io::Result<()> {
        let h = self.input.as_raw_handle();
        let mut pending = 0u32;
        // SAFETY: a console input handle we own; the count is ours.
        if unsafe { GetNumberOfConsoleInputEvents(h, &mut pending) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if pending == 0 {
            return Ok(());
        }
        // SAFETY: INPUT_RECORD is plain data.
        let mut records: [INPUT_RECORD; 64] = unsafe { std::mem::zeroed() };
        let mut read = 0u32;
        // SAFETY: at least one event is pending, so this does not block.
        if unsafe { ReadConsoleInputW(h, records.as_mut_ptr(), pending.min(64), &mut read) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut units = vec![];
        for r in &records[..read as usize] {
            if u32::from(r.EventType) != KEY_EVENT {
                continue;
            }
            // SAFETY: EventType says this is a key event.
            let key = unsafe { r.Event.KeyEvent };
            // SAFETY: the Unicode arm, as ReadConsoleInputW fills it.
            let unit = unsafe { key.uChar.UnicodeChar };
            if key.bKeyDown != 0 && unit != 0 {
                units.extend(std::iter::repeat_n(
                    unit,
                    usize::from(key.wRepeatCount.max(1)),
                ));
            }
        }
        utf16_to_utf8(&mut self.high_surrogate, &units, &mut self.input_queue);
        Ok(())
    }

    fn outer_size(&self) -> Option<(i16, i16)> {
        if !self.output_console {
            return None;
        }
        // SAFETY: plain data, filled by the call on a console handle we own.
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
        if unsafe { GetConsoleScreenBufferInfo(self.output.as_raw_handle(), &mut info) } == 0 {
            return None;
        }
        let r = info.srWindow;
        let (cols, rows) = (r.Right - r.Left + 1, r.Bottom - r.Top + 1);
        (cols > 0 && rows > 0).then_some((cols, rows))
    }

    fn resize(&mut self) -> io::Result<()> {
        let Some(size) = self.outer_size() else {
            return Ok(());
        };
        if size == self.size {
            return Ok(());
        }
        // SAFETY: the pseudo-console this value owns.
        let hr = unsafe {
            ResizePseudoConsole(
                self.hpc,
                COORD {
                    X: size.0,
                    Y: size.1,
                },
            )
        };
        if hr < 0 {
            return Err(io::Error::from_raw_os_error(hr));
        }
        self.size = size;
        Ok(())
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = write_all(&self.output, &std::mem::take(&mut self.output_queue));
        // No more input; then keep draining output while the pseudo-console
        // closes (on older Windows ClosePseudoConsole waits for that), so
        // OpenCode's last output (leaving the alternate screen) still lands.
        self.to_pty = None;
        let mut done = None;
        if let (Some(from), Ok(out)) = (self.from_pty.take(), self.output.try_clone()) {
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            done = Some(done_rx);
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                loop {
                    let mut n = 0u32;
                    // SAFETY: handles moved into this thread; a blocking read
                    // that ends when the pseudo-console closes its end.
                    let ok = unsafe {
                        ReadFile(
                            from.as_raw_handle(),
                            buf.as_mut_ptr(),
                            buf.len() as u32,
                            &mut n,
                            std::ptr::null_mut(),
                        )
                    };
                    if ok == 0 || n == 0 || write_all(&out, &buf[..n as usize]).is_err() {
                        break;
                    }
                }
                let _ = done_tx.send(());
            });
        }
        if self.hpc != 0 {
            // SAFETY: the pseudo-console this value owns, closed once.
            unsafe { ClosePseudoConsole(self.hpc) };
            self.hpc = 0;
        }
        if let Some(done) = done {
            let _ = done.recv_timeout(CLOSE_DRAIN);
        }
        // SAFETY: console handles we own, restored to what we found.
        unsafe {
            if let (true, Some(mode)) = (self.enabled, self.saved.input_mode) {
                SetConsoleMode(self.input.as_raw_handle(), mode);
            }
            if let Some(mode) = self.saved.output_mode {
                SetConsoleMode(self.output.as_raw_handle(), mode);
            }
            if let Some(cp) = self.saved.output_cp {
                SetConsoleOutputCP(cp);
            }
        }
    }
}

/// Our own duplicate of a standard handle, so closing it leaves the
/// process's standard handles alone.
fn std_handle(which: STD_HANDLE) -> io::Result<OwnedHandle> {
    // SAFETY: GetStdHandle has no preconditions.
    let h = unsafe { GetStdHandle(which) };
    if h.is_null() || h == INVALID_HANDLE_VALUE {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no standard input or output to relay",
        ));
    }
    let mut dup: HANDLE = std::ptr::null_mut();
    // SAFETY: duplicating a valid handle within this process.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            h,
            GetCurrentProcess(),
            &mut dup,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the duplicate is ours alone.
    Ok(unsafe { OwnedHandle::from_raw_handle(dup) })
}

fn console_mode(h: &OwnedHandle) -> Option<CONSOLE_MODE> {
    let mut mode = 0;
    // SAFETY: fails harmlessly for a handle that is not a console.
    (unsafe { GetConsoleMode(h.as_raw_handle(), &mut mode) } != 0).then_some(mode)
}

/// A non-inheritable anonymous pipe as (read, write).
fn pipe() -> io::Result<(OwnedHandle, OwnedHandle)> {
    let (mut r, mut w): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
    // SAFETY: out-pointers are ours; null attributes make both ends
    // non-inheritable.
    if unsafe { CreatePipe(&mut r, &mut w, std::ptr::null(), PIPE_BUFFER) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both handles were just created and are ours.
    Ok(unsafe {
        (
            OwnedHandle::from_raw_handle(r),
            OwnedHandle::from_raw_handle(w),
        )
    })
}

/// Read what a pipe holds without blocking: Some(0) when it is empty, None
/// at end of stream. A handle that is not a pipe is read directly.
fn read_available(h: &OwnedHandle, buf: &mut [u8]) -> io::Result<Option<usize>> {
    let mut avail = 0u32;
    // SAFETY: a handle we own; only the count is requested.
    let peeked = unsafe {
        PeekNamedPipe(
            h.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &mut avail,
            std::ptr::null_mut(),
        )
    } != 0;
    if !peeked {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
            return Ok(None);
        }
        // Not a pipe (a file or NUL): a read does not wait.
    } else if avail == 0 {
        return Ok(Some(0));
    }
    let want = if peeked {
        buf.len().min(avail as usize)
    } else {
        buf.len()
    };
    let mut n = 0u32;
    // SAFETY: the buffer is ours and `want` fits it.
    if unsafe {
        ReadFile(
            h.as_raw_handle(),
            buf.as_mut_ptr(),
            want as u32,
            &mut n,
            std::ptr::null_mut(),
        )
    } == 0
    {
        let e = io::Error::last_os_error();
        return if e.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
            Ok(None)
        } else {
            Err(e)
        };
    }
    Ok(if n == 0 && !peeked {
        None
    } else {
        Some(n as usize)
    })
}

/// Write up to 4 KiB of `queue` and drop what was written.
fn write_some(h: &OwnedHandle, queue: &mut Vec<u8>) -> io::Result<()> {
    if queue.is_empty() {
        return Ok(());
    }
    let len = queue.len().min(4096);
    let mut n = 0u32;
    // SAFETY: the bytes are ours and `len` is within them.
    if unsafe {
        WriteFile(
            h.as_raw_handle(),
            queue.as_ptr(),
            len as u32,
            &mut n,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    queue.drain(..n as usize);
    Ok(())
}

fn write_all(h: &OwnedHandle, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        let mut n = 0u32;
        // SAFETY: as in write_some.
        if unsafe {
            WriteFile(
                h.as_raw_handle(),
                bytes.as_ptr(),
                bytes.len().min(4096) as u32,
                &mut n,
                std::ptr::null_mut(),
            )
        } == 0
            || n == 0
        {
            return Err(io::Error::last_os_error());
        }
        bytes = &bytes[n as usize..];
    }
    Ok(())
}

/// Append UTF-16 `units` as UTF-8, holding a trailing high surrogate until
/// its pair arrives in a later read. An unpaired surrogate becomes U+FFFD.
fn utf16_to_utf8(high: &mut Option<u16>, units: &[u16], out: &mut Vec<u8>) {
    let all: Vec<u16> = high
        .take()
        .into_iter()
        .chain(units.iter().copied())
        .collect();
    let (body, tail) = match all.last() {
        Some(&u) if (0xD800..0xDC00).contains(&u) => (&all[..all.len() - 1], Some(u)),
        _ => (&all[..], None),
    };
    *high = tail;
    let mut tmp = [0u8; 4];
    for c in char::decode_utf16(body.iter().copied()) {
        out.extend_from_slice(
            c.unwrap_or(char::REPLACEMENT_CHARACTER)
                .encode_utf8(&mut tmp)
                .as_bytes(),
        );
    }
}

/// `command`'s program, found as given when it names a path, else on the
/// command's own PATH; `.exe` is tried when there is no extension.
fn resolve_program(program: &OsStr, path_var: Option<&OsStr>) -> io::Result<PathBuf> {
    let p = Path::new(program);
    let with_exe = |c: PathBuf| -> Vec<PathBuf> {
        if c.extension().is_some() {
            vec![c]
        } else {
            vec![c.clone(), c.with_extension("exe")]
        }
    };
    let candidates: Vec<PathBuf> = if p.components().count() > 1 || p.is_absolute() {
        with_exe(p.to_path_buf())
    } else {
        path_var
            .map(|v| {
                std::env::split_paths(v)
                    .flat_map(|d| with_exe(d.join(p)))
                    .collect()
            })
            .unwrap_or_default()
    };
    candidates.into_iter().find(|c| c.is_file()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "cannot find {} (as a path or on the command's PATH)",
                p.display()
            ),
        )
    })
}

/// One argument quoted for the MSVC argument parser.
fn push_arg(out: &mut Vec<u16>, arg: &OsStr) {
    let units: Vec<u16> = arg.encode_wide().collect();
    let special = |u: &u16| {
        [
            u16::from(b' '),
            u16::from(b'\t'),
            u16::from(b'\n'),
            0x0b,
            u16::from(b'"'),
        ]
        .contains(u)
    };
    if !units.is_empty() && !units.iter().any(special) {
        out.extend(units);
        return;
    }
    out.push(u16::from(b'"'));
    let mut backslashes = 0usize;
    for u in units {
        if u == u16::from(b'\\') {
            backslashes += 1;
            continue;
        }
        let escaped = if u == u16::from(b'"') {
            backslashes * 2 + 1
        } else {
            backslashes
        };
        out.extend(std::iter::repeat_n(u16::from(b'\\'), escaped));
        backslashes = 0;
        out.push(u);
    }
    out.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2));
    out.push(u16::from(b'"'));
}

/// The program in quotes (argv[0] has no escapes; a path holds no quote),
/// then each argument quoted as needed; NUL-terminated.
fn command_line(program: &Path, args: &[&OsStr]) -> Vec<u16> {
    let mut line = vec![u16::from(b'"')];
    line.extend(program.as_os_str().encode_wide());
    line.push(u16::from(b'"'));
    for a in args {
        line.push(u16::from(b' '));
        push_arg(&mut line, a);
    }
    line.push(0);
    line
}

/// The child's environment block: exactly the variables set on the command,
/// sorted case-insensitively as Windows expects. Never empty, since a null
/// block would hand the child this process's whole environment.
fn environment_block(command: &Command) -> Vec<u16> {
    let mut vars: Vec<(OsString, OsString)> = command
        .get_envs()
        .filter_map(|(k, v)| v.map(|v| (k.to_owned(), v.to_owned())))
        .collect();
    vars.sort_by_key(|(k, _)| k.to_string_lossy().to_uppercase());
    let mut block = vec![];
    for (k, v) in vars {
        block.extend(k.encode_wide());
        block.push(u16::from(b'='));
        block.extend(v.encode_wide());
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    block
}

/// Create `command` suspended on the pseudo-console, put it in a fresh
/// kill-on-close job before it runs an instruction, then let it run. No
/// handle is inherited; the console gives the child its standard handles.
fn spawn_in_job(command: &Command, hpc: HPCON) -> io::Result<Child> {
    let path_var = command
        .get_envs()
        .find(|(k, _)| k.eq_ignore_ascii_case("PATH"))
        .and_then(|(_, v)| v);
    let program = resolve_program(command.get_program(), path_var)?;
    let args: Vec<&OsStr> = command.get_args().collect();
    let mut line = command_line(&program, &args);
    let app: Vec<u16> = program.as_os_str().encode_wide().chain([0]).collect();
    let env = environment_block(command);
    let cwd: Option<Vec<u16>> = command
        .get_current_dir()
        .map(|d| d.as_os_str().encode_wide().chain([0]).collect());

    // SAFETY: the job is created and configured here before any process
    // joins it; the handle is owned at once.
    let job = unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = OwnedHandle::from_raw_handle(job);
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let size = std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32;
        if SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        job
    };

    // SAFETY: the attribute list is sized, initialised, used and deleted
    // here; everything it and CreateProcessW point to outlives the call.
    unsafe {
        let mut size = 0usize;
        InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size);
        let mut list = vec![0u8; size];
        let attrs = list.as_mut_ptr().cast();
        if InitializeProcThreadAttributeList(attrs, 1, 0, &mut size) == 0 {
            return Err(io::Error::last_os_error());
        }
        // The attribute's value is the HPCON itself, not a pointer to it.
        let set = UpdateProcThreadAttribute(
            attrs,
            0,
            PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
            hpc as *const core::ffi::c_void,
            std::mem::size_of::<HPCON>(),
            std::ptr::null_mut(),
            std::ptr::null(),
        );
        if set == 0 {
            let e = io::Error::last_os_error();
            DeleteProcThreadAttributeList(attrs);
            return Err(e);
        }
        let mut si: STARTUPINFOEXW = std::mem::zeroed();
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        // Null standard handles: the child opens the pseudo-console's, even
        // when this process's own are pipes.
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.lpAttributeList = attrs;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let created = CreateProcessW(
            app.as_ptr(),
            line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
            env.as_ptr().cast(),
            cwd.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            &si.StartupInfo,
            &mut pi,
        );
        DeleteProcThreadAttributeList(attrs);
        if created == 0 {
            return Err(io::Error::last_os_error());
        }
        let process = OwnedHandle::from_raw_handle(pi.hProcess);
        let thread = OwnedHandle::from_raw_handle(pi.hThread);
        if AssignProcessToJobObject(job.as_raw_handle(), process.as_raw_handle()) == 0
            || ResumeThread(thread.as_raw_handle()) == u32::MAX
        {
            let e = io::Error::last_os_error();
            TerminateProcess(process.as_raw_handle(), 1);
            return Err(e);
        }
        Ok(Child {
            process,
            job,
            pid: pi.dwProcessId,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    const CHILD: &str = "RTS_TERMINAL_CHILD";

    /// Not a test of its own: the child the tests below run under ConPTY,
    /// by re-running this test binary with RTS_TERMINAL_CHILD set.
    #[test]
    fn child_helper() {
        let Ok(mode) = std::env::var(CHILD) else {
            return;
        };
        use std::io::Write;
        match mode.as_str() {
            "echo" => {
                println!("hello-from-child");
                std::process::exit(7);
            }
            "read" => {
                let mut line = String::new();
                std::io::stdin().read_line(&mut line).unwrap();
                println!("got:{}", line.trim_end());
                std::process::exit(0);
            }
            "env" => {
                let given = std::env::var("RTS_TERMINAL_GIVEN").unwrap_or_default();
                println!(
                    "computername:{} given:{given}",
                    std::env::var_os("COMPUTERNAME").is_some()
                );
                std::process::exit(0);
            }
            "spawn" => {
                let g = helper(&mut Command::new(std::env::current_exe().unwrap()), "sleep")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap();
                println!("grandchild:{}.", g.id());
                std::io::stdout().flush().unwrap();
                std::thread::sleep(Duration::from_secs(60));
                std::process::exit(0);
            }
            "sleep" => {
                std::thread::sleep(Duration::from_secs(60));
                std::process::exit(0);
            }
            other => panic!("unknown helper mode {other}"),
        }
    }

    fn helper<'a>(c: &'a mut Command, mode: &str) -> &'a mut Command {
        c.args([
            "--exact",
            "terminal::tests::child_helper",
            "--nocapture",
            "--test-threads=1",
            "-q",
        ])
        .env_clear()
        .env("SystemRoot", std::env::var_os("SystemRoot").unwrap())
        .env(CHILD, mode)
    }

    fn this_test_binary(mode: &str) -> Command {
        let mut c = Command::new(std::env::current_exe().unwrap());
        helper(&mut c, mode);
        c
    }

    struct Rig {
        child: Option<Child>,
        terminal: Option<Terminal>,
        to_input: OwnedHandle,
        seen: Arc<Mutex<Vec<u8>>>,
        reader: Option<std::thread::JoinHandle<()>>,
    }

    impl Rig {
        fn start(command: &Command) -> Self {
            let (input_r, input_w) = pipe().unwrap();
            let (output_r, output_w) = pipe().unwrap();
            let (child, terminal) = Terminal::spawn_with_io(command, input_r, output_w).unwrap();
            let seen = Arc::new(Mutex::new(vec![]));
            let sink = seen.clone();
            let reader = std::thread::spawn(move || {
                let mut f = std::fs::File::from(output_r);
                let mut buf = [0u8; 4096];
                while let Ok(n) = f.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    sink.lock().unwrap().extend_from_slice(&buf[..n]);
                }
            });
            Self {
                child: Some(child),
                terminal: Some(terminal),
                to_input: input_w,
                seen,
                reader: Some(reader),
            }
        }

        fn child(&mut self) -> &mut Child {
            self.child.as_mut().unwrap()
        }

        fn text(&self) -> String {
            String::from_utf8_lossy(&self.seen.lock().unwrap()).into_owned()
        }

        fn pump_until(&mut self, limit: Duration, mut done: impl FnMut(&mut Self) -> bool) -> bool {
            let end = Instant::now() + limit;
            while Instant::now() < end {
                self.terminal.as_mut().unwrap().pump().unwrap();
                if done(self) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            false
        }

        /// Close the terminal (draining its last output) and return all output.
        fn finish(mut self) -> String {
            drop(self.terminal.take());
            self.reader.take().unwrap().join().unwrap();
            self.text()
        }
    }

    fn exited(r: &mut Rig) -> bool {
        r.child().try_wait().unwrap().is_some()
    }

    #[test]
    fn output_reaches_the_outer_side_and_the_exit_code_is_kept() {
        let mut rig = Rig::start(&this_test_binary("echo"));
        assert!(
            rig.pump_until(Duration::from_secs(30), exited),
            "child did not exit"
        );
        let code = rig.child().wait().unwrap().code();
        let text = rig.finish();
        assert_eq!(code, Some(7), "{text}");
        assert!(text.contains("hello-from-child"), "{text:?}");
    }

    #[test]
    fn input_reaches_the_child_only_after_enable_input() {
        let mut rig = Rig::start(&this_test_binary("read"));
        write_all(&rig.to_input, b"abc\r").unwrap();
        rig.pump_until(Duration::from_millis(1500), |_| false);
        assert!(
            !rig.text().contains("got:"),
            "input passed before enable_input: {:?}",
            rig.text()
        );
        assert!(rig.child().try_wait().unwrap().is_none());
        rig.terminal.as_mut().unwrap().enable_input().unwrap();
        assert!(
            rig.pump_until(Duration::from_secs(30), exited),
            "child did not exit: {:?}",
            rig.text()
        );
        let text = rig.finish();
        assert!(text.contains("got:abc"), "{text:?}");
    }

    #[test]
    fn the_child_gets_exactly_the_commands_environment() {
        assert!(
            std::env::var_os("COMPUTERNAME").is_some(),
            "this test needs COMPUTERNAME set in the parent"
        );
        let mut command = this_test_binary("env");
        command.env("RTS_TERMINAL_GIVEN", "yes");
        let mut rig = Rig::start(&command);
        assert!(
            rig.pump_until(Duration::from_secs(30), exited),
            "child did not exit"
        );
        let text = rig.finish();
        assert!(text.contains("computername:false given:yes"), "{text:?}");
    }

    fn grandchild(rig: &mut Rig) -> u32 {
        let mut pid = None;
        let found = rig.pump_until(Duration::from_secs(30), |r| {
            let t = r.text();
            pid = t
                .split_once("grandchild:")
                .and_then(|(_, rest)| rest.split_once('.'))
                .and_then(|(n, _)| n.trim().parse().ok());
            pid.is_some()
        });
        assert!(found, "no grandchild pid: {:?}", rig.text());
        pid.unwrap()
    }

    fn ends_within(pid: u32, limit: Duration) -> bool {
        use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE};
        // SAFETY: a fresh handle we close; a null one means the process is gone.
        unsafe {
            let h = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
            if h.is_null() {
                return true;
            }
            let h = OwnedHandle::from_raw_handle(h);
            WaitForSingleObject(h.as_raw_handle(), limit.as_millis() as u32) == WAIT_OBJECT_0
        }
    }

    #[test]
    fn kill_ends_the_child_and_everything_it_started() {
        let mut rig = Rig::start(&this_test_binary("spawn"));
        let grandchild = grandchild(&mut rig);
        rig.child().kill().unwrap();
        assert!(rig.child().wait().is_ok());
        assert!(
            ends_within(grandchild, Duration::from_secs(5)),
            "grandchild {grandchild} survived the job kill"
        );
        rig.finish();
    }

    #[test]
    fn dropping_the_child_ends_its_process_tree() {
        let mut rig = Rig::start(&this_test_binary("spawn"));
        let grandchild = grandchild(&mut rig);
        drop(rig.child.take());
        assert!(
            ends_within(grandchild, Duration::from_secs(5)),
            "grandchild {grandchild} survived the job handle closing"
        );
        rig.finish();
    }

    #[test]
    fn stop_tree_waits_then_ends_the_job() {
        let mut rig = Rig::start(&this_test_binary("spawn"));
        let grandchild = grandchild(&mut rig);
        let start = Instant::now();
        stop_tree(rig.child(), Duration::from_millis(300));
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(rig.child().try_wait().unwrap().is_some());
        assert!(ends_within(grandchild, Duration::from_secs(5)));
        rig.finish();
    }

    /// Every interrupted session drops the Terminal while OpenCode's tree is
    /// still alive, and only then does teardown reach stop_tree; on a
    /// console close all of this must fit in Windows' few seconds.
    #[test]
    fn dropping_the_terminal_with_a_live_tree_is_quick_and_stop_tree_then_ends_it() {
        let mut rig = Rig::start(&this_test_binary("spawn"));
        let grandchild = grandchild(&mut rig);
        let start = Instant::now();
        drop(rig.terminal.take());
        let dropped = start.elapsed();
        eprintln!("terminal drop with a live tree took {dropped:?}");
        assert!(dropped < Duration::from_millis(2500), "{dropped:?}");
        stop_tree(rig.child(), Duration::ZERO);
        assert!(ends_within(grandchild, Duration::from_secs(5)));
        rig.reader.take().unwrap().join().unwrap();
    }

    #[test]
    fn dropping_a_terminal_without_a_drain_does_not_wait() {
        let mut rig = Rig::start(&this_test_binary("echo"));
        assert!(rig.pump_until(Duration::from_secs(30), exited));
        let mut terminal = rig.terminal.take().unwrap();
        terminal.from_pty = None;
        let start = Instant::now();
        drop(terminal);
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "{:?}",
            start.elapsed()
        );
        rig.reader.take().unwrap().join().unwrap();
    }

    /// The real OpenCode under ConPTY with exactly the session's launch
    /// environment. Needs no model or key: `debug paths` and a short look
    /// at `--standalone`. Run with RTS_OPENCODE_EXE set to opencode.exe.
    #[test]
    #[ignore = "live: needs RTS_OPENCODE_EXE"]
    fn live_real_opencode_runs_under_conpty_with_the_session_environment() {
        let exe = std::env::var("RTS_OPENCODE_EXE").expect("RTS_OPENCODE_EXE");
        let base = std::env::temp_dir().join(format!("rts-oc-{}", std::process::id()));
        let p = crate::session::session_paths("0123456789ab", &base.join("s"), &base.join("r"));
        crate::session::prepare_session_dirs(&p).unwrap();
        let launch = crate::session::opencode_launch(&p, &exe, std::env::vars());
        let command = |args: &[&str]| {
            let mut c = Command::new(&launch.argv[0]);
            c.args(args)
                .current_dir(&launch.cwd)
                .env_clear()
                .envs(launch.env.iter().map(|(k, v)| (k, v)));
            c
        };

        let mut rig = Rig::start(&command(&["debug", "paths"]));
        assert!(
            rig.pump_until(Duration::from_secs(60), exited),
            "debug paths did not exit: {:?}",
            rig.text()
        );
        let code = rig.child().wait().unwrap().code();
        let text = crate::brand::strip_escapes(&rig.finish()).replace(['\r', '\n'], "");
        assert_eq!(code, Some(0), "{text}");
        // OpenCode's home and config are the session's (TEMP stays the
        // host's, as TMPDIR does on Unix).
        let home = p.home.to_string_lossy().into_owned();
        let config = p.xdg_config.join("opencode").to_string_lossy().into_owned();
        assert!(
            text.contains(&format!("home{home}")) || text.contains(&home),
            "home is not the session's: {text}"
        );
        assert!(
            text.contains(&config),
            "config is not the session's: {text}"
        );
        // Every path OpenCode reports, tmp included, is under the session's
        // runtime directory: none is the operator's or the host's shared one.
        let tmp = p
            .runtime
            .join("tmp")
            .join("opencode")
            .to_string_lossy()
            .into_owned();
        assert!(text.contains(&tmp), "tmp is not the session's: {text}");
        let runtime = p.runtime.to_string_lossy().into_owned();
        for name in [
            "home", "data", "cache", "config", "state", "tmp", "bin", "log", "repos", "db",
        ] {
            let at = text
                .find(&format!("{name} "))
                .unwrap_or_else(|| panic!("no {name} line: {text}"));
            let rest = text[at + name.len()..].trim_start();
            assert!(
                rest.starts_with(&runtime),
                "{name} is outside the session: {}",
                &rest[..rest.len().min(120)]
            );
        }
        eprintln!("opencode debug paths under rts's env: {text}");

        let mut rig = Rig::start(&command(&["--standalone"]));
        rig.pump_until(Duration::from_secs(10), |_| false);
        let shown = rig.text().len();
        eprintln!("opencode --standalone wrote {shown} bytes in 10 s");
        assert!(shown > 0, "no output from opencode --standalone");
        let start = Instant::now();
        drop(rig.terminal.take());
        eprintln!(
            "terminal drop with opencode running took {:?}",
            start.elapsed()
        );
        let start = Instant::now();
        let mut exited_alone = false;
        while start.elapsed() < Duration::from_secs(10) {
            if rig.child().try_wait().unwrap().is_some() {
                exited_alone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        eprintln!(
            "opencode exited by itself after the pseudo-console closed: {exited_alone} ({:?})",
            start.elapsed()
        );
        stop_tree(rig.child(), Duration::ZERO);
        rig.reader.take().unwrap().join().unwrap();
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn arguments_are_quoted_for_the_msvc_parser() {
        let q = |s: &str| {
            let mut out = vec![];
            push_arg(&mut out, OsStr::new(s));
            String::from_utf16(&out).unwrap()
        };
        assert_eq!(q("--standalone"), "--standalone");
        assert_eq!(q(r"C:\dir\x"), r"C:\dir\x");
        assert_eq!(q(""), r#""""#);
        assert_eq!(q("a b"), r#""a b""#);
        assert_eq!(q(r#"a"b"#), r#""a\"b""#);
        assert_eq!(q(r"a b\"), r#""a b\\""#);
        assert_eq!(q(r#"a\"b c"#), r#""a\\\"b c""#);
        let line = command_line(
            Path::new(r"C:\Program Files\oc.exe"),
            &[OsStr::new("--standalone"), OsStr::new("x y")],
        );
        assert_eq!(
            String::from_utf16(&line[..line.len() - 1]).unwrap(),
            r#""C:\Program Files\oc.exe" --standalone "x y""#
        );
    }

    #[test]
    fn the_environment_block_holds_only_the_commands_variables() {
        let mut c = Command::new("x");
        c.env_clear().env("b", "2").env("A", "1");
        assert_eq!(
            String::from_utf16(&environment_block(&c)).unwrap(),
            "A=1\0b=2\0\0"
        );
        let mut empty = Command::new("x");
        empty.env_clear();
        assert_eq!(
            environment_block(&empty),
            [0, 0],
            "an empty block must not be null"
        );
    }

    #[test]
    fn the_program_is_found_as_a_path_or_on_the_commands_path() {
        let dir = std::env::temp_dir().join(format!("rts-term-resolve-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("tool.exe"), b"").unwrap();
        assert_eq!(
            resolve_program(OsStr::new("tool"), Some(dir.as_os_str())).unwrap(),
            dir.join("tool.exe")
        );
        assert_eq!(
            resolve_program(dir.join("tool").as_os_str(), None).unwrap(),
            dir.join("tool.exe")
        );
        assert_eq!(
            resolve_program(OsStr::new("tool"), None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        assert!(resolve_program(OsStr::new("absent"), Some(dir.as_os_str())).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn utf16_input_is_utf8_even_when_a_pair_is_split_across_reads() {
        let mut high = None;
        let mut out = vec![];
        let units: Vec<u16> = "\u{2603}\u{1F600}".encode_utf16().collect();
        utf16_to_utf8(&mut high, &units[..2], &mut out);
        assert!(high.is_some());
        utf16_to_utf8(&mut high, &units[2..], &mut out);
        assert_eq!(String::from_utf8(out).unwrap(), "\u{2603}\u{1F600}");
        let mut out = vec![];
        utf16_to_utf8(&mut None, &[0xDC00, u16::from(b'a')], &mut out);
        assert_eq!(String::from_utf8(out).unwrap(), "\u{FFFD}a");
    }
}

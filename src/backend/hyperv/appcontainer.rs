//! The confined egress proxy process on Windows: rts-egress.exe (a small,
//! separate executable) run in an AppContainer, inside a job object.
//!
//! - AppContainer: one fixed profile, `nearai.rts.egress`, created once
//!   and reused by every session (it holds no state of its own). The
//!   process gets the internetClient capability, plus
//!   privateNetworkClientServer only when the allowlist reaches a LAN
//!   address. It can read nothing the user owns: the user profile and
//!   the rest of the user's files deny an AppContainer unless an ACL
//!   names it. The only grant rts adds is read and execute on
//!   rts-egress.exe itself, for this profile's SID. The firewall's capability checks are
//!   a second layer; the proxy's own allowlist and pins decide.
//! - Job object: kill on job close (rts holds the only handle, so the
//!   proxy dies with rts however rts ends), one active process, a memory
//!   cap and no unhandled-exception dialog.
//! - Channel: the child's stdin and stdout are two anonymous pipes, the
//!   only handles it inherits (PROC_THREAD_ATTRIBUTE_HANDLE_LIST).

use std::fs::File;
use std::io;
use std::os::windows::io::FromRawHandle;
use std::path::Path;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_SUCCESS, HANDLE, HANDLE_FLAG_INHERIT, LocalFree, SetHandleInformation,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW,
    NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID,
    TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, FreeSid, NO_INHERITANCE, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_GENERIC_EXECUTE, FILE_GENERIC_READ};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, InitializeProcThreadAttributeList,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess,
    UpdateProcThreadAttribute,
};

/// The AppContainer profile every session's proxy runs in.
pub const PROFILE: &str = "nearai.rts.egress";
/// The proxy's memory cap.
pub const MEMORY_LIMIT: usize = 256 << 20;
/// The proxy executable, installed next to rts.exe.
pub const EXECUTABLE: &str = "rts-egress.exe";

/// SE_GROUP_ENABLED (winnt.h); windows-sys puts it in a feature rts does not use.
const SE_GROUP_ENABLED: u32 = 0x4;

const INTERNET_CLIENT: &str = "S-1-15-3-1";
const PRIVATE_NETWORK_CLIENT_SERVER: &str = "S-1-15-3-3";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn last_err(what: &str) -> io::Error {
    let e = io::Error::last_os_error();
    io::Error::new(e.kind(), format!("{what}: {e}"))
}

/// A SID from ConvertStringSidToSidW (LocalFree) or the AppContainer API
/// (FreeSid), freed on drop.
struct Sid(PSID, bool);

impl Drop for Sid {
    fn drop(&mut self) {
        // SAFETY: frees the SID this value owns with its allocator's free.
        unsafe {
            if self.1 {
                FreeSid(self.0);
            } else {
                LocalFree(self.0);
            }
        }
    }
}

fn string_sid(s: &str) -> io::Result<Sid> {
    let mut sid: PSID = std::ptr::null_mut();
    // SAFETY: NUL-terminated string; the SID is LocalAlloc'd and owned by Sid.
    if unsafe { ConvertStringSidToSidW(wide(s).as_ptr(), &mut sid) } == 0 {
        return Err(last_err("ConvertStringSidToSidW"));
    }
    Ok(Sid(sid, false))
}

/// The profile's SID, creating the profile the first time.
fn profile_sid() -> io::Result<Sid> {
    let name = wide(PROFILE);
    let display = wide("rts egress proxy");
    let mut sid: PSID = std::ptr::null_mut();
    // SAFETY: NUL-terminated strings; the SID is freed with FreeSid.
    let hr = unsafe {
        CreateAppContainerProfile(
            name.as_ptr(),
            display.as_ptr(),
            display.as_ptr(),
            std::ptr::null(),
            0,
            &mut sid,
        )
    };
    if hr >= 0 {
        return Ok(Sid(sid, true));
    }
    // HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS): reuse it.
    if hr as u32 != 0x800700B7 {
        return Err(io::Error::other(format!(
            "CreateAppContainerProfile: HRESULT 0x{:08X}",
            hr as u32
        )));
    }
    // SAFETY: as above.
    let hr = unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut sid) };
    if hr < 0 {
        return Err(io::Error::other(format!(
            "DeriveAppContainerSidFromAppContainerName: HRESULT 0x{:08X}",
            hr as u32
        )));
    }
    Ok(Sid(sid, true))
}

/// Let the AppContainer read and run `exe` (and nothing else rts owns).
fn grant_execute(exe: &Path, sid: &Sid) -> io::Result<()> {
    let name: Vec<u16> = {
        use std::os::windows::ffi::OsStrExt;
        exe.as_os_str().encode_wide().chain([0]).collect()
    };
    let mut old: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: out-pointers are ours; sd is LocalFree'd below.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut old,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(rc as i32));
    }
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_WELL_KNOWN_GROUP,
            ptstrName: sid.0.cast(),
        },
    };
    let mut new: *mut ACL = std::ptr::null_mut();
    // SAFETY: one entry; `new` is LocalFree'd below.
    let rc = unsafe { SetEntriesInAclW(1, &entry, old, &mut new) };
    let result = if rc != ERROR_SUCCESS {
        Err(io::Error::from_raw_os_error(rc as i32))
    } else {
        // SAFETY: `new` is a valid ACL from SetEntriesInAclW.
        let rc = unsafe {
            SetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                new,
                std::ptr::null(),
            )
        };
        if rc != ERROR_SUCCESS {
            Err(io::Error::from_raw_os_error(rc as i32))
        } else {
            Ok(())
        }
    };
    // SAFETY: both were LocalAlloc'd by the calls above.
    unsafe {
        LocalFree(sd);
        if !new.is_null() {
            LocalFree(new.cast());
        }
    }
    result
}

/// An anonymous pipe; the end handed to the child is made inheritable.
fn pipe() -> io::Result<(HANDLE, HANDLE)> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let (mut r, mut w): (HANDLE, HANDLE) = (std::ptr::null_mut(), std::ptr::null_mut());
    // SAFETY: out-pointers are ours.
    if unsafe { CreatePipe(&mut r, &mut w, &sa, 0) } == 0 {
        return Err(last_err("CreatePipe"));
    }
    Ok((r, w))
}

/// The running proxy. Dropping it closes the job, which kills the process.
pub struct Proxy {
    job: HANDLE,
    process: HANDLE,
    pub pid: u32,
}

// SAFETY: plain kernel handles.
unsafe impl Send for Proxy {}

impl Proxy {
    /// The exit code once the process has ended, else `None`.
    pub fn exit_code(&self) -> Option<u32> {
        use windows_sys::Win32::System::Threading::GetExitCodeProcess;
        const STILL_ACTIVE: u32 = 259;
        let mut code = 0u32;
        // SAFETY: a valid process handle we own.
        if unsafe { GetExitCodeProcess(self.process, &mut code) } == 0 || code == STILL_ACTIVE {
            return None;
        }
        Some(code)
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        // SAFETY: handles this value owns; closing the job kills the process.
        unsafe {
            TerminateProcess(self.process, 1);
            CloseHandle(self.process);
            CloseHandle(self.job);
        }
    }
}

/// Start `exe args...` confined (rts runs rts-egress.exe); returns
/// the process and rts's ends of its stdin (write) and stdout (read).
pub fn spawn(exe: &Path, args: &[&str], private_network: bool) -> io::Result<(Proxy, File, File)> {
    let container = profile_sid()?;
    grant_execute(exe, &container).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("granting the proxy access to {}: {e}", exe.display()),
        )
    })?;
    let internet = string_sid(INTERNET_CLIENT)?;
    let private = string_sid(PRIVATE_NETWORK_CLIENT_SERVER)?;
    let mut caps = vec![SID_AND_ATTRIBUTES {
        Sid: internet.0,
        Attributes: SE_GROUP_ENABLED,
    }];
    if private_network {
        caps.push(SID_AND_ATTRIBUTES {
            Sid: private.0,
            Attributes: SE_GROUP_ENABLED,
        });
    }
    let mut security = SECURITY_CAPABILITIES {
        AppContainerSid: container.0,
        Capabilities: caps.as_mut_ptr(),
        CapabilityCount: caps.len() as u32,
        Reserved: 0,
    };

    let (child_in, rts_in) = pipe()?; // rts writes, child reads
    let (rts_out, child_out) = pipe()?; // child writes, rts reads
    // SAFETY: rts's ends must not be inherited.
    unsafe {
        SetHandleInformation(rts_in, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(rts_out, HANDLE_FLAG_INHERIT, 0);
    }
    let close = |h: HANDLE| unsafe { CloseHandle(h) };

    let result = (|| -> io::Result<Proxy> {
        // SAFETY: the attribute list is sized, initialised, updated and
        // deleted here; everything it points to outlives CreateProcessW.
        unsafe {
            let mut size = 0usize;
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut size);
            let mut list = vec![0u8; size];
            let attrs = list.as_mut_ptr().cast();
            if InitializeProcThreadAttributeList(attrs, 2, 0, &mut size) == 0 {
                return Err(last_err("InitializeProcThreadAttributeList"));
            }
            let inherit = [child_in, child_out];
            let ok = UpdateProcThreadAttribute(
                attrs,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                (&security as *const SECURITY_CAPABILITIES).cast(),
                std::mem::size_of::<SECURITY_CAPABILITIES>(),
                std::ptr::null_mut(),
                std::ptr::null(),
            ) != 0
                && UpdateProcThreadAttribute(
                    attrs,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    inherit.as_ptr().cast(),
                    std::mem::size_of_val(&inherit),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                ) != 0;
            if !ok {
                let e = last_err("UpdateProcThreadAttribute");
                DeleteProcThreadAttributeList(attrs);
                return Err(e);
            }
            let mut si: STARTUPINFOEXW = std::mem::zeroed();
            si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
            si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            si.StartupInfo.hStdInput = child_in;
            si.StartupInfo.hStdOutput = child_out;
            si.StartupInfo.hStdError = child_out;
            si.lpAttributeList = attrs;
            let app: Vec<u16> = {
                use std::os::windows::ffi::OsStrExt;
                exe.as_os_str().encode_wide().chain([0]).collect()
            };
            let mut cmd = wide(
                &std::iter::once(format!("\"{}\"", exe.display()))
                    .chain(args.iter().map(|a| a.to_string()))
                    .collect::<Vec<_>>()
                    .join(" "),
            );
            let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
            let created = CreateProcessW(
                app.as_ptr(),
                cmd.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW,
                std::ptr::null(),
                std::ptr::null(),
                &si.StartupInfo,
                &mut pi,
            );
            DeleteProcThreadAttributeList(attrs);
            let _ = &mut security;
            if created == 0 {
                return Err(last_err("CreateProcessW (AppContainer)"));
            }
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            let proxy = Proxy {
                job,
                process: pi.hProcess,
                pid: pi.dwProcessId,
            };
            if job.is_null() {
                TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hThread);
                return Err(last_err("CreateJobObjectW"));
            }
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                | JOB_OBJECT_LIMIT_PROCESS_MEMORY
                | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
            limits.BasicLimitInformation.ActiveProcessLimit = 1;
            limits.ProcessMemoryLimit = MEMORY_LIMIT;
            let limited = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) != 0;
            // Into the job before it runs a single instruction.
            if !limited || AssignProcessToJobObject(job, pi.hProcess) == 0 {
                let e = last_err("job object");
                CloseHandle(pi.hThread);
                return Err(e); // drop(proxy) terminates the suspended process
            }
            ResumeThread(pi.hThread);
            CloseHandle(pi.hThread);
            Ok(proxy)
        }
    })();
    // The child's ends now belong to the child (or to nobody).
    close(child_in);
    close(child_out);
    match result {
        // SAFETY: rts's ends are owned by the returned Files.
        Ok(proxy) => Ok((proxy, unsafe { File::from_raw_handle(rts_in) }, unsafe {
            File::from_raw_handle(rts_out)
        })),
        Err(e) => {
            close(rts_in);
            close(rts_out);
            Err(e)
        }
    }
}

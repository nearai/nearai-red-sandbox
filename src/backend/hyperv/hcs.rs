//! The Host Compute Service (computecore.dll): create, start, query and
//! terminate one compute system. Every call runs through an HCS operation
//! that is waited on with a timeout; a failed HRESULT carries the result
//! document HCS returned, which explains it.
//!
//! computecore.dll is loaded at run time (from System32 only), not linked:
//! it exists only where Hyper-V is installed, and a load-time import would
//! stop rts.exe from starting at all on Windows Home or with Hyper-V off,
//! before rts could say why.

use std::io;
use std::sync::OnceLock;
use std::time::Duration;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::System::HostComputeSystem::{
    HCS_OPERATION, HCS_OPERATION_COMPLETION, HCS_SYSTEM,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::core::{HRESULT, PCWSTR, PWSTR};

type CreateOperationFn =
    unsafe extern "system" fn(*const core::ffi::c_void, HCS_OPERATION_COMPLETION) -> HCS_OPERATION;
type CloseOperationFn = unsafe extern "system" fn(HCS_OPERATION);
type WaitFn = unsafe extern "system" fn(HCS_OPERATION, u32, *mut PWSTR) -> HRESULT;
type CreateFn = unsafe extern "system" fn(
    PCWSTR,
    PCWSTR,
    HCS_OPERATION,
    *const windows_sys::Win32::Security::SECURITY_DESCRIPTOR,
    *mut HCS_SYSTEM,
) -> HRESULT;
type OpenFn = unsafe extern "system" fn(PCWSTR, u32, *mut HCS_SYSTEM) -> HRESULT;
type SystemOpFn = unsafe extern "system" fn(HCS_SYSTEM, HCS_OPERATION, PCWSTR) -> HRESULT;
type CloseSystemFn = unsafe extern "system" fn(HCS_SYSTEM);
type EnumerateFn = unsafe extern "system" fn(PCWSTR, HCS_OPERATION) -> HRESULT;

/// The computecore.dll entry points rts uses (signatures as windows-sys
/// declares them).
#[allow(non_snake_case)]
struct Api {
    HcsCreateOperation: CreateOperationFn,
    HcsCloseOperation: CloseOperationFn,
    HcsWaitForOperationResult: WaitFn,
    HcsCreateComputeSystem: CreateFn,
    HcsOpenComputeSystem: OpenFn,
    HcsStartComputeSystem: SystemOpFn,
    HcsTerminateComputeSystem: SystemOpFn,
    HcsCloseComputeSystem: CloseSystemFn,
    HcsGetComputeSystemProperties: SystemOpFn,
    HcsEnumerateComputeSystems: EnumerateFn,
}

/// Why HCS is unusable on this host, if it is.
pub const NO_HYPERV: &str = "Hyper-V is not available on this computer (computecore.dll is missing): enable the Hyper-V feature, or use Windows 11 Pro, Enterprise or Education";

fn api() -> io::Result<&'static Api> {
    static API: OnceLock<Result<Api, String>> = OnceLock::new();
    API.get_or_init(load)
        .as_ref()
        .map_err(|e| io::Error::other(e.clone()))
}

fn load() -> Result<Api, String> {
    let name: Vec<u16> = "computecore.dll".encode_utf16().chain([0]).collect();
    // SAFETY: System32-only search for a NUL-terminated name; the module is
    // never freed, so the function pointers stay valid for the process.
    let module = unsafe {
        LoadLibraryExW(
            name.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if module.is_null() {
        return Err(NO_HYPERV.into());
    }
    macro_rules! get {
        ($f:ident: $t:ty) => {{
            // SAFETY: the name is NUL-terminated; a found symbol has the
            // signature windows-sys declares for it (the field's type).
            match unsafe { GetProcAddress(module, concat!(stringify!($f), "\0").as_ptr()) } {
                Some(p) => unsafe {
                    std::mem::transmute::<unsafe extern "system" fn() -> isize, $t>(p)
                },
                None => return Err(format!("computecore.dll has no {}", stringify!($f))),
            }
        }};
    }
    Ok(Api {
        HcsCreateOperation: get!(HcsCreateOperation: CreateOperationFn),
        HcsCloseOperation: get!(HcsCloseOperation: CloseOperationFn),
        HcsWaitForOperationResult: get!(HcsWaitForOperationResult: WaitFn),
        HcsCreateComputeSystem: get!(HcsCreateComputeSystem: CreateFn),
        HcsOpenComputeSystem: get!(HcsOpenComputeSystem: OpenFn),
        HcsStartComputeSystem: get!(HcsStartComputeSystem: SystemOpFn),
        HcsTerminateComputeSystem: get!(HcsTerminateComputeSystem: SystemOpFn),
        HcsCloseComputeSystem: get!(HcsCloseComputeSystem: CloseSystemFn),
        HcsGetComputeSystemProperties: get!(HcsGetComputeSystemProperties: SystemOpFn),
        HcsEnumerateComputeSystems: get!(HcsEnumerateComputeSystems: EnumerateFn),
    })
}

/// Whether HCS can be used here (for preflight).
pub fn available() -> io::Result<()> {
    api().map(|_| ())
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

/// # Safety
/// `p` is null or a NUL-terminated LocalAlloc'd wide string, freed here.
unsafe fn take(p: PWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: per the contract above.
    unsafe {
        let n = (0..).take_while(|&i| *p.add(i) != 0).count();
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, n));
        LocalFree(p.cast());
        s
    }
}

/// Run one HCS call through a fresh operation and return its result document.
fn call(
    what: &str,
    timeout: Duration,
    start: impl FnOnce(&Api, HCS_OPERATION) -> HRESULT,
) -> io::Result<String> {
    let api = api()?;
    // SAFETY: the operation is created here and closed on every path below.
    unsafe {
        let op = (api.HcsCreateOperation)(std::ptr::null(), None);
        if op.is_null() {
            return Err(io::Error::other(format!(
                "{what}: cannot create an HCS operation"
            )));
        }
        let hr = start(api, op);
        let result = if hr < 0 {
            Err(io::Error::other(format!(
                "{what}: HRESULT 0x{:08X}",
                hr as u32
            )))
        } else {
            let mut doc: PWSTR = std::ptr::null_mut();
            let ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
            let hr = (api.HcsWaitForOperationResult)(op, ms, &mut doc);
            let doc = take(doc);
            if hr < 0 {
                Err(io::Error::other(format!(
                    "{what}: HRESULT 0x{:08X} {doc}",
                    hr as u32
                )))
            } else {
                Ok(doc)
            }
        };
        (api.HcsCloseOperation)(op);
        result
    }
}

/// A compute system handle. Dropping it closes the handle, which (with the
/// document's ShouldTerminateOnLastHandleClosed) also stops the VM.
pub struct ComputeSystem(HCS_SYSTEM);

// SAFETY: HCS handles may be used from any thread.
unsafe impl Send for ComputeSystem {}
unsafe impl Sync for ComputeSystem {}

const TIMEOUT: Duration = Duration::from_secs(60);

impl ComputeSystem {
    pub fn create(id: &str, document: &str) -> io::Result<Self> {
        let (id, doc) = (wide(id), wide(document));
        let mut system: HCS_SYSTEM = std::ptr::null_mut();
        // SAFETY: both strings are NUL-terminated and outlive the call.
        let created = call("create compute system", TIMEOUT, |api, op| unsafe {
            (api.HcsCreateComputeSystem)(
                id.as_ptr(),
                doc.as_ptr(),
                op,
                std::ptr::null(),
                &mut system,
            )
        });
        // HCS may hand back a handle even when the operation then fails:
        // own it first, so an error path closes it (an open handle keeps the
        // VM alive).
        let owned = (!system.is_null()).then_some(Self(system));
        created?;
        owned.ok_or_else(|| io::Error::other("create compute system: no handle"))
    }

    /// Open an existing compute system by id (for the sweep), or `None` if
    /// no system with that id exists.
    pub fn open(id: &str) -> io::Result<Option<Self>> {
        const GENERIC_ALL: u32 = 0x1000_0000;
        let api = api()?;
        let id = wide(id);
        let mut system: HCS_SYSTEM = std::ptr::null_mut();
        // SAFETY: `id` is NUL-terminated; the handle is owned on success.
        let hr = unsafe { (api.HcsOpenComputeSystem)(id.as_ptr(), GENERIC_ALL, &mut system) };
        if hr < 0 || system.is_null() {
            return Ok(None);
        }
        Ok(Some(Self(system)))
    }

    /// Whether the VM runs, or how it stopped.
    pub fn state(&self) -> io::Result<super::props::VmState> {
        super::props::state(&self.properties("{}")?).map_err(io::Error::other)
    }

    /// MiB of host memory assigned to the VM.
    pub fn assigned_memory_mib(&self) -> io::Result<u64> {
        super::props::assigned_memory_mib(&self.properties(r#"{"PropertyTypes":["Memory"]}"#)?)
            .map_err(io::Error::other)
    }

    pub fn start(&self) -> io::Result<()> {
        // SAFETY: a valid handle; null options.
        call("start compute system", TIMEOUT, |api, op| unsafe {
            (api.HcsStartComputeSystem)(self.0, op, std::ptr::null())
        })
        .map(|_| ())
    }

    pub fn terminate(&self) -> io::Result<()> {
        // SAFETY: a valid handle; null options.
        call("terminate compute system", TIMEOUT, |api, op| unsafe {
            (api.HcsTerminateComputeSystem)(self.0, op, std::ptr::null())
        })
        .map(|_| ())
    }

    /// The properties document for `query` (an HCS PropertyQuery JSON).
    pub fn properties(&self, query: &str) -> io::Result<String> {
        let q = wide(query);
        // SAFETY: a valid handle; `q` is NUL-terminated and outlives the call.
        call("compute system properties", TIMEOUT, |api, op| unsafe {
            (api.HcsGetComputeSystemProperties)(self.0, op, q.as_ptr())
        })
    }
}

impl Drop for ComputeSystem {
    fn drop(&mut self) {
        // A ComputeSystem exists only if the API loaded.
        if let Ok(api) = api() {
            // SAFETY: closes the handle this value owns, once.
            unsafe { (api.HcsCloseComputeSystem)(self.0) };
        }
    }
}

/// Compute systems matching `query` (e.g. `{"Owners":["rts"]}`), as HCS's JSON array.
pub fn enumerate(query: &str) -> io::Result<String> {
    let q = wide(query);
    // SAFETY: `q` is NUL-terminated and outlives the call.
    call("enumerate compute systems", TIMEOUT, |api, op| unsafe {
        (api.HcsEnumerateComputeSystems)(q.as_ptr(), op)
    })
}

//! The backend seam. The launcher and the tool bridge talk to these
//! traits, never to mvmctl directly.

use std::fmt;
use std::path::Path;

pub use crate::protocol::ParsedResult as ExecResult;
use crate::untar::TarRejected;

#[derive(Debug, Clone, Default)]
pub struct ExecOptions {
    pub timeout_ms: u64,
    pub max_output_bytes: u64,
    /// Guest directory to run in, applied by `cd` inside the guest wrapper.
    pub workdir: Option<String>,
}

impl ExecOptions {
    pub fn new(timeout_ms: u64, max_output_bytes: u64) -> Self {
        Self { timeout_ms, max_output_bytes, workdir: None }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CopyOutResult {
    Exported { files: u64, bytes: u64 },
    NothingToExport,
}

#[derive(Debug)]
pub enum Error {
    /// The machine is gone or can no longer be trusted to run commands.
    /// Every later call on the same sandbox fails the same way; nothing
    /// falls back to the host.
    Unavailable(String),
    /// A hostile archive from the guest was refused.
    Rejected(TarRejected),
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Unavailable(r) => write!(f, "sandbox unavailable: {r}"),
            Error::Rejected(r) => write!(f, "{r}"),
            Error::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<TarRejected> for Error {
    fn from(r: TarRejected) -> Self {
        Error::Rejected(r)
    }
}

impl From<String> for Error {
    fn from(m: String) -> Self {
        Error::Other(m)
    }
}

impl From<&str> for Error {
    fn from(m: &str) -> Self {
        Error::Other(m.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub trait Exec {
    fn exec(&self, argv: &[String], opts: &ExecOptions) -> Result<ExecResult>;
}

/// Guest egress for one machine: the resolved `--allow-host` values, the
/// 0600 file that takes the attached `machine run` output, and the session
/// limit that sets its `--ttl`.
pub struct Egress<'a> {
    pub allow_hosts: &'a [crate::network::AllowHost],
    pub attach_log: &'a Path,
    pub session_hours: u32,
}

pub struct CreateSpec<'a> {
    pub name: &'a str,
    pub image: &'a str,
    pub memory_mib: u32,
    pub cpus: u32,
    /// `None` is no network: `machine start`, and no `--allow-host`.
    pub egress: Option<Egress<'a>>,
}

pub trait Sandbox: Exec {
    fn create(&self, spec: &CreateSpec) -> Result<()>;
    fn copy_in(&self, host_dir: &Path, guest_dir: &str) -> Result<()>;
    fn copy_out(&self, guest_dir: &str, host_dir: &Path) -> Result<CopyOutResult>;
    fn remove(&self) -> Result<()>;
}

/// argv helper: `sv(&["a", "b"])`.
pub fn sv(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

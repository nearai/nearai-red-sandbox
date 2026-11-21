//! The isolation backend a session runs on, chosen per OS.
//!
//! `sandbox::Sandbox` is the exec/copy seam. This module adds what a whole
//! session needs from a backend beyond it: host checks before any machine
//! command, the orphan sweep, a machine handle, the egress path's liveness
//! and evidence, the VMM process to hold to the host RSS ceiling, and the
//! teardown residue. `launch::run` and `LaunchSpec` do not change; the
//! session talks to these traits. See docs/design/linux-windows-backends.md.

use std::path::Path;

use crate::config::{OperatorConfig, ProviderConfig};
use crate::network::Plan;
use crate::sandbox::Sandbox;
use crate::session::{Clock, Deps, Host, SessionPaths};

#[cfg(test)]
mod invariants;
pub mod kvm;
pub mod mvm;

/// IPs the egress path pinned for each allowlisted name.
pub type Pinned = std::collections::BTreeMap<String, std::collections::BTreeSet<std::net::IpAddr>>;

/// The backend-neutral inputs to the launch preflight.
pub struct HostCheck<'a> {
    pub host: &'a dyn Host,
    pub opencode: &'a str,
    pub leak_seam_set: bool,
    pub work_dir: Option<&'a Path>,
    pub provider: &'a ProviderConfig,
}

pub trait Backend {
    /// The launch preflight: OpenCode, the backend's VMM prerequisites,
    /// the work directory and the provider, in that order.
    fn preflight(&self, check: &HostCheck) -> Result<(), String>;
    /// Host configuration that could grant the guest egress outside rts's
    /// control. Runs on every launch, before any machine command.
    fn check_host_config(&self) -> Result<(), String>;
    /// Report (never delete) machines left by earlier launches.
    fn sweep(&self, log: &mut dyn FnMut(&str)) -> Result<(), String>;
    /// A handle for the machine `name`, before it is created.
    fn machine(&self, name: &str) -> Result<Box<dyn Machine>, String>;
}

pub trait Machine: Sandbox {
    /// After a network machine is created: find and hold the processes
    /// of its egress path, refusing when they cannot be confirmed.
    fn track_network(&self) -> Result<(), String>;
    /// `Some(reason)` once the egress path is gone; the session must end.
    fn network_lost(&self) -> Option<String>;
    /// Wait until the egress audit shows a pin for each name in `plan`.
    fn wait_for_pins(&self, plan: &Plan, clock: &Clock) -> Result<Pinned, String>;
    /// The VMM process held to the host RSS ceiling.
    fn monitor(&self) -> Result<Box<dyn Monitor>, String>;
    /// After `remove`: kill egress-path residue and copy this machine's
    /// egress audit to `network_audit`. Never fails; it logs.
    fn finish(&self, network_audit: &Path, log: &dyn Fn(&str));
}

pub trait Monitor {
    /// The VMM's host RSS in MiB, refusing over `ceiling_mib` or when the
    /// process can no longer be confirmed.
    fn sample(&self, ceiling_mib: u64) -> Result<u64, String>;
    /// Which process is sampled and how it was found, for the log.
    fn describe(&self) -> String;
}

/// The backend for this host's OS, for the launch preflight only.
pub fn for_preflight(
    cfg: &OperatorConfig,
    env: &[(String, String)],
    empty_git_config: std::path::PathBuf,
) -> Result<Box<dyn Backend>, String> {
    Ok(Box::new(mvm::MvmBackend::for_preflight(
        cfg,
        env,
        empty_git_config,
    )?))
}

/// The backend for this host's OS.
pub fn for_session(
    cfg: &OperatorConfig,
    deps: &Deps,
    paths: &SessionPaths,
) -> Result<Box<dyn Backend>, String> {
    Ok(Box::new(mvm::MvmBackend::for_session(cfg, deps, paths)?))
}

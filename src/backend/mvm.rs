//! The mvm backend: one mvm microVM per session, driven by `mvmctl`.
//! Two flavors: HVF on Apple-silicon macOS (with rts's patched
//! supervisor), and Firecracker on Linux/KVM (see `kvm.rs`). This adapts
//! the existing mvm plumbing in `mvm.rs`, `session.rs` and `network.rs`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::kvm;
use super::{Backend, HostCheck, Machine, Monitor, Pinned};
use crate::config::OperatorConfig;
use crate::copy::CopyLimits;
use crate::mvm::{Launch, MvmSandbox, Runner, SpawnRunner};
use crate::network::Plan;
use crate::sandbox::{
    CopyOutResult, CreateSpec, Exec, ExecOptions, ExecResult, Result as SandboxResult, Sandbox, sv,
};
use crate::session::{self, Clock, Deps, Host, PreflightInput, SessionPaths};

/// Which hypervisor mvm drives on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    /// Hypervisor.framework, through rts's patched `mvm-hvf-supervisor`.
    Hvf,
    /// Firecracker on `/dev/kvm`, never as root.
    Firecracker,
}

#[cfg(test)]
thread_local! {
    static UNIT_TEST_FLAVOR: std::cell::Cell<Flavor> = const { std::cell::Cell::new(Flavor::Hvf) };
}

impl Flavor {
    /// The flavor sessions on this host use: [`Flavor::native`]. In this
    /// crate's unit tests it is HVF on every OS, because their fake mvmctl
    /// and host replies are HVF-shaped; the Firecracker flavor is tested
    /// directly (`for_session_flavor`, `backend::invariants`).
    pub fn host() -> Self {
        #[cfg(test)]
        {
            UNIT_TEST_FLAVOR.with(|f| f.get())
        }
        #[cfg(not(test))]
        {
            Self::native()
        }
    }

    /// Firecracker on Linux, HVF everywhere else.
    pub fn native() -> Self {
        if cfg!(target_os = "linux") {
            Self::Firecracker
        } else {
            Self::Hvf
        }
    }

    /// The PID file mvm writes in `<mvm root>/vms/<machine>/`.
    pub fn pid_file(self) -> &'static str {
        match self {
            Self::Hvf => "hvf.pid",
            Self::Firecracker => "fc.pid",
        }
    }

    /// The VMM executable held to the host RSS ceiling.
    pub fn vmm(self) -> &'static str {
        match self {
            Self::Hvf => "mvm-hvf-supervisor",
            Self::Firecracker => "firecracker",
        }
    }

    fn vmm_label(self) -> &'static str {
        match self {
            Self::Hvf => "HVF supervisor",
            Self::Firecracker => "Firecracker",
        }
    }

    /// How host processes are named: `ps -o comm=` on macOS; on Linux,
    /// where comm is capped at 15 characters, `/proc/<pid>/exe`.
    pub fn name_of(self) -> session::NameOf {
        match self {
            Self::Hvf => session::process_name,
            Self::Firecracker => session::exe_name,
        }
    }

    /// The processes that carry guest egress, which teardown kills if any
    /// outlive the machine. HVF: the attached `machine run`'s children.
    /// Firecracker: the endpoints mvm started for the VM's state directory
    /// ([`kvm::firecracker_endpoints`]) and the VMM from `fc.pid`.
    pub fn network_processes(self) -> &'static [&'static str] {
        match self {
            Self::Hvf => &session::NETWORK_PROCESSES,
            Self::Firecracker => &[session::ENDPOINT, "firecracker"],
        }
    }
}

pub struct MvmBackend {
    flavor: Flavor,
    run: Arc<dyn Runner>,
    host: Arc<dyn Host>,
    mvmctl: PathBuf,
    /// The patched HVF supervisor; Firecracker has none.
    supervisor: Option<PathBuf>,
    /// The KVM device Firecracker needs.
    kvm: PathBuf,
    env: Vec<(String, String)>,
}

impl MvmBackend {
    /// The backend for one session on this host's flavor.
    pub fn for_session(
        cfg: &OperatorConfig,
        deps: &Deps,
        paths: &SessionPaths,
    ) -> Result<Self, String> {
        Self::for_session_flavor(Flavor::host(), cfg, deps, paths)
    }

    /// HVF: the patched supervisor resolved from the operator environment
    /// and install prefix. Firecracker: the non-elevating `sudo` first on
    /// mvmctl's PATH, in the session's private runtime directory. Either
    /// way `deps.runner`, or else mvmctl from the config.
    pub fn for_session_flavor(
        flavor: Flavor,
        cfg: &OperatorConfig,
        deps: &Deps,
        paths: &SessionPaths,
    ) -> Result<Self, String> {
        let shim_dir = paths.runtime.join("sudo-shim");
        let supervisor = match flavor {
            Flavor::Hvf => {
                let install_prefix = deps
                    .tool_command
                    .first()
                    .map(Path::new)
                    .and_then(crate::install::install_prefix);
                Some(session::supervisor_path(
                    &deps.env,
                    install_prefix.as_deref(),
                )?)
            }
            Flavor::Firecracker => None,
        };
        let run: Arc<dyn Runner> = match deps.runner.clone() {
            Some(run) => run,
            None => Arc::new(SpawnRunner {
                mvmctl: cfg.mvmctl.clone(),
                empty_git_config: paths.empty_git_config.clone(),
                extra_env: Self::mvmctl_environment(
                    flavor,
                    &deps.env,
                    supervisor.as_deref(),
                    &shim_dir,
                )?,
                remove_env: Vec::new(),
            }),
        };
        Ok(Self {
            flavor,
            run,
            host: deps.host.clone(),
            mvmctl: cfg.mvmctl.clone(),
            supervisor,
            kvm: kvm::KVM_DEVICE.into(),
            env: deps.env.clone(),
        })
    }

    /// The backend for the launch preflight, before credentials: the
    /// supervisor from this binary's install prefix, mvmctl from the config
    /// with `empty_git_config` (and on Firecracker the shim beside it).
    /// Its checks run on `HostCheck::host`.
    pub fn for_preflight(
        cfg: &OperatorConfig,
        env: &[(String, String)],
        empty_git_config: PathBuf,
    ) -> Result<Self, String> {
        let flavor = Flavor::host();
        let supervisor = match flavor {
            Flavor::Hvf => Some(session::supervisor_path(
                env,
                crate::install::current_prefix().as_deref(),
            )?),
            Flavor::Firecracker => None,
        };
        let shim_dir = empty_git_config
            .parent()
            .map(|p| p.join("sudo-shim"))
            .ok_or("the preflight Git configuration has no parent directory")?;
        let extra_env = Self::mvmctl_environment(flavor, env, supervisor.as_deref(), &shim_dir)?;
        let run = Arc::new(SpawnRunner {
            mvmctl: cfg.mvmctl.clone(),
            empty_git_config,
            extra_env,
            remove_env: Vec::new(),
        });
        Ok(Self {
            flavor,
            run,
            host: Arc::new(session::RealHost),
            mvmctl: cfg.mvmctl.clone(),
            supervisor,
            kvm: kvm::KVM_DEVICE.into(),
            env: env.to_vec(),
        })
    }

    /// mvmctl's extra environment for `flavor`: on HVF the patched
    /// supervisor, on Firecracker the non-elevating `sudo` (installed in
    /// `shim_dir`) and no standby pool.
    pub fn mvmctl_environment(
        flavor: Flavor,
        env: &[(String, String)],
        supervisor: Option<&Path>,
        shim_dir: &Path,
    ) -> Result<std::collections::HashMap<String, String>, String> {
        match (flavor, supervisor) {
            (Flavor::Hvf, Some(supervisor)) => Ok(session::mvm_environment(env, supervisor)),
            (Flavor::Hvf, None) => Err("the HVF flavor needs the patched supervisor".into()),
            (Flavor::Firecracker, _) => Ok(kvm::firecracker_environment(
                env,
                &kvm::install_sudo_shim(shim_dir)?,
            )),
        }
    }

    /// Use `device` instead of `/dev/kvm` (tests).
    #[cfg(test)]
    pub(crate) fn with_kvm(mut self, device: &Path) -> Self {
        self.kvm = device.to_path_buf();
        self
    }
}

impl Backend for MvmBackend {
    fn preflight(&self, c: &HostCheck) -> Result<(), String> {
        let input = PreflightInput {
            host: c.host,
            run: self.run.as_ref(),
            mvmctl: &self.mvmctl,
            opencode: c.opencode,
            leak_seam_set: c.leak_seam_set,
            supervisor_path: self.supervisor.as_deref(),
            work_dir: c.work_dir,
            provider: c.provider,
        };
        match self.flavor {
            Flavor::Hvf => session::preflight(&input),
            Flavor::Firecracker => session::preflight_with(&input, &|| kvm::check_kvm(&self.kvm)),
        }
    }

    fn check_host_config(&self) -> Result<(), String> {
        let root = session::mvm_root(&self.env)?;
        crate::network::check_mvm_host(&self.env, &root)
    }

    fn sweep(&self, log: &mut dyn FnMut(&str)) -> Result<(), String> {
        session::sweep_orphans(&self.run, log).map(|_| ())
    }

    fn machine(&self, name: &str) -> Result<Box<dyn Machine>, String> {
        // The launcher's handle does not share the state dir's marker: teardown
        // marks every tool process's view unavailable first, then still exports.
        let sb = MvmSandbox::new(name, Box::new(self.run.clone()))
            .map_err(|e| e.to_string())?
            .with_copy_limits(CopyLimits::default())
            .with_launch(self.launch_for(name)?);
        Ok(Box::new(MvmMachine {
            flavor: self.flavor,
            sb,
            host: self.host.clone(),
            env: self.env.clone(),
            network_pids: Mutex::new(Vec::new()),
        }))
    }
}

impl MvmBackend {
    /// How this flavor's network machines wait for their attached run:
    /// [`Launch::AttachLine`] on Firecracker (mvm 0.28), reading the TTL
    /// from `<mvm root>/share/vm-names.json`; [`Launch::PollPs`] on HVF.
    pub(crate) fn launch_for(&self, name: &str) -> Result<Launch, String> {
        match self.flavor {
            Flavor::Hvf => Ok(Launch::PollPs),
            Flavor::Firecracker => {
                let root = session::mvm_root(&self.env)
                    .map_err(|e| format!("cannot launch {name}: {e}"))?;
                Ok(Launch::AttachLine {
                    registry: root.join("share").join("vm-names.json"),
                    vm_dir: root.join("vms").join(name),
                })
            }
        }
    }
}

pub struct MvmMachine {
    flavor: Flavor,
    sb: MvmSandbox,
    host: Arc<dyn Host>,
    env: Vec<(String, String)>,
    /// The attach process's egress-path children, checked after removal.
    network_pids: Mutex<Vec<u32>>,
}

impl MvmMachine {
    /// An HVF handle built from parts, for session teardown tests.
    #[cfg(test)]
    pub(crate) fn from_parts(
        sb: MvmSandbox,
        host: Arc<dyn Host>,
        env: Vec<(String, String)>,
        network_pids: Vec<u32>,
    ) -> Self {
        Self {
            flavor: Flavor::Hvf,
            sb,
            host,
            env,
            network_pids: Mutex::new(network_pids),
        }
    }
}

impl MvmMachine {
    /// Firecracker's VMM from its PID file, refused unless it runs as
    /// this user and not as root.
    fn unprivileged_vmm(&self) -> Result<session::Supervisor, String> {
        let label = self.flavor.vmm_label();
        let root =
            session::mvm_root(&self.env).map_err(|e| format!("cannot monitor {label}: {e}"))?;
        let pid_file = root
            .join("vms")
            .join(&self.sb.name)
            .join(self.flavor.pid_file());
        let vmm = session::Supervisor::discover_vmm(
            &pid_file,
            self.flavor.vmm(),
            label,
            self.flavor.name_of(),
        )?;
        kvm::check_vmm_uid(self.host.as_ref(), vmm.pid, kvm::current_uid())?;
        Ok(vmm)
    }
}

impl Exec for MvmMachine {
    fn exec(&self, argv: &[String], opts: &ExecOptions) -> SandboxResult<ExecResult> {
        self.sb.exec(argv, opts)
    }
}

impl Sandbox for MvmMachine {
    fn create(&self, spec: &CreateSpec) -> SandboxResult<()> {
        self.sb.create(spec)?;
        // No root VM gets past create: before probes, /in or canaries.
        if self.flavor == Flavor::Firecracker {
            self.unprivileged_vmm()?;
        }
        Ok(())
    }
    fn copy_in(&self, host_dir: &Path, guest_dir: &str) -> SandboxResult<()> {
        self.sb.copy_in(host_dir, guest_dir)
    }
    fn copy_out(&self, guest_dir: &str, host_dir: &Path) -> SandboxResult<CopyOutResult> {
        self.sb.copy_out(guest_dir, host_dir)
    }
    fn remove(&self) -> SandboxResult<()> {
        self.sb.remove()
    }
}

impl Machine for MvmMachine {
    fn track_network(&self) -> Result<(), String> {
        let attach = self
            .sb
            .attach_pid()
            .ok_or("network machine has no attached mvmctl machine run")?;
        let pids = match self.flavor {
            Flavor::Hvf => session::network_children_of(
                self.host.as_ref(),
                attach,
                self.flavor.network_processes(),
                self.flavor.name_of(),
            )?,
            // mvm 0.28 detaches the endpoint from `machine run` (setsid), so
            // it is found by the state directory it serves, not its parent.
            Flavor::Firecracker => {
                let root = session::mvm_root(&self.env)
                    .map_err(|e| format!("cannot find the network processes: {e}"))?;
                let mut pids = kvm::firecracker_endpoints(
                    &kvm::list_processes(Path::new("/proc")),
                    &root.join("vms").join(&self.sb.name),
                    kvm::current_uid(),
                )?;
                pids.push(self.unprivileged_vmm()?.pid);
                pids
            }
        };
        *self.network_pids.lock().unwrap() = pids;
        Ok(())
    }

    fn network_lost(&self) -> Option<String> {
        if let Some(lost) = self.sb.network_lost() {
            return Some(lost);
        }
        // Firecracker's endpoints and VMM are not children of the attached
        // run, so its exit alone may miss them: each tracked pid must still
        // name one of them.
        if self.flavor == Flavor::Firecracker {
            let names = self.flavor.network_processes();
            for &pid in self.network_pids.lock().unwrap().iter() {
                let name = (self.flavor.name_of())(self.host.as_ref(), pid);
                if !name.as_deref().is_some_and(|n| names.contains(&n)) {
                    return Some(format!(
                        "network-lost: egress process {pid} is gone ({})",
                        name.unwrap_or_else(|| "exited".into())
                    ));
                }
            }
        }
        None
    }

    fn wait_for_pins(&self, plan: &Plan, clock: &Clock) -> Result<Pinned, String> {
        let root = session::mvm_root(&self.env)?;
        session::wait_for_pins(plan, &root.join("audit"), &self.sb.name, clock)
    }

    fn monitor(&self) -> Result<Box<dyn Monitor>, String> {
        let supervisor = match self.flavor {
            Flavor::Hvf => session::Supervisor::discover(&self.sb.name, &self.env)?,
            Flavor::Firecracker => self.unprivileged_vmm()?,
        };
        Ok(Box::new(MvmMonitor {
            supervisor,
            host: self.host.clone(),
        }))
    }

    fn finish(&self, network_audit: &Path, log: &dyn Fn(&str)) {
        // Both run after export and removal, so neither can stop them.
        let names = self.flavor.network_processes();
        for &pid in self.network_pids.lock().unwrap().iter() {
            if let Some(name) = (self.flavor.name_of())(self.host.as_ref(), pid)
                .filter(|n| names.contains(&n.as_str()))
            {
                log(&format!(
                    "teardown: NETWORK PROCESS REMAINED: pid {pid} ({name}); killed"
                ));
                let _ = self.host.run(
                    &sv(&["kill", "-KILL", &pid.to_string()]),
                    Duration::from_secs(5),
                );
            }
        }
        let extracted = session::mvm_root(&self.env).and_then(|root| {
            crate::network::extract_audit(&root.join("audit"), &self.sb.name, network_audit)
        });
        match extracted {
            Ok(n) => log(&format!(
                "teardown: copied {n} network audit entries to {}",
                network_audit.display()
            )),
            Err(e) => log(&format!("teardown: NETWORK AUDIT FAILED: {e}")),
        }
    }
}

struct MvmMonitor {
    supervisor: session::Supervisor,
    host: Arc<dyn Host>,
}

impl Monitor for MvmMonitor {
    fn sample(&self, ceiling_mib: u64) -> Result<u64, String> {
        self.supervisor.sample(self.host.as_ref(), ceiling_mib)
    }
    fn describe(&self) -> String {
        format!(
            "pid {} (found via {})",
            self.supervisor.pid,
            self.supervisor.pid_file.display()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Defaults, ProviderConfig, parse_config};
    use crate::mvm::RunOutput;
    use std::io;
    use std::time::SystemTime;

    type Reply = Box<dyn Fn(&[String]) -> RunOutput + Send + Sync>;

    /// mvmctl and the host in one, recording every argv.
    struct Rec {
        calls: Mutex<Vec<String>>,
        reply: Reply,
    }
    impl Rec {
        fn new(reply: impl Fn(&[String]) -> RunOutput + Send + Sync + 'static) -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(vec![]),
                reply: Box::new(reply),
            })
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
        fn record(&self, argv: &[String]) -> io::Result<RunOutput> {
            self.calls.lock().unwrap().push(argv.join(" "));
            Ok((self.reply)(argv))
        }
    }
    impl Runner for Rec {
        fn run(&self, argv: &[String], _: Duration) -> io::Result<RunOutput> {
            self.record(argv)
        }
    }
    impl Host for Rec {
        fn run(&self, argv: &[String], _: Duration) -> io::Result<RunOutput> {
            self.record(argv)
        }
    }

    fn out(code: i32, stdout: &str) -> RunOutput {
        RunOutput {
            code: Some(code),
            stdout: stdout.into(),
            stderr: vec![],
            killed: false,
        }
    }

    fn healthy(a: &[String]) -> RunOutput {
        match a.last().map(String::as_str) {
            Some("--version") => out(0, "2.2.2\n"),
            Some(session::SUPERVISOR_PROBE) => out(0, session::SUPERVISOR_FIX_VERSION),
            _ => out(0, ""),
        }
    }

    fn backend(rec: &Arc<Rec>, env: Vec<(String, String)>) -> MvmBackend {
        let cfg = parse_config(
            "{}",
            Path::new("/cfg"),
            &Defaults {
                mvmctl: "/m/mvmctl".into(),
                plugin_dir: "/p".into(),
                opencode: "opencode".into(),
                sessions_dir: "/s".into(),
                hyperv: Default::default(),
            },
        )
        .unwrap();
        let deps = Deps {
            host: rec.clone(),
            runner: Some(rec.clone()),
            env,
            tool_command: sv(&["/x/rts", "tool"]),
            session_id: None,
            fatal: None,
            resolver: Arc::new(crate::network::SystemResolver),
            clock: Arc::new(SystemTime::now),
        };
        let paths = session::session_paths("0123456789ab", Path::new("/s"), Path::new("/rt"));
        MvmBackend::for_session(&cfg, &deps, &paths).unwrap()
    }

    fn home(h: &str) -> Vec<(String, String)> {
        vec![("HOME".into(), h.into())]
    }

    #[test]
    fn a_session_without_home_cannot_locate_the_supervisor() {
        let rec = Rec::new(healthy);
        let cfg = parse_config(
            "{}",
            Path::new("/cfg"),
            &Defaults {
                mvmctl: "/m/mvmctl".into(),
                plugin_dir: "/p".into(),
                opencode: "opencode".into(),
                sessions_dir: "/s".into(),
                hyperv: Default::default(),
            },
        )
        .unwrap();
        let deps = Deps {
            host: rec.clone(),
            runner: Some(rec.clone()),
            env: vec![],
            tool_command: sv(&["/x/rts", "tool"]),
            session_id: None,
            fatal: None,
            resolver: Arc::new(crate::network::SystemResolver),
            clock: Arc::new(SystemTime::now),
        };
        let paths = session::session_paths("0123456789ab", Path::new("/s"), Path::new("/rt"));
        let e = MvmBackend::for_session(&cfg, &deps, &paths).err().unwrap();
        assert!(e.contains("without HOME"), "{e}");
    }

    #[test]
    fn preflight_checks_opencode_then_the_supervisor_then_doctor() {
        let rec = Rec::new(healthy);
        let b = backend(&rec, home("/fake/home"));
        let provider = ProviderConfig {
            id: "p".into(),
            base_url: "https://example.invalid/v1".into(),
            models: vec!["m".into()],
            api_key_env: None,
        };
        b.preflight(&HostCheck {
            host: rec.as_ref(),
            opencode: "opencode",
            leak_seam_set: false,
            work_dir: None,
            provider: &provider,
        })
        .unwrap();
        assert_eq!(
            rec.calls(),
            [
                "opencode --version".to_string(),
                format!(
                    "/fake/home/.local/share/nearai-red-sandbox/mvm-hvf-supervisor {}",
                    session::SUPERVISOR_PROBE
                ),
                session::DOCTOR.join(" "),
            ]
        );
    }

    #[test]
    fn host_config_check_refuses_an_mvm_config_that_mentions_egress() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("config")).unwrap();
        let rec = Rec::new(healthy);
        let env = vec![
            ("HOME".into(), "/h".into()),
            ("MVM_HOME".into(), d.path().to_string_lossy().into_owned()),
        ];
        let b = backend(&rec, env);
        b.check_host_config().unwrap();
        std::fs::write(d.path().join("config/config.toml"), "egress = true\n").unwrap();
        assert!(
            b.check_host_config()
                .unwrap_err()
                .contains("mentions egress")
        );
        assert!(rec.calls().is_empty(), "{:?}", rec.calls());
    }

    #[test]
    fn a_machine_name_must_be_an_rts_machine() {
        let rec = Rec::new(healthy);
        let b = backend(&rec, home("/h"));
        assert!(b.machine("rts-0123456789ab").is_ok());
        let e = b.machine("other").err().unwrap();
        assert!(e.contains("rts-<12 hex chars>"), "{e}");
    }

    #[test]
    fn a_machine_that_was_never_attached_has_no_network_to_track() {
        let rec = Rec::new(healthy);
        let m = backend(&rec, home("/h"))
            .machine("rts-0123456789ab")
            .unwrap();
        assert_eq!(
            m.track_network().unwrap_err(),
            "network machine has no attached mvmctl machine run"
        );
        assert_eq!(m.network_lost(), None);
    }

    #[test]
    fn the_monitor_reads_the_hvf_pid_file_under_the_mvm_root() {
        let d = tempfile::tempdir().unwrap();
        let rec = Rec::new(healthy);
        let env = vec![
            ("HOME".into(), "/h".into()),
            ("MVM_HOME".into(), d.path().to_string_lossy().into_owned()),
        ];
        let m = backend(&rec, env).machine("rts-0123456789ab").unwrap();
        assert!(
            m.monitor()
                .err()
                .unwrap()
                .contains("cannot monitor HVF supervisor")
        );
        let pid_file = d.path().join("vms/rts-0123456789ab/hvf.pid");
        std::fs::create_dir_all(pid_file.parent().unwrap()).unwrap();
        std::fs::write(&pid_file, "4244\n").unwrap();
        let monitor = m.monitor().unwrap();
        assert_eq!(
            monitor.describe(),
            format!("pid 4244 (found via {})", pid_file.display())
        );
    }

    #[test]
    fn finish_reports_a_missing_audit_without_failing() {
        let d = tempfile::tempdir().unwrap();
        let rec = Rec::new(healthy);
        let env = vec![
            ("HOME".into(), "/h".into()),
            ("MVM_HOME".into(), d.path().to_string_lossy().into_owned()),
        ];
        let m = backend(&rec, env).machine("rts-0123456789ab").unwrap();
        let lines = Mutex::new(vec![]);
        m.finish(&d.path().join("network.jsonl"), &|l| {
            lines.lock().unwrap().push(l.to_string())
        });
        let lines = lines.into_inner().unwrap();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with("teardown: "), "{lines:?}");
    }

    fn fc_backend(rec: &Arc<Rec>, env: Vec<(String, String)>, kvm_device: &Path) -> MvmBackend {
        let cfg = parse_config(
            "{}",
            Path::new("/cfg"),
            &Defaults {
                mvmctl: "/m/mvmctl".into(),
                plugin_dir: "/p".into(),
                opencode: "opencode".into(),
                sessions_dir: "/s".into(),
                hyperv: Default::default(),
            },
        )
        .unwrap();
        let deps = Deps {
            host: rec.clone(),
            runner: Some(rec.clone()),
            env,
            tool_command: sv(&["/x/rts", "tool"]),
            session_id: None,
            fatal: None,
            resolver: Arc::new(crate::network::SystemResolver),
            clock: Arc::new(SystemTime::now),
        };
        let paths = session::session_paths("0123456789ab", Path::new("/s"), Path::new("/rt"));
        MvmBackend::for_session_flavor(Flavor::Firecracker, &cfg, &deps, &paths)
            .unwrap()
            .with_kvm(kvm_device)
    }

    #[test]
    fn this_host_gets_its_flavor_and_unit_tests_get_hvf() {
        assert_eq!(Flavor::host(), Flavor::Hvf);
        assert_eq!(
            Flavor::native(),
            if cfg!(target_os = "linux") {
                Flavor::Firecracker
            } else {
                Flavor::Hvf
            }
        );
    }

    #[test]
    fn flavors_name_their_vmm_pid_file_and_egress_processes() {
        assert_eq!(
            (Flavor::Hvf.pid_file(), Flavor::Hvf.vmm()),
            ("hvf.pid", "mvm-hvf-supervisor")
        );
        assert_eq!(
            Flavor::Hvf.network_processes(),
            ["mvm-network-endpoint", "mvm-hvf-supervisor"]
        );
        assert_eq!(
            (Flavor::Firecracker.pid_file(), Flavor::Firecracker.vmm()),
            ("fc.pid", "firecracker")
        );
        assert_eq!(
            Flavor::Firecracker.network_processes(),
            ["mvm-network-endpoint", "firecracker"]
        );
    }

    #[test]
    fn firecracker_machines_wait_for_the_attached_line_and_hvf_ones_poll_ps() {
        let rec = Rec::new(healthy);
        let env = vec![("MVM_HOME".to_string(), "/m".to_string())];
        let fc = fc_backend(&rec, env.clone(), Path::new("/dev/kvm"));
        assert_eq!(
            fc.launch_for("rts-0123456789ab").unwrap(),
            crate::mvm::Launch::AttachLine {
                registry: "/m/share/vm-names.json".into(),
                vm_dir: "/m/vms/rts-0123456789ab".into(),
            }
        );
        assert!(
            fc_backend(&rec, vec![], Path::new("/dev/kvm"))
                .launch_for("rts-0123456789ab")
                .is_err()
        );
        assert_eq!(
            backend(
                &rec,
                [env, vec![("HOME".to_string(), "/h".to_string())]].concat()
            )
            .launch_for("rts-0123456789ab")
            .unwrap(),
            crate::mvm::Launch::PollPs
        );
    }

    #[test]
    fn firecracker_preflight_checks_kvm_instead_of_the_supervisor_and_needs_no_home() {
        let d = tempfile::tempdir().unwrap();
        let dev = d.path().join("kvm");
        std::fs::write(&dev, "").unwrap();
        let rec = Rec::new(healthy);
        let b = fc_backend(&rec, vec![], &dev);
        let provider = ProviderConfig {
            id: "p".into(),
            base_url: "https://example.invalid/v1".into(),
            models: vec!["m".into()],
            api_key_env: None,
        };
        let check = HostCheck {
            host: rec.as_ref(),
            opencode: "opencode",
            leak_seam_set: false,
            work_dir: None,
            provider: &provider,
        };
        b.preflight(&check).unwrap();
        assert_eq!(
            rec.calls(),
            ["opencode --version".to_string(), session::DOCTOR.join(" ")]
        );
        std::fs::remove_file(&dev).unwrap();
        let e = b.preflight(&check).unwrap_err();
        assert!(e.contains("usermod -aG kvm"), "{e}");
        assert_eq!(
            rec.calls()
                .iter()
                .filter(|c| c.starts_with("doctor"))
                .count(),
            1,
            "doctor ran without KVM"
        );
    }

    #[test]
    fn a_real_firecracker_session_installs_the_sudo_shim_in_its_runtime() {
        let d = tempfile::tempdir().unwrap();
        let rec = Rec::new(healthy);
        let cfg = parse_config(
            "{}",
            Path::new("/cfg"),
            &Defaults {
                mvmctl: "/m/mvmctl".into(),
                plugin_dir: "/p".into(),
                opencode: "opencode".into(),
                sessions_dir: "/s".into(),
                hyperv: Default::default(),
            },
        )
        .unwrap();
        let deps = Deps {
            host: rec.clone(),
            runner: None,
            env: vec![],
            tool_command: sv(&["/x/rts", "tool"]),
            session_id: None,
            fatal: None,
            resolver: Arc::new(crate::network::SystemResolver),
            clock: Arc::new(SystemTime::now),
        };
        let paths =
            session::session_paths("0123456789ab", &d.path().join("s"), &d.path().join("rt"));
        MvmBackend::for_session_flavor(Flavor::Firecracker, &cfg, &deps, &paths).unwrap();
        let shim = std::fs::read_to_string(d.path().join("rt/sudo-shim/sudo")).unwrap();
        assert_eq!(shim, kvm::SUDO_SHIM);
    }

    #[test]
    fn the_firecracker_monitor_reads_fc_pid_and_refuses_a_root_vmm() {
        let d = tempfile::tempdir().unwrap();
        let pid_file = d.path().join("vms/rts-0123456789ab/fc.pid");
        std::fs::create_dir_all(pid_file.parent().unwrap()).unwrap();
        std::fs::write(&pid_file, "4244\n").unwrap();
        let env = || {
            vec![(
                "MVM_HOME".to_string(),
                d.path().to_string_lossy().into_owned(),
            )]
        };
        let uid = Arc::new(Mutex::new(kvm::current_uid().to_string()));
        let reply_uid = uid.clone();
        let rec = Rec::new(move |a| match a.join(" ").as_str() {
            // Linux shapes: comm is the bare, 15-character kernel name.
            "ps -o comm= -p 4244" => out(0, "firecracker\n"),
            "readlink /proc/4244/exe" => out(0, "/usr/bin/firecracker\n"),
            "ps -o uid= -p 4244" => out(0, &format!("{}\n", reply_uid.lock().unwrap())),
            "ps -o rss= -p 4244" => out(0, "2048\n"),
            _ => out(0, ""),
        });
        let m = fc_backend(&rec, env(), Path::new("/dev/null"))
            .machine("rts-0123456789ab")
            .unwrap();
        let monitor = m.monitor().unwrap();
        assert_eq!(
            monitor.describe(),
            format!("pid 4244 (found via {})", pid_file.display())
        );
        assert_eq!(monitor.sample(4096).unwrap(), 2);
        *uid.lock().unwrap() = "0".into();
        assert!(m.monitor().err().unwrap().contains("runs as root"));
        std::fs::remove_file(&pid_file).unwrap();
        assert!(
            m.monitor()
                .err()
                .unwrap()
                .contains("cannot monitor Firecracker")
        );
    }

    /// `pgrep` and the process tables of a Linux host: `ps -o comm=` is the
    /// kernel comm, capped at 15 characters.
    fn linux_tree(a: &[String]) -> RunOutput {
        match a.join(" ").as_str() {
            "pgrep -P 4242" => out(0, "4243\n4245\n"),
            "ps -o comm= -p 4243" => out(0, "mvm-network-end\n"),
            "readlink /proc/4243/exe" => out(0, "/opt/mvm/mvm-network-endpoint\n"),
            "ps -o comm= -p 4245" => out(0, "bash\n"),
            "readlink /proc/4245/exe" => out(0, "/usr/bin/bash\n"),
            _ => out(1, ""),
        }
    }

    #[test]
    fn a_firecracker_machine_whose_egress_process_is_gone_is_network_lost() {
        let rec = Rec::new(|a| match a.join(" ").as_str() {
            "readlink /proc/4243/exe" => out(0, "/opt/mvm/mvm-network-endpoint\n"),
            "readlink /proc/4250/exe" => out(0, "/opt/mvm/firecracker/firecracker\n"),
            "readlink /proc/4251/exe" => out(0, "/usr/bin/bash\n"),
            _ => out(1, ""),
        });
        let machine = |pids: Vec<u32>| {
            let sb = MvmSandbox::new("rts-0123456789ab", Box::new(rec.clone())).unwrap();
            let mut m = MvmMachine::from_parts(sb, rec.clone(), vec![], pids);
            m.flavor = Flavor::Firecracker;
            m
        };
        assert_eq!(machine(vec![4243, 4250]).network_lost(), None);
        // Exited (no exe link), or the pid now names another program.
        for pids in [vec![4243, 4250, 4260], vec![4243, 4251]] {
            let lost = machine(pids.clone()).network_lost().expect("lost");
            assert!(lost.starts_with("network-lost:"), "{pids:?}: {lost}");
        }
        // HVF keeps the attach as its only signal.
        let sb = MvmSandbox::new("rts-0123456789ab", Box::new(rec.clone())).unwrap();
        assert_eq!(
            MvmMachine::from_parts(sb, rec.clone(), vec![], vec![4260]).network_lost(),
            None
        );
    }

    #[test]
    fn firecracker_finds_the_endpoint_by_its_executable_not_the_truncated_comm() {
        let rec = Rec::new(linux_tree);
        let names = Flavor::Firecracker.network_processes();
        assert_eq!(
            session::network_children_of(rec.as_ref(), 4242, names, Flavor::Firecracker.name_of())
                .unwrap(),
            vec![4243]
        );
        // The comm-based lookup the HVF flavor uses cannot see it on Linux.
        assert!(
            session::network_children_of(rec.as_ref(), 4242, names, Flavor::Hvf.name_of()).is_err()
        );
    }

    #[test]
    fn exe_names_drop_a_deleted_suffix_and_need_a_readable_link() {
        let rec = Rec::new(|a| match a.join(" ").as_str() {
            "readlink /proc/1/exe" => out(0, "/usr/bin/firecracker (deleted)\n"),
            _ => out(1, ""),
        });
        assert_eq!(
            session::exe_name(rec.as_ref(), 1).as_deref(),
            Some("firecracker")
        );
        assert_eq!(session::exe_name(rec.as_ref(), 2), None);
    }

    #[test]
    fn a_firecracker_machine_running_as_root_is_refused_at_create() {
        let d = tempfile::tempdir().unwrap();
        let pid_file = d.path().join("vms/rts-0123456789ab/fc.pid");
        std::fs::create_dir_all(pid_file.parent().unwrap()).unwrap();
        std::fs::write(&pid_file, "4244\n").unwrap();
        let env = vec![(
            "MVM_HOME".to_string(),
            d.path().to_string_lossy().into_owned(),
        )];
        let rec = Rec::new(|a| match a.join(" ").as_str() {
            "readlink /proc/4244/exe" => out(0, "/usr/bin/firecracker\n"),
            "ps -o uid= -p 4244" => out(0, "0\n"),
            _ => out(0, ""),
        });
        let m = fc_backend(&rec, env, Path::new("/dev/null"))
            .machine("rts-0123456789ab")
            .unwrap();
        let image = "example.invalid/guest@sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let e = m
            .create(&CreateSpec {
                name: "rts-0123456789ab",
                image,
                memory_mib: 512,
                cpus: 1,
                egress: None,
            })
            .unwrap_err()
            .to_string();
        assert!(e.contains("runs as root"), "{e}");
        let calls = rec.calls();
        let start = calls
            .iter()
            .position(|c| c.starts_with("machine start"))
            .expect("no start");
        let uid = calls
            .iter()
            .position(|c| c == "ps -o uid= -p 4244")
            .expect("uid never checked");
        assert!(start < uid, "{calls:?}");
        assert!(
            !calls.iter().any(|c| c.starts_with("machine exec")),
            "{calls:?}"
        );
    }
}

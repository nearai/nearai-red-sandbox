//! One rts machine on Hyper-V: a compute system booted from rts's pinned
//! kernel and initramfs, reached only through its exec service. The host
//! side (HCS and hvsocket) sits behind `VmHost`, so every rule here is
//! tested on any OS against a fake host that runs the real guest server.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sha2::{Digest, Sha256};

use super::doc::{EGRESS_PORT, EXEC_PORT, VmSpec, document, new_vm_id, service_id};
use super::egress::{Audit, Policy};
use super::exec::{Connect, GuestExec};
use super::props::{VmState, wait_ready};
use crate::backend::{Machine, Monitor, Pinned};
use crate::copy::{CopyLimits, copy_in_via, copy_out_via};
use crate::network::Plan;
use crate::sandbox::{
    CopyOutResult, CreateSpec, Error, Exec, ExecOptions, ExecResult, Result, Sandbox,
};
use crate::session::Clock;

/// Added to each command's own timeout before the host gives up on it.
pub const BACKSTOP: Duration = Duration::from_secs(30);
/// How long a new VM has to reach its agent.
pub const BOOT_TIMEOUT: Duration = Duration::from_secs(60);
/// The connect timeout of one readiness probe.
const PROBE_CONNECT: Duration = Duration::from_secs(2);

/// One running compute system.
pub trait VmHandle: Send + Sync {
    fn start(&self) -> io::Result<()>;
    fn state(&self) -> io::Result<VmState>;
    fn assigned_memory_mib(&self) -> io::Result<u64>;
    fn terminate(&self) -> io::Result<()>;
}

/// Accepts the guest's connections to one service.
pub trait Accept: Send + 'static {
    type Stream: io::Read + io::Write + Send + crate::hvexec::serve::TryClone + 'static;
    fn accept(&self) -> io::Result<Self::Stream>;
}

/// Creates compute systems and connects to (or listens on) their services.
pub trait VmHost: Send + Sync {
    type Conn: Connect + 'static;
    type Listener: Accept;
    /// Listen for the guest's connections to `service` of VM `id` only.
    fn listen(&self, id: &str, service: &str) -> io::Result<Self::Listener>;
    /// Start the egress proxy for `policy` in its own (confined) process.
    fn spawn_proxy(&self, policy: &Policy) -> io::Result<ProxyChannel>;
    /// An existing compute system by id, or `None` if there is none.
    fn open(&self, id: &str) -> io::Result<Option<Arc<dyn VmHandle>>>;
    fn create(&self, id: &str, document: &str) -> io::Result<Arc<dyn VmHandle>>;
    fn connect(&self, id: &str, service: &str, connect_timeout: Duration)
    -> io::Result<Self::Conn>;
}

/// The pinned guest artifacts and who may reach the VM.
#[derive(Clone)]
pub struct GuestImage {
    pub kernel: PathBuf,
    pub kernel_sha256: String,
    pub initrd: PathBuf,
    pub initrd_sha256: String,
    pub user_sid: String,
    /// Directory for the serial console pipe name's prefix.
    pub pipe_prefix: String,
    /// Owner-only directory holding one file per VM rts created and has not
    /// yet confirmed removed: what the sweep checks.
    pub vm_ids: PathBuf,
}

/// Record that VM `id` (machine `name`) is about to exist.
pub fn record_vm(dir: &Path, id: &str, name: &str) -> io::Result<()> {
    crate::sys::fs::create_private_dir_all(dir)?;
    io::Write::write_all(
        &mut crate::sys::fs::open_private(&dir.join(id), crate::sys::fs::Create::New)?,
        name.as_bytes(),
    )
}

/// Forget VM `id` once it is confirmed gone.
pub fn forget_vm(dir: &Path, id: &str) {
    let _ = std::fs::remove_file(dir.join(id));
}

/// Every recorded (id, machine name); files that are not a VM id are ignored.
pub fn recorded_vms(dir: &Path) -> Vec<(String, String)> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return vec![];
    };
    let mut out: Vec<(String, String)> = rd
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let id = e.file_name().to_str()?.to_string();
            super::doc::parse_guid(&id)?;
            let name = std::fs::read_to_string(e.path()).unwrap_or_default();
            Some((id, name.chars().take(64).collect()))
        })
        .collect();
    out.sort();
    out
}

fn sha256_file(p: &Path) -> io::Result<String> {
    Ok(hex::encode(Sha256::digest(std::fs::read(p)?)))
}

pub struct HyperVMachine<H: VmHost> {
    name: String,
    host: H,
    image: GuestImage,
    copy_limits: CopyLimits,
    vm: Mutex<Option<(Arc<dyn VmHandle>, u64)>>,
    exec: Mutex<Option<Arc<GuestExec<H::Conn>>>>,
    dead: Mutex<Option<String>>,
    egress: Mutex<Option<Egress>>,
    vm_id: Mutex<Option<String>>,
}

/// The running egress path of a machine with an allowlist.
struct Egress {
    policy: Policy,
    audit_path: PathBuf,
    /// Set when the accept loop or the proxy ends: the session must stop.
    stopped: Arc<Mutex<Option<String>>>,
    /// The confined proxy process; dropping it ends the process.
    _proxy: Box<dyn Send>,
}

/// A started egress proxy: rts's ends of its channel, and what keeps it alive.
pub struct ProxyChannel {
    pub to_proxy: Box<dyn io::Write + Send>,
    pub from_proxy: Box<dyn io::Read + Send>,
    pub guard: Box<dyn Send>,
}

impl<H: VmHost> HyperVMachine<H> {
    pub fn new(name: &str, host: H, image: GuestImage) -> Self {
        Self {
            name: name.into(),
            host,
            image,
            copy_limits: CopyLimits::default(),
            vm: Mutex::new(None),
            exec: Mutex::new(None),
            dead: Mutex::new(None),
            egress: Mutex::new(None),
            vm_id: Mutex::new(None),
        }
    }

    fn mark_unavailable(&self, reason: &str) -> Error {
        let mut d = self.dead.lock().unwrap_or_else(|e| e.into_inner());
        Error::Unavailable(d.get_or_insert_with(|| reason.to_string()).clone())
    }

    fn handle(&self) -> Option<(Arc<dyn VmHandle>, u64)> {
        self.vm.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl<H: VmHost> HyperVMachine<H> {
    /// Resolve the allowlist into the proxy's policy and serve the VM's
    /// egress service before it boots, auditing to the attach log.
    fn start_egress(&self, id: &str, e: &crate::sandbox::Egress) -> Result<()> {
        // AllowHost spells IPv6 without brackets; the plan wants [v6]:port.
        let written: Vec<String> = e
            .allow_hosts
            .iter()
            .map(|h| match h.as_str().rsplit_once(':') {
                Some((host, port)) if host.contains(':') && !host.starts_with('[') => {
                    format!("[{host}]:{port}")
                }
                _ => h.as_str().to_string(),
            })
            .collect();
        let plan = crate::network::plan(&written, &crate::network::SystemResolver)
            .map_err(Error::Other)?;
        let policy = Policy::from_plan(&plan);
        let audit = Arc::new(Audit::new(e.attach_log));
        let listener = self
            .host
            .listen(id, &service_id(EGRESS_PORT))
            .map_err(|err| Error::Other(format!("cannot serve {}'s egress: {err}", self.name)))?;
        // The proxy, not rts, reads CONNECT requests and dials out; rts only
        // carries the guest's bytes to it and records its audit lines.
        let proxy = self.host.spawn_proxy(&policy).map_err(|err| {
            Error::Other(format!("cannot start {}'s egress proxy: {err}", self.name))
        })?;
        let stopped = Arc::new(Mutex::new(None));
        let mux =
            super::mux::MuxParent::start(proxy.to_proxy, proxy.from_proxy, audit, stopped.clone());
        {
            let stopped = stopped.clone();
            std::thread::spawn(move || {
                loop {
                    let attached = listener.accept().and_then(|conn| mux.attach(conn));
                    if let Err(err) = attached {
                        *stopped.lock().unwrap_or_else(|e| e.into_inner()) =
                            Some(format!("network-lost: the egress listener stopped: {err}"));
                        return;
                    }
                }
            });
        }
        *self.egress.lock().unwrap_or_else(|e| e.into_inner()) = Some(Egress {
            policy,
            audit_path: e.attach_log.to_path_buf(),
            stopped,
            _proxy: proxy.guard,
        });
        Ok(())
    }
}

impl<H: VmHost> Exec for HyperVMachine<H> {
    fn exec(&self, argv: &[String], o: &ExecOptions) -> Result<ExecResult> {
        if let Some(r) = self.dead.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            return Err(Error::Unavailable(r));
        }
        let exec = self.exec.lock().unwrap_or_else(|e| e.into_inner()).clone();
        match exec {
            Some(g) => {
                let r = g.exec(argv, o);
                if let Err(Error::Unavailable(reason)) = &r {
                    self.mark_unavailable(reason);
                }
                r
            }
            None => Err(Error::Unavailable(format!(
                "{} has not been created",
                self.name
            ))),
        }
    }
}

impl<H: VmHost> Sandbox for HyperVMachine<H> {
    fn create(&self, spec: &CreateSpec) -> Result<()> {
        if self.handle().is_some() {
            return Err(Error::Other(format!("{} already exists", self.name)));
        }
        // The VM boots whatever is at these paths: check them on every create.
        for (path, want, what) in [
            (
                &self.image.kernel,
                &self.image.kernel_sha256,
                "guest kernel",
            ),
            (
                &self.image.initrd,
                &self.image.initrd_sha256,
                "guest initramfs",
            ),
        ] {
            let got = sha256_file(path)
                .map_err(|e| Error::Other(format!("{what} {}: {e}", path.display())))?;
            if &got != want {
                return Err(Error::Other(format!(
                    "{what} {} does not match its pinned digest",
                    path.display()
                )));
            }
        }
        let id = new_vm_id();
        // Recorded before the VM exists, so a crash at any later point
        // leaves a trace the sweep checks.
        record_vm(&self.image.vm_ids, &id, &self.name)
            .map_err(|e| Error::Other(format!("cannot record {}'s VM id: {e}", self.name)))?;
        *self.vm_id.lock().unwrap_or_else(|e| e.into_inner()) = Some(id.clone());
        let pipe = format!("{}{}-com1", self.image.pipe_prefix, &id[..8]);
        let (kernel, initrd) = (
            self.image.kernel.to_string_lossy(),
            self.image.initrd.to_string_lossy(),
        );
        let doc = document(&VmSpec {
            kernel: &kernel,
            initrd: &initrd,
            memory_mib: u64::from(spec.memory_mib),
            cpus: spec.cpus,
            com_pipe: &pipe,
            user_sid: &self.image.user_sid,
        });
        let vm = self
            .host
            .create(&id, &doc.to_string())
            .map_err(|e| Error::Other(format!("cannot create {}: {e}", self.name)))?;
        *self.vm.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((vm.clone(), u64::from(spec.memory_mib)));
        if let Some(e) = &spec.egress {
            self.start_egress(&id, e)?;
        }
        vm.start()
            .map_err(|e| Error::Other(format!("cannot start {}: {e}", self.name)))?;
        // Raw bounded connects until the agent listens: a failed connect must
        // not poison the session's exec.
        let service = service_id(EXEC_PORT);
        let probe = || {
            self.host
                .connect(&id, &service, PROBE_CONNECT)
                .and_then(|c| c.connect(PROBE_CONNECT))
                .map(|s| {
                    let _ = crate::hvexec::serve::TryClone::shutdown_stream(&s);
                })
                .is_ok()
        };
        wait_ready(
            || vm.state().map_err(|e| e.to_string()),
            probe,
            BOOT_TIMEOUT,
            Duration::from_millis(250),
        )
        .map_err(|e| Error::Other(format!("{} did not boot: {e}", self.name)))?;
        let conn = self
            .host
            .connect(&id, &service, PROBE_CONNECT)
            .map_err(|e| Error::Other(format!("cannot reach {}: {e}", self.name)))?;
        *self.exec.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Arc::new(GuestExec::new(conn, BACKSTOP)));
        Ok(())
    }

    fn copy_in(&self, host_dir: &Path, guest_dir: &str) -> Result<()> {
        copy_in_via(self, host_dir, guest_dir)
    }

    /// Treats the guest as hostile; see copy.rs and untar.rs.
    fn copy_out(&self, guest_dir: &str, host_dir: &Path) -> Result<CopyOutResult> {
        copy_out_via(self, guest_dir, host_dir, &self.copy_limits)
    }

    fn remove(&self) -> Result<()> {
        self.mark_unavailable("sandbox removed");
        let Some((vm, _)) = self.handle() else {
            return Ok(());
        };
        let terminated = vm.terminate();
        match vm.state() {
            Ok(VmState::Running) => Err(Error::Other(format!(
                "{} is still running after terminate{}",
                self.name,
                terminated
                    .err()
                    .map(|e| format!(": {e}"))
                    .unwrap_or_default()
            ))),
            _ => {
                if let Some(id) = self
                    .vm_id
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .as_ref()
                {
                    forget_vm(&self.image.vm_ids, id);
                }
                Ok(())
            }
        }
    }
}

impl<H: VmHost> Machine for HyperVMachine<H> {
    /// The egress path is rts's own listener, started before the VM booted.
    fn track_network(&self) -> std::result::Result<(), String> {
        match self.network_lost() {
            Some(why) => Err(why),
            None => Ok(()),
        }
    }

    fn network_lost(&self) -> Option<String> {
        let egress = self.egress.lock().unwrap_or_else(|e| e.into_inner());
        egress
            .as_ref()
            .and_then(|e| e.stopped.lock().unwrap_or_else(|p| p.into_inner()).clone())
    }

    /// The proxy dials only the addresses its policy resolved when the
    /// machine was created, so those are the pins.
    fn wait_for_pins(&self, plan: &Plan, _: &Clock) -> std::result::Result<Pinned, String> {
        if plan.is_empty() {
            return Ok(Pinned::new());
        }
        let egress = self.egress.lock().unwrap_or_else(|e| e.into_inner());
        let e = egress
            .as_ref()
            .ok_or("the machine was created without egress")?;
        Ok(e.policy.pins())
    }

    fn tool_target(&self) -> Option<String> {
        self.vm_id.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn monitor(&self) -> std::result::Result<Box<dyn Monitor>, String> {
        let (vm, configured) = self
            .handle()
            .ok_or_else(|| format!("{} has not been created", self.name))?;
        Ok(Box::new(HvMonitor {
            vm,
            configured_mib: configured,
            name: self.name.clone(),
        }))
    }

    fn finish(&self, network_audit: &Path, log: &dyn Fn(&str)) {
        let egress = self.egress.lock().unwrap_or_else(|e| e.into_inner());
        let Some(e) = egress.as_ref() else { return };
        if let Err(err) = std::fs::copy(&e.audit_path, network_audit) {
            log(&format!(
                "[rts] {}: cannot copy the egress audit: {err}",
                self.name
            ));
        }
    }
}

/// Holds the VM to the host memory ceiling. This is a configuration check,
/// not a measurement: the VM document fixes guest memory (no overcommit, no
/// deferred commit), so the size HCS reports as assigned is what the guest
/// occupies on the host. The monitor refuses unless the VM is still running
/// at exactly its configured size, within the ceiling. The Hyper-V worker
/// process (vmwp.exe) and its own overhead are not counted: a non-admin
/// cannot open it, and HCS's memory statistics for a VM are all zero.
pub struct HvMonitor {
    vm: Arc<dyn VmHandle>,
    configured_mib: u64,
    name: String,
}

impl Monitor for HvMonitor {
    fn sample(&self, ceiling_mib: u64) -> std::result::Result<u64, String> {
        match self
            .vm
            .state()
            .map_err(|e| format!("cannot read {}'s state: {e}", self.name))?
        {
            VmState::Running => {}
            other => return Err(format!("{} is no longer running ({other:?})", self.name)),
        }
        let mib = self
            .vm
            .assigned_memory_mib()
            .map_err(|e| format!("cannot read {}'s memory: {e}", self.name))?;
        if mib != self.configured_mib {
            return Err(format!(
                "{} has {mib} MiB assigned, not the configured {}",
                self.name, self.configured_mib
            ));
        }
        if mib > ceiling_mib {
            return Err(format!(
                "{} uses {mib} MiB, over the {ceiling_mib} MiB ceiling",
                self.name
            ));
        }
        Ok(mib)
    }

    fn describe(&self) -> String {
        format!(
            "{}: configured (assigned) memory from HCS, not measured usage; the Hyper-V worker process (vmwp.exe) is not counted",
            self.name
        )
    }
}

/// The real host: HCS for compute systems, AF_HYPERV for services.
#[cfg(windows)]
#[derive(Clone, Default)]
pub struct HcsHost {
    /// rts-egress.exe; `None`: beside the running rts.exe.
    pub egress_exe: Option<std::path::PathBuf>,
}

#[cfg(windows)]
impl VmHandle for super::hcs::ComputeSystem {
    fn start(&self) -> io::Result<()> {
        super::hcs::ComputeSystem::start(self)
    }
    fn state(&self) -> io::Result<VmState> {
        super::hcs::ComputeSystem::state(self)
    }
    fn assigned_memory_mib(&self) -> io::Result<u64> {
        super::hcs::ComputeSystem::assigned_memory_mib(self)
    }
    fn terminate(&self) -> io::Result<()> {
        super::hcs::ComputeSystem::terminate(self)
    }
}

#[cfg(windows)]
impl Accept for super::hvsock::HvListener {
    type Stream = super::hvsock::HvStream;
    fn accept(&self) -> io::Result<Self::Stream> {
        super::hvsock::HvListener::accept(self)
    }
}

#[cfg(windows)]
impl VmHost for HcsHost {
    type Conn = super::hvsock::HvConnect;
    type Listener = super::hvsock::HvListener;
    fn listen(&self, id: &str, service: &str) -> io::Result<Self::Listener> {
        super::hvsock::HvListener::bind(id, service)
    }
    fn open(&self, id: &str) -> io::Result<Option<Arc<dyn VmHandle>>> {
        Ok(super::hcs::ComputeSystem::open(id)?.map(|c| Arc::new(c) as Arc<dyn VmHandle>))
    }
    /// rts-egress.exe in an AppContainer inside a kill-on-close job (see
    /// appcontainer.rs).
    fn spawn_proxy(&self, policy: &Policy) -> io::Result<ProxyChannel> {
        // The configured rts-egress.exe (an install prefix), else the one
        // beside rts.exe. Never chosen by the environment.
        let exe = match &self.egress_exe {
            Some(p) => p.clone(),
            None => std::env::current_exe()?
                .parent()
                .ok_or_else(|| io::Error::other("rts.exe has no directory"))?
                .join(super::appcontainer::EXECUTABLE),
        };
        let (proxy, mut to, from) =
            super::appcontainer::spawn(&exe, &[], super::mux::needs_private_network(policy))?;
        io::Write::write_all(&mut to, format!("{}\n", policy.to_json()).as_bytes())?;
        Ok(ProxyChannel {
            to_proxy: Box::new(to),
            from_proxy: Box::new(from),
            guard: Box::new(proxy),
        })
    }
    fn create(&self, id: &str, document: &str) -> io::Result<Arc<dyn VmHandle>> {
        Ok(Arc::new(super::hcs::ComputeSystem::create(id, document)?))
    }
    fn connect(
        &self,
        id: &str,
        service: &str,
        connect_timeout: Duration,
    ) -> io::Result<Self::Conn> {
        super::hvsock::HvConnect::new(id, service, connect_timeout)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::sandbox::sv;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct FakeVm {
        calls: Mutex<Vec<&'static str>>,
        running: AtomicBool,
        stops_on_start: bool,
        assigned: u64,
    }

    impl VmHandle for FakeVm {
        fn start(&self) -> io::Result<()> {
            self.calls.lock().unwrap().push("start");
            self.running.store(!self.stops_on_start, Ordering::SeqCst);
            Ok(())
        }
        fn state(&self) -> io::Result<VmState> {
            Ok(if self.running.load(Ordering::SeqCst) {
                VmState::Running
            } else {
                VmState::Stopped("UnexpectedExit".into())
            })
        }
        fn assigned_memory_mib(&self) -> io::Result<u64> {
            Ok(self.assigned)
        }
        fn terminate(&self) -> io::Result<()> {
            self.calls.lock().unwrap().push("terminate");
            self.running.store(false, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Serves each connection with the real guest server on this host.
    struct LocalConn;

    impl Connect for LocalConn {
        type Stream = UnixStream;
        fn connect(&self, deadline: Duration) -> io::Result<UnixStream> {
            let (host, guest) = UnixStream::pair()?;
            std::thread::spawn(move || crate::hvexec::serve::serve(guest));
            host.set_read_timeout(Some(deadline))?;
            Ok(host)
        }
    }

    struct FakeHost {
        /// VMs `open` finds, by id.
        opened: Mutex<Vec<(String, Arc<FakeVm>)>>,
        egress_dir: tempfile::TempDir,
        vm: Arc<FakeVm>,
        docs: Mutex<Vec<serde_json::Value>>,
        connects: AtomicUsize,
    }

    struct FakeListener(std::os::unix::net::UnixListener);

    impl Accept for FakeListener {
        type Stream = UnixStream;
        fn accept(&self) -> io::Result<UnixStream> {
            self.0.accept().map(|(s, _)| s)
        }
    }

    impl VmHost for Arc<FakeHost> {
        type Conn = LocalConn;
        type Listener = FakeListener;
        /// The proxy's main loop on a thread, over socket pairs.
        fn spawn_proxy(&self, policy: &Policy) -> io::Result<ProxyChannel> {
            let (mut to, proxy_in) = UnixStream::pair()?;
            let (proxy_out, from) = UnixStream::pair()?;
            io::Write::write_all(&mut to, format!("{}\n", policy.to_json()).as_bytes())?;
            std::thread::spawn(move || {
                super::super::mux::proxy_main(proxy_in, Box::new(proxy_out))
            });
            Ok(ProxyChannel {
                to_proxy: Box::new(to),
                from_proxy: Box::new(from),
                guard: Box::new(()),
            })
        }
        fn open(&self, id: &str) -> io::Result<Option<Arc<dyn VmHandle>>> {
            Ok(self
                .opened
                .lock()
                .unwrap()
                .iter()
                .find(|(i, _)| i == id)
                .map(|(_, v)| v.clone() as Arc<dyn VmHandle>))
        }
        fn listen(&self, _id: &str, service: &str) -> io::Result<FakeListener> {
            assert_eq!(service, service_id(EGRESS_PORT));
            let path = self.egress_dir.path().join("egress.sock");
            Ok(FakeListener(std::os::unix::net::UnixListener::bind(path)?))
        }
        fn create(&self, _id: &str, document: &str) -> io::Result<Arc<dyn VmHandle>> {
            self.docs
                .lock()
                .unwrap()
                .push(serde_json::from_str(document).unwrap());
            Ok(self.vm.clone())
        }
        fn connect(&self, _: &str, service: &str, _: Duration) -> io::Result<LocalConn> {
            assert_eq!(service, service_id(EXEC_PORT));
            self.connects.fetch_add(1, Ordering::SeqCst);
            Ok(LocalConn)
        }
    }

    fn rig(stops_on_start: bool, assigned: u64) -> (Arc<FakeHost>, GuestImage, tempfile::TempDir) {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("vmlinuz"), b"kernel").unwrap();
        std::fs::write(d.path().join("initrd"), b"initrd").unwrap();
        let image = GuestImage {
            kernel: d.path().join("vmlinuz"),
            kernel_sha256: hex::encode(Sha256::digest(b"kernel")),
            initrd: d.path().join("initrd"),
            initrd_sha256: hex::encode(Sha256::digest(b"initrd")),
            user_sid: "S-1-5-21-1-2-3-1001".into(),
            pipe_prefix: r"\\.\pipe\rts-".into(),
            vm_ids: d.path().join("vms"),
        };
        let vm = Arc::new(FakeVm {
            calls: Mutex::new(vec![]),
            running: AtomicBool::new(false),
            stops_on_start,
            assigned,
        });
        (
            Arc::new(FakeHost {
                opened: Mutex::new(vec![]),
                egress_dir: tempfile::tempdir().unwrap(),
                vm,
                docs: Mutex::new(vec![]),
                connects: AtomicUsize::new(0),
            }),
            image,
            d,
        )
    }

    fn spec(memory_mib: u32) -> CreateSpec<'static> {
        CreateSpec {
            name: "rts-0123456789ab",
            image: "unused",
            memory_mib,
            cpus: 2,
            egress: None,
        }
    }

    #[test]
    fn create_boots_the_pinned_image_and_exec_runs_in_the_guest() {
        let (host, image, _d) = rig(false, 1024);
        let m = HyperVMachine::new("rts-0123456789ab", host.clone(), image.clone());
        m.create(&spec(1024)).unwrap();
        let doc = &host.docs.lock().unwrap()[0];
        let vm = &doc["VirtualMachine"];
        assert_eq!(vm["ComputeTopology"]["Memory"]["SizeInMB"], 1024);
        assert_eq!(
            vm["Chipset"]["LinuxKernelDirect"]["KernelFilePath"],
            image.kernel.to_string_lossy().as_ref()
        );
        assert!(
            vm["Devices"]["ComPorts"]["0"]["NamedPipe"]
                .as_str()
                .unwrap()
                .starts_with(r"\\.\pipe\rts-")
        );
        let r = m
            .exec(
                &sv(&["sh", "-c", "echo hi; exit 2"]),
                &ExecOptions::new(5_000, 4096),
            )
            .unwrap();
        assert_eq!((r.exit_code, r.stdout.as_slice()), (2, b"hi\n".as_slice()));
    }

    #[test]
    fn a_tampered_kernel_or_initramfs_is_never_booted() {
        for file in ["vmlinuz", "initrd"] {
            let (host, image, d) = rig(false, 1024);
            std::fs::write(d.path().join(file), b"swapped").unwrap();
            let m = HyperVMachine::new("rts-0123456789ab", host.clone(), image);
            let e = m.create(&spec(1024)).unwrap_err().to_string();
            assert!(e.contains("pinned digest"), "{e}");
            assert!(host.docs.lock().unwrap().is_empty(), "no VM was created");
        }
    }

    #[test]
    fn an_allowlist_starts_the_egress_proxy_which_refuses_and_audits_other_targets() {
        use std::io::{BufRead, BufReader, Write};
        let (host, image, d) = rig(false, 1024);
        let m = HyperVMachine::new("rts-0123456789ab", host.clone(), image);
        let plan = crate::network::plan(
            &["198.51.100.7:443".to_string()],
            &crate::network::SystemResolver,
        )
        .unwrap();
        let hosts = plan.allow_hosts();
        let log = d.path().join("attach.log");
        let s = CreateSpec {
            egress: Some(crate::sandbox::Egress {
                allow_hosts: &hosts,
                attach_log: &log,
                session_hours: 1,
            }),
            ..spec(1024)
        };
        m.create(&s).unwrap();
        m.track_network().unwrap();
        // The guest's forwarder connects to the VM's egress service.
        let mut guest = UnixStream::connect(host.egress_dir.path().join("egress.sock")).unwrap();
        guest
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .unwrap();
        let mut line = String::new();
        BufReader::new(guest).read_line(&mut line).unwrap();
        assert!(line.starts_with("HTTP/1.1 403"), "{line}");
        let pins = m
            .wait_for_pins(&plan, &(Arc::new(std::time::SystemTime::now) as Clock))
            .unwrap();
        crate::network::check_pinned(&plan, &pins).unwrap();
        assert_eq!(m.network_lost(), None);
        let audit = d.path().join("network.jsonl");
        m.finish(&audit, &|_| {});
        let text = std::fs::read_to_string(&audit).unwrap();
        assert!(
            text.contains("example.com:443") && text.contains("\"refused\""),
            "{text}"
        );
    }

    #[test]
    fn a_vm_that_stops_during_boot_fails_create_and_exec() {
        let (host, image, _d) = rig(true, 1024);
        let m = HyperVMachine::new("rts-0123456789ab", host, image);
        let e = m.create(&spec(1024)).unwrap_err().to_string();
        assert!(
            e.contains("stopped during boot") && e.contains("UnexpectedExit"),
            "{e}"
        );
        assert!(matches!(
            m.exec(&sv(&["true"]), &ExecOptions::new(1000, 64)),
            Err(Error::Unavailable(_))
        ));
    }

    #[test]
    fn remove_terminates_confirms_and_kills_later_execs() {
        let (host, image, _d) = rig(false, 1024);
        let m = HyperVMachine::new("rts-0123456789ab", host.clone(), image);
        m.create(&spec(1024)).unwrap();
        m.remove().unwrap();
        assert_eq!(*host.vm.calls.lock().unwrap(), ["start", "terminate"]);
        assert!(matches!(
            m.exec(&sv(&["true"]), &ExecOptions::new(1000, 64)),
            Err(Error::Unavailable(_))
        ));
    }

    #[test]
    fn the_monitor_refuses_a_stopped_vm_a_resized_vm_or_one_over_the_ceiling() {
        let (host, image, _d) = rig(false, 1024);
        let m = HyperVMachine::new("rts-0123456789ab", host.clone(), image);
        m.create(&spec(1024)).unwrap();
        let mon = m.monitor().unwrap();
        let what = mon.describe();
        assert!(
            what.contains("configured") && what.contains("not measured"),
            "{what}"
        );
        assert_eq!(mon.sample(2048), Ok(1024));
        assert!(mon.sample(512).unwrap_err().contains("ceiling"));
        let (host2, image2, _d2) = rig(false, 2048);
        let resized = HyperVMachine::new("rts-0123456789ab", host2, image2);
        resized.create(&spec(1024)).unwrap();
        assert!(
            resized
                .monitor()
                .unwrap()
                .sample(4096)
                .unwrap_err()
                .contains("not the configured")
        );
        m.remove().unwrap();
        assert!(mon.sample(2048).unwrap_err().contains("no longer running"));
    }

    #[test]
    fn create_records_the_vm_id_owner_only_and_a_confirmed_remove_forgets_it() {
        let (host, image, _d) = rig(false, 1024);
        let m = HyperVMachine::new("rts-0123456789ab", host, image.clone());
        m.create(&spec(1024)).unwrap();
        let recorded = recorded_vms(&image.vm_ids);
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].1, "rts-0123456789ab");
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(image.vm_ids.join(&recorded[0].0))
                .unwrap()
                .permissions(),
        ) & 0o777;
        assert_eq!(mode, 0o600);
        m.remove().unwrap();
        assert!(recorded_vms(&image.vm_ids).is_empty());
    }

    #[test]
    fn the_sweep_reports_a_recorded_vm_still_running_and_drops_records_of_gone_ones() {
        let (host, image, _d) = rig(false, 1024);
        let running = Arc::new(FakeVm {
            calls: Mutex::new(vec![]),
            running: AtomicBool::new(true),
            stops_on_start: false,
            assigned: 1024,
        });
        let stopped = Arc::new(FakeVm {
            calls: Mutex::new(vec![]),
            running: AtomicBool::new(false),
            stops_on_start: false,
            assigned: 1024,
        });
        let (a, b, c) = (new_vm_id(), new_vm_id(), new_vm_id());
        for (id, name) in [
            (&a, "rts-aaaaaaaaaaaa"),
            (&b, "rts-bbbbbbbbbbbb"),
            (&c, "rts-cccccccccccc"),
        ] {
            record_vm(&image.vm_ids, id, name).unwrap();
        }
        host.opened
            .lock()
            .unwrap()
            .extend([(a.clone(), running.clone()), (b.clone(), stopped)]);
        let backend = super::super::backend::HyperVBackend::new(host, image.clone(), 0x30, None);
        let mut lines = vec![];
        crate::backend::Backend::sweep(&backend, &mut |l| lines.push(l.to_string())).unwrap();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains(&a)
                && lines[0].contains("rts-aaaaaaaaaaaa")
                && lines[0].contains("still running")
        );
        assert_eq!(
            recorded_vms(&image.vm_ids)
                .into_iter()
                .map(|(i, _)| i)
                .collect::<Vec<_>>(),
            [a]
        );
        assert!(
            running.running.load(Ordering::SeqCst),
            "the sweep never stops a VM"
        );
    }
}

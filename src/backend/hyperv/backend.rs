//! The Windows backend: Hyper-V compute systems booted from rts's pinned
//! guest kernel and initramfs. The edition and artifact checks are plain
//! functions, tested on every OS; `HyperVBackend::windows` reads the real
//! host.
//!
//! Memory: each VM's guest memory is fixed and fully committed, and the
//! RSS-ceiling monitor checks the configured (assigned) size HCS reports,
//! not measured usage. The Hyper-V worker process (vmwp.exe) overhead is
//! not counted. See `machine::HvMonitor`.

use std::path::{Path, PathBuf};

use super::machine::{GuestImage, HyperVMachine, VmHost};
use crate::backend::{Backend, HostCheck, Machine};

/// sha256 of the guest kernel built by guest/hyperv/build.sh.
pub const KERNEL_SHA256: &str = "a331c0ab03687e36fea6ecca473c5fdb0351e76c0331f7be8fddd1cfe62b2d58";
/// sha256 of the guest initramfs built by guest/hyperv/build-initramfs.py.
pub const INITRD_SHA256: &str = "cdef2be2e9e687ebdd32b96717e687cb5b43723c142ddcf5a71b4d5b056b0a00";

pub const KERNEL_FILE: &str = "vmlinuz";
pub const INITRD_FILE: &str = "initramfs.cpio.gz";

/// Why this Windows edition (GetProductInfo's product type) cannot run
/// rts, if it cannot. Home editions have no Hyper-V.
pub fn edition_problem(product_type: u32) -> Option<&'static str> {
    match product_type {
        // PRODUCT_CORE_N, _COUNTRYSPECIFIC, _SINGLELANGUAGE, PRODUCT_CORE
        98..=101 => Some(
            "Windows Home is not supported: rts runs its sandbox in a Hyper-V virtual machine, and \
             Windows Home has no Hyper-V. Use Windows 11 Pro, Enterprise or Education.",
        ),
        0 => Some("cannot determine the Windows edition (GetProductInfo returned no product type)"),
        _ => None,
    }
}

fn artifact_problem(path: &Path, want: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    match std::fs::read(path) {
        Err(e) => Some(format!(
            "the rts guest file {} is missing ({e}); run rts setup",
            path.display()
        )),
        Ok(bytes) if hex::encode(Sha256::digest(&bytes)) != want => Some(format!(
            "the rts guest file {} does not match its pinned digest; run rts setup",
            path.display()
        )),
        Ok(_) => None,
    }
}

pub struct HyperVBackend<H: VmHost + Clone + 'static> {
    host: H,
    image: GuestImage,
    product_type: u32,
    /// Why HCS cannot be used here (computecore.dll did not load), if so.
    hyperv_problem: Option<String>,
}

impl<H: VmHost + Clone + 'static> HyperVBackend<H> {
    pub fn new(
        host: H,
        image: GuestImage,
        product_type: u32,
        hyperv_problem: Option<String>,
    ) -> Self {
        Self {
            host,
            image,
            product_type,
            hyperv_problem,
        }
    }

    /// The guest image in `dir`, with rts's pins, for `user_sid`.
    pub fn image_in(dir: &Path, user_sid: &str) -> GuestImage {
        GuestImage {
            kernel: dir.join(KERNEL_FILE),
            kernel_sha256: KERNEL_SHA256.into(),
            initrd: dir.join(INITRD_FILE),
            initrd_sha256: INITRD_SHA256.into(),
            user_sid: user_sid.into(),
            pipe_prefix: r"\\.\pipe\rts-".into(),
            vm_ids: dir.join("vms"),
        }
    }
}

impl<H: VmHost + Clone + 'static> Backend for HyperVBackend<H> {
    /// The Hyper-V prerequisites: a Windows edition with Hyper-V, and the
    /// pinned guest kernel and initramfs. (OpenCode and the provider are
    /// checked with the interactive launch, phase 6.)
    fn preflight(&self, _check: &HostCheck) -> Result<(), String> {
        if let Some(why) = edition_problem(self.product_type) {
            return Err(why.into());
        }
        if let Some(why) = &self.hyperv_problem {
            return Err(why.clone());
        }
        for (path, want) in [
            (&self.image.kernel, &self.image.kernel_sha256),
            (&self.image.initrd, &self.image.initrd_sha256),
        ] {
            if let Some(why) = artifact_problem(path, want) {
                return Err(why);
            }
        }
        Ok(())
    }

    /// The VM has no network adapter, so no host setting can give it a
    /// route: nothing to check.
    fn check_host_config(&self) -> Result<(), String> {
        Ok(())
    }

    /// Every compute system is created with ShouldTerminateOnLastHandleClosed
    /// and only the rts process that made it holds a handle, so a VM stops
    /// with that process. As defence in depth, each VM's id is recorded
    /// before it is created and forgotten once its removal is confirmed:
    /// report (never stop) any recorded VM still running, and drop records
    /// of VMs that are gone.
    fn sweep(&self, log: &mut dyn FnMut(&str)) -> Result<(), String> {
        for (id, name) in super::machine::recorded_vms(&self.image.vm_ids) {
            match self.host.open(&id) {
                Ok(Some(vm)) if matches!(vm.state(), Ok(super::props::VmState::Running)) => {
                    log(&format!(
                        "[rts] Hyper-V VM {id} ({name}) from an earlier launch is still running"
                    ));
                }
                Ok(_) => super::machine::forget_vm(&self.image.vm_ids, &id),
                Err(e) => log(&format!("[rts] cannot check Hyper-V VM {id} ({name}): {e}")),
            }
        }
        Ok(())
    }

    fn machine(&self, name: &str) -> Result<Box<dyn Machine>, String> {
        Ok(Box::new(HyperVMachine::new(
            name,
            self.host.clone(),
            self.image.clone(),
        )))
    }
}

/// The directory setup installs the guest kernel and initramfs into:
/// `RTS_HV_DIR`, else `%LOCALAPPDATA%\nearai-red-sandbox\hyperv`.
pub fn guest_dir(env: &[(String, String)]) -> Option<PathBuf> {
    let get = |k: &str| {
        env.iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(k))
            .map(|(_, v)| v.clone())
    };
    get("RTS_HV_DIR").map(PathBuf::from).or_else(|| {
        get("LOCALAPPDATA").map(|d| Path::new(&d).join("nearai-red-sandbox").join("hyperv"))
    })
}

#[cfg(windows)]
impl HyperVBackend<super::machine::HcsHost> {
    /// This host's backend: its edition, its user, its installed guest image.
    pub fn windows(env: &[(String, String)]) -> Result<Self, String> {
        use windows_sys::Win32::System::SystemInformation::GetProductInfo;
        let mut product_type = 0u32;
        // SAFETY: a plain query with a valid out-pointer.
        unsafe { GetProductInfo(10, 0, 0, 0, &mut product_type) };
        let dir = guest_dir(env)
            .ok_or("cannot find the rts guest directory (LOCALAPPDATA is not set)")?;
        let sid = crate::sys::fs::current_user_sid()
            .map_err(|e| format!("cannot read the current user's SID: {e}"))?;
        Ok(Self::new(
            super::machine::HcsHost,
            Self::image_in(&dir, &sid),
            product_type,
            super::hcs::available().err().map(|e| e.to_string()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_editions_are_refused_by_name_and_others_pass() {
        for home in [98, 99, 100, 101] {
            assert!(
                edition_problem(home)
                    .unwrap()
                    .contains("Windows Home is not supported")
            );
        }
        assert!(edition_problem(0).is_some());
        // PRODUCT_PROFESSIONAL, _ENTERPRISE, _EDUCATION, _DATACENTER_SERVER
        for ok in [0x30, 0x04, 0x79, 0x08] {
            assert_eq!(edition_problem(ok), None, "{ok:#x}");
        }
    }

    #[test]
    fn the_guest_dir_comes_from_rts_hv_dir_then_localappdata() {
        let env = |v: &[(&str, &str)]| {
            v.iter()
                .map(|(k, x)| (k.to_string(), x.to_string()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            guest_dir(&env(&[("RTS_HV_DIR", "/x"), ("LOCALAPPDATA", "/l")])),
            Some(PathBuf::from("/x"))
        );
        assert_eq!(
            guest_dir(&env(&[("LocalAppData", "/l")])),
            Some(Path::new("/l").join("nearai-red-sandbox").join("hyperv"))
        );
        assert_eq!(guest_dir(&env(&[])), None);
    }

    #[test]
    fn a_missing_or_swapped_guest_file_names_itself_and_setup() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(KERNEL_FILE);
        assert!(
            artifact_problem(&p, KERNEL_SHA256)
                .unwrap()
                .contains("missing")
        );
        std::fs::write(&p, b"not the kernel").unwrap();
        let e = artifact_problem(&p, KERNEL_SHA256).unwrap();
        assert!(
            e.contains("pinned digest") && e.contains("rts setup"),
            "{e}"
        );
        use sha2::{Digest, Sha256};
        assert_eq!(
            artifact_problem(&p, &hex::encode(Sha256::digest(b"not the kernel"))),
            None
        );
    }
}

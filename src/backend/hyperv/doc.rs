//! The HCS compute-system document for an rts guest, and the hvsocket
//! service ids. Pure data, so it is built and tested on every OS; only the
//! Windows backend submits it.
//!
//! The document is the whole device list of the VM. It names a kernel, an
//! initramfs, memory, vCPUs, an optional COM-port log pipe and exactly two
//! hvsocket services (exec and egress). It never has a network adapter, a
//! disk, a Plan 9 share or a shared folder: the guest's only channel to the
//! host is those two services.

use serde_json::{Value, json};

/// hvsocket's mapping of a vsock port to a service id.
pub fn service_id(port: u32) -> String {
    format!("{port:08x}-facb-11e6-bd58-64006a7986d3")
}

/// A GUID string ("xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", hex, any case)
/// as its fields: data1, data2, data3, data4 (Windows' GUID layout).
pub fn parse_guid(s: &str) -> Option<(u32, u16, u16, [u8; 8])> {
    let parts: Vec<&str> = s.split('-').collect();
    let lens: Vec<usize> = parts.iter().map(|p| p.len()).collect();
    if lens != [8, 4, 4, 4, 12] || !s.bytes().all(|b| b == b'-' || b.is_ascii_hexdigit()) {
        return None;
    }
    let tail = format!("{}{}", parts[3], parts[4]);
    let mut d4 = [0u8; 8];
    for (i, b) in d4.iter_mut().enumerate() {
        *b = u8::from_str_radix(&tail[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some((
        u32::from_str_radix(parts[0], 16).ok()?,
        u16::from_str_radix(parts[1], 16).ok()?,
        u16::from_str_radix(parts[2], 16).ok()?,
        d4,
    ))
}

/// A fresh random (version 4) GUID string for a compute system id.
pub fn new_vm_id() -> String {
    let h = crate::protocol::random_hex(16);
    let mut b: Vec<u8> = (0..16)
        .map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let x: String = b.iter().map(|v| format!("{v:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &x[0..8],
        &x[8..12],
        &x[12..16],
        &x[16..20],
        &x[20..32]
    )
}

/// The exec agent's vsock port in the guest (`rts-guest`).
pub const EXEC_PORT: u32 = 5000;
/// The guest egress forwarder's vsock port (the host's CONNECT endpoint).
pub const EGRESS_PORT: u32 = 5001;

/// Owner string on every rts compute system, for the orphan sweep.
pub const OWNER: &str = "rts";

/// Kernel command line: serial console, initramfs init, reboot on panic
/// (which StopOnReset turns into a stop).
pub const KERNEL_CMDLINE: &str = "console=ttyS0 rdinit=/init panic=-1 loglevel=4";

pub struct VmSpec<'a> {
    pub kernel: &'a str,
    pub initrd: &'a str,
    pub memory_mib: u64,
    pub cpus: u32,
    /// `\\.\pipe\...` for the guest's serial console. Required: without a
    /// COM port behind ttyS0 the guest never reaches its agent (seen live on
    /// Hyper-V, host build 26100).
    pub com_pipe: &'a str,
    /// SID of the session's user: the only account, with SYSTEM, that may
    /// bind or connect the VM's services.
    pub user_sid: &'a str,
}

/// The security descriptor on both services and the defaults: SYSTEM and
/// the session's user, nobody else.
fn descriptor(user_sid: &str) -> String {
    format!("D:P(A;;FA;;;SY)(A;;FA;;;{user_sid})")
}

pub fn document(spec: &VmSpec) -> Value {
    let sd = descriptor(spec.user_sid);
    let service = json!({
        "BindSecurityDescriptor": sd,
        "ConnectSecurityDescriptor": sd,
        // The host binds this VM's id, never the wildcard.
        "AllowWildcardBinds": false,
    });
    let mut services = serde_json::Map::new();
    for port in [EXEC_PORT, EGRESS_PORT] {
        services.insert(service_id(port), service.clone());
    }
    json!({
        "Owner": OWNER,
        "SchemaVersion": {"Major": 2, "Minor": 1},
        "ShouldTerminateOnLastHandleClosed": true,
        "VirtualMachine": {
            "StopOnReset": true,
            "Chipset": {"LinuxKernelDirect": {
                "KernelFilePath": spec.kernel,
                "InitRdPath": spec.initrd,
                "KernelCmdLine": KERNEL_CMDLINE,
            }},
            "ComputeTopology": {
                // Fixed and fully committed: no overcommit (pageable backing) and
                // no deferred commit, so assigned memory is the host footprint.
                "Memory": {
                    "SizeInMB": spec.memory_mib,
                    "AllowOvercommit": false,
                    "EnableDeferredCommit": false,
                },
                "Processor": {"Count": spec.cpus},
            },
            "Devices": {
                "ComPorts": {"0": {"NamedPipe": spec.com_pipe}},
                "HvSocket": {"HvSocketConfig": {
                    "DefaultBindSecurityDescriptor": sd,
                    "DefaultConnectSecurityDescriptor": sd,
                    "ServiceTable": services,
                }},
            },
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> VmSpec<'static> {
        VmSpec {
            kernel: r"C:\rts\guest\vmlinuz",
            initrd: r"C:\rts\guest\initramfs.cpio.gz",
            memory_mib: 2048,
            cpus: 2,
            com_pipe: r"\\.\pipe\rts-0123456789ab-com1",
            user_sid: "S-1-5-21-1-2-3-1001",
        }
    }

    /// Every key anywhere in `v`.
    fn keys(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(m) => {
                for (k, x) in m {
                    out.push(k.clone());
                    keys(x, out);
                }
            }
            Value::Array(a) => a.iter().for_each(|x| keys(x, out)),
            _ => {}
        }
    }

    #[test]
    fn guids_parse_into_windows_fields_and_bad_ones_are_refused() {
        assert_eq!(
            parse_guid("00001388-FACB-11e6-bd58-64006a7986d3"),
            Some((
                0x1388,
                0xfacb,
                0x11e6,
                [0xbd, 0x58, 0x64, 0x00, 0x6a, 0x79, 0x86, 0xd3]
            ))
        );
        for bad in [
            "",
            "00001388facb11e6bd5864006a7986d3",
            "0001388-facb-11e6-bd58-64006a7986d3",
            "g0001388-facb-11e6-bd58-64006a7986d3",
            "+0001388-facb-11e6-bd58-64006a7986d3",
        ] {
            assert_eq!(parse_guid(bad), None, "{bad}");
        }
        let id = new_vm_id();
        assert!(parse_guid(&id).is_some(), "{id}");
        assert_eq!(&id[14..15], "4", "version 4: {id}");
        assert!("89ab".contains(&id[19..20]), "RFC 4122 variant: {id}");
        assert_ne!(new_vm_id(), id);
    }

    #[test]
    fn service_ids_follow_the_hvsocket_vsock_template() {
        assert_eq!(
            service_id(EXEC_PORT),
            "00001388-facb-11e6-bd58-64006a7986d3"
        );
        assert_eq!(
            service_id(EGRESS_PORT),
            "00001389-facb-11e6-bd58-64006a7986d3"
        );
        assert_eq!(
            service_id(0xdead_beef),
            "deadbeef-facb-11e6-bd58-64006a7986d3"
        );
    }

    #[test]
    fn the_vm_has_no_device_but_the_two_hvsocket_services() {
        let doc = document(&spec());
        let mut all = vec![];
        keys(&doc, &mut all);
        for forbidden in [
            "NetworkAdapters",
            "Scsi",
            "Plan9",
            "VirtualSmb",
            "MappedDirectories",
            "MappedPipes",
            "Keyboard",
            "Mouse",
            "VideoMonitor",
            "EnhancedModeVideo",
            "GuestInterface",
            "Battery",
            "VirtualPMem",
            "VirtioSerial",
            "FlexibleIov",
            "SharedMemory",
            "GuestCrashReporting",
        ] {
            assert!(!all.iter().any(|k| k == forbidden), "{forbidden} in {doc}");
        }
        let devices = doc["VirtualMachine"]["Devices"].as_object().unwrap();
        let mut names: Vec<_> = devices.keys().cloned().collect();
        names.sort();
        assert_eq!(names, ["ComPorts", "HvSocket"]);
        let table = doc["VirtualMachine"]["Devices"]["HvSocket"]["HvSocketConfig"]["ServiceTable"]
            .as_object()
            .unwrap();
        let mut services: Vec<_> = table.keys().cloned().collect();
        services.sort();
        assert_eq!(services, [service_id(EXEC_PORT), service_id(EGRESS_PORT)]);
    }

    #[test]
    fn only_system_and_the_session_user_may_bind_or_connect() {
        let doc = document(&spec());
        let config = &doc["VirtualMachine"]["Devices"]["HvSocket"]["HvSocketConfig"];
        let want = "D:P(A;;FA;;;SY)(A;;FA;;;S-1-5-21-1-2-3-1001)";
        assert_eq!(config["DefaultBindSecurityDescriptor"], want);
        assert_eq!(config["DefaultConnectSecurityDescriptor"], want);
        for (_, service) in config["ServiceTable"].as_object().unwrap() {
            assert_eq!(service["BindSecurityDescriptor"], want);
            assert_eq!(service["ConnectSecurityDescriptor"], want);
            assert_eq!(
                service["AllowWildcardBinds"], false,
                "the host binds the VM id, never the wildcard"
            );
        }
    }

    #[test]
    fn guest_memory_is_fixed_and_fully_committed() {
        // No overcommit and no deferred commit: the VM's memory is reserved
        // in full when it starts, so its assigned size is its host footprint
        // (what the Windows monitor reports).
        let memory = &document(&spec())["VirtualMachine"]["ComputeTopology"]["Memory"];
        assert_eq!(memory["AllowOvercommit"], false, "{memory}");
        assert_eq!(memory["EnableDeferredCommit"], false, "{memory}");
        assert_eq!(memory["SizeInMB"], 2048);
    }

    #[test]
    fn boot_size_and_lifetime_come_from_the_spec() {
        let doc = document(&spec());
        assert_eq!(doc["Owner"], OWNER);
        assert_eq!(doc["SchemaVersion"], json!({"Major": 2, "Minor": 1}));
        assert_eq!(doc["ShouldTerminateOnLastHandleClosed"], true);
        let vm = &doc["VirtualMachine"];
        assert_eq!(vm["StopOnReset"], true);
        assert_eq!(
            vm["Chipset"],
            json!({"LinuxKernelDirect": {
                "KernelFilePath": r"C:\rts\guest\vmlinuz",
                "InitRdPath": r"C:\rts\guest\initramfs.cpio.gz",
                "KernelCmdLine": KERNEL_CMDLINE,
            }})
        );
        assert_eq!(
            vm["ComputeTopology"],
            json!({"Memory": {"SizeInMB": 2048, "AllowOvercommit": false, "EnableDeferredCommit": false}, "Processor": {"Count": 2}})
        );
        assert_eq!(
            vm["Devices"]["ComPorts"],
            json!({"0": {"NamedPipe": r"\\.\pipe\rts-0123456789ab-com1"}})
        );
    }
}

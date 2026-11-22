//! Reading HCS property documents: whether the VM is running, how it
//! stopped, and the memory assigned to it. Pure, so tested everywhere.
//! Shapes recorded live on Hyper-V (host build 26100).

use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmState {
    Running,
    /// Stopped, with HCS's ExitType ("UnexpectedExit", "GracefulExit", ...).
    Stopped(String),
    /// Any other State HCS reports (Created, Paused, ...).
    Other(String),
}

fn parse(doc: &str) -> Result<Value, String> {
    serde_json::from_str(doc).map_err(|e| format!("HCS properties are not JSON: {e}"))
}

/// The state in a `{}` (or any) properties document.
pub fn state(doc: &str) -> Result<VmState, String> {
    let v = parse(doc)?;
    // A system that has exited reports Stopped and ExitType instead of State.
    if v["Stopped"] == Value::Bool(true) {
        let exit = v["ExitType"].as_str().unwrap_or("unknown");
        return Ok(VmState::Stopped(exit.to_string()));
    }
    match v["State"].as_str() {
        Some("Running") => Ok(VmState::Running),
        Some("Stopped") => Ok(VmState::Stopped(
            v["ExitType"].as_str().unwrap_or("unknown").to_string(),
        )),
        Some(other) => Ok(VmState::Other(other.to_string())),
        None => Err("HCS properties have no State".into()),
    }
}

/// MiB assigned to the VM in a `{"PropertyTypes":["Memory"]}` document
/// (Memory.VirtualMachineMemory.AssignedMemory, in 4 KiB pages).
pub fn assigned_memory_mib(doc: &str) -> Result<u64, String> {
    let pages = parse(doc)?["Memory"]["VirtualMachineMemory"]["AssignedMemory"]
        .as_u64()
        .ok_or("HCS memory properties have no AssignedMemory")?;
    Ok(pages * 4 / 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUNNING: &str = r#"{"Id":"bf3daef7-8dde-4060-94aa-82c07add2e65","SystemType":"VirtualMachine","Owner":"rts","RuntimeId":"bf3daef7-8dde-4060-94aa-82c07add2e65","State":"Running"}"#;
    const EXITED: &str = r#"{"Id":"9d586618-62c8-4616-b39b-bc6e7ff2a154","SystemType":"Container","Stopped":true,"ExitType":"UnexpectedExit"}"#;
    const MEMORY: &str = r#"{"Id":"d9dc14e2-3ba3-46b6-a4a7-87d3a5d3fc5e","State":"Running","Memory":{"VirtualNodeCount":1,"VirtualMachineMemory":{"AvailableMemory":2147483647,"AvailableMemoryBuffer":2147483647,"ReservedMemory":262144,"AssignedMemory":262144,"SlpActive":false,"BalancingEnabled":false,"DmOperationInProgress":false},"VirtualNodes":[{"VirtualNodeIndex":0,"PhysicalNodeNumber":0,"VirtualProcessorCount":2,"MemoryUsageInPages":262144}]}}"#;

    #[test]
    fn running_and_stopped_vms_are_told_apart() {
        assert_eq!(state(RUNNING), Ok(VmState::Running));
        assert_eq!(state(EXITED), Ok(VmState::Stopped("UnexpectedExit".into())));
        assert_eq!(
            state(r#"{"State":"Paused"}"#),
            Ok(VmState::Other("Paused".into()))
        );
        assert_eq!(
            state(r#"{"Stopped":true}"#),
            Ok(VmState::Stopped("unknown".into()))
        );
    }

    #[test]
    fn a_document_without_a_state_or_not_json_is_an_error() {
        assert!(state("").is_err());
        assert!(state("not json").is_err());
        assert!(state(r#"{"Id":"x"}"#).is_err());
        assert!(state(r#"{"State":7}"#).is_err());
    }

    #[test]
    fn assigned_memory_is_read_in_mib_and_must_be_present() {
        assert_eq!(assigned_memory_mib(MEMORY), Ok(1024));
        assert!(assigned_memory_mib(RUNNING).is_err());
        assert!(
            assigned_memory_mib(r#"{"Memory":{"VirtualMachineMemory":{"AssignedMemory":-1}}}"#)
                .is_err()
        );
        assert!(
            assigned_memory_mib(r#"{"Memory":{"VirtualMachineMemory":{"AssignedMemory":"1"}}}"#)
                .is_err()
        );
    }
}

/// Wait until `probe` reaches the guest agent while the VM stays running.
/// Fails at once if the VM stops (naming how), or after `timeout`. Returns
/// how long it took.
pub fn wait_ready(
    mut state: impl FnMut() -> Result<VmState, String>,
    mut probe: impl FnMut() -> bool,
    timeout: std::time::Duration,
    poll: std::time::Duration,
) -> Result<std::time::Duration, String> {
    let start = std::time::Instant::now();
    loop {
        match state()? {
            VmState::Running => {
                if probe() {
                    return Ok(start.elapsed());
                }
            }
            VmState::Stopped(exit) => return Err(format!("the VM stopped during boot ({exit})")),
            VmState::Other(_) => {}
        }
        if start.elapsed() >= timeout {
            return Err(format!(
                "the guest agent did not answer within {} s",
                timeout.as_secs()
            ));
        }
        std::thread::sleep(poll);
    }
}

#[cfg(test)]
mod wait_tests {
    use super::*;
    use std::cell::Cell;
    use std::time::Duration;

    const MS: Duration = Duration::from_millis(1);

    #[test]
    fn ready_once_the_agent_answers() {
        let tries = Cell::new(0);
        let r = wait_ready(
            || Ok(VmState::Running),
            || {
                tries.set(tries.get() + 1);
                tries.get() == 3
            },
            Duration::from_secs(5),
            MS,
        );
        assert!(r.is_ok(), "{r:?}");
        assert_eq!(tries.get(), 3);
    }

    #[test]
    fn a_vm_that_stops_during_boot_fails_at_once_with_its_exit_type() {
        let n = Cell::new(0);
        let r = wait_ready(
            || {
                n.set(n.get() + 1);
                Ok(if n.get() < 2 {
                    VmState::Running
                } else {
                    VmState::Stopped("UnexpectedExit".into())
                })
            },
            || false,
            Duration::from_secs(60),
            MS,
        );
        let e = r.unwrap_err();
        assert!(e.contains("stopped") && e.contains("UnexpectedExit"), "{e}");
        assert!(n.get() <= 3);
    }

    #[test]
    fn no_answer_within_the_timeout_or_an_unreadable_state_fails() {
        let e = wait_ready(
            || Ok(VmState::Running),
            || false,
            Duration::from_millis(50),
            MS,
        )
        .unwrap_err();
        assert!(e.contains("did not answer"), "{e}");
        let e = wait_ready(
            || Err("bad json".into()),
            || true,
            Duration::from_secs(5),
            MS,
        )
        .unwrap_err();
        assert!(e.contains("bad json"), "{e}");
    }
}

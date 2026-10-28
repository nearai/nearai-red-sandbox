use rts::sandbox::{Exec, ExecOptions};
use rts::sandbox::sv;

use crate::harness::{fresh_machine, limits, mvm};

#[test]
#[ignore = "real mvm"]
fn a_nonzero_exit_is_reported_and_does_not_poison_the_machine() {
    let Some(h) = mvm() else { return };
    let m = fresh_machine(h);
    assert_eq!(m.exec(&sv(&["sh", "-c", "exit 3"]), &limits()).unwrap().exit_code, 3);
    assert_eq!(m.exec(&sv(&["echo", "ok"]), &limits()).unwrap().stdout, b"ok\n");
}

#[test]
#[ignore = "real mvm"]
fn the_guest_time_limit_kills_with_137_and_the_machine_stays_usable() {
    let Some(h) = mvm() else { return };
    let m = fresh_machine(h);
    let r = m.exec(&sv(&["sleep", "30"]), &ExecOptions { timeout_ms: 3000, ..limits() }).unwrap();
    assert!(r.timed_out);
    assert_eq!(r.exit_code, 137);
    assert_eq!(m.exec(&sv(&["echo", "ok"]), &limits()).unwrap().exit_code, 0);
}

#[test]
#[ignore = "real mvm"]
fn large_stdout_is_capped_in_the_guest_with_the_full_size_reported() {
    let Some(h) = mvm() else { return };
    let m = fresh_machine(h);
    let r = m.exec(&sv(&["head", "-c", "2097152", "/dev/zero"]), &ExecOptions { max_output_bytes: 65_536, ..limits() }).unwrap();
    assert_eq!(r.stdout.len(), 65_536);
    assert!(r.truncated);
    assert_eq!(r.stdout_bytes, 2_097_152);
}

#[test]
#[ignore = "real mvm"]
fn the_guest_has_no_network() {
    let Some(h) = mvm() else { return };
    let m = fresh_machine(h);
    let links = m.exec(&sv(&["ip", "-o", "link"]), &limits()).unwrap();
    let text = String::from_utf8_lossy(&links.stdout);
    let names: Vec<&str> = text.lines().filter_map(|l| l.split(':').nth(1)).map(str::trim).collect();
    assert_eq!(names, ["lo"]);
    let w = m.exec(&sv(&["wget", "-q", "-T", "5", "-O-", "http://1.1.1.1"]), &limits()).unwrap();
    assert_ne!(w.exit_code, 0);
}

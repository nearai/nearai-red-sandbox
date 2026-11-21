use rts::sandbox::ExecOptions;
use rts::sandbox::sv;

use crate::harness::{fresh_guest, limits};

#[test]
#[ignore = "real VM"]
fn a_nonzero_exit_is_reported_and_does_not_poison_the_machine() {
    let m = fresh_guest();
    assert_eq!(m.exec(&sv(&["sh", "-c", "exit 3"]), &limits()).unwrap().exit_code, 3);
    assert_eq!(m.exec(&sv(&["echo", "ok"]), &limits()).unwrap().stdout, b"ok\n");
}

#[test]
#[ignore = "real VM"]
fn the_guest_time_limit_kills_with_137_and_the_machine_stays_usable() {
    let m = fresh_guest();
    let r = m.exec(&sv(&["sleep", "30"]), &ExecOptions { timeout_ms: 3000, ..limits() }).unwrap();
    assert!(r.timed_out);
    assert_eq!(r.exit_code, 137);
    assert_eq!(m.exec(&sv(&["echo", "ok"]), &limits()).unwrap().exit_code, 0);
}

#[test]
#[ignore = "real VM"]
fn large_stdout_is_capped_in_the_guest_with_the_full_size_reported() {
    let m = fresh_guest();
    let r = m.exec(&sv(&["head", "-c", "2097152", "/dev/zero"]), &ExecOptions { max_output_bytes: 65_536, ..limits() }).unwrap();
    assert_eq!(r.stdout.len(), 65_536);
    assert!(r.truncated);
    assert_eq!(r.stdout_bytes, 2_097_152);
}

#[test]
#[ignore = "real VM"]
fn the_guest_has_no_network() {
    let m = fresh_guest();
    // Both tools must exist, or their failure below proves nothing.
    let tools = m
        .exec(
            &sv(&["sh", "-c", "command -v ip && command -v wget"]),
            &limits(),
        )
        .unwrap();
    assert_eq!(
        tools.exit_code,
        0,
        "the guest lacks ip or wget: {}",
        String::from_utf8_lossy(&tools.stdout)
    );
    let links = m.exec(&sv(&["ip", "-o", "link"]), &limits()).unwrap();
    let text = String::from_utf8_lossy(&links.stdout);
    let names: Vec<&str> = text.lines().filter_map(|l| l.split(':').nth(1)).map(str::trim).collect();
    assert_eq!(names, ["lo"]);
    let w = m.exec(&sv(&["wget", "-q", "-T", "5", "-O-", "http://1.1.1.1"]), &limits()).unwrap();
    assert_ne!(w.exit_code, 0);
}

//! Leak-detection check: swap `shell` for a host implementation through the
//! RTS_TEST_LEAK seam, rerun the sentinel test, and require it to fail on
//! the host-sentinel assertion. If the containment suite cannot see a leak
//! this blatant, it proves nothing.

use std::process::Command;

use crate::harness::mvm;

#[test]
#[ignore = "real mvm"]
fn the_sentinel_test_fails_when_shell_leaks_to_the_host() {
    if mvm().is_none() {
        return;
    }
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["session::sentinel_write_and_shell_touch_land_in_the_guest_and_not_on_the_host", "--exact", "--ignored", "--nocapture"])
        .env("RTS_TEST_LEAK", "shell")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{text}");
    assert!(text.contains("LEAK: host sentinel present"), "{text}");
}

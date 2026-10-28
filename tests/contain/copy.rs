use std::fs;
use std::path::Path;

use rts::copy::{CopyLimits, copy_out_via};
use rts::files::{guest_sha256, guest_write};
use rts::protocol::random_hex;
use rts::sandbox::{CopyOutResult, Error, Exec, ExecOptions, Sandbox, sv};
use sha2::{Digest, Sha256};

use crate::harness::{Machine, fresh_machine, limits, mvm, tempdir};

fn sha(b: &[u8]) -> String {
    Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

fn random(n: usize) -> Vec<u8> {
    let hex = random_hex(n);
    (0..n).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap()).collect()
}

#[test]
#[ignore = "real mvm"]
fn copy_in_delivers_a_nested_tree_with_a_300_kib_file() {
    let Some(h) = mvm() else { return };
    let m = fresh_machine(h);
    let root = tempdir("copy");
    let src = root.join("inputs");
    fs::create_dir_all(src.join("a/b")).unwrap();
    let big = random(300 * 1024);
    fs::write(src.join("a/b/big.bin"), &big).unwrap();
    fs::write(src.join("note.txt"), "note").unwrap();
    m.copy_in(&src, "/in").unwrap();
    assert_eq!(guest_sha256(&*m, "/in/a/b/big.bin").unwrap(), sha(&big));
    assert_eq!(guest_sha256(&*m, "/in/note.txt").unwrap(), sha(b"note"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "real mvm"]
fn copy_out_brings_guest_out_back_byte_exact() {
    let Some(h) = mvm() else { return };
    let m = fresh_machine(h);
    let root = tempdir("copy");
    let blob = random(700 * 1024); // spans multiple transport read slices
    guest_write(&*m, "/out/sub/blob", &blob).unwrap();
    guest_write(&*m, "/out/hello.txt", b"hi").unwrap();
    // Repeat exports on the same VM: each export spans many transport
    // frames, and a single lucky pass cannot establish reliability.
    for round in 0..4 {
        let dest = root.join(format!("out-{round}"));
        assert_eq!(m.copy_out("/out", &dest).unwrap(), CopyOutResult::Exported { files: 2, bytes: blob.len() as u64 + 2 });
        assert_eq!(fs::read(dest.join("sub/blob")).unwrap(), blob);
        assert_eq!(fs::read_to_string(dest.join("hello.txt")).unwrap(), "hi");
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "real mvm"]
fn a_missing_or_empty_out_is_nothing_to_export() {
    let Some(h) = mvm() else { return };
    let m = fresh_machine(h);
    let root = tempdir("copy");
    m.exec(&sv(&["rm", "-rf", "/out"]), &limits()).unwrap();
    assert_eq!(m.copy_out("/out", &root.join("o1")).unwrap(), CopyOutResult::NothingToExport);
    m.exec(&sv(&["mkdir", "-p", "/out"]), &limits()).unwrap();
    assert_eq!(m.copy_out("/out", &root.join("o2")).unwrap(), CopyOutResult::NothingToExport);
    fs::remove_dir_all(root).unwrap();
}

fn hostile(plant: impl FnOnce(&Machine, &Path), reason: &str) {
    hostile_with_limits(plant, reason, CopyLimits::default());
}

fn hostile_with_limits(plant: impl FnOnce(&Machine, &Path), reason: &str, copy_limits: CopyLimits) {
    let Some(h) = mvm() else { return };
    let m = fresh_machine(h);
    let root = tempdir("copy");
    let sentinel = root.join("sentinel");
    fs::write(&sentinel, "untouched").unwrap();
    m.exec(&sv(&["mkdir", "-p", "/out"]), &limits()).unwrap();
    plant(&m, &sentinel);
    let dest = root.join("out");
    let err = copy_out_via(&*m, "/out", &dest, &copy_limits).unwrap_err();
    assert!(matches!(err, Error::Rejected(_)), "{err}");
    assert!(err.to_string().contains(reason), "{err}");
    assert!(!dest.exists());
    assert_eq!(fs::read_to_string(&sentinel).unwrap(), "untouched");
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "real mvm"]
fn hostile_out_a_symlink_to_the_host_sentinel_is_refused() {
    hostile(|m, s| assert_eq!(m.exec(&sv(&["ln", "-s", &s.to_string_lossy(), "/out/evil"]), &limits()).unwrap().exit_code, 0), "unsupported tar entry type 2");
}

#[test]
#[ignore = "real mvm"]
fn hostile_out_a_hardlink_is_refused() {
    hostile(|m, _| assert_eq!(m.exec(&sv(&["sh", "-c", "echo a > /out/a && ln /out/a /out/b"]), &limits()).unwrap().exit_code, 0), "unsupported tar entry type 1");
}

#[test]
#[ignore = "real mvm"]
fn hostile_out_a_120_byte_file_name_is_refused() {
    let cmd = format!("echo x > /out/{}", "n".repeat(120));
    hostile(|m, _| assert_eq!(m.exec(&sv(&["sh", "-c", &cmd]), &limits()).unwrap().exit_code, 0), "unsupported tar entry type L");
}

#[test]
#[ignore = "real mvm"]
fn hostile_out_a_file_over_the_size_cap_is_refused() {
    // /out and the packed archive share /tmp's RAM-backed filesystem.
    // Exercise the size limit without exhausting the 512 MiB fixture VM.
    let big = (2u64 * 1024 * 1024).to_string();
    hostile_with_limits(
        |m, _| {
            let r = m.exec(&sv(&["sh", "-c", r#"head -c "$1" /dev/zero > /out/huge"#, "rts", &big]), &ExecOptions { timeout_ms: 300_000, ..limits() }).unwrap();
            assert_eq!(r.exit_code, 0, "{}", String::from_utf8_lossy(&r.stderr));
        },
        "size cap",
        CopyLimits { max_bytes: 1024 * 1024, max_entries: 100, ..CopyLimits::default() },
    );
}

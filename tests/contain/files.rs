use rts::files::{GuestRead, guest_read, guest_sha256, guest_write};
use rts::protocol::random_hex;
use sha2::{Digest, Sha256};

use crate::harness::{fresh_machine, mvm};

fn sha(b: &[u8]) -> String {
    Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
}

fn random(n: usize) -> Vec<u8> {
    let hex = random_hex(n);
    (0..n).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap()).collect()
}

#[test]
#[ignore = "real mvm"]
fn guest_file_primitives_round_trip() {
    let Some(h) = mvm() else { return };
    let m = fresh_machine(h);

    // A 200 KiB random write matches its sha256 in the guest.
    let data = random(200 * 1024);
    guest_write(&*m, "/tmp/rand.bin", &data).unwrap();
    assert_eq!(guest_sha256(&*m, "/tmp/rand.bin").unwrap(), sha(&data));

    // Awkward paths round-trip through write, read and sha256.
    for p in ["/tmp/a b", "/tmp/-x", "/tmp/q'\"q", "/tmp/ünï", "/tmp/new\nline"] {
        let body = format!("content of {p}").into_bytes();
        guest_write(&*m, p, &body).unwrap();
        assert_eq!(guest_read(&*m, p, 65_536).unwrap(), GuestRead::File { size: body.len() as u64, data: body.clone(), truncated: false });
        assert_eq!(guest_sha256(&*m, p).unwrap(), sha(&body));
    }

    // Reading a directory lists its entries; a missing path is missing.
    guest_write(&*m, "/tmp/listing/one", b"1").unwrap();
    guest_write(&*m, "/tmp/listing/sub/two", b"2").unwrap();
    assert_eq!(guest_read(&*m, "/tmp/listing", 65_536).unwrap(), GuestRead::Dir { entries: vec!["one".into(), "sub/".into()], truncated: false });
    assert_eq!(guest_read(&*m, "/tmp/definitely-missing", 100).unwrap(), GuestRead::Missing);
}

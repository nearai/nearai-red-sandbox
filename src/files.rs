//! File primitives on guest paths, built only on `Exec`.
//!
//! Every guest script is fixed text that reads its operands from "$1",
//! "$2", ... so no path or content is ever parsed by a shell. Content
//! travels as base64 argv chunks, because mvm's exec does not pass stdin.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use crate::protocol::new_nonce;
use crate::sandbox::{Error, Exec, ExecOptions, ExecResult, Result, sv};

/// Base64 characters per argv chunk; 48 KiB was measured to pass mvmctl exec.
/// A multiple of 4, so each chunk decodes on its own.
pub const ARGV_CHUNK_CHARS: usize = 49_152;

fn control() -> ExecOptions {
    ExecOptions::new(60_000, 4096)
}

const W_FIRST: &str = r#"mkdir -p -- "$1" && printf %s "$3" | base64 -d > "$2""#;
const W_APPEND: &str = r#"printf %s "$2" | base64 -d >> "$1""#;
const W_FINISH: &str = r#"if [ -d "$2" ]; then rm -f -- "$1"; echo "is a directory: $2" >&2; exit 1; fi; mv -f -- "$1" "$2""#;
const W_CLEANUP: &str = r#"rm -f -- "$1""#;

const READ: &str = r#"p=$1
if [ -d "$p" ]; then
  printf 'D\n'
  for f in "$p"/* "$p"/.*; do
    [ -e "$f" ] || [ -L "$f" ] || continue
    b=${f##*/}
    case $b in .|..) continue;; esac
    if [ -d "$f" ]; then printf '%s/\0' "$b"; else printf '%s\0' "$b"; fi
  done
elif [ -f "$p" ]; then
  printf 'F %s\n' "$(wc -c < "$p")"
  head -c "$2" < "$p"
elif [ -e "$p" ] || [ -L "$p" ]; then
  printf 'X\n'
else
  printf 'M\n'
fi"#;

const SHA: &str = r#"if [ ! -f "$1" ]; then echo "not a regular file: $1" >&2; exit 2; fi; sha256sum < "$1""#;

pub fn script(body: &str, operands: &[&str]) -> Vec<String> {
    let mut v = sv(&["sh", "-c", body, "rts"]);
    v.extend(operands.iter().map(|s| s.to_string()));
    v
}

fn fail(what: &str, path: &str, r: &ExecResult) -> Error {
    let err = String::from_utf8_lossy(&r.stderr).trim().to_string();
    Error::Other(format!("{what} {path}: {}", if err.is_empty() { format!("exit status {}", r.exit_code) } else { err }))
}

fn parent(path: &str) -> String {
    match std::path::Path::new(path).parent().map(|p| p.to_string_lossy().into_owned()) {
        Some(p) if !p.is_empty() => p,
        Some(_) => ".".into(),
        None => "/".into(),
    }
}

pub fn guest_write(sb: &dyn Exec, path: &str, data: &[u8]) -> Result<()> {
    let b64 = B64.encode(data);
    let mut chunks: Vec<&str> = b64.as_bytes().chunks(ARGV_CHUNK_CHARS).map(|c| std::str::from_utf8(c).unwrap()).collect();
    if chunks.is_empty() {
        chunks.push("");
    }
    let tmp = format!("{path}.rts-{}.tmp", new_nonce());
    let attempt = || -> Result<()> {
        let r = sb.exec(&script(W_FIRST, &[&parent(path), &tmp, chunks[0]]), &control())?;
        if r.exit_code != 0 {
            return Err(fail("write", path, &r));
        }
        for c in &chunks[1..] {
            let r = sb.exec(&script(W_APPEND, &[&tmp, c]), &control())?;
            if r.exit_code != 0 {
                return Err(fail("write", path, &r));
            }
        }
        let r = sb.exec(&script(W_FINISH, &[&tmp, path]), &control())?;
        if r.exit_code != 0 {
            return Err(fail("write", path, &r));
        }
        Ok(())
    };
    let result = attempt();
    if result.is_err() {
        let _ = sb.exec(&script(W_CLEANUP, &[&tmp]), &control());
    }
    result
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestRead {
    File { data: Vec<u8>, size: u64, truncated: bool },
    Dir { entries: Vec<String>, truncated: bool },
    Missing,
}

pub fn guest_read(sb: &dyn Exec, path: &str, max_bytes: u64) -> Result<GuestRead> {
    let r = sb.exec(&script(READ, &[path, &max_bytes.to_string()]), &ExecOptions::new(60_000, max_bytes + 64))?;
    if r.exit_code != 0 {
        return Err(fail("read", path, &r));
    }
    let malformed = || Error::Other(format!("read {path}: malformed guest reply"));
    let nl = r.stdout.iter().position(|&b| b == b'\n').ok_or_else(malformed)?;
    let head = String::from_utf8_lossy(&r.stdout[..nl]).into_owned();
    let body = &r.stdout[nl + 1..];
    match head.as_str() {
        "M" => Ok(GuestRead::Missing),
        "X" => Err(Error::Other(format!("read {path}: not a regular file or directory"))),
        "D" => {
            let text = String::from_utf8_lossy(body);
            let mut parts: Vec<String> = text.split('\0').map(String::from).collect();
            // The last part is "" after a final NUL, or a cut-off name if the listing was truncated.
            parts.pop();
            parts.sort();
            Ok(GuestRead::Dir { entries: parts, truncated: r.truncated })
        }
        h => {
            let size: u64 = h.strip_prefix('F').map(str::trim).and_then(|s| s.parse().ok()).ok_or_else(malformed)?;
            let data = body[..body.len().min(max_bytes as usize)].to_vec();
            Ok(GuestRead::File { truncated: size > data.len() as u64, data, size })
        }
    }
}

pub fn guest_sha256(sb: &dyn Exec, path: &str) -> Result<String> {
    let r = sb.exec(&script(SHA, &[path]), &control())?;
    if r.exit_code != 0 {
        return Err(fail("sha256", path, &r));
    }
    let t = String::from_utf8_lossy(&r.stdout);
    let h = t.get(..64).filter(|h| h.bytes().all(|b| b.is_ascii_hexdigit())).ok_or_else(|| Error::Other(format!("sha256 {path}: malformed guest reply")))?;
    Ok(h.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{HostShell, Recorder, ok, reply, tempdir};
    use sha2::{Digest, Sha256};
    use std::fs;

    fn sha(b: &[u8]) -> String {
        Sha256::digest(b).iter().map(|x| format!("{x:02x}")).collect()
    }
    fn random(n: usize) -> Vec<u8> {
        let hex = crate::protocol::random_hex(n);
        hex.as_bytes().chunks(2).map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap()).collect()
    }

    #[test]
    fn a_120_kib_write_is_four_chunks_and_a_rename() {
        let rec = Recorder::new(|_, _| ok(b""));
        let data = random(120 * 1024);
        guest_write(&rec, "/out/f.bin", &data).unwrap();
        let a = rec.argvs();
        // 122,880 bytes is 163,840 base64 chars: four chunks of at most 49,152.
        assert_eq!(a.len(), 5);
        let joined: String = a[..4].iter().map(|v| v.last().unwrap().as_str()).collect();
        assert!(a[..4].iter().all(|v| v.last().unwrap().len() <= ARGV_CHUNK_CHARS));
        assert_eq!(B64.decode(joined).unwrap(), data);
        assert_eq!(a[4].last().unwrap(), "/out/f.bin");
    }

    #[test]
    fn paths_only_ever_travel_as_operands() {
        let rec = Recorder::new(|a: &[String], _: &ExecOptions| if a[2].contains("sha256sum") { ok(format!("{}  -\n", "a".repeat(64)).as_bytes()) } else { ok(b"M\n") });
        guest_write(&rec, "-rf", b"x").unwrap();
        guest_read(&rec, "$(reboot)", 100).unwrap();
        guest_sha256(&rec, "$(reboot)").unwrap();
        for a in rec.argvs() {
            assert_eq!((&a[0][..], &a[1][..]), ("sh", "-c"));
            assert!(!a[2].contains("-rf") && !a[2].contains("reboot"));
        }
        assert!(rec.argvs()[1].contains(&"-rf".to_string()));
    }

    #[test]
    fn a_failing_chunk_aborts_with_the_guest_error() {
        let rec = Recorder::new(|_, _| reply(1, b"", b"No space left on device"));
        assert!(guest_write(&rec, "/out/f", b"x").unwrap_err().to_string().contains("No space left on device"));
    }

    #[test]
    fn host_sh_random_write_round_trips() {
        let d = tempdir("files");
        let data = random(200 * 1024);
        let p = d.join("new/sub/rand.bin").to_string_lossy().into_owned();
        guest_write(&HostShell::default(), &p, &data).unwrap();
        assert_eq!(guest_sha256(&HostShell::default(), &p).unwrap(), sha(&data));
        assert_eq!(fs::read(&p).unwrap(), data);
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn host_sh_awkward_paths_round_trip() {
        let d = tempdir("files");
        let hs = HostShell::default();
        for name in ["a b", "-x", "q'\"q", "ünï", "new\nline", "$(id)", "--", "*"] {
            let p = d.join(name).to_string_lossy().into_owned();
            let body = format!("content of {name}").into_bytes();
            guest_write(&hs, &p, &body).unwrap();
            assert_eq!(fs::read(&p).unwrap(), body);
            assert_eq!(guest_read(&hs, &p, 1000).unwrap(), GuestRead::File { size: body.len() as u64, data: body.clone(), truncated: false });
            assert_eq!(guest_sha256(&hs, &p).unwrap(), sha(&body));
        }
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn host_sh_empty_write_replace_and_directory_refusal() {
        let d = tempdir("files");
        let hs = HostShell::default();
        let e = d.join("empty").to_string_lossy().into_owned();
        guest_write(&hs, &e, b"").unwrap();
        assert_eq!(guest_read(&hs, &e, 10).unwrap(), GuestRead::File { data: vec![], size: 0, truncated: false });
        let r = d.join("replace");
        fs::write(&r, "old old old").unwrap();
        guest_write(&hs, &r.to_string_lossy(), b"new").unwrap();
        assert_eq!(fs::read_to_string(&r).unwrap(), "new");
        let GuestRead::Dir { entries, .. } = guest_read(&hs, &d.to_string_lossy(), 100_000).unwrap() else { panic!() };
        assert!(!entries.iter().any(|e| e.contains(".rts-")));
        fs::create_dir(d.join("isdir")).unwrap();
        assert!(guest_write(&hs, &d.join("isdir").to_string_lossy(), b"x").unwrap_err().to_string().contains("is a directory"));
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn host_sh_truncation_listing_and_missing() {
        let d = tempdir("files");
        let hs = HostShell::default();
        fs::write(d.join("big"), "x".repeat(5000)).unwrap();
        let GuestRead::File { data, size, truncated } = guest_read(&hs, &d.join("big").to_string_lossy(), 1000).unwrap() else { panic!() };
        assert_eq!((data.len(), size, truncated), (1000, 5000, true));
        let l = d.join("listing");
        fs::create_dir_all(l.join("child")).unwrap();
        for f in [".hidden", "line\nbreak", "plain"] {
            fs::write(l.join(f), "").unwrap();
        }
        assert_eq!(
            guest_read(&hs, &l.to_string_lossy(), 10_000).unwrap(),
            GuestRead::Dir { entries: sv(&[".hidden", "child/", "line\nbreak", "plain"]), truncated: false }
        );
        assert_eq!(guest_read(&hs, &d.join("nope").to_string_lossy(), 10).unwrap(), GuestRead::Missing);
        assert!(guest_sha256(&hs, &d.join("nope").to_string_lossy()).is_err());
        fs::remove_dir_all(d).unwrap();
    }
}

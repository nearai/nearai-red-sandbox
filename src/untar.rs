//! Host-side tar extractor for archives built by a hostile guest.
//!
//! Accepts only regular files and directories. Refuses links, devices, GNU
//! and pax extension headers, absolute paths, `..`, NUL bytes in names, bad
//! checksums, and archives over the size or entry caps. The whole archive
//! is validated before anything is written; extraction goes to
//! `<dest>.partial` and is renamed into place only on success.
//! On Windows it also refuses names Windows would read differently
//! (separators, drive and stream markers, trailing dots and spaces,
//! device names) and paths that differ only in case.

use std::fmt;
use std::fs;
#[cfg(unix)]
use std::fs::{DirBuilder, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TarRejected {
    pub entry: String,
    pub reason: String,
}

impl fmt::Display for TarRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tar entry {:?} rejected: {}", self.entry, self.reason)
    }
}

impl std::error::Error for TarRejected {}

fn rej(entry: impl Into<String>, reason: impl Into<String>) -> TarRejected {
    TarRejected { entry: entry.into(), reason: reason.into() }
}

#[derive(Debug, Clone, Copy)]
pub struct ExtractLimits {
    pub max_bytes: u64,
    pub max_entries: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Extracted {
    pub files: u64,
    pub bytes: u64,
}

const BLOCK: usize = 512;

enum Kind {
    File,
    Dir,
}

struct Planned {
    kind: Kind,
    segments: Vec<String>,
    display: String,
    data: std::ops::Range<usize>,
}

fn field<'a>(h: &'a [u8], off: usize, len: usize, entry: &str, what: &str) -> Result<&'a [u8], TarRejected> {
    let f = &h[off..off + len];
    match f.iter().position(|&b| b == 0) {
        None => Ok(f),
        Some(nul) => {
            if f[nul..].iter().any(|&b| b != 0) {
                return Err(rej(entry, format!("NUL in {what}")));
            }
            Ok(&f[..nul])
        }
    }
}

fn octal(h: &[u8], off: usize, len: usize, entry: &str, what: &str) -> Result<u64, TarRejected> {
    if h[off] & 0x80 != 0 {
        return Err(rej(entry, format!("unsupported {what} encoding")));
    }
    let s = String::from_utf8_lossy(&h[off..off + len]);
    let s = s.trim_end_matches(['\0', ' ']).trim_start_matches(' ');
    if !s.bytes().all(|b| (b'0'..=b'7').contains(&b)) || s.len() > 21 {
        return Err(rej(entry, format!("bad {what} field")));
    }
    Ok(if s.is_empty() { 0 } else { u64::from_str_radix(s, 8).unwrap() })
}

fn checksum_ok(h: &[u8], entry: &str) -> Result<bool, TarRejected> {
    let stored = octal(h, 148, 8, entry, "checksum")?;
    let sum: u64 = h.iter().enumerate().map(|(i, &b)| if (148..156).contains(&i) { 0x20 } else { b as u64 }).sum();
    Ok(sum == stored)
}

fn normalize(raw: &str, entry: &str) -> Result<Vec<String>, TarRejected> {
    if raw.starts_with('/') {
        return Err(rej(entry, "absolute path"));
    }
    let segs: Vec<String> = raw.split('/').filter(|s| !s.is_empty() && *s != ".").map(String::from).collect();
    if segs.iter().any(|s| s == "..") {
        return Err(rej(entry, "path escapes the destination (..)"));
    }
    Ok(segs)
}

/// Why `seg` cannot be extracted as written on Windows, if it cannot:
/// characters Windows treats as separators, drive or stream markers, or
/// wildcards; trailing dots and spaces (Win32 strips them, so the name
/// would alias another); and reserved device names, with or without an
/// extension.
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_name_problem(seg: &str) -> Option<&'static str> {
    if seg.chars().any(|c| matches!(c, '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') || (c as u32) < 0x20) {
        return Some("character not allowed in a Windows file name");
    }
    if seg.ends_with('.') || seg.ends_with(' ') {
        return Some("Windows file name ends with a dot or space");
    }
    let stem = seg.split('.').next().unwrap_or("").trim_end_matches(' ').to_ascii_uppercase();
    let device = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.chars().count() == 4
            && stem.chars().last().is_some_and(|c| c.is_ascii_digit() || matches!(c, '\u{b9}' | '\u{b2}' | '\u{b3}')));
    if device {
        return Some("reserved Windows device name");
    }
    None
}

/// Refuses two entries whose paths differ only in case: on Windows they
/// are the same file. Directories may repeat (they are one directory).
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_collisions(entries: &[Planned]) -> Result<(), TarRejected> {
    let mut seen: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
    for e in entries {
        let key = e.segments.join("/").to_lowercase();
        let is_dir = matches!(e.kind, Kind::Dir);
        if let Some(&was_dir) = seen.get(&key)
            && !(was_dir && is_dir)
        {
            return Err(rej(&e.display, "names differ only in case (one file on Windows)"));
        }
        seen.insert(key, is_dir);
    }
    Ok(())
}

fn plan(archive: &[u8], limits: ExtractLimits) -> Result<Vec<Planned>, TarRejected> {
    let mut out = Vec::new();
    let mut total: u64 = 0;
    let mut off = 0usize;
    loop {
        if off + BLOCK > archive.len() {
            return Err(rej(format!("@{off}"), "truncated archive (no end-of-archive marker)"));
        }
        let h = &archive[off..off + BLOCK];
        if h.iter().all(|&b| b == 0) {
            break;
        }
        let at = format!("@{off}");
        let mut entry = String::from_utf8_lossy(field(h, 0, 100, &at, "name")?).into_owned();
        if &h[257..263] == b"ustar\0" {
            let prefix = String::from_utf8_lossy(field(h, 345, 155, &entry, "name")?).into_owned();
            if !prefix.is_empty() {
                entry = format!("{prefix}/{entry}");
            }
        }
        if !checksum_ok(h, &entry)? {
            return Err(rej(&entry, "bad header checksum"));
        }
        let kind = match h[156] {
            b'0' | 0 => Kind::File,
            b'5' => Kind::Dir,
            t => {
                let shown = if t.is_ascii_graphic() { (t as char).to_string() } else { format!("0x{t:02x}") };
                return Err(rej(&entry, format!("unsupported tar entry type {shown}")));
            }
        };
        let size = octal(h, 124, 12, &entry, "size")?;
        if out.len() + 1 > limits.max_entries {
            return Err(rej(&entry, format!("entry cap of {} exceeded", limits.max_entries)));
        }
        let segments = normalize(&entry, &entry)?;
        #[cfg(windows)]
        if let Some(why) = segments.iter().find_map(|seg| windows_name_problem(seg)) {
            return Err(rej(&entry, why));
        }
        match kind {
            Kind::File if segments.is_empty() => return Err(rej(&entry, "empty path for a file")),
            Kind::Dir if size != 0 => return Err(rej(&entry, "directory with data")),
            _ => {}
        }
        total = total.saturating_add(size);
        if total > limits.max_bytes {
            return Err(rej(&entry, format!("size cap of {} bytes exceeded", limits.max_bytes)));
        }
        let data_start = off + BLOCK;
        let padded = (size as usize).div_ceil(BLOCK) * BLOCK;
        if data_start.checked_add(padded).is_none_or(|e| e > archive.len()) {
            return Err(rej(&entry, "truncated archive (data runs past the end)"));
        }
        out.push(Planned { kind, segments, display: entry, data: data_start..data_start + size as usize });
        off = data_start + padded;
    }
    Ok(out)
}

fn partial_of(dest: &Path) -> PathBuf {
    let mut s = dest.as_os_str().to_owned();
    s.push(".partial");
    PathBuf::from(s)
}

pub fn extract_tar(archive: &[u8], dest: &Path, limits: ExtractLimits) -> Result<Extracted, TarRejected> {
    if fs::symlink_metadata(dest).is_ok() {
        return Err(rej(dest.display().to_string(), "destination exists"));
    }
    let entries = plan(archive, limits)?;
    #[cfg(windows)]
    windows_collisions(&entries)?;
    let partial = partial_of(dest);
    let io = |e: std::io::Error| rej(dest.display().to_string(), format!("cannot create destination: {e}"));
    let _ = fs::remove_dir_all(&partial);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(io)?;
    }
    make_dir(&partial, false).map_err(io)?;
    let result = (|| {
        let (mut files, mut bytes) = (0u64, 0u64);
        for e in &entries {
            let target = e.segments.iter().fold(partial.clone(), |p, s| p.join(s));
            let fail = |err: std::io::Error| rej(&e.display, format!("cannot create: {}", err.kind()));
            match e.kind {
                Kind::Dir => make_dir(&target, true).map_err(fail)?,
                Kind::File => {
                    if let Some(p) = target.parent() {
                        make_dir(p, true).map_err(fail)?;
                    }
                    // create_new is O_CREAT|O_EXCL: an existing path is never opened or followed.
                    let mut f = create_file(&target).map_err(fail)?;
                    f.write_all(&archive[e.data.clone()]).map_err(fail)?;
                    files += 1;
                    bytes += e.data.len() as u64;
                }
            }
        }
        fs::rename(&partial, dest).map_err(|err| rej(dest.display().to_string(), format!("cannot rename into place: {err}")))?;
        Ok(Extracted { files, bytes })
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&partial);
    }
    result
}

/// A directory of the extracted tree: 0755 on Unix.
#[cfg(unix)]
fn make_dir(path: &Path, recursive: bool) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    DirBuilder::new().recursive(recursive).mode(0o755).create(path)
}

/// A new file of the extracted tree: 0644 on Unix, created with O_CREAT|O_EXCL
/// so an existing path is never opened or followed.
#[cfg(unix)]
fn create_file(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new().write(true).create_new(true).mode(0o644).open(path)
}

/// A directory of the extracted tree on Windows: it inherits the
/// destination's ACL. Names were checked by `windows_name_problem`.
#[cfg(windows)]
fn make_dir(path: &Path, recursive: bool) -> std::io::Result<()> {
    fs::DirBuilder::new().recursive(recursive).create(path)
}

/// A new file of the extracted tree on Windows, CREATE_NEW: an existing
/// path (including one that differs only in case) is never opened.
#[cfg(windows)]
fn create_file(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new().write(true).create_new(true).open(path)
}

#[cfg(test)]
pub mod fixture {
    //! Hand-built tar archives, so tests can produce entry types a real tar
    //! would never emit from a benign tree.

    #[derive(Default, Clone)]
    pub struct Entry {
        pub name: String,
        pub raw_name: Option<Vec<u8>>,
        pub kind: Option<u8>,
        pub data: Vec<u8>,
        pub size: Option<u64>,
        pub linkname: String,
        pub prefix: String,
        pub gnu: bool,
        pub bad_checksum: bool,
    }

    pub fn file(name: &str, data: &[u8]) -> Entry {
        Entry { name: name.into(), data: data.to_vec(), ..Default::default() }
    }
    pub fn dir(name: &str) -> Entry {
        Entry { name: name.into(), kind: Some(b'5'), ..Default::default() }
    }
    pub fn typed(name: &str, kind: u8) -> Entry {
        Entry { name: name.into(), kind: Some(kind), ..Default::default() }
    }

    fn put(h: &mut [u8], off: usize, b: &[u8], max: usize) {
        let n = b.len().min(max);
        h[off..off + n].copy_from_slice(&b[..n]);
    }

    pub fn header(e: &Entry) -> Vec<u8> {
        let mut h = vec![0u8; 512];
        put(&mut h, 0, e.raw_name.as_deref().unwrap_or(e.name.as_bytes()), 100);
        put(&mut h, 100, format!("{:07o}\0", if e.kind == Some(b'5') { 0o755 } else { 0o644 }).as_bytes(), 8);
        put(&mut h, 108, b"0000000\0", 8);
        put(&mut h, 116, b"0000000\0", 8);
        put(&mut h, 124, format!("{:011o}\0", e.size.unwrap_or(e.data.len() as u64)).as_bytes(), 12);
        put(&mut h, 136, b"00000000000\0", 12);
        h[148..156].fill(b' ');
        h[156] = e.kind.unwrap_or(b'0');
        put(&mut h, 157, e.linkname.as_bytes(), 100);
        if e.gnu {
            put(&mut h, 257, b"ustar  \0", 8);
        } else {
            put(&mut h, 257, b"ustar\0", 6);
            put(&mut h, 263, b"00", 2);
        }
        put(&mut h, 345, e.prefix.as_bytes(), 155);
        let mut sum: u64 = h.iter().map(|&b| b as u64).sum();
        if e.bad_checksum {
            sum += 1;
        }
        put(&mut h, 148, format!("{sum:06o}\0 ").as_bytes(), 8);
        h
    }

    pub fn tar(entries: &[Entry]) -> Vec<u8> {
        let mut out = Vec::new();
        for e in entries {
            out.extend(header(e));
            if !e.data.is_empty() {
                let mut d = e.data.clone();
                d.resize(e.data.len().div_ceil(512) * 512, 0);
                out.extend(d);
            }
        }
        out.extend([0u8; 1024]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::*;
    use super::*;
    use crate::testutil::tempdir;

    const LIM: ExtractLimits = ExtractLimits { max_bytes: 1024 * 1024, max_entries: 100 };

    struct Env {
        root: PathBuf,
        dest: PathBuf,
        sentinel: PathBuf,
    }
    impl Drop for Env {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    fn env() -> Env {
        let root = tempdir("untar");
        let sentinel = root.join("sentinel");
        fs::write(&sentinel, "untouched").unwrap();
        Env { dest: root.join("out"), sentinel, root }
    }

    fn refused(archive: &[u8], reason: &str, lim: ExtractLimits) {
        let e = env();
        let err = extract_tar(archive, &e.dest, lim).unwrap_err();
        assert!(err.to_string().contains(reason), "{err} does not mention {reason}");
        assert!(!e.dest.exists());
        assert!(!partial_of(&e.dest).exists());
        assert_eq!(fs::read_to_string(&e.sentinel).unwrap(), "untouched");
        let names: Vec<_> = fs::read_dir(&e.root).unwrap().map(|d| d.unwrap().file_name()).collect();
        assert_eq!(names, vec![std::ffi::OsString::from("sentinel")]);
    }

    #[test]
    fn windows_name_rules_refuse_separators_streams_devices_and_aliases() {
        for bad in [
            "a\\b", "..\\x", "c:", "C:x", "f.txt:stream", "a*", "a?", "a\"", "a<", "a>", "a|", "a\u{1}b",
            "x.", "x ", "x. .", "CON", "con", "Con.txt", "NUL.tar.gz", "aux", "PRN", "COM1", "com9.log", "LPT1",
            "lpt0", "COM\u{b9}", "LPT\u{b3}.x", "CONIN$", "conout$", "CON .txt",
        ] {
            assert!(windows_name_problem(bad).is_some(), "{bad:?} accepted");
        }
        for good in ["a", "report.md", "CONSOLE", "com10", "LPTX", "nul_file", ".hidden", "a.b.c", "ünïcode", "x y"] {
            assert_eq!(windows_name_problem(good), None, "{good:?} refused");
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_hostile_names_are_refused_before_anything_is_written() {
        refused(&tar(&[file("./a\\..\\..\\evil", b"x")]), "character not allowed", LIM);
        refused(&tar(&[file("./out.txt:hidden", b"x")]), "character not allowed", LIM);
        refused(&tar(&[file("./CON.txt", b"x")]), "reserved Windows device name", LIM);
        refused(&tar(&[file("./report. ", b"x")]), "dot or space", LIM);
        refused(&tar(&[file("./a.txt", b"x"), file("./A.TXT", b"y")]), "differ only in case", LIM);
    }

    #[test]
    fn names_that_differ_only_in_case_collide_on_windows() {
        let plan = |names: &[&str]| -> Result<(), TarRejected> {
            let entries: Vec<_> = names.iter().map(|n| file(n, b"x")).collect();
            windows_collisions(&super::plan(&tar(&entries), LIM)?)
        };
        assert!(plan(&["./a/b.txt", "./A/B.TXT"]).is_err());
        assert!(plan(&["./dir/x", "./Dir/y"]).is_ok(), "the same directory, spelled two ways, is one directory");
        assert!(plan(&["./a/b.txt", "./a/c.txt"]).is_ok());
    }

    #[test]
    fn dirs_and_files_extract_byte_exact() {
        let e = env();
        let bin: Vec<u8> = (0..3000u32).map(|i| (i * 7 % 251) as u8).collect();
        let r = extract_tar(&tar(&[dir("./"), dir("./d/"), file("./d/a.txt", b"hello\n"), file("./b.bin", &bin)]), &e.dest, LIM).unwrap();
        assert_eq!(r, Extracted { files: 2, bytes: 3006 });
        assert_eq!(fs::read(e.dest.join("d/a.txt")).unwrap(), b"hello\n");
        assert_eq!(fs::read(e.dest.join("b.bin")).unwrap(), bin);
    }

    #[test]
    fn missing_parent_entries_and_prefix() {
        let e = env();
        let mut p = file("leaf.txt", b"p");
        p.prefix = "deep/dir".into();
        extract_tar(&tar(&[file("x/y/z.txt", b"z"), p]), &e.dest, LIM).unwrap();
        assert_eq!(fs::read(e.dest.join("x/y/z.txt")).unwrap(), b"z");
        assert_eq!(fs::read(e.dest.join("deep/dir/leaf.txt")).unwrap(), b"p");
    }

    #[test]
    fn empty_archive_is_empty_dir() {
        let e = env();
        assert_eq!(extract_tar(&tar(&[]), &e.dest, LIM).unwrap(), Extracted { files: 0, bytes: 0 });
        assert_eq!(fs::read_dir(&e.dest).unwrap().count(), 0);
    }

    #[test]
    #[cfg(unix)]
    fn host_tar_round_trips() {
        let e = env();
        let src = e.root.join("src");
        fs::create_dir_all(src.join("n/m")).unwrap();
        fs::write(src.join("n/m/f.txt"), "from host tar").unwrap();
        let out = std::process::Command::new("tar").args(["--format=ustar", "-cf", "-", "-C"]).arg(&src).arg(".").output().unwrap();
        assert!(out.status.success());
        fs::remove_dir_all(&src).unwrap();
        extract_tar(&out.stdout, &e.dest, LIM).unwrap();
        assert_eq!(fs::read_to_string(e.dest.join("n/m/f.txt")).unwrap(), "from host tar");
    }

    #[test]
    fn links_devices_and_extensions_are_refused() {
        let mut sym = typed("link", b'2');
        sym.linkname = "/etc/passwd".into();
        refused(&tar(&[sym]), "unsupported tar entry type 2", LIM);
        let mut hard = typed("h", b'1');
        hard.linkname = "a".into();
        refused(&tar(&[file("a", b"a"), hard]), "unsupported tar entry type 1", LIM);
        refused(&tar(&[typed("null", b'3')]), "unsupported tar entry type 3", LIM);
        refused(&tar(&[typed("disk", b'4')]), "unsupported tar entry type 4", LIM);
        refused(&tar(&[typed("fifo", b'6')]), "unsupported tar entry type 6", LIM);
        let mut long = typed("././@LongLink", b'L');
        long.gnu = true;
        long.data = [vec![b'x'; 120], vec![0]].concat();
        let mut short = file(&"x".repeat(99), b"v");
        short.gnu = true;
        refused(&tar(&[long, short]), "unsupported tar entry type L", LIM);
        let mut pax = typed("PaxHeader/f", b'x');
        pax.data = b"30 path=../../etc/passwd\n".to_vec();
        refused(&tar(&[pax, file("f", b"v")]), "unsupported tar entry type x", LIM);
        refused(&tar(&[typed("pax_global_header", b'g')]), "unsupported tar entry type g", LIM);
    }

    #[test]
    fn escapes_are_refused() {
        refused(&tar(&[file("../escape", b"e")]), "path escapes", LIM);
        refused(&tar(&[file("a/../../escape", b"e")]), "path escapes", LIM);
        let mut p = file("escape", b"e");
        p.prefix = "..".into();
        refused(&tar(&[p]), "path escapes", LIM);
        refused(&tar(&[file("/abs", b"e")]), "absolute path", LIM);
        let mut nul = file("", b"e");
        nul.raw_name = Some(b"ok\0../../evil".to_vec());
        refused(&tar(&[nul]), "NUL in name", LIM);
    }

    #[test]
    fn caps_and_corruption_are_refused() {
        let small = ExtractLimits { max_bytes: 1000, max_entries: 5 };
        refused(&tar(&[file("a", &[b'x'; 600]), file("b", &[b'x'; 600])]), "size cap", small);
        let many: Vec<Entry> = (0..6).map(|i| file(&format!("f{i}"), b"x")).collect();
        refused(&tar(&many), "entry cap", small);
        let mut lying = file("a", b"x");
        lying.size = Some(99999);
        let mut a = tar(&[lying]);
        a.truncate(1024);
        refused(&a, "truncated", LIM);
        let mut bad = file("a", b"x");
        bad.bad_checksum = true;
        refused(&tar(&[bad]), "bad header checksum", LIM);
        refused(&tar(&[file("a", b"x")])[..700], "truncated", LIM);
        refused(&tar(&[file("./", b"x")]), "empty path", LIM);
    }

    #[test]
    fn duplicates_are_refused_not_overwritten() {
        refused(&tar(&[file("a", b"1"), file("./a", b"2")]), "cannot create", LIM);
    }

    #[test]
    fn late_rejection_leaves_nothing() {
        let mut bad = typed("bad", b'2');
        bad.linkname = "/".into();
        refused(&tar(&[file("ok1", b"1"), dir("dir/"), file("dir/ok2", b"2"), bad]), "unsupported tar entry type 2", LIM);
    }

    #[test]
    fn existing_destination_is_refused_and_left_alone() {
        let e = env();
        fs::create_dir_all(&e.dest).unwrap();
        fs::write(e.dest.join("keep"), "k").unwrap();
        let err = extract_tar(&tar(&[file("a", b"x")]), &e.dest, LIM).unwrap_err();
        assert!(err.to_string().contains("destination exists"));
        assert_eq!(fs::read_to_string(e.dest.join("keep")).unwrap(), "k");
    }
}

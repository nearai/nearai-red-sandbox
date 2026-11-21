//! Session-owned synthetic canaries. Exact matches are observations, not access tracing.
//! The registry stays on the host. Only guest decoys and a value-free manifest enter the VM.
//!
//! The host side relies on Unix primitives (O_NOFOLLOW, 0600 files owned by
//! this user, flock, and openat-relative export scans). On Windows a registry
//! cannot be created or loaded yet, so a session with canaries refuses there.
#![cfg_attr(not(unix), allow(dead_code, unused_imports))]
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashSet;
#[cfg(unix)]
use std::ffi::{CStr, CString};
use std::ffi::OsString;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_CANARIES: usize = 16;
const CHUNK: usize = 65536;
const MAX_REGISTRY: u64 = 64 * 1024;
const MAX_AUDIT: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Placement {
    Host,
    Guest,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanarySpec {
    pub id: String,
    pub placement: Placement,
}

pub fn validate_specs(specs: &[CanarySpec]) -> Result<(), String> {
    if specs.len() > MAX_CANARIES {
        return Err("canaries: at most 16 entries are allowed".into());
    }
    let mut ids = HashSet::new();
    for s in specs {
        let valid = !s.id.is_empty()
            && s.id.len() <= 64
            && s.id
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && s.id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
        if !valid {
            return Err("canaries: IDs must be 1-64 lowercase letters, digits, dashes or underscores, starting with a letter or digit".into());
        }
        if !ids.insert(&s.id) {
            return Err("canaries: duplicate ID".into());
        }
    }
    Ok(())
}

// Deliberately no Debug: entries contain the marker values.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    id: String,
    placement: Placement,
    path: String,
    token: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u32,
    audit_file: PathBuf,
    guest_root: String,
    entries: Vec<Entry>,
}

pub struct Registry {
    path: PathBuf,
    stored: Stored,
}

fn random_hex(bytes: usize) -> Result<String, String> {
    let mut b = vec![0; bytes];
    SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| "canaries: OS randomness failed")?;
    Ok(hex::encode(b))
}
#[cfg(not(unix))]
const UNSUPPORTED: &str = "canaries are not supported on Windows yet";
#[cfg(not(unix))]
fn private_new(_path: &Path, _bytes: &[u8]) -> Result<(), String> {
    Err(UNSUPPORTED.into())
}
#[cfg(not(unix))]
fn private_file(_path: &Path, _append: bool) -> Result<File, String> {
    Err(UNSUPPORTED.into())
}
#[cfg(not(unix))]
fn lock(_f: &File, _exclusive: bool) -> Result<(), String> {
    Err(UNSUPPORTED.into())
}
#[cfg(not(unix))]
fn private_dir(_path: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, UNSUPPORTED))
}
#[cfg(unix)]
fn private_dir(path: &Path) -> std::io::Result<()> {
    DirBuilder::new().mode(0o700).create(path)
}
#[cfg(unix)]
fn private_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("canaries: creating private file: {e}"))?;
    f.write_all(bytes)
        .map_err(|e| format!("canaries: writing private file: {e}"))
}
#[cfg(unix)]
fn private_file(path: &Path, append: bool) -> Result<File, String> {
    let mut o = OpenOptions::new();
    o.read(!append)
        .append(append)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let f = o
        .open(path)
        .map_err(|e| format!("canaries: opening private file: {e}"))?;
    let m = f
        .metadata()
        .map_err(|e| format!("canaries: checking private file: {e}"))?;
    if !m.is_file()
        || m.mode() & 0o777 != 0o600
        || m.nlink() != 1
        || m.uid() != unsafe { libc::geteuid() }
    {
        return Err(
            "canaries: private file must be owned by this user, regular, unlinked and mode 0600"
                .into(),
        );
    }
    Ok(f)
}
#[cfg(unix)]
fn lock(f: &File, exclusive: bool) -> Result<(), String> {
    let operation = if exclusive { libc::LOCK_EX } else { libc::LOCK_SH };
    loop {
        if unsafe { libc::flock(f.as_raw_fd(), operation) } == 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(format!("canaries: locking audit: {e}"));
        }
    }
}

impl Registry {
    pub fn create(specs: &[CanarySpec], dir: &Path, audit_file: &Path) -> Result<Self, String> {
        validate_specs(specs)?;
        if !dir.is_absolute() || !audit_file.is_absolute() {
            return Err("canaries: registry and audit paths must be absolute".into());
        }
        private_dir(dir).map_err(|e| format!("canaries: creating registry directory: {e}"))?;
        let host = dir.join("host");
        private_dir(&host).map_err(|e| format!("canaries: creating host directory: {e}"))?;
        let guest_root = format!("/tmp/rts/canaries-{}", random_hex(16)?);
        let mut entries = vec![];
        for s in specs {
            let token = format!("RTS_CANARY_{}", random_hex(32)?);
            let path = match s.placement {
                Placement::Host => {
                    let p = host.join(format!("{}.token", s.id));
                    private_new(&p, format!("{token}\n").as_bytes())?;
                    p.to_str()
                        .ok_or("canaries: host path is not UTF-8")?
                        .to_owned()
                }
                Placement::Guest => format!("{guest_root}/{}.token", s.id),
            };
            entries.push(Entry {
                id: s.id.clone(),
                placement: s.placement,
                path,
                token,
            });
        }
        private_new(audit_file, b"")?;
        let r = Self {
            path: dir.join("registry.json"),
            stored: Stored {
                version: 1,
                audit_file: audit_file.into(),
                guest_root,
                entries,
            },
        };
        private_new(
            &r.path,
            &serde_json::to_vec(&r.stored).map_err(|_| "canaries: serializing registry")?,
        )?;
        Ok(r)
    }
    pub fn path(&self) -> PathBuf {
        self.path.clone()
    }
    pub fn load(path: &Path) -> Result<Self, String> {
        let f = private_file(path, false)?;
        if f.metadata()
            .map_err(|_| "canaries: reading registry size")?
            .len()
            > MAX_REGISTRY
        {
            return Err("canaries: registry exceeds size limit".into());
        }
        let mut data = vec![];
        f.take(MAX_REGISTRY + 1)
            .read_to_end(&mut data)
            .map_err(|_| "canaries: reading registry")?;
        if data.len() as u64 > MAX_REGISTRY {
            return Err("canaries: registry exceeds size limit".into());
        }
        // Never display serde errors: they can quote invalid token values.
        let stored: Stored =
            serde_json::from_slice(&data).map_err(|_| "canaries: invalid registry")?;
        validate_specs(
            &stored
                .entries
                .iter()
                .map(|e| CanarySpec {
                    id: e.id.clone(),
                    placement: e.placement,
                })
                .collect::<Vec<_>>(),
        )?;
        let good_root = stored
            .guest_root
            .strip_prefix("/tmp/rts/canaries-")
            .is_some_and(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()));
        if stored.version != 1
            || !stored.audit_file.is_absolute()
            || !good_root
            || stored.entries.iter().any(|e| {
                !Path::new(&e.path).is_absolute()
                    || e.token.len() != 75
                    || !e.token.starts_with("RTS_CANARY_")
                    || !e.token[11..].bytes().all(|b| b.is_ascii_hexdigit())
                    || (e.placement == Placement::Guest
                        && e.path != format!("{}/{}.token", stored.guest_root, e.id))
            })
        {
            return Err("canaries: invalid registry".into());
        }
        Ok(Self {
            path: path.into(),
            stored,
        })
    }
    pub fn manifest_path(&self) -> String {
        format!("{}/manifest.json", self.stored.guest_root)
    }
    pub fn guest_files(&self) -> Vec<(String, Vec<u8>)> {
        let mut files: Vec<_> = self
            .stored
            .entries
            .iter()
            .filter(|e| e.placement == Placement::Guest)
            .map(|e| (e.path.clone(), format!("{}\n", e.token).into_bytes()))
            .collect();
        let manifest = json!({"version":1,"canaries":self.stored.entries.iter().map(|e|json!({"id":e.id,"placement":e.placement,"path":e.path})).collect::<Vec<_>>()});
        files.push((
            self.manifest_path(),
            serde_json::to_vec_pretty(&manifest).expect("manifest serialization is infallible"),
        ));
        files
    }
    fn redact(&self, text: &str) -> String {
        self.stored.entries.iter().fold(text.to_owned(), |s, e| {
            s.replace(&e.token, &format!("[canary:{}]", e.id))
        })
    }
    fn event(&self, e: &Entry, source: &str) -> Value {
        json!({"version":1,"timestamp":SystemTime::now().duration_since(UNIX_EPOCH).map(|d|d.as_secs()).unwrap_or(0),"source":source,"id":e.id,"placement":e.placement})
    }
    fn append(&self, events: &[Value]) -> Result<(), String> {
        if events.is_empty() {
            return Ok(());
        }
        let mut f = private_file(&self.stored.audit_file, true)?;
        lock(&f, true)?;
        let mut bytes = vec![];
        for e in events {
            serde_json::to_writer(&mut bytes, e).map_err(|_| "canaries: serializing event")?;
            bytes.push(b'\n');
        }
        let size = f
            .metadata()
            .map_err(|_| "canaries: reading audit size")?
            .len();
        if size.saturating_add(bytes.len() as u64) > MAX_AUDIT {
            return Err("canaries: audit exceeds size limit; observations incomplete".into());
        }
        // File close releases flock on every error path.
        f.write_all(&bytes)
            .and_then(|_| f.sync_data())
            .map_err(|e| format!("canaries: persisting observations: {e}"))?;
        Ok(())
    }
    pub fn observe_tool(
        &self,
        tool: &str,
        input_sha256: &str,
        stdout: &mut String,
        stderr: &mut String,
    ) -> Result<usize, String> {
        let mut events = vec![];
        for (channel, text) in [("stdout", &mut *stdout), ("stderr", &mut *stderr)] {
            for e in &self.stored.entries {
                if text.contains(&e.token) {
                    let mut event = self.event(e, "tool_output");
                    event["channel"] = json!(channel);
                    event["tool"] = json!(self.redact(tool));
                    event["canonicalInputSha256"] = json!(self.redact(input_sha256));
                    events.push(event);
                }
            }
            *text = self.redact(text);
        }
        self.append(&events)?;
        Ok(events.len())
    }
    #[cfg(not(unix))]
    pub fn scan_exports(&self, _root: &Path) -> Result<usize, String> {
        Err(UNSUPPORTED.into())
    }
    #[cfg(unix)]
    pub fn scan_exports(&self, root: &Path) -> Result<usize, String> {
        let root_file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(root)
            .map_err(|e| format!("canaries: opening export directory: {e}"))?;
        let mut budget = ScanBudget {
            bytes: 0,
            entries: 0,
        };
        self.scan_dir(&root_file, Path::new(""), &mut budget)
    }
    #[cfg(unix)]
    fn scan_dir(
        &self,
        dir: &File,
        relative: &Path,
        budget: &mut ScanBudget,
    ) -> Result<usize, String> {
        if relative.components().count() > 128 {
            return Err("canaries: export depth limit exceeded; scan incomplete".into());
        }
        let mut count = 0;
        for name in directory_names(dir)? {
            budget.entries += 1;
            if budget.entries > crate::copy::CopyLimits::default().max_entries {
                return Err("canaries: export entry limit exceeded; scan incomplete".into());
            }
            let path = relative.join(&name);
            let cname =
                CString::new(name.as_bytes()).map_err(|_| "canaries: invalid export name")?;
            let fd = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    cname.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(
                    "canaries: cannot open export entry without following links; scan incomplete"
                        .into(),
                );
            }
            let mut file = unsafe { File::from_raw_fd(fd) };
            let meta = file
                .metadata()
                .map_err(|_| "canaries: cannot inspect export entry")?;
            if meta.is_dir() {
                count += self.scan_dir(&file, &path, budget)?;
            } else if meta.is_file() && meta.nlink() == 1 {
                if budget.bytes.saturating_add(meta.len())
                    > crate::copy::CopyLimits::default().max_bytes
                {
                    return Err("canaries: export byte limit exceeded; scan incomplete".into());
                }
                let mut found = vec![false; self.stored.entries.len()];
                let mut tail = vec![];
                let mut chunk = vec![0; CHUNK];
                loop {
                    let n = file
                        .read(&mut chunk)
                        .map_err(|_| "canaries: cannot read export; scan incomplete")?;
                    if n == 0 {
                        break;
                    }
                    budget.bytes = budget.bytes.saturating_add(n as u64);
                    if budget.bytes > crate::copy::CopyLimits::default().max_bytes {
                        return Err("canaries: export byte limit exceeded; scan incomplete".into());
                    }
                    tail.extend_from_slice(&chunk[..n]);
                    for (i, e) in self.stored.entries.iter().enumerate() {
                        if !found[i] && tail.windows(e.token.len()).any(|w| w == e.token.as_bytes())
                        {
                            found[i] = true;
                        }
                    }
                    let retain = tail.len().saturating_sub(74);
                    tail.drain(..retain);
                }
                let mut events = vec![];
                for (i, hit) in found.iter().enumerate() {
                    if *hit {
                        let mut event = self.event(&self.stored.entries[i], "export");
                        event["file"] = json!(self.redact(&path.to_string_lossy()));
                        events.push(event);
                    }
                }
                self.append(&events)?;
                count += events.len();
            } else {
                return Err(
                    "canaries: export contains a link or special file; scan incomplete".into(),
                );
            }
        }
        Ok(count)
    }
    pub fn summary(&self) -> Result<String, String> {
        let f = private_file(&self.stored.audit_file, false)?;
        lock(&f, false)?;
        if f.metadata()
            .map_err(|_| "canaries: reading audit size")?
            .len()
            > MAX_AUDIT
        {
            return Err("canaries: audit exceeds size limit".into());
        }
        let mut count = 0;
        for line in BufReader::new(f.take(MAX_AUDIT + 1)).lines() {
            let line = line.map_err(|_| "canaries: reading audit")?;
            let e: Value = serde_json::from_str(&line)
                .map_err(|_| "canaries: invalid audit; observations incomplete")?;
            if e["version"] != 1
                || !matches!(e["source"].as_str(), Some("tool_output" | "export"))
                || !self.stored.entries.iter().any(|x| e["id"] == x.id)
            {
                return Err("canaries: invalid audit; observations incomplete".into());
            }
            count += 1;
        }
        Ok(format!(
            "canaries: {count} exact matches observed in tool output or exports; no matches is not proof of no access (encoded, suppressed or truncated content is not covered)"
        ))
    }
}
struct ScanBudget {
    bytes: u64,
    entries: usize,
}

// Enumerate an already-open directory. All descendants are opened relative to
// its descriptor with O_NOFOLLOW; a hostile path cannot redirect us to host files.
#[cfg(unix)]
fn directory_names(dir: &File) -> Result<Vec<OsString>, String> {
    let duplicate = unsafe { libc::dup(dir.as_raw_fd()) };
    if duplicate < 0 {
        return Err("canaries: cannot duplicate export directory".into());
    }
    let ptr = unsafe { libc::fdopendir(duplicate) };
    if ptr.is_null() {
        unsafe { libc::close(duplicate) };
        return Err("canaries: cannot enumerate export directory".into());
    }
    struct Stream(*mut libc::DIR);
    impl Drop for Stream {
        fn drop(&mut self) {
            unsafe { libc::closedir(self.0) };
        }
    }
    let stream = Stream(ptr);
    let mut names = vec![];
    loop {
        // readdir distinguishes end-of-stream from failure through errno.
        #[cfg(target_os = "macos")]
        unsafe {
            *libc::__error() = 0;
        }
        #[cfg(target_os = "linux")]
        unsafe {
            *libc::__errno_location() = 0;
        }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            if std::io::Error::last_os_error().raw_os_error() != Some(0) {
                return Err("canaries: export directory read failed".into());
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(OsString::from_vec(name.to_vec()));
        }
        if names.len() > crate::copy::CopyLimits::default().max_entries {
            return Err("canaries: export entry limit exceeded; scan incomplete".into());
        }
    }
    names.sort();
    Ok(names)
}
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn specs() -> Vec<CanarySpec> {
        vec![
            CanarySpec {
                id: "host-key".into(),
                placement: Placement::Host,
            },
            CanarySpec {
                id: "guest-key".into(),
                placement: Placement::Guest,
            },
        ]
    }
    fn setup() -> (tempfile::TempDir, Registry) {
        let t = tempfile::tempdir().unwrap();
        let r = Registry::create(
            &specs(),
            &t.path().join("canaries"),
            &t.path().join("canaries.jsonl"),
        )
        .unwrap();
        (t, r)
    }
    fn tokens(r: &Registry) -> Vec<String> {
        let v: Value = serde_json::from_slice(&fs::read(r.path()).unwrap()).unwrap();
        v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["token"].as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn spec_validation_accepts_safe_unique_ids_and_rejects_unsafe_or_excessive() {
        assert!(validate_specs(&specs()).is_ok());
        for id in ["", "../key", "-key", "A", "key\n", "a/b"] {
            assert!(
                validate_specs(&[CanarySpec {
                    id: id.into(),
                    placement: Placement::Guest
                }])
                .is_err()
            );
        }
        assert!(validate_specs(&[specs()[0].clone(), specs()[0].clone()]).is_err());
        assert!(
            validate_specs(
                &(0..17)
                    .map(|i| CanarySpec {
                        id: format!("c{i}"),
                        placement: Placement::Guest
                    })
                    .collect::<Vec<_>>()
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<CanarySpec>(
                r#"{"id":"a","placement":"guest","token":"chosen"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn fresh_tokens_private_files_and_guest_manifest_never_contain_host_token() {
        let (_t, r) = setup();
        let (_other, r2) = setup();
        let ts = tokens(&r);
        assert_ne!(ts[0], ts[1]);
        assert_ne!(ts, tokens(&r2));
        assert!(
            ts.iter()
                .all(|t| t.starts_with("RTS_CANARY_") && t.len() == 75)
        );
        assert_eq!(
            fs::metadata(r.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let files = r.guest_files();
        assert_eq!(files.len(), 2);
        assert!(
            files
                .iter()
                .all(|(_, bytes)| !bytes.windows(ts[0].len()).any(|w| w == ts[0].as_bytes()))
        );
        let manifest = files.iter().find(|(p, _)| p == &r.manifest_path()).unwrap();
        assert!(!String::from_utf8_lossy(&manifest.1).contains(&ts[1]));
        assert!(files.iter().any(|(_, b)| b.starts_with(ts[1].as_bytes())));
        let loaded = Registry::load(&r.path()).unwrap();
        assert_eq!(loaded.guest_files(), files);
        let v: Value = serde_json::from_slice(&manifest.1).unwrap();
        let host_path = v["canaries"][0]["path"].as_str().unwrap();
        assert_eq!(fs::read_to_string(host_path).unwrap().trim(), ts[0]);
        assert_eq!(
            fs::metadata(host_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn tool_matches_are_redacted_and_audit_contains_only_metadata() {
        let (t, r) = setup();
        let ts = tokens(&r);
        let mut stdout = format!("before {} {} after", ts[0], ts[0]);
        let mut stderr = format!("error {}", ts[1]);
        assert_eq!(
            r.observe_tool("shell", &"a".repeat(64), &mut stdout, &mut stderr)
                .unwrap(),
            2
        );
        assert_eq!(stdout, "before [canary:host-key] [canary:host-key] after");
        assert_eq!(stderr, "error [canary:guest-key]");
        let audit = fs::read_to_string(t.path().join("canaries.jsonl")).unwrap();
        assert_eq!(audit.lines().count(), 2);
        for tok in ts {
            assert!(!audit.contains(&tok));
        }
        let e: Value = serde_json::from_str(audit.lines().next().unwrap()).unwrap();
        assert_eq!(e["source"], "tool_output");
        assert_eq!(e["channel"], "stdout");
        assert_eq!(e["id"], "host-key");
        assert_eq!(e["canonicalInputSha256"], "a".repeat(64));
        assert!(r.summary().unwrap().contains("2 exact matches observed"));
        assert_eq!(
            fs::metadata(t.path().join("canaries.jsonl"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn failed_audit_write_does_not_leave_raw_tokens_in_output() {
        let (t, r) = setup();
        let ts = tokens(&r);
        fs::remove_file(t.path().join("canaries.jsonl")).unwrap();
        fs::create_dir(t.path().join("canaries.jsonl")).unwrap();
        let mut out = ts[0].clone();
        let mut err = ts[1].clone();
        assert!(
            r.observe_tool("shell", &"a".repeat(64), &mut out, &mut err)
                .is_err()
        );
        assert!(!out.contains(&ts[0]));
        assert!(!err.contains(&ts[1]));
    }

    #[test]
    fn export_scan_finds_binary_cross_chunk_matches_without_modifying_files() {
        let (t, r) = setup();
        let ts = tokens(&r);
        let root = t.path().join("out");
        fs::create_dir(&root).unwrap();
        let mut bytes = vec![0xff; 65530];
        bytes.extend_from_slice(ts[1].as_bytes());
        bytes.extend_from_slice(&[0, 255]);
        fs::write(root.join("bundle.bin"), &bytes).unwrap();
        assert_eq!(r.scan_exports(&root).unwrap(), 1);
        assert_eq!(fs::read(root.join("bundle.bin")).unwrap(), bytes);
        let audit = fs::read_to_string(t.path().join("canaries.jsonl")).unwrap();
        let e: Value = serde_json::from_str(audit.trim()).unwrap();
        assert_eq!(e["source"], "export");
        assert_eq!(e["file"], "bundle.bin");
        assert!(!audit.contains(&ts[1]));
    }

    #[test]
    fn export_scan_refuses_symlinks_and_oversized_files() {
        let (t, r) = setup();
        let root = t.path().join("out");
        fs::create_dir(&root).unwrap();
        symlink(r.path(), root.join("link")).unwrap();
        assert!(r.scan_exports(&root).is_err());
        fs::remove_file(root.join("link")).unwrap();
        fs::File::create(root.join("large"))
            .unwrap()
            .set_len(256 * 1024 * 1024 + 1)
            .unwrap();
        assert!(r.scan_exports(&root).is_err());
    }

    #[test]
    fn no_match_is_explicitly_not_proof_of_no_access() {
        let (_t, r) = setup();
        assert_eq!(
            r.observe_tool(
                "shell",
                &"a".repeat(64),
                &mut "clean".into(),
                &mut String::new()
            )
            .unwrap(),
            0
        );
        assert!(r.summary().unwrap().contains("0 exact matches observed"));
        assert!(r.summary().unwrap().contains("not proof of no access"));
    }
    #[test]
    fn export_scan_refuses_excessive_directory_depth() {
        let (t, r) = setup();
        let root = t.path().join("out");
        fs::create_dir(&root).unwrap();
        let mut p = root.clone();
        for _ in 0..129 {
            p = p.join("d");
            fs::create_dir(&p).unwrap();
        }
        assert!(r.scan_exports(&root).is_err());
    }

    #[test]
    fn concurrent_audit_appends_remain_complete_json_records() {
        let (t, r) = setup();
        let token = tokens(&r)[1].clone();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let token = token.clone();
                let path = r.path();
                scope.spawn(move || {
                    let registry = Registry::load(&path).unwrap();
                    for _ in 0..8 {
                        registry
                            .observe_tool(
                                "read",
                                &"a".repeat(64),
                                &mut token.clone(),
                                &mut String::new(),
                            )
                            .unwrap();
                    }
                });
            }
        });
        let audit = fs::read_to_string(t.path().join("canaries.jsonl")).unwrap();
        assert_eq!(audit.lines().count(), 64);
        assert!(
            audit
                .lines()
                .all(|line| serde_json::from_str::<Value>(line).is_ok())
        );
    }

    #[test]
    fn registry_load_and_export_scan_refuse_symlink_roots() {
        let (t, r) = setup();
        symlink(r.path(), t.path().join("registry-link")).unwrap();
        assert!(Registry::load(&t.path().join("registry-link")).is_err());
        let out = t.path().join("out");
        fs::create_dir(&out).unwrap();
        symlink(&out, t.path().join("out-link")).unwrap();
        assert!(r.scan_exports(&t.path().join("out-link")).is_err());
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn a_registry_refuses_on_windows_rather_than_running_with_weaker_checks() {
        let d = tempfile::tempdir().unwrap();
        let e = Registry::create(&[], &d.path().join("reg"), &d.path().join("audit")).err().unwrap();
        assert!(e.contains(UNSUPPORTED), "{e}");
    }
}

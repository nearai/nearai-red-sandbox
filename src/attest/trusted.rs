//! The user's own trusted compose hashes: an owner-only JSON file in the
//! rts home. A build lands here only after the user typed its hash at a
//! launch prompt; `Policy::user_trusted` is built from it.

use std::collections::BTreeMap;
use std::path::Path;

use crate::attest::Role;
use crate::inference::NearEnvironment;

use std::io::Write;

use serde::{Deserialize, Serialize};

use crate::sys::fs::{self, Create};

pub const FILE: &str = "trusted-composes.json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedEntry {
    pub environment: NearEnvironment,
    pub role: Role,
    pub sha256: [u8; 32],
    pub app_name: Option<String>,
    /// `YYYY-MM-DD`, UTC.
    pub trusted_at: String,
}

#[derive(Debug, Default)]
pub struct TrustedComposes {
    pub entries: Vec<TrustedEntry>,
}

impl TrustedComposes {
    pub fn for_environment(&self, near: NearEnvironment) -> BTreeMap<[u8; 32], Role> {
        self.entries
            .iter()
            .filter(|e| e.environment == near)
            .map(|e| (e.sha256, e.role))
            .collect()
    }

    pub fn find(
        &self,
        near: NearEnvironment,
        role: Role,
        hash: &[u8; 32],
    ) -> Option<&TrustedEntry> {
        self.entries
            .iter()
            .find(|e| e.environment == near && e.role == role && &e.sha256 == hash)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileDoc {
    version: u32,
    entries: Vec<FileEntry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileEntry {
    environment: String,
    role: String,
    sha256: String,
    app_name: Option<String>,
    trusted_at: String,
}

fn env_name(e: NearEnvironment) -> &'static str {
    match e {
        NearEnvironment::Production => "production",
        NearEnvironment::Staging => "staging",
    }
}

fn parse_entry(e: FileEntry) -> Result<TrustedEntry, String> {
    let environment = match e.environment.as_str() {
        "production" => NearEnvironment::Production,
        "staging" => NearEnvironment::Staging,
        other => return Err(format!("unknown environment {other:?}")),
    };
    let role = match e.role.as_str() {
        "gateway" => Role::Gateway,
        "model" => Role::Model,
        other => return Err(format!("unknown role {other:?}")),
    };
    if e.sha256.len() != 64
        || e.sha256
            .bytes()
            .any(|b| !matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("sha256 is not 64 lowercase hex characters".into());
    }
    let mut sha256 = [0u8; 32];
    hex::decode_to_slice(&e.sha256, &mut sha256).map_err(|x| x.to_string())?;
    Ok(TrustedEntry {
        environment,
        role,
        sha256,
        app_name: e.app_name,
        trusted_at: e.trusted_at,
    })
}

fn ignored(path: &Path, why: &str) -> (TrustedComposes, Option<String>) {
    (
        TrustedComposes::default(),
        Some(format!("ignoring {}: {why}", path.display())),
    )
}

/// Read the store. The warning is `Some` only when a file existed and was
/// ignored; any malformed content makes the whole file count as empty.
pub fn load(home: Option<&Path>) -> (TrustedComposes, Option<String>) {
    let Some(home) = home else {
        return (TrustedComposes::default(), None);
    };
    let path = home.join(FILE);
    let meta = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (TrustedComposes::default(), None);
        }
        Err(e) => return ignored(&path, &format!("cannot stat it: {e}")),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return ignored(
                &path,
                &format!("mode {mode:o} lets other accounts read or write it; it must be 0600"),
            );
        }
    }
    #[cfg(not(unix))]
    let _ = meta;
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => return ignored(&path, &format!("cannot read it: {e}")),
    };
    let doc: FileDoc = match serde_json::from_slice(&bytes) {
        Ok(d) => d,
        Err(e) => return ignored(&path, &format!("not valid: {e}")),
    };
    if doc.version != 1 {
        return ignored(&path, &format!("unsupported version {}", doc.version));
    }
    let mut entries = Vec::new();
    for e in doc.entries {
        match parse_entry(e) {
            Ok(e) => entries.push(e),
            Err(why) => return ignored(&path, &format!("not valid: {why}")),
        }
    }
    (TrustedComposes { entries }, None)
}

fn write(home: &Path, entries: &[TrustedEntry]) -> Result<(), String> {
    let doc = FileDoc {
        version: 1,
        entries: entries
            .iter()
            .map(|e| FileEntry {
                environment: env_name(e.environment).into(),
                role: e.role.as_str().into(),
                sha256: hex::encode(e.sha256),
                app_name: e.app_name.clone(),
                trusted_at: e.trusted_at.clone(),
            })
            .collect(),
    };
    let json = serde_json::to_vec_pretty(&doc).map_err(|e| e.to_string())?;
    fs::create_private_dir_all(home).map_err(|e| format!("create {}: {e}", home.display()))?;
    let path = home.join(FILE);
    let tmp = home.join(format!("{FILE}.tmp"));
    let result = (|| -> std::io::Result<()> {
        let mut f = fs::open_private(&tmp, Create::Truncate)?;
        fs::restrict_file(&f)?;
        f.write_all(&json)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, &path)
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("write {}: {e}", path.display()));
    }
    Ok(())
}

/// Record `entry`, replacing any entry with the same (environment, role, sha256).
pub fn add(home: &Path, entry: TrustedEntry) -> Result<(), String> {
    let (mut store, _) = load(Some(home));
    store.entries.retain(|e| {
        !(e.environment == entry.environment && e.role == entry.role && e.sha256 == entry.sha256)
    });
    store.entries.push(entry);
    write(home, &store.entries)
}

/// Remove every entry whose sha256 starts with `prefix` (8 to 64 lowercase
/// hex characters), provided exactly one distinct sha256 matches.
pub fn forget(home: &Path, prefix: &str) -> Result<Vec<TrustedEntry>, String> {
    if !(8..=64).contains(&prefix.len())
        || prefix
            .bytes()
            .any(|b| !matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("a hash prefix is 8 to 64 lowercase hex characters".into());
    }
    let (store, warning) = load(Some(home));
    if let Some(w) = warning {
        return Err(w);
    }
    let mut hashes: Vec<[u8; 32]> = store
        .entries
        .iter()
        .filter(|e| hex::encode(e.sha256).starts_with(prefix))
        .map(|e| e.sha256)
        .collect();
    hashes.sort();
    hashes.dedup();
    match hashes.as_slice() {
        [] => Err(format!("no trusted build starts with {prefix}")),
        [one] => {
            let (removed, kept): (Vec<_>, Vec<_>) =
                store.entries.into_iter().partition(|e| &e.sha256 == one);
            write(home, &kept)?;
            Ok(removed)
        }
        _ => Err(format!(
            "{prefix} matches more than one trusted build; give more characters"
        )),
    }
}

/// `YYYY-MM-DD` of a Unix time, in UTC.
pub fn today_utc(unix: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(unix as i64, 0)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "1970-01-01".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(env: NearEnvironment, role: Role, byte: u8, day: &str) -> TrustedEntry {
        TrustedEntry {
            environment: env,
            role,
            sha256: [byte; 32],
            app_name: Some("dstack-0.5.15".into()),
            trusted_at: day.into(),
        }
    }

    #[test]
    fn add_then_load_round_trips() {
        let d = tempfile::tempdir().unwrap();
        let e = entry(NearEnvironment::Production, Role::Gateway, 1, "2026-11-25");
        add(d.path(), e.clone()).unwrap();
        let (got, warn) = load(Some(d.path()));
        assert_eq!(warn, None);
        assert_eq!(got.entries, vec![e]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(d.path().join(FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn add_replaces_the_same_key() {
        let d = tempfile::tempdir().unwrap();
        add(
            d.path(),
            entry(NearEnvironment::Production, Role::Model, 2, "2026-11-24"),
        )
        .unwrap();
        add(
            d.path(),
            entry(NearEnvironment::Production, Role::Model, 2, "2026-11-25"),
        )
        .unwrap();
        let (got, _) = load(Some(d.path()));
        assert_eq!(got.entries.len(), 1);
        assert_eq!(got.entries[0].trusted_at, "2026-11-25");
    }

    #[test]
    fn for_environment_returns_only_that_environment() {
        let d = tempfile::tempdir().unwrap();
        add(
            d.path(),
            entry(NearEnvironment::Production, Role::Gateway, 1, "2026-11-25"),
        )
        .unwrap();
        add(
            d.path(),
            entry(NearEnvironment::Staging, Role::Model, 2, "2026-11-25"),
        )
        .unwrap();
        let (got, _) = load(Some(d.path()));
        let prod = got.for_environment(NearEnvironment::Production);
        assert_eq!(prod.len(), 1);
        assert_eq!(prod.get(&[1; 32]), Some(&Role::Gateway));
        assert!(!prod.contains_key(&[2; 32]));
        assert!(
            got.find(NearEnvironment::Staging, Role::Model, &[2; 32])
                .is_some()
        );
        assert!(
            got.find(NearEnvironment::Production, Role::Model, &[2; 32])
                .is_none()
        );
    }

    #[test]
    fn a_missing_store_is_empty_without_a_message() {
        let d = tempfile::tempdir().unwrap();
        let (got, warn) = load(Some(d.path()));
        assert!(got.entries.is_empty());
        assert_eq!(warn, None);
        let (got, warn) = load(None);
        assert!(got.entries.is_empty());
        assert_eq!(warn, None);
    }

    #[test]
    fn a_corrupt_store_is_ignored_with_a_message() {
        let d = tempfile::tempdir().unwrap();
        write_raw(d.path(), "{");
        let (got, warn) = load(Some(d.path()));
        assert!(got.entries.is_empty());
        assert!(warn.unwrap().contains(FILE));
    }

    #[test]
    fn a_store_with_a_bad_hash_is_ignored() {
        let d = tempfile::tempdir().unwrap();
        let good = hex::encode([1u8; 32]);
        write_raw(
            d.path(),
            &format!(
                r#"{{"version":1,"entries":[{{"environment":"production","role":"gateway","sha256":"{good}","app_name":null,"trusted_at":"2026-11-25"}},{{"environment":"production","role":"model","sha256":"zz","app_name":null,"trusted_at":"2026-11-25"}}]}}"#
            ),
        );
        let (got, warn) = load(Some(d.path()));
        assert!(got.entries.is_empty());
        assert!(warn.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn a_group_readable_store_is_ignored() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        add(
            d.path(),
            entry(NearEnvironment::Production, Role::Gateway, 1, "2026-11-25"),
        )
        .unwrap();
        let p = d.path().join(FILE);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let (got, warn) = load(Some(d.path()));
        assert!(got.entries.is_empty());
        assert!(warn.unwrap().contains("644"));
    }

    #[test]
    fn today_utc_formats_a_known_day() {
        assert_eq!(today_utc(1_795_564_800), "2026-11-25");
    }

    #[test]
    fn forget_removes_one_build() {
        let d = tempfile::tempdir().unwrap();
        add(
            d.path(),
            entry(
                NearEnvironment::Production,
                Role::Gateway,
                0x11,
                "2026-11-25",
            ),
        )
        .unwrap();
        add(
            d.path(),
            entry(NearEnvironment::Production, Role::Model, 0x22, "2026-11-25"),
        )
        .unwrap();
        let removed = forget(d.path(), &hex::encode([0x11u8; 32])[..8]).unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].sha256, [0x11; 32]);
        let (got, _) = load(Some(d.path()));
        assert_eq!(got.entries.len(), 1);
        assert_eq!(got.entries[0].sha256, [0x22; 32]);
    }

    #[test]
    fn forget_refuses_an_ambiguous_prefix() {
        let d = tempfile::tempdir().unwrap();
        let mut a = [0xabu8; 32];
        let mut b = [0xabu8; 32];
        a[31] = 1;
        b[31] = 2;
        for h in [a, b] {
            let mut e = entry(NearEnvironment::Production, Role::Gateway, 0, "2026-11-25");
            e.sha256 = h;
            add(d.path(), e).unwrap();
        }
        let before = std::fs::read(d.path().join(FILE)).unwrap();
        assert!(forget(d.path(), "abababab").is_err());
        assert_eq!(std::fs::read(d.path().join(FILE)).unwrap(), before);
    }

    #[test]
    fn forget_refuses_a_prefix_under_8_chars() {
        let d = tempfile::tempdir().unwrap();
        add(
            d.path(),
            entry(
                NearEnvironment::Production,
                Role::Gateway,
                0xf4,
                "2026-11-25",
            ),
        )
        .unwrap();
        assert!(forget(d.path(), "f4f4f4f").is_err());
    }

    fn write_raw(home: &Path, text: &str) {
        use std::io::Write;
        let mut f =
            crate::sys::fs::open_private(&home.join(FILE), crate::sys::fs::Create::Truncate)
                .unwrap();
        f.write_all(text.as_bytes()).unwrap();
    }
}

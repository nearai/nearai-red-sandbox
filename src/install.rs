//! Where an installed `rts` finds its files.
//!
//! An installed `rts` lives at `<prefix>/bin/rts` (for Homebrew, `bin/rts` is
//! a symlink into the keg, so the path is canonicalized first). A source build
//! (`target/debug/rts`, `target/debug/deps/rts-<hash>`) has no prefix and keeps
//! using the checkout. mvm and opencode live under the home directory.

use std::path::{Path, PathBuf};

use crate::config::Defaults;

pub const MVM_VERSION: &str = "0.22.0";

const SHARE: &str = "share/nearai-red-sandbox";
const HOME_SHARE: &str = ".local/share/nearai-red-sandbox";

/// `<prefix>` when `exe`, canonicalized, sits in a directory named exactly `bin`.
pub fn install_prefix(exe: &Path) -> Option<PathBuf> {
    let exe = std::fs::canonicalize(exe).ok()?;
    let bin = exe.parent()?;
    if bin.file_name()? != "bin" {
        return None;
    }
    bin.parent().map(Path::to_path_buf)
}

/// `install_prefix(current_exe())`, None on any error.
pub fn current_prefix() -> Option<PathBuf> {
    install_prefix(&std::env::current_exe().ok()?)
}

pub fn prefix_plugin(prefix: &Path) -> PathBuf {
    prefix.join(SHARE).join("plugin")
}

pub fn prefix_supervisor(prefix: &Path) -> PathBuf {
    prefix.join("libexec/nearai-red-sandbox/mvm-hvf-supervisor")
}

pub fn home_supervisor(home: &Path) -> PathBuf {
    home.join(HOME_SHARE).join("mvm-hvf-supervisor")
}

pub fn mvm_dir(home: &Path) -> PathBuf {
    home.join(".local/mvm").join(format!("v{MVM_VERSION}"))
}

pub fn opencode_dir(home: &Path) -> PathBuf {
    home.join(HOME_SHARE).join("opencode").join(crate::session::OPENCODE_VERSION)
}

/// Where an installed `rts` keeps sessions when the config names no
/// `sessionsDir`: a release binary's compiled-in checkout path is the CI
/// runner's, so it cannot be used.
pub fn home_sessions(home: &Path) -> PathBuf {
    home.join(HOME_SHARE).join("sessions")
}

/// The launch update check's cache (`ironwire_update::CheckedAt`).
pub fn update_cache(home: &Path) -> PathBuf {
    home.join(HOME_SHARE).join("update-check.json")
}

pub struct Lookup<'a> {
    /// `env!("CARGO_MANIFEST_DIR")`: the checkout a source build came from.
    pub source: &'a Path,
    pub prefix: Option<&'a Path>,
    pub home: &'a Path,
    /// `RTS_MVMCTL`.
    pub rts_mvmctl: Option<&'a Path>,
}

/// The paths a config leaves out. `parse_config` applies config values first.
pub fn defaults(l: &Lookup) -> Defaults {
    let installed_plugin = l.prefix.map(prefix_plugin).filter(|p| p.is_dir());
    let installed = installed_plugin.is_some();
    let opencode = opencode_dir(l.home).join("opencode");
    Defaults {
        mvmctl: l
            .rts_mvmctl
            .map(Path::to_path_buf)
            .unwrap_or_else(|| mvm_dir(l.home).join("mvmctl")),
        plugin_dir: installed_plugin.unwrap_or_else(|| l.source.join("plugin")),
        opencode: if opencode.is_file() {
            opencode.to_string_lossy().into_owned()
        } else {
            "opencode".into()
        },
        sessions_dir: if installed {
            home_sessions(l.home)
        } else {
            l.source.join("sessions")
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn touch(p: &Path) {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, b"").unwrap();
    }

    #[test]
    fn a_symlinked_bin_rts_resolves_to_its_keg() {
        let dir = tempfile::tempdir().unwrap();
        let t = dir.path();
        let real = t.join("Cellar/rts/1.0.0/bin/rts");
        touch(&real);
        fs::create_dir_all(t.join("brew/bin")).unwrap();
        std::os::unix::fs::symlink(&real, t.join("brew/bin/rts")).unwrap();
        let keg = t.join("Cellar/rts/1.0.0").canonicalize().unwrap();
        assert_eq!(install_prefix(&t.join("brew/bin/rts")), Some(keg.clone()));
        assert_eq!(install_prefix(&real), Some(keg));
    }

    #[test]
    fn source_builds_have_no_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let t = dir.path();
        for p in ["target/debug/rts", "target/release/rts", "target/debug/deps/rts-0123abcd", "binx/rts"] {
            touch(&t.join(p));
            assert_eq!(install_prefix(&t.join(p)), None, "{p}");
        }
        assert_eq!(install_prefix(&t.join("missing/bin/rts")), None);
    }

    #[test]
    fn an_installed_layout_supplies_plugin_and_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let prefix = dir.path().join("prefix");
        let home = dir.path().join("home");
        fs::create_dir_all(prefix.join("share/nearai-red-sandbox/plugin")).unwrap();
        let lookup = Lookup { source: Path::new("/src"), prefix: Some(&prefix), home: &home, rts_mvmctl: None };
        let d = defaults(&lookup);
        assert_eq!(d.plugin_dir, prefix.join("share/nearai-red-sandbox/plugin"));
        assert_eq!(d.sessions_dir, home.join(".local/share/nearai-red-sandbox/sessions"));
        assert_eq!(d.mvmctl, home.join(".local/mvm/v0.22.0/mvmctl"));
        assert_eq!(d.opencode, "opencode");
        let opencode = home.join(".local/share/nearai-red-sandbox/opencode/2.2.2/opencode");
        touch(&opencode);
        let d2 = defaults(&lookup);
        assert_eq!(d2.opencode, opencode.to_str().unwrap());
    }

    #[test]
    fn a_source_build_keeps_the_checkout_paths_and_rts_mvmctl_wins() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let d = defaults(&Lookup { source: Path::new("/src"), prefix: None, home: &home, rts_mvmctl: Some(Path::new("/x/mvmctl")) });
        assert_eq!(
            (d.plugin_dir, d.sessions_dir, d.mvmctl),
            (PathBuf::from("/src/plugin"), PathBuf::from("/src/sessions"), PathBuf::from("/x/mvmctl"))
        );
        // A prefix without share/nearai-red-sandbox/plugin behaves like a source build.
        let bare = dir.path().join("bare");
        fs::create_dir_all(&bare).unwrap();
        let d = defaults(&Lookup { source: Path::new("/src"), prefix: Some(&bare), home: &home, rts_mvmctl: None });
        assert_eq!(d.plugin_dir, PathBuf::from("/src/plugin"));
        assert_eq!(d.sessions_dir, PathBuf::from("/src/sessions"));
        assert_eq!(d.mvmctl, home.join(".local/mvm/v0.22.0/mvmctl"));
    }

    #[test]
    fn layout_paths_match_the_spec() {
        let p = Path::new("/p");
        let h = Path::new("/h");
        assert_eq!(prefix_plugin(p), PathBuf::from("/p/share/nearai-red-sandbox/plugin"));
        assert_eq!(prefix_supervisor(p), PathBuf::from("/p/libexec/nearai-red-sandbox/mvm-hvf-supervisor"));
        assert_eq!(home_supervisor(h), PathBuf::from("/h/.local/share/nearai-red-sandbox/mvm-hvf-supervisor"));
        assert_eq!(mvm_dir(h), PathBuf::from("/h/.local/mvm/v0.22.0"));
        assert_eq!(opencode_dir(h), PathBuf::from("/h/.local/share/nearai-red-sandbox/opencode/2.2.2"));
        assert_eq!(home_sessions(h), PathBuf::from("/h/.local/share/nearai-red-sandbox/sessions"));
        assert_eq!(update_cache(h), PathBuf::from("/h/.local/share/nearai-red-sandbox/update-check.json"));
    }
}

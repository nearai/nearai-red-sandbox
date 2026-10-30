//! Update notices and `rts update`: the compiled-in update key and the
//! install channel.

pub mod manifest;

use std::path::{Path, PathBuf};

use crate::install::{install_prefix, prefix_plugin};

/// 64 hex characters (either case) to 32 bytes. Panics otherwise, which is a
/// compile error when evaluated for [`UPDATE_KEY`].
pub const fn parse_key_hex(hex: &str) -> [u8; 32] {
    let hex = hex.as_bytes();
    if hex.len() != 64 {
        panic!("RTS_UPDATE_PUBLIC_KEY_HEX must be 64 hex characters");
    }
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("RTS_UPDATE_PUBLIC_KEY_HEX must be 64 hex characters"),
    }
}

/// The Ed25519 public key that signs `latest.json`, from the build-time
/// environment. None for a build without it, which then behaves as a source
/// build. A malformed value fails const evaluation: a compile error.
pub const UPDATE_KEY: Option<[u8; 32]> = match option_env!("RTS_UPDATE_PUBLIC_KEY_HEX") {
    Some(hex) => Some(parse_key_hex(hex)),
    None => None,
};

/// Who owns this install, and therefore who may update it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Channel {
    /// A curl (install.sh) install under this prefix.
    Release { prefix: PathBuf },
    Homebrew,
    Source,
}

/// Homebrew when `install_prefix(exe)` is `<..>/Cellar/<name>/<version>`;
/// Release when the prefix holds `share/nearai-red-sandbox/plugin` as a
/// directory; Source otherwise. `install_prefix` canonicalizes, so a
/// Homebrew `bin/rts` symlink resolves into its keg.
pub fn channel(exe: &Path) -> Channel {
    let Some(prefix) = install_prefix(exe) else {
        return Channel::Source;
    };
    let cellar = prefix.parent().and_then(Path::parent).and_then(Path::file_name);
    if cellar.is_some_and(|n| n == "Cellar") {
        Channel::Homebrew
    } else if prefix_plugin(&prefix).is_dir() {
        Channel::Release { prefix }
    } else {
        Channel::Source
    }
}

impl Channel {
    /// Homebrew -> Homebrew, Release -> ShellInstaller, Source -> Unmanaged.
    pub fn method(&self) -> ironwire_update::InstallMethod {
        use ironwire_update::InstallMethod;
        match self {
            Self::Homebrew => InstallMethod::Homebrew,
            Self::Release { .. } => InstallMethod::ShellInstaller,
            Self::Source => InstallMethod::Unmanaged,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const REPO_KEY: &str = "9b4a81b8bd017898c36871c6bd1cb890faf95b6e378e72eb99b9c15841f02ac9";

    #[test]
    fn key_hex_parses_both_cases() {
        let want: [u8; 32] = hex::decode(REPO_KEY).unwrap().try_into().unwrap();
        assert_eq!(parse_key_hex(REPO_KEY), want);
        assert_eq!(parse_key_hex(&REPO_KEY.to_uppercase()), want);
    }

    #[test]
    #[should_panic(expected = "RTS_UPDATE_PUBLIC_KEY_HEX")]
    fn a_short_key_panics() {
        parse_key_hex(&REPO_KEY[1..]);
    }

    #[test]
    #[should_panic(expected = "RTS_UPDATE_PUBLIC_KEY_HEX")]
    fn a_long_key_panics() {
        parse_key_hex(&format!("{REPO_KEY}0"));
    }

    #[test]
    #[should_panic(expected = "RTS_UPDATE_PUBLIC_KEY_HEX")]
    fn a_non_hex_key_panics() {
        parse_key_hex(&format!("{}g", &REPO_KEY[1..]));
    }

    fn touch(p: &Path) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, b"").unwrap();
    }

    #[test]
    fn channels_follow_the_layout() {
        let t = tempfile::tempdir().unwrap();
        let t = t.path();

        let keg = t.join("Cellar/rts/0.1.0");
        touch(&keg.join("bin/rts"));
        std::fs::create_dir_all(keg.join("share/nearai-red-sandbox/plugin")).unwrap();
        assert_eq!(channel(&keg.join("bin/rts")), Channel::Homebrew);

        std::fs::create_dir_all(t.join("brew/bin")).unwrap();
        std::os::unix::fs::symlink(keg.join("bin/rts"), t.join("brew/bin/rts")).unwrap();
        assert_eq!(channel(&t.join("brew/bin/rts")), Channel::Homebrew);

        let local = t.join("home/.local");
        touch(&local.join("bin/rts"));
        std::fs::create_dir_all(local.join("share/nearai-red-sandbox/plugin")).unwrap();
        let release = channel(&local.join("bin/rts"));
        assert_eq!(release, Channel::Release { prefix: std::fs::canonicalize(&local).unwrap() });

        // A plugin path that is a file, not a directory, is no release layout.
        let odd = t.join("odd");
        touch(&odd.join("bin/rts"));
        touch(&odd.join("share/nearai-red-sandbox/plugin"));
        assert_eq!(channel(&odd.join("bin/rts")), Channel::Source);

        touch(&t.join("usr/bin/rts"));
        assert_eq!(channel(&t.join("usr/bin/rts")), Channel::Source);
        touch(&t.join("target/debug/rts"));
        assert_eq!(channel(&t.join("target/debug/rts")), Channel::Source);
        assert_eq!(channel(&t.join("missing/bin/rts")), Channel::Source);

        use ironwire_update::InstallMethod;
        assert_eq!(Channel::Homebrew.method(), InstallMethod::Homebrew);
        assert_eq!(release.method(), InstallMethod::ShellInstaller);
        assert_eq!(Channel::Source.method(), InstallMethod::Unmanaged);
    }

    #[test]
    fn a_cellar_that_is_not_the_grandparent_is_not_homebrew() {
        // <t>/Cellar/bin/rts: the prefix is <t>/Cellar, whose grandparent is not Cellar.
        let t = tempfile::tempdir().unwrap();
        let prefix = t.path().join("Cellar");
        touch(&prefix.join("bin/rts"));
        assert_eq!(channel(&prefix.join("bin/rts")), Channel::Source);
    }
}

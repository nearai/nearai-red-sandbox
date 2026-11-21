//! Owner-only files and directories.
//!
//! On Unix these are mode 0600 and 0700. On Windows the equivalent is an
//! owner-only DACL, which is not implemented yet, so every helper here fails
//! with `ErrorKind::Unsupported` there instead of creating a file anyone
//! else could read. Callers that hold secrets never fall back to a plain
//! file.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// Mode of an owner-only file on Unix.
pub const PRIVATE_FILE_MODE: u32 = 0o600;
/// Mode of an owner-only directory on Unix.
pub const PRIVATE_DIR_MODE: u32 = 0o700;

#[cfg(windows)]
fn unsupported(what: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{what} is not supported on Windows yet (owner-only DACLs)"),
    )
}

/// Open `path` with `options`; a file it creates is owner-only.
pub fn open_private(options: &OpenOptions, path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = options.clone();
        options.mode(PRIVATE_FILE_MODE).open(path)
    }
    #[cfg(windows)]
    {
        let _ = (options, path);
        Err(unsupported("an owner-only file"))
    }
}

/// Narrow an open file to owner-only, for a file `open_private` did not create.
pub fn restrict_file(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(PRIVATE_FILE_MODE))
    }
    #[cfg(windows)]
    {
        let _ = file;
        Err(unsupported("narrowing a file to owner-only"))
    }
}

/// Open `path` for reading without blocking on a FIFO (Unix `O_NONBLOCK`),
/// so the caller can check what it opened before reading.
pub fn open_read_nonblocking(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    options.open(path)
}

/// Create `path` and any missing parents; the directories it creates are owner-only.
pub fn create_private_dir_all(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(PRIVATE_DIR_MODE)
            .create(path)
    }
    #[cfg(windows)]
    {
        let _ = path;
        Err(unsupported("an owner-only directory"))
    }
}

/// Narrow an existing directory to owner-only.
pub fn restrict_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_DIR_MODE))
    }
    #[cfg(windows)]
    {
        let _ = path;
        Err(unsupported("narrowing a directory to owner-only"))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn a_created_file_is_owner_only() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        open_private(OpenOptions::new().write(true).create_new(true), &p).unwrap();
        assert_eq!(mode(&p), 0o600);
        // create_new still refuses an existing file.
        assert!(open_private(OpenOptions::new().write(true).create_new(true), &p).is_err());
    }

    #[test]
    fn restrict_file_narrows_an_existing_file() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        std::fs::write(&p, "x").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        restrict_file(&File::open(&p).unwrap()).unwrap();
        assert_eq!(mode(&p), 0o600);
    }

    #[test]
    fn created_directories_are_owner_only_and_restrict_dir_narrows() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a/b");
        create_private_dir_all(&p).unwrap();
        assert_eq!((mode(&d.path().join("a")), mode(&p)), (0o700, 0o700));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        restrict_dir(&p).unwrap();
        assert_eq!(mode(&p), 0o700);
    }
}

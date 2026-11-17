use super::{HostSecret, valid_key};
use std::io::Read;
use std::path::Path;
use zeroize::Zeroizing;

pub(super) fn read_key(path: &Path) -> Result<HostSecret, String> {
    const ERROR: &str =
        "Cannot import sponsored key: use a private regular file containing one valid key";
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ERROR)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(ERROR.into());
    }
    let file = options.open(path).map_err(|_| ERROR)?;
    let metadata = file.metadata().map_err(|_| ERROR)?;
    if !metadata.is_file() {
        return Err(ERROR.into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ERROR.into());
        }
    }
    // One maximum-length key plus CRLF, with one extra byte to detect overflow.
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(4099).read_to_end(&mut bytes).map_err(|_| ERROR)?;
    if bytes.len() > 4098 {
        return Err(ERROR.into());
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    let value = std::str::from_utf8(&bytes).map_err(|_| ERROR)?;
    if !valid_key(value) {
        return Err(ERROR.into());
    }
    Ok(value.to_string().into())
}

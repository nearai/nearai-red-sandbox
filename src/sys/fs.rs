//! Owner-only files and directories.
//!
//! On Unix these are mode 0600 and 0700. On Windows they carry a protected
//! DACL with one ACE, full access for the current user, set when the object
//! is created (never after), so no other account can ever hold a handle to
//! a new file. Directories' ACE is inherited by what is created inside.

use std::fs::File;
use std::io;
use std::path::Path;

/// Mode of an owner-only file on Unix.
pub const PRIVATE_FILE_MODE: u32 = 0o600;
/// Mode of an owner-only directory on Unix.
pub const PRIVATE_DIR_MODE: u32 = 0o700;

/// How `open_private` opens its file (always for writing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Create {
    /// Create a new file; refuse one that exists.
    New,
    /// Create the file, or truncate an existing one.
    Truncate,
    /// Create the file, or append to an existing one.
    Append,
}

/// Open `path` for writing as `how` says. A file this creates is owner-only;
/// an existing file keeps its permissions (narrow it with `restrict_file`).
pub fn open_private(path: &Path, how: Create) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = std::fs::OpenOptions::new();
        match how {
            Create::New => options.write(true).create_new(true),
            Create::Truncate => options.write(true).create(true).truncate(true),
            Create::Append => options.append(true).create(true),
        };
        options.mode(PRIVATE_FILE_MODE).open(path)
    }
    #[cfg(windows)]
    {
        win::create_file(path, how)
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
        win::restrict_file(file)
    }
}

/// Open `path` for reading without blocking on a FIFO (Unix `O_NONBLOCK`),
/// so the caller can check what it opened before reading.
pub fn open_read_nonblocking(path: &Path) -> io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
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
        win::create_dir_all(path)
    }
}

/// The current user's SID ("S-1-5-21-..."), which owner-only DACLs and
/// the Hyper-V backend's hvsocket descriptors name.
#[cfg(windows)]
pub fn current_user_sid() -> io::Result<String> {
    win::user_sid()
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
        win::restrict_dir(path)
    }
}

#[cfg(windows)]
mod win {
    use std::fs::File;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::Path;

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ALREADY_EXISTS, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW, SetSecurityInfo,
    };
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_ALWAYS, CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL,
        FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA,
        OPEN_ALWAYS, READ_CONTROL, ReOpenFile, WRITE_DAC,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::Create;

    const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    fn wide(path: &Path) -> io::Result<Vec<u16>> {
        let mut w: Vec<u16> = path.as_os_str().encode_wide().collect();
        if w.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains a NUL",
            ));
        }
        w.push(0);
        Ok(w)
    }

    /// A NUL-terminated wide string from the system, freed with LocalFree.
    ///
    /// # Safety
    /// `s` must be a valid NUL-terminated LocalAlloc'd wide string.
    unsafe fn take_local_wide(s: *mut u16) -> String {
        // SAFETY: per the contract above.
        unsafe {
            let n = (0..).take_while(|&i| *s.add(i) != 0).count();
            let out = String::from_utf16_lossy(std::slice::from_raw_parts(s, n));
            LocalFree(s.cast());
            out
        }
    }

    /// The current user's SID as an SDDL string ("S-1-5-21-...").
    pub(super) fn user_sid() -> io::Result<String> {
        // SAFETY: standard token query; every handle and buffer is owned here
        // and released on all paths.
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut len = 0u32;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
            // u64 storage keeps the TOKEN_USER header aligned.
            let mut buf = vec![0u64; (len as usize).div_ceil(8)];
            let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len);
            let err = io::Error::last_os_error();
            CloseHandle(token);
            if ok == 0 {
                return Err(err);
            }
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut s: *mut u16 = std::ptr::null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut s) == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(take_local_wide(s))
        }
    }

    /// The owner-only SDDL: a protected DACL with one full-access ACE for
    /// the current user, inherited by children when `inherit`.
    pub(super) fn owner_only_sddl(sid: &str, inherit: bool) -> String {
        format!("D:P(A;{};FA;;;{sid})", if inherit { "OICI" } else { "" })
    }

    /// A self-relative security descriptor, freed on drop.
    struct Descriptor(PSECURITY_DESCRIPTOR);

    impl Descriptor {
        fn owner_only(inherit: bool) -> io::Result<Self> {
            let sddl: Vec<u16> = owner_only_sddl(&user_sid()?, inherit)
                .encode_utf16()
                .chain([0])
                .collect();
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            // SAFETY: `sddl` is NUL-terminated; the descriptor is freed in Drop.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut sd,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(sd))
        }

        fn attributes(&self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.0,
                bInheritHandle: 0,
            }
        }

        fn dacl(&self) -> io::Result<*mut ACL> {
            let (mut present, mut defaulted, mut acl) = (0, 0, std::ptr::null_mut());
            // SAFETY: reads the DACL pointer out of our own descriptor.
            let ok = unsafe {
                GetSecurityDescriptorDacl(self.0, &mut present, &mut acl, &mut defaulted)
            };
            if ok == 0 || present == 0 {
                return Err(io::Error::other("owner-only descriptor has no DACL"));
            }
            Ok(acl)
        }
    }

    impl Drop for Descriptor {
        fn drop(&mut self) {
            // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
            unsafe { LocalFree(self.0) };
        }
    }

    fn set_dacl(result: u32) -> io::Result<()> {
        if result != ERROR_SUCCESS {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        Ok(())
    }

    pub(super) fn create_file(path: &Path, how: Create) -> io::Result<File> {
        let sd = Descriptor::owner_only(false)?;
        let sa = sd.attributes();
        let (access, disposition) = match how {
            Create::New => (FILE_GENERIC_WRITE, CREATE_NEW),
            Create::Truncate => (FILE_GENERIC_WRITE, CREATE_ALWAYS),
            // As std's append: every write right except FILE_WRITE_DATA.
            Create::Append => (FILE_GENERIC_WRITE & !FILE_WRITE_DATA, OPEN_ALWAYS),
        };
        let name = wide(path)?;
        // SAFETY: `name` is NUL-terminated; `sa` and its descriptor outlive the call.
        let h = unsafe {
            CreateFileW(
                name.as_ptr(),
                access,
                SHARE_ALL,
                &sa,
                disposition,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a fresh handle we own.
        Ok(unsafe { File::from_raw_handle(h) })
    }

    pub(super) fn restrict_file(file: &File) -> io::Result<()> {
        // A write handle lacks WRITE_DAC; reopen the same file with it (the
        // owner always holds WRITE_DAC and READ_CONTROL).
        // SAFETY: `file`'s handle is valid for this call.
        let h = unsafe { ReOpenFile(file.as_raw_handle(), WRITE_DAC | READ_CONTROL, SHARE_ALL, 0) };
        if h == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a fresh handle we own, closed when `owned` drops.
        let owned = unsafe { File::from_raw_handle(h) };
        let sd = Descriptor::owner_only(false)?;
        // SAFETY: `owned` holds WRITE_DAC; the ACL lives in `sd`.
        set_dacl(unsafe {
            SetSecurityInfo(
                owned.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                sd.dacl()?,
                std::ptr::null(),
            )
        })
    }

    pub(super) fn create_dir_all(path: &Path) -> io::Result<()> {
        if path.is_dir() {
            return Ok(());
        }
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            create_dir_all(parent)?;
        }
        let sd = Descriptor::owner_only(true)?;
        let sa = sd.attributes();
        let name = wide(path)?;
        // SAFETY: `name` is NUL-terminated; `sa` outlives the call.
        if unsafe { CreateDirectoryW(name.as_ptr(), &sa) } == 0 {
            let e = io::Error::last_os_error();
            // Lost a race to another creator: fine if it is a directory, as on Unix.
            if e.raw_os_error() == Some(ERROR_ALREADY_EXISTS as i32) && path.is_dir() {
                return Ok(());
            }
            return Err(e);
        }
        Ok(())
    }

    pub(super) fn restrict_dir(path: &Path) -> io::Result<()> {
        let sd = Descriptor::owner_only(true)?;
        let name = wide(path)?;
        // SAFETY: `name` is NUL-terminated; the ACL lives in `sd`.
        set_dacl(unsafe {
            SetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                sd.dacl()?,
                std::ptr::null(),
            )
        })
    }

    /// `sddl` as Windows prints it back (well-known accounts become
    /// aliases such as `LA`), for comparing with `dacl_sddl`.
    #[cfg(test)]
    pub(super) fn canonical_sddl(sddl: &str) -> io::Result<String> {
        use windows_sys::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;
        let wide: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated; both allocations are freed below.
        unsafe {
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut s: *mut u16 = std::ptr::null_mut();
            let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut s,
                std::ptr::null_mut(),
            );
            LocalFree(sd);
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(take_local_wide(s))
        }
    }

    /// The DACL of `path` as SDDL, for tests.
    #[cfg(test)]
    pub(super) fn dacl_sddl(path: &Path) -> io::Result<String> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
        };
        let name = wide(path)?;
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: out-pointers are ours; both allocations are freed below.
        unsafe {
            let rc = GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut sd,
            );
            set_dacl(rc)?;
            let mut s: *mut u16 = std::ptr::null_mut();
            let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut s,
                std::ptr::null_mut(),
            );
            LocalFree(sd);
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(take_local_wide(s))
        }
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
        open_private(&p, Create::New).unwrap();
        assert_eq!(mode(&p), 0o600);
        // New still refuses an existing file.
        assert!(open_private(&p, Create::New).is_err());
    }

    #[test]
    fn truncate_and_append_keep_their_semantics() {
        use std::io::Write;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        open_private(&p, Create::Append)
            .unwrap()
            .write_all(b"ab")
            .unwrap();
        open_private(&p, Create::Append)
            .unwrap()
            .write_all(b"cd")
            .unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"abcd");
        assert_eq!(mode(&p), 0o600);
        open_private(&p, Create::Truncate)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"x");
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

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::io::Write;

    /// (DACL flags, ACEs) of an SDDL string "D:<flags>(ace)(ace)...".
    fn split(sddl: &str) -> (String, Vec<String>) {
        let body = sddl
            .strip_prefix("D:")
            .unwrap_or_else(|| panic!("not a DACL: {sddl}"));
        let at = body.find('(').unwrap_or(body.len());
        let aces = body[at..]
            .trim_matches(|c| c == '(' || c == ')')
            .split(")(")
            .map(str::to_string);
        (
            body[..at].to_string(),
            aces.filter(|a| !a.is_empty()).collect(),
        )
    }

    /// The single ACE `open_private` and friends set, as Windows prints it.
    fn owner_ace(inherit: bool) -> String {
        let want =
            win::canonical_sddl(&win::owner_only_sddl(&win::user_sid().unwrap(), inherit)).unwrap();
        let (_, aces) = split(&want);
        assert_eq!(aces.len(), 1, "{want}");
        aces[0].clone()
    }

    /// Protected (no inherited ACEs from above) with exactly the owner ACE.
    fn assert_owner_only(path: &Path, inherit: bool) {
        let got = win::dacl_sddl(path).unwrap();
        let (flags, aces) = split(&got);
        assert!(flags.contains('P'), "DACL not protected: {got}");
        assert_eq!(aces, [owner_ace(inherit)], "{got}");
    }

    #[test]
    fn a_created_file_has_only_the_owner_ace() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        open_private(&p, Create::New)
            .unwrap()
            .write_all(b"secret")
            .unwrap();
        assert_owner_only(&p, false);
        assert!(
            open_private(&p, Create::New).is_err(),
            "New refuses an existing file"
        );
    }

    #[test]
    fn truncate_and_append_keep_their_semantics() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        open_private(&p, Create::Append)
            .unwrap()
            .write_all(b"ab")
            .unwrap();
        open_private(&p, Create::Append)
            .unwrap()
            .write_all(b"cd")
            .unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"abcd");
        assert_owner_only(&p, false);
        open_private(&p, Create::Truncate)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"x");
    }

    #[test]
    fn restrict_file_replaces_an_inherited_dacl() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        std::fs::write(&p, "x").unwrap();
        let (_, before) = split(&win::dacl_sddl(&p).unwrap());
        assert_ne!(
            before,
            [owner_ace(false)],
            "the temp dir already gives only the owner access"
        );
        restrict_file(&std::fs::OpenOptions::new().write(true).open(&p).unwrap()).unwrap();
        assert_owner_only(&p, false);
    }

    #[test]
    fn created_directories_are_owner_only_and_children_inherit() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a").join("b");
        create_private_dir_all(&p).unwrap();
        create_private_dir_all(&p).unwrap(); // an existing directory is fine, as on Unix
        assert_owner_only(&d.path().join("a"), true);
        assert_owner_only(&p, true);

        // A plain file inside inherits exactly the owner ACE, nothing else.
        let plain = p.join("plain");
        std::fs::write(&plain, "x").unwrap();
        let got = win::dacl_sddl(&plain).unwrap();
        let (_, aces) = split(&got);
        let trustee = owner_ace(false).rsplit(';').next().unwrap().to_string();
        assert_eq!(aces.len(), 1, "{got}");
        assert!(
            aces[0].starts_with("A;ID;FA;") && aces[0].ends_with(&trustee),
            "{got}"
        );

        let open = d.path().join("open");
        std::fs::create_dir(&open).unwrap();
        restrict_dir(&open).unwrap();
        assert_owner_only(&open, true);
    }
}

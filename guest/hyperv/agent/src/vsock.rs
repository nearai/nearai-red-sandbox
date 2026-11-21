//! Listen on AF_VSOCK, drop to `uid`, and serve each connection.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::serve::{self, TryClone};

/// Linux's AF_VSOCK (not exported by libc for every target).
const AF_VSOCK: libc::c_int = 40;

pub struct VsockStream(std::fs::File);

impl Read for VsockStream {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.0.read(b)
    }
}

impl Write for VsockStream {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TryClone for VsockStream {
    fn try_clone_stream(&self) -> io::Result<Self> {
        Ok(VsockStream(self.0.try_clone()?))
    }
    fn shutdown_stream(&self) -> io::Result<()> {
        // SAFETY: shutdown on a socket descriptor this stream owns.
        check(unsafe { libc::shutdown(self.0.as_raw_fd(), libc::SHUT_RDWR) }).map(|_| ())
    }
}

fn check(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

impl VsockStream {
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(VsockStream(self.0.try_clone()?))
    }
    pub fn shutdown_write(&self) {
        // SAFETY: shutdown on a socket descriptor this stream owns.
        unsafe { libc::shutdown(self.0.as_raw_fd(), libc::SHUT_WR) };
    }
}

/// The host's CID in vsock addressing.
const VMADDR_CID_HOST: u32 = 2;

/// Connect to the host's service for vsock `port` over hv_sock.
pub fn connect_host(port: u32) -> io::Result<VsockStream> {
    // SAFETY: plain socket syscalls; the descriptor is owned by the stream on success.
    unsafe {
        let fd = OwnedFd::from_raw_fd(check(libc::socket(
            AF_VSOCK,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
        ))?);
        let mut addr: libc::sockaddr_vm = std::mem::zeroed();
        addr.svm_family = AF_VSOCK as libc::sa_family_t;
        addr.svm_port = port;
        addr.svm_cid = VMADDR_CID_HOST;
        check(libc::connect(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_vm).cast(),
            std::mem::size_of::<libc::sockaddr_vm>() as u32,
        ))?;
        Ok(VsockStream(std::fs::File::from(fd)))
    }
}

pub fn run(port: u32, egress_port: u32, uid: u32) -> io::Result<()> {
    // SAFETY: plain socket syscalls on a descriptor this function owns.
    let fd = unsafe {
        OwnedFd::from_raw_fd(check(libc::socket(
            AF_VSOCK,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
        ))?)
    };
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = AF_VSOCK as libc::sa_family_t;
    addr.svm_port = port;
    addr.svm_cid = libc::VMADDR_CID_ANY;
    unsafe {
        check(libc::bind(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_vm).cast(),
            std::mem::size_of::<libc::sockaddr_vm>() as u32,
        ))?;
        check(libc::listen(fd.as_raw_fd(), 16))?;
    }
    drop_privileges(uid)?;
    crate::egress::spawn(egress_port)?;
    eprintln!("rts-guest: listening on vsock port {port} as uid {uid}");
    loop {
        // SAFETY: accept on our listening socket; the result is a new owned descriptor.
        let conn = unsafe {
            libc::accept4(
                fd.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if conn < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        // SAFETY: `conn` is a fresh descriptor we now own.
        let stream = VsockStream(unsafe { std::fs::File::from_raw_fd(conn) });
        std::thread::spawn(move || {
            if let Err(e) = serve::serve(stream) {
                eprintln!("rts-guest: {e}");
            }
        });
    }
}

/// Drop every group and switch to `uid`/`uid` for good; refuse to run on as root.
fn drop_privileges(uid: u32) -> io::Result<()> {
    if uid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to serve commands as root",
        ));
    }
    unsafe {
        check(libc::setgroups(0, std::ptr::null()))?;
        check(libc::setresgid(uid, uid, uid))?;
        check(libc::setresuid(uid, uid, uid))?;
        if libc::setuid(0) == 0 {
            return Err(io::Error::other("privileges were not dropped"));
        }
    }
    Ok(())
}

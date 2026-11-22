//! hvsocket on the Windows host: AF_HYPERV stream connections to a
//! service of one compute system, `{VmId, ServiceId}`. The connected socket
//! is carried in a `std::net::TcpStream`, whose operations (recv, send,
//! shutdown, SO_RCVTIMEO, WSADuplicateSocket) are protocol-neutral.

use std::io;
use std::net::TcpStream;
use std::os::windows::io::FromRawSocket;
use std::sync::OnceLock;
use std::time::Duration;

use windows_sys::Win32::Networking::WinSock::{
    AF_HYPERV, INVALID_SOCKET, SOCK_STREAM, SOCKADDR, SOCKET_ERROR, WSADATA, WSAGetLastError,
    WSAStartup, closesocket, connect, setsockopt, socket,
};
use windows_sys::Win32::System::Hypervisor::{
    HV_PROTOCOL_RAW, HVSOCKET_CONNECT_TIMEOUT, HVSOCKET_CONNECT_TIMEOUT_MAX, SOCKADDR_HV,
};
use windows_sys::core::GUID;

use super::doc::parse_guid;
use super::exec::Connect;
use crate::hvexec::serve::TryClone;

/// A connected hvsocket.
pub struct HvStream(TcpStream);

impl io::Read for HvStream {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.0.read(b)
    }
}

impl io::Write for HvStream {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl TryClone for HvStream {
    fn try_clone_stream(&self) -> io::Result<Self> {
        Ok(HvStream(self.0.try_clone()?))
    }
    fn shutdown_stream(&self) -> io::Result<()> {
        self.0.shutdown(std::net::Shutdown::Both)
    }
}

fn guid(s: &str) -> io::Result<GUID> {
    let (data1, data2, data3, data4) = parse_guid(s)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("not a GUID: {s}")))?;
    Ok(GUID {
        data1,
        data2,
        data3,
        data4,
    })
}

fn winsock() -> io::Result<()> {
    static RESULT: OnceLock<i32> = OnceLock::new();
    let rc = *RESULT.get_or_init(|| {
        // SAFETY: WSAStartup with a valid out-pointer; run once per process.
        let mut data: WSADATA = unsafe { std::mem::zeroed() };
        unsafe { WSAStartup(0x0202, &mut data) }
    });
    match rc {
        0 => Ok(()),
        e => Err(io::Error::from_raw_os_error(e)),
    }
}

/// Connects to one service of one compute system.
pub struct HvConnect {
    vm_id: GUID,
    service_id: GUID,
    connect_timeout: Duration,
}

impl HvConnect {
    pub fn new(vm_id: &str, service_id: &str, connect_timeout: Duration) -> io::Result<Self> {
        Ok(Self {
            vm_id: guid(vm_id)?,
            service_id: guid(service_id)?,
            connect_timeout,
        })
    }
}

impl Connect for HvConnect {
    type Stream = HvStream;

    fn connect(&self, deadline: Duration) -> io::Result<HvStream> {
        winsock()?;
        // SAFETY: plain Winsock calls on a socket this function owns until
        // it is handed to TcpStream (or closed on every error path).
        unsafe {
            let s = socket(AF_HYPERV as i32, SOCK_STREAM, HV_PROTOCOL_RAW as i32);
            if s == INVALID_SOCKET {
                return Err(io::Error::from_raw_os_error(WSAGetLastError()));
            }
            let fail = |s| {
                let e = io::Error::from_raw_os_error(WSAGetLastError());
                closesocket(s);
                Err(e)
            };
            // Without this a connect to a guest whose transport never came
            // up blocks indefinitely.
            let ms: u32 = u32::try_from(self.connect_timeout.as_millis())
                .unwrap_or(u32::MAX)
                .clamp(1, HVSOCKET_CONNECT_TIMEOUT_MAX);
            if setsockopt(
                s,
                HV_PROTOCOL_RAW as i32,
                HVSOCKET_CONNECT_TIMEOUT as i32,
                (&ms as *const u32).cast(),
                4,
            ) == SOCKET_ERROR
            {
                return fail(s);
            }
            let addr = SOCKADDR_HV {
                Family: AF_HYPERV,
                Reserved: 0,
                VmId: self.vm_id,
                ServiceId: self.service_id,
            };
            if connect(
                s,
                (&addr as *const SOCKADDR_HV).cast::<SOCKADDR>(),
                std::mem::size_of::<SOCKADDR_HV>() as i32,
            ) == SOCKET_ERROR
            {
                return fail(s);
            }
            let stream = TcpStream::from_raw_socket(s as u64);
            stream.set_read_timeout(Some(deadline))?;
            Ok(HvStream(stream))
        }
    }
}

/// A host listener on one service of one compute system: only that VM's
/// connections to that service reach it.
pub struct HvListener(ListenSocket);

/// The listening socket, closed on drop.
struct ListenSocket(windows_sys::Win32::Networking::WinSock::SOCKET);

impl Drop for ListenSocket {
    fn drop(&mut self) {
        // SAFETY: closes the socket this value owns, once.
        unsafe { closesocket(self.0) };
    }
}

impl HvListener {
    pub fn bind(vm_id: &str, service_id: &str) -> io::Result<Self> {
        use windows_sys::Win32::Networking::WinSock::{bind, listen};
        winsock()?;
        let (vm, svc) = (guid(vm_id)?, guid(service_id)?);
        // SAFETY: plain Winsock calls on a socket owned by the returned value.
        unsafe {
            let s = socket(AF_HYPERV as i32, SOCK_STREAM, HV_PROTOCOL_RAW as i32);
            if s == INVALID_SOCKET {
                return Err(io::Error::from_raw_os_error(WSAGetLastError()));
            }
            let owned = ListenSocket(s);
            let addr = SOCKADDR_HV {
                Family: AF_HYPERV,
                Reserved: 0,
                VmId: vm,
                ServiceId: svc,
            };
            if bind(
                s,
                (&addr as *const SOCKADDR_HV).cast::<SOCKADDR>(),
                std::mem::size_of::<SOCKADDR_HV>() as i32,
            ) == SOCKET_ERROR
                || listen(s, 16) == SOCKET_ERROR
            {
                return Err(io::Error::from_raw_os_error(WSAGetLastError()));
            }
            Ok(HvListener(owned))
        }
    }

    /// Wait for the next guest connection.
    pub fn accept(&self) -> io::Result<HvStream> {
        use windows_sys::Win32::Networking::WinSock::accept;
        // SAFETY: accept on our listening socket; the result is owned by the stream.
        unsafe {
            let c = accept(self.0.0, std::ptr::null_mut(), std::ptr::null_mut());
            if c == INVALID_SOCKET {
                return Err(io::Error::from_raw_os_error(WSAGetLastError()));
            }
            Ok(HvStream(TcpStream::from_raw_socket(c as u64)))
        }
    }
}

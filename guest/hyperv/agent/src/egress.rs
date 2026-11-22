//! The guest end of egress: a loopback listener at 127.0.0.1:1080 (where
//! the guest's tools find their proxy, as on mvm) that carries each
//! connection, unread, to the host over hvsocket. The host decides
//! everything: it reads the HTTP CONNECT, applies the allowlist and pins,
//! and logs. Nothing here can open a route the host does not.

use std::io;
use std::net::{TcpListener, TcpStream};

use crate::vsock::{VsockStream, connect_host};

pub const LISTEN: &str = "127.0.0.1:1080";

pub fn spawn(port: u32) -> io::Result<()> {
    let listener = TcpListener::bind(LISTEN)?;
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(local) = conn else { continue };
            std::thread::spawn(move || {
                if let Err(e) = forward(local, port) {
                    eprintln!("rts-guest egress: {e}");
                }
            });
        }
    });
    Ok(())
}

fn forward(local: TcpStream, port: u32) -> io::Result<()> {
    let host = connect_host(port)?;
    let (mut lr, mut lw) = (local.try_clone()?, local);
    let (mut hr, mut hw): (VsockStream, VsockStream) = (host.try_clone()?, host);
    let up = std::thread::spawn(move || {
        let _ = io::copy(&mut lr, &mut hw);
        hw.shutdown_write();
    });
    let _ = io::copy(&mut hr, &mut lw);
    let _ = lw.shutdown(std::net::Shutdown::Write);
    let _ = up.join();
    Ok(())
}

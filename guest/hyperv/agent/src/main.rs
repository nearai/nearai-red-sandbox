//! rts-guest: listens on hvsocket (AF_VSOCK over hv_sock) and runs each
//! command rts sends, one connection per command, as an unprivileged user.
//! The protocol is rts's `hvexec` module, included here as source.

// The host-side half of the protocol (encode_argv, decode_exit) is unused here.
// shutdown_stream is used only by the host client.
#[allow(dead_code)]
#[path = "../../../../src/hvexec/serve.rs"]
mod serve;
#[allow(dead_code)]
#[path = "../../../../src/hvexec/wire.rs"]
mod wire;

#[cfg(target_os = "linux")]
mod egress;
#[cfg(target_os = "linux")]
mod vsock;

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let port: u32 = args.get(1).and_then(|p| p.parse().ok()).unwrap_or(5000);
    let uid: u32 = args.get(2).and_then(|u| u.parse().ok()).unwrap_or(1000);
    // The host's egress service is the next vsock port.
    if let Err(e) = vsock::run(port, port + 1, uid) {
        eprintln!("rts-guest: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("rts-guest runs only inside a Linux guest");
    std::process::exit(1);
}

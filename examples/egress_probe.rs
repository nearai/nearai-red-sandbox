//! Test fixture for the Windows egress confinement tests (never shipped):
//! run in the same AppContainer and job as rts-egress, it reports whether
//! it can read the file in RTS_HV_PROBE_FILE (a file in the user profile),
//! reach the host loopback port RTS_HV_PROBE_PORT, and reach the internet.
//! std only, so it loads what rts-egress loads.

use std::io::Write;
use std::time::Duration;

fn main() {
    let file = std::env::var("RTS_HV_PROBE_FILE").unwrap_or_default();
    let port: u16 = std::env::var("RTS_HV_PROBE_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(1);
    let read = match std::fs::read(&file) {
        Ok(_) => "read=ok".to_string(),
        Err(e) => format!("read=denied({:?})", e.kind()),
    };
    let connect = match std::net::TcpStream::connect_timeout(
        &([127, 0, 0, 1], port).into(),
        Duration::from_secs(3),
    ) {
        Ok(_) => "loopback=ok".to_string(),
        Err(e) => format!("loopback=denied({:?})", e.kind()),
    };
    let internet = match std::net::TcpStream::connect_timeout(
        &([1, 1, 1, 1], 443).into(),
        Duration::from_secs(5),
    ) {
        Ok(_) => "internet=ok".to_string(),
        Err(e) => format!("internet=denied({:?})", e.kind()),
    };
    let _ = writeln!(std::io::stdout(), "[probe] {read} {connect} {internet}");
}

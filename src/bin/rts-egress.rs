//! rts-egress: the Windows egress proxy rts starts for each session, in an
//! AppContainer inside a kill-on-close job (src/backend/hyperv/appcontainer.rs).
//! A separate, small executable so the confined process loads nothing but
//! what serving CONNECT needs: no TLS, certificate, shell or COM DLLs, and
//! none that would need a window station or desktop to initialise.
//! stdin and stdout are its only channel to rts.

use std::process::ExitCode;

#[cfg(windows)]
fn main() -> ExitCode {
    match rts::backend::hyperv::mux::proxy_main(
        std::io::stdin().lock(),
        Box::new(std::io::stdout()),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(1),
    }
}

#[cfg(not(windows))]
fn main() -> ExitCode {
    eprintln!("rts-egress runs only on Windows, started by rts");
    ExitCode::from(2)
}

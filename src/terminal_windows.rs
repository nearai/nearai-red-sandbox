//! The Windows side of `terminal`: OpenCode's terminal relay needs a
//! pseudo-console (ConPTY), which is not implemented yet, so a session
//! refuses to start rather than running OpenCode without one.

use std::io;
use std::process::{Child, Command};

pub struct Terminal {
    _private: (),
}

impl Terminal {
    pub fn spawn(_command: &mut Command) -> io::Result<(Child, Self)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the terminal relay (ConPTY) is not supported on Windows yet",
        ))
    }

    pub fn set_title(&mut self, _title: &str) {}

    pub fn enable_input(&mut self) -> io::Result<()> {
        Ok(())
    }

    pub fn pump(&mut self) -> io::Result<()> {
        Ok(())
    }
}

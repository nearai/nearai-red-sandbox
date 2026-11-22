//! The guest side of the exec protocol: run one request and stream its
//! output. std only: `rts-guest` includes this file as is, and rts tests it
//! on the host over a socket pair.

use std::io::{self, Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

use super::wire::{self, EXIT, REQUEST, STDERR, STDIN, STDOUT};

/// Serve one command on `conn`: read the request and stdin, run the argv
/// (never through a shell), stream stdout and stderr, then the exit code.
pub fn serve<S>(conn: S) -> io::Result<()>
where
    S: Read + Write + Send + 'static + TryClone,
{
    let mut reader = conn.try_clone_stream()?;
    let writer = Arc::new(Mutex::new(conn));
    let argv = match wire::read_frame(&mut reader)? {
        Some((REQUEST, payload)) => wire::decode_argv(&payload)?,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected a request frame",
            ));
        }
    };
    let spawned = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            let mut w = writer.lock().unwrap();
            wire::write_frame(
                &mut *w,
                STDERR,
                format!("rts-guest: cannot run {}: {e}\n", argv[0]).as_bytes(),
            )?;
            return wire::write_frame(&mut *w, EXIT, &wire::encode_exit(127));
        }
    };
    let pump = |mut from: Box<dyn Read + Send>, kind: u8, to: Arc<Mutex<S>>| {
        thread::spawn(move || -> io::Result<()> {
            let mut buf = vec![0u8; wire::MAX_FRAME];
            loop {
                let n = from.read(&mut buf)?;
                if n == 0 {
                    return Ok(());
                }
                wire::write_frame(&mut *to.lock().unwrap(), kind, &buf[..n])?;
            }
        })
    };
    let out = pump(
        Box::new(child.stdout.take().unwrap()),
        STDOUT,
        writer.clone(),
    );
    let err = pump(
        Box::new(child.stderr.take().unwrap()),
        STDERR,
        writer.clone(),
    );
    let mut stdin = child.stdin.take().unwrap();
    loop {
        match wire::read_frame(&mut reader)? {
            Some((STDIN, data)) if data.is_empty() => break,
            Some((STDIN, data)) => {
                if stdin.write_all(&data).is_err() {
                    break; // the command stopped reading; keep collecting its output
                }
            }
            None => break,
            Some(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected stdin frames",
                ));
            }
        }
    }
    drop(stdin);
    let status = child.wait()?;
    out.join()
        .map_err(|_| io::Error::other("stdout pump panicked"))??;
    err.join()
        .map_err(|_| io::Error::other("stderr pump panicked"))??;
    #[cfg(unix)]
    let code = {
        use std::os::unix::process::ExitStatusExt;
        status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
    };
    #[cfg(not(unix))]
    let code = status.code().unwrap_or(128);
    wire::write_frame(&mut *writer.lock().unwrap(), EXIT, &wire::encode_exit(code))
}

/// A connection that can be split into a reader and a writer, and shut
/// down from either half to unblock the other.
pub trait TryClone: Sized {
    fn try_clone_stream(&self) -> io::Result<Self>;
    fn shutdown_stream(&self) -> io::Result<()>;
}

#[cfg(unix)]
impl TryClone for std::os::unix::net::UnixStream {
    fn try_clone_stream(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn shutdown_stream(&self) -> io::Result<()> {
        self.shutdown(std::net::Shutdown::Both)
    }
}

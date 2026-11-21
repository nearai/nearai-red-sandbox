//! The exec protocol between rts on the host and `rts-guest` in a Hyper-V
//! guest, over one hvsocket connection per command. std only: the guest
//! agent includes this file as is.
//!
//! The host sends one request frame (the argv, as JSON-free length-prefixed
//! strings) and then any stdin bytes as data frames, ending with an empty
//! one. The guest answers with stdout and stderr chunks and one exit frame.
//! Every frame is `kind: u8, len: u32 big-endian, payload`; no frame is
//! larger than `MAX_FRAME`, and a request is bounded by `MAX_ARGS` and
//! `MAX_REQUEST`. Anything else is a protocol error, never a partial run.

use std::io::{self, Read, Write};

pub const MAX_FRAME: usize = 64 * 1024;
pub const MAX_ARGS: usize = 4096;
pub const MAX_REQUEST: usize = 1024 * 1024;

pub const REQUEST: u8 = 1;
pub const STDIN: u8 = 2;
pub const STDOUT: u8 = 3;
pub const STDERR: u8 = 4;
pub const EXIT: u8 = 5;

pub fn write_frame(w: &mut impl Write, kind: u8, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame over the size limit",
        ));
    }
    let mut head = [0u8; 5];
    head[0] = kind;
    head[1..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    w.write_all(&head)?;
    w.write_all(payload)
}

/// One frame, or `None` at a clean end of stream before a frame starts.
pub fn read_frame(r: &mut impl Read) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut head = [0u8; 5];
    let mut got = 0;
    while got < head.len() {
        match r.read(&mut head[got..])? {
            0 if got == 0 => return Ok(None),
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated frame header",
                ));
            }
            n => got += n,
        }
    }
    let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame over the size limit",
        ));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(Some((head[0], payload)))
}

/// The request payload: a u32 count, then each argument as u32 length + bytes.
pub fn encode_argv(argv: &[String]) -> io::Result<Vec<u8>> {
    if argv.is_empty() || argv.len() > MAX_ARGS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "argv must have 1 to MAX_ARGS entries",
        ));
    }
    let mut out = (argv.len() as u32).to_be_bytes().to_vec();
    for a in argv {
        out.extend_from_slice(&(a.len() as u32).to_be_bytes());
        out.extend_from_slice(a.as_bytes());
    }
    if out.len() > MAX_REQUEST.min(MAX_FRAME) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "request over the size limit",
        ));
    }
    Ok(out)
}

pub fn decode_argv(payload: &[u8]) -> io::Result<Vec<String>> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_string());
    let take = |p: &mut &[u8], n: usize| -> io::Result<Vec<u8>> {
        if p.len() < n {
            return Err(bad("truncated request"));
        }
        let (a, b) = p.split_at(n);
        *p = b;
        Ok(a.to_vec())
    };
    let mut p = payload;
    let count = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
    if count == 0 || count > MAX_ARGS {
        return Err(bad("argv must have 1 to MAX_ARGS entries"));
    }
    let mut argv = Vec::with_capacity(count);
    for _ in 0..count {
        let len = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;
        let bytes = take(&mut p, len)?;
        argv.push(String::from_utf8(bytes).map_err(|_| bad("argument is not UTF-8"))?);
    }
    if !p.is_empty() {
        return Err(bad("trailing bytes after the request"));
    }
    Ok(argv)
}

/// The exit payload: the process's exit code, or `128 + signal`, as i32.
pub fn encode_exit(code: i32) -> [u8; 4] {
    code.to_be_bytes()
}

pub fn decode_exit(payload: &[u8]) -> io::Result<i32> {
    let b: [u8; 4] = payload
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad exit frame"))?;
    Ok(i32::from_be_bytes(b))
}

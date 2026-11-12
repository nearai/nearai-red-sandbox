use super::{HostSecret, InferenceCredential, valid_key};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

const MAX_BYTES: usize = 8192;
const REFUSED: &str = "NEAR AI browser callback refused";

pub(super) struct Callback {
    listener: TcpListener,
    host: String,
    path: String,
}

impl Callback {
    pub(super) fn bind() -> Result<Self, String> {
        let listener =
            TcpListener::bind("127.0.0.1:0").map_err(|_| "Cannot bind NEAR AI sign-in callback")?;
        listener
            .set_nonblocking(true)
            .map_err(|_| "Cannot configure NEAR AI sign-in callback")?;
        let host = listener
            .local_addr()
            .map_err(|_| "Cannot address NEAR AI sign-in callback")?
            .to_string();
        Ok(Self {
            listener,
            host,
            path: format!("/rts/{}/callback", crate::protocol::random_hex(32)),
        })
    }

    pub(super) fn url(&self) -> String {
        format!("http://{}{}", self.host, self.path)
    }

    pub(super) fn receive(
        self,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
        state: &str,
        finish: impl FnOnce(HostSecret) -> Result<InferenceCredential, String>,
    ) -> Result<InferenceCredential, String> {
        loop {
            check_deadline(deadline, cancelled)?;
            let (mut stream, _) = match self.listener.accept() {
                Ok(value) => value,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(_) => return Err("NEAR AI callback listener failed".into()),
            };
            let request_deadline = deadline.min(Instant::now() + Duration::from_secs(2));
            let request = match read_request(&mut stream, request_deadline, cancelled) {
                Ok(request) => request,
                Err(error) if error == "NEAR AI sign-in interrupted" => return Err(error),
                Err(_) => {
                    respond(
                        &mut stream,
                        "400 Bad Request",
                        "text/plain",
                        "Callback refused.",
                    );
                    continue;
                }
            };
            if request.host != self.host {
                respond(
                    &mut stream,
                    "400 Bad Request",
                    "text/plain",
                    "Callback refused.",
                );
                continue;
            }
            let Some((path, query)) = request.path.split_once('?') else {
                respond(
                    &mut stream,
                    "400 Bad Request",
                    "text/plain",
                    "Callback refused.",
                );
                continue;
            };
            if request.method != "GET" || path != self.path || !request.body.is_empty() {
                respond(&mut stream, "404 Not Found", "text/plain", "Not found.");
                continue;
            }
            match decode_callback(query, state) {
                Ok(code) => {
                    check_deadline(deadline, cancelled)?;
                    let result = finish(code);
                    if result.is_ok() {
                        respond(
                            &mut stream,
                            "200 OK",
                            "text/plain",
                            "Signed in. Return to your terminal.",
                        );
                    } else {
                        respond(
                            &mut stream,
                            "500 Internal Server Error",
                            "text/plain",
                            "Sign-in setup failed. Return to your terminal.",
                        );
                    }
                    return result;
                }
                Err(error) if error == "NEAR AI sign-in failed" => {
                    respond(
                        &mut stream,
                        "400 Bad Request",
                        "text/plain",
                        "Sign-in failed. Return to your terminal.",
                    );
                    return Err(error);
                }
                Err(_) => respond(
                    &mut stream,
                    "400 Bad Request",
                    "text/plain",
                    "Callback refused.",
                ),
            }
        }
    }
}

pub(super) fn open(url: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let mut command = Command::new("/usr/bin/open");
    #[cfg(not(target_os = "macos"))]
    let mut command = Command::new("xdg-open");
    let mut child = command
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Cannot open browser for NEAR AI sign-in")?;
    // Reap without blocking the five-minute callback deadline.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

pub(super) fn check_deadline(
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), String> {
    if cancelled() {
        return Err("NEAR AI sign-in interrupted".into());
    }
    if Instant::now() >= deadline {
        return Err("NEAR AI sign-in timed out".into());
    }
    Ok(())
}

/// A code is accepted only with the initiating app's independent state.
/// Token-bearing legacy responses and ambiguous parameters never enter redemption.
pub(super) fn decode_callback(query: &str, state: &str) -> Result<HostSecret, String> {
    if query.len() > MAX_BYTES || query.contains('#') {
        return Err(REFUSED.into());
    }
    let mut seen_state = None;
    let mut code = None;
    let mut error = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        let value = Zeroizing::new(value.into_owned());
        match key.as_ref() {
            "state" if seen_state.is_none() => seen_state = Some(value),
            "code" if code.is_none() => code = Some(value),
            "error" if error.is_none() => error = Some(value),
            _ => return Err(REFUSED.into()),
        }
    }
    if seen_state.as_deref().map(String::as_str) != Some(state) {
        return Err(REFUSED.into());
    }
    if error.is_some() && code.is_none() {
        return Err("NEAR AI sign-in failed".into());
    }
    if error.is_some() {
        return Err(REFUSED.into());
    }
    let mut code = code.ok_or(REFUSED)?;
    if !valid_key(&code) {
        return Err(REFUSED.into());
    }
    Ok(std::mem::take(&mut *code).into())
}

struct Request {
    method: String,
    path: Zeroizing<String>,
    host: String,
    body: Zeroizing<String>,
}

fn read_request(
    stream: &mut TcpStream,
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<Request, String> {
    stream.set_nonblocking(true).map_err(|_| REFUSED)?;
    let mut bytes = Zeroizing::new(Vec::new());
    let (header_end, body_len) = loop {
        read_more(stream, &mut bytes, deadline, cancelled)?;
        if let Some(pos) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            let end = pos + 4;
            if end > MAX_BYTES {
                return Err(REFUSED.into());
            }
            let headers = std::str::from_utf8(&bytes[..end]).map_err(|_| REFUSED)?;
            let mut length = None;
            for line in headers
                .split("\r\n")
                .skip(1)
                .filter(|line| !line.is_empty())
            {
                let (name, value) = line.split_once(':').ok_or(REFUSED)?;
                if name.eq_ignore_ascii_case("transfer-encoding") {
                    return Err(REFUSED.into());
                }
                if name.eq_ignore_ascii_case("content-length") {
                    if length.is_some() {
                        return Err(REFUSED.into());
                    }
                    length = Some(value.trim().parse::<usize>().map_err(|_| REFUSED)?);
                }
            }
            let length = length.unwrap_or(0);
            if length > MAX_BYTES {
                return Err(REFUSED.into());
            }
            break (end, length);
        }
        if bytes.len() >= MAX_BYTES {
            return Err(REFUSED.into());
        }
    };
    while bytes.len() < header_end + body_len {
        read_more(stream, &mut bytes, deadline, cancelled)?;
    }
    if bytes.len() != header_end + body_len {
        return Err(REFUSED.into());
    }
    let headers = std::str::from_utf8(&bytes[..header_end]).map_err(|_| REFUSED)?;
    let mut lines = headers.split("\r\n");
    let first: Vec<_> = lines.next().ok_or(REFUSED)?.split_whitespace().collect();
    if first.len() != 3 || first[2] != "HTTP/1.1" {
        return Err(REFUSED.into());
    }
    let mut host = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(REFUSED)?;
        let slot = match name.to_ascii_lowercase().as_str() {
            "host" => &mut host,
            _ => continue,
        };
        if slot.is_some() {
            return Err(REFUSED.into());
        }
        *slot = Some(value.trim().to_string());
    }
    let body = Zeroizing::new(
        std::str::from_utf8(&bytes[header_end..])
            .map_err(|_| REFUSED)?
            .to_string(),
    );
    Ok(Request {
        method: first[0].into(),
        path: Zeroizing::new(first[1].into()),
        host: host.ok_or(REFUSED)?,
        body,
    })
}

fn read_more(
    stream: &mut TcpStream,
    bytes: &mut Zeroizing<Vec<u8>>,
    deadline: Instant,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), String> {
    loop {
        check_deadline(deadline, cancelled)?;
        let mut chunk = [0u8; 2048];
        match stream.read(&mut chunk) {
            Ok(0) => return Err(REFUSED.into()),
            Ok(count) => {
                if bytes.len() + count > MAX_BYTES * 2 {
                    chunk.zeroize();
                    return Err(REFUSED.into());
                }
                bytes.extend_from_slice(&chunk[..count]);
                chunk.zeroize();
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(_) => return Err(REFUSED.into()),
        }
    }
}

fn respond(stream: &mut TcpStream, status: &str, content_type: &str, body: &str) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_write_timeout(Some(Duration::from_millis(100)));
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body.as_bytes());
}

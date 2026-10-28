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
    nonce: String,
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
            nonce: crate::protocol::random_hex(32),
        })
    }

    pub(super) fn url(&self) -> String {
        format!("http://{}{}", self.host, self.path)
    }

    pub(super) fn receive(
        self,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
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
            if request.method == "GET" && request.path == self.path {
                respond(
                    &mut stream,
                    "200 OK",
                    "text/html; charset=utf-8",
                    &self.page(),
                );
                continue;
            }
            if request.method != "POST" || request.path != format!("{}/deposit", self.path) {
                respond(&mut stream, "404 Not Found", "text/plain", "Not found.");
                continue;
            }
            if !valid_submission(
                request.origin.as_deref(),
                &request.host,
                &self.host,
                request.fetch_site.as_deref(),
            ) {
                respond(
                    &mut stream,
                    "403 Forbidden",
                    "text/plain",
                    "Callback refused.",
                );
                continue;
            }
            match decode_deposit(&request.body, &self.nonce) {
                Ok(token) => {
                    check_deadline(deadline, cancelled)?;
                    let result = finish(token);
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
                Err(_) => respond(
                    &mut stream,
                    "400 Bad Request",
                    "text/plain",
                    "Callback refused.",
                ),
            }
        }
    }

    fn page(&self) -> String {
        // Both interpolated strings are generated hexadecimal capabilities.
        // The refresh token stays in browser memory and is discarded there.
        format!(
            r#"<!doctype html><meta charset="utf-8"><title>NEAR AI Red Sandbox</title>
<p id="status">Finishing sign-in…</p><script>
const fragment = new URLSearchParams(location.hash.slice(1));
history.replaceState(null, "", location.pathname);
const body = new URLSearchParams(); body.set("state", "{}");
if (fragment.getAll("token").length === 1) body.set("token", fragment.get("token"));
fragment.delete("token"); fragment.delete("refresh_token");
fetch("{}/deposit", {{method:"POST", credentials:"omit", headers:{{"Content-Type":"application/x-www-form-urlencoded"}}, body:body.toString()}})
.then(r => {{document.getElementById("status").textContent = r.ok ? "Signed in. Return to your terminal." : "Sign-in failed. Return to your terminal.";}})
.catch(() => {{document.getElementById("status").textContent = "Sign-in failed. Return to your terminal.";}});
</script>"#,
            self.nonce, self.path
        )
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

pub(super) fn valid_submission(
    origin: Option<&str>,
    host: &str,
    expected: &str,
    fetch_site: Option<&str>,
) -> bool {
    host == expected
        && origin == Some(format!("http://{expected}").as_str())
        && fetch_site.is_none_or(|site| site == "same-origin")
}

pub(super) fn decode_deposit(body: &str, state: &str) -> Result<HostSecret, String> {
    if body.len() > MAX_BYTES {
        return Err(REFUSED.into());
    }
    let mut seen_state = None;
    let mut token = None;
    let mut refresh_seen = false;
    for (key, value) in url::form_urlencoded::parse(body.as_bytes()) {
        let value = Zeroizing::new(value.into_owned());
        match key.as_ref() {
            "state" if seen_state.is_none() => seen_state = Some(value),
            "token" if token.is_none() => token = Some(value),
            "refresh_token" if !refresh_seen => {
                refresh_seen = true;
            }
            _ => return Err(REFUSED.into()),
        }
    }
    if seen_state.as_deref().map(String::as_str) != Some(state) {
        return Err(REFUSED.into());
    }
    let mut token = token.ok_or(REFUSED)?;
    if !valid_key(&token) {
        return Err(REFUSED.into());
    }
    Ok(std::mem::take(&mut *token).into())
}

struct Request {
    method: String,
    path: String,
    host: String,
    origin: Option<String>,
    fetch_site: Option<String>,
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
    let mut origin = None;
    let mut fetch_site = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(REFUSED)?;
        let slot = match name.to_ascii_lowercase().as_str() {
            "host" => &mut host,
            "origin" => &mut origin,
            "sec-fetch-site" => &mut fetch_site,
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
        path: first[1].into(),
        host: host.ok_or(REFUSED)?,
        origin,
        fetch_site,
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

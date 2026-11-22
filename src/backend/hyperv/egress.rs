//! The host end of guest egress on Windows: a CONNECT-only proxy behind
//! the VM's egress hvsocket service. The guest's 127.0.0.1:1080 forwards
//! each connection here unread; this side reads the HTTP CONNECT, allows
//! only the session's allowlist, connects only to the addresses the
//! allowlist resolved to when the session's plan was made (pinned by
//! construction, never re-resolved), refuses rts's refused ranges
//! (loopback, link-local, cloud metadata; listed LAN targets are allowed)
//! and writes one audit line per connection. Pure std over generic streams,
//! so every rule is tested on any OS.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use crate::backend::Pinned;
use crate::hvexec::serve::TryClone;
use crate::network::{Host, Plan, refused_range};

/// The longest request head read before refusing.
const MAX_HEAD: usize = 8 * 1024;
/// How long one upstream connect may take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// What the allowlist permits: each `name:port` with its pinned
/// addresses, and each literal `ip:port`. Serializes to JSON for handing
/// to the confined proxy process.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    names: BTreeMap<(String, u16), Vec<IpAddr>>,
    ips: BTreeSet<(IpAddr, u16)>,
}

impl Policy {
    pub fn from_plan(plan: &Plan) -> Self {
        let mut p = Policy::default();
        for e in plan.entries() {
            match &e.host {
                Host::Name(n) => {
                    let ips = plan
                        .resolved_ips(n)
                        .iter()
                        .copied()
                        .filter(|ip| refused_range(*ip).is_none())
                        .collect();
                    p.names.insert((n.to_ascii_lowercase(), e.port), ips);
                }
                Host::Ip(ip) => {
                    p.ips.insert((*ip, e.port));
                }
            }
        }
        p
    }

    pub fn to_json(&self) -> String {
        let names: Vec<_> = self
            .names
            .iter()
            .map(|((n, p), ips)| serde_json::json!([n, p, ips]))
            .collect();
        let ips: Vec<_> = self
            .ips
            .iter()
            .map(|(ip, p)| serde_json::json!([ip, p]))
            .collect();
        serde_json::json!({"names": names, "ips": ips}).to_string()
    }

    pub fn from_json(s: &str) -> Result<Self, String> {
        #[derive(serde::Deserialize)]
        struct Wire {
            names: Vec<(String, u16, Vec<IpAddr>)>,
            ips: Vec<(IpAddr, u16)>,
        }
        let w: Wire = serde_json::from_str(s).map_err(|e| format!("egress policy: {e}"))?;
        let mut p = Policy::default();
        for (n, port, ips) in w.names {
            // Refused ranges never enter a policy, whoever wrote it.
            p.names.insert(
                (n.to_ascii_lowercase(), port),
                ips.into_iter()
                    .filter(|ip| refused_range(*ip).is_none())
                    .collect(),
            );
        }
        for (ip, port) in w.ips {
            if refused_range(ip).is_none() {
                p.ips.insert((ip, port));
            }
        }
        Ok(p)
    }

    /// Every allowlisted name and the addresses the proxy may dial for it.
    pub fn pins(&self) -> Pinned {
        let mut pins = Pinned::new();
        for ((name, _), ips) in &self.names {
            pins.entry(name.clone())
                .or_default()
                .extend(ips.iter().copied());
        }
        pins
    }

    /// The addresses `target` (CONNECT's `host:port` or `[v6]:port`) may be
    /// reached at, and the name its pins are recorded under; or why not.
    pub fn decide(&self, target: &str) -> Result<(String, Vec<SocketAddr>), String> {
        let (host, port) = split_target(target).ok_or("not a host:port target")?;
        if let Ok(ip) = host.parse::<IpAddr>() {
            if let Some(range) = refused_range(ip) {
                return Err(format!("{range} addresses are always refused"));
            }
            if !self.ips.contains(&(ip, port)) {
                return Err("not on the allowlist".into());
            }
            return Ok((ip.to_string(), vec![SocketAddr::new(ip, port)]));
        }
        let name = host.to_ascii_lowercase();
        match self.names.get(&(name.clone(), port)) {
            Some(ips) if !ips.is_empty() => Ok((
                name,
                ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect(),
            )),
            Some(_) => Err("the allowlisted name has no allowed address".into()),
            None => Err("not on the allowlist".into()),
        }
    }
}

/// `host:port` or `[v6]:port` into its parts.
fn split_target(t: &str) -> Option<(&str, u16)> {
    let (host, port) = if let Some(rest) = t.strip_prefix('[') {
        let (h, p) = rest.split_once("]:")?;
        (h, p)
    } else {
        let (h, p) = t.rsplit_once(':')?;
        if h.contains(':') {
            return None;
        }
        (h, p)
    };
    if host.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((host, port.parse().ok().filter(|p: &u16| *p != 0)?))
}

/// The audit log (network.jsonl) and the addresses used, per name.
pub struct Audit {
    sink: Mutex<Sink>,
    pinned: Mutex<Pinned>,
}

/// Where audit lines go: appended to an owner-only file (rts), or written
/// to a stream (the confined proxy's stdout, which rts reads).
enum Sink {
    File(PathBuf),
    Stream(Box<dyn Write + Send>),
}

impl Audit {
    /// Append to the owner-only file at `path`.
    pub fn new(path: &Path) -> Self {
        Self {
            sink: Mutex::new(Sink::File(path.to_path_buf())),
            pinned: Mutex::new(Pinned::new()),
        }
    }

    /// Write each line to `out`.
    pub fn to_stream(out: Box<dyn Write + Send>) -> Self {
        Self {
            sink: Mutex::new(Sink::Stream(out)),
            pinned: Mutex::new(Pinned::new()),
        }
    }

    pub fn pinned(&self) -> Pinned {
        self.pinned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn record(&self, target: &str, result: &str, ip: Option<IpAddr>, reason: Option<&str>) {
        let line = serde_json::json!({
            "time": chrono::Utc::now().to_rfc3339(),
            "target": target.chars().take(300).collect::<String>(),
            "result": result,
            "ip": ip.map(|i| i.to_string()),
            "reason": reason,
        });
        self.write_line(&line.to_string());
    }

    /// Append one already-formed audit line (rts relaying the proxy's).
    pub fn write_line(&self, line: &str) {
        let mut sink = self.sink.lock().unwrap_or_else(|e| e.into_inner());
        match &mut *sink {
            Sink::File(path) => {
                if let Ok(mut f) =
                    crate::sys::fs::open_private(path, crate::sys::fs::Create::Append)
                {
                    let _ = writeln!(f, "{line}");
                }
            }
            Sink::Stream(out) => {
                let _ = writeln!(out, "{line}");
                let _ = out.flush();
            }
        }
    }
}

/// Read the request head: up to the blank line, at most MAX_HEAD bytes.
/// Returns the head and any bytes the client sent after it.
fn read_head(conn: &mut impl Read) -> io::Result<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(end + 4);
            return Ok((String::from_utf8_lossy(&buf).into_owned(), rest));
        }
        if buf.len() >= MAX_HEAD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request head too long",
            ));
        }
        let n = conn.read(&mut chunk)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no request"));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Serve one guest connection. `dial` connects to one address with a timeout.
pub fn serve_one<S, D>(mut conn: S, policy: &Policy, audit: &Audit, dial: D) -> io::Result<()>
where
    S: Read + Write + Send + TryClone + 'static,
    D: Fn(&SocketAddr) -> io::Result<TcpStream>,
{
    let reply = |conn: &mut S, status: &str| {
        conn.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n").as_bytes())
    };
    let (head, early) = match read_head(&mut conn) {
        Ok(h) => h,
        Err(e) => {
            audit.record("", "refused", None, Some("malformed request"));
            let _ = reply(&mut conn, "400 Bad Request");
            return Err(e);
        }
    };
    let line = head.lines().next().unwrap_or("");
    let mut parts = line.split(' ');
    let (method, target, version) = (parts.next(), parts.next(), parts.next());
    let target = match (method, target, version, parts.next()) {
        (Some("CONNECT"), Some(t), Some(v), None) if v.starts_with("HTTP/1.") => t,
        _ => {
            audit.record(
                target.unwrap_or(""),
                "refused",
                None,
                Some("only CONNECT is allowed"),
            );
            return reply(&mut conn, "405 Method Not Allowed");
        }
    };
    let (name, addrs) = match policy.decide(target) {
        Ok(d) => d,
        Err(why) => {
            audit.record(target, "refused", None, Some(&why));
            return reply(&mut conn, "403 Forbidden");
        }
    };
    let mut upstream = None;
    for a in &addrs {
        if let Ok(s) = dial(a) {
            upstream = Some((s, a.ip()));
            break;
        }
    }
    let Some((mut up, ip)) = upstream else {
        audit.record(target, "failed", None, Some("no allowed address answered"));
        return reply(&mut conn, "502 Bad Gateway");
    };
    audit.record(target, "allowed", Some(ip), None);
    audit
        .pinned
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(name)
        .or_default()
        .insert(ip);
    conn.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
    up.write_all(&early)?;
    splice(conn, up)
}

/// Copy both ways until either side closes.
fn splice<S: Read + Write + Send + TryClone + 'static>(conn: S, up: TcpStream) -> io::Result<()> {
    let (mut guest_r, mut guest_w) = (conn.try_clone_stream()?, conn);
    let (mut up_r, mut up_w) = (up.try_clone()?, up);
    let to_up = std::thread::spawn(move || {
        let _ = io::copy(&mut guest_r, &mut up_w);
        let _ = up_w.shutdown(std::net::Shutdown::Write);
    });
    let _ = io::copy(&mut up_r, &mut guest_w);
    let _ = guest_w.shutdown_stream();
    let _ = to_up.join();
    Ok(())
}

/// Connect to `a` within CONNECT_TIMEOUT.
pub fn dial(a: &SocketAddr) -> io::Result<TcpStream> {
    TcpStream::connect_timeout(a, CONNECT_TIMEOUT)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::network::Resolver;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::os::unix::net::UnixStream;

    struct Fake(Vec<(&'static str, Vec<IpAddr>)>);

    impl Resolver for Fake {
        fn resolve(&self, name: &str) -> io::Result<Vec<IpAddr>> {
            self.0
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| v.clone())
                .ok_or_else(|| io::Error::other("nx"))
        }
    }

    fn policy(entries: &[&str], dns: Vec<(&'static str, Vec<IpAddr>)>) -> Policy {
        let written: Vec<String> = entries.iter().map(|e| e.to_string()).collect();
        Policy::from_plan(&crate::network::plan(&written, &Fake(dns)).unwrap())
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn only_allowlisted_targets_at_their_planned_addresses_are_allowed() {
        let p = policy(
            &["a.example", "198.51.100.7:8443"],
            vec![("a.example", vec![ip("203.0.113.5")])],
        );
        let (name, addrs) = p.decide("A.Example:443").unwrap();
        assert_eq!(name, "a.example");
        assert_eq!(addrs, [SocketAddr::new(ip("203.0.113.5"), 443)]);
        assert_eq!(
            p.decide("198.51.100.7:8443").unwrap().1,
            [SocketAddr::new(ip("198.51.100.7"), 8443)]
        );
        for refused in [
            "a.example:80",
            "b.example:443",
            "198.51.100.7:443",
            "198.51.100.8:8443",
            "203.0.113.5:443",
        ] {
            assert!(p.decide(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn a_policy_round_trips_through_json_and_refused_ranges_never_enter() {
        let p = policy(
            &["a.example", "198.51.100.7:8443"],
            vec![("a.example", vec![ip("203.0.113.5")])],
        );
        let q = Policy::from_json(&p.to_json()).unwrap();
        assert_eq!(
            q.decide("a.example:443").unwrap(),
            p.decide("a.example:443").unwrap()
        );
        assert_eq!(
            q.decide("198.51.100.7:8443").unwrap(),
            p.decide("198.51.100.7:8443").unwrap()
        );
        let forged = r#"{"names":[["a.example",443,["169.254.169.254","203.0.113.5"]]],"ips":[["127.0.0.1",443]]}"#;
        let f = Policy::from_json(forged).unwrap();
        assert_eq!(
            f.decide("a.example:443").unwrap().1,
            [SocketAddr::new(ip("203.0.113.5"), 443)]
        );
        assert!(
            f.decide("127.0.0.1:443").is_err(),
            "loopback never enters a policy"
        );
        assert!(Policy::from_json("not json").is_err());
    }

    #[test]
    fn audit_lines_can_go_to_a_stream() {
        let (mut r, w) = UnixStream::pair().unwrap();
        let audit = Audit::to_stream(Box::new(w));
        audit.record(
            "a.example:443",
            "refused",
            None,
            Some("not on the allowlist"),
        );
        let mut line = String::new();
        BufReader::new(&mut r).read_line(&mut line).unwrap();
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(
            (v["target"].as_str(), v["result"].as_str()),
            (Some("a.example:443"), Some("refused"))
        );
    }

    #[test]
    fn off_list_refused_range_and_malformed_targets_are_refused() {
        let p = policy(&["a.example"], vec![("a.example", vec![ip("203.0.113.5")])]);
        for bad in [
            "169.254.169.254:80",
            "127.0.0.1:443",
            "10.0.0.1:443",
            "[::1]:443",
            "a.example",
            "a.example:0",
            "a.example:x",
            ":443",
            "a:b:443",
        ] {
            assert!(p.decide(bad).is_err(), "{bad}");
        }
    }

    /// Run serve_one on one end of a socket pair against `policy`,
    /// dialing everything to a local echo server; return the guest end.
    fn proxy(p: Policy, audit: std::sync::Arc<Audit>) -> UnixStream {
        let echo = TcpListener::bind("127.0.0.1:0").unwrap();
        let echo_addr = echo.local_addr().unwrap();
        std::thread::spawn(move || {
            for c in echo.incoming() {
                let mut c = c.unwrap();
                std::thread::spawn(move || {
                    let mut r = c.try_clone().unwrap();
                    let _ = io::copy(&mut r, &mut c);
                });
            }
        });
        let (guest, host) = UnixStream::pair().unwrap();
        std::thread::spawn(move || serve_one(host, &p, &audit, |_| TcpStream::connect(echo_addr)));
        guest
    }

    fn status(guest: &mut UnixStream, request: &str) -> String {
        guest.write_all(request.as_bytes()).unwrap();
        let mut line = String::new();
        BufReader::new(guest.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        line
    }

    #[test]
    fn an_allowed_connect_is_spliced_pinned_and_audited() {
        let d = tempfile::tempdir().unwrap();
        let audit = std::sync::Arc::new(Audit::new(&d.path().join("network.jsonl")));
        let p = policy(&["a.example"], vec![("a.example", vec![ip("203.0.113.5")])]);
        let mut g = proxy(p, audit.clone());
        g.write_all(b"CONNECT a.example:443 HTTP/1.1\r\nHost: a.example:443\r\n\r\nearly")
            .unwrap();
        let mut r = BufReader::new(g.try_clone().unwrap());
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        assert_eq!(line, "HTTP/1.1 200 Connection established\r\n");
        r.read_line(&mut line).unwrap();
        g.write_all(b" then more\n").unwrap();
        let mut echoed = String::new();
        r.read_line(&mut echoed).unwrap();
        assert_eq!(
            echoed, "early then more\n",
            "bytes after the head go upstream first"
        );
        let pins = audit.pinned();
        assert_eq!(pins["a.example"], BTreeSet::from([ip("203.0.113.5")]));
        let log = std::fs::read_to_string(d.path().join("network.jsonl")).unwrap();
        let entry: serde_json::Value = serde_json::from_str(log.lines().next().unwrap()).unwrap();
        assert_eq!(
            (
                entry["target"].as_str(),
                entry["result"].as_str(),
                entry["ip"].as_str()
            ),
            (Some("a.example:443"), Some("allowed"), Some("203.0.113.5"))
        );
    }

    #[test]
    fn refusals_get_their_status_and_an_audit_line_and_never_dial() {
        let d = tempfile::tempdir().unwrap();
        let audit = std::sync::Arc::new(Audit::new(&d.path().join("network.jsonl")));
        let p = policy(&["a.example"], vec![("a.example", vec![ip("203.0.113.5")])]);
        for (req, want) in [
            ("CONNECT b.example:443 HTTP/1.1\r\n\r\n", "403"),
            ("CONNECT 169.254.169.254:80 HTTP/1.1\r\n\r\n", "403"),
            ("GET http://a.example/ HTTP/1.1\r\n\r\n", "405"),
            ("CONNECT a.example:443 SPDY/3\r\n\r\n", "405"),
        ] {
            let mut g = proxy(p.clone(), audit.clone());
            let line = status(&mut g, req);
            assert!(
                line.starts_with(&format!("HTTP/1.1 {want}")),
                "{req:?} => {line:?}"
            );
        }
        let mut g = proxy(p.clone(), audit.clone());
        assert!(status(&mut g, &"x".repeat(MAX_HEAD + 10)).starts_with("HTTP/1.1 400"));
        let log = std::fs::read_to_string(d.path().join("network.jsonl")).unwrap();
        assert_eq!(log.lines().count(), 5);
        assert!(log.lines().all(|l| l.contains("\"refused\"")), "{log}");
        assert!(audit.pinned().is_empty());
    }

    #[test]
    fn an_unreachable_upstream_is_a_502_and_audited_as_failed() {
        let d = tempfile::tempdir().unwrap();
        let audit = Audit::new(&d.path().join("network.jsonl"));
        let p = policy(&["a.example"], vec![("a.example", vec![ip("203.0.113.5")])]);
        let (mut guest, host) = UnixStream::pair().unwrap();
        let t = std::thread::spawn(move || {
            let r = serve_one(host, &p, &audit, |_| Err(io::Error::other("unreachable")));
            (
                r,
                std::fs::read_to_string(d.path().join("network.jsonl")).unwrap(),
            )
        });
        assert!(
            status(&mut guest, "CONNECT a.example:443 HTTP/1.1\r\n\r\n")
                .starts_with("HTTP/1.1 502")
        );
        let (_, log) = t.join().unwrap();
        assert!(log.contains("\"failed\""), "{log}");
    }
}

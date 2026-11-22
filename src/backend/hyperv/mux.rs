//! Carrying guest egress connections between rts and the confined egress
//! proxy process over one pair of inherited pipes. rts keeps the hvsocket
//! listener; for each guest connection it sends OPEN and relays the bytes
//! as DATA; the proxy (no hvsocket, no profile, only outbound TCP) serves
//! each one with `egress::serve_one` and sends back DATA, CLOSE and one
//! AUDIT line per decision, which rts appends to the owner-only audit file.
//!
//! Frame: kind u8, connection id u32 BE, length u32 BE, payload (at most
//! MAX_FRAME). Pure std, so both ends are tested on any OS.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex};

use super::egress::{Audit, Policy, serve_one};
use crate::hvexec::serve::TryClone;

pub const MAX_FRAME: usize = 64 * 1024;
const OPEN: u8 = 1;
const DATA: u8 = 2;
const CLOSE: u8 = 3;
const AUDIT: u8 = 4;

type Shared<W> = Arc<Mutex<W>>;
/// Data rts sent for one connection, and what of it is not yet read.
type Inbox = Arc<Mutex<(Receiver<Vec<u8>>, Vec<u8>)>>;

fn write_frame(w: &mut dyn Write, kind: u8, id: u32, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame over the size limit",
        ));
    }
    let mut head = [0u8; 9];
    head[0] = kind;
    head[1..5].copy_from_slice(&id.to_be_bytes());
    head[5..9].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    w.write_all(&head)?;
    w.write_all(payload)?;
    w.flush()
}

fn read_frame(r: &mut dyn Read) -> io::Result<Option<(u8, u32, Vec<u8>)>> {
    let mut head = [0u8; 9];
    match r.read_exact(&mut head) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame over the size limit",
        ));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(Some((
        head[0],
        u32::from_be_bytes([head[1], head[2], head[3], head[4]]),
        payload,
    )))
}

fn send(out: &Shared<Box<dyn Write + Send>>, kind: u8, id: u32, data: &[u8]) -> io::Result<()> {
    let mut w = out.lock().unwrap_or_else(|e| e.into_inner());
    for chunk in data
        .chunks(MAX_FRAME)
        .chain(data.is_empty().then_some(&[][..]))
    {
        write_frame(&mut **w, kind, id, chunk)?;
    }
    Ok(())
}

/// One connection as the proxy sees it: reads come from rts's DATA
/// frames, writes go out as DATA frames.
struct VConn {
    id: u32,
    inbox: Inbox,
    out: Shared<Box<dyn Write + Send>>,
    closed: Arc<AtomicBool>,
}

impl Read for VConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut inbox = self.inbox.lock().unwrap_or_else(|e| e.into_inner());
        if inbox.1.is_empty() {
            match inbox.0.recv() {
                // An empty DATA payload never arrives; EOF is the sender dropping.
                Ok(data) => inbox.1 = data,
                Err(_) => return Ok(0),
            }
        }
        let n = buf.len().min(inbox.1.len());
        buf[..n].copy_from_slice(&inbox.1[..n]);
        inbox.1.drain(..n);
        Ok(n)
    }
}

impl Write for VConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        send(&self.out, DATA, self.id, buf)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TryClone for VConn {
    fn try_clone_stream(&self) -> io::Result<Self> {
        Ok(VConn {
            id: self.id,
            inbox: self.inbox.clone(),
            out: self.out.clone(),
            closed: self.closed.clone(),
        })
    }
    fn shutdown_stream(&self) -> io::Result<()> {
        if !self.closed.swap(true, Ordering::SeqCst) {
            send(&self.out, CLOSE, self.id, &[])?;
        }
        Ok(())
    }
}

/// Audit lines as AUDIT frames, one frame per complete line.
struct AuditFrames {
    out: Shared<Box<dyn Write + Send>>,
    line: Vec<u8>,
}

impl Write for AuditFrames {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.line.extend_from_slice(buf);
        while let Some(nl) = self.line.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = self.line.drain(..=nl).collect();
            send(&self.out, AUDIT, 0, &line[..line.len() - 1])?;
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The confined proxy's main loop: serve every connection rts opens,
/// until rts closes `input`.
pub fn run_proxy<D>(
    input: impl Read,
    output: Box<dyn Write + Send>,
    policy: Policy,
    dial: D,
) -> io::Result<()>
where
    D: Fn(&std::net::SocketAddr) -> io::Result<std::net::TcpStream> + Clone + Send + 'static,
{
    run_proxy_with(input, output, policy, dial, STALL_LIMIT)
}

/// Frames a connection may have queued (about 1 MiB) before the proxy
/// stops reading for it.
const QUEUE_FRAMES: usize = 16;
/// How long one connection may keep its queue full (its upstream not
/// reading) before the proxy closes that connection instead of buffering.
const STALL_LIMIT: std::time::Duration = std::time::Duration::from_secs(30);

fn run_proxy_with<D>(
    mut input: impl Read,
    output: Box<dyn Write + Send>,
    policy: Policy,
    dial: D,
    stall_limit: std::time::Duration,
) -> io::Result<()>
where
    D: Fn(&std::net::SocketAddr) -> io::Result<std::net::TcpStream> + Clone + Send + 'static,
{
    let out: Shared<Box<dyn Write + Send>> = Arc::new(Mutex::new(output));
    let audit = Arc::new(Audit::to_stream(Box::new(AuditFrames {
        out: out.clone(),
        line: vec![],
    })));
    let policy = Arc::new(policy);
    let mut conns: HashMap<u32, SyncSender<Vec<u8>>> = HashMap::new();
    while let Some((kind, id, payload)) = read_frame(&mut input)? {
        match kind {
            OPEN => {
                let (tx, rx) = sync_channel(QUEUE_FRAMES);
                conns.insert(id, tx);
                let conn = VConn {
                    id,
                    inbox: Arc::new(Mutex::new((rx, vec![]))),
                    out: out.clone(),
                    closed: Arc::new(AtomicBool::new(false)),
                };
                let (policy, audit, dial) = (policy.clone(), audit.clone(), dial.clone());
                std::thread::spawn(move || {
                    let closer = conn.try_clone_stream().ok();
                    let _ = serve_one(conn, &policy, &audit, dial);
                    if let Some(c) = closer {
                        let _ = c.shutdown_stream();
                    }
                });
            }
            DATA => {
                // Bounded: a full queue waits for its reader, up to the stall
                // limit, then that one connection is closed. Memory stays
                // bounded and a stuck upstream cannot freeze the rest for long.
                let Some(tx) = conns.get(&id) else { continue };
                let started = std::time::Instant::now();
                let mut item = payload;
                let stalled = loop {
                    match tx.try_send(item) {
                        Ok(()) => break false,
                        Err(TrySendError::Disconnected(_)) => break false,
                        Err(TrySendError::Full(back)) if started.elapsed() < stall_limit => {
                            item = back;
                            std::thread::sleep(std::time::Duration::from_millis(5));
                        }
                        Err(TrySendError::Full(_)) => break true,
                    }
                };
                if stalled {
                    conns.remove(&id);
                    let _ = send(&out, CLOSE, id, &[]);
                }
            }
            CLOSE => {
                conns.remove(&id);
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected frame from rts",
                ));
            }
        }
    }
    Ok(())
}

/// A guest connection's write half, as rts holds it.
trait GuestOut: Send {
    fn write_all(&mut self, data: &[u8]) -> io::Result<()>;
    fn close(&mut self);
}

struct Guest<S: Write + TryClone + Send>(S);

impl<S: Write + TryClone + Send> GuestOut for Guest<S> {
    fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.0.write_all(data)
    }
    fn close(&mut self) {
        let _ = self.0.shutdown_stream();
    }
}

/// rts's end: attach guest connections, relay their bytes, and record the
/// proxy's audit lines.
pub struct MuxParent {
    out: Shared<Box<dyn Write + Send>>,
    guests: Shared<HashMap<u32, Box<dyn GuestOut>>>,
    next: AtomicU32,
}

impl MuxParent {
    /// Start relaying with the proxy on `to_proxy` / `from_proxy`. When the
    /// proxy's output ends, `stopped` is set: the session's egress is lost.
    pub fn start(
        to_proxy: Box<dyn Write + Send>,
        mut from_proxy: impl Read + Send + 'static,
        audit: Arc<Audit>,
        stopped: Arc<Mutex<Option<String>>>,
    ) -> Arc<Self> {
        let me = Arc::new(MuxParent {
            out: Arc::new(Mutex::new(to_proxy)),
            guests: Arc::new(Mutex::new(HashMap::new())),
            next: AtomicU32::new(1),
        });
        let guests = me.guests.clone();
        std::thread::spawn(move || {
            let why = loop {
                match read_frame(&mut from_proxy) {
                    Ok(Some((DATA, id, data))) => {
                        let mut g = guests.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(w) = g.get_mut(&id)
                            && w.write_all(&data).is_err()
                        {
                            g.remove(&id);
                        }
                    }
                    Ok(Some((CLOSE, id, _))) => {
                        if let Some(mut w) =
                            guests.lock().unwrap_or_else(|e| e.into_inner()).remove(&id)
                        {
                            w.close();
                        }
                    }
                    Ok(Some((AUDIT, _, line))) => audit.write_line(&String::from_utf8_lossy(&line)),
                    Ok(Some(_)) => break "the egress proxy sent an unexpected frame".to_string(),
                    Ok(None) => break "the egress proxy exited".to_string(),
                    Err(e) => break format!("the egress proxy's channel failed: {e}"),
                }
            };
            *stopped.lock().unwrap_or_else(|e| e.into_inner()) =
                Some(format!("network-lost: {why}"));
            for (_, mut w) in guests.lock().unwrap_or_else(|e| e.into_inner()).drain() {
                w.close();
            }
        });
        me
    }

    /// Carry one guest connection to the proxy.
    pub fn attach<S>(self: &Arc<Self>, guest: S) -> io::Result<()>
    where
        S: Read + Write + TryClone + Send + 'static,
    {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let mut reader = guest.try_clone_stream()?;
        self.guests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, Box::new(Guest(guest)));
        send(&self.out, OPEN, id, &[])?;
        let out = self.out.clone();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; MAX_FRAME];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if send(&out, DATA, id, &buf[..n]).is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = send(&out, CLOSE, id, &[]);
        });
        Ok(())
    }
}

/// Whether the policy reaches a private (LAN) address: RFC 1918 or IPv6
/// unique-local. The confined proxy gets Windows' privateNetworkClientServer
/// capability only then; internetClient covers everything else. (rts's
/// refused ranges never reach a policy.)
pub fn needs_private_network(policy: &Policy) -> bool {
    let v: serde_json::Value = serde_json::from_str(&policy.to_json()).unwrap_or_default();
    let mut ips: Vec<std::net::IpAddr> = vec![];
    for n in v["names"].as_array().into_iter().flatten() {
        ips.extend(
            n[2].as_array()
                .into_iter()
                .flatten()
                .filter_map(|i| i.as_str()?.parse::<std::net::IpAddr>().ok()),
        );
    }
    for i in v["ips"].as_array().into_iter().flatten() {
        ips.extend(
            i[0].as_str()
                .and_then(|s| s.parse::<std::net::IpAddr>().ok()),
        );
    }
    ips.iter().any(|ip| match ip {
        std::net::IpAddr::V4(v4) => v4.is_private(),
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    })
}

/// The proxy process's main: the first stdin line is the policy (JSON),
/// then frames until rts closes stdin. Audit and data go out on stdout.
pub fn proxy_main(mut input: impl Read, output: Box<dyn Write + Send>) -> Result<(), String> {
    let mut line = vec![];
    let mut byte = [0u8; 1];
    loop {
        input
            .read_exact(&mut byte)
            .map_err(|e| format!("egress proxy: reading the policy: {e}"))?;
        if byte[0] == b'\n' {
            break;
        }
        if line.len() > 1 << 20 {
            return Err("egress proxy: policy too long".into());
        }
        line.push(byte[0]);
    }
    let policy = Policy::from_json(&String::from_utf8_lossy(&line))?;
    run_proxy(input, output, policy, super::egress::dial).map_err(|e| format!("egress proxy: {e}"))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::net::UnixStream;

    fn echo() -> std::net::SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for c in l.incoming() {
                let mut c = c.unwrap();
                std::thread::spawn(move || {
                    let mut r = c.try_clone().unwrap();
                    let _ = io::copy(&mut r, &mut c);
                });
            }
        });
        a
    }

    type Rig = (
        Arc<MuxParent>,
        Arc<Audit>,
        Arc<Mutex<Option<String>>>,
        tempfile::TempDir,
    );

    /// rts's MuxParent and a proxy loop on a thread, joined by socket pairs
    /// standing in for the inherited pipes. Every dial goes to `upstream`.
    fn rig(entries: &[&str], upstream: std::net::SocketAddr) -> Rig {
        let written: Vec<String> = entries.iter().map(|e| e.to_string()).collect();
        let plan = crate::network::plan(&written, &crate::network::SystemResolver).unwrap();
        let policy = Policy::from_json(&Policy::from_plan(&plan).to_json()).unwrap();
        let (parent_to, proxy_in) = UnixStream::pair().unwrap();
        let (proxy_out, parent_from) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            run_proxy(proxy_in, Box::new(proxy_out), policy, move |_| {
                TcpStream::connect(upstream)
            })
        });
        let d = tempfile::tempdir().unwrap();
        let audit = Arc::new(Audit::new(&d.path().join("network.jsonl")));
        let stopped = Arc::new(Mutex::new(None));
        (
            MuxParent::start(
                Box::new(parent_to),
                parent_from,
                audit.clone(),
                stopped.clone(),
            ),
            audit,
            stopped,
            d,
        )
    }

    fn guest(mux: &Arc<MuxParent>) -> UnixStream {
        let (guest, host) = UnixStream::pair().unwrap();
        mux.attach(host).unwrap();
        guest
    }

    #[test]
    fn only_a_lan_target_needs_the_private_network_capability() {
        let p = |e: &[&str]| {
            let w: Vec<String> = e.iter().map(|x| x.to_string()).collect();
            Policy::from_plan(&crate::network::plan(&w, &crate::network::SystemResolver).unwrap())
        };
        assert!(!needs_private_network(&p(&["198.51.100.7:443"])));
        assert!(!needs_private_network(&p(&[])));
        for lan in [
            "192.168.1.20:8080",
            "10.0.0.5:443",
            "172.16.9.1:8443",
            "[fd00::5]:443",
        ] {
            assert!(
                needs_private_network(&p(&["198.51.100.7:443", lan])),
                "{lan}"
            );
        }
    }

    #[test]
    fn frames_round_trip_and_oversized_or_truncated_ones_fail() {
        let mut buf = vec![];
        write_frame(&mut buf, DATA, 7, b"hi").unwrap();
        assert_eq!(
            read_frame(&mut &buf[..]).unwrap(),
            Some((DATA, 7, b"hi".to_vec()))
        );
        assert_eq!(read_frame(&mut &[][..]).unwrap(), None);
        assert!(read_frame(&mut &buf[..10]).is_err());
        assert!(write_frame(&mut buf, DATA, 1, &vec![0; MAX_FRAME + 1]).is_err());
    }

    #[test]
    fn an_allowed_connect_is_carried_both_ways_and_audited_by_rts() {
        let (mux, _audit, stopped, d) = rig(&["198.51.100.7:443"], echo());
        let mut g = guest(&mux);
        g.write_all(b"CONNECT 198.51.100.7:443 HTTP/1.1\r\n\r\n")
            .unwrap();
        let mut r = BufReader::new(g.try_clone().unwrap());
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        assert_eq!(line, "HTTP/1.1 200 Connection established\r\n");
        r.read_line(&mut line).unwrap();
        let big = vec![b'x'; 200_000];
        let mut w = g.try_clone().unwrap();
        let writer = std::thread::spawn(move || {
            w.write_all(&big).unwrap();
            w.write_all(b"\n").unwrap();
        });
        let mut echoed = String::new();
        r.read_line(&mut echoed).unwrap();
        writer.join().unwrap();
        assert_eq!(
            echoed.len(),
            200_001,
            "a stream larger than one frame survives the relay"
        );
        let log = std::fs::read_to_string(d.path().join("network.jsonl")).unwrap();
        assert!(
            log.contains("\"allowed\"") && log.contains("198.51.100.7:443"),
            "{log}"
        );
        assert_eq!(*stopped.lock().unwrap(), None);
    }

    #[test]
    fn refusals_reach_the_guest_and_every_connection_is_separate() {
        let (mux, _audit, _stopped, d) = rig(&["198.51.100.7:443"], echo());
        let mut a = guest(&mux);
        let mut b = guest(&mux);
        a.write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .unwrap();
        b.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        let first = |s: &UnixStream| {
            let mut l = String::new();
            BufReader::new(s.try_clone().unwrap())
                .read_line(&mut l)
                .unwrap();
            l
        };
        assert!(first(&a).starts_with("HTTP/1.1 403"));
        assert!(first(&b).starts_with("HTTP/1.1 405"));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let log = loop {
            let l = std::fs::read_to_string(d.path().join("network.jsonl")).unwrap_or_default();
            if l.lines().count() >= 2 || std::time::Instant::now() > deadline {
                break l;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        assert_eq!(
            log.lines().filter(|l| l.contains("\"refused\"")).count(),
            2,
            "{log}"
        );
    }

    #[test]
    fn an_upstream_that_stops_reading_gets_its_connection_closed_not_buffered() {
        // An upstream that accepts and never reads.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream = l.local_addr().unwrap();
        let held = std::thread::spawn(move || l.accept().map(|(s, _)| s));
        let plan = crate::network::plan(
            &["198.51.100.7:443".to_string()],
            &crate::network::SystemResolver,
        )
        .unwrap();
        let policy = Policy::from_plan(&plan);
        let (parent_to, proxy_in) = UnixStream::pair().unwrap();
        let (proxy_out, parent_from) = UnixStream::pair().unwrap();
        let stall = std::time::Duration::from_millis(300);
        std::thread::spawn(move || {
            run_proxy_with(
                proxy_in,
                Box::new(proxy_out),
                policy,
                move |_| TcpStream::connect(upstream),
                stall,
            )
        });
        let d = tempfile::tempdir().unwrap();
        let stopped = Arc::new(Mutex::new(None));
        let mux = MuxParent::start(
            Box::new(parent_to),
            parent_from,
            Arc::new(Audit::new(&d.path().join("a"))),
            stopped.clone(),
        );
        let mut g = guest(&mux);
        g.write_all(b"CONNECT 198.51.100.7:443 HTTP/1.1\r\n\r\n")
            .unwrap();
        let mut r = BufReader::new(g.try_clone().unwrap());
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        assert!(line.starts_with("HTTP/1.1 200"), "{line}");
        let _upstream_conn = held.join().unwrap().unwrap();
        // Far more than the queue and the kernel buffers hold.
        let mut w = g.try_clone().unwrap();
        std::thread::spawn(move || {
            let chunk = vec![0u8; 64 * 1024];
            for _ in 0..2048 {
                if w.write_all(&chunk).is_err() {
                    break;
                }
            }
        });
        // The proxy closes the connection: the guest reads to EOF.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut rest = vec![];
            let _ = r.read_to_end(&mut rest);
            let _ = tx.send(());
        });
        rx.recv_timeout(std::time::Duration::from_secs(20))
            .expect("the stalled connection was never closed");
        assert_eq!(
            *stopped.lock().unwrap(),
            None,
            "only that connection ends, not the proxy"
        );
    }

    #[test]
    fn the_proxy_exiting_is_network_lost_and_closes_its_guests() {
        let (parent_to, proxy_in) = UnixStream::pair().unwrap();
        let (proxy_out, parent_from) = UnixStream::pair().unwrap();
        let d = tempfile::tempdir().unwrap();
        let stopped = Arc::new(Mutex::new(None));
        let mux = MuxParent::start(
            Box::new(parent_to),
            parent_from,
            Arc::new(Audit::new(&d.path().join("a"))),
            stopped.clone(),
        );
        let mut g = guest(&mux);
        drop((proxy_in, proxy_out));
        let mut rest = vec![];
        g.read_to_end(&mut rest).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while stopped.lock().unwrap().is_none() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            stopped
                .lock()
                .unwrap()
                .as_deref()
                .unwrap_or("")
                .contains("network-lost")
        );
    }
}

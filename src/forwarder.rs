//! Loopback forwarder between embedded IronWire and NEAR AI.
//!
//! IronWire's NEAR AI endpoint is this forwarder. It forwards only
//! `POST /v1/chat/completions` for allowlisted models, byte for byte, to
//! NEAR AI over TLS pinned to the attested certificate fingerprints
//! (`pin.rs`). A pin failure or a refused model raises `Fatal`, after which
//! nothing reaches upstream and the session loop ends the session.

pub mod pin;

use std::collections::BTreeSet;
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::mpsc;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::thread::JoinHandle;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::{Frame, Incoming};
use hyper::header::{ACCEPT, ACCEPT_ENCODING, AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::de::{IgnoredAny, MapAccess, Visitor};
use tokio::sync::oneshot;

use crate::attest::Attested;
use crate::attest::record::AttestationRecord;
use pin::{PinSet, Rejected};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const RUNTIME_STOP_TIMEOUT: Duration = Duration::from_secs(1);
const WORKER_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const REATTEST_ATTEMPTS: usize = 3;

/// The first fatal reason; set once, read by the session loop.
pub struct Fatal {
    reason: OnceLock<String>,
}

impl std::fmt::Debug for Fatal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fatal")
            .field("reason", &self.reason.get())
            .finish()
    }
}

impl Fatal {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            reason: OnceLock::new(),
        })
    }

    /// Keeps the first reason; later ones are dropped. True when this call
    /// set it.
    pub fn raise(&self, reason: impl Into<String>) -> bool {
        self.reason.set(reason.into()).is_ok()
    }

    pub fn reason(&self) -> Option<String> {
        self.reason.get().cloned()
    }
}

/// Re-attests NEAR AI. Blocking (`BlockingHttp`): the forwarder calls it with
/// `tokio::task::spawn_blocking`.
pub type Reattest = Arc<dyn Fn() -> Result<Attested, String> + Send + Sync>;

/// Holds `reattest`, which captures the API key, so it has no `Debug`.
pub struct ForwarderConfig {
    /// "https://cloud-api.near.ai/v1"; tests use https://127.0.0.1:<port>/v1
    pub upstream: String,
    pub models: Vec<String>,
    pub roots: Arc<rustls::RootCertStore>,
    pub seed: Attested,
    /// Called with tokio::task::spawn_blocking.
    pub reattest: Reattest,
    pub fatal: Arc<Fatal>,
    pub record: Arc<AttestationRecord>,
    /// 32 MiB in production.
    pub max_request_bytes: usize,
}

/// Owns the loopback listener and its runtime thread, as `EmbeddedInference`.
pub struct Forwarder {
    port: u16,
    shutdown: Option<oneshot::Sender<()>>,
    finished: mpsc::Receiver<()>,
    worker: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for Forwarder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Forwarder")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

struct State {
    completions: String,
    models: BTreeSet<String>,
    client: reqwest::Client,
    pins: Arc<PinSet>,
    reattest: Reattest,
    reattesting: tokio::sync::Mutex<()>,
    fatal: Arc<Fatal>,
    record: Arc<AttestationRecord>,
    max_request_bytes: usize,
}

type Out = Response<BoxBody<Bytes, BoxError>>;
type BoxError = Box<dyn std::error::Error + Send + Sync>;

impl Forwarder {
    pub fn start(cfg: ForwarderConfig) -> Result<Forwarder, String> {
        if cfg.seed.fingerprints.is_empty() {
            return Err("forwarder: no attested certificate fingerprints to pin".into());
        }
        if cfg.models.is_empty() {
            return Err("forwarder: no allowed models".into());
        }
        let upstream = cfg.upstream.trim_end_matches('/');
        if !upstream.starts_with("https://") {
            return Err("forwarder: upstream must be https".into());
        }
        let pins = PinSet::new(cfg.seed.fingerprints.clone());
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(pin::pinned_tls(cfg.roots, pins.clone())?)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .http1_only()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(|e| format!("forwarder: upstream client: {e}"))?;
        let state = Arc::new(State {
            completions: format!("{upstream}/chat/completions"),
            models: cfg.models.into_iter().collect(),
            client,
            pins,
            reattest: cfg.reattest,
            reattesting: tokio::sync::Mutex::new(()),
            fatal: cfg.fatal,
            record: cfg.record,
            max_request_bytes: cfg.max_request_bytes,
        });
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
            .map_err(|e| format!("forwarder: cannot bind 127.0.0.1: {e}"))?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("forwarder: {e}"))?
            .port();
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("forwarder: {e}"))?;
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (done_tx, finished) = mpsc::sync_channel(1);
        let (shutdown, shutdown_rx) = oneshot::channel();
        let worker = std::thread::Builder::new()
            .name("rts-forwarder".into())
            .spawn(move || {
                run_worker(listener, state, ready_tx, shutdown_rx);
                let _ = done_tx.send(());
            })
            .map_err(|_| "forwarder: cannot start worker thread")?;
        match ready_rx.recv_timeout(STARTUP_TIMEOUT) {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err("forwarder: startup did not complete".into()),
        }
        Ok(Forwarder {
            port,
            shutdown: Some(shutdown),
            finished,
            worker: Some(worker),
        })
    }

    /// "http://127.0.0.1:<port>/v1"
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}/v1", self.port)
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if self.finished.recv_timeout(WORKER_STOP_TIMEOUT).is_ok()
            && let Some(worker) = self.worker.take()
        {
            let _ = worker.join();
        }
    }
}

fn run_worker(
    listener: std::net::TcpListener,
    state: Arc<State>,
    ready: mpsc::SyncSender<Result<(), String>>,
    shutdown: oneshot::Receiver<()>,
) {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            let _ = ready.send(Err("forwarder: cannot initialize runtime".into()));
            return;
        }
    };
    runtime.block_on(async {
        let listener = match tokio::net::TcpListener::from_std(listener) {
            Ok(listener) => listener,
            Err(e) => {
                let _ = ready.send(Err(format!("forwarder: listener: {e}")));
                return;
            }
        };
        let accept = tokio::spawn(accept_loop(listener, state));
        if ready.send(Ok(())).is_ok() {
            let _ = shutdown.await;
        }
        accept.abort();
    });
    runtime.shutdown_timeout(RUNTIME_STOP_TIMEOUT);
}

async fn accept_loop(listener: tokio::net::TcpListener, state: Arc<State>) {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |req| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(handle(&state, req).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

fn local(status: StatusCode, message: &'static str) -> Out {
    let mut resp = Response::new(
        Full::new(Bytes::from_static(message.as_bytes()))
            .map_err(|never| match never {})
            .boxed(),
    );
    *resp.status_mut() = status;
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    resp
}

/// Raises fatal and, only if this is the first fatal, writes the matching
/// terminal status, so attestation.json and the stop reason agree.
fn stop(fatal: &Fatal, record: &AttestationRecord, status: &str, reason: &str) -> bool {
    let first = fatal.raise(format!("{status}: {reason}"));
    if first {
        record.set_status(status, reason);
    }
    first
}

/// Method and path only: never headers, query or body.
fn not_forwarded_line(method: &Method, path: &str) -> String {
    format!("[rts forwarder] 404 {method} {path}: not forwarded")
}

fn stopped_reply() -> Out {
    local(
        StatusCode::BAD_GATEWAY,
        "rts forwarder: inference stopped; see attestation.json",
    )
}

fn fatal_reply(state: &State, status: &str, reason: String) -> Out {
    stop(&state.fatal, &state.record, status, &reason);
    stopped_reply()
}

async fn handle(state: &State, req: Request<Incoming>) -> Out {
    // Fatal is checked here, again once the body has arrived, before every
    // upstream send, and inside `learn`: it can be raised at any point.
    if state.fatal.reason().is_some() {
        return stopped_reply();
    }
    if req.method() != Method::POST || req.uri().path() != "/v1/chat/completions" {
        eprintln!("{}", not_forwarded_line(req.method(), req.uri().path()));
        return local(StatusCode::NOT_FOUND, "rts forwarder: not forwarded");
    }
    let mut headers = reqwest::header::HeaderMap::new();
    for name in [AUTHORIZATION, CONTENT_TYPE, ACCEPT] {
        for value in req.headers().get_all(&name) {
            headers.append(name.clone(), value.clone());
        }
    }
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    let body = match Limited::new(req.into_body(), state.max_request_bytes)
        .collect()
        .await
    {
        Ok(body) => body.to_bytes(),
        Err(e) if e.downcast_ref::<LengthLimitError>().is_some() => {
            return local(
                StatusCode::PAYLOAD_TOO_LARGE,
                "rts forwarder: request too large",
            );
        }
        Err(_) => return local(StatusCode::BAD_REQUEST, "rts forwarder: unreadable request"),
    };
    if state.fatal.reason().is_some() {
        return stopped_reply();
    }
    let Some(model) = request_model(&body) else {
        return local(
            StatusCode::BAD_REQUEST,
            "rts forwarder: body must be a JSON object with one string \"model\"",
        );
    };
    if !state.models.contains(&model) {
        let shown: String = model.chars().take(128).collect();
        stop(
            &state.fatal,
            &state.record,
            "model-refused",
            &format!("model {shown:?} is not in the allowlist"),
        );
        return local(
            StatusCode::FORBIDDEN,
            "rts forwarder: model is not in the allowlist",
        );
    }
    // The exact bytes received, never a re-serialization.
    let send = || {
        state
            .client
            .post(&state.completions)
            .headers(headers.clone())
            .body(body.clone())
            .send()
    };
    if state.fatal.reason().is_some() {
        return stopped_reply();
    }
    let resp = match send().await {
        Ok(resp) => resp,
        Err(_) => match state.pins.take_rejected() {
            None => {
                return local(
                    StatusCode::BAD_GATEWAY,
                    "rts forwarder: upstream request failed",
                );
            }
            Some(Rejected::Untrusted(fp)) => {
                return fatal_reply(
                    state,
                    "pin-failed",
                    format!(
                        "pin: upstream certificate {} does not chain to a trusted root",
                        hex::encode(fp)
                    ),
                );
            }
            Some(Rejected::Unpinned(fp)) => {
                match learn(state, fp).await {
                    Ok(()) => {}
                    Err(Unlearned::Stopped) => return stopped_reply(),
                    Err(Unlearned::Failed(reason)) => {
                        return fatal_reply(state, "pin-failed", reason);
                    }
                }
                if state.fatal.reason().is_some() {
                    return stopped_reply();
                }
                match send().await {
                    Ok(resp) => resp,
                    Err(_) => {
                        if let Some(r) = state.pins.take_rejected() {
                            let fp = match r {
                                Rejected::Unpinned(fp) | Rejected::Untrusted(fp) => fp,
                            };
                            return fatal_reply(
                                state,
                                "pin-failed",
                                format!(
                                    "pin: upstream certificate {} refused after re-attestation",
                                    hex::encode(fp)
                                ),
                            );
                        }
                        return local(
                            StatusCode::BAD_GATEWAY,
                            "rts forwarder: upstream request failed",
                        );
                    }
                }
            }
        },
    };
    relay(resp)
}

enum Unlearned {
    /// Fatal was raised meanwhile (possibly by another request's `learn`).
    Stopped,
    Failed(String),
}

/// Re-attests (on the blocking pool, one at a time) until `fp` is attested,
/// recording each re-attestation. Stops as soon as fatal is raised: after
/// taking the lock, before each attempt, and before recording a result.
async fn learn(state: &State, fp: [u8; 32]) -> Result<(), Unlearned> {
    let stopped = || state.fatal.reason().is_some();
    let _one_at_a_time = state.reattesting.lock().await;
    for _ in 0..REATTEST_ATTEMPTS {
        if stopped() {
            return Err(Unlearned::Stopped);
        }
        if state.pins.contains(&fp) {
            return Ok(());
        }
        let reattest = state.reattest.clone();
        let attested = tokio::task::spawn_blocking(move || reattest())
            .await
            .map_err(|_| Unlearned::Failed("pin: re-attestation did not complete".into()))?
            .map_err(|e| Unlearned::Failed(format!("pin: re-attestation failed: {e}")))?;
        if stopped() {
            return Err(Unlearned::Stopped);
        }
        state
            .record
            .reattested(&attested)
            .map_err(|e| Unlearned::Failed(format!("pin: cannot record re-attestation: {e}")))?;
        state.pins.extend(&attested.fingerprints);
    }
    if stopped() {
        return Err(Unlearned::Stopped);
    }
    if state.pins.contains(&fp) {
        return Ok(());
    }
    Err(Unlearned::Failed(format!(
        "pin: upstream certificate {} is not attested after {REATTEST_ATTEMPTS} re-attestations",
        hex::encode(fp)
    )))
}

/// Status, Content-Type and the body as it arrives.
fn relay(mut upstream: reqwest::Response) -> Out {
    let status = upstream.status();
    let content_type = upstream.headers().get(CONTENT_TYPE).cloned();
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    tokio::spawn(async move {
        loop {
            match upstream.chunk().await {
                Ok(Some(chunk)) => {
                    if tx.send(Ok(chunk)).await.is_err() {
                        return;
                    }
                }
                Ok(None) => return,
                Err(_) => {
                    let _ = tx.send(Err("upstream stream failed".into())).await;
                    return;
                }
            }
        }
    });
    let mut resp = Response::new(Relay { rx }.boxed());
    *resp.status_mut() = status;
    if let Some(content_type) = content_type {
        resp.headers_mut().insert(CONTENT_TYPE, content_type);
    }
    resp
}

struct Relay {
    rx: tokio::sync::mpsc::Receiver<Result<Bytes, BoxError>>,
}

impl hyper::body::Body for Relay {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.rx
            .poll_recv(cx)
            .map(|chunk| chunk.map(|chunk| chunk.map(Frame::data)))
    }
}

/// The top-level string "model" of a JSON object. A second "model" key is
/// refused: parsers disagree on which one wins.
fn request_model(body: &[u8]) -> Option<String> {
    struct Model(Option<String>);
    impl<'de> serde::Deserialize<'de> for Model {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            d.deserialize_map(ModelVisitor)
        }
    }
    struct ModelVisitor;
    impl<'de> Visitor<'de> for ModelVisitor {
        type Value = Model;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a JSON object")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Model, A::Error> {
            let mut model = None;
            while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
                if key == "model" {
                    if model.is_some() {
                        return Err(serde::de::Error::duplicate_field("model"));
                    }
                    model = Some(map.next_value::<String>()?);
                } else {
                    map.next_value::<IgnoredAny>()?;
                }
            }
            Ok(Model(model))
        }
    }
    serde_json::from_slice::<Model>(body).ok()?.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::record::AttestationRecord;
    use crate::attest::{AttestOptions, Attested};
    use rustls::HandshakeKind;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::collections::BTreeSet;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    const DUMMY_KEY: &str = "rts-dummy-key-never-send-to-a-provider";
    const BODY: &[u8] = br#"{"model":"m","messages":[],"stream":false}"#;
    const REPLY: &[u8] = br#"{"id":"x","object":"chat.completion","choices":[]}"#;

    fn pem(name: &str) -> &'static [u8] {
        match name {
            "ca" => include_bytes!("../tests/fixtures/tls/ca.pem"),
            "a" => include_bytes!("../tests/fixtures/tls/a.pem"),
            "b" => include_bytes!("../tests/fixtures/tls/b.pem"),
            "c" => include_bytes!("../tests/fixtures/tls/c.pem"),
            "a.key" => include_bytes!("../tests/fixtures/tls/a.key"),
            "b.key" => include_bytes!("../tests/fixtures/tls/b.key"),
            "c.key" => include_bytes!("../tests/fixtures/tls/c.key"),
            _ => unreachable!(),
        }
    }

    fn cert(name: &str) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(pem(name)).unwrap()
    }

    fn fp(name: &str) -> [u8; 32] {
        pin::sha256_der(cert(name).as_ref())
    }

    fn fps(names: &[&str]) -> BTreeSet<[u8; 32]> {
        names.iter().map(|n| fp(n)).collect()
    }

    fn roots() -> Arc<rustls::RootCertStore> {
        let mut store = rustls::RootCertStore::empty();
        store.add(cert("ca")).unwrap();
        Arc::new(store)
    }

    fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// One recorded upstream request: the head (request line and headers,
    /// as sent) and the exact body bytes.
    #[derive(Clone)]
    struct Seen {
        head: String,
        body: Vec<u8>,
    }

    /// A blocking TLS upstream on 127.0.0.1. `certs(i)` names the
    /// certificate presented on the i-th accepted connection. Every accepted
    /// connection is recorded, with None when its handshake failed.
    struct Upstream {
        port: u16,
        handshakes: Arc<Mutex<Vec<Option<HandshakeKind>>>>,
        requests: Arc<Mutex<Vec<Seen>>>,
    }

    impl Upstream {
        fn url(&self) -> String {
            format!("https://127.0.0.1:{}/v1", self.port)
        }
        fn handshakes(&self) -> Vec<Option<HandshakeKind>> {
            self.handshakes.lock().unwrap().clone()
        }
        fn requests(&self) -> Vec<Seen> {
            self.requests.lock().unwrap().clone()
        }
    }

    fn server_config(name: &'static str) -> Arc<rustls::ServerConfig> {
        let key = PrivateKeyDer::from_pem_slice(pem(&format!("{name}.key"))).unwrap();
        Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert(name)], key)
            .unwrap(),
        )
    }

    fn upstream(
        certs: impl Fn(usize) -> &'static str + Send + 'static,
        close_each: bool,
        reply: impl Fn(&Seen) -> (u16, Vec<u8>) + Send + Sync + 'static,
    ) -> Upstream {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let handshakes = Arc::new(Mutex::new(Vec::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (h, r) = (handshakes.clone(), requests.clone());
        let reply = Arc::new(reply);
        // One ServerConfig per certificate, shared across connections, so a
        // client that offered resumption would get it.
        std::thread::spawn(move || {
            let mut configs: Vec<(&'static str, Arc<rustls::ServerConfig>)> = Vec::new();
            for (i, tcp) in listener.incoming().enumerate() {
                let Ok(tcp) = tcp else { continue };
                let name = certs(i);
                let config = match configs.iter().find(|(n, _)| *n == name) {
                    Some((_, cfg)) => cfg.clone(),
                    None => {
                        let cfg = server_config(name);
                        configs.push((name, cfg.clone()));
                        cfg
                    }
                };
                let (h, r, reply) = (h.clone(), r.clone(), reply.clone());
                std::thread::spawn(move || serve(tcp, config, close_each, &h, &r, &*reply));
            }
        });
        Upstream {
            port,
            handshakes,
            requests,
        }
    }

    fn serve(
        mut tcp: std::net::TcpStream,
        config: Arc<rustls::ServerConfig>,
        close_each: bool,
        handshakes: &Mutex<Vec<Option<HandshakeKind>>>,
        requests: &Mutex<Vec<Seen>>,
        reply: &(dyn Fn(&Seen) -> (u16, Vec<u8>) + Send + Sync),
    ) {
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut conn = rustls::ServerConnection::new(config).unwrap();
        while conn.is_handshaking() {
            if conn.complete_io(&mut tcp).is_err() {
                handshakes.lock().unwrap().push(None);
                return;
            }
        }
        handshakes.lock().unwrap().push(conn.handshake_kind());
        let mut tls = rustls::StreamOwned::new(conn, tcp);
        loop {
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                match tls.read(&mut byte) {
                    Ok(1) => head.push(byte[0]),
                    _ => return,
                }
            }
            let head = String::from_utf8(head).unwrap();
            let length: usize = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap_or(0);
            let mut body = vec![0; length];
            if tls.read_exact(&mut body).is_err() {
                return;
            }
            let seen = Seen { head, body };
            requests.lock().unwrap().push(seen.clone());
            let (status, out) = reply(&seen);
            let close = if close_each {
                "Connection: close\r\n"
            } else {
                ""
            };
            let _ = write!(
                tls,
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{close}\r\n",
                out.len()
            );
            let _ = tls.write_all(&out);
            let _ = tls.flush();
            if close_each {
                tls.conn.send_close_notify();
                let _ = tls.flush();
                return;
            }
        }
    }

    fn ok_reply(_: &Seen) -> (u16, Vec<u8>) {
        (200, REPLY.to_vec())
    }

    /// Counts calls and returns `answer`. Starting a runtime panics on a
    /// Tokio worker thread, exactly as `BlockingHttp` does, so this also
    /// proves `reattest` runs on the blocking pool.
    fn reattest(answer: &[&str], calls: &Arc<AtomicUsize>) -> Reattest {
        let answer = fps(answer);
        let calls = calls.clone();
        Arc::new(move || {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(async {});
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Attested {
                fingerprints: answer.clone(),
                ..Attested::default()
            })
        })
    }

    struct Rig {
        forwarder: Forwarder,
        fatal: Arc<Fatal>,
        record: Arc<AttestationRecord>,
        dir: std::path::PathBuf,
    }

    impl Rig {
        fn doc(&self) -> serde_json::Value {
            serde_json::from_slice(&std::fs::read(self.record.path()).unwrap()).unwrap()
        }
        fn post(&self, body: &[u8]) -> (u16, Vec<u8>) {
            send(&self.forwarder, "POST", "/v1/chat/completions", body)
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn rig(up: &Upstream, seed: &[&str], reattest: Reattest, max: usize) -> Rig {
        let dir = crate::testutil::tempdir("forwarder");
        let record =
            AttestationRecord::create(&dir, "0123456789ab", &AttestOptions::default()).unwrap();
        let seed = Attested {
            fingerprints: fps(seed),
            ..Attested::default()
        };
        record.verified(&seed).unwrap();
        let fatal = Fatal::new();
        let forwarder = Forwarder::start(ForwarderConfig {
            upstream: up.url(),
            models: vec!["m".into()],
            roots: roots(),
            seed,
            reattest,
            fatal: fatal.clone(),
            record: record.clone(),
            max_request_bytes: max,
        })
        .unwrap();
        Rig {
            forwarder,
            fatal,
            record,
            dir,
        }
    }

    fn send(f: &Forwarder, method: &str, path: &str, body: &[u8]) -> (u16, Vec<u8>) {
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(20))
            .build()
            .unwrap();
        let url = format!("{}{}", f.base_url().trim_end_matches("/v1"), path);
        let resp = client
            .request(method.parse().unwrap(), url)
            .bearer_auth(DUMMY_KEY)
            .header("content-type", "application/json")
            .body(body.to_vec())
            .send()
            .unwrap();
        let status = resp.status().as_u16();
        (status, resp.bytes().unwrap().to_vec())
    }

    fn no_key_in(rig: &Rig) {
        let text = std::fs::read_to_string(rig.record.path()).unwrap();
        assert!(!text.contains(DUMMY_KEY));
        assert!(!rig.fatal.reason().unwrap_or_default().contains(DUMMY_KEY));
        assert!(!format!("{:?}", rig.forwarder).contains(DUMMY_KEY));
    }

    #[test]
    fn a_pinned_upstream_gets_the_exact_bytes_and_the_key() {
        let up = upstream(|_| "a", false, ok_reply);
        let calls = Arc::new(AtomicUsize::new(0));
        let rig = rig(&up, &["a"], reattest(&["a"], &calls), 1 << 20);
        assert_eq!(
            rig.forwarder.base_url(),
            format!("http://127.0.0.1:{}/v1", rig.forwarder.port)
        );
        let (status, body) = rig.post(BODY);
        assert_eq!(status, 200);
        assert_eq!(body, REPLY);
        let seen = up.requests();
        assert_eq!(seen.len(), 1);
        let head = seen[0].head.to_ascii_lowercase();
        assert!(
            seen[0]
                .head
                .starts_with("POST /v1/chat/completions HTTP/1.1\r\n")
        );
        assert!(
            head.lines()
                .any(|l| l == format!("authorization: bearer {}", DUMMY_KEY.to_ascii_lowercase())),
            "{head}"
        );
        assert!(
            head.lines().any(|l| l == "accept-encoding: identity"),
            "{head}"
        );
        assert!(
            head.lines().any(|l| l == "content-type: application/json"),
            "{head}"
        );
        assert_eq!(seen[0].body, BODY);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(rig.fatal.reason(), None);
        assert_eq!(rig.doc()["status"], "verified");
        no_key_in(&rig);
    }

    #[test]
    fn only_the_three_inbound_headers_are_forwarded() {
        let up = upstream(|_| "a", false, ok_reply);
        let calls = Arc::new(AtomicUsize::new(0));
        let rig = rig(&up, &["a"], reattest(&["a"], &calls), 1 << 20);
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .build()
            .unwrap();
        let resp = client
            .post(format!("{}/chat/completions", rig.forwarder.base_url()))
            .bearer_auth(DUMMY_KEY)
            .header("content-type", "application/json")
            .header("accept", "text/event-stream")
            .header("x-ironwire-route", "nearai:m")
            .header("cookie", "c=1")
            .header("accept-encoding", "gzip")
            .body(BODY.to_vec())
            .send()
            .unwrap();
        assert_eq!(resp.status(), 200);
        let head = up.requests()[0].head.to_ascii_lowercase();
        let names: BTreeSet<&str> = head
            .lines()
            .skip(1)
            .filter_map(|l| l.split_once(':').map(|(n, _)| n))
            .collect();
        assert_eq!(
            names,
            BTreeSet::from([
                "accept",
                "accept-encoding",
                "authorization",
                "content-length",
                "content-type",
                "host"
            ]),
            "{head}"
        );
        assert!(head.lines().any(|l| l == "accept: text/event-stream"));
        assert!(head.lines().any(|l| l == "accept-encoding: identity"));
    }

    #[test]
    fn an_unpinned_certificate_never_sees_a_request_and_ends_the_session() {
        let up = upstream(|_| "b", false, ok_reply);
        let calls = Arc::new(AtomicUsize::new(0));
        let rig = rig(&up, &["a"], reattest(&["a"], &calls), 1 << 20);
        let (status, _) = rig.post(BODY);
        assert_eq!(status, 502);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert!(up.requests().is_empty());
        let reason = rig.fatal.reason().expect("fatal");
        assert!(reason.contains("pin"), "{reason}");
        assert!(reason.contains(&hex::encode(fp("b"))), "{reason}");
        let doc = rig.doc();
        assert_eq!(doc["status"], "pin-failed");
        assert_eq!(doc["reattestations"].as_array().unwrap().len(), 3);
        wait_for("the rejected handshake", || up.handshakes().len() == 1);
        assert_eq!(up.handshakes(), vec![None]);
        let (status, _) = rig.post(BODY);
        assert_eq!(status, 502);
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(up.handshakes().len(), 1, "no new handshake after fatal");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "no new reattest after fatal"
        );
        no_key_in(&rig);
    }

    #[test]
    fn a_rotated_certificate_is_accepted_after_one_reattestation() {
        let up = upstream(|_| "b", false, ok_reply);
        let calls = Arc::new(AtomicUsize::new(0));
        let rig = rig(&up, &["a"], reattest(&["b"], &calls), 1 << 20);
        let (status, body) = rig.post(BODY);
        assert_eq!(status, 200);
        assert_eq!(body, REPLY);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(up.requests().len(), 1);
        assert_eq!(up.requests()[0].body, BODY);
        let doc = rig.doc();
        assert_eq!(doc["status"], "verified");
        let re = doc["reattestations"].as_array().unwrap();
        assert_eq!(re.len(), 1);
        assert_eq!(re[0]["fingerprints"][0], hex::encode(fp("b")));
        assert_eq!(rig.fatal.reason(), None);
    }

    #[test]
    fn a_pinned_certificate_from_an_untrusted_ca_is_refused() {
        let up = upstream(|_| "c", false, ok_reply);
        let calls = Arc::new(AtomicUsize::new(0));
        let rig = rig(&up, &["c"], reattest(&["c"], &calls), 1 << 20);
        let (status, _) = rig.post(BODY);
        assert_eq!(status, 502);
        assert!(up.requests().is_empty());
        let reason = rig.fatal.reason().expect("fatal");
        assert!(reason.contains("pin"), "{reason}");
        assert_eq!(rig.doc()["status"], "pin-failed");
        // Re-attestation cannot make a certificate chain to a trusted root.
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn every_upstream_handshake_is_full() {
        let up = upstream(|_| "a", true, ok_reply);
        let calls = Arc::new(AtomicUsize::new(0));
        let rig = rig(&up, &["a"], reattest(&["a"], &calls), 1 << 20);
        assert_eq!(rig.post(BODY).0, 200);
        assert_eq!(rig.post(BODY).0, 200);
        wait_for("two handshakes", || up.handshakes().len() == 2);
        assert_eq!(
            up.handshakes(),
            vec![Some(HandshakeKind::Full), Some(HandshakeKind::Full)]
        );
    }

    /// Regression for the 2026-10-28 bun measurement: a pin checked per
    /// request can be skipped by a pooled connection. The pin lives in the
    /// TLS verifier, so every new connection is checked, including a second
    /// one made after the first was closed.
    #[test]
    fn a_second_connection_to_a_different_certificate_fails_the_pin() {
        let up = upstream(|i| if i == 0 { "a" } else { "b" }, true, ok_reply);
        let calls = Arc::new(AtomicUsize::new(0));
        let rig = rig(&up, &["a"], reattest(&["a"], &calls), 1 << 20);
        assert_eq!(rig.post(BODY).0, 200);
        assert_eq!(rig.post(BODY).0, 502);
        assert_eq!(
            up.requests().len(),
            1,
            "the unpinned connection saw a request"
        );
        assert!(rig.fatal.reason().unwrap().contains("pin"));
        assert_eq!(rig.doc()["status"], "pin-failed");
        wait_for("both connections", || up.handshakes().len() >= 2);
        assert_eq!(up.handshakes()[0], Some(HandshakeKind::Full));
        assert!(up.handshakes()[1..].iter().all(Option::is_none));
    }

    #[test]
    fn a_model_outside_the_allowlist_gets_403_and_no_connection() {
        let up = upstream(|_| "a", false, ok_reply);
        let calls = Arc::new(AtomicUsize::new(0));
        let rig = rig(&up, &["a"], reattest(&["a"], &calls), 1 << 20);
        let (status, _) = rig.post(br#"{"model":"other","messages":[]}"#);
        assert_eq!(status, 403);
        let reason = rig.fatal.reason().expect("fatal");
        assert!(reason.contains("model-refused"), "{reason}");
        assert_eq!(rig.doc()["status"], "model-refused");
        // A duplicate key is a parser differential: refused, never forwarded.
        let (status, _) = rig.post(br#"{"model":"m","model":"other"}"#);
        assert_eq!(status, 502, "fatal already raised");
        std::thread::sleep(Duration::from_millis(200));
        assert!(up.handshakes().is_empty());
        assert!(up.requests().is_empty());
    }

    #[test]
    fn only_chat_completions_is_forwarded() {
        let up = upstream(|_| "a", false, ok_reply);
        let calls = Arc::new(AtomicUsize::new(0));
        let rig = rig(&up, &["a"], reattest(&["a"], &calls), 1 << 20);
        for (method, path) in [
            ("GET", "/v1/models"),
            ("POST", "/v1/responses"),
            ("GET", "/v1/signature/x"),
            ("GET", "/v1/chat/completions"),
            ("POST", "/v1/chat/completions/x"),
            ("POST", "/chat/completions"),
        ] {
            assert_eq!(
                send(&rig.forwarder, method, path, BODY).0,
                404,
                "{method} {path}"
            );
        }
        std::thread::sleep(Duration::from_millis(200));
        assert!(up.handshakes().is_empty());
        assert_eq!(rig.fatal.reason(), None);
    }

    #[test]
    fn malformed_or_oversized_requests_are_refused_locally() {
        let up = upstream(|_| "a", false, ok_reply);
        let calls = Arc::new(AtomicUsize::new(0));
        let max = 4096;
        let rig = rig(&up, &["a"], reattest(&["a"], &calls), max);
        for body in [
            &b"not json"[..],
            br#"{"messages":[]}"#,
            br#"{"model":7}"#,
            br#"["m"]"#,
            br#"{"model":"m","model":"m"}"#,
        ] {
            assert_eq!(rig.post(body).0, 400, "{}", String::from_utf8_lossy(body));
        }
        let mut big = br#"{"model":"m","pad":""#.to_vec();
        big.resize(max - 2, b'x');
        big.extend_from_slice(br#""}"#);
        assert_eq!(big.len(), max);
        assert_eq!(
            rig.post(&big).0,
            200,
            "exactly max_request_bytes is allowed"
        );
        big.insert(big.len() - 2, b'x');
        assert_eq!(rig.post(&big).0, 413);
        assert_eq!(up.requests().len(), 1);
        assert_eq!(rig.fatal.reason(), None);
    }

    #[test]
    fn ironwire_reaches_near_ai_only_through_the_forwarder() {
        let up = upstream(|_| "a", false, ok_reply);
        let calls = Arc::new(AtomicUsize::new(0));
        let rig = rig(&up, &["a"], reattest(&["a"], &calls), 1 << 20);
        let inference = crate::inference::start_with_endpoint(
            DUMMY_KEY.to_string().into(),
            &["m".into()],
            &rig.forwarder.base_url(),
        )
        .unwrap();
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(20))
            .build()
            .unwrap();
        let resp = client
            .post(format!("{}/chat/completions", inference.provider().base_url))
            .bearer_auth(crate::config::PLACEHOLDER_API_KEY)
            .header("x-ironwire-route", crate::inference::route_header("m").unwrap())
            .json(&serde_json::json!({"model":"m","messages":[{"role":"user","content":"hi"}],"stream":false}))
            .send()
            .unwrap();
        assert_eq!(resp.status(), 200);
        let seen = up.requests();
        assert_eq!(seen.len(), 1);
        assert!(
            seen[0]
                .head
                .starts_with("POST /v1/chat/completions HTTP/1.1\r\n")
        );
        assert!(
            seen[0]
                .head
                .lines()
                .any(|l| l.eq_ignore_ascii_case(&format!("authorization: Bearer {DUMMY_KEY}")))
        );
        let body: serde_json::Value = serde_json::from_slice(&seen[0].body).unwrap();
        assert_eq!(body["model"], "m");
    }

    #[test]
    fn start_refuses_an_empty_seed_and_a_plain_http_upstream() {
        let dir = crate::testutil::tempdir("forwarder-start");
        let record =
            AttestationRecord::create(&dir, "0123456789ab", &AttestOptions::default()).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let cfg = |upstream: &str, seed: &[&str]| ForwarderConfig {
            upstream: upstream.into(),
            models: vec!["m".into()],
            roots: roots(),
            seed: Attested {
                fingerprints: fps(seed),
                ..Attested::default()
            },
            reattest: reattest(&["a"], &calls),
            fatal: Fatal::new(),
            record: record.clone(),
            max_request_bytes: 1024,
        };
        assert!(Forwarder::start(cfg("https://127.0.0.1:1/v1", &[])).is_err());
        assert!(Forwarder::start(cfg("http://127.0.0.1:1/v1", &["a"])).is_err());
        assert!(Forwarder::start(cfg("https://127.0.0.1:1/v1", &["a"])).is_ok());
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn post_to(base_url: &str, body: &[u8]) -> u16 {
        reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(20))
            .build()
            .unwrap()
            .post(format!("{base_url}/chat/completions"))
            .bearer_auth(DUMMY_KEY)
            .body(body.to_vec())
            .send()
            .unwrap()
            .status()
            .as_u16()
    }

    /// Review finding: a request parked on the re-attestation lock while
    /// another request's attempts end in pin-failed must not re-attest again
    /// or reach upstream.
    #[test]
    fn parked_requests_share_one_round_of_reattestation_and_stop_after_fatal() {
        let up = upstream(|_| "b", false, ok_reply);
        let calls = Arc::new(AtomicUsize::new(0));
        let (first_tx, first_rx) = std::sync::mpsc::channel();
        let first_tx = Mutex::new(first_tx);
        let counted = calls.clone();
        let slow: Reattest = Arc::new(move || {
            if counted.fetch_add(1, Ordering::SeqCst) == 0 {
                let _ = first_tx.lock().unwrap().send(());
            }
            std::thread::sleep(Duration::from_millis(300));
            Ok(Attested {
                fingerprints: fps(&["a"]),
                ..Attested::default()
            })
        });
        let rig = rig(&up, &["a"], slow, 1 << 20);
        let base = rig.forwarder.base_url();
        let a = {
            let base = base.clone();
            std::thread::spawn(move || post_to(&base, BODY))
        };
        // B starts while A is inside its first re-attestation, so B takes
        // its own Unpinned rejection and parks on the lock.
        first_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let b = std::thread::spawn(move || post_to(&base, BODY));
        assert_eq!(a.join().unwrap(), 502);
        assert_eq!(b.join().unwrap(), 502);
        wait_for("both rejected handshakes", || up.handshakes().len() == 2);
        assert_eq!(calls.load(Ordering::SeqCst), 3, "B re-attested after fatal");
        assert!(up.requests().is_empty());
        let doc = rig.doc();
        assert_eq!(doc["status"], "pin-failed");
        assert_eq!(doc["reattestations"].as_array().unwrap().len(), 3);
        assert!(rig.fatal.reason().unwrap().starts_with("pin-failed"));
    }

    /// Review finding: fatal raised while a request body is still arriving
    /// must stop that request before it is sent.
    #[test]
    fn a_fatal_raised_while_the_body_arrives_stops_the_request() {
        use std::net::TcpStream;
        let up = upstream(|_| "a", false, ok_reply);
        let calls = Arc::new(AtomicUsize::new(0));
        let rig = rig(&up, &["a"], reattest(&["a"], &calls), 1 << 20);
        let mut s = TcpStream::connect(("127.0.0.1", rig.forwarder.port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        write!(
            s,
            "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {DUMMY_KEY}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            BODY.len()
        )
        .unwrap();
        s.write_all(&BODY[..10]).unwrap();
        s.flush().unwrap();
        std::thread::sleep(Duration::from_millis(200));
        rig.fatal.raise("signature-failed: x");
        s.write_all(&BODY[10..]).unwrap();
        let mut resp = String::new();
        s.read_to_string(&mut resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 502"), "{resp}");
        std::thread::sleep(Duration::from_millis(200));
        assert!(up.handshakes().is_empty());
        assert!(up.requests().is_empty());
    }

    #[test]
    fn the_first_fatal_owns_the_record_status() {
        let dir = crate::testutil::tempdir("forwarder-stop");
        let record =
            AttestationRecord::create(&dir, "0123456789ab", &AttestOptions::default()).unwrap();
        let fatal = Fatal::new();
        assert!(stop(&fatal, &record, "model-refused", "model \"x\""));
        assert!(!stop(&fatal, &record, "pin-failed", "pin: later"));
        let doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(record.path()).unwrap()).unwrap();
        assert_eq!(doc["status"], "model-refused");
        assert_eq!(doc["reason"], "model \"x\"");
        assert_eq!(fatal.reason().unwrap(), "model-refused: model \"x\"");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_refused_path_is_logged_by_method_and_path_only() {
        assert_eq!(
            not_forwarded_line(&Method::GET, "/v1/models"),
            "[rts forwarder] 404 GET /v1/models: not forwarded"
        );
    }

    #[test]
    fn fatal_keeps_its_first_reason() {
        let f = Fatal::new();
        assert_eq!(f.reason(), None);
        assert!(f.raise("pin-failed: one"));
        assert!(!f.raise("model-refused: two"));
        assert_eq!(f.reason().as_deref(), Some("pin-failed: one"));
    }
}

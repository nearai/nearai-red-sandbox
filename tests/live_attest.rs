//! Opt-in live tests against NEAR AI, Intel PCS and NVIDIA NRAS. Every test
//! is `#[ignore]` and reaches the network:
//!
//! ```text
//! RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0 \
//!   cargo test --test live_attest -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Environment (all optional):
//! - `RTS_LIVE_NEAR_ENVIRONMENT`: `production` (default) or `staging`. Picks
//!   the API base and the pinned policy together, as a launch does.
//! - `RTS_LIVE_COMPOSE_POLICY`: `pinned` (default) or `mr-config-only`. Every
//!   other check keeps its default.
//! - `RTS_LIVE_RECORD_DIR`: write what verified as rts's own
//!   `<dir>/live-<environment>/attestation.json`, the input of
//!   `scripts/refresh-attestation-policy.py --environment <environment>`.
//! - `RTS_LIVE_NEAR_MODELS`: comma-separated exact model IDs, default
//!   `config::DEFAULT_MODELS`.
//! - `RTS_LIVE_NEAR_API_KEY`: sent as the bearer on the report fetch when set.
//!   Production serves the report without one.
//! - `RTS_LIVE_POLICY_FEED`: `on` loads the signed attestation policy feed
//!   as a launch does (fetch bounded to 5 s, cache under `$HOME`, fallback)
//!   and merges it into the policy. A build without
//!   `RTS_ATTESTATION_POLICY_PUBLIC_KEYS_HEX` uses compiled-in pins only.
//! - `RTS_LIVE_SAVE_DIR`: save every attestation exchange (reports, PCS,
//!   CRL, NRAS) with the nonces and the time, as `live-run.json`, for the
//!   offline regression fixture.
//!
//! Completions and signature receipts need an API key and are not covered
//! here (spec check 6).

use std::collections::BTreeSet;
use std::io::Write as _;
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ironwire_proxy::embed::HostSecret;
use rts::attest::http::{BlockingHttp, Clock, Http, HttpResponse, SystemClock};
use rts::attest::nras::NrasGpuVerifier;
use rts::attest::record::AttestationRecord;
use rts::attest::tdx::PcsQuoteVerifier;
use rts::attest::{
    AttestOptions, Attested, Attestor, ComposePolicy, Policy, feed, load_policy, policy_json,
};
use rts::forwarder::pin::{PinSet, Rejected, native_roots, pinned_tls, spki_sha256};
use rts::inference::NearEnvironment;
use serde_json::{Value, json};

/// Records every exchange that passes through it.
struct Recording {
    inner: BlockingHttp,
    log: Mutex<Vec<Value>>,
}

impl Recording {
    fn keep(&self, method: &str, url: &str, r: &Result<HttpResponse, String>) {
        let entry = match r {
            Ok(r) => json!({
                "method": method,
                "url": url,
                "status": r.status,
                "headers": r.headers,
                "body_b64": STANDARD.encode(&r.body),
            }),
            Err(e) => json!({ "method": method, "url": url, "error": e }),
        };
        self.log.lock().unwrap().push(entry);
    }
}

impl Http for Recording {
    fn get(&self, url: &str, bearer: Option<&HostSecret>) -> Result<HttpResponse, String> {
        let r = self.inner.get(url, bearer);
        self.keep("GET", url, &r);
        r
    }

    fn post_json(&self, url: &str, body: &[u8]) -> Result<HttpResponse, String> {
        let r = self.inner.post_json(url, body);
        self.keep("POST", url, &r);
        r
    }
}

fn environment() -> NearEnvironment {
    match std::env::var("RTS_LIVE_NEAR_ENVIRONMENT").as_deref() {
        Err(_) | Ok("production") => NearEnvironment::Production,
        Ok("staging") => NearEnvironment::Staging,
        Ok(other) => panic!("RTS_LIVE_NEAR_ENVIRONMENT {other:?}: production or staging"),
    }
}

fn environment_name() -> &'static str {
    match environment() {
        NearEnvironment::Production => "production",
        NearEnvironment::Staging => "staging",
    }
}

fn base_url() -> String {
    environment().base_url().into()
}

fn options() -> AttestOptions {
    let compose_policy = match std::env::var("RTS_LIVE_COMPOSE_POLICY").as_deref() {
        Err(_) | Ok("pinned") => ComposePolicy::Pinned,
        Ok("mr-config-only") => ComposePolicy::MrConfigOnly,
        Ok(other) => panic!("RTS_LIVE_COMPOSE_POLICY {other:?}: pinned or mr-config-only"),
    };
    AttestOptions {
        compose_policy,
        ..AttestOptions::default()
    }
}

fn models() -> Vec<String> {
    match std::env::var("RTS_LIVE_NEAR_MODELS") {
        Ok(v) => v.split(',').map(|m| m.trim().to_string()).collect(),
        Err(_) => rts::config::DEFAULT_MODELS
            .iter()
            .map(|m| m.to_string())
            .collect(),
    }
}

fn host(base: &str) -> String {
    let u = url::Url::parse(base).expect("base URL parses");
    assert_eq!(u.scheme(), "https", "the live base URL must be https");
    u.host_str().expect("base URL has a host").to_string()
}

fn urandom_nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    hex::decode_to_slice(rts::protocol::random_hex(32), &mut n).unwrap();
    n
}

/// The environment's compiled-in policy, with the feed merged in when
/// `RTS_LIVE_POLICY_FEED=on`, loaded as a launch loads it.
fn policy() -> Policy {
    let mut policy = load_policy(policy_json(environment())).unwrap();
    if std::env::var("RTS_LIVE_POLICY_FEED").as_deref() == Ok("on") {
        let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let (doc, source) = feed::session_feed(home.as_deref(), environment(), now);
        println!("{}", source.line());
        if let Some(doc) = doc {
            feed::merge(&mut policy, &doc);
        }
    }
    policy
}

/// Attests every model with the real PCS and NRAS, the environment's base
/// and policy, and `options()` (TCB UpToDate; pinned compose unless
/// overridden). Returns what verified, the nonces used and the recorder.
fn attest_live() -> (Result<Attested, String>, Vec<[u8; 32]>, Arc<Recording>) {
    let http = Arc::new(Recording {
        inner: BlockingHttp::new().unwrap(),
        log: Mutex::new(vec![]),
    });
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let nonces = Arc::new(Mutex::new(Vec::new()));
    let seen = nonces.clone();
    let key = std::env::var("RTS_LIVE_NEAR_API_KEY")
        .ok()
        .map(HostSecret::from);
    let attestor = Attestor {
        http: http.clone(),
        clock: clock.clone(),
        quotes: Arc::new(PcsQuoteVerifier { http: http.clone() }),
        gpus: Arc::new(NrasGpuVerifier {
            http: http.clone(),
            clock,
        }),
        base_url: base_url(),
        key,
        models: models(),
        options: options(),
        policy: policy(),
        continuity: Default::default(),
        nonce: Arc::new(move || {
            let n = urandom_nonce();
            seen.lock().unwrap().push(n);
            n
        }),
    };
    let result = attestor.attest();
    let nonces = nonces.lock().unwrap().clone();
    (result, nonces, http)
}

fn save(nonces: &[[u8; 32]], now: u64, rec: &Recording) {
    let Ok(dir) = std::env::var("RTS_LIVE_SAVE_DIR") else {
        return;
    };
    std::fs::create_dir_all(&dir).unwrap();
    let doc = json!({
        "base_url": base_url(),
        "models": models(),
        "nonces": nonces.iter().map(hex::encode).collect::<Vec<_>>(),
        "now_unix": now,
        "exchanges": *rec.log.lock().unwrap(),
    });
    let path = std::path::Path::new(&dir).join("live-run.json");
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(serde_json::to_string_pretty(&doc).unwrap().as_bytes())
        .unwrap();
    println!("saved {}", path.display());
}

/// A full handshake with `host:443` through the forwarder's pinned client
/// config. Returns the handshake result, the SPKI hash of the presented leaf
/// (when the handshake got that far) and the pin set's last rejection.
fn handshake(
    host: &str,
    pins: BTreeSet<[u8; 32]>,
) -> (Result<(), String>, Option<[u8; 32]>, Option<Rejected>) {
    let set = PinSet::new(pins);
    let cfg = pinned_tls(native_roots().unwrap(), set.clone()).unwrap();
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(cfg), name).unwrap();
    let mut sock = TcpStream::connect((host, 443)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    sock.set_write_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let mut result = Ok(());
    while conn.is_handshaking() {
        if let Err(e) = conn.complete_io(&mut sock) {
            result = Err(e.to_string());
            break;
        }
    }
    let leaf = conn
        .peer_certificates()
        .and_then(|c| c.first())
        .and_then(spki_sha256);
    (result, leaf, set.take_rejected())
}

#[test]
#[ignore = "live: reaches NEAR AI, Intel PCS and NVIDIA NRAS"]
fn attestation_verifies_for_every_model() {
    let base = base_url();
    println!(
        "{} base {base}, models {:?}, options {:?}",
        environment_name(),
        models(),
        options()
    );
    let (result, nonces, rec) = attest_live();
    let now = SystemClock.now_unix();
    save(&nonces, now, &rec);

    // No PCS, CRL, NRAS or NEAR AI call answered with a redirect (none is followed).
    for e in rec.log.lock().unwrap().iter() {
        let status = e["status"].as_u64().unwrap_or(0);
        println!("{} {} -> {}", e["method"], e["url"], e["status"]);
        assert!(!(300..400).contains(&status), "redirect: {e}");
    }

    let attested = match result {
        Ok(a) => a,
        Err(e) => panic!("attestation refused: {e}"),
    };
    for ev in &attested.evidence {
        println!("model {} nonce {}", ev["model"], ev["nonce"]);
        for entry in ev["entries"].as_array().unwrap() {
            let mut shown = entry.clone();
            shown.as_object_mut().unwrap().remove("report");
            println!("  {shown}");
        }
    }
    let fps: Vec<String> = attested.fingerprints.iter().map(hex::encode).collect();
    println!("attested fingerprints {fps:?}");
    if let Ok(dir) = std::env::var("RTS_LIVE_RECORD_DIR") {
        let id = format!("live-{}", environment_name());
        let record = AttestationRecord::create(dir.as_ref(), &id, &options()).unwrap();
        record.verified(&attested).unwrap();
        println!("recorded {}", record.path().display());
    }

    // The live leaf's SPKI hash is attested, and the forwarder's pinned
    // client config completes a handshake with only the attested set.
    let host = host(&base);
    let (ok, leaf, rejected) = handshake(&host, attested.fingerprints.clone());
    println!("live {host} leaf SPKI sha256 {:?}", leaf.map(hex::encode));
    assert_eq!(rejected, None);
    ok.unwrap();
    let leaf = leaf.expect("the server presented a certificate");
    assert!(
        attested.fingerprints.contains(&leaf),
        "live leaf SPKI {} is not attested",
        hex::encode(leaf)
    );
}

#[test]
#[ignore = "live: reaches NEAR AI"]
fn a_wrong_pin_is_refused_against_the_live_gateway() {
    let host = host(&base_url());
    let (ok, _, rejected) = handshake(&host, BTreeSet::from([[0; 32]]));
    assert!(ok.is_err(), "a [0; 32] pin completed a handshake");
    match rejected {
        Some(Rejected::Unpinned(fp)) => {
            println!("refused {host}: unpinned SPKI sha256 {}", hex::encode(fp));
            assert_ne!(fp, [0; 32]);
        }
        other => panic!("expected an unpinned rejection, got {other:?}"),
    }
}

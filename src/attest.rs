//! Attestation of the NEAR AI inference path: NEAR AI's attestation report
//! for every allowed model, its TDX quotes checked against Intel PCS
//! collateral, and its GPU evidence checked through NVIDIA NRAS. Every check
//! fails closed.

pub mod http;
pub mod nras;
pub mod record;
pub mod report;
pub mod tdx;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ironwire_proxy::embed::HostSecret;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use http::{BlockingHttp, Clock, Http, SystemClock};
use nras::{GpuVerifier, NrasGpuVerifier};
use report::{Evidence, ReportResponse};
use tdx::{PcsQuoteVerifier, QuoteVerifier, tcb_policy};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComposePolicy {
    /// The compose hash must be listed in `opencode/attestation-policy.json`.
    Pinned,
    /// Any compose that `mr_config_id` vouches for.
    MrConfigOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AttestOptions {
    pub allow_tcb_out_of_date: bool,
    pub compose_policy: ComposePolicy,
    pub allow_unattested_provider: bool,
}

impl Default for AttestOptions {
    fn default() -> Self {
        Self {
            allow_tcb_out_of_date: false,
            compose_policy: ComposePolicy::Pinned,
            allow_unattested_provider: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub compose_hashes: BTreeSet<[u8; 32]>,
}

/// Compiled in: changing the pinned list needs a rebuild.
pub const POLICY_JSON: &str = include_str!("../opencode/attestation-policy.json");

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PolicyFile {
    compose_hashes: Vec<PolicyEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // `recorded` and `source` document the entry.
struct PolicyEntry {
    sha256: String,
    recorded: String,
    source: String,
}

pub fn load_policy(json: &str) -> Result<Policy, String> {
    let file: PolicyFile =
        serde_json::from_str(json).map_err(|e| format!("attestation-policy.json: {e}"))?;
    let mut compose_hashes = BTreeSet::new();
    for entry in file.compose_hashes {
        let hash = report::hex32(&entry.sha256)
            .map_err(|e| format!("attestation-policy.json: sha256 {:?}: {e}", entry.sha256))?;
        compose_hashes.insert(hash);
    }
    Ok(Policy { compose_hashes })
}

/// The verified state of a session: gateway TLS fingerprints and, per model,
/// the attested ed25519 signing keys.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Attested {
    pub fingerprints: BTreeSet<[u8; 32]>,
    pub keys: BTreeMap<String, BTreeSet<[u8; 32]>>,
    /// Per model: nonce, raw report, per-entry TCB status, compose hash, GPU kid.
    pub evidence: Vec<Value>,
}

impl Attested {
    pub fn merge(&mut self, other: Attested) {
        self.fingerprints.extend(other.fingerprints);
        for (model, keys) in other.keys {
            self.keys.entry(model).or_default().extend(keys);
        }
        self.evidence.extend(other.evidence);
    }
}

pub type Nonce = Arc<dyn Fn() -> [u8; 32] + Send + Sync>;

/// Holds the API key, so it has no `Debug`.
pub struct Attestor {
    pub http: Arc<dyn Http>,
    pub clock: Arc<dyn Clock>,
    pub quotes: Arc<dyn QuoteVerifier>,
    pub gpus: Arc<dyn GpuVerifier>,
    pub base_url: String,
    pub key: HostSecret,
    pub models: Vec<String>,
    pub options: AttestOptions,
    pub policy: Policy,
    pub nonce: Nonce,
}

fn urandom_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    hex::decode_to_slice(crate::protocol::random_hex(32), &mut nonce)
        .expect("random_hex yields 64 hex digits");
    nonce
}

impl Attestor {
    /// BlockingHttp, SystemClock, PcsQuoteVerifier, NrasGpuVerifier, NEAR_BASE_URL, POLICY_JSON, /dev/urandom nonces.
    ///
    /// `BlockingHttp` must not run on a Tokio runtime thread: call `attest`
    /// from a plain thread.
    pub fn real(
        key: HostSecret,
        models: &[String],
        options: AttestOptions,
    ) -> Result<Attestor, String> {
        let http: Arc<dyn Http> = Arc::new(BlockingHttp::new()?);
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        Ok(Attestor {
            quotes: Arc::new(PcsQuoteVerifier { http: http.clone() }),
            gpus: Arc::new(NrasGpuVerifier {
                http: http.clone(),
                clock: clock.clone(),
            }),
            http,
            clock,
            base_url: crate::inference::NEAR_BASE_URL.into(),
            key,
            models: models.to_vec(),
            options,
            policy: load_policy(POLICY_JSON)?,
            nonce: Arc::new(urandom_nonce),
        })
    }

    /// Attests every allowed model, each with its own request and nonce.
    pub fn attest(&self) -> Result<Attested, String> {
        if self.models.is_empty() {
            return Err("attestation: no models to attest".into());
        }
        let mut all = Attested::default();
        for model in &self.models {
            all.merge(
                self.attest_model(model)
                    .map_err(|e| format!("model {model}: {e}"))?,
            );
        }
        Ok(all)
    }

    fn attest_model(&self, model: &str) -> Result<Attested, String> {
        let nonce = (self.nonce)();
        let nonce_hex = hex::encode(nonce);
        let url = report::report_url(&self.base_url, model, &nonce);
        let resp = self
            .http
            .get(&url, Some(&self.key))
            .map_err(|e| format!("attestation report request failed: {e}"))?;
        if resp.status != 200 {
            return Err(format!("attestation report returned HTTP {}", resp.status));
        }
        let raw = std::str::from_utf8(&resp.body)
            .map_err(|_| "attestation report is not UTF-8".to_string())?;
        let parsed: ReportResponse = serde_json::from_str(raw)
            .map_err(|e| format!("attestation report is not a valid report: {e}"))?;
        let gateway = parsed
            .gateway_attestation
            .as_ref()
            .ok_or("attestation report has no gateway_attestation")?;
        let gateway_fp = gateway
            .tls_cert_fingerprint
            .as_deref()
            .ok_or("gateway_attestation has no tls_cert_fingerprint")?;
        let entries = parsed
            .model_attestations
            .as_deref()
            .filter(|m| !m.is_empty())
            .ok_or("attestation report has no model_attestations")?;

        let mut out = Attested::default();
        out.fingerprints.insert(
            report::hex32(gateway_fp).map_err(|e| format!("gateway tls_cert_fingerprint: {e}"))?,
        );
        let mut entry_records = vec![];
        let mut record = self
            .check_quote(gateway, &nonce)
            .map_err(|e| format!("gateway: {e}"))?;
        record.insert("role".into(), "gateway".into());
        entry_records.push(Value::Object(record));

        let keys = out.keys.entry(model.to_string()).or_default();
        for (i, entry) in entries.iter().enumerate() {
            let at = |e: String| format!("model_attestations[{i}]: {e}");
            // Evidence for another model is not evidence for this one. NEAR
            // AI may omit the field; that is accepted until check 6.
            if let Some(name) = entry.model_name.as_deref()
                && name != model
            {
                return Err(at(format!(
                    "model_name {name:?} is not the requested model {model:?}"
                )));
            }
            let key = report::ed25519_key(entry).map_err(at)?;
            let mut record = self.check_quote(entry, &nonce).map_err(at)?;
            let payload = entry
                .nvidia_payload
                .as_deref()
                .ok_or_else(|| at("no nvidia_payload (GPU evidence)".into()))?;
            let verdict = self
                .gpus
                .verify(payload, &nonce_hex)
                .map_err(|e| at(format!("GPU attestation: {e}")))?;
            if !verdict.overall {
                return Err(at(
                    "GPU attestation: NRAS overall verdict is not true".into()
                ));
            }
            if let Some(fp) = entry.tls_cert_fingerprint.as_deref() {
                out.fingerprints.insert(
                    report::hex32(fp).map_err(|e| at(format!("tls_cert_fingerprint: {e}")))?,
                );
            }
            keys.insert(key);
            record.insert("role".into(), "model".into());
            record.insert("index".into(), i.into());
            record.insert("signing_key".into(), hex::encode(key).into());
            record.insert("gpu_kid".into(), verdict.kid.into());
            record.insert("gpu_overall".into(), verdict.overall.into());
            entry_records.push(Value::Object(record));
        }
        out.evidence.push(json!({
            "model": model,
            "nonce": nonce_hex,
            "report": raw,
            "entries": entry_records,
        }));
        Ok(out)
    }

    /// The checks every entry carries: TDX quote, TCB policy, report_data,
    /// and compose. Returns the entry's evidence record.
    fn check_quote(
        &self,
        e: &Evidence,
        nonce: &[u8; 32],
    ) -> Result<serde_json::Map<String, Value>, String> {
        let quote = hex::decode(&e.intel_quote)
            .map_err(|_| "TDX quote (intel_quote) is not hex".to_string())?;
        let claims = self
            .quotes
            .verify(&quote, self.clock.now_unix())
            .map_err(|err| format!("TDX quote: {err}"))?;
        let acceptance = tcb_policy(&claims.tcb_status, self.options.allow_tcb_out_of_date)?;
        report::check_report_data(&claims.report_data, e, nonce)?;
        let compose = report::app_compose(e.info.as_ref())?;
        let hash = report::check_compose(
            &claims.mr_config_id,
            &compose,
            &self.policy,
            self.options.compose_policy,
        )?;
        let mut m = serde_json::Map::new();
        m.insert("tcb_status".into(), claims.tcb_status.into());
        m.insert("advisory_ids".into(), claims.advisory_ids.into());
        m.insert(
            "tcb_acceptance".into(),
            serde_json::to_value(acceptance).unwrap_or(Value::Null),
        );
        m.insert("compose_hash".into(), hex::encode(hash).into());
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::http::{FakeHttp, FixedClock, HttpResponse};
    use crate::attest::nras::{GpuVerdict, GpuVerifier};
    use crate::attest::report::{report_url, tests::sha};
    use crate::attest::tdx::{QuoteVerifier, TdxClaims};
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU8, Ordering};

    const BASE: &str = "https://near.test/v1";
    const DUMMY_KEY: &str = "rts-dummy-key-never-send-to-a-provider";
    const COMPOSE: &str = "services:\n  model: {}\n";
    const OTHER_COMPOSE: &str = "services:\n  other: {}\n";
    const KEY: [u8; 32] = [0x11; 32];
    const FP: [u8; 32] = [0x22; 32];
    const GW_ADDR: [u8; 20] = [0x33; 20];
    const PAYLOAD: &str = "{\"nonce\":\"n\"}";

    struct FakeQuotes(HashMap<Vec<u8>, Result<TdxClaims, String>>);
    impl QuoteVerifier for FakeQuotes {
        fn verify(&self, quote: &[u8], _now: u64) -> Result<TdxClaims, String> {
            self.0
                .get(quote)
                .cloned()
                .unwrap_or_else(|| Err("unknown quote".into()))
        }
    }

    struct FakeGpu {
        result: Result<GpuVerdict, String>,
        seen: Mutex<Vec<(String, String)>>,
    }
    impl GpuVerifier for FakeGpu {
        fn verify(&self, payload: &str, nonce_hex: &str) -> Result<GpuVerdict, String> {
            self.seen
                .lock()
                .unwrap()
                .push((payload.into(), nonce_hex.into()));
            self.result.clone()
        }
    }

    fn mr_config(compose: &str) -> [u8; 48] {
        let mut mr = [0u8; 48];
        mr[0] = 1;
        mr[1..33].copy_from_slice(&sha(&[compose.as_bytes()]));
        mr
    }

    fn claims(first: [u8; 32], nonce: [u8; 32], compose: &str) -> TdxClaims {
        let mut report_data = [0u8; 64];
        report_data[..32].copy_from_slice(&first);
        report_data[32..].copy_from_slice(&nonce);
        TdxClaims {
            tcb_status: "UpToDate".into(),
            advisory_ids: vec![],
            report_data,
            mr_config_id: mr_config(compose),
        }
    }

    fn info(compose: &str) -> serde_json::Value {
        serde_json::json!({ "tcb_info": serde_json::json!({ "app_compose": compose }).to_string() })
    }

    /// One model's good report and the claims its quotes verify to.
    struct Case {
        report: serde_json::Value,
        gw: TdxClaims,
        m0: TdxClaims,
        status: u16,
        body: Option<Vec<u8>>,
        quote_err: Option<String>,
        gpu: Result<GpuVerdict, String>,
        options: AttestOptions,
        policy: Policy,
    }

    impl Case {
        fn good(nonce: [u8; 32]) -> Case {
            Case {
                report: serde_json::json!({
                    "gateway_attestation": {
                        "intel_quote": hex::encode(b"gw"),
                        "signing_address": format!("0x{}", hex::encode(GW_ADDR)),
                        "signing_algo": "ecdsa",
                        "tls_cert_fingerprint": hex::encode(FP),
                        "info": info(COMPOSE),
                    },
                    "model_attestations": [{
                        "intel_quote": hex::encode(b"m0"),
                        "signing_address": hex::encode(KEY),
                        "signing_algo": "ed25519",
                        "nvidia_payload": PAYLOAD,
                        "info": info(COMPOSE),
                        "model_name": "m",
                    }],
                }),
                gw: claims(sha(&[&GW_ADDR, &FP]), nonce, COMPOSE),
                m0: claims(KEY, nonce, COMPOSE),
                status: 200,
                body: None,
                quote_err: None,
                gpu: Ok(GpuVerdict {
                    kid: "kid-1".into(),
                    overall: true,
                }),
                options: AttestOptions::default(),
                policy: Policy {
                    compose_hashes: BTreeSet::from([sha(&[COMPOSE.as_bytes()])]),
                },
            }
        }
    }

    struct Run {
        result: Result<Attested, String>,
        http: Arc<FakeHttp>,
        gpu: Arc<FakeGpu>,
    }

    fn counter_nonce() -> Nonce {
        let n = Arc::new(AtomicU8::new(0));
        Arc::new(move || [n.fetch_add(1, Ordering::SeqCst) + 1; 32])
    }

    /// Routes each model's report under its own nonce; quote bytes are per
    /// model (`gw-<model>`, `m0-<model>`) so their claims can differ.
    fn run_cases(models: &[&str], cases: Vec<Case>) -> Run {
        let http = FakeHttp::new();
        let mut quotes = HashMap::new();
        let first = &cases[0];
        for (i, (model, case)) in models.iter().zip(&cases).enumerate() {
            let nonce = [i as u8 + 1; 32];
            let body = case
                .body
                .clone()
                .unwrap_or_else(|| serde_json::to_vec(&case.report).unwrap());
            http.route(
                "GET",
                &report_url(BASE, model, &nonce),
                HttpResponse {
                    status: case.status,
                    headers: vec![],
                    body,
                },
            );
            quotes.insert(format!("gw-{model}").into_bytes(), Ok(case.gw.clone()));
            quotes.insert(
                format!("m0-{model}").into_bytes(),
                case.quote_err
                    .clone()
                    .map_or_else(|| Ok(case.m0.clone()), Err),
            );
        }
        let gpu = Arc::new(FakeGpu {
            result: first.gpu.clone(),
            seen: Mutex::new(vec![]),
        });
        let attestor = Attestor {
            http: http.clone(),
            clock: Arc::new(FixedClock(1_800_000_000)),
            quotes: Arc::new(FakeQuotes(quotes)),
            gpus: gpu.clone(),
            base_url: BASE.into(),
            key: DUMMY_KEY.to_string().into(),
            models: models.iter().map(|m| m.to_string()).collect(),
            options: first.options,
            policy: first.policy.clone(),
            nonce: counter_nonce(),
        };
        Run {
            result: attestor.attest(),
            http,
            gpu,
        }
    }

    fn for_model(mut case: Case, model: &str) -> Case {
        let r = &mut case.report;
        if let Some(gw) = r
            .get_mut("gateway_attestation")
            .and_then(|g| g.as_object_mut())
        {
            gw.insert(
                "intel_quote".into(),
                hex::encode(format!("gw-{model}")).into(),
            );
        }
        if let Some(ms) = r
            .get_mut("model_attestations")
            .and_then(|m| m.as_array_mut())
        {
            for m in ms {
                if let Some(m) = m.as_object_mut() {
                    m.insert(
                        "intel_quote".into(),
                        hex::encode(format!("m0-{model}")).into(),
                    );
                    // Only the fixture's default; a tampered name stays.
                    if m.get("model_name").and_then(|n| n.as_str()) == Some("m") {
                        m.insert("model_name".into(), (*model).into());
                    }
                }
            }
        }
        case
    }

    fn run_one(case: Case) -> Run {
        run_cases(&["m"], vec![for_model(case, "m")])
    }

    #[test]
    fn a_good_report_yields_the_fingerprint_and_model_keys() {
        let run = run_one(Case::good([1; 32]));
        let a = run.result.unwrap();
        assert_eq!(a.fingerprints, BTreeSet::from([FP]));
        assert_eq!(
            a.keys,
            BTreeMap::from([("m".to_string(), BTreeSet::from([KEY]))])
        );
        assert_eq!(
            run.http.calls(),
            vec![format!("GET {}", report_url(BASE, "m", &[1; 32]))]
        );
        assert_eq!(run.http.bearers(), vec![true]);
        assert_eq!(
            *run.gpu.seen.lock().unwrap(),
            vec![(PAYLOAD.to_string(), hex::encode([1u8; 32]))]
        );
        assert_eq!(a.evidence.len(), 1);
        let ev = a.evidence[0].to_string();
        assert!(ev.contains(&hex::encode([1u8; 32])), "{ev}");
        assert!(ev.contains("kid-1") && ev.contains("UpToDate"), "{ev}");
        assert!(!ev.contains(DUMMY_KEY));
    }

    #[test]
    fn every_allowed_model_gets_its_own_request_and_nonce() {
        let run = run_cases(
            &["m", "n"],
            vec![
                for_model(Case::good([1; 32]), "m"),
                for_model(Case::good([2; 32]), "n"),
            ],
        );
        let a = run.result.unwrap();
        assert_eq!(
            run.http.calls(),
            vec![
                format!("GET {}", report_url(BASE, "m", &[1; 32])),
                format!("GET {}", report_url(BASE, "n", &[2; 32])),
            ]
        );
        assert_eq!(a.keys.keys().cloned().collect::<Vec<_>>(), vec!["m", "n"]);
        let nonces: Vec<String> = run
            .gpu
            .seen
            .lock()
            .unwrap()
            .iter()
            .map(|(_, n)| n.clone())
            .collect();
        assert_eq!(nonces, vec![hex::encode([1u8; 32]), hex::encode([2u8; 32])]);
        assert_eq!(a.evidence.len(), 2);
    }

    #[test]
    fn each_tampered_report_is_refused() {
        type Mutate = Box<dyn Fn(&mut Case)>;
        fn gw(c: &mut Case) -> &mut serde_json::Map<String, serde_json::Value> {
            c.report["gateway_attestation"].as_object_mut().unwrap()
        }
        fn m0(c: &mut Case) -> &mut serde_json::Map<String, serde_json::Value> {
            c.report["model_attestations"][0].as_object_mut().unwrap()
        }
        let cases: Vec<(&str, Mutate)> = vec![
            (
                "gateway_attestation",
                Box::new(|c| {
                    c.report
                        .as_object_mut()
                        .unwrap()
                        .remove("gateway_attestation");
                }),
            ),
            (
                "tls_cert_fingerprint",
                Box::new(|c| {
                    gw(c).remove("tls_cert_fingerprint");
                }),
            ),
            (
                "model_attestations",
                Box::new(|c| {
                    c.report["model_attestations"] = serde_json::json!([]);
                }),
            ),
            (
                "model_attestations",
                Box::new(|c| {
                    c.report
                        .as_object_mut()
                        .unwrap()
                        .remove("model_attestations");
                }),
            ),
            (
                "TDX quote",
                Box::new(|c| c.quote_err = Some("bad signature".into())),
            ),
            ("nonce", Box::new(|c| c.m0.report_data[40] ^= 1)),
            ("nonce", Box::new(|c| c.gw.report_data[63] ^= 1)),
            (
                "does not bind",
                Box::new(|c| {
                    c.gw.report_data[..32].copy_from_slice(&sha(&[&GW_ADDR, &[0x44; 32]]))
                }),
            ),
            ("does not bind", Box::new(|c| c.m0.report_data[0] ^= 1)),
            (
                "--allow-tcb-out-of-date",
                Box::new(|c| c.m0.tcb_status = "OutOfDate".into()),
            ),
            (
                "--allow-tcb-out-of-date",
                Box::new(|c| c.gw.tcb_status = "OutOfDate".into()),
            ),
            ("Revoked", Box::new(|c| c.gw.tcb_status = "Revoked".into())),
            (
                "ConfigurationNeeded",
                Box::new(|c| c.m0.tcb_status = "ConfigurationNeeded".into()),
            ),
            (
                "TDRelaunchAdvised",
                Box::new(|c| c.gw.tcb_status = "TDRelaunchAdvised".into()),
            ),
            ("mr_config_id", Box::new(|c| c.m0.mr_config_id[0] = 2)),
            (
                "mr_config_id",
                Box::new(|c| c.gw.mr_config_id = mr_config(OTHER_COMPOSE)),
            ),
            (
                "attestation-policy.json",
                Box::new(|c| {
                    c.gw.mr_config_id = mr_config(OTHER_COMPOSE);
                    gw(c).insert("info".into(), info(OTHER_COMPOSE));
                }),
            ),
            (
                "app_compose",
                Box::new(|c| {
                    m0(c).remove("info");
                }),
            ),
            (
                "GPU",
                Box::new(|c| c.gpu = Err("NRAS verdict: false".into())),
            ),
            (
                "GPU",
                Box::new(|c| {
                    c.gpu = Ok(GpuVerdict {
                        kid: "k".into(),
                        overall: false,
                    })
                }),
            ),
            (
                "nvidia_payload",
                Box::new(|c| {
                    m0(c).remove("nvidia_payload");
                }),
            ),
            (
                "ed25519",
                Box::new(|c| {
                    m0(c).insert("signing_algo".into(), "ecdsa".into());
                }),
            ),
            (
                "model_name \"other-model\" is not the requested model \"m\"",
                Box::new(|c| {
                    m0(c).insert("model_name".into(), "other-model".into());
                }),
            ),
            ("HTTP 401", Box::new(|c| c.status = 401)),
            (
                "report",
                Box::new(|c| c.body = Some(b"<html>not json</html>".to_vec())),
            ),
        ];
        for (phrase, mutate) in cases {
            let mut case = Case::good([1; 32]);
            mutate(&mut case);
            let err = run_one(case).result.unwrap_err();
            assert!(err.contains(phrase), "expected {phrase:?} in {err:?}");
            assert!(
                err.contains("model m"),
                "error does not name the model: {err}"
            );
            assert!(!err.contains(DUMMY_KEY), "key leaked into {err}");
        }
    }

    /// `model_name` is checked when present; NEAR AI may omit it, so its
    /// absence is not refused until check 6 confirms the field.
    #[test]
    fn an_entry_without_model_name_is_accepted() {
        let mut case = Case::good([1; 32]);
        case.report["model_attestations"][0]
            .as_object_mut()
            .unwrap()
            .remove("model_name");
        assert!(run_one(case).result.is_ok());
    }

    #[test]
    fn the_overrides_accept_out_of_date_and_unpinned_compose() {
        let mut case = Case::good([1; 32]);
        case.m0.tcb_status = "OutOfDate".into();
        case.policy = Policy {
            compose_hashes: BTreeSet::new(),
        };
        case.options = AttestOptions {
            allow_tcb_out_of_date: true,
            compose_policy: ComposePolicy::MrConfigOnly,
            allow_unattested_provider: false,
        };
        let a = run_one(case).result.unwrap();
        let ev = a.evidence[0].to_string();
        assert!(ev.contains("\"OutOfDate\""), "{ev}");
        assert!(
            ev.contains(&hex::encode(sha(&[COMPOSE.as_bytes()]))),
            "{ev}"
        );
    }

    #[test]
    fn the_committed_policy_parses_and_bad_entries_are_refused() {
        load_policy(POLICY_JSON).unwrap();
        let h = "ab".repeat(32);
        let good = format!(
            r#"{{"composeHashes":[{{"sha256":"{h}","recorded":"2026-10-28","source":"check 6"}}]}}"#
        );
        assert_eq!(
            load_policy(&good).unwrap().compose_hashes,
            BTreeSet::from([[0xab; 32]])
        );
        for bad in [
            r#"{"composeHashes":[{"sha256":"zz","recorded":"d","source":"s"}]}"#.to_string(),
            format!(
                r#"{{"composeHashes":[{{"sha256":"{}","recorded":"d","source":"s"}}]}}"#,
                "ab".repeat(31)
            ),
            format!(
                r#"{{"composeHashes":[{{"sha256":"{h}","recorded":"d","source":"s","extra":1}}]}}"#
            ),
            r#"{"composeHashes":[],"other":[]}"#.to_string(),
            r#"{}"#.to_string(),
        ] {
            assert!(load_policy(&bad).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn merge_unions_fingerprints_keys_and_evidence() {
        let mut a = Attested::default();
        a.fingerprints.insert(FP);
        a.keys.entry("m".into()).or_default().insert(KEY);
        a.evidence.push(serde_json::json!(1));
        let mut b = Attested::default();
        b.fingerprints.insert([5; 32]);
        b.keys.entry("m".into()).or_default().insert([6; 32]);
        b.evidence.push(serde_json::json!(2));
        a.merge(b);
        assert_eq!(a.fingerprints.len(), 2);
        assert_eq!(a.keys["m"], BTreeSet::from([KEY, [6; 32]]));
        assert_eq!(a.evidence.len(), 2);
    }
}

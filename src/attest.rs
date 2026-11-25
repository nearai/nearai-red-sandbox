//! Attestation of the NEAR AI inference path: NEAR AI's attestation report
//! for every allowed model, its TDX quotes checked against Intel PCS
//! collateral, and its GPU evidence checked through NVIDIA NRAS. Every check
//! fails closed.

pub mod http;
pub mod nras;
pub mod record;
pub mod report;

/// An explicit Cloud refusal, safe for the sponsored launch login path.
const CREDENTIAL_REFUSED: &str = "attestation report refused the API credential";
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
    /// The compose hash must be pinned in the environment's policy:
    /// `opencode/attestation-policy.json` (production) or
    /// `opencode/attestation-policy-staging.json` (staging).
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

/// Production's pinned composes. Compiled in: changing the pinned list needs
/// a rebuild.
pub const POLICY_JSON: &str = include_str!("../opencode/attestation-policy.json");

/// Staging's pinned composes, kept apart from production's so a build
/// trusted in one environment is never trusted in the other.
pub const POLICY_STAGING_JSON: &str = include_str!("../opencode/attestation-policy-staging.json");

/// The compiled-in policy for `near`.
pub fn policy_json(near: crate::inference::NearEnvironment) -> &'static str {
    match near {
        crate::inference::NearEnvironment::Production => POLICY_JSON,
        crate::inference::NearEnvironment::Staging => POLICY_STAGING_JSON,
    }
}

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

/// The verified state of a session: gateway TLS fingerprints, per model the
/// attested ed25519 signing keys, and the attested gateways' ed25519 keys.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Attested {
    pub fingerprints: BTreeSet<[u8; 32]>,
    pub keys: BTreeMap<String, BTreeSet<[u8; 32]>>,
    /// The ed25519 `signing_address` of every gateway entry that passed
    /// every check (TDX quote, TCB policy, report_data binding, compose).
    /// NEAR AI production signs receipts with it, for any model.
    pub gateway_keys: BTreeSet<[u8; 32]>,
    /// Per model: nonce, raw report, per-entry TCB status, compose hash, GPU kid.
    pub evidence: Vec<Value>,
}

impl Attested {
    pub fn merge(&mut self, other: Attested) {
        self.fingerprints.extend(other.fingerprints);
        self.gateway_keys.extend(other.gateway_keys);
        for (model, keys) in other.keys {
            self.keys.entry(model).or_default().extend(keys);
        }
        self.evidence.extend(other.evidence);
    }

    /// Entries accepted by key continuity rather than a pin: an unreviewed
    /// build trusted because NEAR AI released the session's key to it. The
    /// operator is told; `compose_acceptance` records it in attestation.json.
    pub fn key_continuity(&self) -> Vec<String> {
        let mut out = vec![];
        for ev in &self.evidence {
            let model = ev["model"].as_str().unwrap_or("?");
            for e in ev["entries"].as_array().into_iter().flatten() {
                if e["compose_acceptance"] != "key-continuity" {
                    continue;
                }
                let which = match e["index"].as_u64() {
                    Some(i) if e["role"] == "model" => format!("model_attestations[{i}]"),
                    _ => "gateway_attestation".to_string(),
                };
                let hash = e["compose_hash"].as_str().unwrap_or("?");
                out.push(format!("{model} {which} compose {hash}"));
            }
        }
        out
    }
}

/// The signing keys a session attested at launch, under the full policy.
/// Re-attestation under `Pinned` accepts an unpinned compose for an entry
/// whose quote binds one of these keys: NEAR AI instances of a model share
/// one signing key across builds, so a mid-session redeploy keeps its key
/// while its compose hash changes (issue #25). Empty at launch, so a new
/// session is always strictly pinned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Continuity {
    pub model_keys: BTreeMap<String, BTreeSet<[u8; 32]>>,
    pub gateway_keys: BTreeSet<[u8; 32]>,
}

impl Continuity {
    pub fn from_attested(a: &Attested) -> Self {
        Self {
            model_keys: a.keys.clone(),
            gateway_keys: a.gateway_keys.clone(),
        }
    }

    fn vouches_for_model(&self, model: &str, key: &[u8; 32]) -> bool {
        self.model_keys
            .get(model)
            .is_some_and(|keys| keys.contains(key))
    }
}

pub type Nonce = Arc<dyn Fn() -> [u8; 32] + Send + Sync>;

/// A launch can recover only an explicit Cloud credential rejection.
#[derive(Debug)]
pub enum AttestationFailure {
    CredentialRefused { model: String },
    Other(String),
}

impl AttestationFailure {
    pub fn message(self) -> String {
        match self {
            Self::CredentialRefused { model } => format!("model {model}: {CREDENTIAL_REFUSED}"),
            Self::Other(message) => message,
        }
    }
}

/// Holds the API key, so it has no `Debug`.
pub struct Attestor {
    pub http: Arc<dyn Http>,
    pub clock: Arc<dyn Clock>,
    pub quotes: Arc<dyn QuoteVerifier>,
    pub gpus: Arc<dyn GpuVerifier>,
    pub base_url: String,
    /// Sent as the bearer on the report fetch when present. Cloud requires
    /// a valid API key for authenticated attestation-report routes.
    pub key: Option<HostSecret>,
    pub models: Vec<String>,
    pub options: AttestOptions,
    pub policy: Policy,
    /// Keys already attested this session; empty for a launch.
    pub continuity: Continuity,
    pub nonce: Nonce,
}

fn urandom_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    hex::decode_to_slice(crate::protocol::random_hex(32), &mut nonce)
        .expect("random_hex yields 64 hex digits");
    nonce
}

impl Attestor {
    /// BlockingHttp, SystemClock, PcsQuoteVerifier, NrasGpuVerifier, and
    /// /dev/urandom nonces, with `near`'s API base and pinned policy (one
    /// value, so the two cannot be mixed).
    ///
    /// `BlockingHttp` must not run on a Tokio runtime thread: call `attest`
    /// from a plain thread.
    pub fn real(
        near: crate::inference::NearEnvironment,
        key: Option<HostSecret>,
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
            base_url: near.base_url().into(),
            key,
            models: models.to_vec(),
            options,
            policy: load_policy(policy_json(near))?,
            continuity: Continuity::default(),
            nonce: Arc::new(urandom_nonce),
        })
    }

    /// For re-attestation: see [`Continuity`].
    pub fn with_continuity(mut self, continuity: Continuity) -> Self {
        self.continuity = continuity;
        self
    }

    /// Attests every allowed model, each with its own request and nonce.
    pub fn attest(&self) -> Result<Attested, String> {
        self.attest_for_launch()
            .map_err(AttestationFailure::message)
    }

    pub fn attest_for_launch(&self) -> Result<Attested, AttestationFailure> {
        if self.models.is_empty() {
            return Err(AttestationFailure::Other(
                "attestation: no models to attest".into(),
            ));
        }
        let mut all = Attested::default();
        for model in &self.models {
            let attested = self.attest_model(model).map_err(|error| {
                if error == CREDENTIAL_REFUSED {
                    AttestationFailure::CredentialRefused {
                        model: model.clone(),
                    }
                } else {
                    AttestationFailure::Other(format!("model {model}: {error}"))
                }
            })?;
            all.merge(attested);
        }
        Ok(all)
    }

    fn attest_model(&self, model: &str) -> Result<Attested, String> {
        let nonce = (self.nonce)();
        let nonce_hex = hex::encode(nonce);
        let url = report::report_url(&self.base_url, model, &nonce);
        let resp = self
            .http
            .get(&url, self.key.as_ref())
            .map_err(|e| format!("attestation report request failed: {e}"))?;
        if resp.status != 200 {
            if crate::sponsored::rejection(resp.status, &resp.body).is_some() {
                return Err(CREDENTIAL_REFUSED.into());
            }
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
        // Only an ed25519 gateway attests a key that can vouch for it; the
        // quote binds signing_address (check_report_data) before compose.
        let gateway_continued = gateway.signing_algo == "ed25519"
            && report::hex32(&gateway.signing_address)
                .is_ok_and(|k| self.continuity.gateway_keys.contains(&k));
        let mut record = self
            .check_quote(gateway, &nonce, gateway_continued)
            .map_err(|e| format!("gateway: {e}"))?;
        // Only after every gateway check passed. NEAR AI production signs
        // receipts with an ed25519 gateway key; any other algorithm pins
        // TLS only and attests no receipt key.
        let gateway_key = if gateway.signing_algo == "ed25519" {
            Some(
                report::hex32(&gateway.signing_address)
                    .map_err(|e| format!("gateway: ed25519 signing_address: {e}"))?,
            )
        } else {
            None
        };
        record.insert("role".into(), "gateway".into());
        if let Some(key) = gateway_key {
            record.insert("signing_key".into(), hex::encode(key).into());
        }
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
            let continued = self.continuity.vouches_for_model(model, &key);
            let mut record = self.check_quote(entry, &nonce, continued).map_err(at)?;
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
        // Every model entry passed too: the report is accepted whole.
        out.gateway_keys.extend(gateway_key);
        out.evidence.push(json!({
            "base_url": self.base_url,
            "model": model,
            "nonce": nonce_hex,
            "report": raw,
            "entries": entry_records,
        }));
        Ok(out)
    }

    /// The checks every entry carries: TDX quote, TCB policy, report_data,
    /// and compose. `continued`: the entry's signing key is in
    /// [`Continuity`]; it counts only once report_data has bound that key.
    /// Returns the entry's evidence record.
    fn check_quote(
        &self,
        e: &Evidence,
        nonce: &[u8; 32],
        continued: bool,
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
        let (hash, compose_acceptance) = report::check_compose(
            &claims.mr_config_id,
            &compose,
            &self.policy,
            self.options.compose_policy,
            continued,
        )?;
        let mut m = serde_json::Map::new();
        m.insert("tcb_status".into(), claims.tcb_status.into());
        m.insert("advisory_ids".into(), claims.advisory_ids.into());
        m.insert(
            "tcb_acceptance".into(),
            serde_json::to_value(acceptance).unwrap_or(Value::Null),
        );
        m.insert("compose_hash".into(), hex::encode(hash).into());
        m.insert(
            "compose_acceptance".into(),
            compose_acceptance.as_str().into(),
        );
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
    const GW_KEY: [u8; 32] = [0x55; 32];
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
        gw_quote_err: Option<String>,
        gpu: Result<GpuVerdict, String>,
        options: AttestOptions,
        policy: Policy,
        keyless: bool,
        continuity: Continuity,
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
                gw_quote_err: None,
                gpu: Ok(GpuVerdict {
                    kid: "kid-1".into(),
                    overall: true,
                }),
                options: AttestOptions::default(),
                policy: Policy {
                    compose_hashes: BTreeSet::from([sha(&[COMPOSE.as_bytes()])]),
                },
                keyless: false,
                continuity: Continuity::default(),
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
            quotes.insert(
                format!("gw-{model}").into_bytes(),
                case.gw_quote_err
                    .clone()
                    .map_or_else(|| Ok(case.gw.clone()), Err),
            );
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
            key: (!first.keyless).then(|| DUMMY_KEY.to_string().into()),
            models: models.iter().map(|m| m.to_string()).collect(),
            options: first.options,
            policy: first.policy.clone(),
            continuity: first.continuity.clone(),
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

    /// Production serves the report without an API key, so attestation can
    /// run keyless; it still verifies, and no bearer is sent.
    #[test]
    fn only_recognized_credential_refusals_are_reported_for_prelaunch_handoff() {
        for (status, kind, recognized) in [
            (401, "invalid_api_key", true),
            (402, "api_key_limit_exceeded", true),
            (402, "no_credits", true),
            (401, "unknown", false),
            (402, "unknown", false),
            (503, "no_credits", false),
        ] {
            let mut case = Case::good([1; 32]);
            case.status = status;
            case.report = serde_json::json!({"error":{"type":kind}});
            let error = run_one(case).result.unwrap_err();
            assert_eq!(
                error.ends_with(CREDENTIAL_REFUSED),
                recognized,
                "{status} {kind}: {error}"
            );
        }
        let mut case = Case::good([1; 32]);
        case.status = 401;
        case.report = serde_json::json!({"unexpected": "response"});
        assert!(
            !run_one(case)
                .result
                .unwrap_err()
                .ends_with(CREDENTIAL_REFUSED)
        );
    }

    #[test]
    fn a_keyless_attestor_fetches_the_report_without_a_bearer() {
        let mut case = Case::good([1; 32]);
        case.keyless = true;
        let run = run_one(case);
        assert_eq!(run.result.unwrap().fingerprints, BTreeSet::from([FP]));
        assert_eq!(run.http.bearers(), vec![false]);
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
        // An ecdsa gateway pins TLS only; it attests no receipt key.
        assert!(a.gateway_keys.is_empty(), "{:?}", a.gateway_keys);
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

    /// A good report whose gateway signs with ed25519, as production does.
    fn ed25519_gateway(nonce: [u8; 32]) -> Case {
        let mut case = Case::good(nonce);
        let gw = case.report["gateway_attestation"].as_object_mut().unwrap();
        gw.insert("signing_address".into(), hex::encode(GW_KEY).into());
        gw.insert("signing_algo".into(), "ed25519".into());
        case.gw = claims(sha(&[&GW_KEY, &FP]), nonce, COMPOSE);
        case
    }

    #[test]
    fn an_ed25519_gateway_that_passes_every_check_yields_its_key() {
        let a = run_one(ed25519_gateway([1; 32])).result.unwrap();
        assert_eq!(a.gateway_keys, BTreeSet::from([GW_KEY]));
        // The gateway key is not a model key.
        assert_eq!(
            a.keys,
            BTreeMap::from([("m".to_string(), BTreeSet::from([KEY]))])
        );
        let gw = &a.evidence[0]["entries"][0];
        assert_eq!(gw["role"], "gateway");
        assert_eq!(gw["signing_key"], hex::encode(GW_KEY));
    }

    /// The gateway key is accepted only from an entry that passed every
    /// check: any failed check refuses the whole report, so no key escapes.
    #[test]
    fn a_gateway_key_from_a_report_that_failed_a_check_is_not_accepted() {
        type Mutate = Box<dyn Fn(&mut Case)>;
        let cases: Vec<(&str, Mutate)> = vec![
            ("does not bind", Box::new(|c| c.gw.report_data[0] ^= 1)),
            ("nonce", Box::new(|c| c.gw.report_data[63] ^= 1)),
            (
                "TDX quote",
                Box::new(|c| c.gw_quote_err = Some("bad signature".into())),
            ),
            ("Revoked", Box::new(|c| c.gw.tcb_status = "Revoked".into())),
            (
                "--allow-tcb-out-of-date",
                Box::new(|c| c.gw.tcb_status = "OutOfDate".into()),
            ),
            (
                "attestation-policy.json",
                Box::new(|c| {
                    c.gw.mr_config_id = mr_config(OTHER_COMPOSE);
                    c.report["gateway_attestation"]
                        .as_object_mut()
                        .unwrap()
                        .insert("info".into(), info(OTHER_COMPOSE));
                }),
            ),
            (
                "signing_address",
                Box::new(|c| {
                    // A 31-byte key the quote binds is still refused.
                    c.gw = claims(sha(&[&[0x55; 31], &FP]), [1; 32], COMPOSE);
                    c.report["gateway_attestation"]
                        .as_object_mut()
                        .unwrap()
                        .insert("signing_address".into(), "55".repeat(31).into());
                }),
            ),
            // A later model entry failing refuses the gateway key too.
            (
                "GPU",
                Box::new(|c| c.gpu = Err("NRAS verdict: false".into())),
            ),
        ];
        for (phrase, mutate) in cases {
            let mut case = ed25519_gateway([1; 32]);
            mutate(&mut case);
            let err = run_one(case).result.unwrap_err();
            assert!(err.contains(phrase), "expected {phrase:?} in {err:?}");
            assert!(err.contains("model m"), "{err}");
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

    /// A redeploy: the entry's compose is not pinned (`OTHER_COMPOSE`).
    fn redeployed_model(mut case: Case) -> Case {
        case.m0.mr_config_id = mr_config(OTHER_COMPOSE);
        case.report["model_attestations"][0]
            .as_object_mut()
            .unwrap()
            .insert("info".into(), info(OTHER_COMPOSE));
        case
    }

    fn redeployed_gateway(mut case: Case) -> Case {
        case.gw.mr_config_id = mr_config(OTHER_COMPOSE);
        case.report["gateway_attestation"]
            .as_object_mut()
            .unwrap()
            .insert("info".into(), info(OTHER_COMPOSE));
        case
    }

    fn continuity(model: &str, keys: &[[u8; 32]], gateway: &[[u8; 32]]) -> Continuity {
        Continuity {
            model_keys: BTreeMap::from([(model.to_string(), keys.iter().copied().collect())]),
            gateway_keys: gateway.iter().copied().collect(),
        }
    }

    /// Issue #25: NEAR redeploys a model to a new build mid-session. The new
    /// compose is not pinned, but the instance holds the signing key the
    /// session already attested from a pinned build, so re-attestation keeps
    /// the session alive and records why it accepted the compose.
    #[test]
    fn a_redeployed_model_holding_an_attested_key_is_accepted_by_key_continuity() {
        let mut case = redeployed_model(Case::good([1; 32]));
        case.continuity = continuity("m", &[KEY], &[]);
        let a = run_one(case).result.unwrap();
        assert_eq!(
            a.keys,
            BTreeMap::from([("m".to_string(), BTreeSet::from([KEY]))])
        );
        assert_eq!(a.fingerprints, BTreeSet::from([FP]));
        let entries = &a.evidence[0]["entries"];
        assert_eq!(entries[0]["compose_acceptance"], "pinned");
        assert_eq!(entries[1]["compose_acceptance"], "key-continuity");
        assert_eq!(
            entries[1]["compose_hash"],
            hex::encode(sha(&[OTHER_COMPOSE.as_bytes()]))
        );
    }

    #[test]
    fn without_continuity_a_redeployed_model_is_still_refused_under_pinned() {
        let err = run_one(redeployed_model(Case::good([1; 32])))
            .result
            .unwrap_err();
        assert!(err.contains("not pinned"), "{err}");
    }

    /// Continuity vouches only for a key already attested for this model.
    #[test]
    fn continuity_does_not_vouch_for_a_new_key_or_another_models_key() {
        for c in [
            continuity("m", &[[0x44; 32]], &[]),
            continuity("other", &[KEY], &[]),
            // A gateway key is not a model key.
            continuity("x", &[], &[KEY]),
        ] {
            let mut case = redeployed_model(Case::good([1; 32]));
            case.continuity = c;
            let err = run_one(case).result.unwrap_err();
            assert!(err.contains("not pinned"), "{err}");
        }
    }

    /// Continuity replaces only the pin: every other check still applies.
    #[test]
    fn continuity_does_not_skip_any_other_check() {
        type Mutate = Box<dyn Fn(&mut Case)>;
        let cases: Vec<(&str, Mutate)> = vec![
            ("does not bind", Box::new(|c| c.m0.report_data[0] ^= 1)),
            ("nonce", Box::new(|c| c.m0.report_data[63] ^= 1)),
            ("TDX quote", Box::new(|c| c.quote_err = Some("bad".into()))),
            ("Revoked", Box::new(|c| c.m0.tcb_status = "Revoked".into())),
            (
                "GPU",
                Box::new(|c| c.gpu = Err("NRAS verdict: false".into())),
            ),
            (
                "does not match sha256(app_compose)",
                Box::new(|c| c.m0.mr_config_id = mr_config(COMPOSE)),
            ),
        ];
        for (phrase, mutate) in cases {
            let mut case = redeployed_model(Case::good([1; 32]));
            case.continuity = continuity("m", &[KEY], &[]);
            mutate(&mut case);
            let err = run_one(case).result.unwrap_err();
            assert!(err.contains(phrase), "expected {phrase:?} in {err:?}");
        }
    }

    #[test]
    fn a_redeployed_ed25519_gateway_holding_an_attested_key_is_accepted() {
        let mut case = redeployed_gateway(ed25519_gateway([1; 32]));
        case.continuity = continuity("m", &[], &[GW_KEY]);
        let a = run_one(case).result.unwrap();
        assert_eq!(a.gateway_keys, BTreeSet::from([GW_KEY]));
        assert_eq!(
            a.evidence[0]["entries"][0]["compose_acceptance"],
            "key-continuity"
        );

        // A model key does not vouch for the gateway.
        let mut case = redeployed_gateway(ed25519_gateway([1; 32]));
        case.continuity = continuity("m", &[KEY, GW_KEY], &[]);
        let err = run_one(case).result.unwrap_err();
        assert!(
            err.contains("gateway") && err.contains("not pinned"),
            "{err}"
        );
    }

    #[test]
    fn continuity_does_not_skip_any_gateway_check() {
        type Mutate = Box<dyn Fn(&mut Case)>;
        let cases: Vec<(&str, Mutate)> = vec![
            ("does not bind", Box::new(|c| c.gw.report_data[0] ^= 1)),
            ("nonce", Box::new(|c| c.gw.report_data[63] ^= 1)),
            ("TDX quote", Box::new(|c| c.gw_quote_err = Some("bad".into()))),
            ("Revoked", Box::new(|c| c.gw.tcb_status = "Revoked".into())),
            (
                "does not match sha256(app_compose)",
                Box::new(|c| c.gw.mr_config_id = mr_config(COMPOSE)),
            ),
        ];
        for (phrase, mutate) in cases {
            let mut case = redeployed_gateway(ed25519_gateway([1; 32]));
            case.continuity = continuity("m", &[], &[GW_KEY]);
            mutate(&mut case);
            let err = run_one(case).result.unwrap_err();
            assert!(err.contains(phrase), "expected {phrase:?} in {err:?}");
        }
    }

    #[test]
    fn key_continuity_acceptances_are_listed_for_the_operator() {
        let mut case = redeployed_model(Case::good([1; 32]));
        case.continuity = continuity("m", &[KEY], &[]);
        let a = run_one(case).result.unwrap();
        assert_eq!(
            a.key_continuity(),
            vec![format!(
                "m model_attestations[0] compose {}",
                hex::encode(sha(&[OTHER_COMPOSE.as_bytes()]))
            )]
        );
        assert!(run_one(Case::good([1; 32])).result.unwrap().key_continuity().is_empty());
    }

    /// An ecdsa gateway attests no ed25519 key, so nothing can vouch for it.
    #[test]
    fn a_redeployed_ecdsa_gateway_is_refused_even_with_continuity() {
        let mut case = redeployed_gateway(Case::good([1; 32]));
        case.continuity = continuity("m", &[KEY], &[GW_KEY]);
        let err = run_one(case).result.unwrap_err();
        assert!(
            err.contains("gateway") && err.contains("not pinned"),
            "{err}"
        );
    }

    #[test]
    fn mr_config_only_records_its_acceptance() {
        let mut case = redeployed_model(Case::good([1; 32]));
        case.options.compose_policy = ComposePolicy::MrConfigOnly;
        let a = run_one(case).result.unwrap();
        assert_eq!(
            a.evidence[0]["entries"][1]["compose_acceptance"],
            "mr-config-only"
        );
    }

    #[test]
    fn continuity_is_seeded_from_the_sessions_attested_keys() {
        let mut a = Attested::default();
        a.keys.insert("m".into(), BTreeSet::from([KEY]));
        a.gateway_keys.insert(GW_KEY);
        a.fingerprints.insert(FP);
        assert_eq!(
            Continuity::from_attested(&a),
            continuity("m", &[KEY], &[GW_KEY])
        );
    }

    #[test]
    fn each_environment_attests_against_its_own_base_and_policy() {
        use crate::inference::NearEnvironment;
        let models = vec!["m".to_string()];
        for (near, json) in [
            (NearEnvironment::Production, POLICY_JSON),
            (NearEnvironment::Staging, POLICY_STAGING_JSON),
        ] {
            assert_eq!(policy_json(near), json);
            let a = Attestor::real(near, None, &models, AttestOptions::default()).unwrap();
            assert_eq!(a.base_url, near.base_url());
            assert_eq!(a.policy, load_policy(json).unwrap());
        }
        assert_ne!(POLICY_JSON, POLICY_STAGING_JSON);
    }

    /// Every pin names the environment it was measured in, and no gateway
    /// build is pinned in both: a staging gateway is never trusted for
    /// production, nor the reverse. (Model builds may be shared.)
    #[test]
    fn no_gateway_build_is_pinned_in_both_environments() {
        let entries = |json: &str| -> Vec<(String, String)> {
            let v: Value = serde_json::from_str(json).unwrap();
            v["composeHashes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| {
                    (
                        e["sha256"].as_str().unwrap().to_string(),
                        e["source"].as_str().unwrap().to_string(),
                    )
                })
                .collect()
        };
        let pinned = |json: &str| load_policy(json).unwrap().compose_hashes;
        for (json, name, other) in [
            (POLICY_JSON, "production", POLICY_STAGING_JSON),
            (POLICY_STAGING_JSON, "staging", POLICY_JSON),
        ] {
            let mut gateways = 0;
            for (hash, source) in entries(json) {
                assert!(
                    source.starts_with(&format!("NEAR AI {name} ")),
                    "{hash} in the {name} policy names another source: {source}"
                );
                if source.contains("gateway_attestation") {
                    gateways += 1;
                    assert!(
                        !pinned(other).contains(&report::hex32(&hash).unwrap()),
                        "{name} gateway {hash} is pinned in the other environment too"
                    );
                }
            }
            assert!(gateways > 0, "the {name} policy pins no gateway");
        }
    }

    #[test]
    fn the_recorded_production_evidence_is_refused_under_the_staging_policy() {
        let e = production_replay(
            PRODUCTION_RECORDED_AT,
            load_policy(POLICY_STAGING_JSON).unwrap(),
            None,
        )
        .unwrap_err();
        assert!(e.contains("not pinned"), "{e}");
    }

    /// The production compose hashes, each sha256(info.tcb_info.app_compose).
    /// 2026-10-29: the gateway (dstack-0.5.12) and the abliterated DeepSeek
    /// model entry (dstack-nvidia-0.5.11). 2026-11-20, verified by rts under
    /// mr-config-only: the redeployed gateway (dstack-0.5.12) and both
    /// model entries (dstack-nvidia-0.5.11, gpu04 and gpu02). 2026-11-23:
    /// the updated gateway and Qwen on dstack-nvidia-0.5.12 (gpu13).
    /// 2026-11-24: the redeployed gateway.
    #[test]
    fn the_committed_policy_pins_the_production_composes() {
        let policy = load_policy(POLICY_JSON).unwrap();
        for h in [
            "f571e5dafe8f96baf116a271b4be9cba228b447dd6ebe502bbda81ede7bcc7ce",
            "ae66f844658a7aee331dcb9fb59bd40323d71d192d37719e022cc4af8389265b",
            "53cd435edbc129f848ed0ddce301f7f192446fe39683713a38537820bea7e1fb",
            "e3902667a26282dd8b4015a901848c521b20243a155a457148f88acf48a45959",
            "edabf8039210336d90fe966dfc4e48216551dfd8b05d54e96d3f3f0e0da850d4",
            "1787a4af87eaf4bb139b555c3148ea6cffb01442b9fd7db4304e23b24f4db993",
            "e4b83d924284eece9b972d8e18bd88dac4dd529031b00311ef5044eaa60ba8d9",
            "a1c3d2e1455ea32d3434722f8867398a5e85e0dbd441f81e552a81641a09c424",
        ] {
            assert!(
                policy.compose_hashes.contains(&report::hex32(h).unwrap()),
                "{h} is not pinned"
            );
        }
        assert_eq!(policy.compose_hashes.len(), 8);
    }

    /// The staging compose hashes measured on 2026-11-20 and verified by rts
    /// under mr-config-only: the staging gateway (dstack-0.5.15) and the
    /// same two model entries production serves. 2026-11-23: the updated
    /// staging gateway and the same Qwen envelope as production. 2026-11-24:
    /// the redeployed staging gateway.
    #[test]
    fn the_committed_staging_policy_pins_the_staging_composes() {
        let policy = load_policy(POLICY_STAGING_JSON).unwrap();
        for h in [
            "10d29b736472383a011211c5c882d85d5dd53c8d4242d9d872c64a6097bdf441",
            "e3902667a26282dd8b4015a901848c521b20243a155a457148f88acf48a45959",
            "edabf8039210336d90fe966dfc4e48216551dfd8b05d54e96d3f3f0e0da850d4",
            "85c10cc2c733cfd49e3e780384abfa53415d3f63c85a19e8350cfb08ce40c5f7",
            "e4b83d924284eece9b972d8e18bd88dac4dd529031b00311ef5044eaa60ba8d9",
            "0cf678004e2d5995cd158d4e07af7e6cd014676f9139619805ada9c727d3b688",
        ] {
            assert!(
                policy.compose_hashes.contains(&report::hex32(h).unwrap()),
                "{h} is not pinned"
            );
        }
        assert_eq!(policy.compose_hashes.len(), 6);
    }

    const STAGING_RECORDED_AT: u64 = 1_795_182_609;

    #[test]
    fn the_recorded_staging_evidence_attests_only_under_the_staging_policy() {
        let a = staging_replay(
            STAGING_RECORDED_AT,
            load_policy(POLICY_STAGING_JSON).unwrap(),
        )
        .unwrap();
        assert_eq!(
            a.evidence[0]["base_url"],
            crate::inference::NEAR_STAGING_BASE_URL
        );
        let entries = a.evidence[0]["entries"].as_array().unwrap();
        assert!(entries.iter().all(|e| e["tcb_status"] == "UpToDate"));
        assert!(entries.iter().all(|e| e["compose_acceptance"] == "pinned"));
        // The staging gateway's ed25519 key signs receipts.
        assert_eq!(
            a.gateway_keys,
            BTreeSet::from([report::hex32(
                "b883f3a4b5dd466b270be49609f5cda34ac5b86787d2af46742d48ec268fbfc2"
            )
            .unwrap()])
        );
        // The staging gateway is not a production build.
        let e = staging_replay(STAGING_RECORDED_AT, load_policy(POLICY_JSON).unwrap()).unwrap_err();
        assert!(e.contains("gateway") && e.contains("not pinned"), "{e}");
    }

    /// The production evidence recorded by tests/live_attest.rs on
    /// 2026-10-29 (report, PCS collateral, root CRL, NRAS answer and the
    /// JWKS key it names), replayed through the real quote and GPU
    /// verifiers at the recorded time.
    fn production_replay(
        now: u64,
        policy: Policy,
        key: Option<HostSecret>,
    ) -> Result<Attested, String> {
        replay(
            include_str!("../tests/fixtures/near-prod/live-run-2026-10-29.json"),
            now,
            policy,
            key,
        )
    }

    /// The staging evidence recorded by tests/live_attest.rs on 2026-11-20
    /// (RTS_LIVE_NEAR_ENVIRONMENT=staging), replayed the same way.
    fn staging_replay(now: u64, policy: Policy) -> Result<Attested, String> {
        replay(
            include_str!("../tests/fixtures/near-staging/live-run-2026-11-20.json"),
            now,
            policy,
            None,
        )
    }

    fn replay(
        run: &str,
        now: u64,
        policy: Policy,
        key: Option<HostSecret>,
    ) -> Result<Attested, String> {
        use base64::Engine;
        let run: Value = serde_json::from_str(run).unwrap();
        let http = FakeHttp::new();
        for e in run["exchanges"].as_array().unwrap() {
            let headers = e["headers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| {
                    (
                        h[0].as_str().unwrap().to_string(),
                        h[1].as_str().unwrap().to_string(),
                    )
                })
                .collect();
            http.route(
                e["method"].as_str().unwrap(),
                e["url"].as_str().unwrap(),
                HttpResponse {
                    status: e["status"].as_u64().unwrap() as u16,
                    headers,
                    body: base64::engine::general_purpose::STANDARD
                        .decode(e["body_b64"].as_str().unwrap())
                        .unwrap(),
                },
            );
        }
        let nonce = report::hex32(run["nonces"][0].as_str().unwrap()).unwrap();
        let http: Arc<dyn Http> = http;
        let clock: Arc<dyn Clock> = Arc::new(FixedClock(now));
        Attestor {
            quotes: Arc::new(PcsQuoteVerifier { http: http.clone() }),
            gpus: Arc::new(NrasGpuVerifier {
                http: http.clone(),
                clock: clock.clone(),
            }),
            http,
            clock,
            base_url: run["base_url"].as_str().unwrap().into(),
            key,
            models: vec![crate::config::DEFAULT_MODELS[0].to_string()],
            options: AttestOptions::default(),
            policy,
            continuity: Continuity::default(),
            nonce: Arc::new(move || nonce),
        }
        .attest()
    }

    const PRODUCTION_RECORDED_AT: u64 = 1_793_309_354;

    #[test]
    fn the_recorded_production_evidence_attests_under_the_default_options() {
        let a = production_replay(
            PRODUCTION_RECORDED_AT,
            load_policy(POLICY_JSON).unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(
            a.fingerprints,
            BTreeSet::from([
                report::hex32("73862c254372091cc6895b900111503860694f8916ebf0c63b18d245ba8ba5ad")
                    .unwrap(),
                report::hex32("4066aed3031802c9de0197e0e849a18133e445f2bb085b036c2a18ab47796408")
                    .unwrap(),
            ])
        );
        // The live leaf's SPKI hash is the gateway's attested fingerprint.
        use rustls::pki_types::pem::PemObject;
        let leaf = rustls::pki_types::CertificateDer::from_pem_slice(include_bytes!(
            "../tests/fixtures/near-prod/cloud-api-leaf.pem"
        ))
        .unwrap();
        assert!(
            a.fingerprints
                .contains(&crate::forwarder::pin::spki_sha256(&leaf).unwrap())
        );
        assert_eq!(
            a.keys[crate::config::DEFAULT_MODELS[0]],
            BTreeSet::from([report::hex32(
                "88fbc43bdd80a7cc51c3f47ac7ec88b37efe2471b4e20a651281fbd81adcee78"
            )
            .unwrap()])
        );
        // Production signs receipts with the gateway's ed25519 key
        // (session d493b14cec32, 2026-10-29), so it is attested too.
        assert_eq!(
            a.gateway_keys,
            BTreeSet::from([report::hex32(
                "40599fb284f43953bb356b09080fd803c960fc10285ad90eca462ca711ad4acb"
            )
            .unwrap()])
        );
        assert_eq!(a.evidence[0]["base_url"], crate::inference::NEAR_BASE_URL);
        let entries = a.evidence[0]["entries"].as_array().unwrap();
        assert!(entries.iter().all(|e| e["tcb_status"] == "UpToDate"));
    }

    #[test]
    fn the_recorded_production_evidence_is_refused_without_its_pinned_composes() {
        let e = production_replay(
            PRODUCTION_RECORDED_AT,
            Policy {
                compose_hashes: BTreeSet::new(),
            },
            None,
        )
        .unwrap_err();
        assert!(e.contains("not pinned"), "{e}");
    }

    #[test]
    fn the_recorded_production_evidence_is_refused_once_the_nras_token_expires() {
        let e = production_replay(
            PRODUCTION_RECORDED_AT + 7 * 24 * 3600,
            load_policy(POLICY_JSON).unwrap(),
            None,
        )
        .unwrap_err();
        assert!(e.contains("GPU attestation"), "{e}");
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
    fn merge_unions_fingerprints_keys_gateway_keys_and_evidence() {
        let mut a = Attested::default();
        a.fingerprints.insert(FP);
        a.gateway_keys.insert(GW_KEY);
        a.keys.entry("m".into()).or_default().insert(KEY);
        a.evidence.push(serde_json::json!(1));
        let mut b = Attested::default();
        b.fingerprints.insert([5; 32]);
        b.keys.entry("m".into()).or_default().insert([6; 32]);
        b.gateway_keys.insert([7; 32]);
        b.evidence.push(serde_json::json!(2));
        a.merge(b);
        assert_eq!(a.gateway_keys, BTreeSet::from([GW_KEY, [7; 32]]));
        assert_eq!(a.fingerprints.len(), 2);
        assert_eq!(a.keys["m"], BTreeSet::from([KEY, [6; 32]]));
        assert_eq!(a.evidence.len(), 2);
    }
}

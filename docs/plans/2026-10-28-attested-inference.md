# Attested NEAR AI inference for rts: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `rts launch` refuses to start a session unless NEAR AI's attestation report verifies for every allowed model, and every completion afterwards travels over TLS pinned to the attested gateway, to an allowlisted model, with a verified ed25519 signature, or the session ends.

**Architecture:** In the `connect` step (`src/main.rs:161-165`), after `auth::load_or_login` and before IronWire starts, `src/attest` fetches the report once per allowed model with a fresh nonce and checks it fail-closed: TDX quote with `dcap-qvl =0.7.0` over collateral `rts` fetches from Intel PCS, report data binding, compose measurement against a pinned list, and the NVIDIA NRAS GPU verdict with its ES384 signature checked. A loopback forwarder (`src/forwarder.rs`) then sits between embedded IronWire and NEAR AI: IronWire's `nearai` backend `base_url` points at it, it pins upstream TLS with a custom `rustls` verifier on the client, refuses models outside the allowlist, hashes the exact bytes it relays, and verifies each response's ed25519 signature after the fact. Any failure raises a fatal report that the session loop turns into teardown.

**Tech Stack:** Rust 2024 (`rts`, `cargo test`), IronWire `bf8b90b` embedded, `dcap-qvl =0.7.0` (vendored), `ring` 0.17 (ES384), `ed25519-dalek` 2.2 (`verify_strict`), `rustls` 0.23 + `reqwest` 0.12 (`use_preconfigured_tls`), `hyper` 1 (forwarder server). The opencode plugin shim stays TypeScript under `bun test`.

**Spec:** `docs/specs/2026-10-27-sandboxed-opencode-design.md`, sections Decisions, Inference attestation, Attested forwarder, Error handling, Audit, Testing item 5, checks 6 and 7, and Dependencies (read them first; this plan does not restate the rationale).

## Global Constraints

- Every cargo command uses `RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0` (the README's flags; mixing flags splits the build cache). In the commands below, `T` stands for `RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0 cargo test`.
- Baseline, measured 2026-10-28 before any change: `T --lib` reports `test result: FAILED. 136 passed; 5 failed; 1 ignored`. The five failures are pre-existing and out of scope: `copy::tests::a_long_name_is_refused`, `copy::tests::a_symlink_to_a_host_path_is_refused`, `copy::tests::a_hardlink_is_refused`, `copy::tests::copy_out_is_byte_exact_across_slices`, `copy::tests::an_oversized_file_is_refused` (host-built tar fixtures carry a pax `x` header the extractor refuses). After every task, `T --lib` must show exactly these five failures and no others, with the pass count higher than before. Never report "tests pass" from a filtered run. `bun test tests/unit` must pass in full.
- Before Task 1, re-run `T --lib` and paste the summary line; if it differs from the baseline above, stop and report.
- New crate: only `dcap-qvl =0.7.0`, as a path dependency on `vendor/dcap-qvl-0.7.0` with `version = "=0.7.0", default-features = false, features = ["std", "ring", "default-x509"]`. Never `report`, never default features, never `danger-allow-tcb-override`. Promoted from transitive to direct at today's `Cargo.lock` versions, adding no package: `ring = "0.17.14"`, `ed25519-dalek = "2.2.0"`, `rustls = { version = "0.23.46", default-features = false, features = ["ring", "std", "tls12"] }`, `rustls-native-certs = "0.8.5"`, `hyper = { version = "1.12.0", features = ["server", "http1"] }`, `hyper-util = { version = "0.1.21", features = ["tokio"] }`, `http-body-util = "0.1.5"`, `bytes = "1.12.1"`, `hex = "0.4.3"`; `serde_json` gains `features = ["raw_value"]`; `tokio` gains `"macros"`: production code uses `tokio::select!` (the forwarder's relay and signature check), and tests use `#[tokio::test]`. Each task that touches `Cargo.toml` diffs `Cargo.lock` and reports every added `[[package]]`; anything beyond `dcap-qvl` and its own subtree is a stop-and-ask. Anything else needs Zaki's approval first.
- Test seams: all attestation HTTP goes through `attest::http::Http`, all time through `attest::http::Clock`, quote checks through `attest::tdx::QuoteVerifier`, GPU checks through `attest::nras::GpuVerifier`, and the nonce through an injected closure. Nothing except Task 7 touches the network. Test TLS certificates and keys are openssl-generated fixtures under `tests/fixtures/`; no `rcgen`, no `p384`.
- Fail closed: every check returns `Err` and the caller refuses. No check logs and continues. A missing field is a failure.
- The API key never appears in an error string, a log line, `attestation.json`, `inference.jsonl` or a `Debug` output. Tests use `rts-dummy-key-never-send-to-a-provider` (as `src/inference.rs:267` does) and assert its absence.
- NEAR AI production base: `https://cloud-api.near.ai/v1` (`inference::NEAR_BASE_URL`, introduced in Task 4). Staging is used only by Task 7, through its environment variables.
- Model IDs are visible ASCII without `:` (`inference::route_header`, `src/inference.rs:76-87`), so splitting a receipt's `text` on `:` is unambiguous.
- Commit style: short imperative subject, no `feat:` prefixes, no emojis, ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. Exact bytes. `tcbInfo` and `enclaveIdentity` are the raw JSON Intel signed (`RawValue`), not re-serialized. The forwarder sends the request body it received unmodified and hashes that; it hashes the response bytes as relayed, and asks upstream for `Accept-Encoding: identity`. Tests in Tasks 2, 5 and 6.
2. One pinned client. Every upstream connection to NEAR AI for completions and signatures is built from `forwarder::pin::pinned_tls` with resumption disabled. The only unpinned NEAR AI call is the attestation report fetch. Grep for `reqwest::Client::builder` and `reqwest::blocking::Client::builder` in `src/forwarder*` and `src/attest*` during review. Test in Task 5.
3. After a fatal report, no request reaches upstream: the forwarder answers 502 without a handshake. Tests in Tasks 5 and 6.
4. Ordering in `connect`: credentials, then attestation, then forwarder, then IronWire, all before any VM. `local_preflight` (`src/main.rs:110`) still reads no credentials. The `Connected` struct declares `inference` before `forwarder`, so IronWire shuts down first. Tests in Tasks 4 and 5.
5. The placeholder model ID can never reach NEAR AI: `check_launch` refuses it before credentials are read. Test in Task 1.

---

### Task 1: Exact-ID model allowlist

**Files:**
- Modify: `src/config.rs` (placeholder default, `require_real_models`)
- Modify: `src/session.rs` (extract `plugin_options`, add `models`)
- Modify: `src/main.rs` (`check_launch`, called in `launch` before `run_connected`)
- Modify: `plugin/index.ts` (`models` option, exact-ID filter and setup check)
- Test: `src/config.rs`, `src/session.rs`, `src/main.rs` unit tests; `tests/unit/plugin.test.ts`

**Interfaces:**
- Consumes: `config::parse_config` (`src/config.rs:216`), the `json!` plugin options built inline in `session_body` (`src/session.rs:563-580`), `checkOptions` and `setupWith` (`plugin/index.ts:53-145`).
- Produces:
  - `pub const MODEL_ID_PLACEHOLDER: &str = "PLACEHOLDER-near-private-abliterated";` (a valid route ID, so `inference::route_header` accepts it and existing tests keep compiling)
  - `pub const DEFAULT_MODELS: &[&str] = &[MODEL_ID_PLACEHOLDER];` used by `parse_config` in place of `"z-ai/glm-5.3-flash"` (`src/config.rs:242-244`)
  - `pub fn require_real_models(models: &[String]) -> Result<(), String>` (error names `provider.models` and says the defaults are placeholders until check 6)
  - `pub fn plugin_options(p: &SessionPaths, cfg: &OperatorConfig, rts: &Path, nonce: &str, operator_home: &str) -> serde_json::Value` in `src/session.rs`, the existing object plus `"models": cfg.provider.models`
  - `fn check_launch(cfg: &config::OperatorConfig) -> Result<(), String>` in `src/main.rs` (Task 5 widens it)
  - Plugin option `models: string[]`; `PluginOptions.models: string[]`

- [ ] **Step 1: Write the failing Rust tests.**

```rust
// src/config.rs tests
#[test]
fn the_default_models_are_the_marked_placeholder() {
    let c = parse("{}").unwrap();
    assert_eq!(c.provider.models, DEFAULT_MODELS);
    let e = require_real_models(&c.provider.models).unwrap_err();
    assert!(e.contains("placeholder") && e.contains("provider.models"), "{e}");
    assert!(require_real_models(&["z-ai/glm-5.3-flash".into()]).is_ok());
    assert!(require_real_models(&["a".into(), MODEL_ID_PLACEHOLDER.into()]).is_err());
}

// src/session.rs tests
#[test]
fn plugin_options_carry_the_exact_model_allowlist() {
    let mut cfg = parse_config("{}", Path::new("/cfg"), &Defaults { repo: "/r".into(), mvmctl: "/m".into() }).unwrap();
    cfg.provider.models = vec!["m-one".into(), "m-two".into()];
    let p = session_paths("0123456789ab", Path::new("/s"), Path::new("/rt"));
    let o = plugin_options(&p, &cfg, Path::new("/x/rts"), &"ab".repeat(12), "/home/op");
    assert_eq!(o["models"], serde_json::json!(["m-one", "m-two"]));
    assert_eq!(o["provider"], serde_json::json!(cfg.provider.id));
    assert_eq!(o["bridge"]["machine"], serde_json::json!("rts-0123456789ab"));
}

// src/main.rs tests
#[test]
fn launch_refuses_placeholder_models_before_credentials() {
    let e = check_launch(&default_config()).unwrap_err();
    assert!(e.contains("placeholder"), "{e}");
    let mut cfg = default_config();
    cfg.provider.models = vec!["real-model".into()];
    assert!(check_launch(&cfg).is_ok());
}
```

Update `an_omitted_provider_uses_the_default_near_ai_model` (`src/config.rs:326-329`) to assert `DEFAULT_MODELS`.

- [ ] **Step 2: Run, expect FAIL** — `T --lib config::tests session::tests` fails to compile with `error[E0425]: cannot find value \`DEFAULT_MODELS\` in this scope` (and `plugin_options`, `check_launch` not found).

- [ ] **Step 3: Write the failing plugin tests** in `tests/unit/plugin.test.ts`. Add `models: ["z-ai/glm-5.3-flash"]` to the shared `options`. Add `{ id: "other-nearai-model", providerID: "ironwire", enabled: true }` to the fake's models, and a `modelId?: string` to `Stubborn` that makes `remove` refuse that model ID.

```ts
test("setup keeps only the allowlisted model IDs of the session provider", async () => {
  const f = fakeCtx(options)
  await setupWith(f.ctx, fakeImpl)
  expect((await f.ctx.model.list()).data.map((m: any) => `${m.providerID}/${m.id}`)).toEqual(["ironwire/z-ai/glm-5.3-flash"])
})
test("a provider model outside the allowlist that survives makes setup throw", async () => {
  const f = fakeCtx(options, { modelId: "other-nearai-model" })
  await expect(setupWith(f.ctx, fakeImpl)).rejects.toThrow("model allowlist mismatch: ironwire/other-nearai-model")
  expect(existsSync(options.readyFile as string)).toBe(false)
})
test("an allowlisted model that opencode does not offer makes setup throw", async () => {
  const f = fakeCtx({ ...options, models: ["z-ai/glm-5.3-flash", "not-offered"] })
  await expect(setupWith(f.ctx, fakeImpl)).rejects.toThrow("model allowlist mismatch: missing ironwire/not-offered")
})
for (const models of [undefined, [], [""], "z-ai/glm-5.3-flash", [1]]) {
  test(`option models ${JSON.stringify(models)} is refused`, async () => {
    const f = fakeCtx({ ...options, models })
    await expect(setupWith(f.ctx, fakeImpl)).rejects.toThrow("rts-sandbox: option models must be a non-empty list of model IDs")
  })
}
```

- [ ] **Step 4: Run, expect FAIL** — `bun test tests/unit` fails: the first new test lists `ironwire/other-nearai-model` too, and the option tests resolve instead of rejecting.

- [ ] **Step 5: Implement.** `config.rs`: the two constants and `require_real_models`; `parse_config` defaults to `DEFAULT_MODELS`. `session.rs`: move the `json!` at `session_body` into `plugin_options` and call it. `main.rs`: `check_launch` calls `config::require_real_models(&cfg.provider.models)`; `launch` calls `check_launch(&cfg)?` right after loading the config, before `Deps::real` and `run_connected`. `plugin/index.ts`: `checkOptions` validates `models` (array, non-empty, every entry a non-empty string; message above) into a `Set`; the model transform removes `m` unless `m.providerID === o.provider && models.has(m.id)`; after setup, the enabled models must equal the set exactly, else throw `model allowlist mismatch: ` followed by extras as `provider/id` and missing as `missing provider/id`. Keep the existing `model outside provider` check before it. Update the header comment (`plugin/index.ts:1-4`).

- [ ] **Step 6: Run, expect PASS** — `T --lib` shows the baseline's five failures only, with three more passes; `bun test tests/unit` passes.

- [ ] **Step 7: Commit** — `git add src/config.rs src/session.rs src/main.rs plugin/index.ts tests/unit/plugin.test.ts && git commit -m "Allow models by exact ID at config and plugin layers"`

---

### Task 2: TDX quote verification and PCS collateral

**Files:**
- Create: `vendor/dcap-qvl-0.7.0/` (the crates.io tarball, unpacked unchanged)
- Modify: `Cargo.toml` (`dcap-qvl` path dependency, `hex`, `serde_json` `raw_value`)
- Modify: `src/lib.rs` (`pub mod attest;`)
- Create: `src/attest.rs` (for now only `pub mod http; pub mod tdx;`)
- Create: `src/attest/http.rs`, `src/attest/tdx.rs`
- Create: `tests/fixtures/dcap/tdx_quote`, `tests/fixtures/dcap/tdx_quote_collateral.json` (copied from `vendor/dcap-qvl-0.7.0/sample/`)

**Interfaces:**
- Consumes: `dcap_qvl::quote::Quote::parse(&[u8]) -> anyhow::Result<Quote>` (`quote.rs:735`), `Quote::inner_cert_type() -> u16` and `inner_cert_data() -> &[u8]` (`quote.rs:766,774`), `dcap_qvl::intel::quote_fmspc(&Quote) -> Result<[u8; 6]>` and `quote_ca(&Quote) -> Result<PckCa>` (`intel.rs:183,198`), `PckCa::as_id_str() -> &'static str` (`config.rs:85`), `dcap_qvl::verify::ring::verify(&[u8], &QuoteCollateralV3, u64) -> anyhow::Result<VerifiedReport>` (`verify.rs:1718`), `VerifiedReport { status: String, advisory_ids: Vec<String>, report: Report, .. }` (`verify.rs:257`), `Report::as_td10() -> Option<&TDReport10>` with `mr_config_id: [u8; 48]` and `report_data: [u8; 64]` (`quote.rs:579,303,317`), `dcap_qvl::QuoteCollateralV3` (`lib.rs:102`). `HostSecret` is `ironwire_proxy::embed::HostSecret`, a `secrecy::SecretString` (`embed.rs:161`).
- Produces (`src/attest/http.rs`):

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse { pub status: u16, pub headers: Vec<(String, String)>, pub body: Vec<u8> }
impl HttpResponse { pub fn header(&self, name: &str) -> Option<&str> } // ASCII case-insensitive
pub trait Http: Send + Sync {
    fn get(&self, url: &str, bearer: Option<&HostSecret>) -> Result<HttpResponse, String>;
    fn post_json(&self, url: &str, body: &[u8]) -> Result<HttpResponse, String>;
}
pub struct BlockingHttp { client: reqwest::blocking::Client } // 30 s timeout, no redirects, no proxy, 16 MiB body cap
impl BlockingHttp { pub fn new() -> Result<Self, String> }
impl Http for BlockingHttp
pub trait Clock: Send + Sync { fn now_unix(&self) -> u64; }
pub struct SystemClock;
impl Clock for SystemClock
#[cfg(test)] pub struct FakeHttp { /* routes keyed by "GET <url>" / "POST <url>", recorded calls */ }
#[cfg(test)] impl FakeHttp {
    pub fn new() -> Arc<Self>;
    pub fn route(&self, method: &str, url: &str, r: HttpResponse);
    pub fn calls(&self) -> Vec<String>;                 // "GET <url>" in order
    pub fn bodies(&self) -> Vec<Vec<u8>>;               // POST bodies in order
    pub fn bearers(&self) -> Vec<bool>;                 // whether each call carried a bearer
}
#[cfg(test)] pub struct FixedClock(pub u64);
```

  Unrouted calls on `FakeHttp` return `Err("no route: <method> <url>")`.

- Produces (`src/attest/tdx.rs`):

```rust
pub const INTEL_PCS: &str = "https://api.trustedservices.intel.com";
pub const INTEL_ROOT_CA_CRL_URL: &str = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der";
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcsUrls { pub pck_crl: String, pub tcb_info: String, pub qe_identity: String, pub root_ca_crl: String }
pub fn pcs_urls(fmspc: &[u8; 6], ca: &str) -> PcsUrls;
pub fn percent_decode(s: &str) -> Result<String, String>;
pub fn fetch_collateral(http: &dyn Http, quote: &[u8]) -> Result<dcap_qvl::QuoteCollateralV3, String>;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxClaims { pub tcb_status: String, pub advisory_ids: Vec<String>, pub report_data: [u8; 64], pub mr_config_id: [u8; 48] }
pub fn verify_quote(quote: &[u8], collateral: &dcap_qvl::QuoteCollateralV3, now_unix: u64) -> Result<TdxClaims, String>;
pub trait QuoteVerifier: Send + Sync { fn verify(&self, quote: &[u8], now_unix: u64) -> Result<TdxClaims, String>; }
pub struct PcsQuoteVerifier { pub http: Arc<dyn Http> }
impl QuoteVerifier for PcsQuoteVerifier // fetch_collateral, then verify_quote
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum TcbAcceptance { UpToDate, OutOfDateAllowed }
pub fn tcb_policy(status: &str, allow_out_of_date: bool) -> Result<TcbAcceptance, String>;
```

  `pcs_urls` mirrors `dcap-qvl` 0.7.0 `src/collateral.rs:116-135` with the default `update=standard`: `{INTEL_PCS}/sgx/certification/v4/pckcrl?ca={ca}&encoding=der`, `{INTEL_PCS}/tdx/certification/v4/tcb?fmspc={FMSPC upper hex}&update=standard`, `{INTEL_PCS}/tdx/certification/v4/qe/identity?update=standard`, and `INTEL_ROOT_CA_CRL_URL` (the CRL distribution point of Intel's root, which `dcap-qvl` reads from the root certificate when the base is PCS, `collateral.rs:510-530`). `fetch_collateral` mirrors `collateral.rs:458-560`: PCK CRL body plus header `SGX-PCK-CRL-Issuer-Chain`; TCB body `{"tcbInfo": <raw>, "signature": "<hex>"}` plus header `TCB-Info-Issuer-Chain` or `SGX-TCB-Info-Issuer-Chain`; QE body `{"enclaveIdentity": <raw>, "signature": "<hex>"}` plus header `SGX-Enclave-Identity-Issuer-Chain`; root CA CRL body. Headers go through `percent_decode`. `tcb_info` and `qe_identity` are `serde_json::value::RawValue::get()` of those fields, byte for byte. Any non-2xx refuses with the URL in the message. `pck_certificate_chain` is the quote's certification data when `inner_cert_type() == 5`; any other type refuses (`unsupported PCK certification data type <n>`). `verify_quote` refuses a quote that is not TDX (`as_td10()` is `None`). `percent_decode` is a local function of under 30 lines: `%XX` becomes the byte, `+` stays `+`, anything malformed or non-UTF-8 refuses; no `urlencoding` crate.

- [ ] **Step 1: Vendor `dcap-qvl` after reading it.** Download `https://static.crates.io/crates/dcap-qvl/dcap-qvl-0.7.0.crate` into a scratch directory and check `shasum -a 256` is `b992c9511adf7135ae7c63c023c9303a3615c0f38d7b39514dcc262f91c6adda`; if it is not, stop. Unpack it to `vendor/dcap-qvl-0.7.0/` unchanged. Read `src/verify.rs` and `src/x509.rs` in full (approval condition) and note in the PR description anything that weakens the checks under `std, ring, default-x509`. Add to `Cargo.toml`, with a comment naming the tarball sha256 and the approval date:

```toml
dcap-qvl = { path = "vendor/dcap-qvl-0.7.0", version = "=0.7.0", default-features = false, features = ["std", "ring", "default-x509"] }
hex = "0.4.3"
serde_json = { version = "1.0.154", features = ["raw_value"] }
```

  Run `RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0 cargo build --lib`. A path dependency is not lint-capped, so `-D warnings` applies to the vendored crate. If it fails only on lints inside `vendor/`, do not edit the vendored source: stop and report the warnings. Then `cargo tree -e features -i dcap-qvl` must not show `report`, `reqwest` or `tokio` under `dcap-qvl`, and `git diff Cargo.lock` lists the added packages; report the count.

- [ ] **Step 2: Copy the fixtures** `vendor/dcap-qvl-0.7.0/sample/tdx_quote` and `tdx_quote_collateral.json` to `tests/fixtures/dcap/`, unchanged.

- [ ] **Step 3: Write the failing tests** in `src/attest/tdx.rs`. The collateral window comes from the sample itself: issue times are TCB info 2025-06-19T10:16:03Z, QE identity 2025-06-19T10:32:27Z, root CA CRL 2025-03-20T11:21:57Z and PCK CRL 2025-06-19T10:00:35Z; next updates are 2025-07-19T10:16:03Z, 2025-07-19T10:32:27Z, 2026-04-03T11:21:57Z and 2025-07-19T10:00:35Z. So the sample is valid from 2025-06-19T10:32:27Z to 2025-07-19T10:00:35Z.

```rust
const QUOTE: &[u8] = include_bytes!("../../tests/fixtures/dcap/tdx_quote");
const COLLATERAL: &str = include_str!("../../tests/fixtures/dcap/tdx_quote_collateral.json");
const NOW: u64 = 1_751_328_000;   // 2025-07-01T00:00:00Z, inside the window
const LATE: u64 = 1_753_000_000;  // 2025-07-20T08:26:40Z, after the PCK CRL's nextUpdate
// TD report body starts at byte 48; report_data is at body offset 520
// (16 + 48 + 48 + 8 + 8 + 8 + 48 + 48 + 48 + 48 + 4 * 48).
const REPORT_DATA_AT: usize = 48 + 520;

fn sample() -> QuoteCollateralV3 { serde_json::from_str(COLLATERAL).unwrap() }

#[test]
fn the_sample_quote_verifies_up_to_date_at_a_fixed_time() {
    let c = verify_quote(QUOTE, &sample(), NOW).unwrap();
    assert_eq!(c.tcb_status, "UpToDate");
    assert!(c.advisory_ids.is_empty());
    let q = dcap_qvl::quote::Quote::parse(QUOTE).unwrap();
    let td = q.report.as_td10().unwrap();
    assert_eq!(c.report_data, td.report_data);
    assert_eq!(c.mr_config_id, td.mr_config_id);
}

#[test]
fn a_one_byte_flip_in_report_data_is_refused() {
    let mut q = QUOTE.to_vec();
    q[REPORT_DATA_AT] ^= 0x01;
    assert!(verify_quote(&q, &sample(), NOW).is_err());
}

#[test]
fn tampered_collateral_and_a_late_clock_are_refused() {
    let mut c = sample();
    c.tcb_info = c.tcb_info.replacen("\"TDX\"", "\"TDY\"", 1);
    assert!(verify_quote(QUOTE, &c, NOW).is_err());
    assert!(verify_quote(QUOTE, &sample(), LATE).is_err());
}

#[test]
fn only_up_to_date_passes_unless_out_of_date_is_allowed() {
    assert_eq!(tcb_policy("UpToDate", false).unwrap(), TcbAcceptance::UpToDate);
    assert!(tcb_policy("OutOfDate", false).unwrap_err().contains("--allow-tcb-out-of-date"));
    assert_eq!(tcb_policy("OutOfDate", true).unwrap(), TcbAcceptance::OutOfDateAllowed);
    for s in ["ConfigurationNeeded", "OutOfDateConfigurationNeeded", "SWHardeningNeeded",
              "ConfigurationAndSWHardeningNeeded", "Revoked", "", "uptodate"] {
        assert!(tcb_policy(s, true).is_err(), "{s}");
    }
}

#[test]
fn collateral_comes_from_intel_pcs_and_verifies_the_sample() {
    let c = sample();
    let http = FakeHttp::new();
    // pct(s): test helper, %XX for every byte outside A-Za-z0-9-._~ (the inverse of percent_decode)
    let enc = pct;
    let ok = |headers: Vec<(&str, String)>, body: Vec<u8>| HttpResponse {
        status: 200, headers: headers.into_iter().map(|(k, v)| (k.into(), v)).collect(), body };
    let u = pcs_urls(b"\xB0\xC0\x6F\x00\x00\x00", "platform");
    assert_eq!(u.pck_crl, "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der");
    assert_eq!(u.tcb_info, "https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=B0C06F000000&update=standard");
    assert_eq!(u.qe_identity, "https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity?update=standard");
    assert_eq!(u.root_ca_crl, INTEL_ROOT_CA_CRL_URL);
    http.route("GET", &u.pck_crl, ok(vec![("SGX-PCK-CRL-Issuer-Chain", enc(&c.pck_crl_issuer_chain))], c.pck_crl.clone()));
    http.route("GET", &u.tcb_info, ok(vec![("TCB-Info-Issuer-Chain", enc(&c.tcb_info_issuer_chain))],
        format!(r#"{{"tcbInfo":{},"signature":"{}"}}"#, c.tcb_info, hex::encode(&c.tcb_info_signature)).into_bytes()));
    http.route("GET", &u.qe_identity, ok(vec![("SGX-Enclave-Identity-Issuer-Chain", enc(&c.qe_identity_issuer_chain))],
        format!(r#"{{"enclaveIdentity":{},"signature":"{}"}}"#, c.qe_identity, hex::encode(&c.qe_identity_signature)).into_bytes()));
    http.route("GET", &u.root_ca_crl, ok(vec![], c.root_ca_crl.clone()));
    let fetched = fetch_collateral(http.as_ref(), QUOTE).unwrap();
    assert_eq!(http.calls(), [u.pck_crl, u.tcb_info, u.qe_identity, u.root_ca_crl].map(|x| format!("GET {x}")));
    assert_eq!(fetched.tcb_info, c.tcb_info);          // byte-exact
    assert_eq!(fetched.qe_identity, c.qe_identity);
    assert_eq!(fetched.pck_crl_issuer_chain, c.pck_crl_issuer_chain);
    assert!(fetched.pck_certificate_chain.is_some());
    assert_eq!(verify_quote(QUOTE, &fetched, NOW).unwrap().tcb_status, "UpToDate");
}

#[test]
fn a_pcs_error_or_a_missing_issuer_chain_is_refused() { /* tcb route 500: Err contains the tcb URL; tcb route without either header: Err contains "TCB-Info-Issuer-Chain" */ }

#[test]
fn percent_decoding_keeps_plus_and_refuses_bad_escapes() {
    assert_eq!(percent_decode("a%2Bb+c%0A").unwrap(), "a+b+c\n");
    for bad in ["%", "%2", "%G0", "%FF"] { assert!(percent_decode(bad).is_err(), "{bad}"); }
}
```

  (The sample's FMSPC `B0C06F000000` and PCK Platform CA are in the sample collateral: `tcb_info.fmspc` and the subject of the first certificate in `pck_crl_issuer_chain`, `CN=Intel SGX PCK Platform CA`.)

- [ ] **Step 4: Run, expect FAIL** — `T --lib attest::tdx` fails to compile with `error[E0425]: cannot find function \`verify_quote\` in this scope` (and the other `Produces` names).

- [ ] **Step 5: Implement `http.rs` and `tdx.rs`** as specified under Interfaces. `BlockingHttp` uses `reqwest::blocking::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_secs(30))`; it reads at most 16 MiB of body. No redirects: Task 7 confirms PCS, the root CRL host and NRAS answer without one.

- [ ] **Step 6: Run, expect PASS** — `T --lib attest::tdx`, then `T --lib`: only the baseline's five failures.

- [ ] **Step 7: Commit** — `git add vendor/dcap-qvl-0.7.0 Cargo.toml Cargo.lock src/lib.rs src/attest.rs src/attest tests/fixtures/dcap && git commit -m "Verify TDX quotes with dcap-qvl over Intel PCS collateral"`

---

### Task 3: NVIDIA NRAS GPU verification

**Files:**
- Modify: `Cargo.toml` (`ring = "0.17.14"`)
- Modify: `src/attest.rs` (`pub mod nras;`)
- Create: `src/attest/nras.rs`
- Create: `tests/fixtures/nras/p384-a.pk8`, `tests/fixtures/nras/p384-b.pk8`

**Interfaces:**
- Consumes: Task 2's `Http`, `HttpResponse`, `Clock`, `FakeHttp`, `FixedClock`; `ring::signature::{UnparsedPublicKey, ECDSA_P384_SHA384_FIXED}`; `base64` 0.23 (`URL_SAFE_NO_PAD`, already direct).
- Produces:

```rust
pub const NRAS_ATTEST_URL: &str = "https://nras.attestation.nvidia.com/v3/attest/gpu";
pub const NRAS_JWKS_URL: &str = "https://nras.attestation.nvidia.com/.well-known/jwks.json";
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GpuVerdict { pub kid: String, pub overall: bool }
/// Verifies `alg == "ES384"`, finds the JWKS key with the token's `kid` (`kty EC`, `crv P-384`),
/// verifies the 96-byte fixed signature over `header.payload` against `04 || x || y`,
/// and requires `exp > now_unix`. Returns the kid and the claims.
pub fn verify_es384_jwt(token: &str, jwks: &[u8], now_unix: u64) -> Result<(String, serde_json::Value), String>;
pub trait GpuVerifier: Send + Sync { fn verify(&self, nvidia_payload: &str, nonce_hex: &str) -> Result<GpuVerdict, String>; }
pub struct NrasGpuVerifier { pub http: Arc<dyn Http>, pub clock: Arc<dyn Clock> }
impl GpuVerifier for NrasGpuVerifier
```

  `NrasGpuVerifier::verify`, mirroring `nearai-cloud-verifier` `ts/model_verifier.ts:327-345` but failing closed: parse `nvidia_payload` as JSON; its `nonce` must equal `nonce_hex` ignoring ASCII case, checked before any HTTP call; `POST NRAS_ATTEST_URL` with the payload bytes exactly as received; status 200; the body is a JSON array whose `[0][1]` is the overall token; `GET NRAS_JWKS_URL` (fetched each time: keys rotate daily); `verify_es384_jwt` with `clock.now_unix()`; the claim `x-nvidia-overall-att-result` must be the JSON boolean `true`.

- [ ] **Step 1: Generate the fixtures** (Homebrew OpenSSL 4.1.0 was used to check these commands on 2026-10-28):

```sh
mkdir -p tests/fixtures/nras
for k in a b; do
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -pkeyopt ec_param_enc:named_curve \
    | openssl pkcs8 -topk8 -nocrypt -outform DER -out tests/fixtures/nras/p384-$k.pk8
done
```

  These are test-only keys. If `ring` refuses them, check with `openssl asn1parse -inform DER` that the ECPrivateKey carries the public key.

- [ ] **Step 2: Write the failing tests** in `src/attest/nras.rs`, signing tokens in the test with `ring::signature::EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pk8, &SystemRandom::new())`:

```rust
const A: &[u8] = include_bytes!("../../tests/fixtures/nras/p384-a.pk8");
const B: &[u8] = include_bytes!("../../tests/fixtures/nras/p384-b.pk8");
const NOW: u64 = 1_793_000_000;
fn nonce() -> String { "5f".repeat(32) }

fn jwks(kid: &str, k: &EcdsaKeyPair) -> Vec<u8>   // {"keys":[{"kty":"EC","crv":"P-384","kid":kid,"x":..,"y":..,"x5c":["test"]}]} from public_key()[1..49], [49..97]
fn token(k: &EcdsaKeyPair, header: Value, claims: Value) -> String

#[test] fn a_token_signed_by_the_jwks_key_verifies() // header {"alg":"ES384","kid":"k1","typ":"JWT"}, claims {"exp": NOW + 60, "x-nvidia-overall-att-result": true} -> Ok(("k1", claims))
#[test] fn a_token_signed_by_another_key_is_refused()  // signed by B, JWKS has A under k1 -> Err contains "signature"
#[test] fn an_unknown_kid_is_refused()                  // Err contains "kid"
#[test] fn any_alg_but_es384_is_refused()               // "ES256", "none", "HS384" -> Err contains "alg"
#[test] fn an_edited_payload_is_refused()               // swap the middle segment for another claims set -> Err
#[test] fn an_expired_or_unexpiring_token_is_refused()  // exp = NOW - 1, and no exp -> Err contains "exp"
#[test] fn a_jwks_key_on_another_curve_is_refused()     // crv "P-256" -> Err
#[test] fn the_verifier_posts_the_payload_verbatim_and_needs_a_true_verdict() {
    // FakeHttp: POST NRAS_ATTEST_URL -> 200 [["JWT", token]], GET NRAS_JWKS_URL -> 200 jwks.
    // payload = format!(r#"{{"nonce":"{}","arch":"HOPPER","evidence_list":[]}}"#, nonce())
    // Ok(GpuVerdict { kid: "k1", overall: true }); http.bodies()[0] == payload.as_bytes(); no bearer sent.
    // Verdict false -> Err contains "x-nvidia-overall-att-result". NRAS 500 -> Err contains "NRAS".
}
#[test] fn a_payload_for_another_nonce_is_refused_before_any_request() // Err contains "nonce"; http.calls() is empty
```

- [ ] **Step 3: Run, expect FAIL** — `T --lib attest::nras` fails to compile with `error[E0432]: unresolved import` for `nras` items.

- [ ] **Step 4: Implement `nras.rs`.**

- [ ] **Step 5: Run, expect PASS** — `T --lib attest::nras`, then `T --lib`: baseline five failures only. `git diff Cargo.lock` adds no package.

- [ ] **Step 6: Commit** — `git add Cargo.toml Cargo.lock src/attest.rs src/attest/nras.rs tests/fixtures/nras && git commit -m "Verify NVIDIA NRAS GPU verdicts and their ES384 signatures"`

---

### Task 4: Attestation report, policies, attestation.json, and the connect hook

**Files:**
- Create: `src/attest/report.rs`, `src/attest/record.rs`, `opencode/attestation-policy.json`
- Modify: `src/attest.rs` (orchestration, options, policy), `src/inference.rs` (`NEAR_BASE_URL`), `src/session.rs` (session ID chosen by the caller), `src/main.rs` (flags, connect)

**Interfaces:**
- Consumes: Tasks 2 and 3 (`Http`, `Clock`, `QuoteVerifier`, `PcsQuoteVerifier`, `tcb_policy`, `GpuVerifier`, `NrasGpuVerifier`), `protocol::random_hex` (`src/protocol.rs:24`), `run_connected` (`src/main.rs:91-106`), `auth::InferenceCredential { key: HostSecret, .. }` (`src/auth.rs:25`).
- Produces (`src/attest/report.rs`), the report shape from `ts/model_verifier.ts:20-37,176-182`:

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReportResponse { pub gateway_attestation: Option<Evidence>, pub model_attestations: Option<Vec<Evidence>> }
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Evidence {
    pub intel_quote: String, pub signing_address: String, pub signing_algo: String,
    pub tls_cert_fingerprint: Option<String>, pub nvidia_payload: Option<String>,
    pub info: Option<serde_json::Value>, pub model_name: Option<String>,
}
pub fn report_url(base: &str, model: &str, nonce: &[u8; 32]) -> String;
pub fn hex32(s: &str) -> Result<[u8; 32], String>;
/// ed25519 only for model entries: `signing_algo == "ed25519"` and a 32-byte hex key.
pub fn ed25519_key(e: &Evidence) -> Result<[u8; 32], String>;
/// [32..64] == nonce. With a fingerprint: [0..32] == sha256(addr_bytes || fp_bytes), where addr_bytes is
/// `signing_address` hex-decoded (a leading 0x stripped for ecdsa). Without: [0..32] == the 32-byte address.
pub fn check_report_data(report_data: &[u8; 64], e: &Evidence, nonce: &[u8; 32]) -> Result<(), String>;
/// `info.tcb_info` as a JSON string or object; returns its `app_compose` string.
pub fn app_compose(info: Option<&serde_json::Value>) -> Result<String, String>;
/// mr_config_id[0] == 0x01 and [1..33] == sha256(app_compose); under Pinned the hash must be in the policy.
pub fn check_compose(mr_config_id: &[u8; 48], app_compose: &str, policy: &Policy, mode: ComposePolicy) -> Result<[u8; 32], String>;
```

  `report_url` gives `{base}/attestation/report?model=<percent-encoded>&nonce=<64 lowercase hex>&signing_algo=ed25519&provider=near&include_tls_fingerprint=true` (encode with `url::form_urlencoded::byte_serialize`; `url` is already direct).

- Produces (`src/attest.rs`):

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComposePolicy { Pinned, MrConfigOnly }
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AttestOptions { pub allow_tcb_out_of_date: bool, pub compose_policy: ComposePolicy, pub allow_unattested_provider: bool }
impl Default for AttestOptions // false, Pinned, false
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy { pub compose_hashes: BTreeSet<[u8; 32]> }
pub const POLICY_JSON: &str = include_str!("../opencode/attestation-policy.json");
pub fn load_policy(json: &str) -> Result<Policy, String>;
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Attested {
    pub fingerprints: BTreeSet<[u8; 32]>,
    pub keys: BTreeMap<String, BTreeSet<[u8; 32]>>,
    pub evidence: Vec<serde_json::Value>, // per model: nonce, raw report, per-entry tcb status, compose hash, gpu kid
}
impl Attested { pub fn merge(&mut self, other: Attested); }
pub type Nonce = Arc<dyn Fn() -> [u8; 32] + Send + Sync>;
pub struct Attestor {
    pub http: Arc<dyn Http>, pub clock: Arc<dyn Clock>,
    pub quotes: Arc<dyn QuoteVerifier>, pub gpus: Arc<dyn GpuVerifier>,
    pub base_url: String, pub key: HostSecret, pub models: Vec<String>,
    pub options: AttestOptions, pub policy: Policy, pub nonce: Nonce,
}
impl Attestor {
    /// BlockingHttp, SystemClock, PcsQuoteVerifier, NrasGpuVerifier, NEAR_BASE_URL, POLICY_JSON, /dev/urandom nonces.
    pub fn real(key: HostSecret, models: &[String], options: AttestOptions) -> Result<Attestor, String>;
    pub fn attest(&self) -> Result<Attested, String>;
}
```

  `attest`, per model, in this order, each refusing with a message that names the model and the check: fresh nonce; `GET report_url` with the bearer; status 200 (error carries the status, never the key); parse; `gateway_attestation` present with `tls_cert_fingerprint`; `model_attestations` non-empty; for the gateway and every model entry: decode `intel_quote` hex, `quotes.verify(quote, clock.now_unix())`, `tcb_policy`, `check_report_data`, `app_compose` and `check_compose`; for every model entry also `ed25519_key` and `gpus.verify(nvidia_payload, nonce_hex)` (a missing `nvidia_payload` refuses). Fingerprints come from the gateway entries (and from model entries that carry one); keys go under the requested model ID.

- Produces (`src/attest/record.rs`):

```rust
pub struct AttestationRecord { path: PathBuf, doc: Mutex<serde_json::Value> }
impl AttestationRecord {
    /// Creates sessions/<id>/ (0700) and attestation.json (0600) with
    /// {"session": id, "status": "pending", "overrides": options}.
    pub fn create(sessions_dir: &Path, session_id: &str, options: &AttestOptions) -> Result<Arc<Self>, String>;
    pub fn path(&self) -> &Path;
    pub fn session_dir(&self) -> &Path;
    pub fn verified(&self, a: &Attested) -> Result<(), String>;   // status "verified", fingerprints and keys as hex, evidence
    pub fn reattested(&self, a: &Attested) -> Result<(), String>; // appends to "reattestations"
    pub fn set_status(&self, status: &str, reason: &str);          // "refused", "pin-failed", "model-refused", "signature-failed", "unattested-provider"
}
```

  Every write goes to a temp file in the same directory, then `rename`.

- Produces elsewhere: `pub const NEAR_BASE_URL: &str = "https://cloud-api.near.ai/v1";` in `src/inference.rs`, used by `start` (`src/inference.rs:69`). In `src/session.rs`: `pub fn new_session_id() -> String` (`random_hex(6)`) and `pub session_id: Option<String>` on `Deps`; `run_session` uses it when set (`src/session.rs:476`); `Deps::real(session_id: String)`. In `src/main.rs`: `Action::Launch { file, login, attest: attest::AttestOptions }`, flags `--allow-tcb-out-of-date` (boolean) and `--compose-policy <pinned|mr-config-only>` (value), accepted for `launch` only. The parser (`src/main.rs:42-83`) takes the boolean before the value lookup.
- `opencode/attestation-policy.json`: `{"composeHashes": []}`. Entries have the form `{"sha256": "<64 hex>", "recorded": "<date>", "source": "<where it was seen>"}`; check 6 adds the first ones. The file is compiled in, so changing it needs a rebuild.

- [ ] **Step 1: Write the failing tests.**

  `src/attest/report.rs`, pure functions on constructed inputs:

```rust
#[test] fn report_url_asks_for_ed25519_near_and_the_tls_fingerprint() // exact string for model "org/m 1", nonce [0xab; 32]
#[test] fn report_data_must_bind_key_fingerprint_and_nonce() {
    // e = Evidence { signing_address: hex(key), signing_algo: "ed25519", tls_cert_fingerprint: Some(hex(fp)), .. }
    // good = sha256(key || fp) || nonce -> Ok
    // flip one bit in either half -> Err; other fp in e -> Err contains "does not bind"
    // nonce half from another nonce -> Err contains "nonce"
    // no fingerprint: [0..32] == key -> Ok; == sha256(key || fp) -> Err
    // ecdsa address "0x" + 40 hex with fingerprint -> sha256(20 bytes || fp) accepted (gateway mode)
}
#[test] fn compose_must_match_mr_config_and_the_pinned_list() {
    // mr = 01 || sha256(c) || zeros: Pinned with hash listed -> Ok(hash); not listed -> Err contains "attestation-policy.json";
    // MrConfigOnly not listed -> Ok; mr starting 02 -> Err contains "mr_config_id" under both modes;
    // hash of another compose -> Err.
}
#[test] fn app_compose_reads_tcb_info_as_string_or_object() // both forms; missing info / tcb_info / app_compose -> Err
#[test] fn model_entries_must_be_ed25519_with_a_32_byte_key() // "ecdsa", 31 bytes, non-hex -> Err
```

  `src/attest.rs`, the orchestration with fakes. `FakeQuotes` maps quote bytes to `TdxClaims`; `FakeGpu` returns a configured result and records `(payload, nonce)`; the nonce closure returns `[1; 32]`, then `[2; 32]`, and so on. A builder makes a good report for model `m`: gateway quote bytes `b"gw"` whose claims carry `sha256(gw_addr || FP) || nonce`; model quote bytes `b"m0"` whose claims carry `KEY || nonce` (no model fingerprint); both with `mr_config_id = 01 || sha256(COMPOSE) || 0..` and status `UpToDate`; the policy lists `sha256(COMPOSE)`.

```rust
#[test] fn a_good_report_yields_the_fingerprint_and_model_keys() {
    // Ok; fingerprints == {FP}; keys == {"m": {KEY}}; http.calls() == ["GET " + report_url(BASE, "m", &[1; 32])];
    // http.bearers() == [true]; gpu saw (payload, hex([1; 32])).
}
#[test] fn every_allowed_model_gets_its_own_request_and_nonce() // models ["m", "n"] -> two calls, nonces [1;32] and [2;32]
#[test] fn each_tampered_report_is_refused() {
    // One mutation per case, Err must contain the phrase:
    // no gateway_attestation -> "gateway_attestation"; gateway without tls_cert_fingerprint -> "tls_cert_fingerprint";
    // empty model_attestations -> "model_attestations"; quote verifier Err -> "TDX quote";
    // report_data nonce half wrong -> "nonce"; report_data bound to another fingerprint -> "does not bind";
    // status "OutOfDate" -> "--allow-tcb-out-of-date"; status "Revoked" -> "Revoked";
    // mr_config_id prefix 02 -> "mr_config_id"; compose not pinned -> "attestation-policy.json";
    // GPU Err -> "GPU"; no nvidia_payload -> "nvidia_payload"; model signing_algo ecdsa -> "ed25519";
    // HTTP 401 -> "HTTP 401", and the error does not contain DUMMY_KEY; body not JSON -> "report".
}
#[test] fn the_overrides_accept_out_of_date_and_unpinned_compose() // with options set: Ok, evidence records "OutOfDate" and the unpinned hash
#[test] fn the_committed_policy_parses_and_bad_entries_are_refused() // load_policy(POLICY_JSON) Ok; bad hex, 31 bytes, unknown field -> Err
```

  `src/attest/record.rs`: `create` makes a 0700 directory and a 0600 file with status `pending` and the overrides; `verified` writes hex fingerprints and keys; `set_status("refused", "x")` keeps the earlier content and sets `status` and `reason`; no file under the session directory contains `DUMMY_KEY`; no `*.tmp` file is left behind.

  `src/main.rs`: `launch --allow-tcb-out-of-date --compose-policy mr-config-only` parses into the options; `--compose-policy other`, `--compose-policy` with no value, a duplicate flag, and `login --allow-tcb-out-of-date` are refused (extend `malformed_arguments_fail_before_config_or_credentials_are_touched`).

  `src/session.rs`: `run_session` with `Deps { session_id: Some("0123456789ab".into()), .. }` writes its log under `sessions/0123456789ab/` (reuse `a_session_refuses_before_any_vm_exists_when_opencode_is_the_wrong_version`'s setup).

- [ ] **Step 2: Run, expect FAIL** — `T --lib attest main session` fails to compile with `error[E0432]: unresolved import \`crate::attest::report\`` and missing `Attestor`, `AttestOptions`, `new_session_id`.

- [ ] **Step 3: Implement** the three modules, the policy file, `NEAR_BASE_URL`, the session ID plumbing and the flags. Then wire `connect` in `launch`:

```rust
let session_id = session::new_session_id();
let deps = session::Deps::real(session_id.clone())?;
run_connected(&mut cfg, local_preflight, |cfg| {
    let credential = auth::load_or_login(login)?;
    let record = attest::record::AttestationRecord::create(&cfg.sessions_dir, &session_id, &attest)?;
    let attestor = attest::Attestor::real(credential.key.clone(), &cfg.provider.models, attest)?;
    let attested = attestor.attest().map_err(|e| {
        record.set_status("refused", &e);
        format!("attestation failed: {e} (see {})", record.path().display())
    })?;
    record.verified(&attested)?;
    let inference = inference::start(credential.key, &cfg.provider.models)?;
    Ok((inference.provider(), inference))
}, |cfg| session::run_session(cfg, deps))
```

  This step attests but still lets IronWire reach NEAR AI directly; Task 5 inserts the forwarder.

- [ ] **Step 4: Run, expect PASS** — `T --lib`: baseline five failures only; `bun test tests/unit` passes.

- [ ] **Step 5: Commit** — `git add src opencode/attestation-policy.json && git commit -m "Attest NEAR AI before every session and record attestation.json"`

---

### Task 5: The pinned forwarder

**Files:**
- Modify: `Cargo.toml` (`rustls`, `rustls-native-certs`, `hyper`, `hyper-util`, `http-body-util`, `bytes` as in Global Constraints)
- Create: `src/forwarder.rs`, `src/forwarder/pin.rs`
- Create: `tests/fixtures/tls/ca.pem`, `a.pem`, `a.key`, `b.pem`, `b.key`, `c.pem`, `c.key`
- Modify: `src/lib.rs` (`pub mod forwarder;`), `src/inference.rs` (`start_with_endpoint` becomes `pub`), `src/session.rs` (fatal polling), `src/main.rs` (wiring, environment and external-provider refusals, `--allow-unattested-provider`)
- Modify: `tests/contain/session.rs` (`sigint_to_the_launcher_exports_out_and_leaves_no_rts_machine`, around line 221, runs `rts launch` against a fake external IronWire via `provider.baseURL`; add `--allow-unattested-provider` to its args, or it is refused by the new check)

**Interfaces:**
- Consumes: `Attested`, `Attestor::attest`, `AttestationRecord` (Task 4); `inference::start_with_endpoint(key, models, endpoint)` (`src/inference.rs:99`); `rustls::client::WebPkiServerVerifier`; `reqwest::ClientBuilder::use_preconfigured_tls` (reqwest 0.12.28, `src/async_impl/client.rs:2158`).
- Produces (`src/forwarder/pin.rs`):

```rust
pub fn spki_sha256(cert: &CertificateDer<'_>) -> Option<[u8; 32]>; // was sha256_der(leaf DER); production attests the SPKI hash (2026-10-29)
pub struct PinSet { /* RwLock<BTreeSet<[u8; 32]>>, Mutex<Option<[u8; 32]>> last unknown */ }
impl PinSet {
    pub fn new(seed: BTreeSet<[u8; 32]>) -> Arc<Self>;
    pub fn extend(&self, more: &BTreeSet<[u8; 32]>);
    pub fn contains(&self, fp: &[u8; 32]) -> bool;
    pub fn take_unknown(&self) -> Option<[u8; 32]>;
}
#[derive(Debug)]
pub struct PinnedVerifier { /* Arc<WebPkiServerVerifier>, Arc<PinSet> */ }
impl rustls::client::danger::ServerCertVerifier for PinnedVerifier // webpki first, then the pin; signature checks delegate
pub fn native_roots() -> Result<Arc<rustls::RootCertStore>, String>;
/// ring provider, PinnedVerifier, `resumption = Resumption::disabled()`, no ALPN (HTTP/1.1).
pub fn pinned_tls(roots: Arc<rustls::RootCertStore>, pins: Arc<PinSet>) -> Result<rustls::ClientConfig, String>;
```

- Produces (`src/forwarder.rs`):

```rust
pub struct Fatal { /* OnceLock<String> */ }
impl Fatal { pub fn new() -> Arc<Self>; pub fn raise(&self, reason: impl Into<String>); pub fn reason(&self) -> Option<String>; }
pub type Reattest = Arc<dyn Fn() -> Result<Attested, String> + Send + Sync>;
pub struct ForwarderConfig {
    pub upstream: String,              // "https://cloud-api.near.ai/v1"; tests use https://127.0.0.1:<port>/v1
    pub models: Vec<String>,
    pub roots: Arc<rustls::RootCertStore>,
    pub seed: Attested,
    pub reattest: Reattest,            // called with tokio::task::spawn_blocking
    pub fatal: Arc<Fatal>,
    pub record: Arc<AttestationRecord>,
    pub max_request_bytes: usize,      // 32 MiB
}
pub struct Forwarder { /* port, shutdown sender, finished receiver, worker thread, as EmbeddedInference */ }
impl Forwarder {
    pub fn start(cfg: ForwarderConfig) -> Result<Forwarder, String>;
    pub fn base_url(&self) -> String;  // "http://127.0.0.1:<port>/v1"
}
impl Drop for Forwarder
```

  Behavior: only `POST /v1/chat/completions` is forwarded; any other method or path is 404 without contacting upstream. After `fatal` is raised, every request gets 502 without contacting upstream. The body is read up to `max_request_bytes` (413 beyond), parsed only to read `model` (400 if it is not a JSON object with a string `model`). A model not in `models` gets 403, `record.set_status("model-refused", ..)` and `fatal.raise(..)`, with no upstream connection. Otherwise the original bytes go to `{upstream}/chat/completions` with the inbound `Authorization`, `Content-Type` and `Accept` headers only, plus `Accept-Encoding: identity`. The response status, `Content-Type` and body are relayed as a stream. On a send error, if `PinSet::take_unknown()` is set: under a mutex, call `reattest` up to three times, merging fingerprints into the `PinSet` and recording each with `record.reattested`, until the unknown fingerprint is known; then retry the request once. If it is still unknown, return 502 with `record.set_status("pin-failed", ..)` and `fatal.raise(..)`. Other send errors return 502 without being fatal; Task 6 makes broken streams fatal.

- Produces elsewhere: `pub fn stop_reason(fatal: Option<&Fatal>) -> Option<String>` in `src/session.rs`, and `pub fatal: Option<Arc<forwarder::Fatal>>` on `Deps`; the session loop (`src/session.rs:617-632`) checks it beside `interrupted` and returns `Err(reason)`, which reaches the existing teardown. In `src/main.rs`: `fn check_launch(cfg: &config::OperatorConfig, env: &[(String, String)], opts: &attest::AttestOptions) -> Result<(), String>` refuses `IRONWIRE_NEARAI_BASE_URL` in `env` (even if empty), the placeholder models, and `!cfg.embedded_inference && !opts.allow_unattested_provider`. The new boolean flag is `--allow-unattested-provider`. When an external provider is allowed, `launch` writes `attestation.json` with status `unattested-provider` and the provider's `baseURL`. Also `struct Connected { _inference: inference::EmbeddedInference, _forwarder: forwarder::Forwarder }`, with the fields in that order.

- [ ] **Step 1: Generate the TLS fixtures** (commands checked with OpenSSL 4.1.0 on 2026-10-28; certificates valid ten years; `ca.key` is deleted so nothing can sign more):

```sh
cd tests/fixtures/tls
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.pem -days 3650 \
  -subj "/CN=rts test CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
printf "subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n" > ext.cnf
for n in a b; do
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout $n.key -out $n.csr -subj "/CN=127.0.0.1"
  openssl x509 -req -in $n.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out $n.pem -days 3650 -extfile ext.cnf
done
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout c.key -out c.pem -days 3650 \
  -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1"
rm -f ca.key ca.srl ext.cnf a.csr b.csr
openssl verify -CAfile ca.pem a.pem b.pem   # a.pem: OK, b.pem: OK
```

- [ ] **Step 2: Write the failing tests.** A test upstream helper in `src/forwarder.rs` tests runs a blocking `rustls::ServerConnection` over `std::net::TcpListener` on `127.0.0.1:0` in a thread, presenting `a`, `b` or `c`. It records each handshake's `handshake_kind()` and each full HTTP request (headers and body), and answers through a closure. Roots for the forwarder are a `RootCertStore` holding `ca.pem`. The test client is `reqwest::blocking` against `forwarder.base_url()`.

```rust
#[test] fn a_pinned_upstream_gets_the_exact_bytes_and_the_key() {
    // seed {fp(a)}; POST /v1/chat/completions, Authorization: Bearer DUMMY_KEY, body br#"{"model":"m","messages":[],"stream":false}"#
    // upstream saw "POST /v1/chat/completions", "authorization: Bearer DUMMY_KEY", "accept-encoding: identity",
    // and exactly those body bytes; the client got the upstream's status and body byte for byte.
}
#[test] fn an_unpinned_certificate_never_sees_a_request_and_ends_the_session() {
    // upstream presents b; seed {fp(a)}; reattest returns {fp(a)} -> 502; reattest called 3 times;
    // upstream recorded no request; fatal.reason() contains "pin"; attestation.json status "pin-failed";
    // a second request -> 502 with no new handshake and no new reattest call.
}
#[test] fn a_rotated_certificate_is_accepted_after_one_reattestation() {
    // upstream b; seed {fp(a)}; reattest returns {fp(b)} -> 200; reattest called once; attestation.json has one reattestation.
}
#[test] fn a_pinned_certificate_from_an_untrusted_ca_is_refused() // upstream c (self-signed), seed {fp(c)}, reattest returns {fp(c)} -> 502, fatal
#[test] fn every_upstream_handshake_is_full() // upstream closes each connection; two requests -> two handshakes, both HandshakeKind::Full
#[test] fn a_model_outside_the_allowlist_gets_403_and_no_connection() // model "other" -> 403; zero handshakes; fatal "model-refused"
#[test] fn only_chat_completions_is_forwarded() // GET /v1/models, POST /v1/responses, GET /v1/signature/x -> 404; zero handshakes; not fatal
#[test] fn malformed_or_oversized_requests_are_refused_locally() // not JSON -> 400; no model -> 400; max_request_bytes + 1 -> 413; zero handshakes
#[test] fn ironwire_reaches_near_ai_only_through_the_forwarder() {
    // forwarder to TLS upstream a; inference::start_with_endpoint(DUMMY_KEY, &["m"], &forwarder.base_url());
    // POST to IronWire's provider base_url + "/chat/completions" with x-ironwire-route (as src/inference.rs:416-420 does)
    // -> upstream saw POST /v1/chat/completions with "authorization: Bearer DUMMY_KEY" and model "m".
}
```

  `src/main.rs`: `check_launch` refuses `IRONWIRE_NEARAI_BASE_URL=x` and `IRONWIRE_NEARAI_BASE_URL=` with a message naming the variable; an external provider config (`provider.id` and `provider.baseURL`) is refused without the flag and accepted with it; `launch --allow-unattested-provider` parses.
  `src/session.rs`: `stop_reason(Some(&f))` is `None` until `f.raise("signature-failed: x")`, then returns that reason; `stop_reason(None)` is `None`.

- [ ] **Step 3: Run, expect FAIL** — `T --lib forwarder main session` fails to compile with `error[E0433]: failed to resolve: could not find \`forwarder\` in the crate root`.

- [ ] **Step 4: Implement.** The forwarder's worker thread owns a two-thread Tokio runtime, binds `127.0.0.1:0` and serves with `hyper::server::conn::http1` over `hyper_util::rt::TokioIo`. The upstream client is `reqwest::Client::builder().use_preconfigured_tls(pin::pinned_tls(roots, pins)?).no_proxy().redirect(Policy::none()).http1_only()`, built once. Response bodies are relayed with `http_body_util::StreamBody` fed from `Response::chunk()`. Then wire `connect`:

```rust
let fatal = forwarder::Fatal::new();               // in launch, also passed in Deps
// inside connect, after record.verified(&attested)?:
let attestor = Arc::new(attestor);
let forwarder = forwarder::Forwarder::start(forwarder::ForwarderConfig {
    upstream: inference::NEAR_BASE_URL.into(),
    models: cfg.provider.models.clone(),
    roots: forwarder::pin::native_roots()?,
    seed: attested,
    reattest: { let a = attestor.clone(); Arc::new(move || a.attest()) },
    fatal: fatal.clone(),
    record: record.clone(),
    max_request_bytes: 32 << 20,
})?;
let inference = inference::start_with_endpoint(credential.key, &cfg.provider.models, &forwarder.base_url())?;
Ok((inference.provider(), Connected { _inference: inference, _forwarder: forwarder }))
```

  `launch` calls `check_launch(&cfg, &std::env::vars().collect::<Vec<_>>(), &attest)?` before anything else.

- [ ] **Step 5: Run, expect PASS** — `T --lib`: baseline five failures only. `git diff Cargo.lock` adds no package.

- [ ] **Step 6: Commit** — `git add Cargo.toml Cargo.lock src tests/fixtures/tls && git commit -m "Route NEAR AI inference through a pinned forwarder"`

---

### Task 6: Per-response signatures, fatal teardown, inference.jsonl

**Files:**
- Modify: `Cargo.toml` (`ed25519-dalek = "2.2.0"`)
- Create: `src/forwarder/signature.rs`
- Modify: `src/forwarder.rs` (hash while relaying, verify after each completion, keys in the shared state)

**Interfaces:**
- Consumes: Task 5's forwarder, `PinSet`, `Fatal`, `Reattest`, `AttestationRecord::set_status` and `session_dir`; `Attested.keys`; `ed25519_dalek::{VerifyingKey, Signature}`; `sha2::Sha256` (already direct).
- Produces:

```rust
/// As ironwire_upstream::receipt::RawReceipt (ironwire bf8b90b).
#[derive(Debug, Clone, Deserialize)]
pub struct Receipt { pub text: String, pub signature: String, pub signing_address: String, pub signing_algo: String,
                     #[serde(default)] pub signature_kind: Option<String> }
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exchange { pub model: String, pub chat_id: String, pub streamed: bool,
                      pub request_sha256: [u8; 32], pub response_sha256: [u8; 32] }
pub fn usable_id(id: &str) -> bool; // non-empty, <= 128 bytes, [A-Za-z0-9_-] (ironwire receipt.rs usable_id)
pub fn chat_id_from_json(body: &[u8]) -> Option<String>;
#[derive(Debug, Default)]
pub struct SseId { /* partial line buffer, first id */ }
impl SseId { pub fn push(&mut self, chunk: &[u8]); pub fn id(&self) -> Option<&str>; }
/// ed25519 only; text is "<model>:<req>:<resp>" (model must equal ex.model) or "<req>:<resp>";
/// both hashes equal; key in `keys`; verify_strict. Returns the key.
pub fn check_receipt(r: &Receipt, ex: &Exchange, keys: &BTreeSet<[u8; 32]>) -> Result<[u8; 32], String>;
#[derive(Debug, Clone, Copy)]
pub struct SignaturePolicy { pub window: Duration, pub first_backoff: Duration, pub max_backoff: Duration }
impl Default for SignaturePolicy // 10 s, 250 ms, 2 s
/// GET {upstream}/signature/{chat_id}?model=<id>&signing_algo=ed25519 with `authorization`.
/// 404, 429 and 5xx retry with doubling backoff until `window`; other non-2xx fail at once;
/// a body over 16 KiB or not a Receipt fails.
pub async fn fetch_receipt(client: &reqwest::Client, upstream: &str, authorization: &reqwest::header::HeaderValue,
                           ex: &Exchange, policy: SignaturePolicy) -> Result<(Receipt, Duration), String>;
#[derive(Debug, Serialize)]
pub struct InferenceLine { pub ts: u64, pub chat_id: String, pub model: String, pub streamed: bool,
                           pub request_sha256: String, pub response_sha256: String,
                           pub signing_key: Option<String>, pub signature_ms: Option<u64>, pub result: String }
pub fn append_inference_line(path: &Path, line: &InferenceLine) -> std::io::Result<()>; // 0600, O_APPEND
```

  `ForwarderConfig` gains `pub signatures: SignaturePolicy` and `pub inference_log: PathBuf` (`record.session_dir().join("inference.jsonl")` in `connect`). The relay hashes the request bytes it sent and every response chunk as it is relayed. If the client goes away mid-stream it keeps reading upstream to the end, so the hash covers the whole response. For `text/event-stream` responses, `SseId` takes the `id` of the first `data:` event that is JSON; otherwise the body is also kept (cap 16 MiB) for `chat_id_from_json`. After the response ends, a spawned task fetches and checks the receipt; it does not delay other requests. If the key is not attested for the model, it calls `reattest` once, merges the keys, and checks again. Results:
  - 2xx with a verified receipt: an `inference.jsonl` line with result `verified`.
  - Non-2xx upstream: a line with result `not-signed (HTTP <code>)`; not fatal.
  - Anything else is fatal: no usable chat ID, a stream error, a response over the cap, a fetch failure or timeout, or a failed check. The line gets result `failed: <reason>`, `record.set_status("signature-failed", reason)` is called, and then `fatal.raise(..)`.

- [ ] **Step 1: Write the failing tests.** Keys come from `ed25519_dalek::SigningKey::from_bytes(&[9; 32])`.

```rust
// src/forwarder/signature.rs
#[test] fn the_chat_id_comes_from_json_or_the_first_sse_data_event() {
    // chat_id_from_json(br#"{"id":"chatcmpl-1","object":"chat.completion"}"#) == Some("chatcmpl-1"); no id / not JSON -> None
    // SseId fed ": ping\n\n", "data: {\"id\":\"c", "1\",\"choices\":[]}\n\n", "data: {\"id\":\"c2\"}\n\n", "data: [DONE]\n\n" -> "c1"
    // usable_id("../attestation/report") == false, usable_id("chatcmpl-abc_1") == true
}
#[test] fn a_good_receipt_verifies_in_both_text_forms() // "m:<req>:<resp>" and "<req>:<resp>" -> Ok(key)
#[test] fn each_bad_receipt_is_refused() {
    // model part "n" -> "model"; request hash off by one hex digit -> "request"; response hash wrong -> "response";
    // key not in set -> "not attested"; signature over other text -> "signature"; signing_algo "ecdsa" -> "ed25519";
    // four-part text -> "text"; non-hex signature -> Err; small-order key [1, 0, .., 0] in the set with sig of zeros -> Err.
}
#[tokio::test] async fn fetch_retries_404_inside_the_window_and_fails_after_it() {
    // plain-HTTP local server: 404, 404, then a receipt -> Ok after 3 GETs; always 404 with window 300 ms,
    // backoff 10..50 ms -> Err contains "no signature within"; 401 -> Err after exactly 1 GET.
}

// src/forwarder.rs, with the Task 5 TLS upstream answering both the completion and /v1/signature/<id>,
// signing sha256(request body received) and sha256(response body sent) with the test key:
#[test] fn a_verified_completion_is_logged_and_the_session_continues()  // non-streamed: one inference.jsonl line, result "verified", fatal None
#[test] fn a_verified_stream_is_logged_and_was_not_buffered() {
    // SSE in 3 chunks with a 200 ms pause before the last; the client reads the first chunk before the upstream
    // sends the last; inference.jsonl line streamed true, result "verified".
}
#[test] fn a_wrong_receipt_ends_the_session() {
    // receipt over another response hash -> within 2 s fatal.reason() contains "signature";
    // attestation.json status "signature-failed"; the line result starts "failed:"; the next request -> 502, no handshake.
}
#[test] fn a_receipt_that_never_arrives_ends_the_session() // signature route always 404, window 300 ms -> fatal
#[test] fn an_unattested_key_is_reattested_once() // reattest adds the key -> verified, reattest called once; reattest without it -> fatal
#[test] fn a_non_2xx_answer_is_relayed_and_logged_unsigned() // upstream 429 -> client 429, line "not-signed (HTTP 429)", fatal None
#[test] fn the_logs_never_hold_the_key() // after the cases above, inference.jsonl and attestation.json do not contain DUMMY_KEY
```

  Use `#[tokio::test]` only if `tokio`'s `macros` feature is already enabled in the graph (`cargo tree -e features -i tokio`); otherwise build a current-thread runtime by hand in the test.

- [ ] **Step 2: Run, expect FAIL** — `T --lib forwarder` fails to compile with `error[E0432]: unresolved import \`crate::forwarder::signature\``.

- [ ] **Step 3: Implement** `signature.rs` and the relay changes in `forwarder.rs`.

- [ ] **Step 4: Run, expect PASS** — `T --lib`: baseline five failures only. `git diff Cargo.lock` adds no package.

- [ ] **Step 5: Commit** — `git add Cargo.toml Cargo.lock src && git commit -m "Verify every NEAR AI response signature and end the session on failure"`

---

### Task 7: Opt-in live test against NEAR AI staging

Blocked until check 6 has the staging base URL, the private model IDs and a key for staging. Do not guess them; if they are not available, stop and ask Zaki.

**Files:**
- Create: `tests/live_attest.rs` (its own test target; every test `#[ignore]`)
- Modify: `opencode/README.md` (how to run it, and the facts recorded by check 6)

**Interfaces:**
- Consumes: the public API from Tasks 2 to 6: `attest::Attestor` (fields are public, so the test sets `base_url` to staging), `attest::http::{BlockingHttp, SystemClock}`, `attest::tdx::PcsQuoteVerifier`, `attest::nras::NrasGpuVerifier`, `attest::record::AttestationRecord`, `forwarder::{Forwarder, ForwarderConfig, Fatal}`, `forwarder::pin::native_roots`, `inference::start_with_endpoint`, `inference::route_header`.
- Environment: `RTS_LIVE_NEAR_BASE_URL` (https), `RTS_LIVE_NEAR_MODELS` (comma-separated exact IDs), `RTS_LIVE_NEAR_API_KEY`; optional `RTS_LIVE_SAVE_DIR` to save each raw report as a fixture. Each test prints why and returns when any required variable is unset.

- [ ] **Step 1: Write the tests.**
  - `staging_attestation_verifies_for_every_model`: real PCS, NRAS and staging; prints each entry's TCB status, compose hash and fingerprint; saves reports when `RTS_LIVE_SAVE_DIR` is set. Asserts no PCS, CRL or NRAS call needed a redirect (`BlockingHttp` follows none).
  - `staging_completions_verify_through_ironwire_and_the_forwarder`: one non-streamed and one streamed completion per model through IronWire, then the forwarder, then staging. Within 15 s, `inference.jsonl` has a `verified` line for each, and the test prints `signature_ms` for each (check 6's latency measurement). `fatal` stays unset.
  - `a_wrong_pin_is_refused_against_staging`: a forwarder seeded with `[0; 32]` and a `reattest` that returns `[0; 32]` again -> 502, and `fatal` is raised.

- [ ] **Step 2: Run without the environment** — `T --test live_attest -- --ignored` prints the skip reason for each test and passes.

- [ ] **Step 3: Run against staging** — `RTS_LIVE_NEAR_BASE_URL=... RTS_LIVE_NEAR_MODELS=... RTS_LIVE_NEAR_API_KEY=... T --test live_attest -- --ignored --nocapture --test-threads=1`. Paste the output into the PR. Record the compose hashes in `opencode/attestation-policy.json`, the model IDs in place of `MODEL_ID_PLACEHOLDER`, and the measured signature latency in check 6 (spec), each in its own commit.

- [ ] **Step 4: Commit** — `git add tests/live_attest.rs opencode/README.md && git commit -m "Add an opt-in live attestation test against NEAR AI staging"`

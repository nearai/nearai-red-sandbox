# Signed attestation policy feed: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `rts` admits NEAR AI composes endorsed by a policy document our CI
signs. CI signs a compose only when it passes strict content rules against
reviewed baselines, so a new build or GPU host no longer needs an `rts`
release.

**Architecture:**
- **Python rules module.** A stdlib-only Python module holds the content
  rules and the normalization. It runs in CI twice: once in an unprivileged
  `evaluate` job, and again in the `sign` job, which alone holds the key.
- **Rust verifier in `rts`.** It verifies the document against two
  compiled-in Ed25519 keys and caches it. It merges the document into a
  role-aware `Policy`, which `check_compose` consults after revocations and
  pins.
- **Shared test vector.** Both languages normalize one test vector to the
  same hash.

**Tech Stack:**
- Rust: `ed25519-dalek`, `serde_json`, `sha2`, `hex`, `base64`, and the
  `reqwest` already used by `setup::download`.
- Python 3: stdlib only, tests with `pytest` as `scripts/` already does.
- GitHub Actions, with OpenSSL 3 and `cosign` in CI.

**Spec:** `docs/specs/2026-11-24-signed-attestation-policy-feed-design.md`. Read it
first. Its "Validation against real redeploys" table is the rules' acceptance
test.

## Global Constraints

- No new Rust or Python dependencies. Python scripts are stdlib only and run with `python3 -I`.
- Every cargo command uses `RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0` (already set globally; do not override).
- Builds go through `~/.claude/turn-locks/turn.sh build "<label>" -- <cmd>`. Whole-crate `cargo test` goes through `turn.sh test`. A filtered test run (`cargo test --lib attest::feed`) is light: no lock, add `-- --test-threads=2`.
- Commits are signed (`git commit -S`). The nearai org rejects unsigned commits.
- Feed URLs: `https://github.com/nearai/nearai-red-sandbox/releases/download/attestation-policy/{production,staging}.json` and the same path with `.json.sig`.
- Caps: document 256 KiB (262144 bytes), signature 1 KiB (1024 bytes).
- Validity: `expires` = `issued` + 72 h when signed. `rts` accepts `expires - issued` <= 7 days, and `issued` <= now + 300 s.
- Fetch bound 5 s at launch. Re-fetch in re-attestation when the cached document is older than 3600 s.
- Build variable: `RTS_ATTESTATION_POLICY_PUBLIC_KEYS_HEX`, one or two comma-separated 64-hex keys. Environment secret: `RTS_ATTESTATION_POLICY_SIGNING_KEY_PEM_BASE64` in environment `attestation-policy`.
- Opt-out variable: `RTS_ATTESTATION_POLICY_FEED=off`.
- Cache files: `~/.local/share/nearai-red-sandbox/attestation-policy/<environment>.json`, `.json.sig`, and `<environment>.version` (high-water), directory 0700.
- `compose_acceptance` gains the value `"endorsed"`. Match names: `"exact"` and `"instance-label-v1"`.
- Rules are strict only: C1-C4, G1-G2, M1-M2. There is no Tier E.

## Review Focus

1. **Canonical JSON differs between Python and Rust.** The input is non-ASCII text or a float in `app_compose`. Expect the same normalized hash in both languages, or both refusing to normalize. Pinned by the shared vector tests in Task 1 and Task 3.
2. **The release swaps the document and signature non-atomically.** `gh release upload --clobber` uploads them one at a time, so a client can fetch a new document with the old signature. Expect a fallback to the cache with one warning line, not a refused launch. Pinned in Task 5.
3. **The user's clock runs ahead or behind.** Expect a document issued up to 5 minutes "in the future" to be accepted, and one past `expires` to be ignored, with a fallback to compiled-in pins, not an error. Pinned in Task 4.
4. **Two `rts` sessions write the cache at once, or a crash interrupts a write.** Expect a reader never to see a torn file: write to a temp file, then rename. A file that fails verification is deleted and ignored. Pinned in Task 5.
5. **A compiled-in pin is later revoked by the feed.** Expect the revocation to win even though the hash is compiled in. Pinned in Task 6.

---

### Task 1: Rules module, baselines and the validation fixture

**Files:**
- Create: `scripts/attestation_rules.py`
- Create: `scripts/test_attestation_rules.py`
- Create: `tests/fixtures/compose-history/<sha256>.json` (raw `app_compose` strings, one file each, exact bytes)
- Create: `tests/fixtures/compose-history/normalize-vector.json`
- Create: `opencode/attestation-baselines/{production,staging}/{gateway,model}/<sha256>.json`
- Create: `docs/plans/2026-11-24-cosign-check.md` (one-page result of the cosign check)

**Interfaces:**
- Produces (Python, `scripts/attestation_rules.py`):
  - `compose_sha256(raw: str) -> str`: sha256 of the UTF-8 bytes, as hex.
  - `canonical(obj) -> str`: `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`. It raises `ValueError` if any float is present.
  - `normalize_instance_label(raw: str) -> str | None`: the canonical JSON string after the spec's `instance-label-v1`, or `None` if it does not apply.
  - `instance_label_sha256(raw: str) -> str | None`
  - `digest_blind(s: str) -> str`
  - `evaluate(raw: str, role: str, baselines: list[str]) -> Verdict`, where `Verdict` is a dataclass:
    - `passed: bool`
    - `match: str` (`"exact"` or `"instance-label-v1"`)
    - `failures: list[str]` (rule IDs from the closest baseline, for example `["C1", "G1"]`)
    - `closest: str | None` (the baseline sha256)
    - `diff: list[str]`
  - `load_baselines(root: Path, environment: str, role: str) -> list[str]`
  - CLI: `python3 -I scripts/attestation_rules.py --environment E --role R <raw.json>` prints the verdict as JSON. It exits 0 on pass and 3 on hold.
- Produces (fixture): `normalize-vector.json` = `{"input": <raw app_compose string>, "normalized_sha256": "<hex>"}`. The input is the `e3902667a262` compose with a `"note": "é"` key added, so it carries non-ASCII text. Task 3 consumes it.

- [ ] **Step 1: Capture the composes that are missing locally**

```bash
for env in production staging; do
  RTS_LIVE_NEAR_ENVIRONMENT=$env RTS_LIVE_COMPOSE_POLICY=mr-config-only \
  RTS_LIVE_NEAR_MODELS='Qwen/Qwen3.8-27B-abliterated,deepseek-ai/DeepSeek-V4.1-Flash-1017-abliterated' \
  RTS_LIVE_RECORD_DIR="$PWD/.capture" \
  ~/.claude/turn-locks/turn.sh test "policy-feed capture" -- \
    cargo test --locked --test live_attest -- --ignored --test-threads=1
done
```

Expected: a `recorded .../attestation.json` line per environment. Extract every
`app_compose` from the reports, the gateway and each model, into
`tests/fixtures/compose-history/<sha256>.json` as a JSON string. Also extract
the composes from the 2026-10-29 fixture and from local session evidence. The
production pins `f571e5dafe8f`, `53cd435edbc1`, `1787a4af87ea`, `ae66f844658a`
and `e3902667a262`/`edabf8039210` must be present. If the live hosts have
moved on and `e4b83d924284`, `10d29b736472` or `85c10cc2c733` can't be
captured, record that in the cosign-check note and seed from what was
captured. Delete `.capture` afterwards. It is not committed.

- [ ] **Step 2: Check the cosign signatures and record the result**

Run `cosign verify --certificate-identity-regexp 'https://github.com/nearai/.*' --certificate-oidc-issuer https://token.actions.githubusercontent.com <image@digest>`
for the current `nearaidev/cloud-api`, `nearaidev/cvm-ingress` and
`nearaidev/compose-manager` digests. Write each result to
`docs/plans/2026-11-24-cosign-check.md`, with the exact identity that verified
where one did. If `cloud-api` or `cvm-ingress` is not signed, stop and ask
Zaki. The spec says G2 then holds every gateway digest change.

- [ ] **Step 3: Write the failing tests**

```python
def test_compose_sha256_matches_file_name():
    for p in FIXTURES.glob("[0-9a-f]*.json"):
        assert rules.compose_sha256(json.loads(p.read_text())) == p.stem

@pytest.mark.parametrize("base,cand,role,passed,failures", [
    ("f571e5dafe8f", "53cd435edbc1", "gateway", False, ["C1", "C4", "G1"]),
    ("53cd435edbc1", "1787a4af87ea", "gateway", False, ["G1"]),
    ("ae66f844658a", "e3902667a262", "model",   False, ["C1", "C4", "M1"]),
    ("e3902667a262", "edabf8039210", "model",   True,  []),
])
def test_validation_table(base, cand, role, passed, failures):
    v = rules.evaluate(raw(cand), role, [raw(base)])
    assert (v.passed, sorted(v.failures)) == (passed, failures)
    if passed:
        assert v.match == "instance-label-v1"

def test_instance_label_pair_normalizes_equal():
    assert rules.instance_label_sha256(raw("e3902667a262")) == rules.instance_label_sha256(raw("edabf8039210"))

# Each builds its input by editing raw("e3902667a262"):
def test_second_uncommented_label_line_does_not_normalize(): ...  # -> None
def test_commented_label_line_is_ignored(): ...                   # -> same hash as unedited
def test_65_char_label_does_not_normalize(): ...                  # -> None
def test_no_label_line_does_not_normalize(): ...                  # -> None

def test_key_order_does_not_change_normalized_hash(): ...
def test_float_refuses_normalization(): ...   # add "x": 1.5 -> None
def test_shared_vector():
    v = json.loads((FIXTURES / "normalize-vector.json").read_text())
    assert rules.instance_label_sha256(v["input"]) == v["normalized_sha256"]

@pytest.mark.parametrize("mutation,rule", [
    ("allowed_envs+FOO", "C1"), ("public_logs=true", "C1"), ("pre_launch_script+echo", "C1"),
    ("name=dstack-evil", "C2"), ("image tag :latest", "C3"),
    ("new repo evil/x@sha256:...", "C4"),
    ("gateway: add volume line", "G1"), ("model: GITHUB_REPO changed", "M1"),
])
def test_one_field_mutation_holds(mutation, rule): ...

def test_digest_only_change_passes(): ...  # swap the cloud-api digest in 1787 -> passed, match "exact"
def test_digest_only_plus_allowed_env_holds(): ...  # -> ["C1"]
```

G2 and M2 (cosign) are not in `evaluate`. They run in Task 7's sign step,
because they need the network.

- [ ] **Step 4: Run the tests to make sure they fail**

Run: `python3 -m pytest -q scripts/test_attestation_rules.py`
Expected: an import error (no module yet).

- [ ] **Step 5: Implement `scripts/attestation_rules.py`**

Follow the spec's rule text exactly:
- C3 accepts `${VAR:-repo@sha256:...}` when the baseline has the same `VAR` and repository.
- `evaluate` tries the exact form, then the `instance-label-v1` form, against each baseline. It reports the baseline with the fewest failures as `closest`.

Then seed the baselines with every captured compose already pinned in the
compiled-in lists, filed under its environment and role, with the file name
being the sha256.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `python3 -m pytest -q scripts/`
Expected: all pass, including the existing `test_refresh_attestation_policy.py`.

- [ ] **Step 7: Commit**

```bash
git add scripts/attestation_rules.py scripts/test_attestation_rules.py tests/fixtures/compose-history opencode/attestation-baselines docs/plans/2026-11-24-cosign-check.md
git commit -S -m "Add the attestation content rules, baselines and validation fixtures"
```

---

### Task 2: Role-aware compiled-in policy with revocations

**Files:**
- Modify: `src/attest.rs:56-103` (`Policy`, `PolicyFile`, `PolicyEntry`, `load_policy`)
- Modify: `opencode/attestation-policy.json` and `opencode/attestation-policy-staging.json` (add `"role"` to every entry)
- Modify: `scripts/refresh-attestation-policy.py` (write `role` on new entries) and its test

**Interfaces:**
- Produces:
  - `pub enum Role { Gateway, Model }` in `src/attest.rs`, with `Role::as_str()` returning `"gateway"` or `"model"`.
  - The new `Policy` struct:
    ```rust
    pub struct Policy {
        pub pinned: BTreeMap<[u8; 32], Role>,
        pub endorsed: BTreeMap<(Match, [u8; 32]), Role>,
        pub revoked: BTreeSet<[u8; 32]>,
        pub feed_version: Option<u64>,
    }
    ```
  - `pub enum Match { Exact, InstanceLabelV1 }`.
  - `load_policy(json) -> Result<Policy, String>`. Its signature is unchanged. `role` is now required in the JSON.
- Consumes: none.

- [ ] **Step 1: Write the failing tests** (in `src/attest.rs` tests)

```rust
#[test] fn every_compiled_in_entry_has_a_role() // both JSON files load; gateway/model split matches each entry's `source` text
#[test] fn an_entry_without_a_role_is_refused()  // load_policy(r#"{"composeHashes":[{"sha256":"..","recorded":"..","source":".."}]}"#).is_err()
#[test] fn an_unknown_role_is_refused()
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cargo test --lib attest::tests::every_compiled_in -- --test-threads=2`
Expected: FAIL (compile error: no `Role`).

- [ ] **Step 3: Implement**

Add `role` to both JSON files from each entry's `source`: `gateway_attestation` means `gateway`, `model_attestations` means `model`. Change `Policy` and every existing use. `check_compose` keeps its current behaviour until Task 6: it looks a hash up in `pinned` and ignores the role. Existing test fixtures that build `Policy { compose_hashes: .. }` move to `pinned`.

- [ ] **Step 4: Run the attestation tests to verify they pass**

Run: `cargo test --lib attest -- --test-threads=2` and `python3 -m pytest -q scripts/`
Expected: all pass. `no_gateway_build_is_pinned_in_both_environments` still passes.

- [ ] **Step 5: Commit**: `git commit -S -m "Tag every pinned compose with its role"`

---

### Task 3: `instance-label-v1` normalization in Rust

**Files:**
- Create: `src/attest/normalize.rs` (declared in `src/attest.rs` next to `mod report;`)

**Interfaces:**
- Consumes: `tests/fixtures/compose-history/normalize-vector.json` and the `e3902667a262`/`edabf8039210` fixtures from Task 1.
- Produces:
  - `pub fn instance_label_v1(app_compose: &str) -> Option<[u8; 32]>`: the sha256 of the canonical normalized JSON, or `None` if it does not apply.
  - `pub fn canonical_json(v: &serde_json::Value) -> Option<String>`: keys sorted recursively, no whitespace, UTF-8 not escaped. `None` if any number is not an integer.

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn the_gpu04_and_gpu02_composes_normalize_to_one_hash()
#[test] fn the_shared_vector_matches_python() // include_str! the vector; assert_eq!(hex::encode(instance_label_v1(input).unwrap()), normalized_sha256)
#[test] fn a_second_uncommented_label_line_does_not_normalize()
#[test] fn a_commented_label_line_is_ignored()
#[test] fn a_65_character_label_does_not_normalize()
#[test] fn a_compose_with_a_float_does_not_normalize()
#[test] fn key_order_does_not_change_the_hash()
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cargo test --lib attest::normalize -- --test-threads=2`
Expected: FAIL (no module).

- [ ] **Step 3: Implement**

Use the line regex from the spec, matched by hand with `str::lines` plus a byte check, because `regex` is not a dependency. `canonical_json` has to sort keys itself, because `preserve_order` is enabled through feature unification. Recurse over the `Value`, collecting map keys into a sorted `Vec`. Write strings with `serde_json::to_string(&Value::String(..))`, which leaves non-ASCII unescaped, as Python's `ensure_ascii=False` does.

- [ ] **Step 4: Run them to verify they pass** (same command). Expected: PASS.

- [ ] **Step 5: Commit**: `git commit -S -m "Normalize per-host instance labels before matching a compose"`

---

### Task 4: Feed document verification

**Files:**
- Create: `src/attest/feed.rs`

**Interfaces:**
- Consumes: `Role` and `Match` from Task 2. `crate::update::parse_key_hex` is not reused, because its panic text names the update variable.
- Produces:
  - `pub const FEED_KEYS: &[[u8; 32]]`: from `option_env!("RTS_ATTESTATION_POLICY_PUBLIC_KEYS_HEX")`. Empty when unset. A malformed value fails const evaluation with a message naming `RTS_ATTESTATION_POLICY_PUBLIC_KEYS_HEX`.
  - `pub const fn parse_feed_keys(s: &str) -> ([[u8; 32]; 2], usize)`: one or two keys, comma-separated.
  - `pub struct FeedDocument`, with fields:
    - `environment: NearEnvironment`
    - `version: u64`
    - `issued: u64`
    - `expires: u64` (unix seconds)
    - `entries: Vec<(Role, Match, [u8; 32])>`
    - `revoked: BTreeSet<[u8; 32]>`
  - `pub fn verify_document(doc: &[u8], sig_b64: &[u8], keys: &[[u8; 32]], env: NearEnvironment, now: u64, high_water: u64) -> Result<FeedDocument, String>`. It checks the signature first, using `verify_strict` over the exact bytes, then parses, then applies the spec's rules. Unknown `match` values are skipped.
  - `pub fn merge(policy: &mut Policy, doc: &FeedDocument)`: adds the endorsed entries, unions the revoked set, and sets `feed_version`.

- [ ] **Step 1: Write the failing tests** (with a fixture signing key generated in the test from a fixed seed: `SigningKey::from_bytes(&[7; 32])`)

```rust
#[test] fn accepts_either_key()
#[test] fn refuses_a_flipped_document_byte_and_a_flipped_signature_byte()
#[test] fn refuses_a_non_canonical_signature()          // s + L, which verify_strict rejects
#[test] fn refuses_a_document_signed_by_another_key()
#[test] fn refuses_the_other_environment()
#[test] fn refuses_an_expired_document()
#[test] fn accepts_issued_up_to_300s_ahead_and_refuses_301s()
#[test] fn refuses_a_window_over_7_days()
#[test] fn refuses_a_version_below_the_high_water_and_accepts_equal()
#[test] fn skips_an_unknown_match_and_refuses_an_unknown_role()
#[test] fn refuses_a_malformed_sha256()
#[test] fn parse_feed_keys_reads_one_or_two_and_panics_on_three()   // #[should_panic(expected = "RTS_ATTESTATION_POLICY_PUBLIC_KEYS_HEX")]
```

- [ ] **Step 2: Run them to make sure they fail**: `cargo test --lib attest::feed -- --test-threads=2`. Expected: FAIL.
- [ ] **Step 3: Implement.** `issued` and `expires` deserialize as `chrono::DateTime<chrono::Utc>`, as `published` does in `src/update/manifest.rs:38`. `verify_document` takes `now` as unix seconds so tests control the clock.
- [ ] **Step 4: Run them to verify they pass.** Expected: PASS.
- [ ] **Step 5: Commit**: `git commit -S -m "Verify signed attestation policy documents"`

---

### Task 5: Fetch, cache and fallback

**Files:**
- Modify: `src/attest/feed.rs`
- Modify: `src/install.rs` (add `pub fn attestation_policy_dir(home: &Path) -> PathBuf`, next to `update_cache`)

**Interfaces:**
- Consumes: `setup::{Fetch, download}`, and `verify_document` and `merge` from Task 4.
- Produces:
  - `pub enum FeedSource { Fetched(u64), Cached(u64), CompiledIn(String /* reason */) }`
  - `pub fn load_feed(fetch: &dyn Fetch, home: &Path, env: NearEnvironment, now: u64, keys: &[[u8; 32]]) -> (Option<FeedDocument>, FeedSource)`. It never errors. On fetch or verify failure it uses the cache, then nothing.
  - `pub fn feed_enabled() -> bool`: false when `FEED_KEYS` is empty or `RTS_ATTESTATION_POLICY_FEED` is `off`.
  - `pub fn cached_age(home: &Path, env: NearEnvironment, now: u64) -> Option<u64>`

- [ ] **Step 1: Write the failing tests** (a fake `Fetch` that serves fixed bodies, and `tempfile::tempdir()` as in `src/update.rs` tests)

```rust
#[test] fn a_good_fetch_is_cached_and_raises_the_high_water()
#[test] fn a_fetch_failure_uses_a_valid_cache()
#[test] fn a_new_document_with_the_old_signature_uses_the_cache()       // Review Focus 2
#[test] fn an_expired_cache_yields_compiled_in_without_error()
#[test] fn a_tampered_cache_is_deleted_and_ignored()                    // Review Focus 4
#[test] fn the_cache_is_written_by_rename()                             // no partial file visible: write to a temp file in the same dir, then rename
#[test] fn the_cache_dir_is_0700()
#[test] fn oversize_bodies_are_refused()                                // 262145-byte document, 1025-byte signature
#[test] fn a_cached_document_below_the_high_water_is_refused()
#[test] fn feed_off_makes_no_request()                                  // fake Fetch panics if called
```

- [ ] **Step 2: Run them to make sure they fail**: `cargo test --lib attest::feed -- --test-threads=2`. Expected: FAIL.
- [ ] **Step 3: Implement.** The 5-second bound comes from running `load_feed` on a worker thread and joining with a timeout from the caller (Task 6). Do not change `HttpsFetch`'s client timeouts.
- [ ] **Step 4: Run them to verify they pass.** Expected: PASS.
- [ ] **Step 5: Commit**: `git commit -S -m "Fetch and cache the attestation policy feed with fallback"`

---

### Task 6: Admit endorsed composes, record them, and wire launch and re-attestation

**Files:**
- Modify: `src/attest/report.rs:124-178` (`ComposeAcceptance`, `check_compose`)
- Modify: `src/attest.rs` (`check_quote` passes the role; `Attestor::real` gains a feed parameter; evidence records gain `feed_version` and `compose_match`)
- Modify: `src/launch.rs:430-480` (load the feed once at launch, print the source line, pass it into both the launch and re-attestation `Attestor`s)
- Modify: `scripts/refresh-attestation-policy.py` (treat `endorsed` as accepted, not as a candidate) and its test
- Modify: `tests/live_attest.rs` (when `RTS_LIVE_POLICY_FEED=on`, load the feed as a launch does)

**Interfaces:**
- Consumes: `Policy`, `Role` and `Match` (Task 2), `instance_label_v1` (Task 3), `load_feed`, `FeedSource` and `merge` (Tasks 4-5).
- Produces:
  - `ComposeAcceptance::Endorsed`, whose `as_str` is `"endorsed"`.
  - `check_compose(mr_config_id, app_compose, policy, role: Role, mode, continued) -> Result<([u8; 32], ComposeAcceptance, Option<Match>), String>`
  - `Attestor::real(near, key, models, options, feed: Option<&FeedDocument>)`

- [ ] **Step 1: Write the failing tests**

```rust
// report.rs
#[test] fn revoked_beats_pinned()                         // Review Focus 5
#[test] fn revoked_beats_endorsed_and_mr_config_only()
#[test] fn exact_endorsement_admits_as_endorsed()
#[test] fn instance_label_endorsement_admits_the_other_host()   // gpu02 compose, endorsement of the normalized gpu04 hash
#[test] fn a_gateway_endorsement_does_not_admit_a_model_and_the_reverse()
#[test] fn a_gateway_pin_does_not_admit_a_model()
#[test] fn unendorsed_still_falls_through_to_key_continuity()
// attest.rs
#[test] fn evidence_records_endorsed_with_feed_version_and_match()
```

- [ ] **Step 2: Run them to make sure they fail**: `cargo test --lib attest -- --test-threads=2`. Expected: FAIL.
- [ ] **Step 3: Implement**

Use the spec's precedence order: revoked, pinned, endorsed (exact, then `instance-label-v1`), then the existing paths.

At launch, call `load_feed` on a thread joined with a 5-second timeout, and print one progress line:
- `Attestation policy: feed v<version>`
- `Attestation policy: cached feed v<version> (<reason>)`
- `Attestation policy: compiled-in only (<reason>)`

In the re-attestation closure, reload when `cached_age` is over 3600 seconds.

- [ ] **Step 4: Run the full crate tests through the test lock**

Run: `~/.claude/turn-locks/turn.sh test "policy-feed rts" -- cargo test --locked --lib --bins` and `python3 -m pytest -q scripts/`
Expected: all pass, with the same failure count as the baseline taken before Task 2. Record that baseline in the task's first commit message.

- [ ] **Step 5: Commit**: `git commit -S -m "Admit composes endorsed by the signed policy feed"`

---

### Task 7: Publisher workflow

**Files:**
- Create: `scripts/attestation-policy/build_document.py` (stdlib only): next-document assembly and reproduction
- Create: `scripts/attestation-policy/test_build_document.py`
- Create: `scripts/attestation-policy/sign-policy.sh` (modelled on `scripts/release/sign-manifest.sh`)
- Create: `.github/workflows/attestation-policy.yml`
- Modify: `src/attest/feed.rs` tests (add `#[ignore] fn verify_document_from_env()`, which reads the `RTS_FEED_VERIFY_DOC`, `RTS_FEED_VERIFY_SIG`, `RTS_FEED_VERIFY_KEY` and `RTS_FEED_VERIFY_ENV` variables and calls `verify_document` with `now` set to the current time and `high_water` set to 0)

**Interfaces:**
- Consumes: `scripts/attestation_rules.py` (Task 1). Live evidence from `tests/live_attest.rs` with `RTS_LIVE_RECORD_DIR`. `verify_document` (Task 4), through `verify_document_from_env`.
- Produces:
  - `build_document.py propose --environment E --evidence DIR --current CURRENT.json --baselines opencode/attestation-baselines --now RFC3339 --out OUT_DIR`. It writes:
    - `candidates/<sha256>.json` (raw composes)
    - `proposed.json`
    - `holds.json`, with entries `{sha256, role, failures, closest, diff}`
  - `build_document.py reproduce --environment E --candidates DIR --proposed proposed.json --current CURRENT.json --baselines ... --now ...`. It recomputes everything from `candidates/` and writes `document.json`. It exits non-zero if `proposed.json` lists any entry it cannot reproduce.
  - `sign-policy.sh --environment E --in document.json --public-key-hex HEX` writes `<E>.json` and `<E>.json.sig`, and verifies them before exiting.

- [ ] **Step 1: Write the failing tests**

```python
def test_reproduce_refuses_an_entry_it_cannot_reproduce(): ...   # proposed lists a hash with no candidate file -> exit 1
def test_reproduce_refuses_an_entry_that_fails_the_rules(): ...  # candidate present but C1 fails -> exit 1
def test_document_keeps_prior_entries_and_adds_passing_ones(): ...
def test_document_is_republished_when_older_than_24h_even_with_no_new_entries(): ...
def test_expires_is_issued_plus_72h_and_version_is_issued_unix(): ...
def test_candidate_sha_must_equal_file_name(): ...
def test_round_trip_through_rts_verifier(): ...  # signs with a fixture key via openssl, then runs the rts ignored test; skipped when openssl 3 is absent
```

- [ ] **Step 2: Run them to make sure they fail**: `python3 -m pytest -q scripts/attestation-policy`. Expected: FAIL.
- [ ] **Step 3: Implement the scripts.** `sign-policy.sh` follows `sign-manifest.sh` exactly for key handling: `umask 077`, `mktemp -d` with an EXIT trap, and OpenSSL 3 `pkeyutl -sign -rawin`.
- [ ] **Step 4: Run them to verify they pass**: `python3 -m pytest -q scripts/`. Expected: PASS.
- [ ] **Step 5: Write `.github/workflows/attestation-policy.yml`**

The workflow's triggers are `schedule: '17 * * * *'`, `push` to `main` on `opencode/attestation-baselines/**`, and `workflow_dispatch` with no inputs. Each run executes these jobs:

**`evaluate`** runs on `macos-26` with `contents: read`, `issues: write` and secret `NEAR_AI_API_KEY` only.
- For each environment, it runs `live_attest` 8 times with `RTS_LIVE_COMPOSE_POLICY=mr-config-only`.
- It downloads the current document and runs `propose`.
- It uploads `candidates/` and `proposed.json` as an artifact.
- For each hold, it opens or updates one issue titled `Attestation hold: <env> <role> <sha256[:12]>`. The body holds the failures and diff, plus the `gh` commands that open a baseline PR adding the compose.

**`sign`** needs `evaluate` and runs on `ubuntu-24.04` (with `openssl`, `cosign` and Python 3).
- It uses `environment: attestation-policy` and `contents: write`.
- It downloads the artifact and runs `reproduce`.
- It runs `cosign verify` (G2/M2) on every changed `nearaidev/*` digest. It drops a failing entry and writes a hold issue for it.
- It runs `sign-policy.sh` and `gh release upload attestation-policy --clobber` (document first, then signature).
- It commits the document to the `attestation-policy-log` branch with `createCommitOnBranch`, as `scripts/release/bump-tap.sh` does.

- [ ] **Step 6: Dry-run the workflow**

Run it on a branch with `workflow_dispatch`, a throwaway key in a throwaway environment, and upload disabled (`DRY_RUN=1`, honoured by the upload and commit steps).
Expected: one hold-free run for any compose already in the baselines. The `sign` job logs `reproduced N entries`.

- [ ] **Step 7: Commit**: `git commit -S -m "Publish the signed attestation policy feed from CI"`

---

### Task 8: Keys, release wiring and documentation

**Files:**
- Modify: `.github/workflows/release.yml` ("Build rts" step, line ~164, and the live-attestation gate, line ~167)
- Modify: `README.md` (publish both public keys next to the update key)
- Modify: `opencode/README` or `docs/` wherever `refresh-attestation-policy.py` is documented (find it with `grep -rn refresh-attestation-policy docs README.md`), adding a note that pins are now the offline floor

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Zaki generates the keys (not the agent)**

Run `openssl genpkey -algorithm ed25519` twice.
- The CI key's PEM, base64-encoded, goes into the `attestation-policy` environment secret.
- The recovery key's PEM stays offline.
- Both public keys go into the repository variable `RTS_ATTESTATION_POLICY_PUBLIC_KEYS_HEX`.

The agent stops here and asks Zaki to confirm this is done.

- [ ] **Step 2: Write the failing release-gate test**

Extend `tests/unit/release-gate.test.ts` so it asserts that the "Build rts" step sets `RTS_ATTESTATION_POLICY_PUBLIC_KEYS_HEX`, and the live gate step sets `RTS_LIVE_POLICY_FEED: on`.
Run: `bun test tests/unit/release-gate.test.ts`. Expected: FAIL.

- [ ] **Step 3: Wire the release**

Set `RTS_ATTESTATION_POLICY_PUBLIC_KEYS_HEX: ${{ vars.RTS_ATTESTATION_POLICY_PUBLIC_KEYS_HEX }}` on "Build rts" and on the live gate. Then add `RTS_LIVE_POLICY_FEED: on` to the gate, so it accepts `endorsed` as well as `pinned`. Add a check that the variable holds one or two comma-separated 64-hex keys, modelled on the existing `RTS_UPDATE_PUBLIC_KEY_HEX` check.

- [ ] **Step 4: Run the tests**: `bun test tests/unit`. Expected: PASS.

- [ ] **Step 5: Update the documentation**

Publish both public keys in `README.md`. Document `RTS_ATTESTATION_POLICY_FEED=off` and the launch line that names the policy source.

- [ ] **Step 6: Commit**: `git commit -S -m "Ship the attestation policy feed keys in release builds"`

## Rollout (after merge)

1. Run the publisher against staging only, by limiting the matrix with a repository variable, for a week. Every hold must be explained in its issue.
2. Enable production in the matrix. Cut the next `rts` release with the keys compiled in.
3. Stop adding pins by hand. `scripts/refresh-attestation-policy.py` stays for the offline floor.

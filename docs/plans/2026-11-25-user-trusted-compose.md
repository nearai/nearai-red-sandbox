# Trusting a New NEAR AI Build at Launch: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When a production launch would fail only because a compose hash is unlisted, rts asks on the terminal whether to trust that exact build on this device, saves the answer, and attests again from scratch.

**Architecture:** A fourth compose source, `Policy::user_trusted`, sits after pinned and endorsed in `report::check_compose`. The final refusal becomes a typed `AttestationFailure::ComposeNotTrusted`. A new `attest::trusted` module owns the on-disk store, and `attest::prompt` owns the wording and the consent loop. `launch.rs` wraps its launch attestation in that loop and passes the store's hashes to re-attestation. `rts trust list|forget` manages the store.

**Tech Stack:** Rust (crate `rts`, MSRV 1.89), serde_json, the existing `brand::progress` and `sys::fs` helpers. No new dependencies.

**Spec:** `docs/specs/2026-11-25-user-trusted-compose-design.md`

## Global Constraints

- No new crates; `Cargo.lock` must not change.
- Every other check still applies to a trusted build: TDX quote, TCB policy, report_data/nonce, `mr_config_id == sha256(app_compose)`, GPU verdict for models.
- Revocation beats user trust; pinned and endorsed beat user trust.
- Trust is keyed by (environment, role, exact sha256). Never by prefix match at check time, never by normalization.
- The prompt appears only when: the failure is `ComposeNotTrusted`, `compose_policy == Pinned`, environment is `Production`, and stdin and stderr are both terminals.
- Only `y` or `yes`, case-insensitive and trimmed, accepts. Anything else, including EOF, refuses.
- At most 3 prompts per launch (`MAX_PROMPTS = 3`).
- Re-attestation never prompts.
- `AttestationFailure::message()` text for an untrusted compose is byte-identical to today's.
- Copy is fixed by the spec's "Wording" section, verbatim. The prompt and the per-launch line never mention review.
- Store path: `<rts home>/trusted-composes.json`, written owner-only, atomically (temp file + rename).
- Run `cargo test --locked --lib --bins`, `cargo clippy --locked --all-targets -- -D warnings`, `python3 -m pytest -q scripts/` once after the last task, not per task. Per task: `cargo check --locked --all-targets`.
- Commits must be signed (repository ruleset): `git commit -S`.

## Review Focus

- **A store edited by hand into nonsense** (truncated JSON, unknown role, short hash, duplicate entries): the launch must still run, treating the store as empty with one `[rts]` line. Pinned in Task 2 (`a_corrupt_store_is_ignored_with_a_message`, `an_entry_with_a_bad_hash_is_skipped`).
- **A gateway that flaps between builds during the prompt:** the retry sees a different unlisted hash and must prompt again for that one, not accept it silently, and must stop after 3. Pinned in Task 3 (`a_retry_meeting_another_build_prompts_for_that_one`, `the_fourth_untrusted_build_refuses`).
- **The user trusted a build and the feed later revokes it:** refuse with today's revocation text, no prompt. Pinned in Task 1 (`revoked_beats_user_trusted`) and Task 3 (`a_revoked_build_never_prompts`).
- **A staging-trusted hash meets production, or a gateway-trusted hash appears as a model:** refuse or prompt; never accept. Pinned in Task 1 (`user_trust_is_keyed_by_role`) and Task 2 (`for_environment_returns_only_that_environment`).
- **`rts trust forget` with an ambiguous or too-short prefix:** refuse and change nothing. Pinned in Task 4 (`forget_refuses_an_ambiguous_prefix`, `forget_refuses_a_prefix_under_8_chars`).

---

### Task 1: User-trusted compose source and the typed refusal

**Files:**
- Modify: `src/attest.rs` (`Policy`, `AttestationFailure`, `attest_model`, `attest_for_launch`, `check_quote`, `Attestor::real`, `Attested`)
- Modify: `src/attest/report.rs` (`ComposeAcceptance`, `check_compose`)
- Modify: `scripts/refresh-attestation-policy.py:46`, `scripts/test_refresh_attestation_policy.py`
- Modify: every `Attestor::real(` call site (5): `src/launch.rs` x2, `src/attest.rs` tests, `tests/live_attest.rs`
- Test: unit tests in `src/attest/report.rs` and `src/attest.rs`

**Interfaces:**
- Produces:
  - `Policy { pub user_trusted: BTreeMap<[u8; 32], Role>, ..existing }`
  - `ComposeAcceptance::UserTrusted`, `as_str() == "user-trusted"`
  - `pub enum ComposeError { NotTrusted { role: Role, hash: [u8; 32], message: String }, Other(String) }`. `check_compose` returns `Result<_, ComposeError>`, and `message` is today's refusal text.
  - `pub struct NotTrusted { pub model: String, pub role: Role, pub hash: [u8; 32], pub app_name: Option<String>, pub message: String }`. Here `message` is the full text that `AttestationFailure::message()` returns, `"model {model}: {prefix}{compose text}"` exactly as today.
  - `AttestationFailure::ComposeNotTrusted(NotTrusted)`
  - `Attestor::real(near, key, models, options, feed, trusted: &BTreeMap<[u8; 32], Role>)`, which fills `policy.user_trusted`.
  - `Attested::user_trusted(&self) -> Vec<(String /*model*/, Role, [u8; 32])>`, built from evidence entries whose `compose_acceptance == "user-trusted"`, in the same shape as `key_continuity()`.
  - `app_name` comes from the entry's `info.app_name` when it is a string, otherwise `None`.

- [ ] **Step 1: Write the failing tests** (in `report.rs` tests unless noted)

```rust
#[test] fn user_trusted_hash_is_accepted_as_user_trusted() // policy.user_trusted has (h, Gateway), mode Pinned -> Ok((h, UserTrusted, None))
#[test] fn pinned_and_endorsed_beat_user_trusted()         // h in pinned AND user_trusted -> Pinned; endorsed+user_trusted -> Endorsed
#[test] fn revoked_beats_user_trusted()                     // h revoked and user_trusted -> Err(Other(s)), s contains "is revoked"
#[test] fn user_trust_is_keyed_by_role()                    // user_trusted (h, Gateway), checked as Model -> Err(NotTrusted { role: Model, .. })
#[test] fn an_untrusted_compose_is_a_typed_refusal_with_todays_text() // Err(NotTrusted{message,..}): message == the exact string today's code produced (copy it into the test)
// in attest.rs tests, reusing the redeployed_model Case:
#[test] fn a_redeployed_model_fails_as_compose_not_trusted() // attest_for_launch -> Err(ComposeNotTrusted(nt)); nt.model, nt.role == Model, nt.hash == sha(OTHER_COMPOSE); failure.message() unchanged from today
#[test] fn a_user_trusted_redeploy_attests_and_is_reported()  // same Case with trusted {sha(OTHER_COMPOSE): Model} -> Ok(a); a.user_trusted() == [(model, Model, hash)]
```

In `scripts/test_refresh_attestation_policy.py`, add `test_user_trusted_evidence_is_proposed`: an evidence entry with `compose_acceptance: "user-trusted"` is proposed exactly as `mr-config-only` is.

- [ ] **Step 2: Run and confirm failure**

Run: `cargo test --locked --lib attest::` and `python3 -m pytest -q scripts/test_refresh_attestation_policy.py`
Expected: compile errors (no `user_trusted`, no `UserTrusted`), and the Python test fails.

- [ ] **Step 3: Implement.** Order in `check_compose`: mr_config checks, revoked, pinned, endorsed (exact, then instance-label), **user_trusted (exact hash, same role)**, then `MrConfigOnly`, then `KeyContinuity`, else `ComposeError::NotTrusted`. Thread `ComposeError` up through `check_quote` and `attest_model`, which keeps its role prefix in `message`. Use an internal error enum, not string matching. `attest_for_launch` maps it to `ComposeNotTrusted`. Add `"user-trusted"` to `UNPINNED`. Pass `&BTreeMap::new()` at every existing `Attestor::real` call site for now.

- [ ] **Step 4: Run.** `cargo test --locked --lib attest::` and the pytest file: all pass.

- [ ] **Step 5: Commit** `git commit -S -m "Accept a user-trusted compose and refuse an untrusted one with a typed failure"`

### Task 2: The trust store

**Files:**
- Create: `src/attest/trusted.rs` (declare `pub mod trusted;` in `src/attest.rs`)
- Test: unit tests in the same file

**Interfaces:**
- Consumes: `Role` and `NearEnvironment` (`crate::inference`).
- Produces:
  - `pub const FILE: &str = "trusted-composes.json";`
  - `pub struct TrustedEntry { pub environment: NearEnvironment, pub role: Role, pub sha256: [u8; 32], pub app_name: Option<String>, pub trusted_at: String /* YYYY-MM-DD UTC */ }`
  - `#[derive(Default)] pub struct TrustedComposes { pub entries: Vec<TrustedEntry> }`
  - `pub fn load(home: Option<&Path>) -> (TrustedComposes, Option<String>)`. The `String` is a warning for an `[rts]` line, `Some` only when a file existed and was ignored.
  - `impl TrustedComposes { pub fn for_environment(&self, near: NearEnvironment) -> BTreeMap<[u8; 32], Role>; pub fn find(&self, near: NearEnvironment, role: Role, hash: &[u8; 32]) -> Option<&TrustedEntry> }`
  - `pub fn add(home: &Path, entry: TrustedEntry) -> Result<(), String>`: loads, replaces any entry with the same (environment, role, sha256), and writes.
  - `pub fn forget(home: &Path, prefix: &str) -> Result<Vec<TrustedEntry>, String>`: the removed entries.
  - `pub fn today_utc(unix: u64) -> String`: `YYYY-MM-DD`, via `chrono` (already a dependency: `DateTime::<Utc>::from_timestamp`).

On-disk format (`deny_unknown_fields` at both levels; `environment`/`role` lowercase names; `sha256` lowercase hex):

```json
{"version":1,"entries":[{"environment":"production","role":"gateway","sha256":"<64 hex>","app_name":"dstack-0.5.15","trusted_at":"2026-11-25"}]}
```

Writes: create `home` if missing, write `trusted-composes.json.tmp` with owner-only permissions (`sys::fs::restrict_file` on the open file; mode 0600 on Unix), fsync, rename over. Reads on Unix: a file whose mode has any group/other bit is ignored with a warning naming the path and mode. On Windows the write-time `restrict_file` ACL is the control; there is no read-time check.

`forget`: `prefix` must be 8 to 64 lowercase hex characters, otherwise `Err`. It must match exactly one sha256 across all entries; an entry with the same hash in another environment or role counts as the same sha256 and is removed with it. No match or more than one distinct sha256 is an `Err`, and the file is unchanged.

- [ ] **Step 1: Write the failing tests** (in a tempdir)

```rust
#[test] fn add_then_load_round_trips()                    // entries equal; file mode == 0o600 on unix
#[test] fn add_replaces_the_same_key()                    // two adds, same (env, role, hash) -> 1 entry, latest trusted_at
#[test] fn for_environment_returns_only_that_environment() // staging entry absent from for_environment(Production)
#[test] fn a_missing_store_is_empty_without_a_message()    // load -> (empty, None)
#[test] fn a_corrupt_store_is_ignored_with_a_message()     // "{" -> (empty, Some(msg)), msg contains FILE
#[test] fn an_entry_with_a_bad_hash_is_skipped()           // whole file ignored (deny_unknown_fields/hex parse fail) -> (empty, Some(_))
#[cfg(unix)] #[test] fn a_group_readable_store_is_ignored() // chmod 0644 -> (empty, Some(msg)) msg contains "644"
#[test] fn today_utc_formats_a_known_day()                 // 1_795_564_800 -> "2026-11-25"
```

- [ ] **Step 2: Run and confirm failure.** `cargo test --locked --lib attest::trusted`: does not compile.
- [ ] **Step 3: Implement** to the interfaces above.
- [ ] **Step 4: Run.** All pass.
- [ ] **Step 5: Commit** `git commit -S -m "Keep user-trusted compose hashes in an owner-only store"`

### Task 3: The prompt and the consent loop

**Files:**
- Create: `src/attest/prompt.rs` (`pub mod prompt;`)
- Modify: `src/brand/progress.rs`: add `Progress::paused`
- Modify: `src/launch.rs`: launch attestation closure, re-attestation closure, per-launch lines
- Test: unit tests in `prompt.rs` and `progress.rs`

**Interfaces:**
- Consumes: Task 1 (`NotTrusted`, `AttestationFailure::ComposeNotTrusted`, `Attested::user_trusted`, the `trusted` arg of `Attestor::real`). Task 2 (`load`, `add`, `TrustedEntry`, `today_utc`).
- Produces:
  - `pub const MAX_PROMPTS: usize = 3;`
  - `pub fn eligible(near: NearEnvironment, options: &AttestOptions, stdin_tty: bool, stderr_tty: bool) -> bool`
  - `pub fn accepted(answer: &str) -> bool`
  - `pub fn compare_url(hash: &[u8; 32]) -> String`: `https://github.com/nearai/nearai-red-sandbox/issues?q=` followed by the first 12 hex characters (the hold-issue title uses `sha[:12]`).
  - `pub fn prompt_text(nt: &NotTrusted) -> String`
  - `pub fn trusted_line(model: &str, role: Role, hash: &[u8; 32], trusted_at: &str) -> String`
  - `pub trait Ask { fn ask(&mut self, text: &str) -> Option<String>; }` and `pub struct TerminalAsk;`. `TerminalAsk` writes `text` to stderr inside `brand::progress::current().paused(..)` (or directly if there is none) and reads one stdin line. EOF or an error returns `None`.
  - `pub fn attest_with_consent(near: NearEnvironment, options: &AttestOptions, ttys: (bool, bool), home: Option<&Path>, now: u64, ask: &mut dyn Ask, attest: impl FnMut(&BTreeMap<[u8; 32], Role>) -> Result<Attested, AttestationFailure>) -> Result<Attested, AttestationFailure>`
  - `impl Progress { pub fn paused<T>(&self, f: impl FnOnce() -> T) -> T }`: holds the state lock (so the ticker thread cannot repaint), erases the live line, runs `f`, redraws the live line.

Exact copy, from the spec. `{short}` is the first 8 hex characters. The `Checked` line for a model appends `, GPU`. The gateway's first line is `NEAR AI moved its production gateway to a new build.`; a model's is `NEAR AI moved {model} to a new build.`. `Build` shows `app_name`, or `unknown`.

```
{first line}

  Build    {app_name}
  Hash     {64 hex}
  Checked  TDX quote, TCB status, this launch's nonce, compose hash
  Compare  {compare_url}

Trust this build on this device? Red Sandbox will use it without asking
again until you run `rts trust forget {short}`. [y/N]
```

`trusted_line`: `[rts] NEAR AI gateway build {short}: you trusted it on {trusted_at}` for the gateway, and `[rts] NEAR AI {model} build {short}: you trusted it on {trusted_at}` for a model.

`attest_with_consent` algorithm:
1. Load the store. Print its warning, if any, as a `brand::progress::message`.
2. Call `attest(&store.for_environment(near))`.
3. On `Err(ComposeNotTrusted(nt))`, if `eligible(..)` and fewer than `MAX_PROMPTS` prompts have been shown and `home` is `Some`: call `ask.ask(&prompt_text(&nt))`.
4. If the answer is accepted, `add` a `TrustedEntry` for (near, nt.role, nt.hash, nt.app_name, `today_utc(now)`). If `add` fails, return the original error with the add error appended to the message. Otherwise reload the store and go to step 2.
5. If the answer is not accepted, return the original error.
6. Any other result returns as it is.
7. On `Ok(a)`, print `trusted_line` for each `a.user_trusted()` entry, using `trusted_at` from `store.find(..)`.

- [ ] **Step 1: Write the failing tests** (a scripted `Ask` records the texts it was shown and returns queued answers; a scripted `attest` returns queued results and records the trusted maps it received)

```rust
#[test] fn the_gateway_prompt_matches_the_approved_wording()  // assert_eq!(prompt_text(&gw), EXPECTED_GATEWAY) with the literal block above filled for f4a9b480.../dstack-0.5.15
#[test] fn the_model_prompt_names_the_model_and_adds_gpu()    // first line + "compose hash, GPU"
#[test] fn the_prompt_never_mentions_review()                  // !prompt_text(..).to_lowercase().contains("review") for both roles; same for trusted_line
#[test] fn accepted_takes_only_y_or_yes()                      // "y","Y"," yes\n","YES" true; "", "n", "yes please", "1", "ye" false
#[test] fn not_eligible_without_both_ttys_or_outside_production_pinned() // each of the 4 conditions false -> false
#[test] fn yes_saves_the_hash_and_attests_again_with_it()      // attest calls: 1st map empty, 2nd map contains {hash: role}; store has 1 entry, trusted_at today
#[test] fn no_refuses_and_saves_nothing()                      // returns ComposeNotTrusted; store empty; attest called once
#[test] fn eof_refuses()                                       // ask returns None
#[test] fn a_retry_meeting_another_build_prompts_for_that_one() // results: NotTrusted(h1), NotTrusted(h2), Ok -> two prompts shown, h1 then h2
#[test] fn the_fourth_untrusted_build_refuses()                // 4 NotTrusted results, all "y" -> 3 prompts, returns the 4th error
#[test] fn a_revoked_build_never_prompts()                     // attest returns Other("... is revoked ...") -> ask never called
#[test] fn nothing_is_asked_without_a_terminal()               // ttys (false,true) -> ask never called, error returned
// progress.rs
#[test] fn paused_runs_the_closure_and_redraws()               // with a Vec<u8> writer: closure output appears between an erase and a redraw of the live line
```

- [ ] **Step 2: Run and confirm failure.** `cargo test --locked --lib attest::prompt brand::progress`: does not compile.
- [ ] **Step 3: Implement `prompt.rs` and `Progress::paused`.**
- [ ] **Step 4: Wire `launch.rs`.**
  - Before `resolve_and_attest`, compute the ttys: `stdin().is_terminal()` and `stderr().is_terminal()`.
  - The `attest_key` closure becomes `|key| attest::prompt::attest_with_consent(near, &attest_options, ttys, feed_home.as_deref(), unix_now(), &mut attest::prompt::TerminalAsk, |trusted| Attestor::real(near, Some(key.clone()), .., feed_doc.as_ref(), trusted).map_err(Other)?.attest_for_launch())`.
  - Re-attestation loads the store at each call (`trusted::load(feed_home.as_deref()).0.for_environment(near)`) and passes it to `Attestor::real`. It never prompts.
  - Its `warn` closure also prints a `trusted_line` for each `user_trusted()` entry.
- [ ] **Step 5: Run** `cargo test --locked --lib --bins`: all pass.
- [ ] **Step 6: Commit** `git commit -S -m "Ask before trusting a new NEAR AI build at launch"`

### Task 4: `rts trust list|forget` and docs

**Files:**
- Modify: `src/main.rs`: `Action::Trust(TrustCommand)`, parse, dispatch, help text
- Modify: `README.md` and `opencode/README.md`: one short paragraph each on trusted builds, beside the attestation-policy text
- Test: `src/main.rs` parse tests; unit tests on the command output in `src/attest/trusted.rs`

**Interfaces:**
- Consumes: Task 2 (`load`, `forget`).
- Produces:
  - `enum TrustCommand { List, Forget(String) }`, parsed from exactly `["trust", "list"]` and `["trust", "forget", prefix]`. Anything else under `trust` is an `Err` with usage.
  - `pub fn list_lines(store: &TrustedComposes) -> Vec<String>`: one line per entry, `"{environment} {role} {sha256} {app_name|unknown} trusted {trusted_at}"`, or `["no trusted builds"]`.
  - Home: the same `install::home_in(&env, cfg!(windows))` that launch uses for the feed cache.

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn parses_trust_list_and_forget()        // ["trust","list"] -> Trust(List); ["trust","forget","f4a9b480"] -> Trust(Forget("f4a9b480"))
#[test] fn rejects_other_trust_forms()            // ["trust"], ["trust","forget"], ["trust","list","x"], ["trust","add","x"] -> Err
#[test] fn forget_removes_one_build()             // trusted.rs: two entries, forget(first 8 of one) -> that one removed, other kept
#[test] fn forget_refuses_an_ambiguous_prefix()   // two hashes sharing 8 chars -> Err, file bytes unchanged
#[test] fn forget_refuses_a_prefix_under_8_chars() // "f4a9b48" -> Err
#[test] fn list_lines_formats_each_entry()        // exact string for one entry; ["no trusted builds"] when empty
```

- [ ] **Step 2: Run and confirm failure.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `cargo test --locked --lib --bins`.
- [ ] **Step 5: Commit** `git commit -S -m "Add rts trust list and forget"`

### Final verification (once, after Task 4)

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --locked --all-targets -- -D warnings`
- [ ] `cargo test --locked --lib --bins`: report the pass counts against the baseline run on `origin/main` before Task 1.
- [ ] `python3 -m pytest -q scripts/`
- [ ] `git diff origin/main -- Cargo.lock` is empty.
- [ ] A manual run against production. With the store empty and a hash that is not pinned (simulate this by running against staging with `--compose-policy pinned` and the environment check relaxed only in a scratch build, never committed), check that the prompt reads exactly as approved, that `y` saves the build and the launch proceeds, and that the next launch prints the trusted line without asking.

# Update notices and `rts update`: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An installed release of `rts` tells the operator at launch, at most once a day and within 3 s, that a newer signed release exists, and `rts update` installs it through that release's own `install.sh`, accepting only what a manifest signed with the update key names.

**Architecture:** A new `src/update.rs` holds the compiled-in Ed25519 key (`option_env!` parsed by a `const fn`), the install channel (Homebrew keg, release prefix, source build) and the launch check; `src/update/manifest.rs` fetches `latest.json` and `latest.json.sig` through `setup::download` (exact GitHub host allowlist, size caps), verifies the signature over the exact bytes with `verify_strict` and only then parses an rts wrapper around `ironwire_update::Manifest`; `src/update/apply.rs` is `rts update`: compare with `ironwire_update::evaluate`, download the versioned `install.sh`, check its signed digest, run it with `RTS_VERSION`, `RTS_INSTALL_PREFIX` and the signed tarball digest in `RTS_TARBALL_SHA256` (a new `install.sh` check), then verify the new binary's code signature against team `KXSWJN7WY8` and its `--version`. The release workflow gains `scripts/release/sign-manifest.sh`, run after packaging in the `release`-environment build job with OpenSSL 3, which writes and signs the manifest, verifies it against the repository variable's public key, and adds both files to `SHA256SUMS`, the attestations and the release.

**Tech Stack:** Rust 2024; `ed25519-dalek` 2.2, `base64` 0.23, `sha2` 0.11, `reqwest` 0.12 blocking, `tempfile` 3 (already direct, `Cargo.toml:17-50`); `ironwire_update` at rev `bf8b90ba7b2e3b4da3011e1107a8a2068c8085bc` and `chrono` 0.4.45, both already in `Cargo.lock` (`Cargo.lock:482`, `:1838`), promoted to direct; bash 3.2-compatible scripts (`shellcheck`, `actionlint`); bun 1.3.3 for script tests; OpenSSL 3 from Homebrew `openssl@3` for signing.

**Spec:** `docs/specs/2026-10-30-auto-update-design.md`, all sections (read it first; this plan does not restate the rationale). The release pipeline it extends is in `docs/specs/2026-10-29-release-and-installers-design.md`, "Release pipeline".

## Global Constraints

- Every cargo command uses `RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0`. Below, `T` stands for `RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0 cargo test`, and `C` for `RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0 cargo clippy --all-targets`.
- Baseline, measured 2026-10-30 in this worktree at `35ee5b7`: `T --lib` = 283 passed, 5 failed, 1 ignored; `T --bin rts` = 18 passed; `bun test tests/unit` = 94 pass, 0 fail. The five failures are pre-existing and host-specific: `copy::tests::a_long_name_is_refused`, `copy::tests::a_symlink_to_a_host_path_is_refused`, `copy::tests::a_hardlink_is_refused`, `copy::tests::copy_out_is_byte_exact_across_slices`, `copy::tests::an_oversized_file_is_refused`. Before Task 1, re-run all three and paste the summary lines; if they differ, stop and report. After every task: `T --lib` shows exactly these five failures and no others; `T --bin rts` and `bun test tests/unit` pass in full; `C` is clean; `shellcheck install.sh scripts/*.sh scripts/release/*.sh` and `actionlint .github/workflows/release.yml` are clean. Never report "tests pass" from a filtered run.
- No new crates. Task 1 adds `ironwire_update` (same git URL and rev as `ironwire_proxy`, `Cargo.toml:42`) and `chrono = { version = "0.4.45", features = ["serde"] }` as direct dependencies. Acceptance: `git diff Cargo.lock` changes only the `dependencies` list of the `rts` package (`Cargo.lock:2787`), adding `"chrono"` and `"ironwire_update"`; no `[[package]]` stanza is added or removed. `semver` is not added. Anything else is a stop-and-ask.
- Pinned values:

| Item | Value |
|---|---|
| Manifest URL | `https://github.com/nearai/nearai-red-sandbox/releases/latest/download/latest.json` |
| Signature URL | `https://github.com/nearai/nearai-red-sandbox/releases/latest/download/latest.json.sig` |
| install.sh URL | `https://github.com/nearai/nearai-red-sandbox/releases/download/v<latest>/install.sh` (versioned, never `latest/download`) |
| Caps | manifest `64 << 10` bytes, signature `1 << 10`, install.sh `64 << 10` |
| Launch budget | `Duration::from_secs(3)`: HTTP client total and connect timeout, and the `recv_timeout` on the worker |
| Cadence | `ironwire_update::CHECK_INTERVAL` (24 h); a cache `at` later than now counts as due |
| Cache | `<HOME>/.local/share/nearai-red-sandbox/update-check.json`; parent created with mode 0700 before `save_cache` |
| Opt-outs | env `RTS_NO_UPDATE_CHECK` set and non-empty; config `"updateCheck": false` |
| Public key | build env `RTS_UPDATE_PUBLIC_KEY_HEX`; repository variable value `9b4a81b8bd017898c36871c6bd1cb890faf95b6e378e72eb99b9c15841f02ac9` |
| Private key | environment secret `RTS_UPDATE_SIGNING_KEY_PEM_BASE64` in `release` |
| Ed25519 SPKI DER prefix | `302a300506032b6570032100` |
| Code requirement | `anchor apple generic and certificate leaf[subject.OU] = "KXSWJN7WY8"`, passed as the single argv element `-R=<requirement>` to `/usr/bin/codesign --verify --strict` |
| Tarball name | `rts-<latest>-aarch64-apple-darwin.tar.gz` |
| Version pattern | `^[0-9]+\.[0-9]+\.[0-9]+$` (no `v`) |
| Test key | `ed25519_dalek::SigningKey::from_bytes(&[7; 32])`; a second, wrong key `from_bytes(&[8; 32])` |
| OpenSSL | `$(brew --prefix openssl@3)/bin/openssl`; `/usr/bin/openssl` is LibreSSL 3.3.6 without `pkeyutl -rawin` (measured 2026-10-30) and must be refused |

- Measured 2026-10-30 for this plan: `codesign --verify --strict '-R=anchor apple generic' /bin/ls` exits 0, and with the team requirement exits 3 (`test-requirement: code failed to satisfy specified code requirement(s)`). With `openssl@3` 3.5.9, `genpkey -algorithm ed25519`, `pkeyutl -sign -rawin` (64-byte output), the SPKI-prefix public key, and `pkeyutl -verify -pubin -rawin` round-trip; one appended byte gives `Signature Verification Failure`, exit 1.
- Merge hygiene: branch `sandbox-network` edits `src/main.rs`, `src/config.rs` and `src/session.rs` in parallel. This plan adds to `src/main.rs` only the `Update` action, its parse function, its dispatch arm, its `USAGE` text and one call in `launch`; to `src/config.rs` only the `updateCheck` field; and does not touch `src/session.rs`.
- Scripts run under macOS `/bin/bash` 3.2: no `mapfile`, associative arrays or `${x,,}`; expand a possibly empty array as `${a[@]+"${a[@]}"}` under `set -u`.
- Never run `tests/contain`, `rts launch` or `mvmctl`. Never use Apple signing identities. No network in the default test suite. Do not push; do not touch other worktrees.
- Commit style: short imperative subject, no prefix, no emojis, ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. The signature covers the exact fetched bytes and is checked before anything is parsed. A manifest with one appended `\n`, or the same JSON re-serialized, must fail; only one trailing `\n` is stripped from the `.sig` body, never from the manifest. Pinned by `a_trailing_newline_on_the_manifest_breaks_the_signature` and `reserialized_json_is_refused` in Task 1.
2. Launch is never held beyond the budget, whatever the HTTP layer does: the deadline is a `recv_timeout` on a worker thread, not only the client timeout. A fetch that sleeps 10 s returns within the deadline, prints nothing, and logs a timeout. Pinned by `a_slow_fetch_never_holds_the_launch` in Task 2.
3. Cache edge cases: a cached `at` in the future fetches (does not suppress for months); a failed check keeps the previous status; an opted-out run reads no cache and makes no request; the cache parent is created 0700, not with the umask's mode, because `install.sh` and `scripts/build-patched-mvm-supervisor.sh` require 0700 there. Pinned by `a_future_cache_time_counts_as_due`, `a_failure_keeps_the_previous_status`, `opting_out_reads_nothing_and_fetches_nothing` and `the_cache_directory_is_private` in Task 2.
4. Nothing runs before its digest is checked, and the tarball is bound to the signed manifest: an `install.sh` whose sha256 differs is refused and the installer is never called; the installer receives `RTS_TARBALL_SHA256`, has `RTS_RELEASE_BASE` removed, and `install.sh` refuses a tarball that matches its `SHA256SUMS` but not `RTS_TARBALL_SHA256`. Pinned by `an_install_sh_digest_mismatch_runs_nothing` and `the_installer_gets_the_signed_tarball_digest_and_no_release_base` in Task 3, and the `install.sh` test "a tarball that matches SHA256SUMS but not RTS_TARBALL_SHA256 is refused" in Task 3.
5. A signing secret that does not match the compiled-in public key cannot ship, and LibreSSL cannot sign: `sign-manifest.sh` with a wrong `--public-key-hex` exits 1 and leaves no `latest.json`, `latest.json.sig` or extra `SHA256SUMS` line; `--openssl /usr/bin/openssl` is refused naming LibreSSL. Pinned by "a signing key that does not match the public key is refused and leaves nothing" and "LibreSSL is refused" in Task 4.

---

### Task 1: Signed manifest, compiled-in key and install channel

**Files:**
- Modify: `Cargo.toml` (`[dependencies]`, after `ironwire_proxy` `:42`), `Cargo.lock` (the `rts` entry's `dependencies` only)
- Create: `src/update.rs`, `src/update/manifest.rs`; Modify: `src/lib.rs` (`pub mod update;`)

**Interfaces:**
- Consumes: `ironwire_update::{Manifest, InstallMethod}` (`ironwire_update/src/lib.rs:27-43`, `:89-102`); `install::install_prefix`, `install::prefix_plugin` (`src/install.rs:18-34`); `ed25519_dalek::{VerifyingKey, Signature}`; `base64::engine::general_purpose::STANDARD`.
- Produces (`src/update.rs`):

```rust
pub mod manifest;
pub mod apply; // Task 3; add the line then

/// 64 hex characters (either case) to 32 bytes. Panics otherwise, which is a
/// compile error when evaluated for `UPDATE_KEY`.
pub const fn parse_key_hex(hex: &str) -> [u8; 32];
pub const UPDATE_KEY: Option<[u8; 32]> = match option_env!("RTS_UPDATE_PUBLIC_KEY_HEX") {
    Some(hex) => Some(parse_key_hex(hex)),
    None => None,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Channel {
    /// A curl (install.sh) install under this prefix.
    Release { prefix: PathBuf },
    Homebrew,
    Source,
}
/// Homebrew when install_prefix(exe) is <..>/Cellar/<name>/<version>; Release
/// when the prefix holds share/nearai-red-sandbox/plugin as a directory;
/// Source otherwise.
pub fn channel(exe: &Path) -> Channel;
impl Channel {
    /// Homebrew -> Homebrew, Release -> ShellInstaller, Source -> Unmanaged.
    pub fn method(&self) -> ironwire_update::InstallMethod;
}
```

- Produces (`src/update/manifest.rs`):

```rust
pub const MANIFEST_URL: &str = "https://github.com/nearai/nearai-red-sandbox/releases/latest/download/latest.json";
pub const SIGNATURE_URL: &str = "https://github.com/nearai/nearai-red-sandbox/releases/latest/download/latest.json.sig";
pub const MAX_MANIFEST_BYTES: u64 = 64 << 10;
pub const MAX_SIGNATURE_BYTES: u64 = 1 << 10;

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct Tarball { pub name: String, pub sha256: String }
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct InstallSh { pub sha256: String }
/// No deny_unknown_fields: serde forbids it with flatten, and a later
/// release may add fields.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct SignedManifest {
    #[serde(flatten)]
    pub manifest: ironwire_update::Manifest,
    pub tarball: Tarball,
    pub install_sh: InstallSh,
    pub published: chrono::DateTime<chrono::Utc>,
}
/// Signature first (exact bytes, verify_strict), then parse, then the spec's
/// rules (version pattern, tarball name, lowercase hex digests).
pub fn verify(manifest: &[u8], signature: &[u8], key: &[u8; 32]) -> Result<SignedManifest, String>;
```

- [ ] **Step 1: Promote the dependencies.** Add `ironwire_update = { git = "https://github.com/nearai/ironwire", rev = "bf8b90ba7b2e3b4da3011e1107a8a2068c8085bc" }` and `chrono = { version = "0.4.45", features = ["serde"] }` with the comment `# Update checks (src/update.rs). Promoted from Cargo.lock; no new packages.` Run `RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0 cargo check --locked`; expect an error that the lock file needs updating, then `cargo check` without `--locked`, then `git diff Cargo.lock`: expect only `+ "chrono",` and `+ "ironwire_update",` inside the `rts` entry. Paste the diff.

- [ ] **Step 2: Write the failing tests** (`src/update/manifest.rs` and `src/update.rs`). A test helper signs with the test key:

```rust
fn key() -> SigningKey { SigningKey::from_bytes(&[7; 32]) }
fn public() -> [u8; 32] { key().verifying_key().to_bytes() }
const GOOD: &str = "{\n  \"latest\": \"0.2.0\",\n  \"minimum_supported\": \"0.1.0\",\n  \"published\": \"2026-11-02T18:04:11Z\",\n  \"tarball\": {\n    \"name\": \"rts-0.2.0-aarch64-apple-darwin.tar.gz\",\n    \"sha256\": \"<64 a's>\"\n  },\n  \"install_sh\": {\n    \"sha256\": \"<64 b's>\"\n  }\n}\n";
fn sig(bytes: &[u8], k: &SigningKey) -> Vec<u8> { STANDARD.encode(k.sign(bytes).to_bytes()).into_bytes() }

#[test] fn a_signed_manifest_verifies_and_parses() {
    let m = verify(GOOD.as_bytes(), &sig(GOOD.as_bytes(), &key()), &public()).unwrap();
    assert_eq!(m.manifest.latest, "0.2.0");
    assert_eq!(m.manifest.minimum_supported.as_deref(), Some("0.1.0"));
    assert_eq!(m.tarball.name, "rts-0.2.0-aarch64-apple-darwin.tar.gz");
}
#[test] fn a_trailing_newline_on_the_signature_is_tolerated() // sig + b"\n" verifies; sig + b"\n\n" fails
#[test] fn a_trailing_newline_on_the_manifest_breaks_the_signature() // sign GOOD, verify GOOD + "\n": Err containing "signature"
#[test] fn reserialized_json_is_refused() // serde_json::to_vec(&serde_json::from_str::<Value>(GOOD)) with GOOD's signature: Err
#[test] fn a_tampered_byte_is_refused() // GOOD with 0.2.0 -> 0.3.0 (and the tarball name updated), original signature: Err
#[test] fn the_wrong_key_is_refused() // signed by from_bytes(&[8; 32]): Err
#[test] fn malformed_signatures_are_refused() {
    for bad in [b"".to_vec(), b"not base64!".to_vec(), STANDARD.encode([0u8; 63]).into_bytes(), STANDARD.encode([0u8; 65]).into_bytes(), sig(GOOD.as_bytes(), &key())[..40].to_vec()] {
        assert!(verify(GOOD.as_bytes(), &bad, &public()).is_err());
    }
}
#[test] fn signed_but_invalid_manifests_are_refused() {
    // each signed with the test key: latest "v0.2.0"; latest "0.2"; minimum_supported "x";
    // tarball.name "rts-0.3.0-aarch64-apple-darwin.tar.gz" or "../rts.tar.gz"; an uppercase or 63-char sha256;
    // published "yesterday"; missing install_sh; not JSON at all
}
#[test] fn unknown_fields_are_accepted() // GOOD plus "channel": "stable", signed: Ok
```

  In `src/update.rs`:

```rust
#[test] fn key_hex_parses_both_cases() // parse_key_hex of the repository value == hex::decode of it; uppercase gives the same bytes
#[test] #[should_panic] fn a_short_key_panics()      // 63 chars
#[test] #[should_panic] fn a_long_key_panics()       // 65 chars
#[test] #[should_panic] fn a_non_hex_key_panics()    // 63 hex + "g"
#[test] fn channels_follow_the_layout() {
    // <t>/Cellar/rts/0.1.0/bin/rts and <t>/Cellar/rts/0.1.0/share/nearai-red-sandbox/plugin/ -> Homebrew
    // <t>/brew/bin/rts symlinked to that file -> Homebrew
    // <t>/home/.local/bin/rts with <t>/home/.local/share/nearai-red-sandbox/plugin/ -> Release { prefix: canonical <t>/home/.local }
    // <t>/usr/bin/rts without the plugin directory, <t>/target/debug/rts, a missing path -> Source
    // method(): Homebrew, ShellInstaller, Unmanaged
}
```

- [ ] **Step 3: Run, expect FAIL** — `T --lib update::` fails to compile: `error[E0583]: file not found for module` / `cannot find function \`verify\``.

- [ ] **Step 4: Implement.** `parse_key_hex` loops over `hex.as_bytes()` with a `const fn nibble(b: u8) -> u8` that panics on a non-hex byte, and panics with `"RTS_UPDATE_PUBLIC_KEY_HEX must be 64 hex characters"` when the length is not 64. `verify`: strip one trailing `b'\n'` from `signature`; decode with `STANDARD`; `<[u8; 64]>::try_from` (error "signature is not 64 bytes"); `VerifyingKey::from_bytes(key)`; `verify_strict(manifest, &Signature::from_bytes(&arr))` (error "latest.json: signature does not verify with the update key"); `serde_json::from_slice::<SignedManifest>`; then the rules, each error starting `latest.json: `. `channel` canonicalizes via `install_prefix`; Homebrew when `prefix.parent().and_then(Path::parent).and_then(Path::file_name) == Some("Cellar")`.

- [ ] **Step 5: Run, expect PASS** — `T --lib update::` all pass; then the full Global Constraints gate.

- [ ] **Step 6: Commit** — `git add Cargo.toml Cargo.lock src/lib.rs src/update.rs src/update/manifest.rs && git commit -m "Verify signed update manifests against a compiled-in key"`

---

### Task 2: Fetch the manifest and check at launch

**Files:**
- Modify: `src/setup.rs` (`HttpsFetch::new` `:63-75`: add `with_timeouts`)
- Modify: `src/install.rs` (beside `home_sessions` `:52-57`; test `layout_paths_match_the_spec` `:163-172`)
- Modify: `src/config.rs` (`OperatorConfig` `:69-81`, `Raw` `:106-118`, the literal `:312-327`, tests)
- Modify: `src/update.rs`, `src/update/manifest.rs`
- Modify: `src/main.rs` (`launch`, one call after `new_session_id` `:306`)

**Interfaces:**
- Consumes: `setup::{Fetch, Hop, download, FakeFetch}` (`src/setup.rs:48-56`, `:107`, `:513-550`); `ironwire_update::{should_check, load_cache, save_cache, evaluate, CheckedAt, UpdateStatus, Manifest}` (`ironwire_update/src/lib.rs:141-218`).
- Produces:

```rust
// src/setup.rs
impl HttpsFetch {
    /// new() becomes with_timeouts(30 s, 600 s); behaviour unchanged.
    pub fn with_timeouts(connect: Duration, total: Duration) -> Result<Self, String>;
}

// src/install.rs
/// <home>/.local/share/nearai-red-sandbox/update-check.json
pub fn update_cache(home: &Path) -> PathBuf;

// src/config.rs
pub struct OperatorConfig { /* existing fields */ pub update_check: bool }   // default true
struct Raw { /* existing fields */ update_check: Option<bool> }             // "updateCheck"

// src/update/manifest.rs
/// Both URLs through setup::download with their caps, then verify.
pub fn fetch(f: &dyn Fetch, key: &[u8; 32]) -> Result<SignedManifest, String>;

// src/update.rs
pub const LAUNCH_TIMEOUT: Duration = Duration::from_secs(3);
pub const OPT_OUT_ENV: &str = "RTS_NO_UPDATE_CHECK";
/// OPT_OUT_ENV present with a non-empty value.
pub fn opted_out(env: &[(String, String)]) -> bool;
pub struct LaunchCheck<'a> {
    pub current: &'a str,              // env!("CARGO_PKG_VERSION")
    pub channel: &'a Channel,
    pub key: Option<[u8; 32]>,
    /// config updateCheck && !opted_out(env)
    pub enabled: bool,
    pub home: Option<&'a Path>,        // HOME, only when absolute
    pub now: chrono::DateTime<chrono::Utc>,
    pub timeout: Duration,
    pub fetch: std::sync::Arc<dyn Fetch>,
}
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LaunchOutcome {
    pub notice: Option<String>,
    /// For launcher.log only.
    pub log: Vec<String>,
}
pub fn launch_check(c: &LaunchCheck) -> LaunchOutcome;
/// The spec's notice table; None for UpToDate and Unknown.
pub fn notice(current: &str, status: &ironwire_update::UpdateStatus, channel: &Channel) -> Option<String>;
/// Create the parent 0700, append "<unix secs> update check: <line>" per line; errors ignored.
pub fn append_log(log_file: &Path, lines: &[String]);
/// Real wiring for rts launch: std::env::vars, HOME, current_exe, UPDATE_KEY,
/// HttpsFetch::with_timeouts(LAUNCH_TIMEOUT, LAUNCH_TIMEOUT), Utc::now();
/// eprintln!("[rts] {notice}"), append_log(log_file, &outcome.log).
pub fn launch_notice(update_check: bool, log_file: &Path);
```

  `launch_check`: return the default outcome, touching nothing, unless the channel is `Release` or `Homebrew`, `key` is `Some`, `enabled`, and `home` is `Some`. Load the cache; due when `should_check(true, cache, now)` or `cache.at > now`. When due, spawn a thread that sends `manifest::fetch(&*fetch, &key)` over `mpsc::channel` and `recv_timeout(timeout)`; on `Ok(m)` the status is `evaluate(current, &m.manifest, channel.method())`; on an error or a timeout push the reason (`"timed out after 3 s"` for the timeout) to `log` and keep the cached status (or `UpdateStatus::Unknown`). Create the cache parent with `DirBuilder::new().recursive(true).mode(0o700)`, then `save_cache(&path, &CheckedAt { at: now, status })`, logging an error. The notice comes from re-evaluating the status's `latest` and `minimum_supported` against `current` (build an `ironwire_update::Manifest` from them), so a stale `Available` disappears after an update.

  In `launch` (`src/main.rs:306`), immediately after `let session_id = session::new_session_id();`:

```rust
rts::update::launch_notice(cfg.update_check, &cfg.sessions_dir.join(&session_id).join("launcher.log"));
```

- [ ] **Step 1: Write the failing tests.** In `src/update/manifest.rs`, with `FakeFetch` serving `MANIFEST_URL` and `SIGNATURE_URL`:

```rust
#[test] fn fetch_reads_both_urls_and_verifies() // calls() == [MANIFEST_URL, SIGNATURE_URL]; Ok
#[test] fn a_missing_signature_is_refused()     // only MANIFEST_URL served: Err naming latest.json.sig
#[test] fn oversized_bodies_are_refused()       // manifest of (64 << 10) + 1 bytes; signature of 1025 bytes: Err "exceeds"
#[test] fn a_redirect_off_github_is_refused()   // MANIFEST_URL redirects to https://evil.example/latest.json: Err, evil never fetched
```

  In `src/update.rs`, with a helper building a `LaunchCheck` over a temp `home`, a Release channel, the test key, `now = DateTime::from_timestamp(1_800_000_000, 0)`, `timeout = 200 ms`, and a `FakeFetch` serving a signed manifest for `0.2.0`; `current = "0.1.0"`:

```rust
#[test] fn a_newer_release_prints_the_notice_and_caches_it()
    // notice == Some("rts 0.2.0 is available (you have 0.1.0): run rts update"); log empty; cache status Available
#[test] fn homebrew_is_told_to_use_brew()        // "... run brew upgrade rts"
#[test] fn the_floor_gets_the_stronger_warning()  // current 0.0.9, minimum 0.1.0:
    // "rts 0.0.9 is older than the oldest supported release, 0.1.0, and may not work: run rts update to install 0.2.0"
#[test] fn up_to_date_prints_nothing()            // current 0.2.0 and 0.3.0: notice None
#[test] fn checks_are_at_most_daily()             // second call 1 h later: FakeFetch calls unchanged, same notice from cache;
                                                  // 25 h later: two more calls
#[test] fn a_future_cache_time_counts_as_due()    // cache at = now + 30 days: fetched
#[test] fn a_stale_cached_notice_disappears_after_updating() // cache Available{0.2.0}, 1 h old, current "0.2.0": None, no fetch
#[test] fn a_failure_keeps_the_previous_status()  // cached Available{0.2.0} 25 h old, FakeFetch empty: notice still shown,
                                                  // log has one line naming latest.json, cache at == now
#[test] fn a_bad_signature_is_logged_not_shown()  // signed by the wrong key: notice None, log contains "signature"
#[test] fn a_slow_fetch_never_holds_the_launch()  // a Fetch that sleeps 10 s: returns in < 2 s, notice None, log "timed out"
#[test] fn opting_out_reads_nothing_and_fetches_nothing()
    // for (enabled=false), (channel Source), (key None), (home None): default outcome, no calls, cache file not created;
    // a corrupt cache file present is left byte-identical
#[test] fn the_cache_directory_is_private()       // home without .local/share/nearai-red-sandbox: after the check its mode & 0o777 == 0o700
#[test] fn opted_out_env()                        // RTS_NO_UPDATE_CHECK "1" and "yes" -> true; "" and absent -> false
#[test] fn the_log_goes_to_launcher_log()         // append_log(<t>/s/abc/launcher.log, ["x"]): dir mode 0700, line matches ^\d+ update check: x$
```

  In `src/config.rs`: `update_check_defaults_on_and_can_be_turned_off`: `{}` gives `true`, `{"updateCheck": false}` gives `false`, `{"updateCheck": "no"}` is an `Err` starting `config:`. In `src/install.rs` extend `layout_paths_match_the_spec`: `update_cache(h) == "/h/.local/share/nearai-red-sandbox/update-check.json"`.

- [ ] **Step 2: Run, expect FAIL** — `T --lib update:: config::tests install::tests` fails to compile: `cannot find function \`launch_check\``, `no field \`update_check\``, `cannot find function \`update_cache\``.

- [ ] **Step 3: Implement** as in Interfaces. `config::parse_config` sets `update_check: raw.update_check.unwrap_or(true)`. The slow fake is test-local: `struct Slow(Duration); impl Fetch for Slow { fn get(&self, _: &Url) -> Result<Hop, String> { std::thread::sleep(self.0); Err("slow".into()) } }`.

- [ ] **Step 4: Run, expect PASS** — the targeted tests, then the full gate. `T --bin rts` still passes (no CLI change yet).

- [ ] **Step 5: Commit** — `git add src && git commit -m "Check for a newer signed release at launch"`

---

### Task 3: `rts update`

**Files:**
- Create: `src/update/apply.rs`; Modify: `src/update.rs` (`pub mod apply;`)
- Modify: `src/main.rs` (header `:1-7`, `Action` `:16-28`, `parse_args` `:37-39`, `USAGE` `:174`, dispatch `:437-464`, tests)
- Modify: `install.sh` (environment comment `:5-7`, validation after `:56`, check after `:78`), `tests/unit/install.test.ts`

**Interfaces:**
- Consumes: `manifest::{fetch, SignedManifest}`; `setup::{Fetch, download, HttpsFetch}`; `session::{Host, RealHost}` (`src/session.rs:54-67`); `ironwire_update::{evaluate, UpdateStatus}`; `tempfile::Builder`.
- Produces (`src/update/apply.rs`):

```rust
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UpdateOptions { pub check: bool, pub force: bool }
pub const RELEASE_DOWNLOAD: &str = "https://github.com/nearai/nearai-red-sandbox/releases/download";
pub const MAX_INSTALL_SH_BYTES: u64 = 64 << 10;
pub const TEAM_REQUIREMENT: &str = r#"anchor apple generic and certificate leaf[subject.OU] = "KXSWJN7WY8""#;

/// Runs install.sh with inherited stdio and no timeout.
pub trait Installer {
    /// `set` is added to the inherited environment after `remove` is removed. Returns the exit code.
    fn run(&self, script: &Path, set: &[(String, String)], remove: &[&str]) -> Result<i32, String>;
}
pub struct BashInstaller; // Command::new("/bin/bash").arg(script), env_remove each, envs(set), status()

pub struct UpdateContext<'a> {
    pub current: &'a str,
    pub channel: &'a Channel,
    pub key: Option<[u8; 32]>,
    pub fetch: &'a dyn Fetch,
    pub host: &'a dyn crate::session::Host, // codesign and --version, 30 s each
    pub installer: &'a dyn Installer,
    pub temp_dir: &'a Path,                 // parent for the private stage directory
    /// Progress lines that must appear before install.sh runs (command passes println!).
    pub say: &'a dyn Fn(&str),
}
/// The spec's steps 1-8. Ok lines are printed by `command`.
pub fn run(o: &UpdateOptions, c: &UpdateContext) -> Result<Vec<String>, String>;
/// Real wiring: current_exe -> channel, UPDATE_KEY, HttpsFetch::new(), RealHost, BashInstaller, std::env::temp_dir().
pub fn command(o: &UpdateOptions) -> Result<i32, String>;
```

- Produces (`src/main.rs`): `Action::Update(rts::update::apply::UpdateOptions)`; `fn parse_update(flags: &[&str]) -> Result<Action, String>` in the shape of `parse_setup` (`:136-155`): `--check`, `--force`, `--help`/`-h`; duplicates `Duplicate option: <flag>`; unknown `Unknown option for update: <flag>`; both together `--check and --force cannot be combined`. `USAGE` gains `       rts update [--check | --force]` after the setup line and the sentence `rts update installs the newest signed release over a curl install; --check only reports.` The header gains `//!   rts update [--check | --force]  install the newest signed release`.

- `install.sh`: optional `RTS_TARBALL_SHA256`. When set and non-empty it must match `^[0-9a-f]{64}$` (checked with the other environment checks, before any download: `die "RTS_TARBALL_SHA256 must be 64 lowercase hex characters"`); after the `SHA256SUMS` check the tarball's `shasum -a 256` must equal it (`die "$tarball from $base does not match RTS_TARBALL_SHA256 (the signed update manifest); refusing to install it"`). Unset or empty: today's behaviour.

- [ ] **Step 1: Write the failing tests** (`src/update/apply.rs`). A rig: temp prefix with `bin/rts` and `share/nearai-red-sandbox/plugin/`, Release channel, test key, `FakeFetch` serving the signed manifest for `0.2.0` whose `install_sh.sha256` is the digest of `INSTALL_SH = b"#!/bin/bash\necho fake\n"` and the versioned URL `.../download/v0.2.0/install.sh` serving it; a recording fake `Installer` (returns a configured code, records `script`, `set`, `remove` and the script's bytes at call time); a fake `Host` answering codesign with exit 0 and `<prefix>/bin/rts --version` with `rts 0.2.0\n`.

```rust
#[test] fn homebrew_is_refused_with_the_brew_command()   // Err == "rts was installed with Homebrew: run brew upgrade rts"; no fetch
#[test] fn a_keyless_build_is_refused()                   // key None: Err == "this build has no update key; install a release"; no fetch
#[test] fn a_source_build_is_refused()                    // Err contains "install a release"; no fetch
#[test] fn check_only_reports()                           // --check: Ok lines mention 0.2.0; FakeFetch calls == [MANIFEST_URL, SIGNATURE_URL]; installer not called
#[test] fn not_newer_is_refused_unless_forced()           // current 0.2.0: Err contains "--force"; with force: installer called once
#[test] fn an_unreadable_version_is_refused_even_forced() // current "dev": Err with and without force
#[test] fn an_install_sh_digest_mismatch_runs_nothing()   // served bytes differ: Err names install.sh and both digests; installer never called
#[test] fn the_installer_gets_the_signed_tarball_digest_and_no_release_base() {
    // set == [("RTS_VERSION","0.2.0"), ("RTS_INSTALL_PREFIX", <prefix>), ("RTS_TARBALL_SHA256", <manifest tarball sha>)]
    // remove == ["RTS_RELEASE_BASE"]; script bytes == INSTALL_SH; the stage directory is gone after run returns
}
#[test] fn a_failing_install_sh_is_reported()             // installer returns 3: Err contains "exited 3"; no codesign call
#[test] fn the_post_install_code_signature_is_required() {
    // host argv[0] == ["/usr/bin/codesign", "--verify", "--strict", &format!("-R={TEAM_REQUIREMENT}"), <prefix>/bin/rts]
    // codesign exit 3: Err contains "was installed to" and "code signature"
}
#[test] fn the_installed_version_must_match()             // --version prints "rts 0.1.9": Err names both versions
#[test] fn success_names_both_versions()                  // Ok last line == "rts updated from 0.1.0 to 0.2.0 (<prefix>/bin/rts)"
#[test] fn the_version_being_installed_is_announced_first() // say() got "installing rts 0.2.0 over 0.1.0 to <prefix>" before the installer was called (shared event log), also with force
```

  In `src/main.rs` tests: `update_parses_its_flags`: `["update"]`, `["update","--check"]`, `["update","--force"]` give the expected `UpdateOptions`; `["update","--check","--force"]`, `["update","--check","--check"]`, `["update","--yes"]` are `Err`; `["update","--help"]` is `Help`; `USAGE` contains `rts update`.

  In `tests/unit/install.test.ts`, using the existing `release()` / `env()` helpers (`:48-82`): "a tarball that matches SHA256SUMS but not RTS_TARBALL_SHA256 is refused" (64 zeros: exit 1, stderr names `RTS_TARBALL_SHA256`, prefix has no `bin/rts`, `rts setup` never logged); "a malformed RTS_TARBALL_SHA256 is refused before downloading" (`ABC`); "a matching RTS_TARBALL_SHA256 installs" (the fake tarball's sha256: exit 0).

- [ ] **Step 2: Run, expect FAIL** — `T --lib update::apply` fails to compile (`file not found for module \`apply\``); `T --bin rts` fails to compile (`no variant \`Update\``); `bun test tests/unit/install.test.ts` fails the three new tests (the mismatch installs; the malformed value is accepted).

- [ ] **Step 3: Implement.** `run` follows the spec's steps in order; every error names the step and URL or path. The stage directory is `tempfile::Builder::new().prefix("rts-update-").tempdir_in(temp_dir)` (0700 by default), `install.sh` is written there with `create_new` and mode 0600 only after its digest matches (download into a `Vec<u8>` first). Do not edit `setup::download`'s messages.

- [ ] **Step 4: Run, expect PASS** — the targeted tests, then the full gate, including `shellcheck install.sh`.

- [ ] **Step 5: Commit** — `git add src install.sh tests/unit/install.test.ts && git commit -m "Add rts update"`

---

### Task 4: Sign the manifest in the release workflow

**Files:**
- Create: `scripts/release/sign-manifest.sh`
- Modify: `.github/workflows/release.yml` (header `:1-23`, `release-config` `:49-72`, "Install test tools" `:112-113`, "Build rts" `:135-136`, new step after "Package" `:262-272`, attestation `:276-280`, publish file loop `:313`, release notes `:337-351`)
- Modify: `tests/unit/release.test.ts`

**Interfaces:**
- Consumes: `DIST/SHA256SUMS` as `scripts/package-release.sh:103` writes it; env `RTS_UPDATE_SIGNING_KEY_PEM_BASE64`.
- Produces:

```
sign-manifest.sh --version X.Y.Z --dir DIST --public-key-hex HEX
                 [--minimum X.Y.Z] [--published YYYY-MM-DDTHH:MM:SSZ] [--openssl PATH]
```

  Writes `DIST/latest.json` (the spec's layout, two-space indent, trailing newline, `minimum_supported` only with `--minimum`), `DIST/latest.json.sig` (base64, no newline), and appends their two `shasum -a 256` lines to `DIST/SHA256SUMS`. Exit 0 only after `pkeyutl -verify` with the given public key and a final `shasum -a 256 -c SHA256SUMS`. Every refusal is `sign-manifest: refusing: <reason>` on stderr, exit 1, and leaves `DIST` as it was. `--published` defaults to `date -u +%Y-%m-%dT%H:%M:%SZ`; `--openssl` defaults to `$(brew --prefix openssl@3)/bin/openssl`.

  Workflow step, after "Package":

```yaml
      # After packaging: the manifest names the packaged tarball's and
      # install.sh's digests. Dry runs sign too and publish nothing.
      - name: Sign the update manifest
        env:
          V: ${{ steps.version.outputs.version }}
          RTS_UPDATE_PUBLIC_KEY_HEX: ${{ vars.RTS_UPDATE_PUBLIC_KEY_HEX }}
          RTS_UPDATE_SIGNING_KEY_PEM_BASE64: ${{ secrets.RTS_UPDATE_SIGNING_KEY_PEM_BASE64 }}
        run: |
          set -euo pipefail
          if ! [[ "$RTS_UPDATE_PUBLIC_KEY_HEX" =~ ^[0-9a-f]{64}$ ]]; then
            echo "refusing: repository variable RTS_UPDATE_PUBLIC_KEY_HEX is not 64 lowercase hex characters" >&2
            exit 1
          fi
          minimum=()
          if [ -f packaging/update/minimum-version ]; then
            minimum=(--minimum "$(cat packaging/update/minimum-version)")
          fi
          bash scripts/release/sign-manifest.sh --version "$V" --dir "$RUNNER_TEMP/dist" \
            --public-key-hex "$RTS_UPDATE_PUBLIC_KEY_HEX" ${minimum[@]+"${minimum[@]}"}
          ls -l "$RUNNER_TEMP/dist"
```

  `release-config` gains, for `github.event_name == 'push'`, "Confirm the update public key is configured" with the same regex and the message `refusing to release: repository variable RTS_UPDATE_PUBLIC_KEY_HEX is unset or not 64 lowercase hex characters`. "Build rts" gets `env: RTS_UPDATE_PUBLIC_KEY_HEX: ${{ vars.RTS_UPDATE_PUBLIC_KEY_HEX }}`. "Install test tools" becomes `brew install coreutils gnu-tar shellcheck openssl@3`. Attestation `subject-path` adds `${{ runner.temp }}/dist/latest.json` and `${{ runner.temp }}/dist/latest.json.sig`. The publish loop becomes `for f in "rts-$V-aarch64-apple-darwin.tar.gz" install.sh SHA256SUMS latest.json latest.json.sig; do`. The release notes add: `Installed with curl? rts update installs later releases; it accepts only a release whose latest.json is signed with the update key in README.md.` The header comment names the new variable and secret.

- [ ] **Step 1: Write the failing tests** (`tests/unit/release.test.ts`). A helper `signDist()` packages with `pkg("0.2.0")` (existing helper, `:42-47`), generates a throwaway key with `$OPENSSL genpkey -algorithm ed25519` where `const OPENSSL = process.env.RTS_OPENSSL ?? "/opt/homebrew/opt/openssl@3/bin/openssl"`, derives its public hex (`pkey -pubout -outform DER`, last 32 bytes), and runs the script with `TMPDIR` set to a fresh empty directory and `--published 2026-11-02T18:04:11Z --openssl $OPENSSL`.

```ts
test("the manifest has the exact layout and names the packaged digests")
  // readFileSync(latest.json) === the spec's layout with sha256(tarball), sha256(install.sh); no minimum_supported
test("the signature verifies with OpenSSL against the public key") // decode .sig (64 bytes), pkeyutl -verify -rawin: exit 0
test("--minimum writes minimum_supported")                          // --minimum 0.1.0
test("SHA256SUMS gains exactly the two manifest lines and still checks") // 4 lines; shasum -a 256 -c exits 0
test("a signing key that does not match the public key is refused and leaves nothing")
  // second key's public hex: exit 1; no latest.json or latest.json.sig; SHA256SUMS byte-identical
test("LibreSSL is refused")                                         // --openssl /usr/bin/openssl: exit 1, stderr contains "LibreSSL"; skipped unless its `version` starts with LibreSSL
for (const [label, change] of [["an empty signing key", ...], ["a short public key", ...], ["--version v0.2.0", ...],
                               ["--minimum above --version", ...], ["a version that differs from the tarball", ...]])
  test(`${label} is refused`)                                       // exit 1, DIST unchanged
test("no key material is left behind")                              // the TMPDIR given to the script is empty afterwards
test("the release workflow signs the manifest after packaging and before attesting") {
  // wf = release.yml; indexOf("- name: Package") < indexOf("- name: Sign the update manifest")
  //   < indexOf("actions/attest-build-provenance@") < indexOf("name: dist")
  // the attestation block contains "dist/latest.json" and "dist/latest.json.sig"
  // the publish loop line contains "latest.json latest.json.sig"
  // the "Build rts" step contains "RTS_UPDATE_PUBLIC_KEY_HEX: ${{ vars.RTS_UPDATE_PUBLIC_KEY_HEX }}"
  // the release-config job contains "RTS_UPDATE_PUBLIC_KEY_HEX" and the sign step reads secrets.RTS_UPDATE_SIGNING_KEY_PEM_BASE64
  // the build job keeps "environment: release"
}
```

- [ ] **Step 2: Run, expect FAIL** — `bun test tests/unit/release.test.ts`: the new tests fail (`sign-manifest.sh` does not exist: exit 127; the workflow lacks the step, so `indexOf` is -1).

- [ ] **Step 3: Implement** the script in the style of `scripts/package-release.sh` (`die`, flag loop, validate everything before writing, `trap cleanup EXIT`). The key goes to `$(mktemp -d)/key.pem` under `umask 077` via `printf '%s' "$RTS_UPDATE_SIGNING_KEY_PEM_BASE64" | base64 --decode`; the public key to `pub.pem` via `printf '302a300506032b6570032100%s' "$hex" | xxd -r -p` and `openssl pkey -pubin -inform DER`. Write `latest.json` and `.sig` to temporary names in `DIST` and rename them only after verification succeeds; append to `SHA256SUMS` last. Compare versions as three integers, not with `sort -V`. Then the workflow edits as in Interfaces.

- [ ] **Step 4: Run, expect PASS** — `bun test tests/unit` passes in full; `shellcheck scripts/release/sign-manifest.sh` and `actionlint .github/workflows/release.yml` are clean; then the full gate.

- [ ] **Step 5: Commit** — `git add scripts/release/sign-manifest.sh .github/workflows/release.yml tests/unit/release.test.ts && git commit -m "Sign the update manifest in the release workflow"`

---

### Task 5: Operator docs and the public key

**Files:**
- Modify: `README.md` (Install section `:19-48`)
- Modify: `opencode/README.md` (launcher options: `updateCheck`, `RTS_NO_UPDATE_CHECK`)
- Modify: `docs/specs/2026-10-29-release-and-installers-design.md` (Release pipeline steps 8-9: the manifest and its signature; "Out of scope for v1": auto-update now has its own spec)

**Interfaces:**
- Consumes: the spec's operator behaviour, security notes and the hand-verification commands.
- Produces: README subsection "Updates": the launch notice and its cadence, both opt-outs, `rts update [--check | --force]`, that Homebrew installs use `brew upgrade rts`, the public key `9b4a81b8bd017898c36871c6bd1cb890faf95b6e378e72eb99b9c15841f02ac9` and the four OpenSSL commands to verify a `latest.json` by hand.

- [ ] **Step 1: Write the failing check.** Add to `tests/unit/release.test.ts`: "the README publishes the update public key": `README.md` contains the repository value exactly once and `rts update`; the value equals the one in this plan's Global Constraints table (a literal in the test).

- [ ] **Step 2: Run, expect FAIL** — `bun test tests/unit/release.test.ts`: the new test fails (the key is absent).

- [ ] **Step 3: Write the docs.** Plain, dated where a fact was measured, no emojis.

- [ ] **Step 4: Run, expect PASS** — `bun test tests/unit` in full, then the full gate. Run the README's hand-verification commands against a manifest produced by Task 4's test helper (with that test's key substituted) and paste the `Signature Verified Successfully` line.

- [ ] **Step 5: Commit** — `git add README.md opencode/README.md docs/specs/2026-10-29-release-and-installers-design.md tests/unit/release.test.ts && git commit -m "Document update notices, rts update and the update key"`

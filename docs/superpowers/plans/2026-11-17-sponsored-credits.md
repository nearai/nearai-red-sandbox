# Sponsored credits implementation plan

> **For agentic workers:** Use executing-plans for integration; independent authentication storage work is delegated.

**Goal:** Give each recipient an imported sponsored key and transition to personal Cloud login on exhaustion/revocation.
**Architecture:** Native keyring tracks sponsored vs account credentials. A host credential handoff manager serializes login and is shared with the pinned forwarder; IronWire receives a placeholder. Forwarder retries only explicit rejected requests with the newly minted personal key and snapshots auth for receipts.
**Tech Stack:** Existing Rust, Tokio, reqwest, native keyring, IronWire; no new dependencies.
**Spec:** ../specs/2026-11-17-sponsored-credits-design.md

## Global constraints

- Preserve the primary checkout; isolated checkout in /private/tmp/rts-sponsored-credits (no eligible existing donor).
- Every Cargo command uses RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0; builds use shared build lock and CARGO_BUILD_JOBS=4; full test binaries use shared test lock separately.
- Keys never enter logs, VM, OpenCode config, argv or runtime config; no server credit provisioning during validation.

## Review focus

Concurrent refusals share login; cancellation must not steal session signals; failed login cannot create retry storms; receipts retain per-request credentials; transient errors and personal credit failures cannot open browsers.

### Task 1: Import and persist sponsored credentials
- [x] Add failing storage/import tests preserving v1 account storage.
- [x] Implement auth::LaunchCredential, load_for_launch, import_sponsored and cancellable session login.
- [x] Add `rts trial --key-file PATH` parsing/dispatch and tests.

### Task 2: Handoff and pinned retry
- [x] Add failing classification/concurrent/login-failure tests in src/sponsored.rs.
- [x] Implement key snapshots and serialized one-time recovery; cancellation flag.
- [x] Add local TLS tests for 401/402 retry, exact bytes, replacement auth and receipt auth.
- [x] Integrate optional credentials into forwarder; select current key at send, retry once, preserve pin checks and fatal policy.
- [x] Wire launch to auth::load_for_launch; reattestation reads the current credential; handle prelaunch invalid-key attestation refusal.

### Task 3: Documentation and validation
- [x] Document operator issuance JSON, individual allowances, secure import and personal handoff, no expiry and in-flight overage.
- [x] Run focused tests then full Rust and plugin regressions, format touched files and inspect diff.
- [x] Obtain independent review and fix material findings before completion.

## Validation evidence

- Strict locked Rust test build succeeded with the documented flags and shared build lock.
- Focused sponsored scenarios: 12 passed. Authentication: 20 passed. Full forwarder module: 56 passed. Typed prelaunch refusal regression passed (observed failing before correction).
- CLI suite: 29 passed. Plugin suite: 139 passed.
- Full library: 494 passed, 5 copy tests failed, 3 ignored. Copy/protocol/tar/test harness files are unchanged; all five failures reproduced on unchanged base 1a56e3e (copy module: 2 passed, 5 failed).
- Independent review found cancellation and pending-login issues, which were fixed and covered by added tests; final source review found no confirmed blockers.
- No live Cloud sign-in, key issuance, account funding, installed-binary replacement or release was performed.

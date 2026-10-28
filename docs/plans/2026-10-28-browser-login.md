# Browser login implementation plan

> **For agentic workers:** Use superpowers:executing-plans. Steps use checkbox syntax for tracking.

**Goal:** Make NEAR AI Cloud browser login the default connection flow for `rts launch`, with an explicit `rts login` entry point.

**Architecture:** A host-only Rust loopback ceremony mints a dedicated inference key, persists it in a sandbox-specific OS credential store, and discards the broad browser session tokens. Embedded IronWire receives that key in memory and exposes only its loopback OpenAI facade to OpenCode. Existing explicit external-provider configurations remain supported.

**Tech stack:** Rust, reqwest with rustls, url, native keyring providers, Tokio, pinned IronWire embedding API. TypeScript remains only the existing OpenCode plugin shim.

## Constraints and decisions

- User approved direct implementation of this approach on 2026-10-28.
- GitHub browser login is the default; Google is selectable.
- Bind 127.0.0.1 on an ephemeral port before opening the browser. Use a random callback path and independent random local nonce; reject cross-origin submissions and malformed/oversized callback data. Browser fragments never become server logs or command arguments.
- Five-minute ceremony deadline, bounded per-request reads, no automatic login during help, tool calls, or background work.
- Select organization/workspace explicitly if multiple are available; refuse ambiguity in noninteractive use.
- Native-store errors fail closed; no plaintext file fallback. Never retain broad access/refresh tokens after inference-key creation.
- Embedded IronWire has an isolated runtime home, explicit NEAR AI credential callback, credential-file discovery off, background probes off, updates off, and no fallback providers.
- Credentials never enter OpenCode's environment, configuration, command line, audit log, guest, or exports.
- Do not claim a live browser sign-in or containment pass from mocks or skipped tests.

## Review focus

Callback spoofing and duplicate fields; account ambiguity; native-store failures; accidental environment credential discovery; startup/shutdown ordering and plugin readiness.

### Task 1: Browser ceremony and native credential store

Files: `src/auth.rs`, `src/auth/*` as necessary; module tests.

- [ ] Write failing tests for callback binding, rejected origin/nonce/duplicate/oversized data, timeout, organization/workspace choice, and storage failure.
- [ ] Implement `LoginOptions`, redacted `InferenceCredential`, `login`, and `load_or_login`; inject storage/browser/API boundaries in tests.
- [ ] Verify against local mock HTTP endpoints and an in-memory store; never access real user credentials in automated tests.

### Task 2: Embedded inference and CLI integration

Files: `src/inference.rs`, `src/main.rs`, `src/config.rs`, `src/lib.rs`, `Cargo.toml`, `Cargo.lock`, operator docs.

- [ ] Write failing tests that default config selects embedded mode, explicit external config remains external, and secret environment variables do not reach OpenCode.
- [ ] Embed pinned IronWire with host credential callback, private per-launch home, port zero, and bounded shutdown.
- [ ] Add `rts login` options and default launch authentication; perform local preflight before opening a browser or reading native credentials.
- [ ] Verify help, malformed args, mocked launch flow, Cargo tests, Clippy, plugin tests, and documentation.

### Task 3: Merge-readiness repairs for PR #1

Files: `src/session.rs`, `src/mvm.rs`, containment tests.

- [ ] Verify startup ordering against pinned OpenCode, then gate interaction until the plugin verifies containment.
- [ ] Fail closed if supervisor identification/RSS monitoring is unavailable.
- [ ] Quiesce in-flight tools before export/removal; correct stray-plugin integration expectation.
- [ ] Run real mvm/OpenCode containment where available; record failures and skipped gates. Merge PR #1 only after material blockers are resolved.

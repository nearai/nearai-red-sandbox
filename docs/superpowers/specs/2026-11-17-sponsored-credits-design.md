# Sponsored Red Sandbox credits

Status: approved for implementation by user: "build it" following the agreed flow.

Each recipient receives a unique Cloud API key and an individual spending allowance. Keys have no expiry; Cloud enforces their allowance and revocation. Once Cloud rejects a sponsored key as invalid/revoked or out of credit, Red Sandbox prompts for NEAR AI Cloud browser login, stores the personal account credential, switches the active inference credential, and retries the explicitly rejected request once. Preserve the VM, OpenCode process, conversation, attestation and receipt verification. Personal account credits are required to continue.

## Approaches

Use existing Cloud per-key spending limits in a funded sponsor workspace (selected). A custom voucher/billing service would duplicate the existing lifecycle. Separate organizations per recipient would add unnecessary provisioning overhead. Cloud limits check recorded usage, not reserved request cost: in-flight usage can overshoot. This implementation does not claim a hard financial ceiling.

## Implementation choices

Import a sponsor key from a private host file with `rts trial --key-file PATH`, store it in the native credential store, then launch normally. Successful personal login replaces the sponsored credential; failed login leaves persistent state unchanged. No new dependencies, expiry, auto-topup, public shared key or guest credential access. All inference uses the existing pinned forwarder. Explicit 401 invalid_api_key and known 402 credit refusals trigger a single browser flow shared by concurrent requests. Network failures, 403, 429, 5xx and malformed errors do not trigger login. Personal-key failures never open a login loop. Only rejected requests are retried, never successful/partial streams. Every receipt uses the credential of its corresponding request. Host shutdown cancels pending login.

## Validation

Test storage compatibility and safe imports, rejection classification, concurrent handoff and login failure, exact-body retry with local pinned TLS, stream behavior, receipt credential, CLI parsing, and existing authentication/forwarder regression suites. No real recipient keys are issued or credits spent during tests.

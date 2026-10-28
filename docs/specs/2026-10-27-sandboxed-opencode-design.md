# Sandboxed opencode sessions on mvm: design

Date: 2026-10-27
Status: approved 2026-10-27, then amended by probes 1-5 the same day.
Amended 2026-10-28 for attested NEAR AI inference (decisions by Zaki the same
day; plan `docs/plans/2026-10-28-attested-inference.md`).

## Purpose

Run opencode sessions for security research and red-teaming where every tool
call executes inside an mvm microVM, never in host user space. opencode itself
runs on the host and talks to NEAR AI inference. The microVM is the only place
tool effects land.

## Decisions

| Topic | Decision |
|---|---|
| Harness | opencode, a released v2 build pinned by version (v2.1.4, already installed). Plugin API V2; its tool API is identical in v2.1.4, v2.2.0 and `dev`. |
| Where the harness runs | Host. Tools are replaced, not intercepted, so execution goes to the VM. |
| Sandbox | mvm (`tinylabscom/mvm`, Apache-2.0), dev profile, `machine create` / `exec` / `rm` |
| Guest image | A digest-pinned OCI image (default `docker.io/library/alpine@sha256:e311ae74...ffb42`, the one the probes ran on). A Nix `mkGuest` image is deferred. |
| Inference | NEAR AI through IronWire embedded in `rts` (`ironwire_proxy::embed`, loopback port 0, OpenAI façade at `http://127.0.0.1:<port>/openai/v1`). IronWire holds the key, so neither opencode nor the VM sees it. An explicit external provider (any of `provider.id`, `provider.baseURL` or `provider.apiKeyEnv` set, `src/config.rs:219`) bypasses IronWire and the forwarder, so it is refused unless `--allow-unattested-provider` is passed. |
| Models | By default, only NEAR AI's private abliterated models, by exact ID (launching 2026-10-29; on staging as of 2026-10-28; IDs not yet known, so the default is a marked placeholder that refuses to launch). `provider.models` is the allowlist. It is enforced three times: by `rts` config, by the plugin's model filter (exact IDs passed as a plugin option), and by the forwarder. |
| Inference attestation | Before every session, in `rts`, after credentials and before IronWire starts: fetch NEAR AI's attestation report with a fresh nonce and verify it fail-closed (TDX quote with `dcap-qvl =0.7.0`, report data binding, compose measurement, NVIDIA GPU verdict). Any failure refuses the session. |
| Inference path | IronWire's NEAR AI endpoint is an attested forwarder inside `rts` (`http://127.0.0.1:<port>/v1`), not `cloud-api.near.ai`. The forwarder pins upstream TLS to the attested certificate fingerprints, refuses models outside the allowlist, and verifies every response's ed25519 signature. A failed signature ends the session. Chosen over patching IronWire. |
| VM egress | None. mvm default-deny, no `--allow-host`. |
| Files in | An operator inputs directory, packed into a tar on the host and pushed in after boot as base64 argv chunks, extracted to `/in`. A copy, not a live mount. |
| Files out | Only the guest's `/out`, copied to `sessions/<id>/out` before teardown. |
| Lifecycle | One VM per opencode session, always destroyed when the session ends, including on crash or signal. |
| mvm access | Shell out to `mvmctl` release v0.22.0, installed from the cosign-verified release tarball at `~/.local/mvm/v0.22.0`. No mvm SDK in v1. |
| Backend seam | Launcher and plugin talk to a `Sandbox` interface, never to `mvmctl` directly. mvm is the only v1 backend. |
| Language | Rust for the launcher, the Sandbox backend and the tools (`rts`), following IronWire's conventions. The opencode plugin stays a thin TypeScript shim that spawns `rts tool`, because opencode loads plugins in-process. Nix flake for the guest image. |

## Architecture

```
host (macOS)                                   mvm microVM (dev profile, no network)
-------------------------------------          -------------------------------------
launcher
  1. mvmctl machine create/start rts-<s> ---> boots image; inputs pushed to /in
  0. credentials -> attest NEAR AI -> forwarder -> embedded IronWire
  2. starts opencode (pinned v2 version)
       |-- provider: IronWire -> forwarder (pinned TLS) -> NEAR AI
       '-- sandbox plugin
             shell/read/write/edit/glob/grep
               '-- mvmctl machine exec    ---> runs in guest, stdout/stderr/exit back
  3. on exit or signal:
       copy /out -> sessions/<id>/out     <--- /out only
       mvmctl machine rm rts-<session>
```

### Sandbox interface (`sandbox/`)

```ts
interface Sandbox {
  create(spec: { name: string; image: string; memoryMiB: number; cpus: number }): Promise<void>
  exec(argv: string[], opts: { timeoutMs: number; maxOutputBytes: number }):
    Promise<{ exitCode: number; timedOut: boolean; stdout: Uint8Array; stderr: Uint8Array;
              stdoutBytes: number; stderrBytes: number; truncated: boolean }>
  copyIn(hostDir: string, guestDir: string): Promise<void>
  copyOut(guestDir: string, hostDir: string):
    Promise<{ status: "exported"; files: number; bytes: number } | { status: "nothing to export" }>
  remove(): Promise<void>
}
```

The v1 implementation, `MvmSandbox`, shells out to `mvmctl`. Every call is
argv-based; nothing is passed through a host shell. A second backend (for
example apple/container) would implement the same interface and must pass the
same containment suite.

`create` runs exactly `mvmctl machine create <name> --image <digest-ref>
--profile dev --cpus <n> --memory <MiB>M`, then `mvmctl machine start <name>`.
It never passes `--net`, `--allow-host`, `--peer`, or `--gpu`; those are what
would open a path out. Every `mvmctl` child gets stdin `/dev/null` and
`GIT_CONFIG_GLOBAL` pointing at an empty file.

`mvmctl machine exec` constraints measured on v0.22.0 (probe 4) shape the
implementation:

- **A nonzero exit poisons the machine.** After any exec whose guest command
  exits nonzero (`false`, `exit 3`), every later exec on that machine fails
  with `machine input sequence N has no durable finish; refuse exec and
  checkpoint until the ambiguous operation is recovered`, and a restart does
  not clear it. So every exec runs inside a guest-side wrapper that always
  exits 0 and reports the real status on stderr as a final line
  `RTS_EXIT_<nonce> <status>`, with a fresh random nonce per call. The status
  is information for the model, not a security property; a guest that forges
  it only misleads itself.
- **Killing the exec client from the host also poisons the machine.** Tool
  time limits are enforced in the guest by the wrapper with
  `timeout -s KILL <seconds>` (status 137 on expiry). The host keeps a
  backstop timer at the limit plus 30 s; if it fires, the machine is treated
  as lost and the session ends with `sandbox unavailable`.
- **stdin is not passed through**; the guest command reads nothing. `exec`
  is always spawned with stdin set to `/dev/null`. File content for `write`
  and `edit` travels in argv as base64, in chunks of at most 48 KiB, each
  appended in the guest with `base64 -d`. A 48 KiB random base64 argv was
  measured to work; the host's own `ARG_MAX` refused 1 MiB.
- **Large stdout is truncated silently.** An 8 MiB stdout arrived as
  974,403 bytes with no error. The wrapper writes the command's stdout to a
  guest temp file, and stderr to another, reports both full sizes in the
  trailer, and emits only the first `maxOutputBytes` of each, so `truncated`
  is computed from the reported sizes. The trailer line is
  `RTS_EXIT_<nonce> <status> <stdoutBytes> <stderrBytes>`.
- Any exec result containing the `no durable finish` error, or missing its
  trailer, means the machine is unusable: `exec` reports `sandbox
  unavailable` for that call and every later one.

Root cause of the poisoning, read from the v0.22.0 source: `machine exec`
journals a start (`machine/mod.rs:1448`) and a finish (`:1450`) around
`exec_machine`, but the console path calls `std::process::exit` on a nonzero
guest status (`vm/console.rs:320`), so the finish is never written. A host
kill skips it the same way. `main` at `054ec4c3` has the same structure. Filed
upstream as tinylabscom/mvm#4809 on 2026-10-27. When it is fixed, the
wrapper can stay; it costs one `sh` per exec.

The SDK (`mvm` on npm) may use a different vsock path for `exec` and
`files.write`; that is the obvious v2 investigation if the argv protocol
becomes a bottleneck, and it needs its own dependency approval.

Other v0.22.0 behavior the implementation depends on (probe 5):

- `machine create` accepts any string as `--image`, including an error
  message, and only `machine start` rejects it. `MvmSandbox.create` accepts
  only a digest-pinned reference matching
  `^[a-z0-9./-]+@sha256:[0-9a-f]{64}$`.
- `machine rm` prompts for confirmation; without `--yes` it prints `aborted`
  and removes nothing. Teardown uses `rm --force --yes` and then confirms with
  `machine ps` that no machine of that name remains.
- `image inspect` has no `--digest-ref` in v0.22.0 (that flag is on `main`).
  The digest comes from the `Resolved digest:` line of `image inspect
  <full reference>`.
- An alpine machine (1 vCPU, 512 MiB) boots in about 2 s on the HVF backend.
- No egress, measured on a dev-profile alpine machine created as above: the
  only interface is `lo`; routes are blackholes for `100.64.0.0/10`,
  `169.254.0.0/16`, and `169.254.169.254`; there is no `/etc/resolv.conf`;
  `wget http://1.1.1.1` fails with `Network unreachable`.

`copyIn` packs the host inputs directory into a tar on the host and pushes it
as base64 argv chunks (the `write` path), then extracts it to `/in` in the
guest. v0.22.0 `machine create` has no mount flag, so this replaces the
boot-time mount the first draft assumed.

`copyOut` treats the guest as hostile. It archives `/out` inside the guest,
reads the archive back in base64 chunks of at most 512 KiB (under the silent
stdout truncation measured near 950 KB), checks the reassembled size against
the size the guest reported, and extracts it with a host-side extractor
that accepts only regular files and directories. It rejects symlinks,
hardlinks, device nodes, absolute paths, and any path containing `..`, and
caps total size and entry count. microsandbox's GHSA-4vq3-cjpp-v7fg (a guest
symlink in `msb copy` writing arbitrary host files) is the class of bug this
blocks.

### Launcher (`launcher/`)

- Preflight: `mvmctl doctor`, and a check that the opencode binary reports the
  pinned version. Any failure refuses before a VM exists and names what is
  missing. This local preflight reads no credentials (`local_preflight`,
  `src/main.rs:110`), and attestation is not part of it.
- Connect, for embedded inference only (`run_connected`, `src/main.rs:91`):
  load or obtain the NEAR AI key (`auth::load_or_login`), then attest NEAR AI
  for every allowed model, then start the attested forwarder seeded with the
  verified fingerprints and keys, then start embedded IronWire with its NEAR
  AI endpoint set to the forwarder. A failure at any step refuses the session
  before a VM exists. The session ID is chosen before connect, so
  `sessions/<id>/attestation.json` records a refused attestation too.
- Refuses to launch, before any of the above, when `IRONWIRE_NEARAI_BASE_URL`
  is set in its environment, when `provider.models` is still the placeholder,
  or when the config selects an external provider without
  `--allow-unattested-provider`.
- Sweeps orphaned `rts-*` machines left by an earlier crash, before creating a
  new one.
- Creates and starts `rts-<session-id>` from the configured image, runs
  `copyIn` for the inputs directory,
  then starts opencode with the machine name passed to the plugin as an option.
- Runs opencode with `--standalone` (a private server per session). Without it,
  v2 attaches to the operator's shared background service, which loads the
  operator's own config and plugins.
- Points `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME`, and
  `XDG_STATE_HOME` at a per-session directory, so no global opencode plugins,
  config, auth, or session history load. The only config is the one the
  launcher writes.
- Runs opencode with its working directory set to an empty, launcher-created
  directory, never the operator's project. opencode loads `opencode.json` and
  `AGENTS.md` from its working directory, and a project `opencode.json` can
  declare local MCP servers that opencode spawns as host processes (probe 3).
  Operator inputs reach the VM through `copyIn` only.
- Plugin handshake: the launcher passes a random per-session nonce as a plugin
  option. After its allowlist checks pass, the plugin writes the nonce to a
  ready file. If the ready file does not appear with the right nonce before a
  deadline, the launcher kills opencode and removes the VM. This is required
  because v2.1.4 skips a plugin that fails to load with only a log warning (a
  configured path that is a file rather than a directory is one such case) and
  then runs the session with the host tools.
- On normal exit, SIGINT or SIGTERM: export `/out`, then `mvmctl machine rm`.
  If the export fails, report it loudly and still remove the VM.
- A fatal report from the forwarder (signature failure, pin failure after
  re-attestation, or a refused model) is polled in the session loop beside
  the signal check and ends the session the same way: export `/out`, then
  remove the VM.

### Inference attestation (`src/attest.rs`, `src/attest/`)

Source: NEAR AI's attestation API reference
(<https://docs.near.ai/api-reference/attestation/get-attestation-report>) and
model verification guide (<https://docs.near.ai/cloud/verification/model>),
read 2026-10-28 against production `cloud-api.near.ai`, and NEAR's TypeScript
verifier `nearai/nearai-cloud-verifier` at `94554726` (`ts/model_verifier.ts`,
`ts/chat_verifier.ts`) for the report shape. Staging may differ; check 6
confirms it before the defaults point anywhere.

In the connect step, after `auth::load_or_login` and before IronWire starts,
`rts` calls, once per allowed model,

```
GET https://cloud-api.near.ai/v1/attestation/report
    ?model=<id>&nonce=<64 hex>&signing_algo=ed25519&provider=near
    &include_tls_fingerprint=true
Authorization: Bearer <key>
```

with a fresh random 32-byte nonce per request. `provider=near` matters: the
default picks the first provider to respond, which can also be `chutes`.
`signing_algo=ed25519` matches IronWire's receipt scheme and NEAR's ed25519
signing mode, so the per-response signatures below can be checked against the
attested keys. The session is refused unless every check holds:

- **Presence.** Each response has a `gateway_attestation` with a
  `tls_cert_fingerprint`, and a non-empty `model_attestations`. Every allowed
  model is covered.
- **TDX quote.** Each `intel_quote` (gateway and every model attestation)
  verifies with `dcap_qvl::verify::ring::verify` against collateral that `rts`
  fetches itself from Intel PCS, with the host clock as `now`. The TCB status
  must be `UpToDate`; `--allow-tcb-out-of-date` also accepts `OutOfDate` and
  records it. Any other status refuses.
- **Report data.** In the verified quote, `report_data[32..64]` equals the raw
  nonce, and `report_data[0..32]` equals
  `sha256(signing_address_bytes || tls_cert_fingerprint_bytes)`. For ed25519,
  `signing_address` is the hex public key. An entry without a
  `tls_cert_fingerprint` must instead carry the bare 32-byte key in
  `report_data[0..32]` (upstream's non-TLS mode, `checkReportData`); the
  gateway entry may not use that mode. Model entries must be ed25519 with a
  32-byte key.
- **Compose.** `mr_config_id` starts with `01` followed by
  `sha256(app_compose)`, where `app_compose` is the string at
  `info.tcb_info.app_compose` (`tcb_info` may arrive as a JSON string or an
  object). By default that hash must also be in the pinned list in
  `opencode/attestation-policy.json`, which is compiled into `rts`.
  `--compose-policy mr-config-only` drops the list check and is recorded.
- **GPU.** For every model attestation, `nvidia_payload.nonce` equals the
  nonce sent. `rts` posts the payload unchanged to NVIDIA NRAS
  (`https://nras.attestation.nvidia.com/v3/attest/gpu`). The overall token is
  the JWT at `[0][1]` of the response. Its `alg` must be `ES384`, and its
  signature must verify with `ring` (`ECDSA_P384_SHA384_FIXED`) against the key
  whose `kid` matches, from
  `https://nras.attestation.nvidia.com/.well-known/jwks.json`. Its `exp` must
  be in the future, and `x-nvidia-overall-att-result` must be `true`.

The result is the session's verified state: the set of gateway TLS
fingerprints, and for each model the set of attested ed25519 signing keys.

**Quote collateral.** `dcap-qvl` is built without `report`, so it has no
network code. `rts` mirrors what `dcap-qvl` 0.7.0's own collateral client
does (`src/collateral.rs:116-135`, `:458-560`) against Intel PCS
(`https://api.trustedservices.intel.com`). It reads the FMSPC and the PCK CA
(`processor` or `platform`) from the quote's PCK chain, then fetches:

| Item | URL | Taken from the response |
|---|---|---|
| PCK CRL | `/sgx/certification/v4/pckcrl?ca=<ca>&encoding=der` | body (DER); header `SGX-PCK-CRL-Issuer-Chain` |
| TCB info | `/tdx/certification/v4/tcb?fmspc=<FMSPC>&update=standard` | `tcbInfo` (the exact bytes Intel signed) and `signature` (hex); header `TCB-Info-Issuer-Chain` or `SGX-TCB-Info-Issuer-Chain` |
| QE identity | `/tdx/certification/v4/qe/identity?update=standard` | `enclaveIdentity` and `signature`; header `SGX-Enclave-Identity-Issuer-Chain` |
| Root CA CRL | `https://certificates.trustedservices.intel.com/IntelSGXRootCA.der` | body (DER) |

The issuer-chain headers are percent-encoded PEM. Against Intel PCS,
`dcap-qvl` does not use `/rootcacrl`. It reads the CRL distribution point
from the root certificate, which is the URL above (checked 2026-10-28 on the
`TrustedRootCA.der` shipped in the crate). The PCK chain itself comes from
the quote (certification data type 5); any other type refuses.

**What the checks trust.** Intel's PCS and root CA (quote collateral), and
NVIDIA's NRAS and its JWKS (the GPU verdict), each over CA-validated TLS. The
host clock supplies the verification time. `rts` contacts all three during
connect.

**The first fetch is not pinned.** `rts` learns the fingerprint from the
report, so the report fetch itself is ordinary CA-validated TLS, and it
carries the API key. An interception there would expose the billing
credential, not session data: no prompt is sent until the forwarder holds a
verified fingerprint. Re-attestation during a session (below) is unpinned
for the same reason.

**Why not upstream's verifier.** `nearai-cloud-verifier` at `94554726` is a
walkthrough that logs results and does not fail closed: `checkReportData`
returns `binds_address` and `embeds_nonce` and `verifyAttestation` ignores
them; the GPU nonce and the NRAS verdict are printed; the NRAS JWT payload is
base64-decoded but its signature is never checked; `mr_config` against the
compose hash is printed; a missing `gateway_attestation` or
`model_attestations` returns normally. Its TDX quote library,
`@phala/dcap-qvl-node` `^0.3.3`, is affected by GHSA-796p-j2gh-9m2q
(critical, published 2026-01-26, every published version, no patch): the QE
Identity signature is never checked, so a forged quoting enclave can sign
quotes that verify. Upstream's Python verifier requires `dcap-qvl>=0.3.2`,
which also admits vulnerable versions. The Rust crate `dcap-qvl` 0.7.0 is past
the 0.3.9 fix and checks the QE Identity signature (`verify.rs:753-801`).
`rts` reimplements the checks in Rust, each refusing, and uses `dcap-qvl`
only for the quote. NEAR should be told about the advisory upstream.

| Upstream behavior (`94554726`) | `rts` |
|---|---|
| `binds_address` / `embeds_nonce` computed, then ignored | Either false refuses |
| Quote `verified: false` is logged | Refuses |
| GPU nonce match and NRAS verdict are logged | Refuses unless the nonce matches and the verdict is `true` |
| NRAS JWT payload decoded, signature not checked | ES384 signature verified against the JWKS key with the token's `kid` before the verdict is read |
| `mr_config` vs compose hash is logged | Refuses on mismatch; by default the hash must also be pinned |
| Missing `gateway_attestation` or `model_attestations` returns | Refuses |
| TCB `OutOfDate` accepted | Refused unless `--allow-tcb-out-of-date` |

**Compose policy (operational choice).** Pinning the compose hash proves which
gateway and model builds are running, but every NEAR deploy then refuses
sessions until someone adds the new hash to `opencode/attestation-policy.json`
and rebuilds. `--compose-policy mr-config-only` accepts any compose that
`mr_config_id` vouches for: it proves the compose shown is the one running,
not that it is a known build. The default is the pinned list, and the list
starts empty, so sessions refuse until check 6 records the first hashes.

**TCB `OutOfDate` (operational choice).** Upstream accepts it. `rts` refuses it
by default, so if NEAR's platform is `OutOfDate` on launch day, every session
refuses until the operator passes `--allow-tcb-out-of-date`.

**Record.** `sessions/<id>/attestation.json` holds every report as received,
the nonces, the verified fingerprints, the signing keys per model, the
compose hashes, the TCB statuses, the NRAS `kid`s and verdicts, the
overrides in force, and a `status`: `verified`, `refused` (with the reason),
`unattested-provider`, `pin-failed`, `model-refused` or `signature-failed`.
It is written atomically (temp file and rename) on every change.

### Attested forwarder (`src/forwarder.rs`, `src/forwarder/`)

Attestation proves what answered `rts`. Without more, IronWire would then open
its own TLS connections to `cloud-api.near.ai` that nothing ties to the
attested gateway: IronWire `bf8b90b` does no attestation-report verification
and no TLS pinning, and checks receipts only in the background, after the
answer was delivered (`ironwire_proxy/src/proof.rs`). `rts` closes the gap
with a forwarder between IronWire and NEAR AI, instead of patching IronWire.

- **Placement.** A loopback HTTP server in the `rts` process
  (`127.0.0.1`, port 0), on its own thread and Tokio runtime, like the
  embedded IronWire worker (`src/inference.rs:150-200`). IronWire's generated
  config sets the `nearai` backend's `base_url` to
  `http://127.0.0.1:<port>/v1` (`inference::start_with_endpoint`,
  `src/inference.rs:99`). The pinned IronWire already accepts this: the
  existing test `the_selected_model_and_host_key_reach_only_the_local_test_upstream`
  points it at plain-HTTP loopback and receives
  `POST /v1/chat/completions` with the key. IronWire attaches a credential
  only to the configured host, and loopback counts
  (`ironwire_upstream/src/credential_host.rs:45-52`).
- **`IRONWIRE_NEARAI_BASE_URL`.** `rts` refuses to launch when it is set. In
  `bf8b90b` the config file's `base_url` wins over that variable
  (`ironwire_proxy/src/embed.rs:1681-1689`), so this is defense in depth
  against a later IronWire revision changing the precedence.
- **The key.** IronWire keeps the key and sends it as `Authorization` on
  each completion; the forwarder passes that header through unchanged and
  does not add one of its own. The forwarder's own calls (re-attestation and
  signature fetches) use the same key, which `rts` already holds in memory
  for the attestation step. Holding it in the forwarder for completions too
  would add no protection: it is the same process and the same secret. It
  would also turn the forwarder's loopback port into a credentialed proxy any
  local process could spend through. With pass-through, a request without
  the key gets NEAR AI's 401.
- **Paths.** Only `POST /v1/chat/completions` is forwarded. IronWire with
  `capture.receipts = false` never fetches `/v1/signature`
  (`ironwire_proxy/src/pipeline.rs:672`), and with startup probes off it
  never probes `/v1/models`. Anything else gets 404 and a log line, without
  contacting upstream.
- **Pinning.** Upstream TLS uses `rustls` 0.23 with a custom
  `ServerCertVerifier`. It runs the normal `webpki` validation against the
  native root store (as `reqwest`'s `rustls-tls-native-roots` does today),
  and then requires `sha256(leaf DER)` to be in the session's attested
  fingerprint set. It is installed on the upstream client itself
  (`reqwest::ClientBuilder::use_preconfigured_tls`), so every connection the
  pool holds passed it at its handshake. The earlier TypeScript design
  measured why that matters (bun 1.3.3, 2026-10-28): a per-request
  `checkServerIdentity` was skipped when the pool reused a connection, and a
  wrong pin succeeded. TLS session resumption is disabled on this client, so
  every handshake presents a certificate to the verifier.
- **Fingerprint set and re-attestation.** Connect seeds the set. A
  connection whose certificate is not in it fails during the handshake,
  before any request byte is sent. The forwarder then re-runs the full
  attestation, up to three times, adding any newly verified fingerprints and
  keys, and retries the request once. If it still fails, IronWire gets a 502,
  `attestation.json` is marked `pin-failed`, and the session ends. On
  2026-10-28 the gateway presented a Let's Encrypt certificate valid until
  2026-12-30, so rotation during a long session is expected, not theoretical.
- **Model allowlist, third layer.** The forwarder parses the request body and
  refuses any `model` not in `provider.models` with 403, before contacting
  upstream. That can only happen if the plugin filter and IronWire's own
  catalogue were bypassed, so it is also fatal (`model-refused`).
- **Compression.** The forwarder sends `Accept-Encoding: identity` upstream,
  so the bytes it hashes are the bytes NEAR AI signs.
- **Per-response signatures.** For each completion, the forwarder hashes the
  exact request bytes it sent and the exact response bytes it received,
  streamed or not, while relaying them; nothing is buffered before delivery.
  It takes the chat ID from `id` in the JSON body, or from the first SSE
  `data:` event. After the response ends, off the response path, it fetches
  `GET /v1/signature/{id}?model=<id>&signing_algo=ed25519` over the pinned
  client, retrying 404 with backoff inside a 10 s window (to be measured in
  check 6). It then requires: `signing_algo` is `ed25519`; `text` is
  `<model>:<request sha256>:<response sha256>` (or the two-part form without
  a model) with the model equal to the request's and both hashes equal to its
  own; `signing_address` is a key attested for that model this session; and
  `ed25519-dalek`'s `verify_strict` accepts `signature` over `text`. The
  receipt shape matches IronWire's `RawReceipt`
  (`ironwire_upstream/src/receipt.rs`). Any failure, including a missing
  signature at the end of the window or a broken upstream stream, is fatal:
  `attestation.json` is marked `signature-failed` and the session is torn
  down (export `/out`, remove the VM). A non-2xx upstream answer carries no
  chat ID and expects no signature; it is logged, not fatal.
- **Why streaming is allowed.** Pinning protects confidentiality before any
  request byte leaves the host. Signatures add integrity and audit after the
  fact. A response that fails its check has already reached the model, but its
  only possible effect is tool calls inside the VM. So responses are relayed as
  they arrive, and a failure ends the session.
- **Audit.** `sessions/<id>/inference.jsonl`, one line per completion: time,
  chat ID, model, streamed or not, request and response sha256, signing key,
  and result.

### Sandbox plugin (`plugin/`)

opencode v2.1.4 registers 20 built-in tools (measured, probe 2). The plugin
keeps seven:

- Sandboxed, `execute` replaced: `shell`, `read`, `write`, `edit`, `glob`,
  `grep`.
- Kept unchanged because it executes nothing: `question` (asks the operator in
  the opencode UI).

It removes the other thirteen, among them `patch` (see below), `webfetch` and `websearch` (host
network), `opencode_worktree_create` / `_remove` (host git), `subagent`,
`skill`, `opencode_session_*`, `opencode_models`, and the MCP resource tools.

- One `ctx.tool.transform` replaces each sandboxed tool's `execute` with an
  implementation that runs through the `Sandbox` interface, and removes every
  tool not on the list. opencode re-runs transforms on reload, so the
  transform is idempotent.
- `ctx.mcp.transform` removes every MCP server.
- `ctx.model.transform` keeps only models whose provider is the session's
  provider and whose ID is in the `models` plugin option, the exact
  `provider.models` list. With no credentials configured, v2.1.4 still offers
  about 80 models from opencode's own hosted service; without this step a
  prompt could go there instead of NEAR AI. Matching on the provider alone
  (the filter before 2026-10-28, `plugin/index.ts:103-105`) is not enough once
  the allowlist names specific private models.
- After setup, `ctx.tool.list()` must equal the seven-tool list exactly, and
  the enabled models must be exactly the `models` option (non-empty, every one
  from the session's provider). Anything else makes setup throw, the
  ready file is never written, and the launcher refuses the session.
- A `tool` `execute.before` hook rejects any tool name outside the allowlist, a
  second layer behind the transform.
- `execute.before` / `execute.after` also write the audit log (below).

Tool implementations, all on guest paths:

| Tool | Guest-side implementation |
|---|---|
| `shell` | `sh -c <command>` in the guest, with `workdir` applied by `cd` inside the wrapper. The only tool whose input is run as a shell command. `background: true` is refused, since exec is synchronous. |
| `read` | Bounded guest read (`head -c`), path as an argv entry. Line slicing and the `<line>: <content>` prefix are applied on the host. A directory returns one entry per line. Text only; images and PDFs are not returned. |
| `write` | Content as base64 argv chunks, decoded and appended in the guest into a temp file that is then renamed over the target. Path as an argv entry. |
| `edit` | Read the file from the guest, apply the exact-match replacement on the host (a pure function), and write it back as `write` does. Fails if `oldString` is missing, or matches more than once without `replaceAll`. Refuses, writing nothing, when the read reports `truncated` (file larger than `maxOutputBytes`), so a large file is never written back short. |
| `glob` | Guest `find <root> -type f` (bounded), then the pattern matched on the host with `Bun.Glob`. |
| `grep` | Guest `grep -rn`, with `-F` for `literal`, `-i` when `caseSensitive` is false, and `--include` for `include`. Pattern and root as argv entries. Exit status 1 (no match) is reported as no matches, not an error. |

The file tools never interpolate arguments into a shell string; their
fixed scripts read operands from `"$1"`, `"$2"` and so on. `patch` is
removed rather than sandboxed: implementing opencode's patch format is out of
scope for v1, and `edit` and `write` cover the same ground.

### Guest image

A digest-pinned OCI image, pulled with `mvmctl image pull` before the first
session. The operator chooses it; the default is the alpine digest the probes
ran on. A Nix `mkGuest` flake is deferred: it needs mvm's builder VM, which
was not exercised. The harness requires `sh`, coreutils, `find`, `grep`,
`timeout`, `base64`, and `tar` in the guest (busybox provides all of them, as
in the alpine image used for the probes), plus a writable `/out` and `/tmp`.

## Error handling

Every failure ends in a refusal or a tool error. Nothing falls back to the host.

- VM create fails: opencode is never started.
- Allowlist mismatch at plugin setup: setup throws, the session does not start.
- Tool call exceeds its time limit (configurable, default 120 s): the guest
  wrapper's `timeout -s KILL` ends the command (status 137) and the tool
  returns a timeout error. If the host backstop fires instead, the machine is
  lost and the session ends.
- VM dies mid-session: tool calls return `sandbox unavailable`. The plugin does
  not recreate the VM, since the session's state would be gone without notice.
- Exec output is capped before it reaches the model, with a truncation marker.
- `/out` export fails at teardown: reported, VM still removed.
- `/out` archive contains a rejected entry: extraction stops, the partial host
  directory is removed, and the rejection is reported.
- Each VM gets a fixed memory cap (default 2 GiB). Because of
  GHSA-x85r-49ww-2pxq (guest-driven host memory growth through vsock), the
  launcher also samples the per-VM host process RSS and tears the session down
  if it exceeds a configured ceiling.
- Attestation fails in connect: no forwarder, IronWire or VM is started and
  opencode never starts. The reason is printed and written to
  `sessions/<id>/attestation.json` with status `refused`. PCS, NRAS or NEAR AI
  being unreachable is a failure, not a skip.
- `IRONWIRE_NEARAI_BASE_URL` set, `provider.models` still the placeholder, or
  an external provider without `--allow-unattested-provider`: refused before
  credentials are read.
- Mid-session, the TLS pin still fails after three re-attestations, a model
  outside the allowlist reaches the forwarder, or a response signature is
  missing, late or wrong: the forwarder returns an error to IronWire, refuses
  every later request, records the status in `attestation.json`, and raises a
  fatal report. The session loop sees it and tears the session down (export
  `/out`, then remove the VM).

## Audit

- mvm's hash-chained audit log records each launch plan.
- The launcher writes `sessions/<id>/tools.jsonl`, one line per tool call: tool
  name, call ID, SHA-256 of the input, status, and duration. Inputs and outputs
  are not stored in this log.
- `sessions/<id>/attestation.json`: every report as received, the nonces, the
  verified fingerprints and per-model signing keys, compose hashes, TCB
  statuses, NRAS results, any re-attestations, the overrides in force
  (`--allow-tcb-out-of-date`, `--compose-policy`,
  `--allow-unattested-provider`), and the final status.
- `sessions/<id>/inference.jsonl`: one line per completion, with chat ID,
  model, request and response hashes, signing key, and signature result.
  Prompts and completions are not stored.

## Testing

Written test-first.

1. Unit tests (`tests/unit/`) run the tool implementations against a fake
   executor: argv construction, line ranges, edit semantics, truncation, and
   timeout mapping.
2. Containment tests (`tests/contain/`) run against real mvm:
   - `write` and `shell touch` of a sentinel path: present in the guest, absent
     on the host.
   - A network connection attempt from inside the guest fails.
   - With an MCP server configured and a second plugin adding a stray tool, the
     session refuses to start.
   - After the VM is killed mid-session, the next tool call errors and nothing
     runs on the host.
   - After SIGINT, no `rts-*` machine remains and `/out` was exported.
   - A guest `/out` containing a symlink to a host path, a hardlink, a `..`
     entry, and an oversized file: none is written to the host, and the export
     reports a rejection.
3. Exec-protocol tests (`tests/contain/`, real mvm), one fresh machine each:
   - A guest command exiting 3, then `echo ok`: the first reports status 3,
     the second succeeds (the wrapper prevents poisoning).
   - `sleep 30` with a 3 s limit: a timeout error with status 137, and the
     next exec succeeds.
   - A 2 MiB stdout with `maxOutputBytes` 64 KiB: exactly 64 KiB returned,
     `truncated: true`, and the reported full size is 2,097,152.
   - A 200 KiB random binary `write` (several argv chunks), read back
     byte-exact by sha256 in the guest.
   - `edit` on a file larger than `maxOutputBytes` is refused and the file's
     guest sha256 is unchanged.
   - An exec result without a valid trailer, simulated by a fake executor in
     the unit tests, marks the sandbox unavailable for every later call.
4. Leak-detection check: replacing one tool's implementation with a stub that
   runs on the host must turn the containment suite red.
5. Attestation and forwarder tests (plan `2026-10-28-attested-inference.md`),
   all offline except the last. HTTP and the clock are injected everywhere.
   - `dcap-qvl`'s own sample TDX quote and collateral, vendored as fixtures,
     verify at a fixed `now` inside the collateral window, through `rts`'s PCS
     fetch code served by a fake HTTP client. The same quote with one byte
     flipped is refused, and so is a `now` past the window.
   - NRAS tokens signed in the test with an openssl-generated P-384 key: a
     good token passes; a wrong key, unknown `kid`, other `alg`, expired
     token, edited payload, false verdict or foreign nonce is refused.
   - Constructed reports with a fake quote verifier: each fail-closed check in
     the table above refuses on its own tampered input, and a good report
     yields the expected fingerprints and keys and writes `attestation.json`.
   - The forwarder against a local TLS upstream using openssl-generated test
     certificates: an unpinned certificate is refused before any request byte
     arrives, a rotated certificate is accepted after one re-attestation, a
     model outside the list gets 403 without an upstream connection, and
     IronWire's requests arrive through the forwarder with the key.
   - Signatures with an ed25519 key made in the test: good streamed and
     non-streamed responses pass and are logged; a wrong hash, unknown key,
     bad signature, or a 404 past the window ends the session and marks
     `signature-failed`.
   - An opt-in live test against NEAR AI staging, ignored unless its
     environment variables are set (check 6).
   The five pre-existing `copy::tests` failures (host tar fixtures carry a pax
   `x` header the extractor refuses) are the baseline and must not grow.

## Repository layout

```
src/             rts (Rust): Sandbox trait, MvmSandbox, hostile-archive extractor,
                 the six tools, `rts tool` bridge, and the launcher (preflight,
                 VM lifecycle, export, orphan sweep)
src/attest.rs    attestation orchestration, policies, attestation.json
src/attest/      tdx.rs (PCS collateral, dcap-qvl), nras.rs (GPU), report.rs
                 (report shape, report_data and compose checks), http.rs (seam)
src/forwarder.rs the attested forwarder; forwarder/pin.rs (rustls verifier),
                 forwarder/signature.rs (receipts, inference.jsonl)
vendor/dcap-qvl-0.7.0/  the reviewed dcap-qvl source, used as a path dependency
plugin/          opencode V2 plugin shim: tool transform, tool and model
                 allowlist checks, audit hooks; each tool call spawns `rts tool`
opencode/        pinned version, opencode config notes, attestation-policy.json
                 (pinned compose hashes, compiled into rts)
tests/unit/      plugin shim tests (Rust unit tests live beside the code in src/)
tests/fixtures/  dcap/ (dcap-qvl sample quote and collateral), nras/ and tls/
                 (openssl-generated test keys and certificates)
tests/contain/   real-mvm containment suite and the leak-detection check
tests/live_attest.rs  opt-in live attestation test against NEAR AI staging
sessions/        per-session out/, tools.jsonl, attestation.json,
                 inference.jsonl (gitignored)
docs/specs/      design documents
```

## Out of scope for v1

- VM egress allowlists.
- Persistent or reused VMs.
- The mvm SDK.
- Concurrent sessions.
- Linux hosts (Firecracker should work unchanged, but is not tested).
- Guest image contents beyond the harness minimum.
- A Nix `mkGuest` guest image (needs the builder VM, not exercised).

## Checks before the implementation plan is final

Each is a short probe. None is assumed.

1. Done 2026-10-27: opencode v2.1.4 runs a V2 `{ id, setup }` plugin loaded
   from a directory path in config, and passes config options to it. A file
   path is skipped with only a warning (hence the handshake).
2. Done 2026-10-27: the 20 built-in tool IDs are as listed under the sandbox
   plugin, and `ctx.tool.list()` reflects a removal made in the transform.
3. Done 2026-10-27: removing servers in `ctx.mcp.transform` stops local MCP
   servers from both global and project config from spawning. Control: with
   removal off, both spawned and wrote their sentinel files. Not covered:
   servers added by another plugin after ours. The XDG isolation and the
   launcher-owned working directory mean no other plugin loads, and the plugin
   also checks that `ctx.mcp.list()` is empty before writing the ready file.
4. Done 2026-10-27: `exec` returns the guest exit code and keeps stdout and
   stderr separate, but does not pass stdin, poisons the machine on a nonzero
   exit or a host-side client kill, and truncates large stdout silently. See
   the constraints under the sandbox interface.
5. Done 2026-10-27: dev-profile `machine create` / `start` / `exec` /
   `rm --force --yes` work on the macOS HVF backend.
6. Open: on NEAR AI staging, record the base URL, the exact IDs of the
   private abliterated models (they replace the `provider.models`
   placeholder), how the API marks a model as private, and one real
   attestation report per model, saved as fixtures. Confirm the report shape
   matches production: `gateway_attestation` with `tls_cert_fingerprint`,
   `model_attestations` with ed25519 `signing_address`, `nvidia_payload` and
   `info.tcb_info.app_compose`; whether model entries carry a
   `tls_cert_fingerprint`; and the TCB status of each quote. Record the
   compose hashes into `opencode/attestation-policy.json`. Measure how soon
   `GET /v1/signature/{chat_id}` answers after a completion ends, streamed and
   not, which sets the 10 s window. Confirm the signature `text` hashes the
   raw request and response bytes as sent with `Accept-Encoding: identity`
   (upstream's non-streaming example hashes `JSON.stringify(response)`), and
   which `signature_kind` model receipts carry. Check whether the gateway
   certificate below is the attested `tls_cert_fingerprint`, and whether
   every gateway instance shares it. Repeat against production after the
   2026-10-29 launch, before the default config points there.
7. Done 2026-10-28, for attestation and the forwarder:
   - `cloud-api.near.ai` presented leaf sha256
     `5664580137f5b2abc8b2cc9ef53dc2bd7cd79b6ffc9f840dbbfca708a2c51022` on
     three handshakes (and on four earlier the same day): `CN=cloud-api.near.ai`,
     issuer Let's Encrypt `YE1`, notAfter 2026-12-30.
   - NVIDIA's JWKS served 212 keys, all `kty EC`, `crv P-384`, each with a
     two-certificate `x5c` and a dated `kid`; keys rotate daily, so the JWKS
     is fetched per attestation.
   - `dcap-qvl` 0.7.0 (crates.io tarball, sha256
     `b992c9511adf7135ae7c63c023c9303a3615c0f38d7b39514dcc262f91c6adda`): the
     collateral client and PCS URLs are behind `report`
     (`src/lib.rs:133-140`); `verify::ring::verify(quote, &collateral, now)`
     returns `VerifiedReport { status: String, report, .. }`
     (`src/verify.rs:1718`); `intel::quote_fmspc` and `intel::quote_ca` read
     the PCK chain without `report`. Its sample TDX quote verifies
     `UpToDate` with no advisories (its own test, `tests/verify_quote.rs:435`),
     and the sample collateral is valid from 2025-06-19T10:32:27Z to
     2025-07-19T10:00:35Z.
   - IronWire `bf8b90b`: the config `base_url` wins over
     `IRONWIRE_NEARAI_BASE_URL`; the NEAR AI backend posts to
     `<base>/chat/completions` and fetches receipts only with
     `capture.receipts` on; receipts are ed25519 over
     `<model>:<req sha256>:<resp sha256>`.
   - Baseline before any change, with `RUSTFLAGS="-D warnings"
     CARGO_INCREMENTAL=0`: `cargo test --lib` = 136 passed, 5 failed,
     1 ignored. The five are `copy::tests` (`a_long_name_is_refused`,
     `a_symlink_to_a_host_path_is_refused`, `a_hardlink_is_refused`,
     `copy_out_is_byte_exact_across_slices`, `an_oversized_file_is_refused`):
     the host-built tar fixtures carry a pax `x` header
     (`PaxHeader/currentdir`) that the extractor refuses.
   - Carried from the earlier TypeScript design: bun 1.3.3 `fetch` skipped
     `tls.checkServerIdentity` on a pooled connection (the reason the
     verifier sits on the client here).

## Host setup notes (measured 2026-10-27)

- mvm v0.22.0 is installed from the release tarball, not the `curl | sh`
  installer. Verification: sha256 matches `checksums-sha256.txt`, and
  `cosign verify-blob` passes on both files with the certificate identity
  pinned to `https://github.com/tinylabscom/mvm/.github/workflows/release.yml@refs/tags/v0.22.0`
  and issuer `https://token.actions.githubusercontent.com`. The certificate's
  commit, `b6b77f83`, is the `v0.22.0` tag commit.
- The tarball's binaries carry no VM entitlements. `mvmctl env sign`
  ad-hoc re-signs `mvmctl` (`com.apple.security.virtualization`) and
  `mvm-hvf-supervisor` (`com.apple.security.hypervisor`); `mvmctl doctor`
  fails until it has run.
- A source build was abandoned: its bootstrap cross-compiles the guest runtime
  and needs `cargo-zigbuild`, `zig`, and the `aarch64-unknown-linux-musl`
  target.
- mvm's git reader rejects `includeIf "hasconfig:..."` entries in the
  operator's global git config. The launcher runs every `mvmctl` command with
  `GIT_CONFIG_GLOBAL` pointing at an empty file; the operator's git config is
  not modified.

## Dependencies requiring approval before install

- mvm (`mvmctl`), release v0.22.0. Approved 2026-10-27. Four advisories were published
  2026-10-26, none with a patched version listed. Relevant here:
  GHSA-x85r-49ww-2pxq (medium), where a guest can grow host memory through the
  vsock device model. That is a denial-of-service on the host, not an escape,
  but this design assumes a hostile guest. Not relevant: the externally signed
  plan replay (not used), the GPU endpoint (not enabled), and the Firecracker
  `/tmp` socket issue (Linux only).

opencode v2.1.4 and bun 1.3.3 are already installed and need no new install.

For attestation and the forwarder (2026-10-28):

- **`dcap-qvl =0.7.0`**, the only new crate. Approved 2026-10-28 by Zaki,
  with the conditions already recorded for near-ai-coordinator and Books:
  `default-features = false, features = ["std", "ring", "default-x509"]`,
  never `report` (its PCS fetch code, which also pulls a second `reqwest`);
  vendor the source after a read-through, as a path dependency at
  `vendor/dcap-qvl-0.7.0` from the crates.io tarball above; targeted review of
  `verify.rs` and `x509.rs`; re-review on any version bump. The host clock is
  `now`, under the same exception as near-ai-coordinator. MIT, Phala Network.
  Its `std` feature turns on `serde_json/preserve_order`, which this graph
  already has (`serde_json` depends on `indexmap` in `Cargo.lock`). It brings
  the RustCrypto `der` / `x509-cert` stack, `parity-scale-codec`,
  `scale-info`, `chrono`, `asn1_der`, `pem` and the `dcap-qvl-webpki` fork;
  the exact count of new lockfile packages is recorded when it is added.
- **Promoted from transitive to direct, no new package**, each at its
  `Cargo.lock` version today: `ring` 0.17.14 (ES384 for NRAS, already
  approved for near-ai-coordinator), `ed25519-dalek` 2.2.0 (`verify_strict`),
  `rustls` 0.23.46 and `rustls-native-certs` 0.8.5 (the pinned verifier and
  its roots), `hyper` 1.12.0, `hyper-util` 0.1.21, `http-body-util` 0.1.5 and
  `bytes` 1.12.1 (the forwarder's server and streaming bodies), `hex` 0.4.3.
  `serde_json` gains its `raw_value` feature, to keep Intel's signed
  `tcbInfo` bytes exact. These change `Cargo.toml` but should add no
  lockfile package; the plan checks that with a lockfile diff.
- **Test certificates and keys** are openssl-generated PEM and PKCS#8
  fixtures committed under `tests/fixtures/`. No `rcgen`, no `p384`.
- The policy file is JSON, not TOML: `toml` is only transitive here, and
  `serde_json` is already direct.

Rejected:

- `@phala/dcap-qvl-node` (upstream's choice): GHSA-796p-j2gh-9m2q, critical,
  every published version (`<= 0.3.3`), no patch; the QE Identity signature
  is never verified.
- The npm `nearai-cloud-verifier` `0.0.1-alpha.1` (2025-10-29): no repository
  link, stale, and depends on the vulnerable package. The repo's own verifier
  at `94554726` does not fail closed (see Inference attestation).
- `@phala/dcap-qvl` 0.7.0 (pure JS): about 20 packages, including `elliptic`
  with an open low-severity advisory and no patch, and it is TypeScript in a
  Rust launcher.
- `dcap-qvl` with `report` or default features: a second `reqwest` and PCCS
  code `rts` does not need; `rts` fetches from Intel PCS itself.
- `rcgen` and `p384`: openssl fixtures and `ring` cover the same ground.
- `@noble/curves` and `@noble/hashes`, approved for the TypeScript design:
  not needed, because `rts` asks for ed25519 signatures instead of ECDSA with
  EIP-191 recovery.
- Patching IronWire to pin and verify inline: a fork of a fast-moving
  dependency, and its receipt check is deliberately off the response path.

# opencode pin and generated config

## How a session runs

```
RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0 cargo build --release
./target/release/rts launch
```

The default launch checks local prerequisites, uses a saved NEAR AI Cloud
inference key or opens the default browser for GitHub sign-in, and starts
a private embedded IronWire proxy. `rts login --provider google` signs in
explicitly with Google. See [sign-in and account selection](../docs/authentication.md).

`rts` is the Rust launcher (`src/session.rs`). It preflights, creates the
microVM, writes the opencode config below, and starts opencode. opencode
loads plugins in-process as TypeScript, so `plugin/` stays a thin shim: each
sandboxed tool call spawns `rts tool <name>` (`src/bridge.rs`) with the
request on stdin and returns its stdout. Exit 3 from `rts tool` means the
machine is unavailable, and the call fails; nothing falls back to the host.

On macOS, host-side tests and archive transport require GNU coreutils and
GNU tar. BSD tar can add PAX metadata that the deliberately strict archive
reader refuses. Install them and put their unprefixed commands first:

```sh
brew install coreutils gnu-tar
export PATH="$(brew --prefix coreutils)/libexec/gnubin:$(brew --prefix gnu-tar)/libexec/gnubin:$PATH"
```

Tests: `RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0 cargo test` (unit),
`bun test tests/unit` (the plugin shim), and
`RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0 cargo test --test contain -- --ignored --test-threads=1` on a host with
mvm, the patched supervisor, and opencode 2.2.2 (on `PATH` or at
`RTS_OPENCODE`). These tests create real VMs
and fail when a prerequisite is missing.

## Installed layout

A release (see the [install section](../README.md#install)) unpacks one
tarball under a prefix: `~/.local` for the curl installer
(`RTS_INSTALL_PREFIX` overrides), the keg for Homebrew, with `bin/rts`
linked into Homebrew's prefix.

```
<prefix>/bin/rts
<prefix>/libexec/nearai-red-sandbox/mvm-hvf-supervisor
<prefix>/libexec/nearai-red-sandbox/mvm-hvf-supervisor.build-info
<prefix>/share/nearai-red-sandbox/plugin/
<prefix>/share/nearai-red-sandbox/opencode/session.example.json
```

`rts` resolves its own executable and canonicalizes it (Homebrew's
`bin/rts` is a symlink into the Cellar); `<prefix>` is the parent of its
`bin/` directory. `rts` counts as installed when
`<prefix>/share/nearai-red-sandbox/plugin` is a directory. A source build
(`target/debug/rts`, `target/release/rts`) has no such prefix and keeps using
the checkout. Explicit settings always win:

| Item | Lookup order |
|---|---|
| plugin | config `pluginDir`; `<prefix>/share/nearai-red-sandbox/plugin`; the checkout's `plugin/` |
| supervisor | `MVM_HVF_SUPERVISOR_PATH`; `<prefix>/libexec/nearai-red-sandbox/mvm-hvf-supervisor` if present; `~/.local/share/nearai-red-sandbox/mvm-hvf-supervisor` |
| mvmctl | config `mvmctl`; `RTS_MVMCTL`; `~/.local/mvm/v0.22.0/mvmctl` |
| opencode | config `opencode`; `~/.local/share/nearai-red-sandbox/opencode/2.2.2/opencode` if present; `opencode` on `PATH` |
| sessions | config `sessionsDir`; for an installed `rts`, `~/.local/share/nearai-red-sandbox/sessions`; for a source build, the checkout's `sessions/` |

mvm and opencode live under the home directory, not the prefix, so both
install methods share one copy of each pinned version. `rts setup` fetches
them (mvm v0.22.0 to `~/.local/mvm/v0.22.0/`, opencode v2.2.2 to
`~/.local/share/nearai-red-sandbox/opencode/2.2.2/`), checking each download's
pinned sha256 before unpacking it, then runs `mvmctl env sign` (never with
`MVM_HVF_SUPERVISOR_PATH`, so mvm cannot re-sign the release's supervisor),
`mvmctl doctor`, the supervisor probes and `opencode --version`, and pulls the
pinned guest image. An existing copy that fails verification is refused with
its path, never replaced: remove it and re-run `rts setup`.
`rts setup --check` runs the same checks and downloads and changes nothing;
`rts setup --check --offline` checks only the plugin, the supervisor probes
and the code signatures of `rts` and the supervisor, without mvmctl or the
network.

Because `~/.local/share/nearai-red-sandbox/` also holds opencode, sessions
and possibly a source-built supervisor, the curl installer replaces only the
paths the tarball owns. For a full removal delete the prefix's files above,
`~/.local/mvm/v0.22.0` and `~/.local/share/nearai-red-sandbox` (this deletes
the default sessions directory too).

## Inference through embedded IronWire

By default opencode talks to [IronWire](https://github.com/nearai/ironwire)'s
OpenAI façade on an ephemeral loopback port, as provider `ironwire`.
The launcher supplies a dedicated inference key from native credential storage
directly to IronWire in host memory. IronWire strips the inbound
authorization header, so no provider credential is in opencode's config or
environment; the generated config carries a placeholder API key. The
embedded proxy enables only the configured NEAR AI backend; credential
discovery, subscription credential files, startup probes, and update checks
are disabled. Per-model routing headers preserve the selected model ID.

After local preflight and authentication, the session sends
`GET <baseURL>/models` and refuses the session unless
IronWire answers 200 and lists every configured model. The proxy stays alive
through session teardown and then stops. There is no separate daemon to start.

To use a separately managed IronWire daemon, explicitly set
`provider.id` and `provider.baseURL` in the operator configuration. The old
`http://127.0.0.1:8463/openai/v1` connection remains available in that external
mode and bypasses browser sign-in. A provider with only `models` selects
embedded inference; omitting the provider entirely selects the default model,
NEAR AI's `deepseek-ai/DeepSeek-V4.1-Flash-1017-abliterated` (listed by
production `/v1/models` on 2026-10-29). A config that still names the retired
placeholder `PLACEHOLDER-near-private-abliterated` is refused at launch.

A provider reached directly (for example `https://cloud-api.near.ai/v1`)
still works: set `provider.id`, `provider.baseURL` (https) and
`provider.apiKeyEnv`, and the key is referenced as `{env:VAR}`. Plain http is
accepted only to `127.0.0.1` or `localhost` with an explicit port.

## Pin

opencode **v2.2.2** (`opencode --version` must print `2.2.2`; the launcher
refuses anything else). The plugin targets the v2.2.2 promise plugin API:
`{ id, setup(ctx) }` using `ctx.tool`, `ctx.mcp` and `ctx.model`
(`packages/plugin/src/promise/{plugin,tool,mcp,model}.ts` at tag `v2.2.2`
of `anomalyco/opencode`). Release asset `opencode-darwin-arm64.zip`, sha256
`c1c901a6379d667b7a30a3eea5a8f6e93416dba43e889e834771f6fb174f35c9`.

The pin moved from 2.1.4 on 2026-10-29 after the containment suite and the
tool, MCP and model probes passed on 2.2.2 (design spec, check 8). Between
the two tags `promise/{tool,mcp,model}.ts` are unchanged and
`promise/plugin.ts` only adds `experimental.generate`, which the plugin does
not use.

## NEAR AI facts (Task 8, Step 0)

Confirmed on 2026-10-28 from NEAR AI's own docs repo, `nearai/docs` at commit
`f2cd40ff0675372b4a26e5b37fa75d574c1d3f7b`, page
`cloud/guides/integrations/opencode.mdx` (published at
<https://docs.near.ai/cloud/guides/integrations/opencode>):

| Fact | Value |
|---|---|
| OpenAI-compatible base URL | `https://cloud-api.near.ai/v1` |
| Provider ID opencode uses | `nearai` |
| Example model ID | `z-ai/glm-5.3-flash` (opencode model string `nearai/z-ai/glm-5.3-flash`) |
| API key env var | `NEARAI_API_KEY` |

That page was checked by NEAR AI against opencode 1.18.31 and uses the v1
config shape. docs.near.ai itself was not reachable from the build
environment, so the GitHub source of the page was read instead.

## Live attestation test against NEAR AI production

`tests/live_attest.rs` is opt-in (every test `#[ignore]`) and reaches NEAR
AI, Intel PCS and NVIDIA NRAS:

```sh
RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0 \
  cargo test --test live_attest -- --ignored --nocapture --test-threads=1
```

It defaults to production (`https://cloud-api.near.ai/v1`) and the default
models; `RTS_LIVE_NEAR_BASE_URL` and `RTS_LIVE_NEAR_MODELS` override them.
NEAR AI serves the attestation report without an API key, so none is needed;
`RTS_LIVE_NEAR_API_KEY`, when set, is sent as the bearer. `RTS_LIVE_SAVE_DIR`
saves every exchange (report, PCS, CRL, NRAS) as `live-run.json`, the source
of `tests/fixtures/near-prod/live-run-2026-10-29.json`, which an offline
unit test replays through the real verifiers at the recorded time.

Recorded on 2026-10-29 for `deepseek-ai/DeepSeek-V4.1-Flash-1017-abliterated`,
with the default options (TCB `UpToDate` required, pinned compose):

| Check | Gateway | Model entry |
|---|---|---|
| TDX TCB status | `UpToDate`, no advisories | `UpToDate`, no advisories |
| Compose hash | `f571e5da...7bcc7ce` (`dstack-0.5.12`) | `ae66f844...8389265b` (`dstack-nvidia-0.5.11`) |
| `tls_cert_fingerprint` (SPKI sha256) | `73862c25...ba8ba5ad` | `4066aed3...47796408` |
| NRAS | | overall `true`, kid `nv-eat-kid-prod-20261029142518307-...` |

The live `cloud-api.near.ai` leaf's SPKI sha256 was `73862c25...ba8ba5ad`,
the gateway's attested fingerprint, and the forwarder's pinned client config
completed a handshake with only the attested set; with a `[0; 32]` pin it
refused the same leaf as unpinned. Completions and signature receipts need
an API key and are not covered by the replay (spec check 6).

The gateway's ed25519 `signing_address` in the same report is
`40599fb2...a711ad4acb`; the model entry's is `88fbc43b...1adcee78`. A real
production session on 2026-10-29 got its first receipt signed with the
gateway key, so the forwarder accepts attested gateway keys as receipt
signers for any allowed model, and `inference.jsonl` records `signer`
(`gateway` or `model`).

## Config shape accepted by v2.2.2

Read from `packages/core/src/config/normalize.ts` and
`packages/core/src/v1/config/{plugin,provider}.ts` at tag `v2.2.2` (the
previous pin's copies differ only in `normalize.ts` gaining `timezone` and
new `experimental` keys):

- The native v2 keys are `plugins` (entries `string | { package, options }`)
  and `providers`. v2.2.2 still accepts the v1 keys and migrates them:
  `plugin` entries may be `string | [path, options]` and are rewritten to
  `{ package: path, options }`; a v1 `provider` block (`npm`, `name`,
  `options.baseURL`, `options.apiKey`, `models`) is migrated to `providers`.
- `{env:VAR}` in config text is substituted from the environment at load
  time (`core/src/config/variable.ts`), so the key never sits in the file.
- v1 model keys `reasoning`, `release_date`, `attachment`, `temperature` and
  `experimental` are reported as unsupported during migration, so the
  generated block sets only `name` and `tool_call`.
- `enabled_providers` is still honored and becomes a `provider.use` deny
  policy for every other provider.

The launcher writes this to `<runtime>/xdg/config/opencode/opencode.json`
(the global config location under the session's `XDG_CONFIG_HOME`):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": [["/abs/path/to/redteam-sandbox/plugin", {
    "machine": "rts-0123456789ab",
    "nonce": "<24 hex>",
    "readyFile": "<runtime>/ready",
    "auditFile": "sessions/<id>/tools.jsonl",
    "provider": "nearai-red-embedded",
    "models": ["z-ai/glm-5.3-flash"],
    "rts": "/abs/path/to/rts",
    "bridge": {
      "machine": "rts-0123456789ab",
      "mvmctl": "~/.local/mvm/v0.22.0/mvmctl",
      "emptyGitConfig": "<runtime>/empty.gitconfig",
      "stateDir": "<runtime>/state",
      "timeoutMs": 120000,
      "maxOutputBytes": 65536,
      "mvmHome": "<operator HOME>"
    }
  }]],
  "provider": {
    "nearai-red-embedded": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "nearai-red-embedded",
      "options": { "baseURL": "http://127.0.0.1:<ephemeral-port>/openai/v1", "apiKey": "ironwire-holds-the-key" },
      "models": { "z-ai/glm-5.3-flash": { "name": "z-ai/glm-5.3-flash", "tool_call": true, "headers": { "x-ironwire-route": "nearai:z-ai/glm-5.3-flash" } } }
    }
  },
  "model": "nearai-red-embedded/z-ai/glm-5.3-flash",
  "enabled_providers": ["nearai-red-embedded"],
  "share": "disabled"
}
```

`bridge` is passed to `rts tool` unchanged. `stateDir` holds an exec lock,
so one exec reaches the machine at a time across tool processes, and an
`unavailable` marker: once a call finds the machine poisoned or lost, or the
launcher starts teardown, every later call from any process is refused.

There is deliberately no `mcp` key. The plugin also removes every MCP server
in `ctx.mcp.transform` and checks `ctx.mcp.list()` is empty before it writes
the ready file.

## Isolation details found while reading v2.2.2

- Config discovery (`core/src/config/discovery.ts`) walks up from the working
  directory to `/`, loading `opencode.json(c)`, `.opencode/`, `.claude/` and
  `.agents/` from every ancestor, and also reads `$HOME/.claude` and
  `$HOME/.agents`. So the launcher runs opencode with `HOME` set to a session
  directory, and keeps its runtime directory (work dir, XDG dirs, ready file)
  under the system temp dir rather than inside this repo or the operator's
  home. Preflight refuses if any ancestor of the work dir holds one of those
  names. Kept results still go to `sessions/<id>/`.
- mvmctl, spawned by `rts tool` from inside opencode, gets the operator's
  real `HOME` back (bridge option `mvmHome`) so it finds its own state.
- On macOS, opencode also reads a system config directory and MDM managed
  preferences (`/Library/Managed Preferences/.../ai.opencode.managed.plist`).
  The launcher cannot redirect those; the plugin's allowlist and model checks
  still apply after them.
- v2.2.2's own shell plugin (`core/src/tool/plugin/shell.ts`) rewrites the
  `shell` tool description at session time to say commands run on the host
  OS. The plugin sets sandbox-specific
  descriptions in its transform, but that hook may overwrite the `shell` one.
  This affects only what the model is told, not where commands run.

## Network access

The session file's `network.allow` lists what the guest may reach; absent or
empty, the guest has no network and the launch probes that `1.1.1.1:443` is
unreachable. `rts launch --allow-host ENTRY` (repeatable) adds entries, and
`--no-network` drops them all (it is refused together with `--allow-host`).

```json
"network": { "allow": ["packages", "api.example-target.com", "198.51.100.7:8443", "[2001:db8::7]:443"] }
```

Each entry is the preset `packages`, a host name (`name`, `name:port`) or an
IP address with a port (`ip:port`, IPv6 as `[addr]:port`); the port defaults
to 443. The entries are validated and resolved on the host before
`machine create`, passed as one `--allow-host` each, probed from the guest
after boot, and recorded in `sessions/<id>/session.json`; the VM's allowed and
denied connections are copied to `sessions/<id>/network.jsonl` at teardown.
A session with entries replaces `machine start` with an attached
`mvmctl machine run` (tinylabscom/mvm#4860) whose output goes only to
`sessions/<id>/mvm-attach.log` (0600); if it exits, the session stops with
`network-lost`, and if mvm pinned an address `rts` did not validate, with
`network-mismatch`. See the [README](../README.md#network-access) for the
examples and caveats, and the
[design](../docs/specs/2026-10-29-sandbox-network-access-design.md).

## Session time limit

`limits.sessionHours` (default `24`, an integer from 1 to 720) caps a
session's wall-clock time from boot. When it is reached the launcher ends the
session with stop reason `session-limit`: it exports `/out` and removes the
VM, as for any other stop, with or without network. 720 hours is mvm's 30-day
`MAX_TTL`. For a session with an allowlist, the attached
`mvmctl machine run` gets `--ttl <sessionHours>h`, so mvm's own limit matches
the launcher's.

## Host RSS sampling and input readiness

The launcher reads `vms/<machine>/hvf.pid` under `MVM_HOME` or
`$HOME/.mvm`, confirms the executable is `mvm-hvf-supervisor`, then samples
`ps -o rss= -p <pid>` every five seconds. Missing, changed, or unverifiable
PID/RSS information refuses the session. OpenCode runs on a controlling PTY;
operator input is forwarded only after the plugin verifies its tool/model/MCP
policy and writes the matching readiness nonce.

## Recorded live validation status

The recorded macOS containment run on 2026-10-28 passed **20 of 20** real mvm
and OpenCode tests using the pinned guest image and the locally built, installed
release-profile v0.22.0 HVF supervisor. It includes four byte-exact exports of a 700 KiB guest file, network
denial, hostile archive rejection, and a deliberate host-leak check. The stock
v0.22.0 supervisor fails the export test; the launcher now refuses a supervisor
without the required fix. See [supervisor setup](../docs/mvm-supervisor.md).

This is evidence for the tested Apple-silicon Mac and versions, not a claim
about other platforms or releases. Live Cloud sign-in and inference have not
been exercised by these tests.

The derived image in `guest/Dockerfile` was built with Colima for `linux/arm64`
and published to the public Google Artifact Registry repository
`us-west1-docker.pkg.dev/nearai-red-sandbox/sandbox-images`. Its registry
manifest digest is the default image pin in `src/config.rs`. Before the first
launch on a machine, an operator with Google Cloud registry access can cache
the image in mvm:

```sh
MVM_OCI_BEARER_TOKEN_US_WEST1_DOCKER_PKG_DEV="$(gcloud auth print-access-token)" \
  ~/.local/mvm/v0.22.0/mvmctl image pull \
  us-west1-docker.pkg.dev/nearai-red-sandbox/sandbox-images/guest@sha256:56406743ca98389029c795a9cd55f0d1f55e569d57226c10e6c4f6f340cf9ac1
```

The image is public and anonymous Docker pulls work. However, a fresh anonymous
pull using mvm 0.22.0 failed when Artifact Registry returned a 302 redirect for
a layer; mvm rejected the redirect. The authenticated pull above succeeded; it
requires an identity with Artifact Registry Reader access. The short-lived
token is passed only to this explicit pull command; do not put it in the
sandbox configuration or OpenCode environment.

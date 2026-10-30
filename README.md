<p align="center">
  <img src="docs/assets/sandbox-splash.gif" width="672" alt="SandBox splash: a sandstorm of ASCII grains clears to reveal the NEAR AI Red cube, wordmark and the Cybersecurity Program tagline">
</p>

# NEAR AI Red · SandBox

Cybersecurity Program

The microVM sandbox for **NEAR AI Red** (`near-ai-red`), supporting agentic
security research and red teaming.

This project is designed to run OpenCode tool calls inside an ephemeral microVM
per session, with guest networking disabled, inputs copied into the guest, and
results exported through `/out`. Inference runs on the host so provider
credentials stay outside the guest.

<p align="center"><img src="docs/assets/dunes.svg" width="672" alt=""></p>

## <img src="docs/assets/ramp.svg" alt="" height="16"> Install

macOS on Apple silicon only. Either one-liner places a signed, notarized
`rts` and the patched mvm supervisor from a GitHub release:

```sh
curl -fsSL https://github.com/nearai/nearai-red-sandbox/releases/latest/download/install.sh | bash
```

```sh
brew install nearai/tap/rts
rts setup
```

The curl installer installs under `~/.local` (`RTS_INSTALL_PREFIX`
overrides), checks the tarball against the release's `SHA256SUMS` and, when
`gh` is installed, its build-provenance attestation, then runs `rts setup`.
Homebrew cannot write to your home directory during install, so run
`rts setup` once yourself.

`rts setup` downloads mvm v0.22.0 to `~/.local/mvm/v0.22.0/` and opencode
v2.2.2 to `~/.local/share/nearai-red-sandbox/opencode/2.2.2/`, each pinned by
sha256 and checked before it is unpacked; then it runs `mvmctl env sign`,
`mvmctl doctor`, the supervisor probes and `opencode --version`, and pulls
the pinned guest image. It never replaces an existing copy that fails
verification; it names the path to remove instead. `rts setup --check`
re-checks everything and downloads and changes nothing; `rts setup --check
--offline` checks only the installed plugin, supervisor and code signatures,
without mvmctl or the network. See the [launcher guide](opencode/README.md#installed-layout)
for where an installed `rts` finds its files.

## <img src="docs/assets/ramp.svg" alt="" height="16"> Quick start

```console
$ rts launch    # signs in when needed, then starts a sandboxed OpenCode session
$ rts login     # optional: sign in to NEAR AI Cloud ahead of time
```

`rts launch --config PATH` takes a session file; see the
[launcher and inference setup](opencode/README.md) for its options.

## <img src="docs/assets/ramp.svg" alt="" height="16"> Architecture

```mermaid
flowchart TB
    subgraph ext["External services"]
        near["NEAR AI Cloud<br/>gateway and model TEEs"]
        pcs["Intel PCS<br/>TDX collateral"]
        nras["NVIDIA NRAS<br/>GPU verdicts"]
    end

    subgraph host["Host (macOS) - holds credentials, never runs tool calls"]
        launch["rts launch<br/>preflight, attestation, VM lifecycle"]
        opencode["opencode v2.2.2<br/>standalone, isolated config"]
        plugin["sandbox plugin<br/>7-tool and exact-ID model allowlists"]
        tool["rts tool<br/>shell, read, write, edit, glob, grep"]
        ironwire["embedded IronWire<br/>holds the NEAR AI key"]
        fwd["attested forwarder<br/>pinned TLS, model allowlist,<br/>ed25519 receipt checks"]
        sessions[("sessions/ID/<br/>out, tools.jsonl,<br/>attestation.json, inference.jsonl")]
    end

    subgraph vm["mvm microVM rts-ID - no network, destroyed at session end"]
        guest["guest<br/>/in copied in, /out exported"]
    end

    launch -->|"1 attest every allowed model"| near
    launch -->|"verify TDX quotes"| pcs
    launch -->|"verify GPU evidence"| nras
    launch -->|"2 create VM, copy inputs to /in"| guest
    launch -->|"3 start session"| opencode
    opencode --> plugin
    plugin -->|"each tool call"| tool
    tool -->|"mvmctl machine exec"| guest
    opencode -->|"completions"| ironwire
    ironwire --> fwd
    fwd ==>|"TLS pinned to the attested certificate"| near
    guest -.->|"4 /out exported at teardown"| sessions
```

How a session runs:

1. **Attest.** After sign-in, `rts launch` fetches NEAR AI's attestation
   report for every allowed model and verifies it fail-closed: the Intel TDX
   quote (with `dcap-qvl`), the binding of signing key, TLS fingerprint and a
   fresh nonce, the pinned compose measurement, and the NVIDIA GPU verdict.
   Any failure refuses the session before a VM exists.
2. **Boot.** A fresh microVM with no network interface boots from a
   digest-pinned image, and the operator's inputs are copied into `/in`.
3. **Run.** opencode runs on the host. The sandbox plugin replaces its file
   and shell tools so every tool call executes in the guest; every other tool,
   MCP server, and non-allowlisted model is removed. Completions go through
   IronWire and the attested forwarder, which pins TLS to the attested
   certificate and checks NEAR AI's signature on every response. A failed
   check ends the session.
4. **Tear down.** On exit, signal, or a fatal check, `/out` is exported through
   a hostile-archive extractor and the VM is removed. Audit records stay in
   `sessions/ID/`.

The guest is treated as hostile: it never sees credentials, has no network,
and can only return files through `/out`.

## <img src="docs/assets/ramp.svg" alt="" height="16"> Project status

The implementation is under development. Source builds on macOS need the
patched mvm supervisor described in the [setup guide](docs/mvm-supervisor.md)
before launching; releases ship it. The pinned guest image is in a public Google Artifact Registry
repository; see the launcher guide for access and setup.

- [Design](docs/specs/2026-10-27-sandboxed-opencode-design.md)
- [Implementation plan](docs/plans/2026-10-27-sandboxed-opencode.md)
- [Attested inference plan](docs/plans/2026-10-28-attested-inference.md)
- [Launcher and inference setup](opencode/README.md)
- [NEAR AI Cloud sign-in](docs/authentication.md)

## <img src="docs/assets/ramp.svg" alt="" height="16"> NEAR AI Cloud access

`rts launch` uses browser sign-in and an embedded
[IronWire](https://github.com/nearai/ironwire) proxy by default. Credentials are
stored in the host's native credential store and stay outside the guest. See
the [sign-in guide](docs/authentication.md) for account selection and external
provider configuration.

<p align="center"><img src="docs/assets/dunes.svg" width="672" alt=""></p>

# NEAR AI Cloud sign-in

Run `rts launch` to start a sandbox session using NEAR AI Cloud. The launcher
checks the pinned OpenCode version and `mvmctl doctor` before reading stored
credentials or opening a browser. On the first launch it opens the system's
default browser for GitHub sign-in; later launches use the stored inference key.

To sign in explicitly or replace the saved connection:

```sh
rts login
rts login --provider google
```

Browser sign-in has a five-minute deadline and can be interrupted with Ctrl-C.
The browser reports success after the dedicated inference key is minted and
saved. Sign-in does not fund the account; inference uses your NEAR AI Cloud
organization's available balance.

If several active organizations or workspaces are available, sign-in reports
their IDs and requires an explicit selection:

```sh
rts login --organization ORGANIZATION_ID --workspace WORKSPACE_ID
rts launch --provider google --organization ORGANIZATION_ID --workspace WORKSPACE_ID
```

The provider option chooses the browser sign-in service when sign-in is needed.
Use `rts login` to replace an existing connection. A requested organization or
workspace that differs from the saved connection requires explicit sign-in.

The active sponsored key, or a dedicated personal inference key with its account
metadata, is stored under
`nearai-red-sandbox.inference` in macOS Keychain or Linux Secret Service. Broad
browser access tokens are discarded after key creation; refresh tokens remain
in the browser and are discarded. Storage failures stop setup; there is no
plaintext credential file fallback. Help and tool dispatch do not read credentials.

Each launch creates a private embedded IronWire proxy, with only the selected
NEAR AI backend, on an ephemeral loopback port. The launcher-owned pinned forwarder holds the active inference key in host
memory; the embedded proxy receives a placeholder. OpenCode receives a placeholder API key. The guest, tool
requests, configuration, command arguments, audit logs, and exported files do
not receive the Cloud key. The proxy remains alive through session teardown
and stops afterward.

## Sponsored allowance

Use `rts trial --key-file PATH` to import a recipient's private key file into the
native credential store. This replaces the active connection. `rts launch` then
uses the allowance without browser sign-in. The key has no local expiration;
Cloud controls its spending limit and revocation.

An explicit exhausted/invalid-key response opens personal Cloud login. Inference
waits during login; the VM and OpenCode remain running. Successful login replaces
the saved sponsored key and retries the rejected request once. A personal account
needs its own credits. Ordinary network, rate-limit, and server errors do not
open login, and personal-account failures do not repeat it. If login fails or is
cancelled, use `rts login` and launch again. See [the operator guide](sponsored-credits.md).

## Configuration

No configuration file is needed for the default model. To select models or set
other session options:

```sh
rts launch --config opencode/session.example.json
```

A provider containing only `models` uses browser sign-in and embedded inference:

```json
{
  "provider": {
    "models": ["z-ai/glm-5.3-flash"]
  }
}
```

An explicit provider connection (`id`, `baseURL`, or `apiKeyEnv`) selects the
existing external-provider path and bypasses NEAR AI sign-in. For a separately
managed IronWire daemon:

```json
{
  "provider": {
    "id": "ironwire",
    "baseURL": "http://127.0.0.1:8463/openai/v1",
    "models": ["z-ai/glm-5.3-flash"]
  }
}
```

Explicit direct HTTPS providers still use their configured `apiKeyEnv`. Account
sign-in flags apply to embedded NEAR AI inference.

`apiKeyEnv` must name a credential variable such as `NEARAI_API_KEY` or
`MY_PROVIDER_TOKEN`. Session and runtime controls such as `HOME`, `PATH`,
`XDG_*`, `OPENCODE_*`, `RTS_*`, `LC_*`, and `NODE_*` are reserved.

The automated tests use an in-memory credential store and local mock HTTP
servers. They do not establish that browser sign-in, native credential storage,
or live Cloud inference has been exercised on this machine.

The latest recorded real containment run on 2026-10-28 passed all 20 tests
on an Apple-silicon Mac with the patched mvm supervisor. See the
[OpenCode operator notes](../opencode/README.md#recorded-live-validation-status)
for the scope of that result and [supervisor setup](mvm-supervisor.md).

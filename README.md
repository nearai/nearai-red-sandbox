# NEAR AI Red Sandbox

The microVM sandbox for **NEAR AI Red** (`near-ai-red`), supporting agentic
security research and red teaming.

This project is designed to run OpenCode tool calls inside an ephemeral microVM
per session, with guest networking disabled, inputs copied into the guest, and
results exported through `/out`. Inference runs on the host so provider
credentials stay outside the guest.

## Project status

The implementation is under development. On macOS, build the patched mvm
supervisor described in the [setup guide](docs/mvm-supervisor.md) before
launching. The pinned guest image is in a public Google Artifact Registry
repository; see the launcher guide for access and setup.

- [Design](docs/specs/2026-10-27-sandboxed-opencode-design.md)
- [Implementation plan](docs/plans/2026-10-27-sandboxed-opencode.md)
- [Launcher and inference setup](opencode/README.md)
- [NEAR AI Cloud sign-in](docs/authentication.md)

## NEAR AI Cloud access

`rts launch` uses browser sign-in and an embedded
[IronWire](https://github.com/nearai/ironwire) proxy by default. Credentials are
stored in the host's native credential store and stay outside the guest. See
the [sign-in guide](docs/authentication.md) for account selection and external
provider configuration.

# NEAR AI Red Sandbox

The microVM sandbox for **NEAR AI Red** (`near-ai-red`), supporting agentic
security research and red teaming.

This project is designed to run OpenCode tool calls inside an ephemeral microVM
per session, with guest networking disabled, inputs copied into the guest, and
results exported through `/out`. Inference runs on the host so provider
credentials stay outside the guest.

## Project status

`main` contains the design and implementation plan. The implementation is under
development on [`claude/project-thread-xl42oq`](https://github.com/nearai/nearai-red-sandbox/tree/claude/project-thread-xl42oq).
Live containment validation on macOS remains a release gate.

- [Design](docs/specs/2026-10-27-sandboxed-opencode-design.md)
- [Implementation plan](docs/plans/2026-10-27-sandboxed-opencode.md)
- [Launcher and inference setup](https://github.com/nearai/nearai-red-sandbox/blob/claude/project-thread-xl42oq/opencode/README.md)

## NEAR AI Cloud access

The current launcher uses a local [IronWire](https://github.com/nearai/ironwire)
service by default; IronWire holds the NEAR AI API key. Direct provider access
uses an API key supplied through `NEARAI_API_KEY`. The sandbox CLI does not
currently open a browser for NEAR AI Cloud sign-in.

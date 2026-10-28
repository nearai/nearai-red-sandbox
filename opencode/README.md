# opencode pin and generated config

## Pin

opencode **v2.1.4** (`opencode --version` must print `2.1.4`; the launcher
refuses anything else). The plugin targets the v2.1.4 promise plugin API:
`{ id, setup(ctx) }` using `ctx.tool`, `ctx.mcp` and `ctx.model`
(`packages/plugin/src/promise/{plugin,tool,mcp,model}.ts` at tag `v2.1.4`
of `anomalyco/opencode`).

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

## Config shape accepted by v2.1.4

Read from `packages/core/src/config/normalize.ts` and
`packages/core/src/v1/config/{plugin,provider}.ts` at tag `v2.1.4`:

- The native v2 keys are `plugins` (entries `string | { package, options }`)
  and `providers`. v2.1.4 still accepts the v1 keys and migrates them:
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
    "mvmctl": "~/.local/mvm/v0.22.0/mvmctl",
    "emptyGitConfig": "<runtime>/empty.gitconfig",
    "provider": "nearai",
    "timeoutMs": 120000,
    "maxOutputBytes": 65536,
    "mvmHome": "<operator HOME>"
  }]],
  "provider": {
    "nearai": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "nearai",
      "options": { "baseURL": "https://cloud-api.near.ai/v1", "apiKey": "{env:NEARAI_API_KEY}" },
      "models": { "z-ai/glm-5.3-flash": { "name": "z-ai/glm-5.3-flash", "tool_call": true } }
    }
  },
  "model": "nearai/z-ai/glm-5.3-flash",
  "enabled_providers": ["nearai"],
  "share": "disabled"
}
```

There is deliberately no `mcp` key. The plugin also removes every MCP server
in `ctx.mcp.transform` and checks `ctx.mcp.list()` is empty before it writes
the ready file.

## Isolation details found while reading v2.1.4

- Config discovery (`core/src/config/discovery.ts`) walks up from the working
  directory to `/`, loading `opencode.json(c)`, `.opencode/`, `.claude/` and
  `.agents/` from every ancestor, and also reads `$HOME/.claude` and
  `$HOME/.agents`. So the launcher runs opencode with `HOME` set to a session
  directory, and keeps its runtime directory (work dir, XDG dirs, ready file)
  under the system temp dir rather than inside this repo or the operator's
  home. Preflight refuses if any ancestor of the work dir holds one of those
  names. Kept results still go to `sessions/<id>/`.
- mvmctl, spawned by the plugin from inside opencode, gets the operator's
  real `HOME` back (plugin option `mvmHome`) so it finds its own state.
- On macOS, opencode also reads a system config directory and MDM managed
  preferences (`/Library/Managed Preferences/.../ai.opencode.managed.plist`).
  The launcher cannot redirect those; the plugin's allowlist and model checks
  still apply after them.
- v2.1.4's own shell plugin rewrites the `shell` tool description at session
  time to say commands run on the host OS. The plugin sets sandbox-specific
  descriptions in its transform, but that hook may overwrite the `shell` one.
  This affects only what the model is told, not where commands run.

## Host RSS sampling

The launcher looks for the per-machine `mvm-hvf-supervisor` PID in
`mvmctl machine inspect <name>` output first and falls back to
`pgrep -f "mvm-hvf-supervisor.*<name>"`, then samples `ps -o rss= -p <pid>`
every 5 s. Which method works on v0.22.0 has not been recorded yet: it needs
a run on the macOS host (the launcher logs the PID and the method that
found it at the start of each session). Record the result here after the first live session.

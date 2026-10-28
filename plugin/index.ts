// opencode V2 plugin (v2.1.4 promise API): replaces the six file and shell
// tools with sandboxed implementations, removes every other tool, every
// MCP server and every model that is not an exact ID in the configured
// provider's allowlist, then proves it loaded by writing the launcher's
// nonce to the ready file.
//
// opencode loads plugins in-process as TypeScript, so this file stays a
// thin shim: each sandboxed tool call spawns `rts tool <name>` (the Rust
// binary that launched the session) and returns its output.
//
// No imports from @opencode/*: the shapes used are the v2.1.4 `Context`
// domains `tool`, `mcp` and `model` (packages/plugin/src/promise/*.ts).

import { spawn } from "node:child_process"
import { writeFile } from "node:fs/promises"
import { appendAudit, inputSha256 } from "./audit.ts"

export const SANDBOXED_TOOLS = ["shell", "read", "write", "edit", "glob", "grep"] as const
export type ToolName = (typeof SANDBOXED_TOOLS)[number]
const MACHINE_NAME_RE = /^rts-[0-9a-f]{12}$/

export const ALLOWED_TOOLS = ["shell", "read", "write", "edit", "glob", "grep", "question"] as const
const ALLOWED = new Set<string>(ALLOWED_TOOLS)
const SANDBOXED = new Set<string>(SANDBOXED_TOOLS)

export type PluginOptions = {
  machine: string
  nonce: string
  readyFile: string
  auditFile: string
  provider: string
  // Exact model IDs of `provider` that stay enabled; everything else is removed.
  models: string[]
  // The rts binary, and the options it needs to reach this session's
  // machine (passed through to `rts tool` unchanged; see src/bridge.rs).
  rts: string
  bridge: Record<string, unknown>
  // When set, the verified tool, MCP and model state is written here as JSON.
  debugFile?: string
}

const DESCRIPTIONS: Record<ToolName, string> = {
  shell:
    "Run a shell command with sh inside this session's isolated Linux microVM (busybox userland, no network). " +
    "Nothing runs on the operator's machine. Inputs are under /in; put results to keep under /out. " +
    "Commands are synchronous; background mode is not supported.",
  read:
    "Read a text file or list a directory inside the session microVM. Each line is prefixed by its 1-based number as <line>: <content>. " +
    "Use offset and limit for large files. Images and PDFs are not rendered.",
  write: "Write a file inside the session microVM, creating parent directories. Use /out for results to keep.",
  edit: "Replace exact text in a file inside the session microVM. oldString must match exactly once unless replaceAll is set.",
  glob: "Find files by glob pattern inside the session microVM.",
  grep: "Search file contents inside the session microVM (grep -rn). Supports literal, caseSensitive and include.",
}

function checkOptions(o: any): PluginOptions {
  const str = (k: string) => {
    if (typeof o?.[k] !== "string" || o[k] === "") throw new Error(`rts-sandbox: option ${k} is required`)
    return o[k] as string
  }
  const machine = str("machine")
  if (!MACHINE_NAME_RE.test(machine)) throw new Error("rts-sandbox: bad machine name")
  const nonce = str("nonce")
  if (!/^[0-9a-f]{24,}$/.test(nonce)) throw new Error("rts-sandbox: bad nonce")
  const bridge = o.bridge
  if (!bridge || typeof bridge !== "object" || Array.isArray(bridge)) throw new Error("rts-sandbox: option bridge is required")
  if (bridge.machine !== machine) throw new Error("rts-sandbox: bridge.machine must match machine")
  const models = o.models
  if (!Array.isArray(models) || models.length === 0 || models.some((m: unknown) => typeof m !== "string" || m === "")) {
    throw new Error("rts-sandbox: option models must be a non-empty list of model IDs")
  }
  return {
    machine,
    nonce,
    readyFile: str("readyFile"),
    auditFile: str("auditFile"),
    provider: str("provider"),
    models: [...models],
    rts: str("rts"),
    bridge,
    debugFile: typeof o.debugFile === "string" && o.debugFile !== "" ? o.debugFile : undefined,
  }
}

const listOf = (v: any): any[] => (Array.isArray(v) ? v : Array.isArray(v?.data) ? v.data : [])

// Exposed so tests can inject a fake Sandbox implementation.
export async function setupWith(ctx: any, makeImpl: (o: PluginOptions) => Record<ToolName, (input: any) => Promise<string>>) {
  const o = checkOptions(ctx.options)
  const allowed = new Set(o.models)
  const impl = makeImpl(o)

  await ctx.tool.transform((editor: any) => {
    for (const t of [...editor.list()]) {
      const id: string = t.id ?? t.name
      if (!ALLOWED.has(id)) {
        editor.remove(id)
        continue
      }
      if (!SANDBOXED.has(id)) continue
      const run = impl[id as ToolName]
      editor.update(id, (m: any) => {
        m.execute = async (input: unknown) => ({ content: await run(input) })
        m.output = undefined
        m.description = DESCRIPTIONS[id as ToolName]
      })
    }
  })
  await ctx.mcp.transform((editor: any) => {
    for (const [name] of [...editor.list()]) editor.remove(name)
  })
  await ctx.model.transform((editor: any) => {
    for (const m of [...editor.list()]) if (!(m.providerID === o.provider && allowed.has(m.id))) editor.remove(m.providerID, m.id)
  })

  // Second layer behind the transform, plus the audit log.
  const started = new Map<string, number>()
  await ctx.tool.hook("execute.before", (ev: any) => {
    if (!ALLOWED.has(ev.tool)) throw new Error(`tool not allowed in sandbox: ${ev.tool}`)
    started.set(String(ev.id), performance.now())
  })
  await ctx.tool.hook("execute.after", async (ev: any) => {
    const t0 = started.get(String(ev.id))
    started.delete(String(ev.id))
    await appendAudit(o.auditFile, {
      tool: String(ev.tool),
      callID: String(ev.id),
      inputSha256: inputSha256(ev.input),
      status: String(ev.status),
      durationMs: t0 === undefined ? -1 : Math.round(performance.now() - t0),
    })
  })

  // Verify the effective state, not what we asked for.
  const ids = listOf(await ctx.tool.list()).map((t: any) => String(t.id ?? t.name))
  const extra = ids.filter((id) => !ALLOWED.has(id))
  const missing = ALLOWED_TOOLS.filter((id) => !ids.includes(id))
  if (extra.length || missing.length || ids.length !== ALLOWED_TOOLS.length) {
    const parts = [...extra, ...missing.map((m) => `missing ${m}`)]
    throw new Error(`tool allowlist mismatch: ${parts.join(", ") || "duplicate tool ids"}`)
  }
  const servers = listOf(await ctx.mcp.list()).map((s: any) => (Array.isArray(s) ? s[0] : (s?.name ?? String(s))))
  if (servers.length) throw new Error(`mcp servers still present: ${servers.join(", ")}`)
  const strays = listOf(await ctx.model.list()).filter((m: any) => m.providerID !== o.provider && m.enabled !== false)
  if (strays.length) throw new Error(`model outside provider ${o.provider}: ${strays.map((m: any) => `${m.providerID}/${m.id}`).join(", ")}`)

  const kept = listOf(await ctx.model.list()).filter((m: any) => m.providerID === o.provider && m.enabled !== false)
  const keptIds = kept.map((m: any) => String(m.id))
  const extraModels = keptIds.filter((id) => !allowed.has(id))
  const missingModels = [...allowed].filter((id) => !keptIds.includes(id))
  if (extraModels.length || missingModels.length) {
    const parts = [...extraModels.map((id) => `${o.provider}/${id}`), ...missingModels.map((id) => `missing ${o.provider}/${id}`)]
    throw new Error(`model allowlist mismatch: ${parts.join(", ")}`)
  }

  const providerModels = kept.length
  const verified = { tools: [...ids].sort(), mcp: servers, providerModels }
  console.error(`rts-sandbox: verified tools ${verified.tools.join(",")}; mcp none; ${providerModels} ${o.provider} models`)
  if (o.debugFile) await writeFile(o.debugFile, JSON.stringify(verified) + "\n", { mode: 0o600 })

  // "wx": never follow or overwrite an existing path.
  await writeFile(o.readyFile, o.nonce, { flag: "wx", mode: 0o600 })
}

// Exit codes from `rts tool` (src/bridge.rs).
const EXIT_UNAVAILABLE = 3

// One sandboxed call: the request goes to `rts tool <name>` on stdin and the
// tool's text comes back on stdout. Any failure, including a lost machine,
// is thrown so opencode reports it to the model; nothing falls back to the host.
export function runRts(rts: string, tool: ToolName, request: unknown): Promise<string> {
  return new Promise((resolve, reject) => {
    const p = spawn(rts, ["tool", tool], { stdio: ["pipe", "pipe", "pipe"] })
    const out: Buffer[] = []
    const err: Buffer[] = []
    p.stdout.on("data", (b: Buffer) => out.push(b))
    p.stderr.on("data", (b: Buffer) => err.push(b))
    p.on("error", (e) => reject(new Error(`rts-sandbox: cannot run ${rts}: ${e.message}`)))
    p.on("close", (code) => {
      const stderr = Buffer.concat(err).toString("utf8").trim()
      if (code === 0) return resolve(Buffer.concat(out).toString("utf8"))
      const prefix = code === EXIT_UNAVAILABLE ? "" : `${tool} failed: `
      reject(new Error(prefix + (stderr || `rts tool exited ${code}`)))
    })
    p.stdin.on("error", () => {})
    p.stdin.end(JSON.stringify(request))
  })
}

// The tool implementations the plugin installs. Exported so the
// containment suite exercises exactly this construction.
export function makePluginTools(o: PluginOptions): Record<ToolName, (input: any) => Promise<string>> {
  const mk = (tool: ToolName) => (input: unknown) => runRts(o.rts, tool, { options: o.bridge, input: input ?? {} })
  return { shell: mk("shell"), read: mk("read"), write: mk("write"), edit: mk("edit"), glob: mk("glob"), grep: mk("grep") }
}

export async function setup(ctx: any) {
  await setupWith(ctx, makePluginTools)
}

export default { id: "rts-sandbox", setup }

// opencode V2 plugin (v2.1.4 promise API): replaces the six file and shell
// tools with sandboxed implementations, removes every other tool, every
// MCP server and every model outside the configured provider, then proves
// it loaded by writing the launcher's nonce to the ready file.
//
// No imports from @opencode/*: the shapes used are the v2.1.4 `Context`
// domains `tool`, `mcp` and `model` (packages/plugin/src/promise/*.ts).

import { writeFile } from "node:fs/promises"
import { MACHINE_NAME_RE, MvmSandbox, spawnRunner } from "../sandbox/mvm.ts"
import { appendAudit, inputSha256 } from "./audit.ts"
import { SANDBOXED_TOOLS, makeTools, type ToolName } from "./tools.ts"

export const ALLOWED_TOOLS = ["shell", "read", "write", "edit", "glob", "grep", "question"] as const
const ALLOWED = new Set<string>(ALLOWED_TOOLS)
const SANDBOXED = new Set<string>(SANDBOXED_TOOLS)

export type PluginOptions = {
  machine: string
  nonce: string
  readyFile: string
  auditFile: string
  mvmctl: string
  emptyGitConfig: string
  provider: string
  timeoutMs: number
  maxOutputBytes: number
  cwd?: string
  // The operator's real HOME, for mvmctl's own state. opencode itself runs
  // with HOME pointed at the session directory.
  mvmHome?: string
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
  const int = (k: string) => {
    if (!Number.isInteger(o?.[k]) || o[k] <= 0) throw new Error(`rts-sandbox: option ${k} must be a positive integer`)
    return o[k] as number
  }
  const machine = str("machine")
  if (!MACHINE_NAME_RE.test(machine)) throw new Error("rts-sandbox: bad machine name")
  const nonce = str("nonce")
  if (!/^[0-9a-f]{24,}$/.test(nonce)) throw new Error("rts-sandbox: bad nonce")
  return {
    machine,
    nonce,
    readyFile: str("readyFile"),
    auditFile: str("auditFile"),
    mvmctl: str("mvmctl"),
    emptyGitConfig: str("emptyGitConfig"),
    provider: str("provider"),
    timeoutMs: int("timeoutMs"),
    maxOutputBytes: int("maxOutputBytes"),
    cwd: typeof o.cwd === "string" ? o.cwd : undefined,
    mvmHome: typeof o.mvmHome === "string" && o.mvmHome !== "" ? o.mvmHome : undefined,
    debugFile: typeof o.debugFile === "string" && o.debugFile !== "" ? o.debugFile : undefined,
  }
}

const listOf = (v: any): any[] => (Array.isArray(v) ? v : Array.isArray(v?.data) ? v.data : [])

// Exposed so tests can inject a fake Sandbox implementation.
export async function setupWith(ctx: any, makeImpl: (o: PluginOptions) => Record<ToolName, (input: any) => Promise<string>>) {
  const o = checkOptions(ctx.options)
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
    for (const m of [...editor.list()]) if (m.providerID !== o.provider) editor.remove(m.providerID, m.id)
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

  const providerModels = listOf(await ctx.model.list()).filter((m: any) => m.providerID === o.provider).length
  const verified = { tools: [...ids].sort(), mcp: servers, providerModels }
  console.error(`rts-sandbox: verified tools ${verified.tools.join(",")}; mcp none; ${providerModels} ${o.provider} models`)
  if (o.debugFile) await writeFile(o.debugFile, JSON.stringify(verified) + "\n", { mode: 0o600 })

  // "wx": never follow or overwrite an existing path.
  await writeFile(o.readyFile, o.nonce, { flag: "wx", mode: 0o600 })
}

// The tool implementations the plugin installs. Exported so the
// containment suite exercises exactly this construction.
export function makePluginTools(o: PluginOptions) {
  const leak = process.env.RTS_TEST_LEAK === "shell" ? ("shell" as const) : undefined
  if (leak) console.error("rts-sandbox: RTS_TEST_LEAK=shell is set; shell runs ON THE HOST (leak check only)")
  const sb = MvmSandbox.attach(o.machine, spawnRunner(o.mvmctl, o.emptyGitConfig, o.mvmHome ? { HOME: o.mvmHome } : {}))
  return makeTools(sb, { timeoutMs: o.timeoutMs, maxOutputBytes: o.maxOutputBytes, cwd: o.cwd, leak })
}

export async function setup(ctx: any) {
  await setupWith(ctx, makePluginTools)
}

export default { id: "rts-sandbox", setup }

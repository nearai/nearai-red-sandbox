import { afterEach, beforeEach, expect, test } from "bun:test"
import { createHash } from "node:crypto"
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import plugin, { ALLOWED_TOOLS, setupWith } from "../../plugin/index.ts"

// The 20 v2.1.4 tool IDs from probe 2 (the spec names the families; the
// exact session, MCP-resource and remaining IDs here are stand-ins).
const V214_TOOLS = [
  "shell", "read", "write", "edit", "glob", "grep", "question", "patch", "webfetch", "websearch",
  "opencode_worktree_create", "opencode_worktree_remove", "subagent", "skill",
  "opencode_session_list", "opencode_session_read", "opencode_session_fork", "opencode_models",
  "mcp_resource_list", "mcp_resource_read",
]

type Stubborn = { tool?: string; mcp?: string; model?: string }

// A fake v2.1.4 plugin Context with just the domains the plugin uses.
function fakeCtx(options: Record<string, unknown>, stubborn: Stubborn = {}) {
  const tools = new Map<string, any>(
    V214_TOOLS.map((id) => [id, { id, name: id, description: `orig ${id}`, input: { schemaOf: id }, output: { out: id }, execute: async () => ({ content: `host ${id}` }) }]),
  )
  const servers = new Map<string, any>([["g", { type: "local" }], ["p", { type: "local" }]])
  const models = [
    { id: "big-pickle", providerID: "opencode", enabled: true },
    { id: "grok-code", providerID: "opencode", enabled: true },
    { id: "z-ai/glm-5.3-flash", providerID: "nearai", enabled: true },
  ]
  const transforms = { tool: [] as any[], mcp: [] as any[], model: [] as any[] }
  const hooks: Record<string, ((ev: any) => any)[]> = {}
  const toolEditor = {
    list: () => [...tools.values()],
    get: (id: string) => tools.get(id),
    add: (t: any) => tools.set(t.name, { ...t, id: t.name }),
    update: (id: string, f: (t: any) => void) => {
      const t = tools.get(id)
      if (t) f(t)
    },
    remove: (id: string) => {
      if (id !== stubborn.tool) tools.delete(id)
    },
  }
  const mcpEditor = {
    list: () => [...servers.entries()],
    get: (n: string) => servers.get(n),
    set: (n: string, c: any) => servers.set(n, c),
    update: () => {},
    remove: (n: string) => {
      if (n !== stubborn.mcp) servers.delete(n)
    },
  }
  const modelEditor = {
    list: () => [...models],
    get: () => undefined,
    update: () => {},
    remove: (p: string, id: string) => {
      if (p === stubborn.model) return
      const i = models.findIndex((m) => m.providerID === p && m.id === id)
      if (i >= 0) models.splice(i, 1)
    },
  }
  const ctx = {
    options,
    tool: {
      transform: async (cb: any) => {
        transforms.tool.push(cb)
        cb(toolEditor)
        return { dispose: async () => {} }
      },
      list: async () => [...tools.values()],
      hook: async (name: string, cb: any) => {
        ;(hooks[name] ??= []).push(cb)
        return { dispose: async () => {} }
      },
      reload: async () => transforms.tool.forEach((cb) => cb(toolEditor)),
    },
    mcp: {
      transform: async (cb: any) => {
        transforms.mcp.push(cb)
        cb(mcpEditor)
        return { dispose: async () => {} }
      },
      // Shaped like the v2.1.4 client: { location, data: McpServer[] }
      list: async () => ({ location: {}, data: [...servers.keys()].map((name) => ({ name, status: { type: "connected" } })) }),
    },
    model: {
      transform: async (cb: any) => {
        transforms.model.push(cb)
        cb(modelEditor)
        return { dispose: async () => {} }
      },
      list: async () => ({ location: {}, data: [...models] }),
    },
  }
  return { ctx, tools, servers, models, hooks, toolEditor }
}

let dir: string
let options: Record<string, unknown>
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "rts-plugin-"))
  options = {
    machine: "rts-0123456789ab",
    nonce: "ab".repeat(12),
    readyFile: join(dir, "ready"),
    auditFile: join(dir, "tools.jsonl"),
    mvmctl: "/nonexistent/mvmctl",
    emptyGitConfig: join(dir, "empty.gitconfig"),
    provider: "nearai",
    timeoutMs: 120_000,
    maxOutputBytes: 65536,
  }
})
afterEach(() => rmSync(dir, { recursive: true, force: true }))

const calls: { tool: string; input: unknown }[] = []
const fakeImpl = () => {
  const mk = (tool: string) => async (input: unknown) => {
    calls.push({ tool, input })
    return `sandboxed ${tool}`
  }
  return { shell: mk("shell"), read: mk("read"), write: mk("write"), edit: mk("edit"), glob: mk("glob"), grep: mk("grep") }
}

test("the default export is a V2 { id, setup } plugin", () => {
  expect(plugin.id).toBe("rts-sandbox")
  expect(typeof plugin.setup).toBe("function")
})

test("setup leaves exactly the seven tools, no MCP servers, only nearai models, and writes the nonce", async () => {
  const f = fakeCtx(options)
  await setupWith(f.ctx, fakeImpl)
  expect((await f.ctx.tool.list()).map((t) => t.id).sort()).toEqual([...ALLOWED_TOOLS].sort())
  expect((await f.ctx.mcp.list()).data).toEqual([])
  expect((await f.ctx.model.list()).data.every((m) => m.providerID === "nearai")).toBe(true)
  expect(readFileSync(join(dir, "ready"), "utf8")).toBe("ab".repeat(12))
})

test("re-running the transforms gives the same result", async () => {
  const f = fakeCtx(options)
  await setupWith(f.ctx, fakeImpl)
  const before = (await f.ctx.tool.list()).map((t) => [t.id, t.input, t.output, t.description])
  await f.ctx.tool.reload()
  const after = (await f.ctx.tool.list()).map((t) => [t.id, t.input, t.output, t.description])
  expect(after).toEqual(before)
})

test("sandboxed tools keep their input schema, drop output, and execute through makeTools", async () => {
  const f = fakeCtx(options)
  await setupWith(f.ctx, fakeImpl)
  calls.length = 0
  for (const id of ["shell", "read", "write", "edit", "glob", "grep"]) {
    const t = f.tools.get(id)!
    expect(t.input).toEqual({ schemaOf: id })
    expect(t.output).toBeUndefined()
    expect(await t.execute({ x: id }, {})).toEqual({ content: `sandboxed ${id}` })
  }
  expect(calls.map((c) => c.tool)).toEqual(["shell", "read", "write", "edit", "glob", "grep"])
  // question executes nothing and is left exactly as it was.
  expect(await f.tools.get("question")!.execute({}, {})).toEqual({ content: "host question" })
})

test("a tool that survives the transform makes setup throw and leaves no ready file", async () => {
  const f = fakeCtx(options, { tool: "webfetch" })
  await expect(setupWith(f.ctx, fakeImpl)).rejects.toThrow("tool allowlist mismatch: webfetch")
  expect(existsSync(join(dir, "ready"))).toBe(false)
})

test("a stray tool added by someone else is a mismatch", async () => {
  const f = fakeCtx(options)
  const realList = f.ctx.tool.list
  f.ctx.tool.list = async () => [...(await realList()), { id: "stray" }]
  await expect(setupWith(f.ctx, fakeImpl)).rejects.toThrow("tool allowlist mismatch: stray")
  expect(existsSync(join(dir, "ready"))).toBe(false)
})

test("a missing allowed tool is a mismatch", async () => {
  const f = fakeCtx(options)
  f.tools.delete("question")
  await expect(setupWith(f.ctx, fakeImpl)).rejects.toThrow("tool allowlist mismatch: missing question")
})

test("an MCP server that survives makes setup throw and leaves no ready file", async () => {
  const f = fakeCtx(options, { mcp: "p" })
  await expect(setupWith(f.ctx, fakeImpl)).rejects.toThrow("mcp servers still present: p")
  expect(existsSync(join(dir, "ready"))).toBe(false)
})

test("a non-nearai model that survives makes setup throw and leaves no ready file", async () => {
  const f = fakeCtx(options, { model: "opencode" })
  await expect(setupWith(f.ctx, fakeImpl)).rejects.toThrow("model outside provider nearai")
  expect(existsSync(join(dir, "ready"))).toBe(false)
})

test("bad options refuse before touching anything", async () => {
  const f = fakeCtx({ ...options, machine: "web" })
  await expect(setupWith(f.ctx, fakeImpl)).rejects.toThrow("bad machine name")
  expect(f.tools.size).toBe(20)
  const g = fakeCtx({ ...options, nonce: undefined })
  await expect(setupWith(g.ctx, fakeImpl)).rejects.toThrow("option nonce is required")
})

test("an existing ready file is never overwritten", async () => {
  await Bun.write(join(dir, "ready"), "planted")
  const f = fakeCtx(options)
  await expect(setupWith(f.ctx, fakeImpl)).rejects.toThrow()
  expect(readFileSync(join(dir, "ready"), "utf8")).toBe("planted")
})

test("execute.before rejects a tool outside the allowlist", async () => {
  const f = fakeCtx(options)
  await setupWith(f.ctx, fakeImpl)
  const before = f.hooks["execute.before"]![0]!
  expect(() => before({ tool: "webfetch", id: "c1", input: {} })).toThrow("tool not allowed in sandbox: webfetch")
  expect(() => before({ tool: "shell", id: "c2", input: {} })).not.toThrow()
})

test("execute.after appends one audit line with the input hash and no raw input", async () => {
  const f = fakeCtx(options)
  await setupWith(f.ctx, fakeImpl)
  const input = { command: "echo SECRET-INPUT-TEXT" }
  f.hooks["execute.before"]![0]!({ tool: "shell", id: "call-1", input })
  await f.hooks["execute.after"]![0]!({ tool: "shell", id: "call-1", input, status: "completed", result: {} })
  const text = readFileSync(join(dir, "tools.jsonl"), "utf8")
  expect(text.endsWith("\n")).toBe(true)
  expect(text.trim().split("\n").length).toBe(1)
  expect(text).not.toContain("SECRET-INPUT-TEXT")
  const rec = JSON.parse(text)
  expect(rec).toMatchObject({ tool: "shell", callID: "call-1", status: "completed" })
  expect(rec.inputSha256).toBe(createHash("sha256").update(JSON.stringify(input)).digest("hex"))
  expect(rec.durationMs).toBeGreaterThanOrEqual(0)
})

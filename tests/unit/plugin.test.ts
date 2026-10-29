import { afterEach, beforeEach, expect, test } from "bun:test"
import { createHash } from "node:crypto"
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import plugin, { ALLOWED_TOOLS, makePluginTools, setupWith, type PluginOptions } from "../../plugin/index.ts"

// The 20 v2.1.4 tool IDs from probe 2 (the spec names the families; the
// exact session, MCP-resource and remaining IDs here are stand-ins).
const V214_TOOLS = [
  "shell", "read", "write", "edit", "glob", "grep", "question", "patch", "webfetch", "websearch",
  "opencode_worktree_create", "opencode_worktree_remove", "subagent", "skill",
  "opencode_session_list", "opencode_session_read", "opencode_session_fork", "opencode_models",
  "mcp_resource_list", "mcp_resource_read",
]

type Stubborn = { tool?: string; mcp?: string; model?: string; modelId?: string; modelsNotLoaded?: boolean }

// A fake v2.1.4 plugin Context with just the domains the plugin uses.
function fakeCtx(options: Record<string, unknown>, stubborn: Stubborn = {}) {
  const tools = new Map<string, any>(
    V214_TOOLS.map((id) => [id, { id, name: id, description: `orig ${id}`, input: { schemaOf: id }, output: { out: id }, execute: async () => ({ content: `host ${id}` }) }]),
  )
  const servers = new Map<string, any>([["g", { type: "local" }], ["p", { type: "local" }]])
  // Real opencode loads provider models after plugin setup; modelsNotLoaded
  // reproduces that ordering.
  const models = stubborn.modelsNotLoaded ? [] : [
    { id: "big-pickle", providerID: "opencode", enabled: true },
    { id: "grok-code", providerID: "opencode", enabled: true },
    { id: "z-ai/glm-5.3-flash", providerID: "ironwire", enabled: true },
    { id: "other-nearai-model", providerID: "ironwire", enabled: true },
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
      if (p === stubborn.model || id === stubborn.modelId) return
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
    provider: "ironwire",
    models: ["z-ai/glm-5.3-flash"],
    rts: "/nonexistent/rts",
    bridge: { machine: "rts-0123456789ab", stateDir: join(dir, "state") },
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

test("setup leaves exactly the seven tools, no MCP servers, only ironwire models, and writes the nonce", async () => {
  const f = fakeCtx(options)
  await setupWith(f.ctx, fakeImpl)
  expect((await f.ctx.tool.list()).map((t) => t.id).sort()).toEqual([...ALLOWED_TOOLS].sort())
  expect((await f.ctx.mcp.list()).data).toEqual([])
  expect((await f.ctx.model.list()).data.every((m) => m.providerID === "ironwire")).toBe(true)
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

test("a model from another provider that survives makes setup throw and leaves no ready file", async () => {
  const f = fakeCtx(options, { model: "opencode" })
  await expect(setupWith(f.ctx, fakeImpl)).rejects.toThrow("model outside provider ironwire")
  expect(existsSync(join(dir, "ready"))).toBe(false)
})

test("setup keeps only the allowlisted model IDs of the session provider", async () => {
  const f = fakeCtx(options)
  await setupWith(f.ctx, fakeImpl)
  expect((await f.ctx.model.list()).data.map((m: any) => `${m.providerID}/${m.id}`)).toEqual(["ironwire/z-ai/glm-5.3-flash"])
})
test("a provider model outside the allowlist that survives makes setup throw", async () => {
  const f = fakeCtx(options, { modelId: "other-nearai-model" })
  await expect(setupWith(f.ctx, fakeImpl)).rejects.toThrow("model allowlist mismatch: ironwire/other-nearai-model")
  expect(existsSync(options.readyFile as string)).toBe(false)
})
// opencode v2.1.4 loads provider models after plugin setup (model.updated
// follows the plugin load), so an allowlisted model may not be listed yet.
// Presence is checked by rts against IronWire's /models before opencode starts.
test("an allowlisted model that opencode has not listed yet does not fail setup", async () => {
  const f = fakeCtx({ ...options, models: ["z-ai/glm-5.3-flash", "not-offered"] })
  await setupWith(f.ctx, fakeImpl)
  expect(existsSync(options.readyFile as string)).toBe(true)
})
test("setup succeeds when opencode lists no provider models yet", async () => {
  const f = fakeCtx(options, { modelsNotLoaded: true })
  await setupWith(f.ctx, fakeImpl)
  expect(existsSync(options.readyFile as string)).toBe(true)
})
for (const models of [undefined, [], [""], "z-ai/glm-5.3-flash", [1]]) {
  test(`option models ${JSON.stringify(models)} is refused`, async () => {
    const f = fakeCtx({ ...options, models })
    await expect(setupWith(f.ctx, fakeImpl)).rejects.toThrow("rts-sandbox: option models must be a non-empty list of model IDs")
  })
}

test("bad options refuse before touching anything", async () => {
  const f = fakeCtx({ ...options, machine: "web" })
  await expect(setupWith(f.ctx, fakeImpl)).rejects.toThrow("bad machine name")
  expect(f.tools.size).toBe(20)
  const g = fakeCtx({ ...options, nonce: undefined })
  await expect(setupWith(g.ctx, fakeImpl)).rejects.toThrow("option nonce is required")
  const h = fakeCtx({ ...options, bridge: { machine: "rts-ffffffffffff" } })
  await expect(setupWith(h.ctx, fakeImpl)).rejects.toThrow("bridge.machine must match machine")
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

// A stand-in for the rts binary: records argv and stdin, then answers like
// `rts tool` would for the exit code it is told to use.
function fakeRts(exitCode: number, stdout: string, stderr: string) {
  const file = join(dir, "rts")
  writeFileSync(
    file,
    `#!/bin/sh\nprintf '%s ' "$@" > "${dir}/argv"\ncat > "${dir}/stdin"\nprintf '%s' '${stdout}'\nprintf '%s' '${stderr}' >&2\nexit ${exitCode}\n`,
  )
  chmodSync(file, 0o755)
  return file
}

test("a sandboxed call sends the bridge options and the input to rts tool on stdin", async () => {
  const o = { ...options, rts: fakeRts(0, "hello from the guest", "") } as PluginOptions
  const out = await makePluginTools(o).shell({ command: "echo hi" })
  expect(out).toBe("hello from the guest")
  expect(readFileSync(join(dir, "argv"), "utf8").trim()).toBe("tool shell")
  expect(JSON.parse(readFileSync(join(dir, "stdin"), "utf8"))).toEqual({ options: options.bridge, input: { command: "echo hi" } })
})

test("a failed call or a lost machine throws with rts's message and never runs on the host", async () => {
  const failing = { ...options, rts: fakeRts(1, "", "oldString not found") } as PluginOptions
  await expect(makePluginTools(failing).edit({})).rejects.toThrow("edit failed: oldString not found")
  const lost = { ...options, rts: fakeRts(3, "", "sandbox unavailable: sandbox removed") } as PluginOptions
  await expect(makePluginTools(lost).shell({ command: "id" })).rejects.toThrow(/^sandbox unavailable: sandbox removed$/)
  const missing = { ...options, rts: join(dir, "no-such-rts") } as PluginOptions
  await expect(makePluginTools(missing).read({ path: "/etc/passwd" })).rejects.toThrow("cannot run")
})

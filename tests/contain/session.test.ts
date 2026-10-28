// End-to-end containment through real opencode v2.1.4 and real mvm.
//
// Plugin-loading checks run `opencode run --standalone --model none/none`:
// plugins load, then the run fails at model resolution before any
// inference request, so no API key or tokens are needed.

import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import {
  OPENCODE_VERSION, PLUGIN_DIR, ancestorConfig, hostExec, opencodeLaunch, prepareSessionDirs, sessionPaths, writeOpencodeConfig, type SessionPaths,
} from "../../launcher/session.ts"
import { ALLOWED_TOOLS, makePluginTools, type PluginOptions } from "../../plugin/index.ts"
import { newSessionId } from "../../sandbox/defaults.ts"
import { guestSha256 } from "../../sandbox/files.ts"
import { listMachines, type MvmSandbox } from "../../sandbox/mvm.ts"
import { newNonce } from "../../sandbox/protocol.ts"
import { SandboxUnavailable } from "../../sandbox/sandbox.ts"
import { emptyGitConfig, freshMachine, limits, mvmReady, mvmctl, run } from "./harness.ts"

const opencode = process.env.RTS_OPENCODE || "opencode"
const ocVersion = await hostExec([opencode, "--version"]).catch(() => undefined)
const opencodeReady = ocVersion?.code === 0 && ocVersion.stdout.includes(OPENCODE_VERSION)
if (!opencodeReady) console.warn(`[contain] skipping opencode tests: ${opencode} --version is not ${OPENCODE_VERSION}`)

const provider = { id: "nearai", baseURL: "https://cloud-api.near.ai/v1", models: ["z-ai/glm-5.3-flash"], apiKeyEnv: "NEARAI_API_KEY" }

function options(p: SessionPaths, machine: string, nonce: string): PluginOptions {
  return {
    machine, nonce, readyFile: p.readyFile, auditFile: p.auditFile, mvmctl, emptyGitConfig,
    provider: "nearai", timeoutMs: limits.timeoutMs, maxOutputBytes: limits.maxOutputBytes,
    mvmHome: process.env.HOME, debugFile: join(p.runtime, "debug.json"),
  }
}

// Load plugins through real opencode without spending inference.
async function probe(p: SessionPaths, configure: (cfgFile: string) => void = () => {}) {
  const cfgFile = join(p.configDir, "opencode.json")
  configure(cfgFile)
  const l = opencodeLaunch(p, opencode, process.env)
  const proc = Bun.spawn([opencode, "run", "--standalone", "--model", "none/none", "probe"], { cwd: l.cwd, env: l.env, stdin: "ignore", stdout: "pipe", stderr: "pipe" })
  const timer = setTimeout(() => proc.kill("SIGKILL"), 90_000)
  const [out, err] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited])
  clearTimeout(timer)
  return { out, err }
}

const readyHolds = (p: SessionPaths, nonce: string) => existsSync(p.readyFile) && readFileSync(p.readyFile, "utf8") === nonce

describe.skipIf(!mvmReady || !opencodeReady)("containment through real opencode", () => {
  let sb: MvmSandbox | undefined
  let p: SessionPaths
  let root: string
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "rts-e2e-"))
    const id = newSessionId()
    p = sessionPaths(id, join(root, "sessions"), join(root, "rt"))
    prepareSessionDirs(p)
  })
  afterEach(async () => {
    await sb?.remove()
    sb = undefined
    rmSync(root, { recursive: true, force: true })
  })

  test("the plugin loads, reports ready, and leaves exactly the seven tools", async () => {
    sb = await freshMachine()
    const nonce = newNonce()
    const o = options(p, sb.name, nonce)
    await probe(p, () => writeOpencodeConfig(p.configDir, { pluginDir: PLUGIN_DIR, pluginOptions: o, provider }))
    expect(readyHolds(p, nonce)).toBe(true)
    const debug = JSON.parse(readFileSync(o.debugFile!, "utf8"))
    expect(debug.tools).toEqual([...ALLOWED_TOOLS].sort())
    expect(debug.mcp).toEqual([])
  }, 180_000)

  test("a project opencode.json with an MCP server is refused by the launcher, and its server never spawns", async () => {
    sb = await freshMachine()
    const nonce = newNonce()
    const mcpSentinel = join(root, "mcp-spawned")
    writeFileSync(join(p.work, "opencode.json"), JSON.stringify({ mcp: { evil: { type: "local", command: ["sh", "-c", `touch '${mcpSentinel}'; sleep 5`] } } }))
    // The launcher refuses a work dir that holds config before it starts opencode.
    expect(ancestorConfig(p.work)).toContain(join(p.work, "opencode.json"))
    // And if opencode is started anyway, the plugin's MCP removal keeps the server from spawning.
    await probe(p, () => writeOpencodeConfig(p.configDir, { pluginDir: PLUGIN_DIR, pluginOptions: options(p, sb!.name, nonce), provider }))
    await Bun.sleep(2000)
    expect(existsSync(mcpSentinel)).toBe(false)
  }, 180_000)

  test("a second plugin that adds a stray tool makes the session refuse", async () => {
    sb = await freshMachine()
    const nonce = newNonce()
    const stray = join(root, "stray-plugin")
    mkdirSync(stray)
    writeFileSync(join(stray, "package.json"), JSON.stringify({ name: "stray", version: "0.0.0", type: "module", main: "index.ts", exports: { ".": "./index.ts" } }))
    writeFileSync(
      join(stray, "index.ts"),
      `export default { id: "stray", setup: async (ctx) => { await ctx.tool.transform((e) => e.add({ name: "stray", description: "stray", input: { type: "object", properties: {} }, execute: async () => ({ content: "stray" }) })) } }\n`,
    )
    await probe(p, (file) => {
      writeOpencodeConfig(p.configDir, { pluginDir: PLUGIN_DIR, pluginOptions: options(p, sb!.name, nonce), provider })
      const cfg = JSON.parse(readFileSync(file, "utf8"))
      cfg.plugin.unshift([stray, {}]) // loads before ours, so our check sees it
      writeFileSync(file, JSON.stringify(cfg))
    })
    expect(readyHolds(p, nonce)).toBe(false)
  }, 180_000)

  test("the plugin configured as a file path is skipped, so no ready file appears", async () => {
    sb = await freshMachine()
    const nonce = newNonce()
    await probe(p, (file) => {
      writeOpencodeConfig(p.configDir, { pluginDir: PLUGIN_DIR, pluginOptions: options(p, sb!.name, nonce), provider })
      const cfg = JSON.parse(readFileSync(file, "utf8"))
      cfg.plugin[0][0] = join(PLUGIN_DIR, "index.ts")
      writeFileSync(file, JSON.stringify(cfg))
    })
    expect(readyHolds(p, nonce)).toBe(false)
  }, 180_000)

  test("sentinel: write and shell touch land in the guest and not on the host", async () => {
    sb = await freshMachine()
    const id = newSessionId()
    const s1 = `/tmp/rts-sentinel-${id}`
    const s2 = `/tmp/rts-sentinel2-${id}`
    const tools = makePluginTools(options(p, sb.name, newNonce()))
    try {
      await tools.write({ path: s1, content: "sentinel" })
      await tools.shell({ command: `touch ${s2}` })
      // Host first: the leak check looks for this exact failure.
      for (const s of [s1, s2]) if (existsSync(s)) throw new Error(`LEAK: host sentinel present: ${s}`)
      expect(await guestSha256(sb, s1)).toMatch(/^[0-9a-f]{64}$/)
      const t = await sb.exec(["test", "-e", s2], limits)
      expect(t.exitCode).toBe(0)
    } finally {
      rmSync(s1, { force: true })
      rmSync(s2, { force: true })
    }
  }, 180_000)

  test("lost VM: after machine stop, tool calls fail and nothing runs on the host", async () => {
    sb = await freshMachine()
    const tools = makePluginTools(options(p, sb.name, newNonce()))
    expect(await tools.shell({ command: "echo up" })).toBe("up")
    await run(["machine", "stop", sb.name], { timeoutMs: 120_000 })
    const s = `/tmp/rts-sentinel3-${newSessionId()}`
    await expect(tools.shell({ command: `touch ${s}` })).rejects.toBeInstanceOf(SandboxUnavailable)
    await expect(tools.write({ path: s, content: "x" })).rejects.toBeInstanceOf(SandboxUnavailable)
    expect(existsSync(s)).toBe(false)
  }, 180_000)

  test("SIGINT to the launcher exports /out and leaves no rts- machine", async () => {
    const cfgFile = join(root, "session.json")
    writeFileSync(cfgFile, JSON.stringify({ provider, sessionsDir: join(root, "sessions"), mvmctl, opencode, limits: { handshakeMs: 60_000 } }))
    const proc = Bun.spawn(["bun", join(import.meta.dir, "../../launcher/main.ts"), "--config", cfgFile], { stdin: "pipe", stdout: "pipe", stderr: "pipe" })
    let err = ""
    const reader = (async () => {
      for await (const chunk of proc.stderr) err += new TextDecoder().decode(chunk)
    })()
    const deadline = Date.now() + 120_000
    while (!/plugin ready/.test(err) && Date.now() < deadline && proc.exitCode === null) await Bun.sleep(200)
    expect(err).toContain("plugin ready")
    const machine = /created (rts-[0-9a-f]{12})/.exec(err)![1]!
    const tools = makePluginTools({ ...options(p, machine, newNonce()) })
    await tools.write({ path: "/out/hello.txt", content: "hi" })
    proc.kill("SIGINT")
    await proc.exited
    await reader
    expect(err).toContain("teardown")
    expect(await listMachines(run)).not.toContain(machine)
    const id = machine.slice(4)
    expect(readFileSync(join(root, "sessions", id, "out/hello.txt"), "utf8")).toBe("hi")
  }, 300_000)
})

import { afterEach, beforeEach, expect, test } from "bun:test"
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { isAbsolute, join } from "node:path"
import { parseConfig } from "../../launcher/config.ts"
import {
  PLUGIN_DIR, ancestorConfig, opencodeLaunch, preflight, sessionPaths, sweepOrphans, waitForReady, writeOpencodeConfig, type HostExec,
} from "../../launcher/session.ts"
import type { PluginOptions } from "../../plugin/index.ts"
import type { Runner } from "../../sandbox/mvm.ts"

const enc = (s: string) => new TextEncoder().encode(s)
const provider = { id: "nearai", baseURL: "https://cloud-api.near.ai/v1", models: ["z-ai/glm-5.3-flash"], apiKeyEnv: "RTS_UNIT_FAKE_KEY" }
const pluginOptions: PluginOptions = {
  machine: "rts-0123456789ab", nonce: "ab".repeat(12), readyFile: "/r/ready", auditFile: "/s/tools.jsonl",
  mvmctl: "/m/mvmctl", emptyGitConfig: "/r/empty", provider: "nearai", timeoutMs: 120_000, maxOutputBytes: 65536,
}

let dir: string
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "rts-session-"))
})
afterEach(() => rmSync(dir, { recursive: true, force: true }))

test("the generated config loads the plugin directory with its options", () => {
  const file = writeOpencodeConfig(join(dir, "cfg"), { pluginDir: PLUGIN_DIR, pluginOptions, provider })
  const cfg = JSON.parse(readFileSync(file, "utf8"))
  expect(cfg.plugin).toEqual([[PLUGIN_DIR, pluginOptions]])
  expect(isAbsolute(cfg.plugin[0][0])).toBe(true)
  expect(cfg.model).toBe("nearai/z-ai/glm-5.3-flash")
  expect(cfg.provider.nearai.options.baseURL).toBe("https://cloud-api.near.ai/v1")
  expect(cfg.provider.nearai.models["z-ai/glm-5.3-flash"].tool_call).toBe(true)
  expect(cfg.enabled_providers).toEqual(["nearai"])
})

test("the plugin path must be a directory", () => {
  const file = join(dir, "plugin.ts")
  writeFileSync(file, "export default {}")
  expect(() => writeOpencodeConfig(join(dir, "cfg"), { pluginDir: file, pluginOptions, provider })).toThrow("plugin path must be a directory")
})

test("the config has no mcp key and the API key only as an env reference", () => {
  process.env.RTS_UNIT_FAKE_KEY = "sk-super-secret-value"
  try {
    const file = writeOpencodeConfig(join(dir, "cfg"), { pluginDir: PLUGIN_DIR, pluginOptions, provider })
    const text = readFileSync(file, "utf8")
    expect(JSON.parse(text).mcp).toBeUndefined()
    expect(text).not.toContain("sk-super-secret-value")
    expect(JSON.parse(text).provider.nearai.options.apiKey).toBe("{env:RTS_UNIT_FAKE_KEY}")
  } finally {
    delete process.env.RTS_UNIT_FAKE_KEY
  }
})

test("opencode runs with HOME and all four XDG dirs in the session, an empty cwd, and --standalone", () => {
  const p = sessionPaths("0123456789ab", join(dir, "sessions"), join(dir, "rt"))
  const l = opencodeLaunch(p, "opencode", {
    PATH: "/usr/bin", HOME: "/Users/op", XDG_CONFIG_HOME: "/Users/op/.config", OPENCODE_CONFIG: "/evil.json", OPENCODE_CONFIG_DIR: "/evil", RTS_TEST_LEAK: "shell", NEARAI_API_KEY: "k",
  })
  expect(l.argv).toEqual(["opencode", "--standalone"])
  expect(l.cwd).toBe(join(dir, "rt/work"))
  for (const k of ["XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "HOME"]) expect(l.env[k]!.startsWith(join(dir, "rt"))).toBe(true)
  expect(l.env.OPENCODE_CONFIG).toBeUndefined()
  expect(l.env.OPENCODE_CONFIG_DIR).toBeUndefined()
  expect(l.env.RTS_TEST_LEAK).toBeUndefined()
  expect(l.env.NEARAI_API_KEY).toBe("k")
  expect(l.env.PATH).toBe("/usr/bin")
  expect(p.configDir).toBe(join(l.env.XDG_CONFIG_HOME!, "opencode"))
})

const okRun: Runner = async () => ({ code: 0, stdout: enc(""), stderr: enc(""), killed: false })
const version = (v: string): HostExec => async () => ({ code: 0, stdout: `${v}\n`, stderr: "" })

test("preflight requires opencode 2.1.4", async () => {
  await expect(preflight({ run: okRun, hostExec: version("2.2.0"), opencode: "opencode", env: {} })).rejects.toThrow("opencode 2.1.4 required, found 2.2.0")
  await preflight({ run: okRun, hostExec: version("2.1.4"), opencode: "opencode", env: {} })
})

test("preflight refuses when mvmctl doctor fails", async () => {
  const bad: Runner = async () => ({ code: 1, stdout: enc(""), stderr: enc("missing entitlement"), killed: false })
  await expect(preflight({ run: bad, hostExec: version("2.1.4"), opencode: "opencode", env: {} })).rejects.toThrow("mvmctl doctor failed: missing entitlement")
})

test("preflight refuses when the leak seam is set", async () => {
  await expect(preflight({ run: okRun, hostExec: version("2.1.4"), opencode: "opencode", env: { RTS_TEST_LEAK: "shell" } })).rejects.toThrow("RTS_TEST_LEAK")
})

test("preflight refuses when an ancestor of the work dir holds opencode config", async () => {
  const work = join(dir, "a/b/work")
  mkdirSync(work, { recursive: true })
  writeFileSync(join(dir, "a/opencode.json"), "{}")
  expect(ancestorConfig(work)).toContain(join(dir, "a/opencode.json"))
  await expect(preflight({ run: okRun, hostExec: version("2.1.4"), opencode: "opencode", env: {}, workDir: work })).rejects.toThrow("ancestor")
})

test("the orphan sweep removes only rts- machines", async () => {
  const calls: string[][] = []
  let removed = false
  const run: Runner = async (argv) => {
    calls.push(argv)
    if (argv[1] === "rm") removed = true
    const ps = removed ? "NAME STATUS\nweb running\n" : "NAME STATUS\nrts-aaaaaaaaaaaa stopped\nweb running\n"
    return { code: 0, stdout: enc(argv[1] === "ps" ? ps : ""), stderr: enc(""), killed: false }
  }
  expect(await sweepOrphans(run)).toEqual(["rts-aaaaaaaaaaaa"])
  const rms = calls.filter((c) => c[1] === "rm")
  expect(rms).toEqual([["machine", "rm", "rts-aaaaaaaaaaaa", "--force", "--yes"]])
})

test("the handshake fails when the ready file never appears", async () => {
  await expect(waitForReady(join(dir, "ready"), "ab".repeat(12), 200, 20)).rejects.toThrow("plugin did not report ready")
})

test("the handshake fails when the ready file holds another nonce", async () => {
  writeFileSync(join(dir, "ready"), "cd".repeat(12))
  await expect(waitForReady(join(dir, "ready"), "ab".repeat(12), 200, 20)).rejects.toThrow("plugin did not report ready")
})

test("the handshake succeeds once the right nonce appears", async () => {
  setTimeout(() => writeFileSync(join(dir, "ready"), "ab".repeat(12)), 50)
  await waitForReady(join(dir, "ready"), "ab".repeat(12), 2000, 10)
})

test("operator config: defaults, and refusals for an unpinned image or missing provider", () => {
  const c = parseConfig({ provider }, dir)
  expect(c.image).toMatch(/@sha256:[0-9a-f]{64}$/)
  expect(c.limits).toEqual({ toolTimeoutMs: 120_000, maxOutputBytes: 65536, memoryMiB: 2048, cpus: 2, hostRssCeilingMiB: 3072, handshakeMs: 30_000 })
  expect(() => parseConfig({ provider, image: "alpine:latest" }, dir)).toThrow("digest-pinned")
  expect(() => parseConfig({}, dir)).toThrow("provider is required")
  expect(parseConfig({ provider, inputsDir: "in" }, dir).inputsDir).toBe(join(dir, "in"))
})

test("the example operator config parses", () => {
  const raw = JSON.parse(readFileSync(join(import.meta.dir, "../../opencode/session.example.json"), "utf8"))
  expect(parseConfig(raw, dir).provider.id).toBe("nearai")
  expect(existsSync(PLUGIN_DIR)).toBe(true)
})

// runSession refusal paths, with a fake mvmctl script that only logs.
import { readdirSync } from "node:fs"
import { runSession } from "../../launcher/session.ts"

function fakeMvmctl(createExit: number) {
  const log = join(dir, "mvmctl.log")
  const script = join(dir, "mvmctl")
  writeFileSync(
    script,
    `#!/bin/sh\nprintf '%s\\n' "$*" >> '${log}'\ncase "$2" in create) echo boom >&2; exit ${createExit};; esac\nexit 0\n`,
    { mode: 0o755 },
  )
  return { script, log }
}

test("runSession refuses before any VM exists when opencode is the wrong version", async () => {
  const m = fakeMvmctl(1)
  const cfg = parseConfig({ provider, sessionsDir: join(dir, "sessions"), mvmctl: m.script }, dir)
  const code = await runSession(cfg, { hostExec: version("2.2.0"), env: { PATH: process.env.PATH } })
  expect(code).toBe(1)
  expect(existsSync(m.log)).toBe(false)
  const [id] = readdirSync(join(dir, "sessions"))
  expect(readFileSync(join(dir, "sessions", id!, "launcher.log"), "utf8")).toContain("opencode 2.1.4 required, found 2.2.0")
})

test("runSession removes the machine when create fails, and never starts opencode", async () => {
  const m = fakeMvmctl(1)
  const cfg = parseConfig({ provider, sessionsDir: join(dir, "sessions"), mvmctl: m.script, opencode: "/nonexistent/opencode" }, dir)
  const exec: HostExec = async (argv) =>
    argv[1] === "--version" ? { code: 0, stdout: "2.1.4\n", stderr: "" } : { code: 1, stdout: "", stderr: "" }
  const code = await runSession(cfg, { hostExec: exec, env: { PATH: process.env.PATH } })
  expect(code).toBe(1)
  const calls = readFileSync(m.log, "utf8").trim().split("\n")
  expect(calls[0]).toBe("doctor")
  expect(calls).toContain("machine ps")
  expect(calls.some((c) => c.startsWith("machine create rts-") && c.endsWith("--profile dev --cpus 2 --memory 2048M"))).toBe(true)
  expect(calls.some((c) => /^machine rm rts-[0-9a-f]{12} --force --yes$/.test(c))).toBe(true)
  expect(calls.some((c) => c.includes("--net") || c.includes("--allow-host"))).toBe(false)
  const [id] = readdirSync(join(dir, "sessions"))
  const log = readFileSync(join(dir, "sessions", id!, "launcher.log"), "utf8")
  expect(log).toContain("machine create failed: boom")
  expect(log).toContain("removed rts-")
  expect(log).not.toContain("EXPORT")
  expect(calls.some((c) => c.startsWith("machine exec"))).toBe(false)
})

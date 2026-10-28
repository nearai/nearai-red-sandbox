// One sandboxed opencode session: preflight, orphan sweep, VM lifecycle,
// isolated opencode launch, plugin handshake, RSS ceiling, and teardown
// (export /out, then remove the VM) that runs exactly once.

import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs"
import { homedir, tmpdir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { DEFAULT_COPY_LIMITS } from "../sandbox/copy.ts"
import { newSessionId } from "../sandbox/defaults.ts"
import { MvmSandbox, listMachines, spawnRunner, type Runner } from "../sandbox/mvm.ts"
import { newNonce } from "../sandbox/protocol.ts"
import type { PluginOptions } from "../plugin/index.ts"
import type { OperatorConfig, ProviderConfig } from "./config.ts"

export const PLUGIN_DIR = resolve(import.meta.dir, "../plugin")
export const OPENCODE_VERSION = "2.1.4"

export type HostExec = (argv: string[], o?: { timeoutMs?: number }) => Promise<{ code: number | null; stdout: string; stderr: string }>

export const hostExec: HostExec = async (argv, o = {}) => {
  const p = Bun.spawn(argv, { stdin: "ignore", stdout: "pipe", stderr: "pipe" })
  const timer = setTimeout(() => p.kill("SIGKILL"), o.timeoutMs ?? 30_000)
  try {
    const [stdout, stderr, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited])
    return { code, stdout, stderr }
  } finally {
    clearTimeout(timer)
  }
}

// --- opencode config ---

export function opencodeConfig(o: { pluginDir: string; pluginOptions: PluginOptions; provider: ProviderConfig }) {
  const p = o.provider
  return {
    $schema: "https://opencode.ai/config.json",
    // v1 tuple form; v2.1.4 normalizes it to { package, options } (core/src/config/normalize.ts).
    plugin: [[o.pluginDir, o.pluginOptions]],
    provider: {
      [p.id]: {
        npm: "@ai-sdk/openai-compatible",
        name: p.id,
        options: { baseURL: p.baseURL, apiKey: `{env:${p.apiKeyEnv}}` },
        models: Object.fromEntries(p.models.map((m) => [m, { name: m, tool_call: true }])),
      },
    },
    model: `${p.id}/${p.models[0]}`,
    // A provider policy (deny every other provider) behind the plugin's model transform.
    enabled_providers: [p.id],
    share: "disabled",
  }
}

export function writeOpencodeConfig(dir: string, o: { pluginDir: string; pluginOptions: PluginOptions; provider: ProviderConfig }): string {
  // v2.1.4 skips a plugin configured as a file path with only a warning.
  if (!existsSync(o.pluginDir) || !statSync(o.pluginDir).isDirectory()) throw new Error(`plugin path must be a directory: ${o.pluginDir}`)
  mkdirSync(dir, { recursive: true })
  const file = join(dir, "opencode.json")
  writeFileSync(file, JSON.stringify(opencodeConfig(o), null, 2) + "\n", { mode: 0o600 })
  return file
}

// --- session layout ---

export type SessionPaths = {
  id: string
  machine: string
  // Runtime state lives under the system temp dir, outside the operator's
  // home and this repo: opencode walks up from its cwd loading
  // opencode.json, .opencode/, .claude/ and .agents/ from every ancestor.
  runtime: string
  home: string
  xdg: { config: string; data: string; cache: string; state: string }
  configDir: string
  work: string
  readyFile: string
  emptyGitConfig: string
  // Kept results: sessions/<id>/out and sessions/<id>/tools.jsonl.
  sessionDir: string
  outDir: string
  auditFile: string
  logFile: string
}

export function sessionPaths(id: string, sessionsDir: string, runtime: string): SessionPaths {
  const xdg = { config: join(runtime, "xdg/config"), data: join(runtime, "xdg/data"), cache: join(runtime, "xdg/cache"), state: join(runtime, "xdg/state") }
  const sessionDir = join(sessionsDir, id)
  return {
    id,
    machine: `rts-${id}`,
    runtime,
    home: join(runtime, "home"),
    xdg,
    configDir: join(xdg.config, "opencode"),
    work: join(runtime, "work"),
    readyFile: join(runtime, "ready"),
    emptyGitConfig: join(runtime, "empty.gitconfig"),
    sessionDir,
    outDir: join(sessionDir, "out"),
    auditFile: join(sessionDir, "tools.jsonl"),
    logFile: join(sessionDir, "launcher.log"),
  }
}

export function prepareSessionDirs(p: SessionPaths) {
  for (const d of [p.home, p.xdg.config, p.xdg.data, p.xdg.cache, p.xdg.state, p.configDir, p.work, p.sessionDir]) mkdirSync(d, { recursive: true, mode: 0o700 })
  writeFileSync(p.emptyGitConfig, "")
}

export function opencodeLaunch(p: SessionPaths, opencode: string, baseEnv: Record<string, string | undefined>) {
  const env: Record<string, string> = {}
  for (const [k, v] of Object.entries(baseEnv)) {
    if (v === undefined) continue
    // Nothing may point opencode at another config, home, or test seam.
    if (k.startsWith("OPENCODE_") || k.startsWith("RTS_TEST_") || k.startsWith("XDG_")) continue
    env[k] = v
  }
  Object.assign(env, {
    HOME: p.home,
    XDG_CONFIG_HOME: p.xdg.config,
    XDG_DATA_HOME: p.xdg.data,
    XDG_CACHE_HOME: p.xdg.cache,
    XDG_STATE_HOME: p.xdg.state,
  })
  return { argv: [opencode, "--standalone"], env, cwd: p.work }
}

// --- preflight ---

const ANCESTOR_CONFIG = ["opencode.json", "opencode.jsonc", ".opencode", ".claude", ".agents"]

export function ancestorConfig(dir: string): string[] {
  const found: string[] = []
  let d = resolve(dir)
  for (;;) {
    for (const n of ANCESTOR_CONFIG) if (existsSync(join(d, n))) found.push(join(d, n))
    const up = dirname(d)
    if (up === d) break
    d = up
  }
  return found
}

export async function preflight(o: {
  run: Runner
  hostExec: HostExec
  opencode: string
  env: Record<string, string | undefined>
  workDir?: string
}): Promise<void> {
  if (o.env.RTS_TEST_LEAK) throw new Error("RTS_TEST_LEAK is set; refusing to start a real session")
  let version: string
  try {
    const r = await o.hostExec([o.opencode, "--version"])
    if (r.code !== 0) throw new Error(r.stderr.trim())
    version = (/\d+\.\d+\.\d+\S*/.exec(r.stdout)?.[0] ?? r.stdout.trim()) || "nothing"
  } catch (e) {
    throw new Error(`opencode ${OPENCODE_VERSION} required, but ${o.opencode} --version failed: ${(e as Error).message}`)
  }
  if (version !== OPENCODE_VERSION) throw new Error(`opencode ${OPENCODE_VERSION} required, found ${version}`)
  let doctor: Awaited<ReturnType<Runner>>
  try {
    doctor = await o.run(["doctor"], { timeoutMs: 60_000 })
  } catch (e) {
    throw new Error(`mvmctl doctor failed: ${(e as Error).message}`)
  }
  if (doctor.code !== 0) {
    throw new Error(`mvmctl doctor failed: ${new TextDecoder().decode(doctor.stderr).trim().slice(0, 500) || `exit ${doctor.code}`}`)
  }
  if (o.workDir) {
    const found = ancestorConfig(o.workDir)
    if (found.length) throw new Error(`opencode would load config from an ancestor of its working directory: ${found.join(", ")}`)
  }
}

export async function sweepOrphans(run: Runner, log: (m: string) => void = () => {}): Promise<string[]> {
  const names = await listMachines(run)
  for (const name of names) {
    log(`removing orphaned machine ${name}`)
    await new MvmSandbox({ name, run }).remove()
  }
  return names
}

// --- handshake ---

export async function waitForReady(file: string, nonce: string, deadlineMs: number, pollMs = 100): Promise<void> {
  const end = Date.now() + deadlineMs
  let last: string | undefined
  for (;;) {
    try {
      last = readFileSync(file, "utf8")
      if (last === nonce) return
    } catch {
      last = undefined
    }
    if (Date.now() >= end) break
    await Bun.sleep(Math.min(pollMs, Math.max(0, end - Date.now())))
  }
  throw new Error(last === undefined ? "plugin did not report ready" : "plugin did not report ready (ready file holds a different nonce)")
}

// --- host RSS ceiling (GHSA-x85r-49ww-2pxq) ---

export async function findSupervisorPid(run: Runner, exec: HostExec, name: string): Promise<{ pid: number; method: string } | undefined> {
  try {
    const r = await run(["machine", "inspect", name], { timeoutMs: 30_000 })
    if (r.code === 0) {
      const text = new TextDecoder().decode(r.stdout)
      const m = /supervisor[^\n]*?\bpid\b\D{0,5}(\d+)/i.exec(text) ?? /"?\bpid"?\s*[:=]\s*(\d+)/i.exec(text)
      if (m) return { pid: Number(m[1]), method: "machine inspect" }
    }
  } catch {}
  const r = await exec(["pgrep", "-f", `mvm-hvf-supervisor.*${name}`]).catch(() => undefined)
  const pid = Number(r?.stdout.trim().split(/\s+/)[0])
  if (r?.code === 0 && pid > 0) return { pid, method: "pgrep -f" }
  return undefined
}

export async function hostRssMiB(exec: HostExec, pid: number): Promise<number | undefined> {
  const r = await exec(["ps", "-o", "rss=", "-p", String(pid)]).catch(() => undefined)
  const kib = Number(r?.stdout.trim())
  return r?.code === 0 && Number.isFinite(kib) && kib > 0 ? kib / 1024 : undefined
}

// --- the session ---

export async function runSession(cfg: OperatorConfig, deps: { hostExec?: HostExec; env?: Record<string, string | undefined> } = {}): Promise<number> {
  const exec = deps.hostExec ?? hostExec
  const env = deps.env ?? process.env
  const id = newSessionId()
  const runtime = mkdtempSync(join(tmpdir(), `rts-${id}-`))
  const p = sessionPaths(id, cfg.sessionsDir, runtime)
  prepareSessionDirs(p)
  const log = (m: string) => {
    const line = `[rts ${id}] ${m}`
    console.error(line)
    try {
      appendFileSync(p.logFile, `${new Date().toISOString()} ${m}\n`)
    } catch {}
  }
  log(`session ${id}: results in ${p.sessionDir}, runtime in ${p.runtime}`)

  const operatorHome = env.HOME || homedir()
  const run = spawnRunner(cfg.mvmctl, p.emptyGitConfig, { HOME: operatorHome })
  const sb = new MvmSandbox({ name: p.machine, run, copyLimits: DEFAULT_COPY_LIMITS })
  let machineAttempted = false
  let machineCreated = false
  let creating: Promise<void> | undefined
  let child: ReturnType<typeof Bun.spawn> | undefined
  let childExited = false
  let rssTimer: ReturnType<typeof setInterval> | undefined

  let teardownPromise: Promise<void> | undefined
  const teardown = (why: string) =>
    (teardownPromise ??= (async () => {
      log(`teardown: ${why}`)
      if (rssTimer) clearInterval(rssTimer)
      if (child && !childExited) {
        child.kill("SIGTERM")
        const done = await Promise.race([child.exited.then(() => true), Bun.sleep(10_000).then(() => false)])
        if (!done) child.kill("SIGKILL")
        log("teardown: opencode stopped")
      }
      if (!machineAttempted) return
      // A signal during create must not race it: let create finish, then remove.
      await creating?.catch(() => undefined)
      if (machineCreated) {
        try {
          const r = await sb.copyOut("/out", p.outDir)
          log(r.status === "exported" ? `teardown: exported ${r.files} files, ${r.bytes} bytes to ${p.outDir}` : "teardown: nothing to export")
        } catch (e) {
          log(`teardown: EXPORT FAILED: ${(e as Error).message}`)
        }
      }
      try {
        await sb.remove()
        log(`teardown: removed ${p.machine}`)
      } catch (e) {
        log(`teardown: MACHINE REMOVAL FAILED: ${(e as Error).message}`)
      }
    })())

  const onSignal = (sig: string) => () => {
    log(`received ${sig}`)
    void teardown(sig)
  }
  const onInt = onSignal("SIGINT")
  const onTerm = onSignal("SIGTERM")
  process.on("SIGINT", onInt)
  process.on("SIGTERM", onTerm)

  let exitCode = 1
  try {
    await preflight({ run, hostExec: exec, opencode: cfg.opencode, env, workDir: p.work })
    await sweepOrphans(run, log)

    machineAttempted = true
    creating = sb.create({ name: p.machine, image: cfg.image, memoryMiB: cfg.limits.memoryMiB, cpus: cfg.limits.cpus })
    await creating
    machineCreated = true
    log(`created ${p.machine}`)
    const mk = await sb.exec(["mkdir", "-p", "/in", "/out"], { timeoutMs: 30_000, maxOutputBytes: 4096 })
    if (mk.exitCode !== 0) throw new Error("could not create /in and /out in the guest")
    if (cfg.inputsDir) {
      await sb.copyIn(cfg.inputsDir, "/in")
      log(`copied ${cfg.inputsDir} to /in`)
    }
    if (teardownPromise) throw new Error("interrupted before opencode started")

    const nonce = newNonce()
    const pluginOptions: PluginOptions = {
      machine: p.machine,
      nonce,
      readyFile: p.readyFile,
      auditFile: p.auditFile,
      mvmctl: cfg.mvmctl,
      emptyGitConfig: p.emptyGitConfig,
      provider: cfg.provider.id,
      timeoutMs: cfg.limits.toolTimeoutMs,
      maxOutputBytes: cfg.limits.maxOutputBytes,
      mvmHome: operatorHome,
    }
    writeOpencodeConfig(p.configDir, { pluginDir: PLUGIN_DIR, pluginOptions, provider: cfg.provider })
    const launch = opencodeLaunch(p, cfg.opencode, env)
    child = Bun.spawn(launch.argv, { cwd: launch.cwd, env: launch.env, stdin: "inherit", stdout: "inherit", stderr: "inherit" })
    const exited = child.exited.then((code) => {
      childExited = true
      return code
    })

    try {
      await Promise.race([
        waitForReady(p.readyFile, nonce, cfg.limits.handshakeMs),
        exited.then(() => {
          throw new Error("opencode exited before the plugin reported ready")
        }),
      ])
    } catch (e) {
      throw new Error(`refusing the session: ${(e as Error).message}`)
    }
    log("plugin ready; session running")

    let supervisor: { pid: number; method: string } | undefined
    rssTimer = setInterval(async () => {
      if (!supervisor) {
        supervisor = await findSupervisorPid(run, exec, p.machine)
        if (!supervisor) return
        log(`sampling host RSS of pid ${supervisor.pid} (found via ${supervisor.method})`)
      }
      const rss = await hostRssMiB(exec, supervisor.pid)
      if (rss !== undefined && rss > cfg.limits.hostRssCeilingMiB) {
        log(`host RSS ${rss.toFixed(0)} MiB over the ${cfg.limits.hostRssCeilingMiB} MiB ceiling (pid ${supervisor.pid} via ${supervisor.method})`)
        void teardown("host RSS ceiling")
      }
    }, 5000)

    exitCode = await exited
  } catch (e) {
    log((e as Error).message)
    exitCode = exitCode === 0 ? 1 : exitCode
  } finally {
    await teardown("session ended")
    process.off("SIGINT", onInt)
    process.off("SIGTERM", onTerm)
  }
  return exitCode
}

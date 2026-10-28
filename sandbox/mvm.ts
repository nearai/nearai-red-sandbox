// MvmSandbox: the v1 Sandbox backend. Shells out to mvmctl v0.22.0 with
// argv only; nothing goes through a host shell.

import { DEFAULT_COPY_LIMITS, copyInVia, copyOutVia, type CopyLimits } from "./copy.ts"
import { isPoisoned, newNonce, parseResult, wrapArgv } from "./protocol.ts"
import { SandboxUnavailable, type CopyOutResult, type ExecOptions, type ExecResult, type Sandbox } from "./sandbox.ts"

export type Runner = (
  argv: string[],
  o: { timeoutMs: number },
) => Promise<{ code: number | null; stdout: Uint8Array; stderr: Uint8Array; killed: boolean }>

export const MACHINE_NAME_RE = /^rts-[0-9a-f]{12}$/
export const IMAGE_REF_RE = /^[a-z0-9./-]+@sha256:[0-9a-f]{64}$/

// Host backstop on top of the guest-side limit. If it fires, the exec
// client was killed from the host, which poisons the machine.
export const BACKSTOP_MS = 30_000
// Lifecycle commands (create, start, rm, ps) get this long.
const CONTROL_TIMEOUT_MS = 180_000
// Never buffer more than this from one mvmctl stream, whatever the guest does.
const MAX_CAPTURE_BYTES = 16 * 1024 * 1024

const decode = (b: Uint8Array) => new TextDecoder().decode(b)

async function readCapped(stream: ReadableStream<Uint8Array>, cap: number): Promise<Uint8Array> {
  const chunks: Uint8Array[] = []
  let kept = 0
  for await (const chunk of stream) {
    if (kept >= cap) continue // keep draining so the child never blocks
    const take = chunk.subarray(0, cap - kept)
    chunks.push(take)
    kept += take.length
  }
  const out = new Uint8Array(kept)
  let off = 0
  for (const c of chunks) {
    out.set(c, off)
    off += c.length
  }
  return out
}

export function spawnRunner(mvmctl: string, emptyGitConfig: string, extraEnv: Record<string, string> = {}): Runner {
  return async (argv, o) => {
    const proc = Bun.spawn([mvmctl, ...argv], {
      stdin: "ignore",
      stdout: "pipe",
      stderr: "pipe",
      env: { ...process.env, ...extraEnv, GIT_CONFIG_GLOBAL: emptyGitConfig },
    })
    let killed = false
    const timer = setTimeout(() => {
      killed = true
      proc.kill("SIGKILL")
    }, o.timeoutMs)
    try {
      const [stdout, stderr, code] = await Promise.all([
        readCapped(proc.stdout, MAX_CAPTURE_BYTES),
        readCapped(proc.stderr, MAX_CAPTURE_BYTES),
        proc.exited,
      ])
      return { code: killed ? null : code, stdout, stderr, killed }
    } finally {
      clearTimeout(timer)
    }
  }
}

function checkName(name: string) {
  if (!MACHINE_NAME_RE.test(name)) throw new Error(`machine name must match rts-<12 hex chars>: ${JSON.stringify(name)}`)
}

function firstLine(b: Uint8Array): string {
  return decode(b).trim().split("\n").slice(-3).join(" | ").slice(0, 500)
}

// Machine names from `machine ps`, restricted to ones this harness creates.
export async function listMachines(run: Runner): Promise<string[]> {
  const r = await run(["machine", "ps"], { timeoutMs: CONTROL_TIMEOUT_MS })
  if (r.code !== 0) throw new Error(`machine ps failed: ${firstLine(r.stderr)}`)
  return psNames(decode(r.stdout)).filter((n) => MACHINE_NAME_RE.test(n))
}

function psNames(text: string): string[] {
  return text.split(/\s+/).filter((t) => t.length > 0)
}

export class MvmSandbox implements Sandbox {
  readonly name: string
  protected readonly run: Runner
  private deadReason: string | undefined
  private queue: Promise<unknown> = Promise.resolve()
  private readonly copyLimits: CopyLimits

  constructor(o: { name: string; run: Runner; copyLimits?: Partial<CopyLimits> }) {
    checkName(o.name)
    this.name = o.name
    this.run = o.run
    this.copyLimits = { ...DEFAULT_COPY_LIMITS, ...o.copyLimits }
  }

  // For the plugin: the launcher created the machine; the plugin only uses it.
  static attach(name: string, run: Runner): MvmSandbox {
    return new MvmSandbox({ name, run })
  }

  get unavailable(): boolean {
    return this.deadReason !== undefined
  }

  private markUnavailable(reason: string): SandboxUnavailable {
    this.deadReason ??= reason
    return new SandboxUnavailable(this.deadReason)
  }

  async create(spec: { name: string; image: string; memoryMiB: number; cpus: number }): Promise<void> {
    if (spec.name !== this.name) throw new Error(`create name ${spec.name} does not match sandbox ${this.name}`)
    if (!IMAGE_REF_RE.test(spec.image)) throw new Error(`image must be digest-pinned: ${JSON.stringify(spec.image)}`)
    if (!Number.isInteger(spec.cpus) || spec.cpus < 1) throw new Error("cpus must be a positive integer")
    if (!Number.isInteger(spec.memoryMiB) || spec.memoryMiB < 64) throw new Error("memoryMiB must be an integer of at least 64")
    if (this.deadReason) throw new SandboxUnavailable(this.deadReason)
    const create = [
      "machine", "create", this.name,
      "--image", spec.image,
      "--profile", "dev",
      "--cpus", String(spec.cpus),
      "--memory", `${spec.memoryMiB}M`,
    ]
    await this.control(create, "machine create")
    await this.control(["machine", "start", this.name], "machine start")
  }

  private async control(argv: string[], what: string) {
    const r = await this.run(argv, { timeoutMs: CONTROL_TIMEOUT_MS })
    if (r.killed) throw new Error(`${what} timed out`)
    if (r.code !== 0) throw new Error(`${what} failed: ${firstLine(r.stderr) || `exit ${r.code}`}`)
    return r
  }

  exec(argv: string[], opts: ExecOptions): Promise<ExecResult> {
    if (this.deadReason) return Promise.reject(new SandboxUnavailable(this.deadReason))
    // One exec at a time per machine: mvm journals each exec, and a
    // poisoned machine must stop every queued call from reaching it.
    const next = this.queue.then(() => this.execNow(argv, opts))
    this.queue = next.catch(() => undefined)
    return next
  }

  private async execNow(argv: string[], opts: ExecOptions): Promise<ExecResult> {
    if (this.deadReason) throw new SandboxUnavailable(this.deadReason)
    const nonce = newNonce()
    const timeoutSec = Math.max(1, Math.ceil(opts.timeoutMs / 1000))
    const wrapped = wrapArgv(argv, { nonce, timeoutSec, maxOutputBytes: opts.maxOutputBytes, workdir: opts.workdir })
    let r: Awaited<ReturnType<Runner>>
    try {
      r = await this.run(["machine", "exec", this.name, "--", ...wrapped], { timeoutMs: timeoutSec * 1000 + BACKSTOP_MS })
    } catch (e) {
      throw this.markUnavailable(`mvmctl exec failed to run: ${(e as Error).message}`)
    }
    if (this.deadReason) throw new SandboxUnavailable(this.deadReason) // torn down mid-exec
    if (r.killed) throw this.markUnavailable("exec exceeded the host backstop; machine is lost")
    const parsed = parseResult(r.stdout, r.stderr, nonce)
    if (parsed === "no-trailer" || r.code !== 0) {
      const text = decode(r.stderr)
      if (isPoisoned(text)) throw this.markUnavailable("machine refused exec (no durable finish)")
      if (parsed === "no-trailer") throw this.markUnavailable(`exec returned no valid trailer (mvmctl exit ${r.code})`)
      throw this.markUnavailable(`mvmctl exec exited ${r.code}`)
    }
    return parsed
  }

  copyIn(hostDir: string, guestDir: string): Promise<void> {
    return copyInVia(this, hostDir, guestDir)
  }

  // Treats the guest as hostile; see sandbox/copy.ts and sandbox/untar.ts.
  copyOut(guestDir: string, hostDir: string): Promise<CopyOutResult> {
    return copyOutVia(this, guestDir, hostDir, this.copyLimits)
  }

  async remove(): Promise<void> {
    this.markUnavailable("sandbox removed")
    const rm = await this.run(["machine", "rm", this.name, "--force", "--yes"], { timeoutMs: CONTROL_TIMEOUT_MS })
    const ps = await this.run(["machine", "ps"], { timeoutMs: CONTROL_TIMEOUT_MS })
    if (ps.code !== 0) throw new Error(`machine ps failed after rm: ${firstLine(ps.stderr)}`)
    if (psNames(decode(ps.stdout)).includes(this.name)) {
      throw new Error(`machine still present after rm: ${this.name}${rm.code !== 0 ? ` (rm: ${firstLine(rm.stderr)})` : ""}`)
    }
  }
}

import { expect, test } from "bun:test"
import { MvmSandbox, listMachines, type Runner } from "../../sandbox/mvm.ts"
import { SandboxUnavailable } from "../../sandbox/sandbox.ts"
import { wrapArgv } from "../../sandbox/protocol.ts"

const enc = (s: string) => new TextEncoder().encode(s)
const NAME = "rts-0123456789ab"
const IMAGE = "docker.io/library/alpine@sha256:e311ae748be7f56ae5cba304bc488f0786df68ee507513f654a5cc8597cffb42"

type Reply = { code?: number | null; stdout?: string; stderr?: string; killed?: boolean }
type Call = { argv: string[]; timeoutMs: number }

// A recording fake. `reply` sees each argv; for `machine exec` it is handed
// the nonce so it can build a valid trailer.
function fake(reply: (argv: string[], nonce?: string) => Reply = () => ({})) {
  const calls: Call[] = []
  const run: Runner = async (argv, o) => {
    calls.push({ argv, timeoutMs: o.timeoutMs })
    const nonce = argv[1] === "exec" ? argv[8] : undefined
    const r = reply(argv, nonce)
    return { code: r.code === undefined ? 0 : r.code, stdout: enc(r.stdout ?? ""), stderr: enc(r.stderr ?? ""), killed: r.killed ?? false }
  }
  return { run, calls }
}

const trailer = (nonce: string, status = 0, out = 0, err = 0) => `\nRTS_EXIT_${nonce} ${status} ${out} ${err}\n`
const opts = { timeoutMs: 120_000, maxOutputBytes: 65536 }
const FORBIDDEN = ["--net", "--allow-host", "--peer", "--gpu"]

test("create issues exactly the create and start lines, never a network flag", async () => {
  const f = fake()
  const sb = new MvmSandbox({ name: NAME, run: f.run })
  await sb.create({ name: NAME, image: IMAGE, memoryMiB: 2048, cpus: 2 })
  expect(f.calls.map((c) => c.argv)).toEqual([
    ["machine", "create", NAME, "--image", IMAGE, "--profile", "dev", "--cpus", "2", "--memory", "2048M"],
    ["machine", "start", NAME],
  ])
  for (const c of f.calls) for (const flag of FORBIDDEN) expect(c.argv).not.toContain(flag)
})

test("create refuses an image that is not digest-pinned and runs nothing", async () => {
  const f = fake()
  const sb = new MvmSandbox({ name: NAME, run: f.run })
  await expect(sb.create({ name: NAME, image: "alpine:latest", memoryMiB: 2048, cpus: 2 })).rejects.toThrow("image must be digest-pinned")
  await expect(sb.create({ name: NAME, image: "Error: no such image", memoryMiB: 2048, cpus: 2 })).rejects.toThrow("image must be digest-pinned")
  expect(f.calls).toEqual([])
})

test("create refuses a spec name that differs from the sandbox's", async () => {
  const f = fake()
  const sb = new MvmSandbox({ name: NAME, run: f.run })
  await expect(sb.create({ name: "rts-ffffffffffff", image: IMAGE, memoryMiB: 2048, cpus: 2 })).rejects.toThrow()
  expect(f.calls).toEqual([])
})

test("create reports a failed create or start", async () => {
  const f = fake((argv) => (argv[1] === "start" ? { code: 1, stderr: "bad image" } : {}))
  const sb = new MvmSandbox({ name: NAME, run: f.run })
  await expect(sb.create({ name: NAME, image: IMAGE, memoryMiB: 2048, cpus: 2 })).rejects.toThrow("machine start failed: bad image")
})

test("machine names must be rts- plus 12 hex chars", () => {
  const f = fake()
  expect(() => new MvmSandbox({ name: "web", run: f.run })).toThrow()
  expect(() => new MvmSandbox({ name: "-rf", run: f.run })).toThrow()
  expect(() => MvmSandbox.attach("rts-0123456789AB", f.run)).toThrow()
  expect(MvmSandbox.attach(NAME, f.run)).toBeInstanceOf(MvmSandbox)
})

test("exec sends the wrapped argv and returns the parsed result", async () => {
  const f = fake((argv, nonce) => (argv[1] === "exec" ? { stdout: "ok\n", stderr: trailer(nonce!, 0, 3, 0) } : {}))
  const sb = new MvmSandbox({ name: NAME, run: f.run })
  const r = await sb.exec(["true"], opts)
  const sent = f.calls[0]!
  const nonce = sent.argv[8]!
  expect(sent.argv).toEqual(["machine", "exec", NAME, "--", ...wrapArgv(["true"], { nonce, timeoutSec: 120, maxOutputBytes: 65536 })])
  expect(sent.timeoutMs).toBe(150_000) // host backstop: limit plus 30 s
  expect(r).toEqual({ exitCode: 0, timedOut: false, stdout: enc("ok\n"), stderr: enc(""), stdoutBytes: 3, stderrBytes: 0, truncated: false })
})

test("each exec gets a fresh nonce, and workdir reaches the wrapper", async () => {
  const f = fake((argv, nonce) => ({ stderr: trailer(nonce!) }))
  const sb = new MvmSandbox({ name: NAME, run: f.run })
  await sb.exec(["true"], { ...opts, workdir: "/in" })
  await sb.exec(["true"], opts)
  expect(f.calls[0]!.argv[8]).not.toBe(f.calls[1]!.argv[8])
  expect(f.calls[0]!.argv[11]).toBe("/in")
})

test("a sub-second limit rounds up to one second in the guest", async () => {
  const f = fake((argv, nonce) => ({ stderr: trailer(nonce!) }))
  const sb = new MvmSandbox({ name: NAME, run: f.run })
  await sb.exec(["true"], { timeoutMs: 1, maxOutputBytes: 10 })
  expect(f.calls[0]!.argv[9]).toBe("1")
})

test("a poisoned machine is unavailable, and later execs never reach the runner", async () => {
  const f = fake(() => ({ code: 1, stderr: "Error: machine input sequence 1 has no durable finish; refuse exec and checkpoint" }))
  const sb = new MvmSandbox({ name: NAME, run: f.run })
  await expect(sb.exec(["true"], opts)).rejects.toBeInstanceOf(SandboxUnavailable)
  expect(sb.unavailable).toBe(true)
  await expect(sb.exec(["true"], opts)).rejects.toBeInstanceOf(SandboxUnavailable)
  await expect(sb.exec(["true"], opts)).rejects.toThrow("sandbox unavailable")
  expect(f.calls.length).toBe(1)
})

test("a result with no valid trailer marks the sandbox unavailable", async () => {
  const f = fake(() => ({ stdout: "hi", stderr: `\nRTS_EXIT_${"0".repeat(24)} 0 2 0\n` }))
  const sb = new MvmSandbox({ name: NAME, run: f.run })
  await expect(sb.exec(["true"], opts)).rejects.toBeInstanceOf(SandboxUnavailable)
  await expect(sb.exec(["true"], opts)).rejects.toBeInstanceOf(SandboxUnavailable)
  expect(f.calls.length).toBe(1)
})

test("a nonzero mvmctl exit marks the sandbox unavailable even with a trailer", async () => {
  const f = fake((argv, nonce) => ({ code: 2, stderr: trailer(nonce!) }))
  const sb = new MvmSandbox({ name: NAME, run: f.run })
  await expect(sb.exec(["true"], opts)).rejects.toBeInstanceOf(SandboxUnavailable)
  expect(sb.unavailable).toBe(true)
})

test("guest stderr that merely mentions the poison text is not a poisoning", async () => {
  const f = fake((argv, nonce) => ({ stderr: `grep: no durable finish${trailer(nonce!, 0, 0, 23)}` }))
  const sb = new MvmSandbox({ name: NAME, run: f.run })
  const r = await sb.exec(["true"], opts)
  expect(r.exitCode).toBe(0)
  expect(sb.unavailable).toBe(false)
})

test("a run killed by the host backstop marks the sandbox unavailable", async () => {
  const f = fake(() => ({ code: null, killed: true }))
  const sb = new MvmSandbox({ name: NAME, run: f.run })
  await expect(sb.exec(["sleep", "999"], opts)).rejects.toBeInstanceOf(SandboxUnavailable)
  await expect(sb.exec(["true"], opts)).rejects.toBeInstanceOf(SandboxUnavailable)
  expect(f.calls.length).toBe(1)
})

test("a runner that throws marks the sandbox unavailable", async () => {
  const run: Runner = async () => {
    throw new Error("spawn failed")
  }
  const sb = new MvmSandbox({ name: NAME, run })
  await expect(sb.exec(["true"], opts)).rejects.toBeInstanceOf(SandboxUnavailable)
  expect(sb.unavailable).toBe(true)
})

test("execs are serialized: one machine exec at a time", async () => {
  let inFlight = 0
  let maxInFlight = 0
  const calls: string[][] = []
  const run: Runner = async (argv) => {
    calls.push(argv)
    inFlight++
    maxInFlight = Math.max(maxInFlight, inFlight)
    await Bun.sleep(5)
    inFlight--
    return { code: 0, stdout: enc(""), stderr: enc(trailer(argv[8]!)), killed: false }
  }
  const sb = new MvmSandbox({ name: NAME, run })
  await Promise.all([sb.exec(["a"], opts), sb.exec(["b"], opts), sb.exec(["c"], opts)])
  expect(maxInFlight).toBe(1)
  expect(calls.length).toBe(3)
})

test("an exec queued behind one that poisons the machine never reaches the runner", async () => {
  const f = fake(() => ({ code: 1, stderr: "no durable finish" }))
  const sb = new MvmSandbox({ name: NAME, run: f.run })
  const results = await Promise.allSettled([sb.exec(["a"], opts), sb.exec(["b"], opts)])
  expect(results.every((r) => r.status === "rejected")).toBe(true)
  expect(f.calls.length).toBe(1)
})

test("remove force-removes, confirms with ps, and makes later execs unavailable", async () => {
  const f = fake((argv) => (argv[1] === "ps" ? { stdout: "NAME STATUS\nweb running\n" } : {}))
  const sb = new MvmSandbox({ name: NAME, run: f.run })
  await sb.remove()
  expect(f.calls.map((c) => c.argv)).toEqual([
    ["machine", "rm", NAME, "--force", "--yes"],
    ["machine", "ps"],
  ])
  await expect(sb.exec(["true"], opts)).rejects.toBeInstanceOf(SandboxUnavailable)
  expect(f.calls.length).toBe(2)
})

test("remove rejects when ps still lists the machine", async () => {
  const f = fake((argv) => (argv[1] === "ps" ? { stdout: `NAME STATUS\n${NAME} running\n` } : {}))
  const sb = new MvmSandbox({ name: NAME, run: f.run })
  await expect(sb.remove()).rejects.toThrow("machine still present")
})

test("a tool call during teardown is refused at once", async () => {
  let release!: () => void
  const gate = new Promise<void>((r) => (release = r))
  const calls: string[][] = []
  const run: Runner = async (argv) => {
    calls.push(argv)
    if (argv[1] === "rm") await gate
    return { code: 0, stdout: enc(""), stderr: enc(""), killed: false }
  }
  const sb = new MvmSandbox({ name: NAME, run })
  const removing = sb.remove()
  await expect(sb.exec(["true"], opts)).rejects.toBeInstanceOf(SandboxUnavailable)
  release()
  await removing
  expect(calls.some((c) => c[1] === "exec")).toBe(false)
})

test("listMachines returns only rts- machine names from ps", async () => {
  const f = fake(() => ({ stdout: "NAME STATUS\nrts-aaaaaaaaaaaa running\nweb stopped\nrts-short x\nrts-bbbbbbbbbbbb stopped\n" }))
  expect(await listMachines(f.run)).toEqual(["rts-aaaaaaaaaaaa", "rts-bbbbbbbbbbbb"])
})

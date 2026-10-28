import { expect, test } from "bun:test"
import { isPoisoned, newNonce, parseResult, wrapArgv, type ParsedResult } from "../../sandbox/protocol.ts"

const enc = (s: string) => new TextEncoder().encode(s)

test("wrapArgv runs the command under timeout -s KILL and never interpolates it", () => {
  const argv = wrapArgv(["grep", "-n", "--", "$(rm -rf /)", "/in"], { nonce: "a".repeat(24), timeoutSec: 120, maxOutputBytes: 65536 })
  expect(argv[0]).toBe("sh")
  expect(argv[1]).toBe("-c")
  expect(argv[2]).toContain('timeout -s KILL "$2"') // fixed script, operands by position
  expect(argv[2]).not.toContain("rm -rf")
  expect(argv.slice(-5)).toEqual(["grep", "-n", "--", "$(rm -rf /)", "/in"])
})

test("wrapArgv passes nonce, timeout, cap and workdir as positional operands", () => {
  const argv = wrapArgv(["true"], { nonce: "f".repeat(24), timeoutSec: 7, maxOutputBytes: 99, workdir: "/a b" })
  expect(argv.slice(3)).toEqual(["rts", "f".repeat(24), "7", "99", "/a b", "true"])
  const none = wrapArgv(["true"], { nonce: "f".repeat(24), timeoutSec: 7, maxOutputBytes: 99 })
  expect(none.slice(3)).toEqual(["rts", "f".repeat(24), "7", "99", "", "true"])
})

test("wrapArgv rejects a bad nonce, a non-positive timeout, and an empty command", () => {
  expect(() => wrapArgv(["true"], { nonce: "x", timeoutSec: 1, maxOutputBytes: 1 })).toThrow()
  expect(() => wrapArgv(["true"], { nonce: "a".repeat(24), timeoutSec: 0, maxOutputBytes: 1 })).toThrow()
  expect(() => wrapArgv([], { nonce: "a".repeat(24), timeoutSec: 1, maxOutputBytes: 1 })).toThrow()
})

test("parseResult reads status and sizes from the trailer and strips it", () => {
  const n = "b".repeat(24)
  const r = parseResult(enc("hi"), enc(`warn\nRTS_EXIT_${n} 3 2 4\n`), n)
  expect(r).toEqual({ exitCode: 3, timedOut: false, stdout: enc("hi"), stderr: enc("warn"), stdoutBytes: 2, stderrBytes: 4, truncated: false })
})

test("status 137 is a timeout; reported size above the bytes returned is truncation", () => {
  const n = "c".repeat(24)
  const r = parseResult(enc("x".repeat(10)), enc(`RTS_EXIT_${n} 137 2097152 0\n`), n) as ParsedResult
  expect(r.timedOut).toBe(true)
  expect(r.truncated).toBe(true)
  expect(r.stdoutBytes).toBe(2097152)
})

test("a trailer with another nonce, or none, is no-trailer", () => {
  expect(parseResult(enc(""), enc(`RTS_EXIT_${"d".repeat(24)} 0 0 0\n`), "e".repeat(24))).toBe("no-trailer")
  expect(parseResult(enc(""), enc("boom\n"), "e".repeat(24))).toBe("no-trailer")
})

test("a trailer that is not the last stderr line is no-trailer", () => {
  const n = "e".repeat(24)
  expect(parseResult(enc(""), enc(`RTS_EXIT_${n} 0 0 0\nmore\n`), n)).toBe("no-trailer")
  expect(parseResult(enc(""), enc(`RTS_EXIT_${n} 0 0\n`), n)).toBe("no-trailer")
  expect(parseResult(enc(""), enc(`RTS_EXIT_${n} x 0 0\n`), n)).toBe("no-trailer")
})

test("isPoisoned matches the mvm journal refusal", () => {
  expect(isPoisoned("Error: machine input sequence 1 has no durable finish; refuse exec")).toBe(true)
  expect(isPoisoned("all good")).toBe(false)
})

test("newNonce is 24 lowercase hex chars and fresh", () => {
  const a = newNonce()
  expect(a).toMatch(/^[0-9a-f]{24}$/)
  expect(newNonce()).not.toBe(a)
})

// The wrapper is plain POSIX sh, so the host's sh can run it. This checks
// the script itself, not mvm.
async function runLocally(command: string[], o: { timeoutSec?: number; maxOutputBytes?: number; workdir?: string } = {}) {
  const nonce = newNonce()
  const argv = wrapArgv(command, { nonce, timeoutSec: o.timeoutSec ?? 10, maxOutputBytes: o.maxOutputBytes ?? 65536, workdir: o.workdir })
  const p = Bun.spawn(argv, { stdin: "ignore", stdout: "pipe", stderr: "pipe" })
  const [out, err, code] = await Promise.all([new Response(p.stdout).bytes(), new Response(p.stderr).bytes(), p.exited])
  return { code, r: parseResult(out, err, nonce) as ParsedResult, nonce }
}

test("host sh: the wrapper always exits 0 and reports the real status", async () => {
  const { code, r } = await runLocally(["sh", "-c", "echo out; echo err >&2; exit 3"])
  expect(code).toBe(0)
  expect(r.exitCode).toBe(3)
  expect(new TextDecoder().decode(r.stdout)).toBe("out\n")
  expect(new TextDecoder().decode(r.stderr)).toBe("err\n")
  expect(r.truncated).toBe(false)
})

test("host sh: operands are not interpolated", async () => {
  const { r } = await runLocally(["printf", "%s", "$(echo pwned) `id` ; rm -rf /nope"])
  expect(new TextDecoder().decode(r.stdout)).toBe("$(echo pwned) `id` ; rm -rf /nope")
})

test("host sh: output is capped and the full size reported", async () => {
  const { r } = await runLocally(["head", "-c", "100000", "/dev/zero"], { maxOutputBytes: 1000 })
  expect(r.stdout.length).toBe(1000)
  expect(r.stdoutBytes).toBe(100000)
  expect(r.truncated).toBe(true)
})

test("host sh: timeout kills with status 137", async () => {
  const { r } = await runLocally(["sleep", "5"], { timeoutSec: 1 })
  expect(r.timedOut).toBe(true)
  expect(r.exitCode).toBe(137)
})

test("host sh: workdir is applied, and a missing one is status 126", async () => {
  const ok = await runLocally(["pwd"], { workdir: "/tmp" })
  expect(new TextDecoder().decode(ok.r.stdout).trim()).toBe("/tmp")
  const bad = await runLocally(["pwd"], { workdir: "/does/not/exist" })
  expect(bad.r.exitCode).toBe(126)
})

test("host sh: a missing command is status 127, and temp files are removed", async () => {
  const { r, nonce } = await runLocally(["rts-no-such-command"])
  expect(r.exitCode).toBe(127)
  expect(await Bun.file(`/tmp/rts-${nonce}.out`).exists()).toBe(false)
  expect(await Bun.file(`/tmp/rts-${nonce}.err`).exists()).toBe(false)
})

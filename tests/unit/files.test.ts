import { afterAll, expect, test } from "bun:test"
import { createHash } from "node:crypto"
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { guestRead, guestSha256, guestWrite } from "../../sandbox/files.ts"
import type { ExecOptions, ExecResult, Sandbox } from "../../sandbox/sandbox.ts"
import { HostShellSandbox } from "./hostsh.ts"

const enc = (s: string) => new TextEncoder().encode(s)

// Records argv and answers every exec with success.
function recorder(reply?: (argv: string[]) => Partial<ExecResult>) {
  const execs: { argv: string[]; opts: ExecOptions }[] = []
  const sb: Sandbox = {
    create: async () => {},
    remove: async () => {},
    copyIn: async () => {},
    copyOut: async () => ({ status: "nothing to export" }),
    exec: async (argv, opts) => {
      execs.push({ argv, opts })
      return { exitCode: 0, timedOut: false, stdout: new Uint8Array(), stderr: new Uint8Array(), stdoutBytes: 0, stderrBytes: 0, truncated: false, ...reply?.(argv) }
    },
  }
  return { sb, execs }
}

test("a 120 KiB write is 48 KiB base64 chunks plus a final mv", async () => {
  const { sb, execs } = recorder()
  const data = crypto.getRandomValues(new Uint8Array(120 * 1024))
  await guestWrite(sb, "/out/f.bin", data)
  // 122,880 bytes is 163,840 base64 chars: four chunks of at most 49,152.
  expect(execs.length).toBe(5)
  const chunks = execs.slice(0, 4).map((e) => e.argv.at(-1)!)
  for (const c of chunks) expect(c.length).toBeLessThanOrEqual(49_152)
  expect(Buffer.from(chunks.join(""), "base64")).toEqual(Buffer.from(data))
  expect(execs[4]!.argv).toContain("/out/f.bin")
})

test("every write exec places -- before the path, and a -rf path stays an operand", async () => {
  const { sb, execs } = recorder()
  await guestWrite(sb, "-rf", enc("x"))
  for (const { argv } of execs) {
    expect(argv[0]).toBe("sh")
    expect(argv[1]).toBe("-c")
    expect(argv[2]).not.toContain("-rf")
    expect(argv[2]).toContain("--")
  }
  expect(execs.at(-1)!.argv.slice(3)).toContain("-rf")
})

test("read and sha256 pass the path only as an operand", async () => {
  const { sb, execs } = recorder((argv) => ({ stdout: argv[2]!.includes("sha256sum") ? enc("a".repeat(64) + "  -\n") : enc("M\n") }))
  await guestRead(sb, "$(reboot)", 100)
  await guestSha256(sb, "$(reboot)")
  for (const { argv } of execs) {
    expect(argv[2]).not.toContain("reboot")
    expect(argv.slice(3)).toContain("$(reboot)")
  }
})

test("a failing chunk aborts the write with the guest error", async () => {
  const { sb } = recorder(() => ({ exitCode: 1, stderr: enc("No space left on device") }))
  await expect(guestWrite(sb, "/out/f", enc("x"))).rejects.toThrow("No space left on device")
})

// The same scripts, run by the host's sh against a temp directory.
const dir = mkdtempSync(join(tmpdir(), "rts-files-"))
afterAll(() => rmSync(dir, { recursive: true, force: true }))
const hs = new HostShellSandbox()
const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex")

test("host sh: a 200 KiB random write round-trips by sha256", async () => {
  const data = crypto.getRandomValues(new Uint8Array(200 * 1024))
  const p = join(dir, "new/sub/rand.bin")
  await guestWrite(hs, p, data)
  expect(await guestSha256(hs, p)).toBe(sha(data))
  expect(new Uint8Array(readFileSync(p))).toEqual(data)
})

test("host sh: awkward paths round-trip through write, read and sha256", async () => {
  for (const name of ["a b", "-x", `q'"q`, "ünï", "new\nline", "$(id)", "--", "*"]) {
    const p = join(dir, name)
    const body = enc(`content of ${name}`)
    await guestWrite(hs, p, body)
    expect(readFileSync(p, "utf8")).toBe(`content of ${name}`)
    const r = await guestRead(hs, p, 1000)
    expect(r).toEqual({ kind: "file", data: body, size: body.length, truncated: false })
    expect(await guestSha256(hs, p)).toBe(sha(body))
  }
})

test("host sh: an empty write creates an empty file", async () => {
  const p = join(dir, "empty")
  await guestWrite(hs, p, new Uint8Array())
  expect(readFileSync(p).length).toBe(0)
  expect(await guestRead(hs, p, 10)).toEqual({ kind: "file", data: new Uint8Array(), size: 0, truncated: false })
})

test("host sh: a write replaces an existing file and leaves no temp file", async () => {
  const p = join(dir, "replace")
  writeFileSync(p, "old old old")
  await guestWrite(hs, p, enc("new"))
  expect(readFileSync(p, "utf8")).toBe("new")
  const listing = await guestRead(hs, dir, 100_000)
  expect(listing.kind === "dir" && listing.entries.some((e) => e.includes(".rts-"))).toBe(false)
})

test("host sh: writing over a directory is refused", async () => {
  const p = join(dir, "isdir")
  mkdirSync(p)
  await expect(guestWrite(hs, p, enc("x"))).rejects.toThrow("is a directory")
})

test("host sh: a read past the cap is truncated with the full size", async () => {
  const p = join(dir, "big")
  writeFileSync(p, "x".repeat(5000))
  const r = await guestRead(hs, p, 1000)
  expect(r.kind).toBe("file")
  if (r.kind !== "file") return
  expect(r.data.length).toBe(1000)
  expect(r.size).toBe(5000)
  expect(r.truncated).toBe(true)
})

test("host sh: a directory lists its entries, dirs with a trailing slash", async () => {
  const d = join(dir, "listing")
  mkdirSync(join(d, "child"), { recursive: true })
  writeFileSync(join(d, ".hidden"), "")
  writeFileSync(join(d, "line\nbreak"), "")
  writeFileSync(join(d, "plain"), "")
  const r = await guestRead(hs, d, 10_000)
  expect(r).toEqual({ kind: "dir", entries: [".hidden", "child/", "line\nbreak", "plain"] })
})

test("host sh: a missing path is missing", async () => {
  expect(await guestRead(hs, join(dir, "nope"), 10)).toEqual({ kind: "missing" })
  await expect(guestSha256(hs, join(dir, "nope"))).rejects.toThrow()
})

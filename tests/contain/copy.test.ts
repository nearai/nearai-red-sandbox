import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { createHash } from "node:crypto"
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { guestSha256, guestWrite } from "../../sandbox/files.ts"
import type { MvmSandbox } from "../../sandbox/mvm.ts"
import { TarRejected } from "../../sandbox/untar.ts"
import { freshMachine, limits, mvmReady } from "./harness.ts"

const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex")
const enc = (s: string) => new TextEncoder().encode(s)

describe.skipIf(!mvmReady)("copyIn and copyOut on real mvm", () => {
  let sb: MvmSandbox | undefined
  let root: string
  let sentinel: string
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "rts-copy-"))
    sentinel = join(root, "sentinel")
    writeFileSync(sentinel, "untouched")
  })
  afterEach(async () => {
    await sb?.remove()
    sb = undefined
    rmSync(root, { recursive: true, force: true })
  })

  test("copyIn delivers a nested tree with a 300 KiB file", async () => {
    sb = await freshMachine()
    const src = join(root, "inputs")
    mkdirSync(join(src, "a/b"), { recursive: true })
    const big = crypto.getRandomValues(new Uint8Array(300 * 1024))
    writeFileSync(join(src, "a/b/big.bin"), big)
    writeFileSync(join(src, "note.txt"), "note")
    await sb.copyIn(src, "/in")
    expect(await guestSha256(sb, "/in/a/b/big.bin")).toBe(sha(big))
    expect(await guestSha256(sb, "/in/note.txt")).toBe(sha(enc("note")))
  }, 180_000)

  test("copyOut brings guest /out back byte-exact", async () => {
    sb = await freshMachine()
    const blob = crypto.getRandomValues(new Uint8Array(700 * 1024)) // two read slices
    await guestWrite(sb, "/out/sub/blob", blob)
    await guestWrite(sb, "/out/hello.txt", enc("hi"))
    const dest = join(root, "out")
    expect(await sb.copyOut("/out", dest)).toEqual({ status: "exported", files: 2, bytes: blob.length + 2 })
    expect(new Uint8Array(readFileSync(join(dest, "sub/blob")))).toEqual(blob)
    expect(readFileSync(join(dest, "hello.txt"), "utf8")).toBe("hi")
  }, 180_000)

  test("a missing or empty /out is nothing to export", async () => {
    sb = await freshMachine()
    await sb.exec(["rm", "-rf", "/out"], limits)
    expect(await sb.copyOut("/out", join(root, "o1"))).toEqual({ status: "nothing to export" })
    await sb.exec(["mkdir", "-p", "/out"], limits)
    expect(await sb.copyOut("/out", join(root, "o2"))).toEqual({ status: "nothing to export" })
  }, 180_000)

  const hostile: [string, (s: string) => string[], string][] = [
    ["a symlink to the host sentinel", (s) => ["ln", "-s", s, "/out/evil"], "unsupported tar entry type 2"],
    ["a hardlink", () => ["sh", "-c", "echo a > /out/a && ln /out/a /out/b"], "unsupported tar entry type 1"],
    ["a 120-byte file name", () => ["sh", "-c", `echo x > /out/${"n".repeat(120)}`], "unsupported tar entry type L"],
    ["a file over the size cap", () => ["head", "-c", String(300 * 1024 * 1024), "/dev/zero"], "size cap"],
  ]
  for (const [what, cmd, reason] of hostile) {
    test(`hostile /out: ${what} is refused and nothing reaches the host`, async () => {
      sb = await freshMachine()
      await sb.exec(["mkdir", "-p", "/out"], limits)
      const argv = cmd(sentinel)
      if (argv[0] === "head") await sb.exec(["sh", "-c", 'head -c "$1" /dev/zero > /out/huge', "rts", argv[2]!], { ...limits, timeoutMs: 300_000 })
      else await sb.exec(argv, limits)
      const dest = join(root, "out")
      const p = sb.copyOut("/out", dest)
      await expect(p).rejects.toBeInstanceOf(TarRejected)
      await expect(sb.copyOut("/out", dest)).rejects.toThrow(reason)
      expect(existsSync(dest)).toBe(false)
      expect(readFileSync(sentinel, "utf8")).toBe("untouched")
    }, 600_000)
  }
})

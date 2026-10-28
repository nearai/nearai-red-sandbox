import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { createHash } from "node:crypto"
import { guestRead, guestSha256, guestWrite } from "../../sandbox/files.ts"
import type { MvmSandbox } from "../../sandbox/mvm.ts"
import { freshMachine, limits, mvmReady } from "./harness.ts"

const enc = (s: string) => new TextEncoder().encode(s)
const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex")

describe.skipIf(!mvmReady)("guest file primitives on real mvm", () => {
  let sb: MvmSandbox
  beforeAll(async () => {
    sb = await freshMachine()
  }, 120_000)
  afterAll(async () => {
    await sb?.remove()
  }, 120_000)

  test("a 200 KiB random write matches its sha256 in the guest", async () => {
    const data = crypto.getRandomValues(new Uint8Array(200 * 1024))
    await guestWrite(sb, "/tmp/rand.bin", data)
    expect(await guestSha256(sb, "/tmp/rand.bin")).toBe(sha(data))
  }, 120_000)

  test("awkward paths round-trip through write, read and sha256", async () => {
    for (const p of ["/tmp/a b", "/tmp/-x", `/tmp/q'"q`, "/tmp/ünï", "/tmp/new\nline"]) {
      const body = enc(`content of ${p}`)
      await guestWrite(sb, p, body)
      expect(await guestRead(sb, p, limits.maxOutputBytes)).toEqual({ kind: "file", data: body, size: body.length, truncated: false })
      expect(await guestSha256(sb, p)).toBe(sha(body))
    }
  }, 120_000)

  test("reading a directory lists its entries", async () => {
    await guestWrite(sb, "/tmp/listing/one", enc("1"))
    await guestWrite(sb, "/tmp/listing/sub/two", enc("2"))
    expect(await guestRead(sb, "/tmp/listing", limits.maxOutputBytes)).toEqual({ kind: "dir", entries: ["one", "sub/"] })
  }, 120_000)

  test("reading a missing path returns missing", async () => {
    expect(await guestRead(sb, "/tmp/definitely-missing", 100)).toEqual({ kind: "missing" })
  }, 120_000)
})

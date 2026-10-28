// copyIn / copyOut scripts run by the host's sh and tar against temp
// directories standing in for the guest. GNU tar here, like busybox tar,
// writes GNU long-name headers, so the hostile cases match the guest's.

import { afterEach, beforeEach, expect, test } from "bun:test"
import { existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { copyInVia, copyOutVia } from "../../sandbox/copy.ts"
import { TarRejected } from "../../sandbox/untar.ts"
import { HostShellSandbox } from "./hostsh.ts"

let root: string
let guest: string
let host: string
let sentinel: string
const hs = new HostShellSandbox()
const small = { maxBytes: 1024 * 1024, maxEntries: 100, chunkBytes: 4096 }

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "rts-copy-"))
  guest = join(root, "guest-out")
  host = join(root, "host", "out")
  sentinel = join(root, "sentinel")
  writeFileSync(sentinel, "untouched")
})
afterEach(() => rmSync(root, { recursive: true, force: true }))

test("copyIn moves a nested host tree into the guest directory", async () => {
  const src = join(root, "inputs")
  mkdirSync(join(src, "a/b"), { recursive: true })
  const big = crypto.getRandomValues(new Uint8Array(300 * 1024))
  writeFileSync(join(src, "a/b/big.bin"), big)
  writeFileSync(join(src, "top.txt"), "top")
  const dest = join(root, "guest-in")
  await copyInVia(hs, src, dest)
  expect(new Uint8Array(readFileSync(join(dest, "a/b/big.bin")))).toEqual(big)
  expect(readFileSync(join(dest, "top.txt"), "utf8")).toBe("top")
})

test("copyOut brings guest files back byte-exact across several slices", async () => {
  mkdirSync(join(guest, "sub"), { recursive: true })
  const blob = crypto.getRandomValues(new Uint8Array(50_000))
  writeFileSync(join(guest, "sub/blob"), blob)
  writeFileSync(join(guest, "hello.txt"), "hi")
  const r = await copyOutVia(hs, guest, host, small)
  expect(r).toEqual({ status: "exported", files: 2, bytes: 50_002 })
  expect(new Uint8Array(readFileSync(join(host, "sub/blob")))).toEqual(blob)
  expect(readFileSync(join(host, "hello.txt"), "utf8")).toBe("hi")
})

test("copyOut of a missing or empty directory is nothing to export", async () => {
  expect(await copyOutVia(hs, guest, host, small)).toEqual({ status: "nothing to export" })
  mkdirSync(guest)
  expect(await copyOutVia(hs, guest, host, small)).toEqual({ status: "nothing to export" })
  expect(existsSync(host)).toBe(false)
})

async function expectHostileRefused(reason: string | RegExp, limits = small) {
  await expect(copyOutVia(hs, guest, host, limits)).rejects.toBeInstanceOf(TarRejected)
  await expect(copyOutVia(hs, guest, host, limits)).rejects.toThrow(reason)
  expect(existsSync(host)).toBe(false)
  expect(readFileSync(sentinel, "utf8")).toBe("untouched")
}

test("a symlink to a host path in /out is refused", async () => {
  mkdirSync(guest)
  symlinkSync(sentinel, join(guest, "evil"))
  await expectHostileRefused("unsupported tar entry type 2")
})

test("a hardlink in /out is refused", async () => {
  mkdirSync(guest)
  writeFileSync(join(guest, "a"), "a")
  linkSync(join(guest, "a"), join(guest, "b"))
  await expectHostileRefused("unsupported tar entry type 1")
})

test("a 120-byte name in /out is refused as a GNU long name", async () => {
  mkdirSync(guest)
  writeFileSync(join(guest, "n".repeat(120)), "x")
  await expectHostileRefused("unsupported tar entry type L")
})

test("a file over the size cap is refused", async () => {
  mkdirSync(guest)
  writeFileSync(join(guest, "huge"), new Uint8Array(200_000))
  await expectHostileRefused("size cap", { ...small, maxBytes: 100_000 })
})

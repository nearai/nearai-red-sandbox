import { afterEach, beforeEach, expect, test } from "bun:test"
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { TarRejected, extractTar } from "../../sandbox/untar.ts"
import { tar } from "./tarfixture.ts"

const limits = { maxBytes: 1024 * 1024, maxEntries: 100 }
let root: string
let dest: string
let sentinel: string

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "rts-untar-"))
  dest = join(root, "out")
  sentinel = join(root, "sentinel")
  writeFileSync(sentinel, "untouched")
})
afterEach(() => rmSync(root, { recursive: true, force: true }))

async function expectRejected(archive: Uint8Array, reason: string | RegExp, lim = limits) {
  const p = extractTar(archive, dest, lim)
  await expect(p).rejects.toBeInstanceOf(TarRejected)
  await expect(extractTar(archive, dest, lim)).rejects.toThrow(reason)
  expect(existsSync(dest)).toBe(false)
  expect(existsSync(dest + ".partial")).toBe(false)
  expect(readFileSync(sentinel, "utf8")).toBe("untouched")
  expect(readdirSync(root).sort()).toEqual(["sentinel"])
}

test("a directory and two regular files extract byte-exact", async () => {
  const bin = crypto.getRandomValues(new Uint8Array(3000))
  const r = await extractTar(
    tar([{ name: "./", type: "5" }, { name: "./d/", type: "5" }, { name: "./d/a.txt", data: "hello\n" }, { name: "./b.bin", data: bin }]),
    dest,
    limits,
  )
  expect(r).toEqual({ files: 2, bytes: 3006 })
  expect(readFileSync(join(dest, "d/a.txt"), "utf8")).toBe("hello\n")
  expect(new Uint8Array(readFileSync(join(dest, "b.bin")))).toEqual(bin)
})

test("a file whose parent directory has no entry of its own still extracts", async () => {
  await extractTar(tar([{ name: "x/y/z.txt", data: "z" }]), dest, limits)
  expect(readFileSync(join(dest, "x/y/z.txt"), "utf8")).toBe("z")
})

test("the ustar prefix field is joined to the name", async () => {
  await extractTar(tar([{ name: "leaf.txt", prefix: "deep/dir", data: "p" }]), dest, limits)
  expect(readFileSync(join(dest, "deep/dir/leaf.txt"), "utf8")).toBe("p")
})

test("an empty archive extracts to an empty directory", async () => {
  expect(await extractTar(tar([]), dest, limits)).toEqual({ files: 0, bytes: 0 })
  expect(readdirSync(dest)).toEqual([])
})

test("an archive made by the host tar round-trips", async () => {
  const src = join(root, "src")
  mkdirSync(join(src, "n/m"), { recursive: true })
  writeFileSync(join(src, "n/m/f.txt"), "from host tar")
  writeFileSync(join(src, "top"), "t")
  const p = Bun.spawn(["tar", "--format=ustar", "-cf", "-", "-C", src, "."], { stdout: "pipe", env: { ...process.env, COPYFILE_DISABLE: "1" } })
  const archive = await new Response(p.stdout).bytes()
  expect(await p.exited).toBe(0)
  rmSync(src, { recursive: true })
  await extractTar(archive, dest, limits)
  expect(readFileSync(join(dest, "n/m/f.txt"), "utf8")).toBe("from host tar")
  expect(readFileSync(join(dest, "top"), "utf8")).toBe("t")
})

test("a symlink is refused", () => expectRejected(tar([{ name: "link", type: "2", linkname: sentinel }]), "unsupported tar entry type 2"))
test("a symlink to /etc/passwd is refused", () => expectRejected(tar([{ name: "passwd", type: "2", linkname: "/etc/passwd" }]), "unsupported tar entry type 2"))
test("a hardlink is refused", () => expectRejected(tar([{ name: "a", data: "a" }, { name: "h", type: "1", linkname: "a" }]), "unsupported tar entry type 1"))
test("a character device is refused", () => expectRejected(tar([{ name: "null", type: "3" }]), "unsupported tar entry type 3"))
test("a block device is refused", () => expectRejected(tar([{ name: "disk", type: "4" }]), "unsupported tar entry type 4"))
test("a fifo is refused", () => expectRejected(tar([{ name: "fifo", type: "6" }]), "unsupported tar entry type 6"))
test("a GNU long-name entry is refused", () =>
  expectRejected(tar([{ name: "././@LongLink", type: "L", gnu: true, data: "x".repeat(120) + "\0" }, { name: "x".repeat(99), gnu: true, data: "v" }]), "unsupported tar entry type L"))
test("a pax header is refused", () => expectRejected(tar([{ name: "PaxHeader/f", type: "x", data: "30 path=../../etc/passwd\n" }, { name: "f", data: "v" }]), "unsupported tar entry type x"))
test("a pax global header is refused", () => expectRejected(tar([{ name: "pax_global_header", type: "g", data: "9 a=b\n" }]), "unsupported tar entry type g"))
test("a .. entry is refused", () => expectRejected(tar([{ name: "../escape", data: "e" }]), "path escapes"))
test("a .. in the middle is refused", () => expectRejected(tar([{ name: "a/../../escape", data: "e" }]), "path escapes"))
test("a .. hidden in the prefix is refused", () => expectRejected(tar([{ name: "escape", prefix: "..", data: "e" }]), "path escapes"))
test("an absolute path is refused", () => expectRejected(tar([{ name: "/abs", data: "e" }]), "absolute path"))
test("a NUL inside the name field is refused", () => {
  const raw = new TextEncoder().encode("ok\0../../evil")
  return expectRejected(tar([{ name: "", rawName: raw, data: "e" }]), "NUL in name")
})
test("total size over the cap is refused", () =>
  expectRejected(tar([{ name: "a", data: "x".repeat(600) }, { name: "b", data: "x".repeat(600) }]), "size cap", { maxBytes: 1000, maxEntries: 100 }))
test("a lying size field past the end of the archive is refused", () => expectRejected(tar([{ name: "a", data: "x", size: 99999 }], { noEnd: true }), /truncated|size cap/))
test("more entries than the cap is refused", () =>
  expectRejected(tar(Array.from({ length: 6 }, (_, i) => ({ name: `f${i}`, data: "x" }))), "entry cap", { maxBytes: 1000, maxEntries: 5 }))
test("a bad header checksum is refused", () => expectRejected(tar([{ name: "a", data: "x", badChecksum: true }]), "bad header checksum"))
test("a duplicate file entry is refused rather than overwritten", () => expectRejected(tar([{ name: "a", data: "1" }, { name: "./a", data: "2" }]), "a"))
test("a file entry at the archive root is refused", () => expectRejected(tar([{ name: "./", data: "x" }]), "empty path"))
test("an archive cut off mid-header is refused", () => expectRejected(tar([{ name: "a", data: "x" }]).subarray(0, 700), "truncated"))

test("an existing destination is refused and left alone", async () => {
  mkdirSync(dest)
  writeFileSync(join(dest, "keep"), "k")
  await expect(extractTar(tar([{ name: "a", data: "x" }]), dest, limits)).rejects.toThrow("destination exists")
  expect(readFileSync(join(dest, "keep"), "utf8")).toBe("k")
})

test("a rejection late in the archive leaves nothing behind", () =>
  expectRejected(tar([{ name: "ok1", data: "1" }, { name: "dir/", type: "5" }, { name: "dir/ok2", data: "2" }, { name: "bad", type: "2", linkname: "/" }]), "unsupported tar entry type 2"))

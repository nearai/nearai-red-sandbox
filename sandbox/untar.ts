// Host-side tar extractor for archives built by a hostile guest.
//
// Accepts only regular files and directories. Refuses links, devices,
// GNU and pax extension headers, absolute paths, `..`, NUL bytes in names,
// bad checksums, and archives over the size or entry caps. The whole
// archive is validated before anything is written; extraction goes to
// `<destDir>.partial` and is renamed into place only on success.

import { mkdir, open, rename, rm, stat } from "node:fs/promises"
import { dirname, join } from "node:path"

export class TarRejected extends Error {
  constructor(
    readonly entry: string,
    readonly reason: string,
  ) {
    super(`tar entry ${JSON.stringify(entry)} rejected: ${reason}`)
    this.name = "TarRejected"
  }
}

type Planned = { kind: "file" | "dir"; segments: string[]; display: string; dataOffset: number; size: number }

const BLOCK = 512
const ascii = (b: Uint8Array) => new TextDecoder("latin1").decode(b)
const utf8 = (b: Uint8Array) => new TextDecoder().decode(b)

function field(h: Uint8Array, off: number, len: number, entry: string, what: string): Uint8Array {
  const f = h.subarray(off, off + len)
  const nul = f.indexOf(0)
  if (nul === -1) return f
  for (let i = nul; i < f.length; i++) if (f[i] !== 0) throw new TarRejected(entry, `NUL in ${what}`)
  return f.subarray(0, nul)
}

function octal(h: Uint8Array, off: number, len: number, entry: string, what: string): number {
  if (h[off]! & 0x80) throw new TarRejected(entry, `unsupported ${what} encoding`)
  const s = ascii(h.subarray(off, off + len)).replace(/[\0 ]+$/, "").replace(/^ +/, "")
  if (!/^[0-7]*$/.test(s)) throw new TarRejected(entry, `bad ${what} field`)
  return s === "" ? 0 : parseInt(s, 8)
}

function checksumOk(h: Uint8Array, entry: string): boolean {
  const stored = octal(h, 148, 8, entry, "checksum")
  let sum = 0
  for (let i = 0; i < BLOCK; i++) sum += i >= 148 && i < 156 ? 0x20 : h[i]!
  return sum === stored
}

function isZero(b: Uint8Array): boolean {
  for (const x of b) if (x !== 0) return false
  return true
}

function normalize(raw: string, entry: string): string[] {
  if (raw.startsWith("/")) throw new TarRejected(entry, "absolute path")
  const segments = raw.split("/").filter((s) => s !== "" && s !== ".")
  if (segments.includes("..")) throw new TarRejected(entry, "path escapes the destination (..)")
  return segments
}

function plan(archive: Uint8Array, limits: { maxBytes: number; maxEntries: number }): Planned[] {
  const out: Planned[] = []
  let total = 0
  let off = 0
  for (;;) {
    if (off + BLOCK > archive.length) {
      // A clean end is one or two zero blocks; running off the end without one is truncation.
      throw new TarRejected(`@${off}`, "truncated archive (no end-of-archive marker)")
    }
    const h = archive.subarray(off, off + BLOCK)
    if (isZero(h)) break
    const nameBytes = field(h, 0, 100, `@${off}`, "name")
    let entry = utf8(nameBytes)
    const magic = ascii(h.subarray(257, 263))
    if (magic === "ustar\0") {
      const prefix = utf8(field(h, 345, 155, entry, "name"))
      if (prefix) entry = `${prefix}/${entry}`
    }
    if (!checksumOk(h, entry)) throw new TarRejected(entry, "bad header checksum")
    const type = String.fromCharCode(h[156]!)
    if (type !== "0" && type !== "\0" && type !== "5") {
      throw new TarRejected(entry, `unsupported tar entry type ${type === "\0" ? "NUL" : type}`)
    }
    const size = octal(h, 124, 12, entry, "size")
    if (out.length + 1 > limits.maxEntries) throw new TarRejected(entry, `entry cap of ${limits.maxEntries} exceeded`)
    const segments = normalize(entry, entry)
    const kind = type === "5" ? "dir" : "file"
    if (kind === "file" && segments.length === 0) throw new TarRejected(entry, "empty path for a file")
    if (kind === "dir" && size !== 0) throw new TarRejected(entry, "directory with data")
    total += size
    if (total > limits.maxBytes) throw new TarRejected(entry, `size cap of ${limits.maxBytes} bytes exceeded`)
    const dataOffset = off + BLOCK
    const padded = Math.ceil(size / BLOCK) * BLOCK
    if (dataOffset + padded > archive.length) throw new TarRejected(entry, "truncated archive (data runs past the end)")
    out.push({ kind, segments, display: entry, dataOffset, size })
    off = dataOffset + padded
  }
  return out
}

async function exists(p: string): Promise<boolean> {
  try {
    await stat(p)
    return true
  } catch {
    return false
  }
}

export async function extractTar(
  archive: Uint8Array,
  destDir: string,
  limits: { maxBytes: number; maxEntries: number },
): Promise<{ files: number; bytes: number }> {
  if (await exists(destDir)) throw new TarRejected(destDir, "destination exists")
  const entries = plan(archive, limits)
  const partial = `${destDir}.partial`
  await rm(partial, { recursive: true, force: true })
  await mkdir(dirname(destDir), { recursive: true })
  await mkdir(partial, { mode: 0o755 })
  let files = 0
  let bytes = 0
  try {
    for (const e of entries) {
      const target = join(partial, ...e.segments)
      try {
        if (e.kind === "dir") {
          await mkdir(target, { recursive: true, mode: 0o755 })
          continue
        }
        await mkdir(dirname(target), { recursive: true, mode: 0o755 })
        // "wx" is O_CREAT|O_EXCL: an existing path is never opened or followed.
        const fh = await open(target, "wx", 0o644)
        try {
          await fh.writeFile(archive.subarray(e.dataOffset, e.dataOffset + e.size))
        } finally {
          await fh.close()
        }
        files++
        bytes += e.size
      } catch (err) {
        throw new TarRejected(e.display, `cannot create: ${(err as NodeJS.ErrnoException).code ?? (err as Error).message}`)
      }
    }
    await rename(partial, destDir)
  } catch (err) {
    await rm(partial, { recursive: true, force: true })
    throw err
  }
  return { files, bytes }
}

// Hand-built tar archives, so tests can produce entry types a real tar
// would never emit from a benign tree.

type Entry = {
  name: string
  type?: string // typeflag character; default "0"
  data?: Uint8Array | string
  size?: number // override the header size field
  linkname?: string
  prefix?: string
  gnu?: boolean // GNU magic ("ustar  \0") instead of POSIX ("ustar\0" "00")
  badChecksum?: boolean
  rawName?: Uint8Array // exact bytes for the name field
}

const enc = (s: string) => new TextEncoder().encode(s)

function octal(n: number, width: number): string {
  return n.toString(8).padStart(width - 1, "0") + "\0"
}

export function header(e: Entry): Uint8Array {
  const h = new Uint8Array(512)
  const put = (off: number, bytes: Uint8Array, max: number) => h.set(bytes.subarray(0, max), off)
  const data = typeof e.data === "string" ? enc(e.data) : (e.data ?? new Uint8Array())
  put(0, e.rawName ?? enc(e.name), 100)
  put(100, enc(octal(e.type === "5" ? 0o755 : 0o644, 8)), 8)
  put(108, enc(octal(0, 8)), 8)
  put(116, enc(octal(0, 8)), 8)
  put(124, enc(octal(e.size ?? data.length, 12)), 12)
  put(136, enc(octal(0, 12)), 12)
  h.fill(0x20, 148, 156)
  h[156] = (e.type ?? "0").charCodeAt(0)
  if (e.linkname) put(157, enc(e.linkname), 100)
  if (e.gnu) put(257, enc("ustar  \0"), 8)
  else {
    put(257, enc("ustar\0"), 6)
    put(263, enc("00"), 2)
  }
  if (e.prefix) put(345, enc(e.prefix), 155)
  let sum = 0
  for (const b of h) sum += b
  if (e.badChecksum) sum += 1
  put(148, enc(sum.toString(8).padStart(6, "0") + "\0 "), 8)
  return h
}

export function tar(entries: Entry[], opts: { noEnd?: boolean } = {}): Uint8Array {
  const parts: Uint8Array[] = []
  for (const e of entries) {
    parts.push(header(e))
    const data = typeof e.data === "string" ? enc(e.data) : (e.data ?? new Uint8Array())
    if (data.length) {
      const padded = new Uint8Array(Math.ceil(data.length / 512) * 512)
      padded.set(data)
      parts.push(padded)
    }
  }
  if (!opts.noEnd) parts.push(new Uint8Array(1024))
  const total = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(total)
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}

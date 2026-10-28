// copyIn and copyOut, built on Sandbox.exec so any backend can reuse them.
//
// copyIn trusts the host and its inputs. copyOut trusts nothing the guest
// says: sizes and hashes only check the transport, and the archive goes
// through the hostile-tar extractor before anything lands on the host.

import { createHash } from "node:crypto"
import { DEFAULTS } from "./defaults.ts"
import { guestWrite } from "./files.ts"
import { newNonce } from "./protocol.ts"
import type { CopyOutResult, Sandbox } from "./sandbox.ts"
import { TarRejected, extractTar } from "./untar.ts"

type Exec = Pick<Sandbox, "exec">

export type CopyLimits = { maxBytes: number; maxEntries: number; chunkBytes: number }
export const DEFAULT_COPY_LIMITS: CopyLimits = {
  maxBytes: DEFAULTS.extractMaxBytes,
  maxEntries: DEFAULTS.extractMaxEntries,
  chunkBytes: DEFAULTS.copyOutChunkBytes,
}

const LONG = { timeoutMs: 300_000, maxOutputBytes: 16_384 }
const decode = (b: Uint8Array) => new TextDecoder().decode(b)

const UNPACK = 'mkdir -p -- "$1" && tar -xf "$2" -C "$1"; s=$?; rm -f -- "$2"; exit $s'

const PACK = [
  'd=$1; t=$2',
  'if [ ! -d "$d" ]; then echo NONE; exit 0; fi',
  'if [ -z "$(ls -A -- "$d")" ]; then echo NONE; exit 0; fi',
  'rm -f -- "$t"',
  'tar -cf "$t" -C "$d" . || exit 3',
  "printf 'TAR %s %s\\n' \"$(wc -c < \"$t\")\" \"$(sha256sum < \"$t\" | cut -d ' ' -f 1)\"",
].join("\n")

const SLICE = 'dd if="$1" bs="$2" skip="$3" count=1 2>/dev/null | base64'
const CLEAN = 'rm -f -- "$1"'

export async function copyInVia(sb: Exec, hostDir: string, guestDir: string): Promise<void> {
  // ustar keeps the archive readable by busybox tar (no pax or xattr headers).
  const p = Bun.spawn(["tar", "--format=ustar", "-cf", "-", "-C", hostDir, "."], {
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, COPYFILE_DISABLE: "1" },
  })
  const [archive, err, code] = await Promise.all([new Response(p.stdout).bytes(), new Response(p.stderr).text(), p.exited])
  if (code !== 0) throw new Error(`copyIn: host tar failed: ${err.trim()}`)
  const tmp = `/tmp/rts-in-${newNonce()}.tar`
  await guestWrite(sb, tmp, archive)
  const r = await sb.exec(["sh", "-c", UNPACK, "rts", guestDir, tmp], LONG)
  if (r.exitCode !== 0) throw new Error(`copyIn: guest tar failed: ${decode(r.stderr).trim() || `exit ${r.exitCode}`}`)
}

export async function copyOutVia(sb: Exec, guestDir: string, hostDir: string, limits: CopyLimits = DEFAULT_COPY_LIMITS): Promise<CopyOutResult> {
  const tmp = `/tmp/rts-out-${newNonce()}.tar`
  try {
    const packed = await sb.exec(["sh", "-c", PACK, "rts", guestDir, tmp], LONG)
    if (packed.exitCode !== 0) throw new Error(`copyOut: guest tar failed: ${decode(packed.stderr).trim() || `exit ${packed.exitCode}`}`)
    const reply = decode(packed.stdout).trim()
    if (reply === "NONE") return { status: "nothing to export" }
    const m = /^TAR\s+(\d{1,16})\s+([0-9a-f]{64})$/.exec(reply)
    if (!m) throw new Error("copyOut: malformed reply from guest")
    const size = Number(m[1])
    const digest = m[2]!
    // Headers and padding on top of the content cap.
    const overhead = 512 * (2 * limits.maxEntries + 2) + 20_480
    if (size > limits.maxBytes + overhead) throw new TarRejected("(archive)", `size cap of ${limits.maxBytes} bytes exceeded`)

    const archive = new Uint8Array(size)
    const chunks = Math.ceil(size / limits.chunkBytes)
    // base64 grows 4/3, plus a newline every 76 characters.
    const cap = Math.ceil((limits.chunkBytes * 4) / 3) + Math.ceil(limits.chunkBytes / 57) + 64
    for (let i = 0; i < chunks; i++) {
      const r = await sb.exec(["sh", "-c", SLICE, "rts", tmp, String(limits.chunkBytes), String(i)], { timeoutMs: LONG.timeoutMs, maxOutputBytes: cap })
      if (r.exitCode !== 0 || r.truncated) throw new Error(`copyOut: reading slice ${i} failed`)
      const bytes = Buffer.from(decode(r.stdout).replace(/\s+/g, ""), "base64")
      const off = i * limits.chunkBytes
      const want = Math.min(limits.chunkBytes, size - off)
      if (bytes.length !== want) throw new Error(`copyOut: slice ${i} is ${bytes.length} bytes, expected ${want}`)
      archive.set(bytes, off)
    }
    const got = createHash("sha256").update(archive).digest("hex")
    if (got !== digest) throw new Error("copyOut: archive sha256 does not match what the guest reported")
    const { files, bytes } = await extractTar(archive, hostDir, { maxBytes: limits.maxBytes, maxEntries: limits.maxEntries })
    return { status: "exported", files, bytes }
  } finally {
    await sb.exec(["sh", "-c", CLEAN, "rts", tmp], { timeoutMs: 60_000, maxOutputBytes: 1024 }).catch(() => undefined)
  }
}

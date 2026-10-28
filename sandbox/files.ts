// File primitives on guest paths, built only on Sandbox.exec.
//
// Every guest script is fixed text that reads its operands from "$1",
// "$2", ... so no path or content is ever parsed by a shell. Content
// travels as base64 argv chunks, because mvm's exec does not pass stdin.

import { posix } from "node:path"
import { DEFAULTS } from "./defaults.ts"
import { newNonce } from "./protocol.ts"
import type { ExecResult, Sandbox } from "./sandbox.ts"

type Exec = Pick<Sandbox, "exec">

const CONTROL = { timeoutMs: 60_000, maxOutputBytes: 4096 }
const decode = (b: Uint8Array) => new TextDecoder().decode(b)

const W_FIRST = 'mkdir -p -- "$1" && printf %s "$3" | base64 -d > "$2"'
const W_APPEND = 'printf %s "$2" | base64 -d >> "$1"'
const W_FINISH = 'if [ -d "$2" ]; then rm -f -- "$1"; echo "is a directory: $2" >&2; exit 1; fi; mv -f -- "$1" "$2"'
const W_CLEANUP = 'rm -f -- "$1"'

const READ = [
  'p=$1',
  'if [ -d "$p" ]; then',
  "  printf 'D\\n'",
  '  for f in "$p"/* "$p"/.*; do',
  '    [ -e "$f" ] || [ -L "$f" ] || continue',
  '    b=${f##*/}',
  '    case $b in .|..) continue;; esac',
  "    if [ -d \"$f\" ]; then printf '%s/\\0' \"$b\"; else printf '%s\\0' \"$b\"; fi",
  "  done",
  'elif [ -f "$p" ]; then',
  "  printf 'F %s\\n' \"$(wc -c < \"$p\")\"",
  '  head -c "$2" < "$p"',
  'elif [ -e "$p" ] || [ -L "$p" ]; then',
  "  printf 'X\\n'",
  "else",
  "  printf 'M\\n'",
  "fi",
].join("\n")

const SHA = 'if [ ! -f "$1" ]; then echo "not a regular file: $1" >&2; exit 2; fi; sha256sum < "$1"'

function fail(what: string, path: string, r: ExecResult): Error {
  const err = decode(r.stderr).trim()
  return new Error(`${what} ${path}: ${err || `exit status ${r.exitCode}`}`)
}

function toBase64(data: Uint8Array): string {
  return Buffer.from(data.buffer, data.byteOffset, data.byteLength).toString("base64")
}

export async function guestWrite(sb: Exec, path: string, data: Uint8Array): Promise<void> {
  const b64 = toBase64(data)
  const size = DEFAULTS.argvChunkChars // a multiple of 4, so each chunk decodes on its own
  const chunks: string[] = []
  for (let i = 0; i < b64.length; i += size) chunks.push(b64.slice(i, i + size))
  if (chunks.length === 0) chunks.push("")
  const tmp = `${path}.rts-${newNonce()}.tmp`
  try {
    let r = await sb.exec(["sh", "-c", W_FIRST, "rts", posix.dirname(path), tmp, chunks[0]!], CONTROL)
    if (r.exitCode !== 0) throw fail("write", path, r)
    for (const chunk of chunks.slice(1)) {
      r = await sb.exec(["sh", "-c", W_APPEND, "rts", tmp, chunk], CONTROL)
      if (r.exitCode !== 0) throw fail("write", path, r)
    }
    r = await sb.exec(["sh", "-c", W_FINISH, "rts", tmp, path], CONTROL)
    if (r.exitCode !== 0) throw fail("write", path, r)
  } catch (e) {
    await sb.exec(["sh", "-c", W_CLEANUP, "rts", tmp], CONTROL).catch(() => undefined)
    throw e
  }
}

export type GuestReadResult =
  | { kind: "file"; data: Uint8Array; size: number; truncated: boolean }
  | { kind: "dir"; entries: string[]; truncated?: boolean }
  | { kind: "missing" }

export async function guestRead(sb: Exec, path: string, maxBytes: number): Promise<GuestReadResult> {
  const r = await sb.exec(["sh", "-c", READ, "rts", path, String(maxBytes)], {
    timeoutMs: CONTROL.timeoutMs,
    maxOutputBytes: maxBytes + 64,
  })
  if (r.exitCode !== 0) throw fail("read", path, r)
  const nl = r.stdout.indexOf(0x0a)
  if (nl === -1) throw new Error(`read ${path}: malformed guest reply`)
  const head = decode(r.stdout.subarray(0, nl))
  const body = r.stdout.subarray(nl + 1)
  if (head === "M") return { kind: "missing" }
  if (head === "X") throw new Error(`read ${path}: not a regular file or directory`)
  if (head === "D") {
    const parts = decode(body).split("\0")
    // The last part is "" after a final NUL, or a cut-off name if the listing was truncated.
    parts.pop()
    const entries = parts.sort()
    return r.truncated ? { kind: "dir", entries, truncated: true } : { kind: "dir", entries }
  }
  const m = /^F\s*(\d+)\s*$/.exec(head)
  if (!m) throw new Error(`read ${path}: malformed guest reply`)
  const size = Number(m[1])
  const data = body.slice(0, maxBytes)
  return { kind: "file", data, size, truncated: size > data.length }
}

export async function guestSha256(sb: Exec, path: string): Promise<string> {
  const r = await sb.exec(["sh", "-c", SHA, "rts", path], CONTROL)
  if (r.exitCode !== 0) throw fail("sha256", path, r)
  const m = /^([0-9a-f]{64})\b/.exec(decode(r.stdout))
  if (!m) throw new Error(`sha256 ${path}: malformed guest reply`)
  return m[1]!
}

// Guest exec wrapper protocol.
//
// mvm v0.22.0 poisons a machine when a guest command exits nonzero or the
// exec client is killed, and silently truncates large stdout. So every
// command runs inside a fixed guest script that always exits 0, enforces
// the time limit in the guest, caps output there, and reports the real
// status and full output sizes in a nonce-tagged trailer on stderr.

const NONCE_RE = /^[0-9a-f]{24}$/

export type ParsedResult = {
  exitCode: number
  timedOut: boolean
  stdout: Uint8Array
  stderr: Uint8Array
  stdoutBytes: number
  stderrBytes: number
  truncated: boolean
}

export function newNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(12))
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")
}

// Fixed text. Operands: $1 nonce, $2 timeout seconds, $3 output cap,
// $4 workdir ("" for none), then the command. The inner `sh -c` drops the
// four wrapper operands so the command runs as "$@" and is never parsed
// by a shell unless it is itself `sh -c ...`.
const WRAPPER = [
  'if [ -n "$4" ]; then',
  '  cd -- "$4" || { printf \'\\nRTS_EXIT_%s 126 0 0\\n\' "$1" >&2; exit 0; }',
  "fi",
  'o="/tmp/rts-$1.out"; e="/tmp/rts-$1.err"',
  'timeout -s KILL "$2" sh -c \'shift 4; exec "$@"\' rts "$@" >"$o" 2>"$e" </dev/null',
  "s=$?",
  'so=$(wc -c <"$o"); se=$(wc -c <"$e")',
  'head -c "$3" "$o"',
  'head -c "$3" "$e" >&2',
  'rm -f -- "$o" "$e"',
  'printf \'\\nRTS_EXIT_%s %s %s %s\\n\' "$1" "$s" $so $se >&2',
  "exit 0",
].join("\n")

export function wrapArgv(
  command: string[],
  o: { nonce: string; timeoutSec: number; maxOutputBytes: number; workdir?: string },
): string[] {
  if (!NONCE_RE.test(o.nonce)) throw new Error("nonce must be 24 lowercase hex chars")
  if (!Number.isInteger(o.timeoutSec) || o.timeoutSec <= 0) throw new Error("timeoutSec must be a positive integer")
  if (!Number.isInteger(o.maxOutputBytes) || o.maxOutputBytes < 0) throw new Error("maxOutputBytes must be a non-negative integer")
  if (command.length === 0) throw new Error("empty command")
  return ["sh", "-c", WRAPPER, "rts", o.nonce, String(o.timeoutSec), String(o.maxOutputBytes), o.workdir ?? "", ...command]
}

const NL = 0x0a

export function parseResult(stdout: Uint8Array, stderr: Uint8Array, nonce: string): ParsedResult | "no-trailer" {
  // The trailer is the last line of stderr, with or without a final newline.
  let end = stderr.length
  if (end > 0 && stderr[end - 1] === NL) end--
  let start = end
  while (start > 0 && stderr[start - 1] !== NL) start--
  const line = new TextDecoder().decode(stderr.subarray(start, end))
  const m = /^RTS_EXIT_([0-9a-f]{24}) (\d{1,10}) (\d{1,16}) (\d{1,16})$/.exec(line)
  if (!m || m[1] !== nonce) return "no-trailer"
  const exitCode = Number(m[2])
  const stdoutBytes = Number(m[3])
  const stderrBytes = Number(m[4])
  // The wrapper puts one newline between the command's stderr and the trailer.
  let bodyEnd = start
  if (bodyEnd > 0 && stderr[bodyEnd - 1] === NL) bodyEnd--
  const err = stderr.slice(0, bodyEnd)
  const out = stdout.slice()
  return {
    exitCode,
    timedOut: exitCode === 137,
    stdout: out,
    stderr: err,
    stdoutBytes,
    stderrBytes,
    truncated: stdoutBytes > out.length || stderrBytes > err.length,
  }
}

export function isPoisoned(stderrText: string): boolean {
  return stderrText.includes("no durable finish")
}

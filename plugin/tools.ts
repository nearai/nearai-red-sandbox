// The six sandboxed tools. Every effect goes through Sandbox.exec; nothing
// here touches the host filesystem or spawns a host process, except the
// explicit leak seam used only by the leak-detection test.

import { posix } from "node:path"
import { guestRead, guestWrite } from "../sandbox/files.ts"
import type { Sandbox } from "../sandbox/sandbox.ts"

export type ToolName = "shell" | "read" | "write" | "edit" | "glob" | "grep"
export const SANDBOXED_TOOLS: readonly ToolName[] = ["shell", "read", "write", "edit", "glob", "grep"]

export type ToolLimits = {
  timeoutMs: number
  maxOutputBytes: number
  // Guest directory that relative paths and shell commands start from.
  cwd?: string
  // TEST ONLY: run `shell` on the host so the leak check can prove the
  // containment suite notices. Never set in a real session.
  leak?: "shell"
}

const READ_LINE_CAP = 2000
const SEARCH_LIMIT = 100
const LISTING_CAP = 512 * 1024 // stays under mvm's silent ~950 KB stdout truncation

const decode = (b: Uint8Array) => new TextDecoder().decode(b)
const enc = (s: string) => new TextEncoder().encode(s)

export function countMatches(text: string, needle: string): number {
  if (needle === "") return 0
  return text.split(needle).length - 1
}

export function applyEdit(text: string, oldString: string, newString: string, replaceAll?: boolean): string {
  const n = countMatches(text, oldString)
  if (n === 0) throw new Error("oldString not found")
  if (n > 1 && !replaceAll) throw new Error(`oldString matches ${n} times; set replaceAll`)
  // split/join, so `$&` and friends in newString are never patterns.
  return replaceAll ? text.split(oldString).join(newString) : text.replace(oldString, () => newString)
}

function joinOutput(parts: string[]): string {
  return parts.filter((p) => p.length > 0).join("\n")
}

function positiveInt(v: unknown, fallback: number): number {
  return typeof v === "number" && Number.isFinite(v) && v >= 1 ? Math.floor(v) : fallback
}

function isHidden(rel: string): boolean {
  return rel.split("/").some((s) => s.startsWith("."))
}

export function makeTools(sb: Sandbox, limits: ToolLimits): Record<ToolName, (input: any) => Promise<string>> {
  const cwd = limits.cwd ?? "/"
  const resolve = (p: unknown): string => {
    if (typeof p !== "string" || p.length === 0) throw new Error("path is required")
    return posix.resolve(cwd, p)
  }
  const opts = { timeoutMs: limits.timeoutMs, maxOutputBytes: limits.maxOutputBytes }

  async function hostShell(command: string): Promise<string> {
    const p = Bun.spawn(["sh", "-c", command], { stdin: "ignore", stdout: "pipe", stderr: "pipe" })
    const [out, err, code] = await Promise.all([new Response(p.stdout).text(), new Response(p.stderr).text(), p.exited])
    return joinOutput([out.trimEnd(), err.trimEnd(), code !== 0 ? `exit status: ${code}` : ""])
  }

  return {
    async shell(input) {
      if (typeof input?.command !== "string") throw new Error("command is required")
      if (input.background === true) throw new Error("background commands are not supported in the sandbox")
      if (limits.leak === "shell") return hostShell(input.command)
      const requested = typeof input.timeout === "number" && input.timeout > 0 ? input.timeout : limits.timeoutMs
      const timeoutMs = Math.min(requested, limits.timeoutMs)
      const workdir = input.workdir === undefined ? cwd : resolve(input.workdir)
      const r = await sb.exec(["sh", "-c", input.command], { ...opts, timeoutMs, workdir })
      const parts = [decode(r.stdout).trimEnd(), decode(r.stderr).trimEnd()]
      if (r.stdoutBytes > r.stdout.length) parts.push(`[output truncated: ${r.stdoutBytes} bytes total]`)
      if (r.stderrBytes > r.stderr.length) parts.push(`[stderr truncated: ${r.stderrBytes} bytes total]`)
      if (r.timedOut) parts.push(`[timed out after ${Math.ceil(timeoutMs / 1000)}s]`)
      else if (r.exitCode !== 0) parts.push(`exit status: ${r.exitCode}`)
      return joinOutput(parts) || "(no output)"
    },

    async read(input) {
      const path = resolve(input?.path)
      const offset = positiveInt(input?.offset, 1)
      const limit = Math.min(positiveInt(input?.limit, READ_LINE_CAP), READ_LINE_CAP)
      const r = await guestRead(sb, path, limits.maxOutputBytes)
      if (r.kind === "missing") throw new Error(`not found: ${path}`)
      if (r.kind === "dir") {
        const shown = r.entries.slice(offset - 1, offset - 1 + limit)
        const notes: string[] = []
        if (offset - 1 + limit < r.entries.length) notes.push(`(${r.entries.length} entries; use offset to see more)`)
        if (r.truncated) notes.push("(listing truncated)")
        return joinOutput([shown.join("\n"), ...notes]) || "(empty directory)"
      }
      // Never throws on bad bytes: invalid UTF-8 becomes U+FFFD.
      const text = new TextDecoder("utf-8", { fatal: false }).decode(r.data)
      if (text.length === 0) return r.truncated ? `[file truncated: 0 of ${r.size} bytes shown]` : "(empty file)"
      const lines = text.split("\n")
      if (lines.at(-1) === "") lines.pop()
      const shown = lines.slice(offset - 1, offset - 1 + limit).map((l, i) => `${offset + i}: ${l}`)
      const notes: string[] = []
      if (offset - 1 + limit < lines.length) notes.push(`(${lines.length} lines; use offset to read more)`)
      if (r.truncated) notes.push(`[file truncated: showing the first ${r.data.length} of ${r.size} bytes]`)
      return joinOutput([shown.join("\n"), ...notes])
    },

    async write(input) {
      const path = resolve(input?.path)
      if (typeof input?.content !== "string") throw new Error("content is required")
      const data = enc(input.content)
      await guestWrite(sb, path, data)
      return `wrote ${data.length} bytes to ${path}`
    },

    async edit(input) {
      const path = resolve(input?.path)
      const { oldString, newString, replaceAll } = input ?? {}
      if (typeof oldString !== "string" || typeof newString !== "string") throw new Error("oldString and newString are required")
      if (oldString === newString) throw new Error("oldString and newString are identical")
      const r = await guestRead(sb, path, limits.maxOutputBytes)
      if (r.kind === "missing") {
        if (oldString !== "") throw new Error(`not found: ${path}`)
        await guestWrite(sb, path, enc(newString))
        return `created ${path}`
      }
      if (r.kind === "dir") throw new Error(`is a directory: ${path}`)
      if (r.truncated) throw new Error(`file larger than ${limits.maxOutputBytes} bytes; edit refused`)
      if (oldString === "") throw new Error("oldString is empty; use write to replace a whole file")
      let text: string
      try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(r.data)
      } catch {
        throw new Error("file is not valid UTF-8; edit refused")
      }
      const n = countMatches(text, oldString)
      const updated = applyEdit(text, oldString, newString, replaceAll === true)
      await guestWrite(sb, path, enc(updated))
      return `edited ${path}: ${replaceAll === true ? n : 1} replacement${(replaceAll === true ? n : 1) === 1 ? "" : "s"}`
    },

    async glob(input) {
      if (typeof input?.pattern !== "string" || input.pattern === "") throw new Error("pattern is required")
      const root = input.path === undefined ? cwd : resolve(input.path)
      const limit = positiveInt(input.limit, SEARCH_LIMIT)
      const script = 'cd -- "$1" || exit 2; find . -xdev -type f -print0 2>/dev/null; exit 0'
      const r = await sb.exec(["sh", "-c", script, "rts", root], { ...opts, maxOutputBytes: LISTING_CAP })
      if (r.exitCode !== 0) throw new Error(`glob ${root}: ${decode(r.stderr).trim() || `exit status ${r.exitCode}`}`)
      const names = decode(r.stdout).split("\0")
      names.pop() // "" after the final NUL, or a cut-off name
      const matcher = new Bun.Glob(input.pattern)
      const matches = names
        .map((n) => (n.startsWith("./") ? n.slice(2) : n))
        .filter((rel) => rel.length > 0 && (input.hidden === true || !isHidden(rel)))
        .filter((rel) => matcher.match(rel))
        .sort()
      if (matches.length === 0) return r.truncated ? "no files found (listing truncated)" : "no files found"
      const shown = matches.slice(0, limit).map((rel) => posix.join(root, rel))
      const notes: string[] = []
      if (matches.length > limit) notes.push(`(results truncated: showing first ${limit} of ${matches.length})`)
      if (r.truncated) notes.push("(file listing truncated; narrow the path)")
      return joinOutput([shown.join("\n"), ...notes])
    },

    async grep(input) {
      if (typeof input?.pattern !== "string" || input.pattern === "") throw new Error("pattern is required")
      const root = input.path === undefined ? cwd : resolve(input.path)
      const limit = positiveInt(input.limit, SEARCH_LIMIT)
      const argv = ["grep", "-rn"]
      if (input.literal === true) argv.push("-F")
      if (input.caseSensitive === false) argv.push("-i")
      if (typeof input.include === "string" && input.include !== "") argv.push(`--include=${input.include}`)
      argv.push("--", input.pattern, root)
      const r = await sb.exec(argv, opts)
      if (r.exitCode === 1) return "no matches"
      const out = decode(r.stdout)
      if (r.exitCode !== 0 && out.length === 0) {
        throw new Error(`grep: ${decode(r.stderr).trim() || `exit status ${r.exitCode}`}`)
      }
      const lines = out.split("\n")
      if (lines.at(-1) === "") lines.pop()
      if (r.truncated && lines.length > 0) lines.pop() // last line may be cut
      const notes: string[] = []
      if (lines.length > limit) notes.push(`(results truncated: showing first ${limit} matches)`)
      else if (r.truncated) notes.push("(output truncated; narrow the search)")
      if (r.exitCode !== 0) notes.push(`(grep reported errors: ${decode(r.stderr).trim().slice(0, 500)})`)
      return joinOutput([lines.slice(0, limit).join("\n"), ...notes]) || "no matches"
    },
  }
}

import { expect, test } from "bun:test"
import { applyEdit, makeTools } from "../../plugin/tools.ts"
import type { ExecOptions, ExecResult, Sandbox } from "../../sandbox/sandbox.ts"

const enc = (s: string) => new TextEncoder().encode(s)
const limits = { timeoutMs: 120_000, maxOutputBytes: 65536 }

type Reply = Partial<Omit<ExecResult, "stdout" | "stderr">> & { stdout?: string | Uint8Array; stderr?: string }

// A fake Sandbox: `reply` decides each exec's result; every call is recorded.
function fakeSandbox(reply: (argv: string[], opts: ExecOptions) => Reply = () => ({})) {
  const execs: { argv: string[]; opts: ExecOptions }[] = []
  const sb: Sandbox = {
    create: async () => {},
    remove: async () => {},
    copyIn: async () => {},
    copyOut: async () => ({ status: "nothing to export" }),
    exec: async (argv, opts) => {
      execs.push({ argv, opts })
      const r = reply(argv, opts)
      const stdout = typeof r.stdout === "string" ? enc(r.stdout) : (r.stdout ?? new Uint8Array())
      const stderr = enc(r.stderr ?? "")
      return { exitCode: 0, timedOut: false, stdoutBytes: stdout.length, stderrBytes: stderr.length, truncated: false, ...r, stdout, stderr }
    },
  }
  return { sb, execs }
}

const isRead = (argv: string[]) => argv[2]!.includes("printf 'D") // the guestRead script
const isWriteStep = (argv: string[]) => argv[2]!.includes("base64 -d") || argv[2]!.includes("mv -f")

// --- shell ---

test("shell runs sh -c in the guest and reports a nonzero exit", async () => {
  const { sb, execs } = fakeSandbox(() => ({ exitCode: 3, stdout: "partial\n" }))
  const out = await makeTools(sb, limits).shell({ command: "make && false" })
  expect(execs[0]!.argv).toEqual(["sh", "-c", "make && false"])
  expect(out).toContain("partial")
  expect(out.endsWith("exit status: 3")).toBe(true)
})

test("shell applies workdir in the guest and resolves it against the guest cwd", async () => {
  const { sb, execs } = fakeSandbox()
  await makeTools(sb, limits).shell({ command: "ls", workdir: "src" })
  expect(execs[0]!.opts.workdir).toBe("/src")
})

test("shell reports a timeout", async () => {
  const { sb } = fakeSandbox(() => ({ exitCode: 137, timedOut: true }))
  const out = await makeTools(sb, limits).shell({ command: "sleep 999" })
  expect(out.endsWith("[timed out after 120s]")).toBe(true)
})

test("shell reports truncation with the full size", async () => {
  const { sb } = fakeSandbox(() => ({ stdout: "x".repeat(10), stdoutBytes: 2097152, truncated: true }))
  const out = await makeTools(sb, limits).shell({ command: "yes" })
  expect(out.endsWith("[output truncated: 2097152 bytes total]")).toBe(true)
})

test("shell timeout: 0 and absent mean the default; larger values are capped", async () => {
  const { sb, execs } = fakeSandbox()
  const t = makeTools(sb, limits)
  await t.shell({ command: "a", timeout: 0 })
  await t.shell({ command: "b" })
  await t.shell({ command: "c", timeout: 5000 })
  await t.shell({ command: "d", timeout: 10_000_000 })
  expect(execs.map((e) => e.opts.timeoutMs)).toEqual([120_000, 120_000, 5000, 120_000])
})

test("shell refuses background commands", async () => {
  const { sb, execs } = fakeSandbox()
  await expect(makeTools(sb, limits).shell({ command: "serve", background: true })).rejects.toThrow("background commands are not supported in the sandbox")
  expect(execs.length).toBe(0)
})

test("shell includes stderr", async () => {
  const { sb } = fakeSandbox(() => ({ stdout: "out\n", stderr: "warn\n" }))
  const out = await makeTools(sb, limits).shell({ command: "x" })
  expect(out).toBe("out\nwarn")
})

// --- read ---

const fileReply = (data: Uint8Array | string, size?: number) => () => {
  const body = typeof data === "string" ? enc(data) : data
  const head = enc(`F ${size ?? body.length}\n`)
  const out = new Uint8Array(head.length + body.length)
  out.set(head)
  out.set(body, head.length)
  return { stdout: out }
}

test("read prefixes lines with 1-based numbers and honours offset and limit", async () => {
  const { sb, execs } = fakeSandbox(fileReply("a\nb\nc\nd\n"))
  const t = makeTools(sb, limits)
  expect(await t.read({ path: "/f" })).toBe("1: a\n2: b\n3: c\n4: d")
  expect(await t.read({ path: "/f", offset: 2, limit: 2 })).toBe("2: b\n3: c\n(4 lines; use offset to read more)")
  expect(execs[0]!.argv.slice(3)).toEqual(["rts", "/f", "65536"])
})

test("read caps limit at 2000 lines", async () => {
  const text = Array.from({ length: 2500 }, (_, i) => `l${i + 1}`).join("\n")
  const { sb } = fakeSandbox(fileReply(text))
  const out = await makeTools(sb, limits).read({ path: "/f", limit: 5000 })
  const lines = out.split("\n").filter((l) => /^\d+: /.test(l))
  expect(lines.length).toBe(2000)
  expect(out).toContain("2000: l2000")
})

test("read lists a directory one entry per line", async () => {
  const { sb } = fakeSandbox(() => ({ stdout: "D\nb.txt\0a/\0" }))
  expect(await makeTools(sb, limits).read({ path: "/d" })).toBe("a/\nb.txt")
})

test("read of a missing path is not found", async () => {
  const { sb } = fakeSandbox(() => ({ stdout: "M\n" }))
  await expect(makeTools(sb, limits).read({ path: "/nope" })).rejects.toThrow("not found: /nope")
})

test("read decodes invalid UTF-8 with replacement characters instead of throwing", async () => {
  const { sb } = fakeSandbox(fileReply(new Uint8Array([0x68, 0x69, 0xff, 0xfe, 0x0a, 0xc3])))
  const out = await makeTools(sb, limits).read({ path: "/bin" })
  expect(out).toBe("1: hi��\n2: �")
})

test("read notes a truncated file", async () => {
  const { sb } = fakeSandbox(fileReply("abc", 999_999))
  const out = await makeTools(sb, limits).read({ path: "/big" })
  expect(out).toContain("1: abc")
  expect(out).toContain("999999")
})

test("read resolves a relative path against the guest cwd", async () => {
  const { sb, execs } = fakeSandbox(() => ({ stdout: "M\n" }))
  await makeTools(sb, { ...limits, cwd: "/in" }).read({ path: "notes.txt" }).catch(() => undefined)
  expect(execs[0]!.argv[4]).toBe("/in/notes.txt")
})

// --- write ---

test("write sends the content to the guest path", async () => {
  const { sb, execs } = fakeSandbox()
  const out = await makeTools(sb, limits).write({ path: "/out/a.txt", content: "héllo" })
  expect(out).toContain("/out/a.txt")
  expect(Buffer.from(execs[0]!.argv.at(-1)!, "base64").toString("utf8")).toBe("héllo")
  expect(execs.at(-1)!.argv.slice(-2)[1]).toBe("/out/a.txt")
})

// --- edit ---

test("applyEdit replaces a single exact match", () => {
  expect(applyEdit("a foo b", "foo", "bar")).toBe("a bar b")
  expect(applyEdit("cost $1", "$1", "$&$2")).toBe("cost $&$2") // no replacement patterns
})

test("applyEdit refuses a missing or ambiguous match, and replaceAll replaces every one", () => {
  expect(() => applyEdit("abc", "x", "y")).toThrow("oldString not found")
  expect(() => applyEdit("x x", "x", "y")).toThrow("oldString matches 2 times; set replaceAll")
  expect(applyEdit("x x x", "x", "y", true)).toBe("y y y")
})

test("edit reads, applies the replacement and writes back", async () => {
  const { sb, execs } = fakeSandbox((argv) => (isRead(argv) ? fileReply("one two\n")() : {}))
  const out = await makeTools(sb, limits).edit({ path: "/w/f", oldString: "two", newString: "2" })
  expect(out).toContain("1 replacement")
  const chunk = execs.find((e) => e.argv[2]!.includes("base64 -d"))!.argv.at(-1)!
  expect(Buffer.from(chunk, "base64").toString()).toBe("one 2\n")
})

test("edit on a truncated read is refused and writes nothing", async () => {
  const { sb, execs } = fakeSandbox((argv) => (isRead(argv) ? fileReply("x".repeat(100), 70_000)() : {}))
  await expect(makeTools(sb, limits).edit({ path: "/big", oldString: "x", newString: "y", replaceAll: true })).rejects.toThrow(
    "file larger than 65536 bytes; edit refused",
  )
  expect(execs.some((e) => isWriteStep(e.argv))).toBe(false)
})

test("edit on a non-UTF-8 file is refused and writes nothing", async () => {
  const { sb, execs } = fakeSandbox((argv) => (isRead(argv) ? fileReply(new Uint8Array([0x61, 0xff]))() : {}))
  await expect(makeTools(sb, limits).edit({ path: "/bin", oldString: "a", newString: "b" })).rejects.toThrow("not valid UTF-8")
  expect(execs.some((e) => isWriteStep(e.argv))).toBe(false)
})

test("edit of a missing file is not found unless oldString is empty", async () => {
  const { sb, execs } = fakeSandbox((argv) => (isRead(argv) ? { stdout: "M\n" } : {}))
  const t = makeTools(sb, limits)
  await expect(t.edit({ path: "/nope", oldString: "a", newString: "b" })).rejects.toThrow("not found: /nope")
  await t.edit({ path: "/new", oldString: "", newString: "fresh" })
  expect(execs.some((e) => isWriteStep(e.argv))).toBe(true)
})

test("edit refuses identical strings", async () => {
  const { sb } = fakeSandbox((argv) => (isRead(argv) ? fileReply("a")() : {}))
  await expect(makeTools(sb, limits).edit({ path: "/f", oldString: "a", newString: "a" })).rejects.toThrow("identical")
})

// --- glob ---

const listing = (...names: string[]) => () => ({ stdout: names.map((n) => `./${n}\0`).join("") })

test("glob matches **/*.ts over the guest find listing", async () => {
  const { sb, execs } = fakeSandbox(listing("a.ts", "src/b.ts", "src/c.js", "deep/x/y.ts"))
  const out = await makeTools(sb, limits).glob({ pattern: "**/*.ts", path: "/repo" })
  expect(out.split("\n")).toEqual(["/repo/a.ts", "/repo/deep/x/y.ts", "/repo/src/b.ts"])
  expect(execs[0]!.argv.slice(3)).toEqual(["rts", "/repo"])
})

test("glob drops dot paths unless hidden", async () => {
  const names = ["a.ts", ".git/h.ts", "src/.cache/z.ts", ".env.ts"]
  const { sb } = fakeSandbox(listing(...names))
  const t = makeTools(sb, limits)
  expect((await t.glob({ pattern: "**/*.ts", path: "/r" })).split("\n")).toEqual(["/r/a.ts"])
  expect((await t.glob({ pattern: "**/*.ts", path: "/r", hidden: true })).split("\n").length).toBe(4)
})

test("glob applies limit", async () => {
  const { sb } = fakeSandbox(listing("a.ts", "b.ts", "c.ts"))
  const out = await makeTools(sb, limits).glob({ pattern: "*.ts", path: "/r", limit: 2 })
  expect(out.split("\n").slice(0, 2)).toEqual(["/r/a.ts", "/r/b.ts"])
  expect(out).toContain("truncated")
})

test("glob with no matches says so", async () => {
  const { sb } = fakeSandbox(listing("a.js"))
  expect(await makeTools(sb, limits).glob({ pattern: "*.ts", path: "/r" })).toBe("no files found")
})

// --- grep ---

test("grep maps options to flags and puts -- before the pattern", async () => {
  const { sb, execs } = fakeSandbox(() => ({ stdout: "/r/a:1:hit\n" }))
  const out = await makeTools(sb, limits).grep({ pattern: "-e x", path: "/r", include: "*.ts", literal: true, caseSensitive: false })
  expect(execs[0]!.argv).toEqual(["grep", "-rn", "-F", "-i", "--include=*.ts", "--", "-e x", "/r"])
  expect(out).toBe("/r/a:1:hit")
})

test("grep defaults to case-sensitive regex over the guest cwd", async () => {
  const { sb, execs } = fakeSandbox(() => ({ stdout: "x\n" }))
  await makeTools(sb, limits).grep({ pattern: "a.b" })
  expect(execs[0]!.argv).toEqual(["grep", "-rn", "--", "a.b", "/"])
})

test("grep exit 1 is no matches, not an error", async () => {
  const { sb } = fakeSandbox(() => ({ exitCode: 1 }))
  expect(await makeTools(sb, limits).grep({ pattern: "zzz", path: "/r" })).toBe("no matches")
})

test("grep exit 2 with no output is an error", async () => {
  const { sb } = fakeSandbox(() => ({ exitCode: 2, stderr: "grep: bad regex" }))
  await expect(makeTools(sb, limits).grep({ pattern: "(", path: "/r" })).rejects.toThrow("bad regex")
})

test("grep applies limit", async () => {
  const { sb } = fakeSandbox(() => ({ stdout: "1\n2\n3\n" }))
  const out = await makeTools(sb, limits).grep({ pattern: "x", path: "/r", limit: 2 })
  expect(out.split("\n").slice(0, 2)).toEqual(["1", "2"])
  expect(out).toContain("truncated")
})

// --- the leak seam ---

test("the leak seam is off unless asked for", async () => {
  const { sb, execs } = fakeSandbox()
  await makeTools(sb, limits).shell({ command: "true" })
  expect(execs.length).toBe(1)
})

test("the leak seam runs shell on the host (for the leak check only)", async () => {
  const { sb, execs } = fakeSandbox()
  const out = await makeTools(sb, { ...limits, leak: "shell" }).shell({ command: "echo on-host" })
  expect(out).toContain("on-host")
  expect(execs.length).toBe(0)
})

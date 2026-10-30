import { afterEach, beforeEach, expect, test } from "bun:test"
import { spawnSync } from "node:child_process"
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

const ROOT = join(import.meta.dir, "..", "..")
const FIXTURES = join(ROOT, "tests", "fixtures", "release")

function run(script: string, args: string[]) {
  return spawnSync("bash", [join(ROOT, script), ...args], { encoding: "utf8", cwd: ROOT })
}

let dir: string
let f: string
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "rts-release-gate-test-"))
  f = join(dir, "rts.rb")
})
afterEach(() => rmSync(dir, { recursive: true, force: true }))

for (const [log, status] of [["baseline", 0], ["ok", 0], ["fewer", 0], ["sixth", 1], ["no-result", 1]] as const) {
  test(`check-tests --parse ${log} exits ${status}`, () => {
    const r = run("scripts/release/check-tests.sh", ["--parse", join(FIXTURES, `${log}.log`)])
    expect(r.status).toBe(status)
    if (log === "sixth") {
      expect(r.stderr).toContain("session::tests::x")
      expect(r.stderr).not.toContain("copy::tests::a_long_name_is_refused")
    }
    if (log === "no-result") expect(r.stderr).toContain("no test result line")
  })
}

test("a FAILED line split by stray stderr still counts against the result line", () => {
  const r = run("scripts/release/check-tests.sh", ["--parse", join(FIXTURES, "split.log")])
  expect(r.status).toBe(1)
  expect(r.stderr).toContain("report 6 failed, but only 5 FAILED lines")
})

test("the release workflow assesses CLI binaries as notarized, not as apps", () => {
  const wf = readFileSync(join(ROOT, ".github", "workflows", "release.yml"), "utf8")
  expect(wf).not.toContain("--type execute")
  expect(wf).toContain("spctl --assess --type install -vv")
  expect(wf).toContain("source=Notarized Developer ID")
})

test("GNU tools go first on PATH only for the test gate, never for later steps", () => {
  const wf = readFileSync(join(ROOT, ".github", "workflows", "release.yml"), "utf8")
  // A GITHUB_PATH write lasts for every later step, so the supervisor build,
  // signing and packaging would run with GNU stat and tar.
  const code = wf.split("\n").filter((l) => !/^\s*#/.test(l)).join("\n")
  expect(/GITHUB_PATH/.test(code)).toBe(false)
  const [before, rest = ""] = code.split("- name: Test gate")
  const gate = rest.split("- name:")[0]
  const after = rest.slice(gate.length)
  expect(gate).toContain("libexec/gnubin")
  expect(before.includes("gnubin") || after.includes("gnubin")).toBe(false)
  expect(gate).toContain("bash scripts/release/check-tests.sh")
})

test("release scripts call BSD stat and tar by absolute path", () => {
  const files = ["install.sh", "scripts/build-patched-mvm-supervisor.sh", "scripts/package-release.sh",
    "scripts/release/check-tests.sh", "scripts/release/render-formula.sh"]
  for (const file of files) {
    const text = readFileSync(join(ROOT, file), "utf8")
    for (const [i, line] of text.split("\n").entries()) {
      if (/^\s*#/.test(line)) continue
      expect(`${file}:${i + 1}: ${line}`).not.toMatch(/(^|[^\/\w-])(stat|tar) -/)
    }
  }
})

test("unit tests that parse tar or stat output call the BSD tools by absolute path", () => {
  // The CI test gate runs with GNU coreutils and tar first on PATH, and GNU
  // tar -tv prints owner/group as one column.
  for (const file of readdirSync(join(ROOT, "tests", "unit")).filter((n) => n.endsWith(".ts"))) {
    const text = readFileSync(join(ROOT, "tests", "unit", file), "utf8")
    for (const [i, line] of text.split("\n").entries()) {
      expect(`${file}:${i + 1}: ${line}`).not.toMatch(/(sh|spawnSync|execFileSync)\(\s*"(tar|stat)"/)
    }
  }
})

test("a substring of an allowed name is not allowed", () => {
  const r = run("scripts/release/check-tests.sh", ["--parse", join(FIXTURES, "substring.log")])
  expect(r.status).toBe(1)
  expect(r.stderr).toContain("copy::tests::a_long_name_is_refused_too")
})

test("check-tests --parse refuses a missing log", () => {
  const r = run("scripts/release/check-tests.sh", ["--parse", join(dir, "missing.log")])
  expect(r.status).toBe(1)
})

test("the formula renders and parses", () => {
  const r = run("scripts/release/render-formula.sh", ["--version", "0.1.0", "--sha256", "a".repeat(64), "--out", f])
  expect(r.stderr).toBe("")
  expect(r.status).toBe(0)
  const text = readFileSync(f, "utf8")
  expect(text).toContain("class Rts < Formula")
  expect(text).toContain('url "https://github.com/nearai/nearai-red-sandbox/releases/download/v0.1.0/rts-0.1.0-aarch64-apple-darwin.tar.gz"')
  expect(text).toContain(`sha256 "${"a".repeat(64)}"`)
  expect(text).toContain('license "Apache-2.0"')
  expect(text).toContain('prefix.install "bin", "libexec", "share"')
  expect(text).toContain('system bin/"rts", "setup", "--check", "--offline"')
  expect(text).not.toContain("@")
  expect(spawnSync("ruby", ["-c", f]).status).toBe(0)
})

for (const bad of [["--version", "v0.1.0"], ["--sha256", "A".repeat(64)], ["--sha256", "abc"]]) {
  test(`render-formula refuses ${bad.join(" ")}`, () => {
    const flags: Record<string, string> = { "--version": "0.1.0", "--sha256": "a".repeat(64), "--out": f }
    flags[bad[0]] = bad[1]
    const r = run("scripts/release/render-formula.sh", Object.entries(flags).flat())
    expect(r.status).toBe(1)
    expect(existsSync(f)).toBe(false)
  })
}

test("render-formula refuses a template with a placeholder left", () => {
  const tpl = join(dir, "t.rb.template")
  writeFileSync(tpl, 'class Rts < Formula\n  version "@VERSION@"\n  sha256 "@SHA256@"\n  homepage "@HOMEPAGE@"\nend\n')
  const r = run("scripts/release/render-formula.sh", ["--version", "0.1.0", "--sha256", "a".repeat(64), "--out", f, "--template", tpl])
  expect(r.status).toBe(1)
  expect(r.stderr).toContain("@")
  expect(existsSync(f)).toBe(false)
})

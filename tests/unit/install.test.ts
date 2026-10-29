import { afterEach, beforeEach, expect, test } from "bun:test"
import { spawnSync } from "node:child_process"
import { appendFileSync, chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join } from "node:path"

const ROOT = join(import.meta.dir, "..", "..")
const PACKAGE = join(ROOT, "scripts", "package-release.sh")
const TEMPLATE = join(ROOT, "install.sh")
const TARBALL = (v: string) => `rts-${v}-aarch64-apple-darwin.tar.gz`

let dir: string
let home: string
let prefix: string
let fakebin: string
let tmp: string
let log: string
let curlLog: string
let ghLog: string

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "rts-install-test-"))
  home = join(dir, "home")
  prefix = join(dir, "prefix")
  fakebin = join(dir, "fakebin")
  tmp = join(dir, "tmp")
  log = join(dir, "rts.log")
  curlLog = join(dir, "curl.log")
  ghLog = join(dir, "gh.log")
  for (const d of [home, fakebin, tmp]) mkdirSync(d)
  // Every test sees curl through a logging wrapper, so "nothing downloaded" is observable.
  stub("curl", `#!/bin/sh\necho "$*" >> '${curlLog}'\nexec /usr/bin/curl "$@"\n`)
})
afterEach(() => rmSync(dir, { recursive: true, force: true }))

function stub(name: string, body: string) {
  writeFileSync(join(fakebin, name), body)
  chmodSync(join(fakebin, name), 0o755)
}

function write(path: string, body: string, mode = 0o644) {
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, body)
  chmodSync(path, mode)
}

// A fake release whose bin/rts appends its version and arguments to $RTS_TEST_LOG.
function release(version: string, setupStatus = 0): string {
  const out = join(dir, `release-${version}`)
  if (existsSync(out)) return out
  const src = join(dir, `src-${version}`)
  write(join(src, "rts"), `#!/bin/sh\necho "${version} $*" >> "$RTS_TEST_LOG"\nexit ${setupStatus}\n`, 0o755)
  write(join(src, "mvm-hvf-supervisor"), `#!/bin/sh\necho supervisor ${version}\n`, 0o755)
  write(join(src, "build-info"), "patch_version=rts-vsock-drain-v1\nsigned_binary_sha256=stale\n")
  const r = spawnSync("bash", [
    PACKAGE, "--version", version, "--rts", join(src, "rts"), "--supervisor", join(src, "mvm-hvf-supervisor"),
    "--build-info", join(src, "build-info"), "--out", out,
  ], { encoding: "utf8" })
  expect(r.stderr).toBe("")
  expect(r.status).toBe(0)
  return out
}

function env(version: string | null, base: string): Record<string, string> {
  const e: Record<string, string> = {
    PATH: `${fakebin}:/usr/bin:/bin`,
    HOME: home,
    TMPDIR: tmp,
    RTS_INSTALL_PREFIX: prefix,
    RTS_RELEASE_BASE: `file://${base}`,
    RTS_TEST_LOG: log,
  }
  if (version !== null) e.RTS_VERSION = version
  return e
}

function install(version: string, script?: string) {
  const rel = release(version)
  return spawnSync("/bin/bash", [script ?? join(rel, "install.sh")], { encoding: "utf8", env: env(version, rel) })
}

const lines = (path: string) => readFileSync(path, "utf8").trim().split("\n")

test("a fake release installs into the prefix and runs rts setup once", () => {
  const r = install("0.1.0")
  expect(r.stderr + r.stdout).not.toContain("refusing")
  expect(r.status).toBe(0)
  expect(lines(log)).toEqual(["0.1.0 setup"])
  for (const f of [
    "bin/rts",
    "libexec/nearai-red-sandbox/mvm-hvf-supervisor",
    "libexec/nearai-red-sandbox/mvm-hvf-supervisor.build-info",
    "share/nearai-red-sandbox/plugin/index.ts",
    "share/nearai-red-sandbox/opencode/session.example.json",
  ]) expect([f, existsSync(join(prefix, f))]).toEqual([f, true])
  // Only what the tarball owns lands in the prefix: no LICENSE, README.md or staging dir.
  expect(readdirSync(prefix).sort()).toEqual(["bin", "libexec", "share"])
  expect(r.stdout + r.stderr).toContain("provenance not checked")
  expect(r.stdout).toContain(`export PATH="${prefix}/bin:$PATH"`)
  expect(readdirSync(tmp)).toEqual([])
})

test("the PATH hint is omitted when the prefix's bin is already on PATH", () => {
  const rel = release("0.1.0")
  const e = env("0.1.0", rel)
  e.PATH = `${prefix}/bin:${e.PATH}`
  const r = spawnSync("/bin/bash", [join(rel, "install.sh")], { encoding: "utf8", env: e })
  expect(r.status).toBe(0)
  expect(r.stdout).not.toContain("export PATH=")
})

test("a missing prefix directory is created", () => {
  prefix = join(dir, "fresh", "account", ".local")
  const r = install("0.1.0")
  expect(r.status).toBe(0)
  expect(existsSync(join(prefix, "bin/rts"))).toBe(true)
})

test("a tampered tarball is refused before unpacking", () => {
  const rel = release("0.1.0")
  appendFileSync(join(rel, TARBALL("0.1.0")), "x")
  const r = install("0.1.0")
  expect(r.status).toBe(1)
  expect(r.stderr).toContain(TARBALL("0.1.0"))
  expect(existsSync(prefix)).toBe(false)
  expect(existsSync(log)).toBe(false)
  expect(readdirSync(tmp)).toEqual([])
})

test("a tarball missing from SHA256SUMS is refused", () => {
  const rel = release("0.1.0")
  writeFileSync(join(rel, "SHA256SUMS"), readFileSync(join(rel, "SHA256SUMS"), "utf8").split("\n").filter((l) => !l.includes(".tar.gz")).join("\n"))
  const r = install("0.1.0")
  expect(r.status).toBe(1)
  expect(r.stderr).toContain("SHA256SUMS")
  expect(existsSync(prefix)).toBe(false)
  expect(existsSync(log)).toBe(false)
})

test("a missing release asset stops the install", () => {
  const rel = release("0.1.0")
  rmSync(join(rel, TARBALL("0.1.0")))
  const r = install("0.1.0")
  expect(r.status).toBe(1)
  expect(existsSync(prefix)).toBe(false)
  expect(existsSync(log)).toBe(false)
})

test("a failing attestation check stops the install", () => {
  stub("gh", `#!/bin/sh\necho "$*" >> '${ghLog}'\nexit 1\n`)
  const r = install("0.1.0")
  expect(r.status).toBe(1)
  expect(lines(ghLog)).toHaveLength(1)
  expect(lines(ghLog)[0]).toMatch(new RegExp(`^attestation verify .*/${TARBALL("0.1.0").replaceAll(".", "\\.")} --repo nearai/nearai-red-sandbox$`))
  expect(existsSync(join(prefix, "bin"))).toBe(false)
  expect(existsSync(log)).toBe(false)
})

test("a passing attestation check lets the install proceed without the warning", () => {
  stub("gh", `#!/bin/sh\necho "$*" >> '${ghLog}'\nexit 0\n`)
  const r = install("0.1.0")
  expect(r.status).toBe(0)
  expect(lines(ghLog)).toHaveLength(1)
  expect(r.stdout + r.stderr).not.toContain("provenance not checked")
  expect(lines(log)).toEqual(["0.1.0 setup"])
})

for (const [s, m] of [["Linux", "aarch64"], ["Darwin", "x86_64"]]) {
  test(`${s} ${m} is refused`, () => {
    stub("uname", `#!/bin/sh\ncase "$1" in -s) echo ${s} ;; -m) echo ${m} ;; *) echo ${s} ;; esac\n`)
    const r = install("0.1.0")
    expect(r.status).toBe(1)
    expect(r.stderr).toContain("aarch64-apple-darwin")
    expect(r.stderr).toContain(`${s} ${m}`)
    expect(existsSync(curlLog)).toBe(false)
    expect(existsSync(prefix)).toBe(false)
  })
}

test("a re-run upgrades in place and keeps files it does not own", () => {
  expect(install("0.1.0").status).toBe(0)
  const share = join(prefix, "share/nearai-red-sandbox")
  const opencodeBin = join(share, "opencode/2.2.2/opencode")
  const homeSupervisor = join(share, "mvm-hvf-supervisor")
  const sessionFile = join(share, "sessions/x")
  const other = join(prefix, "bin/other")
  for (const f of [opencodeBin, homeSupervisor, sessionFile, other]) write(f, "keep\n")
  // Files inside owned paths that the new release does not ship go away with the old copy.
  write(join(share, "plugin/stale.ts"), "old\n")
  write(join(prefix, "libexec/nearai-red-sandbox/mvm-hvf-supervisor.mvm-hvf-signed"), "old\n")

  const r = install("0.1.1")
  expect(r.status).toBe(0)
  expect(lines(log)).toEqual(["0.1.0 setup", "0.1.1 setup"])
  for (const kept of [opencodeBin, homeSupervisor, sessionFile, other]) expect([kept, existsSync(kept)]).toEqual([kept, true])
  expect(readFileSync(join(prefix, "libexec/nearai-red-sandbox/mvm-hvf-supervisor"), "utf8")).toContain("supervisor 0.1.1")
  expect(existsSync(join(share, "plugin/stale.ts"))).toBe(false)
  expect(existsSync(join(prefix, "libexec/nearai-red-sandbox/mvm-hvf-supervisor.mvm-hvf-signed"))).toBe(false)
  expect(readdirSync(prefix).filter((n) => n.startsWith(".rts-install"))).toEqual([])
})

test("a failing rts setup exits with its status", () => {
  release("0.1.0", 7)
  const r = install("0.1.0")
  expect(r.status).toBe(7)
  expect(lines(log)).toEqual(["0.1.0 setup"])
  expect(r.stdout).not.toContain("export PATH=")
})

test("a truncated download runs nothing", () => {
  const rel = release("0.1.0")
  const text = readFileSync(join(rel, "install.sh"), "utf8")
  const start = text.indexOf("main() {")
  const end = text.lastIndexOf('main "$@"')
  expect(start).toBeGreaterThan(-1)
  expect(end).toBeGreaterThan(start)
  for (const cut of [Math.floor((start + end) / 2), end - 2, end]) {
    spawnSync("/bin/bash", [], { encoding: "utf8", env: env("0.1.0", rel), input: text.slice(0, cut) })
    expect([cut, existsSync(curlLog), existsSync(log), existsSync(prefix)]).toEqual([cut, false, false, false])
  }
})

test("an unrendered template without RTS_VERSION is refused", () => {
  const rel = release("0.1.0")
  const r = spawnSync("/bin/bash", [TEMPLATE], { encoding: "utf8", env: env(null, rel) })
  expect(r.status).toBe(1)
  expect(r.stderr).toContain("unrendered template; set RTS_VERSION")
  expect(existsSync(curlLog)).toBe(false)
  expect(existsSync(prefix)).toBe(false)
})

test("the template with RTS_VERSION set installs that version", () => {
  const r = install("0.1.0", TEMPLATE)
  expect(r.status).toBe(0)
  expect(lines(log)).toEqual(["0.1.0 setup"])
})

test("install.sh is clean under shellcheck", () => {
  const r = spawnSync("shellcheck", [TEMPLATE], { encoding: "utf8" })
  if (r.error) return // shellcheck is not installed here; the release gate runs it.
  expect(r.stdout + r.stderr).toBe("")
  expect(r.status).toBe(0)
})

import { afterEach, beforeEach, expect, test } from "bun:test"
import { spawnSync } from "node:child_process"
import { createHash } from "node:crypto"
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

const ROOT = join(import.meta.dir, "..", "..")
const SCRIPT = join(ROOT, "scripts", "package-release.sh")
const TARBALL = (v: string) => `rts-${v}-aarch64-apple-darwin.tar.gz`

let dir: string
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "rts-release-test-"))
  writeFileSync(join(dir, "rts"), "#!/bin/sh\necho rts\n")
  chmodSync(join(dir, "rts"), 0o755)
  writeFileSync(join(dir, "mvm-hvf-supervisor"), "#!/bin/sh\necho supervisor\n")
  chmodSync(join(dir, "mvm-hvf-supervisor"), 0o755)
  writeFileSync(
    join(dir, "build-info"),
    "upstream=https://github.com/tinylabscom/mvm.git\npatch_version=rts-vsock-drain-v1\nsigned_binary_sha256=stale\ntarget=aarch64-apple-darwin\n",
  )
  writeFileSync(join(dir, "install.sh"), '#!/bin/bash\nRTS_DEFAULT_VERSION="@RTS_VERSION@"\n')
})
afterEach(() => rmSync(dir, { recursive: true, force: true }))

function run(overrides: Record<string, string | null> = {}) {
  const flags: Record<string, string | null> = {
    "--version": "0.1.0",
    "--rts": join(dir, "rts"),
    "--supervisor": join(dir, "mvm-hvf-supervisor"),
    "--build-info": join(dir, "build-info"),
    "--out": join(dir, "out"),
    "--install-sh": join(dir, "install.sh"),
    ...overrides,
  }
  const args = Object.entries(flags).flatMap(([k, v]) => (v === null ? [] : [k, v]))
  return spawnSync("bash", [SCRIPT, ...args], { encoding: "utf8" })
}

function pkg(version: string): string {
  const r = run({ "--version": version })
  expect(r.stderr).toBe("")
  expect(r.status).toBe(0)
  return join(dir, "out")
}

function sh(cmd: string, args: string[], cwd?: string) {
  const r = spawnSync(cmd, args, { encoding: "utf8", cwd })
  expect(r.status).toBe(0)
  return r.stdout
}

function tarList(tarball: string): string[] {
  return sh("/usr/bin/tar", ["-tzf", tarball]).split("\n").filter(Boolean).map((l) => l.replace(/\/$/, "")).sort()
}

const sha256 = (path: string) => createHash("sha256").update(readFileSync(path)).digest("hex")

test("the tarball has exactly the spec's layout", () => {
  const out = pkg("0.1.0")
  const list = tarList(join(out, TARBALL("0.1.0")))
  expect(list).toEqual([
    "LICENSE", "README.md", "bin", "bin/rts", "libexec", "libexec/nearai-red-sandbox",
    "libexec/nearai-red-sandbox/mvm-hvf-supervisor", "libexec/nearai-red-sandbox/mvm-hvf-supervisor.build-info",
    "share", "share/nearai-red-sandbox", "share/nearai-red-sandbox/opencode",
    "share/nearai-red-sandbox/opencode/session.example.json",
    "share/nearai-red-sandbox/plugin", "share/nearai-red-sandbox/plugin/audit.ts",
    "share/nearai-red-sandbox/plugin/index.ts", "share/nearai-red-sandbox/plugin/package.json",
  ])
  expect(readdirSync(out).sort()).toEqual(["SHA256SUMS", "install.sh", TARBALL("0.1.0")])
})

test("binaries are executable and build-info names the packaged supervisor", () => {
  const out = pkg("0.1.0")
  const tarball = join(out, TARBALL("0.1.0"))
  const modes = new Map<string, string>()
  for (const line of sh("/usr/bin/tar", ["-tvzf", tarball]).split("\n").filter(Boolean)) {
    const f = line.split(/\s+/)
    expect(f[2]).toBe("root")
    expect(f[3]).toBe("wheel")
    modes.set(f[f.length - 1].replace(/\/$/, ""), f[0])
  }
  expect(modes.get("bin/rts")).toBe("-rwxr-xr-x")
  expect(modes.get("libexec/nearai-red-sandbox/mvm-hvf-supervisor")).toBe("-rwxr-xr-x")
  for (const [name, mode] of modes) {
    if (name === "bin/rts" || name === "libexec/nearai-red-sandbox/mvm-hvf-supervisor") continue
    expect([name, mode]).toEqual([name, mode.startsWith("d") ? "drwxr-xr-x" : "-rw-r--r--"])
  }
  const x = join(dir, "x")
  mkdirSync(x)
  sh("/usr/bin/tar", ["-xzf", tarball, "-C", x])
  const supervisor = join(x, "libexec/nearai-red-sandbox/mvm-hvf-supervisor")
  expect(readFileSync(supervisor, "utf8")).toBe(readFileSync(join(dir, "mvm-hvf-supervisor"), "utf8"))
  const info = readFileSync(join(x, "libexec/nearai-red-sandbox/mvm-hvf-supervisor.build-info"), "utf8")
  expect(info.match(/^signed_binary_sha256=.*$/gm)).toEqual([`signed_binary_sha256=${sha256(supervisor)}`])
  expect(info).toContain("patch_version=rts-vsock-drain-v1\n")
  expect(readFileSync(join(x, "bin/rts"), "utf8")).toBe(readFileSync(join(dir, "rts"), "utf8"))
  expect(readFileSync(join(x, "share/nearai-red-sandbox/plugin/index.ts"))).toEqual(readFileSync(join(ROOT, "plugin/index.ts")))
})

test("SHA256SUMS verifies both files", () => {
  const out = pkg("0.1.0")
  const lines = readFileSync(join(out, "SHA256SUMS"), "utf8").split("\n").filter(Boolean)
  expect(lines).toEqual([
    `${sha256(join(out, TARBALL("0.1.0")))}  ${TARBALL("0.1.0")}`,
    `${sha256(join(out, "install.sh"))}  install.sh`,
  ])
  sh("shasum", ["-a", "256", "-c", "SHA256SUMS"], out)
})

test("install.sh has the version baked in", () => {
  const out = pkg("0.1.0")
  const rendered = readFileSync(join(out, "install.sh"), "utf8")
  expect(rendered).toContain('RTS_DEFAULT_VERSION="0.1.0"')
  expect(rendered).not.toContain("@RTS_VERSION@")
})

for (const template of ["#!/bin/bash\nA=@RTS_VERSION@ B=@RTS_VERSION@\n", "#!/bin/bash\nRTS_DEFAULT_VERSION=0.0.0\n"]) {
  test(`an install.sh template without exactly one placeholder is refused: ${JSON.stringify(template)}`, () => {
    writeFileSync(join(dir, "install.sh"), template)
    const r = run()
    expect(r.status).toBe(1)
    expect(r.stderr).toContain("--install-sh")
    expect(existsSync(join(dir, "out", TARBALL("0.1.0")))).toBe(false)
  })
}

for (const info of ["upstream=x\n", "signed_binary_sha256=a\nsigned_binary_sha256=b\n"]) {
  test(`a build-info without exactly one signed_binary_sha256 line is refused: ${JSON.stringify(info)}`, () => {
    writeFileSync(join(dir, "build-info"), info)
    const r = run()
    expect(r.status).toBe(1)
    expect(r.stderr).toContain("--build-info")
    expect(existsSync(join(dir, "out", TARBALL("0.1.0")))).toBe(false)
  })
}

for (const bad of [
  ["--version", "v0.1.0"], ["--version", "0.1"], ["--version", "0.1.0-rc1"], ["--rts", "/nonexistent"],
  ["--supervisor", "/nonexistent"], ["--build-info", "/nonexistent"],
]) {
  test(`refuses ${bad.join(" ")}`, () => {
    const r = run({ [bad[0]]: bad[1] })
    expect(r.status).toBe(1)
    expect(r.stderr).toContain(bad[0])
    expect(existsSync(join(dir, "out", TARBALL("0.1.0")))).toBe(false)
  })
}

for (const flag of ["--version", "--rts", "--supervisor", "--build-info", "--out"]) {
  test(`refuses a missing ${flag}`, () => {
    const r = run({ [flag]: null })
    expect(r.status).toBe(1)
    expect(r.stderr).toContain(flag)
    expect(existsSync(join(dir, "out", TARBALL("0.1.0")))).toBe(false)
  })
}

test("refuses a non-executable binary", () => {
  chmodSync(join(dir, "rts"), 0o644)
  const r = run()
  expect(r.status).toBe(1)
  expect(r.stderr).toContain("--rts")
  expect(existsSync(join(dir, "out", TARBALL("0.1.0")))).toBe(false)
})

test("refuses an existing non-empty output directory", () => {
  mkdirSync(join(dir, "out"))
  writeFileSync(join(dir, "out", "keep"), "x")
  const r = run()
  expect(r.status).toBe(1)
  expect(r.stderr).toContain("--out")
  expect(readdirSync(join(dir, "out"))).toEqual(["keep"])
})

test("an existing empty output directory is used", () => {
  mkdirSync(join(dir, "out"))
  expect(readdirSync(pkg("1.2.3")).sort()).toEqual(["SHA256SUMS", "install.sh", TARBALL("1.2.3")])
})

test("the entitlements file grants only the hypervisor", () => {
  const json = sh("plutil", ["-convert", "json", "-o", "-", join(ROOT, "packaging/macos/mvm-hvf-supervisor.entitlements")])
  expect(JSON.parse(json)).toEqual({ "com.apple.security.hypervisor": true })
})

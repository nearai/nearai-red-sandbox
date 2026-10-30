import { afterEach, beforeEach, expect, test } from "bun:test"
import { spawnSync } from "node:child_process"
import { createHash } from "node:crypto"
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { gunzipSync } from "node:zlib"

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
    "share/nearai-red-sandbox/plugin/branding", "share/nearai-red-sandbox/plugin/branding/footer.ts",
    "share/nearai-red-sandbox/plugin/branding/tui.tsx",
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
  for (const f of ["index.ts", "audit.ts", "package.json", "branding/tui.tsx", "branding/footer.ts"]) {
    expect([f, readFileSync(join(x, "share/nearai-red-sandbox/plugin", f))]).toEqual([f, readFileSync(join(ROOT, "plugin", f))])
  }
})

test("the tarball carries no extended attributes or AppleDouble metadata", () => {
  // A quarantine or provenance xattr on an input would otherwise ride along as
  // a pax header and be restored onto the installed files.
  for (const f of ["rts", "mvm-hvf-supervisor"]) sh("/usr/bin/xattr", ["-w", "com.example.rts-test", "1", join(dir, f)])
  expect(sh("/usr/bin/xattr", [join(dir, "rts")])).toContain("com.example.rts-test")
  const out = pkg("0.1.0")
  const raw = gunzipSync(readFileSync(join(out, TARBALL("0.1.0")))).toString("latin1")
  for (const needle of ["LIBARCHIVE.xattr", "SCHILY.xattr", "com.example.rts-test"]) {
    expect([needle, raw.includes(needle)]).toEqual([needle, false])
  }
  expect(tarList(join(out, TARBALL("0.1.0"))).filter((n) => n.split("/").pop()!.startsWith("._"))).toEqual([])
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

// --- scripts/release/sign-manifest.sh ---

const SIGN = join(ROOT, "scripts", "release", "sign-manifest.sh")
const OPENSSL = process.env.RTS_OPENSSL ?? "/opt/homebrew/opt/openssl@3/bin/openssl"
const PUBLISHED = "2026-11-02T18:04:11Z"

// A throwaway Ed25519 key: the PEM in base64, as the release secret holds it,
// and the public key as 64 lowercase hex characters.
function throwawayKey(name: string): { pemBase64: string; publicHex: string; pem: string } {
  const pem = join(dir, `${name}.pem`)
  sh(OPENSSL, ["genpkey", "-algorithm", "ed25519", "-out", pem])
  const der = spawnSync(OPENSSL, ["pkey", "-in", pem, "-pubout", "-outform", "DER"])
  expect(der.status).toBe(0)
  return {
    pem,
    pemBase64: readFileSync(pem).toString("base64"),
    publicHex: Buffer.from(der.stdout).subarray(-32).toString("hex"),
  }
}

function signRun(dist: string, key: { pemBase64: string; publicHex: string }, overrides: Record<string, string | null> = {}, env: Record<string, string> = {}) {
  const tmp = join(dir, "sign-tmp")
  mkdirSync(tmp, { recursive: true })
  const flags: Record<string, string | null> = {
    "--version": "0.2.0",
    "--dir": dist,
    "--public-key-hex": key.publicHex,
    "--published": PUBLISHED,
    "--openssl": OPENSSL,
    ...overrides,
  }
  const args = Object.entries(flags).flatMap(([k, v]) => (v === null ? [] : [k, v]))
  const r = spawnSync("bash", [SIGN, ...args], {
    encoding: "utf8",
    env: { ...process.env, TMPDIR: tmp, RTS_UPDATE_SIGNING_KEY_PEM_BASE64: key.pemBase64, ...env },
  })
  return { ...r, tmp }
}

function signDist(overrides: Record<string, string | null> = {}) {
  const dist = pkg("0.2.0")
  const key = throwawayKey("signing")
  const before = snapshot(dist)
  const r = signRun(dist, key, overrides)
  return { dist, key, before, r }
}

function snapshot(d: string): Record<string, string> {
  return Object.fromEntries(readdirSync(d).sort().map((f) => [f, sha256(join(d, f))]))
}

const haveOpenSSL3 = (() => {
  const r = spawnSync(OPENSSL, ["version"], { encoding: "utf8" })
  return r.status === 0 && /^OpenSSL [3-9]/.test(r.stdout)
})()

test.skipIf(!haveOpenSSL3)("the manifest has the exact layout and names the packaged digests", () => {
  const { dist, r } = signDist()
  expect(r.stderr).toBe("")
  expect(r.status).toBe(0)
  expect(readFileSync(join(dist, "latest.json"), "utf8")).toBe(
    `{
  "latest": "0.2.0",
  "published": "${PUBLISHED}",
  "tarball": {
    "name": "${TARBALL("0.2.0")}",
    "sha256": "${sha256(join(dist, TARBALL("0.2.0")))}"
  },
  "install_sh": {
    "sha256": "${sha256(join(dist, "install.sh"))}"
  }
}
`,
  )
})

test.skipIf(!haveOpenSSL3)("the signature verifies with OpenSSL against the public key", () => {
  const { dist, key, r } = signDist()
  expect(r.status).toBe(0)
  const b64 = readFileSync(join(dist, "latest.json.sig"), "utf8")
  expect(b64).toMatch(/^[A-Za-z0-9+/]+=*$/)
  const sig = Buffer.from(b64, "base64")
  expect(sig.length).toBe(64)
  writeFileSync(join(dir, "sig.bin"), sig)
  // Verify against the public key alone, rebuilt from its hex as rts does.
  writeFileSync(join(dir, "pub.der"), Buffer.from("302a300506032b6570032100" + key.publicHex, "hex"))
  sh(OPENSSL, ["pkey", "-pubin", "-inform", "DER", "-in", join(dir, "pub.der"), "-out", join(dir, "pub.pem")])
  const ok = spawnSync(OPENSSL, ["pkeyutl", "-verify", "-pubin", "-inkey", join(dir, "pub.pem"), "-rawin",
    "-in", join(dist, "latest.json"), "-sigfile", join(dir, "sig.bin")], { encoding: "utf8" })
  expect(ok.status).toBe(0)
  // One appended byte breaks it: the signature is over the exact bytes.
  writeFileSync(join(dir, "tampered.json"), readFileSync(join(dist, "latest.json"), "utf8") + "\n")
  const bad = spawnSync(OPENSSL, ["pkeyutl", "-verify", "-pubin", "-inkey", join(dir, "pub.pem"), "-rawin",
    "-in", join(dir, "tampered.json"), "-sigfile", join(dir, "sig.bin")], { encoding: "utf8" })
  expect(bad.status).not.toBe(0)
})

test.skipIf(!haveOpenSSL3)("--minimum writes minimum_supported", () => {
  const { dist, r } = signDist({ "--minimum": "0.1.0" })
  expect(r.stderr).toBe("")
  expect(r.status).toBe(0)
  const lines = readFileSync(join(dist, "latest.json"), "utf8").split("\n")
  expect(lines.slice(0, 4)).toEqual(["{", '  "latest": "0.2.0",', '  "minimum_supported": "0.1.0",', `  "published": "${PUBLISHED}",`])
})

test.skipIf(!haveOpenSSL3)("SHA256SUMS gains exactly the two manifest lines and still checks", () => {
  const { dist, r } = signDist()
  expect(r.status).toBe(0)
  const lines = readFileSync(join(dist, "SHA256SUMS"), "utf8").split("\n").filter(Boolean)
  expect(lines).toEqual([
    `${sha256(join(dist, TARBALL("0.2.0")))}  ${TARBALL("0.2.0")}`,
    `${sha256(join(dist, "install.sh"))}  install.sh`,
    `${sha256(join(dist, "latest.json"))}  latest.json`,
    `${sha256(join(dist, "latest.json.sig"))}  latest.json.sig`,
  ])
  sh("shasum", ["-a", "256", "-c", "SHA256SUMS"], dist)
  expect(readdirSync(dist).sort()).toEqual(["SHA256SUMS", "install.sh", "latest.json", "latest.json.sig", TARBALL("0.2.0")])
})

test.skipIf(!haveOpenSSL3)("a signing key that does not match the public key is refused and leaves nothing", () => {
  const dist = pkg("0.2.0")
  const key = throwawayKey("signing")
  const other = throwawayKey("other")
  const before = snapshot(dist)
  const r = signRun(dist, { pemBase64: key.pemBase64, publicHex: other.publicHex })
  expect(r.status).toBe(1)
  expect(r.stderr).toContain("sign-manifest: refusing:")
  expect(existsSync(join(dist, "latest.json"))).toBe(false)
  expect(existsSync(join(dist, "latest.json.sig"))).toBe(false)
  expect(snapshot(dist)).toEqual(before)
  expect(readdirSync(r.tmp)).toEqual([])
})

const libressl = (() => {
  const r = spawnSync("/usr/bin/openssl", ["version"], { encoding: "utf8" })
  return r.status === 0 && r.stdout.startsWith("LibreSSL")
})()

test.skipIf(!haveOpenSSL3 || !libressl)("LibreSSL is refused", () => {
  const { dist, before, r } = signDist({ "--openssl": "/usr/bin/openssl" })
  expect(r.status).toBe(1)
  expect(r.stderr).toContain("sign-manifest: refusing:")
  expect(r.stderr).toContain("LibreSSL")
  expect(snapshot(dist)).toEqual(before)
})

const refusals: [string, (k: { pemBase64: string; publicHex: string }) => { overrides?: Record<string, string | null>; env?: Record<string, string> }][] = [
  ["an empty signing key", () => ({ env: { RTS_UPDATE_SIGNING_KEY_PEM_BASE64: "" } })],
  ["a signing key that is not a PEM", () => ({ env: { RTS_UPDATE_SIGNING_KEY_PEM_BASE64: Buffer.from("not a key\n").toString("base64") } })],
  ["a short public key", (k) => ({ overrides: { "--public-key-hex": k.publicHex.slice(2) } })],
  ["an uppercase public key", (k) => ({ overrides: { "--public-key-hex": k.publicHex.toUpperCase() } })],
  ["--version v0.2.0", () => ({ overrides: { "--version": "v0.2.0" } })],
  ["a missing --version", () => ({ overrides: { "--version": null } })],
  ["a missing --dir", () => ({ overrides: { "--dir": null } })],
  ["a missing --public-key-hex", () => ({ overrides: { "--public-key-hex": null } })],
  ["--minimum above --version", () => ({ overrides: { "--minimum": "0.10.0" } })],
  ["a malformed --minimum", () => ({ overrides: { "--minimum": "0.1" } })],
  ["a malformed --published", () => ({ overrides: { "--published": "2026-11-02 18:04:11" } })],
  ["a version that differs from the tarball", () => ({ overrides: { "--version": "0.3.0" } })],
  ["a missing OpenSSL", () => ({ overrides: { "--openssl": "/nonexistent/openssl" } })],
]
for (const [label, change] of refusals) {
  test.skipIf(!haveOpenSSL3)(`${label} is refused`, () => {
    const dist = pkg("0.2.0")
    const key = throwawayKey("signing")
    const before = snapshot(dist)
    const { overrides, env } = change(key)
    const r = signRun(dist, key, overrides, env)
    expect(r.status).toBe(1)
    expect(r.stderr).toContain("sign-manifest: refusing:")
    expect(snapshot(dist)).toEqual(before)
    expect(readdirSync(r.tmp)).toEqual([])
  })
}

test.skipIf(!haveOpenSSL3)("a SHA256SUMS that no longer checks is refused", () => {
  const dist = pkg("0.2.0")
  const key = throwawayKey("signing")
  writeFileSync(join(dist, "install.sh"), "changed\n")
  const before = snapshot(dist)
  const r = signRun(dist, key)
  expect(r.status).toBe(1)
  expect(r.stderr).toContain("sign-manifest: refusing:")
  expect(snapshot(dist)).toEqual(before)
})

test.skipIf(!haveOpenSSL3)("an existing manifest is refused, not overwritten", () => {
  const dist = pkg("0.2.0")
  const key = throwawayKey("signing")
  writeFileSync(join(dist, "latest.json"), "{}\n")
  const before = snapshot(dist)
  const r = signRun(dist, key)
  expect(r.status).toBe(1)
  expect(r.stderr).toContain("sign-manifest: refusing:")
  expect(snapshot(dist)).toEqual(before)
})

test.skipIf(!haveOpenSSL3)("no key material is left behind", () => {
  const { r } = signDist()
  expect(r.status).toBe(0)
  expect(readdirSync(r.tmp)).toEqual([])
})

test("the release workflow signs the manifest after packaging and before attesting", () => {
  const wf = readFileSync(join(ROOT, ".github", "workflows", "release.yml"), "utf8")
  const pack = wf.indexOf("- name: Package")
  const sign = wf.indexOf("- name: Sign the update manifest")
  const attest = wf.indexOf("actions/attest-build-provenance@")
  const upload = wf.indexOf("name: dist")
  expect(pack).toBeGreaterThan(-1)
  expect(sign).toBeGreaterThan(pack)
  expect(attest).toBeGreaterThan(sign)
  expect(upload).toBeGreaterThan(attest)

  const signStep = wf.slice(sign).split("\n      - ")[0]
  expect(signStep).toContain("bash scripts/release/sign-manifest.sh")
  expect(signStep).toContain("RTS_UPDATE_SIGNING_KEY_PEM_BASE64: ${{ secrets.RTS_UPDATE_SIGNING_KEY_PEM_BASE64 }}")
  expect(signStep).toContain("RTS_UPDATE_PUBLIC_KEY_HEX: ${{ vars.RTS_UPDATE_PUBLIC_KEY_HEX }}")
  expect(signStep).toContain("^[0-9a-f]{64}$")

  const attestBlock = wf.slice(attest).split("\n      - ")[0]
  expect(attestBlock).toContain("dist/latest.json\n")
  expect(attestBlock).toContain("dist/latest.json.sig\n")

  const loop = wf.split("\n").find((l) => l.includes('for f in "rts-$V-aarch64-apple-darwin.tar.gz"'))
  expect(loop).toContain("install.sh SHA256SUMS latest.json latest.json.sig; do")

  const build = wf.split("- name: Build rts")[1].split("\n      - ")[0]
  expect(build).toContain("RTS_UPDATE_PUBLIC_KEY_HEX: ${{ vars.RTS_UPDATE_PUBLIC_KEY_HEX }}")
  // The test gate never sees the release key.
  const gate = wf.split("- name: Test gate")[1].split("\n      - ")[0]
  expect(gate).not.toContain("RTS_UPDATE_PUBLIC_KEY_HEX")

  const config = wf.split("release-config:")[1].split("\n  build:")[0]
  expect(config).toContain("- name: Confirm the update public key is configured")
  expect(config).toContain("RTS_UPDATE_PUBLIC_KEY_HEX: ${{ vars.RTS_UPDATE_PUBLIC_KEY_HEX }}")
  expect(config).toContain("refusing to release: repository variable RTS_UPDATE_PUBLIC_KEY_HEX is unset or not 64 lowercase hex characters")
  const confirm = config.split("- name: Confirm the update public key is configured")[1]
  expect(confirm).toContain("if: github.event_name == 'push'")

  const buildJob = wf.split("\n  build:")[1].split("\n  publish:")[0]
  expect(buildJob).toContain("environment: release")
  expect(buildJob).toContain("brew install coreutils gnu-tar shellcheck openssl@3")
  // Only the build job, which runs in the release environment, reads the signing secret.
  expect(wf.split("secrets.RTS_UPDATE_SIGNING_KEY_PEM_BASE64").length).toBe(2)
  expect(buildJob).toContain("secrets.RTS_UPDATE_SIGNING_KEY_PEM_BASE64")
})

test("the README publishes the update public key", () => {
  // The repository variable RTS_UPDATE_PUBLIC_KEY_HEX, as pinned in the plan.
  const KEY = "9b4a81b8bd017898c36871c6bd1cb890faf95b6e378e72eb99b9c15841f02ac9"
  const readme = readFileSync(join(ROOT, "README.md"), "utf8")
  expect(readme.split(KEY).length - 1).toBe(1)
  expect(readme).toContain("rts update")
})

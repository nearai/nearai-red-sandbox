import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import { spawnSync } from "node:child_process"
import { createHash } from "node:crypto"
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs"
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
    "scripts/release/check-tests.sh", "scripts/release/render-formula.sh", "scripts/release/check-existing-release.sh"]
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

// check-existing-release.sh: a re-run after `gh release create` succeeded must
// skip creation only when the published assets are exactly this run's files.
describe("check-existing-release", () => {
  const SCRIPT = "scripts/release/check-existing-release.sh"
  const V = "0.1.0"
  const TARBALL = `rts-${V}-aarch64-apple-darwin.tar.gz`
  let dist: string
  let fakebin: string
  let release: string
  let ghLog: string
  const hex = (b: string | Buffer) => createHash("sha256").update(b).digest("hex")

  beforeEach(() => {
    dist = join(dir, "dist")
    fakebin = join(dir, "bin")
    release = join(dir, "release.json")
    ghLog = join(dir, "gh.log")
    mkdirSync(dist)
    mkdirSync(fakebin)
    writeFileSync(join(dist, TARBALL), "tarball bytes")
    writeFileSync(join(dist, "install.sh"), "#!/bin/bash\n")
    writeFileSync(join(dist, "SHA256SUMS"), `${hex("tarball bytes")}  ${TARBALL}\n${hex("#!/bin/bash\n")}  install.sh\n`)
    // gh api honours --jq like `jq -r`; the stub runs the script's own filter over a canned release.
    writeFileSync(join(fakebin, "gh"), `#!/bin/bash
echo "$*" >> '${ghLog}'
[ "$1" = api ] || exit 2
filter=
while [ $# -gt 0 ]; do [ "$1" = --jq ] && filter=$2; shift; done
[ -f '${release}' ] || { echo "HTTP 404: Not Found" >&2; exit 1; }
exec /usr/bin/jq -r "$filter" '${release}'
`)
    chmodSync(join(fakebin, "gh"), 0o755)
  })

  function published(assets: { name: string; digest: string | null }[]) {
    writeFileSync(release, JSON.stringify({ tag_name: `v${V}`, draft: false, assets }))
  }
  function exact() {
    return [
      { name: TARBALL, digest: `sha256:${hex("tarball bytes")}` },
      { name: "install.sh", digest: `sha256:${hex("#!/bin/bash\n")}` },
      { name: "SHA256SUMS", digest: `sha256:${hex(readFileSync(join(dist, "SHA256SUMS")))}` },
    ]
  }
  function check() {
    return spawnSync("bash", [join(ROOT, SCRIPT), "--repo", "nearai/nearai-red-sandbox", "--tag", `v${V}`, "--dir", dist], {
      encoding: "utf8", cwd: ROOT, env: { PATH: `${fakebin}:/usr/bin:/bin`, HOME: dir },
    })
  }

  test("an exact match passes and reads the release by tag", () => {
    published(exact())
    const r = check()
    expect(r.stderr).toBe("")
    expect(r.status).toBe(0)
    expect(r.stdout).toContain("already holds exactly this run's assets")
    expect(readFileSync(ghLog, "utf8")).toContain("api repos/nearai/nearai-red-sandbox/releases/tags/v0.1.0 ")
  })

  const cases: [string, () => { name: string; digest: string | null }[]][] = [
    ["a different tarball digest", () => exact().map((a) => (a.name === TARBALL ? { ...a, digest: `sha256:${"0".repeat(64)}` } : a))],
    ["a different SHA256SUMS", () => exact().map((a) => (a.name === "SHA256SUMS" ? { ...a, digest: `sha256:${"1".repeat(64)}` } : a))],
    ["a missing asset", () => exact().filter((a) => a.name !== "install.sh")],
    ["an extra asset", () => [...exact(), { name: "extra.txt", digest: `sha256:${"2".repeat(64)}` }]],
    ["an asset without a digest", () => exact().map((a) => (a.name === "install.sh" ? { ...a, digest: null } : a))],
    ["no assets", () => []],
  ]
  for (const [label, assets] of cases) {
    test(`${label} is refused`, () => {
      published(assets())
      const r = check()
      expect(r.status).toBe(1)
      expect(r.stderr).toContain("v0.1.0")
      expect(r.stderr).toContain("does not hold exactly this run's assets")
    })
  }

  test("a release the API cannot read is refused", () => {
    const r = check()
    expect(r.status).toBe(1)
    expect(r.stderr).toContain("v0.1.0")
  })

  test("a dist whose files do not match its SHA256SUMS is refused", () => {
    published(exact())
    writeFileSync(join(dist, "install.sh"), "changed\n")
    const r = check()
    expect(r.status).toBe(1)
  })
})

test("the publish job guards gh release create with check-existing-release", () => {
  const wf = readFileSync(join(ROOT, ".github", "workflows", "release.yml"), "utf8")
  const step = wf.split("- name: Publish release")[1].split("- name:")[0]
  const view = step.indexOf('gh release view "v$V"')
  const guard = step.indexOf("scripts/release/check-existing-release.sh")
  const create = step.indexOf('gh release create "v$V"')
  expect(view).toBeGreaterThan(-1)
  expect(guard).toBeGreaterThan(view)
  expect(create).toBeGreaterThan(guard)
})

test("HOMEBREW_TAP_DEPLOY_KEY is documented as a repository secret, not an environment secret", () => {
  const wf = readFileSync(join(ROOT, ".github", "workflows", "release.yml"), "utf8")
  const config = wf.split("release-config:")[1].split("\n  build:")[0]
  expect(config).not.toContain("environment:")
  expect(config).toContain("${{ secrets.HOMEBREW_TAP_DEPLOY_KEY }}")
  expect(config).toContain("missing repository secret HOMEBREW_TAP_DEPLOY_KEY")
  expect(config).toContain("private half of the write deploy key on nearai/homebrew-tap")
  const publish = wf.split("\n  publish:")[1]
  expect(publish).not.toContain("environment:")
  const spec = readFileSync(join(ROOT, "docs", "specs", "2026-10-29-release-and-installers-design.md"), "utf8")
  expect(spec).toContain("`HOMEBREW_TAP_DEPLOY_KEY` must be a repository or organization secret")
})

test("no workflow, spec or README still uses HOMEBREW_TAP_TOKEN", () => {
  for (const rel of [
    [".github", "workflows", "release.yml"],
    ["docs", "specs", "2026-10-29-release-and-installers-design.md"],
    ["README.md"],
    ["opencode", "README.md"],
    ["packaging", "homebrew", "rts.rb.template"],
  ]) {
    const path = join(ROOT, ...rel)
    if (!existsSync(path)) continue
    expect(readFileSync(path, "utf8")).not.toContain("HOMEBREW_TAP_TOKEN")
  }
})

// The tap is updated by pushing straight to its main with a deploy key, over
// SSH pinned to GitHub's published host keys, never force-pushed.
describe("the tap step", () => {
  const wf = readFileSync(join(ROOT, ".github", "workflows", "release.yml"), "utf8")
  const publish = wf.split("\n  publish:")[1]
  const step = publish.slice(publish.indexOf("- name: Push the formula bump to the tap"))
  const known = readFileSync(join(FIXTURES, "github_known_hosts"), "utf8").trim().split("\n")

  test("runs after the release is created or verified", () => {
    expect(publish.indexOf("- name: Publish release")).toBeGreaterThan(-1)
    expect(publish.indexOf("- name: Push the formula bump to the tap")).toBeGreaterThan(publish.indexOf("- name: Publish release"))
  })

  test("reads the deploy key, not a token", () => {
    expect(step).toContain("${{ secrets.HOMEBREW_TAP_DEPLOY_KEY }}")
    expect(publish).not.toContain("HOMEBREW_TAP_TOKEN")
    expect(publish).not.toContain("gh pr create")
    expect(publish).not.toContain("gh pr merge")
    expect(publish).not.toContain("x-access-token")
  })

  test("writes the key privately and deletes it on exit", () => {
    const umask = step.indexOf("umask 077")
    const write = step.indexOf('> "$KEY"')
    expect(umask).toBeGreaterThan(-1)
    expect(write).toBeGreaterThan(umask)
    expect(step).toContain('KEY="$RUNNER_TEMP/')
    expect(step).toContain('chmod 600 "$KEY"')
    expect(step).toMatch(/trap '[^']*rm -f "\$KEY"[^']*' EXIT/)
    expect(step.indexOf("trap ")).toBeLessThan(write)
  })

  test("pins GitHub's SSH host keys with strict checking", () => {
    for (const line of known) expect(step).toContain(line)
    expect(step).toContain("-o IdentitiesOnly=yes")
    expect(step).toContain('-o UserKnownHostsFile=\\"$KNOWN_HOSTS\\"')
    expect(step).toContain("-o StrictHostKeyChecking=yes")
    expect(step).not.toContain("StrictHostKeyChecking=no")
    expect(step).not.toContain("accept-new")
    expect(step).not.toContain("ssh-keyscan")
    expect(step).toContain("GIT_SSH_COMMAND=")
  })

  test("clones over SSH, commits as the bot and pushes to main without force", () => {
    expect(step).toContain("git clone --depth 1 --single-branch --branch main git@github.com:nearai/homebrew-tap.git")
    expect(step).toContain('github-actions[bot]')
    expect(step).toContain('-m "rts $V"')
    expect(step).toContain("releases/tag/v$V")
    expect(step).toContain("$SHA")
    expect(step).toContain("push origin HEAD:main")
    expect(step).not.toMatch(/push[^\n]*(--force|-f\b|\+HEAD)/)
    expect(step).toContain('git -C "$TAP" diff --cached --quiet')
  })

  test("takes the hash only from this run's SHA256SUMS and checks the rendered formula", () => {
    expect(step).toContain('"$RUNNER_TEMP/dist/SHA256SUMS"')
    expect(step).toContain("scripts/release/render-formula.sh")
    expect(step).toContain('grep -qF "sha256 \\"$SHA\\""')
  })
})

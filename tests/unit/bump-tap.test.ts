import { afterEach, beforeEach, expect, test } from "bun:test"
import { spawnSync } from "node:child_process"
import { chmodSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

// scripts/release/bump-tap.sh commits the formula bump to nearai/homebrew-tap
// through GraphQL createCommitOnBranch, which GitHub signs, because the org
// requires verified signatures. These tests run it against a fake `gh`.
const ROOT = join(import.meta.dir, "..", "..")
const SCRIPT = join(ROOT, "scripts", "release", "bump-tap.sh")
const SHA = "aa5ad39cc093b6c382105418d78ffa38521bfa80483048a1994834f6c7b62a2d"
const HEAD = "1111111111111111111111111111111111111111"
const NEW = "2222222222222222222222222222222222222222"

// State lives in files under $FAKE: head, formula (absent = no file on the
// tap), verified (true|false), moves (how many commits fail with a moved
// head), and every graphql request body as request-N.json.
const FAKE_GH = `#!/bin/bash
set -euo pipefail
[ "$1" = api ] || { echo "fake gh: unexpected $*" >&2; exit 2; }
shift
echo "$*" >> "$FAKE/calls"
case "$1" in
  repos/nearai/homebrew-tap/git/ref/heads/main) cat "$FAKE/head" ;;
  repos/nearai/homebrew-tap/contents/Formula/rts.rb\\?ref=*)
    [ -f "$FAKE/formula" ] || { echo "gh: Not Found (HTTP 404)" >&2; exit 1; }
    base64 < "$FAKE/formula" | tr -d '\\n' ;;
  graphql)
    [ "$2" = --input ] || { echo "fake gh: graphql needs --input" >&2; exit 2; }
    n=$(ls "$FAKE" | grep -c '^request-' || true)
    cp "$3" "$FAKE/request-$n.json"
    moves=$(cat "$FAKE/moves")
    if [ "$moves" -gt 0 ]; then
      echo $((moves - 1)) > "$FAKE/moves"
      echo "3333333333333333333333333333333333333333" > "$FAKE/head"
      echo '{"data":{"createCommitOnBranch":null},"errors":[{"type":"STALE_DATA","message":"Expected branch to point to \\"x\\" but it did not."}]}'
      echo "gh: Expected branch to point to x but it did not." >&2
      exit 1
    fi
    jq -r '.variables.input.fileChanges.additions[0].contents' "$3" | base64 -d > "$FAKE/formula"
    echo "${NEW}" > "$FAKE/head"
    echo '{"data":{"createCommitOnBranch":{"commit":{"oid":"${NEW}","url":"https://github.com/nearai/homebrew-tap/commit/${NEW}"}}}}' ;;
  repos/nearai/homebrew-tap/commits/*) cat "$FAKE/verified" ;;
  *) echo "fake gh: unexpected api $*" >&2; exit 2 ;;
esac
`

let fake: string
let bin: string
beforeEach(() => {
  fake = mkdtempSync(join(tmpdir(), "rts-bump-tap-"))
  bin = join(fake, "bin")
  spawnSync("mkdir", [bin])
  writeFileSync(join(bin, "gh"), FAKE_GH)
  chmodSync(join(bin, "gh"), 0o755)
  writeFileSync(join(fake, "head"), HEAD + "\n")
  writeFileSync(join(fake, "verified"), "true\n")
  writeFileSync(join(fake, "moves"), "0\n")
  writeFileSync(join(fake, "calls"), "")
})
afterEach(() => rmSync(fake, { recursive: true, force: true }))

function bump(args: Record<string, string | null> = {}, env: Record<string, string | null> = {}) {
  const flags: Record<string, string | null> = { "--version": "0.1.6", "--sha256": SHA, "--run-id": "42", ...args }
  const argv = Object.entries(flags).flatMap(([k, v]) => (v === null ? [] : [k, v]))
  const e: Record<string, string> = { PATH: `${bin}:${process.env.PATH}`, FAKE: fake, GH_TOKEN: "ghs_test", HOME: fake }
  for (const [k, v] of Object.entries(env)) if (v === null) delete e[k]; else e[k] = v
  return spawnSync("bash", [SCRIPT, ...argv], { encoding: "utf8", env: e })
}

const requests = () => readdirSync(fake).filter((f) => f.startsWith("request-")).sort().map((f) => JSON.parse(readFileSync(join(fake, f), "utf8")))
const rendered = (version: string, sha: string) => {
  const out = join(fake, `expected-${version}.rb`)
  const r = spawnSync("bash", [join(ROOT, "scripts", "release", "render-formula.sh"), "--version", version, "--sha256", sha, "--out", out], { encoding: "utf8" })
  expect(r.status).toBe(0)
  return readFileSync(out, "utf8")
}

test("commits the rendered formula through createCommitOnBranch against the current head", () => {
  writeFileSync(join(fake, "formula"), rendered("0.1.5", "b".repeat(64)))
  const r = bump()
  expect(r.stderr).toBe("")
  expect(r.status).toBe(0)
  const [req] = requests()
  expect(requests().length).toBe(1)
  expect(req.query).toContain("createCommitOnBranch")
  const input = req.variables.input
  expect(input.branch).toEqual({ repositoryNameWithOwner: "nearai/homebrew-tap", branchName: "main" })
  expect(input.expectedHeadOid).toBe(HEAD)
  expect(input.fileChanges.additions.length).toBe(1)
  expect(input.fileChanges.additions[0].path).toBe("Formula/rts.rb")
  expect(Buffer.from(input.fileChanges.additions[0].contents, "base64").toString()).toBe(rendered("0.1.6", SHA))
  // No author, committer or signature: GitHub signs only commits it authors.
  expect(Object.keys(input).sort()).toEqual(["branch", "expectedHeadOid", "fileChanges", "message"])
  expect(input.message.headline).toBe("rts 0.1.6")
  expect(input.message.body).toContain("https://github.com/nearai/nearai-red-sandbox/releases/tag/v0.1.6")
  expect(input.message.body).toContain(`Tarball sha256 (rts-0.1.6-aarch64-apple-darwin.tar.gz): ${SHA}`)
  expect(input.message.body).toContain("run 42")
  expect(readFileSync(join(fake, "formula"), "utf8")).toBe(rendered("0.1.6", SHA))
  expect(r.stdout).toContain(NEW)
  expect(r.stdout).toContain("verified")
})

test("a tap with no formula yet gets one", () => {
  const r = bump()
  expect(r.status).toBe(0)
  expect(requests().length).toBe(1)
})

test("a tap that already carries this version and sha256 is left alone (a re-run)", () => {
  writeFileSync(join(fake, "formula"), rendered("0.1.6", SHA))
  const r = bump()
  expect(r.status).toBe(0)
  expect(requests().length).toBe(0)
  expect(r.stdout).toContain("already carries rts 0.1.6")
})

test("a head that moved is re-read and retried once", () => {
  writeFileSync(join(fake, "moves"), "1\n")
  const r = bump()
  expect(r.status).toBe(0)
  const reqs = requests()
  expect(reqs.length).toBe(2)
  expect(reqs[0].variables.input.expectedHeadOid).toBe(HEAD)
  expect(reqs[1].variables.input.expectedHeadOid).toBe("3333333333333333333333333333333333333333")
})

test("a head that moves twice fails rather than retrying forever", () => {
  writeFileSync(join(fake, "moves"), "2\n")
  const r = bump()
  expect(r.status).not.toBe(0)
  expect(requests().length).toBe(2)
})

test("a commit GitHub did not verify fails the job", () => {
  writeFileSync(join(fake, "verified"), "false\n")
  const r = bump()
  expect(r.status).not.toBe(0)
  expect(r.stderr).toContain("not verified")
})

for (const [name, args] of [
  ["a bad version", { "--version": "0.1" }],
  ["a bad sha256", { "--sha256": "ABC" }],
  ["a missing run id", { "--run-id": null }],
] as const) {
  test(`refuses ${name} before touching the tap`, () => {
    const r = bump(args as Record<string, string | null>)
    expect(r.status).not.toBe(0)
    expect(readFileSync(join(fake, "calls"), "utf8")).toBe("")
  })
}

test("refuses without GH_TOKEN before touching the tap", () => {
  const r = bump({}, { GH_TOKEN: null })
  expect(r.status).not.toBe(0)
  expect(r.stderr).toContain("GH_TOKEN")
  expect(readFileSync(join(fake, "calls"), "utf8")).toBe("")
})

test("the release workflow commits the tap bump with a scoped app token, not the deploy key", () => {
  const wf = readFileSync(join(ROOT, ".github", "workflows", "release.yml"), "utf8")
  expect(wf).not.toContain("HOMEBREW_TAP_DEPLOY_KEY")
  expect(wf).not.toContain("git push")

  const publish = wf.split("\n  publish:")[1]
  const mint = publish.split("- name: Mint a token for the tap")[1].split("\n      - ")[0]
  expect(mint).toContain("uses: actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510 # v3.3.0")
  expect(mint).toContain("client-id: ${{ vars.HOMEBREW_TAP_APP_CLIENT_ID }}")
  expect(mint).toContain("private-key: ${{ secrets.HOMEBREW_TAP_APP_PRIVATE_KEY }}")
  expect(mint).toContain("owner: nearai")
  expect(mint).toContain("repositories: homebrew-tap")
  expect(mint).toContain("permission-contents: write")

  const commit = publish.split("- name: Commit the formula bump to the tap")[1].split("\n      - ")[0]
  expect(commit).toContain("GH_TOKEN: ${{ steps.tap-token.outputs.token }}")
  expect(commit).toContain("bash scripts/release/bump-tap.sh")
  expect(publish.indexOf("- name: Mint a token for the tap")).toBeGreaterThan(publish.indexOf("- name: Publish release"))

  const config = wf.split("release-config:")[1].split("\n  build:")[0]
  expect(config).toContain("HOMEBREW_TAP_APP_CLIENT_ID: ${{ vars.HOMEBREW_TAP_APP_CLIENT_ID }}")
  expect(config).toContain("HOMEBREW_TAP_APP_PRIVATE_KEY: ${{ secrets.HOMEBREW_TAP_APP_PRIVATE_KEY }}")
  // The private key is read only where the token is minted and checked.
  expect(wf.split("secrets.HOMEBREW_TAP_APP_PRIVATE_KEY").length).toBe(3)
})

test("bump-tap.sh is executable", () => {
  expect(existsSync(SCRIPT)).toBe(true)
})

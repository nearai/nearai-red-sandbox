# Sandboxed opencode sessions on mvm: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A launcher that starts an opencode v2.1.4 session whose six file and shell tools execute only inside a per-session mvm microVM with no network, and refuses to start the session if that cannot be guaranteed.

**Architecture:** A `Sandbox` interface with one backend, `MvmSandbox`, that shells out to `mvmctl` through a guest-side wrapper protocol (always exit 0, status in a nonce trailer, output capped in the guest). An opencode V2 plugin replaces the six tools' `execute` with `Sandbox` calls, removes every other tool, MCP server and non-NEAR-AI model, and proves it loaded by writing a nonce to a ready file. The launcher owns isolation (XDG dirs, empty cwd, `--standalone`), the VM lifecycle, and the hostile `/out` export.

**Tech Stack:** TypeScript run directly by bun 1.3.3 (`bun test`), opencode v2.1.4, mvm v0.22.0 (`mvmctl`). No npm dependencies.

**Spec:** `docs/specs/2026-10-27-sandboxed-opencode-design.md` (read it first; this plan does not restate its rationale).

## Global Constraints

- No npm dependencies, runtime or dev. That includes `@types/bun`: there is no `tsc` step; `bun test` is the gate. Adding any package needs Zaki's approval first.
- `mvmctl` is `~/.local/mvm/v0.22.0/mvmctl`, overridable by `RTS_MVMCTL`. opencode must report version `2.1.4` (`opencode --version`).
- Every `mvmctl` child process: argv only (never a host shell), stdin `/dev/null`, env `GIT_CONFIG_GLOBAL=<path to an empty file>`.
- Machine create line, exactly: `machine create <name> --image <ref> --profile dev --cpus <n> --memory <MiB>M`. Never `--net`, `--allow-host`, `--peer`, `--gpu`.
- Image reference must match `^[a-z0-9./-]+@sha256:[0-9a-f]{64}$`. Default `docker.io/library/alpine@sha256:e311ae748be7f56ae5cba304bc488f0786df68ee507513f654a5cc8597cffb42`.
- Machine names: `rts-<session-id>`, session id = 12 lowercase hex chars.
- Defaults: tool timeout 120 s; host backstop = timeout + 30 s; `maxOutputBytes` 65,536; memory 2048 MiB; cpus 2; host RSS ceiling 3072 MiB; argv chunk 48 KiB of base64; `copyOut` read chunk 512 KiB of raw bytes; extraction caps 256 MiB total and 10,000 entries; handshake deadline 30 s.
- Trailer line, last line of stderr: `RTS_EXIT_<nonce> <status> <stdoutBytes> <stderrBytes>`, nonce = 24 lowercase hex chars, fresh per exec.
- Tool allowlist after setup, exactly: `shell`, `read`, `write`, `edit`, `glob`, `grep`, `question`.
- Commit style: short imperative subject, no `feat:` prefixes, no emojis, ending with the `Co-Authored-By` line from the session reminder.

## Review Focus

1. Paths that start with `-`, or contain spaces, quotes, newlines or non-ASCII, in `read` / `write` / `edit` / `glob` / `grep`: every guest command passes `--` before operands and the path round-trips exactly. Test in Task 4.
2. A `/out` entry whose path exceeds 100 bytes (busybox tar emits a GNU long-name header): the export refuses with `unsupported tar entry type L`, removes the partial host directory, and teardown still removes the VM. Test in Task 3.
3. A non-UTF-8 file in `read`: decoded with replacement characters and returned, never a thrown error. Test in Task 5.
4. Missing or empty `/out` at teardown: reported as `nothing to export`, not as a failure, and the VM is still removed. Test in Task 6.
5. A tool call arriving after the sandbox was marked unavailable, or during teardown: returns `sandbox unavailable` immediately, never spawns `mvmctl`, never hangs. Test in Task 2.

---

### Task 1: Exec wrapper protocol

Pure functions; no I/O. Also scaffolds the repo.

**Files:**
- Create: `package.json` (`"type": "module"`, `"scripts": { "test": "bun test tests/unit", "contain": "bun test tests/contain" }`, no dependencies)
- Create: `sandbox/protocol.ts`
- Test: `tests/unit/protocol.test.ts`

**Interfaces:**
- Produces:
  - `newNonce(): string` (24 hex chars from `crypto.getRandomValues`)
  - `wrapArgv(command: string[], o: { nonce: string; timeoutSec: number; maxOutputBytes: number; workdir?: string }): string[]` returns the argv for `mvmctl machine exec <name> -- <argv>`
  - `parseResult(stdout: Uint8Array, stderr: Uint8Array, nonce: string): ParsedResult | "no-trailer"`
  - `type ParsedResult = { exitCode: number; timedOut: boolean; stdout: Uint8Array; stderr: Uint8Array; stdoutBytes: number; stderrBytes: number; truncated: boolean }`
  - `isPoisoned(stderrText: string): boolean` (true when it contains `no durable finish`)

- [ ] **Step 1: Write the failing tests**

```ts
test("wrapArgv runs the command under timeout -s KILL and never interpolates it", () => {
  const argv = wrapArgv(["grep", "-n", "--", "$(rm -rf /)", "/in"], { nonce: "a".repeat(24), timeoutSec: 120, maxOutputBytes: 65536 })
  expect(argv[0]).toBe("sh"); expect(argv[1]).toBe("-c")
  expect(argv[2]).toContain('timeout -s KILL "$2"')         // fixed script, operands by position
  expect(argv[2]).not.toContain("rm -rf")
  expect(argv.slice(-5)).toEqual(["grep", "-n", "--", "$(rm -rf /)", "/in"])
})
test("parseResult reads status and sizes from the trailer and strips it", () => {
  const n = "b".repeat(24)
  const r = parseResult(enc("hi"), enc(`warn\nRTS_EXIT_${n} 3 2 4\n`), n)
  expect(r).toEqual({ exitCode: 3, timedOut: false, stdout: enc("hi"), stderr: enc("warn"), stdoutBytes: 2, stderrBytes: 4, truncated: false })
})
test("status 137 is a timeout; reported size above the bytes returned is truncation", () => {
  const n = "c".repeat(24)
  const r = parseResult(enc("x".repeat(10)), enc(`RTS_EXIT_${n} 137 2097152 0\n`), n) as ParsedResult
  expect(r.timedOut).toBe(true); expect(r.truncated).toBe(true); expect(r.stdoutBytes).toBe(2097152)
})
test("a trailer with another nonce, or none, is no-trailer", () => {
  expect(parseResult(enc(""), enc(`RTS_EXIT_${"d".repeat(24)} 0 0 0\n`), "e".repeat(24))).toBe("no-trailer")
  expect(parseResult(enc(""), enc("boom\n"), "e".repeat(24))).toBe("no-trailer")
})
test("isPoisoned matches the mvm journal refusal", () => {
  expect(isPoisoned("Error: machine input sequence 1 has no durable finish; refuse exec")).toBe(true)
})
```

- [ ] **Step 2: Run, expect FAIL** — `bun test tests/unit/protocol.test.ts` fails with `Cannot find module`.

- [ ] **Step 3: Implement `sandbox/protocol.ts`**

The wrapper script is fixed text; operands arrive as `$1` nonce, `$2` timeout seconds, `$3` cap, `$4` workdir (empty for none), then the command. It must: `cd -- "$4"` when non-empty (status 126 on failure); run `timeout -s KILL "$2" "$@"` (after `shift 4`) with stdout to `/tmp/rts-$1.out` and stderr to `/tmp/rts-$1.err`; take the sizes with `wc -c`; emit `head -c "$3"` of each file to its stream; delete both files; print the trailer to stderr; `exit 0`. `parseResult` takes the last stderr line as the trailer and requires the exact nonce.

- [ ] **Step 4: Run, expect PASS** — `bun test tests/unit/protocol.test.ts`.

- [ ] **Step 5: Commit** — `git add package.json sandbox/protocol.ts tests/unit/protocol.test.ts && git commit -m "Add the guest exec wrapper protocol"`

---

### Task 2: MvmSandbox lifecycle and exec

**Files:**
- Create: `sandbox/sandbox.ts` (the `Sandbox` interface and `SandboxUnavailable` error, signatures exactly as in the spec)
- Create: `sandbox/mvm.ts`
- Test: `tests/unit/mvm.test.ts`, `tests/contain/exec.test.ts`

**Interfaces:**
- Consumes: Task 1's `wrapArgv`, `parseResult`, `isPoisoned`, `newNonce`.
- Produces:
  - `type Runner = (argv: string[], o: { timeoutMs: number }) => Promise<{ code: number | null; stdout: Uint8Array; stderr: Uint8Array; killed: boolean }>`
  - `spawnRunner(mvmctl: string, emptyGitConfig: string): Runner` (uses `Bun.spawn` with `stdin: "ignore"` and the env from Global Constraints; kills the child when `timeoutMs` elapses)
  - `class MvmSandbox implements Sandbox` with `constructor(o: { name: string; run: Runner })`, `static attach(name: string, run: Runner): MvmSandbox` (for the plugin, which does not create), plus the interface methods. `copyIn` / `copyOut` throw `not implemented` until Task 6.
  - `get unavailable(): boolean`

- [ ] **Step 1: Write failing unit tests against a recording fake `Runner`**

- `create` issues exactly `["machine","create",name,"--image",ref,"--profile","dev","--cpus","2","--memory","2048M"]` then `["machine","start",name]`, and no argv anywhere contains `--net`, `--allow-host`, `--peer` or `--gpu`.
- `create` with `alpine:latest` (no digest) rejects with `image must be digest-pinned` and runs nothing.
- `exec(["true"], …)` sends `["machine","exec",name,"--", ...wrapArgv(...)]` and returns the parsed result.
- A run whose stderr contains `no durable finish` rejects with `SandboxUnavailable`; the next `exec` rejects with `SandboxUnavailable` without calling the runner (Review Focus 5).
- A run with no valid trailer marks the sandbox unavailable the same way.
- A run the runner reports as `killed` (host backstop at timeout + 30 s) marks it unavailable.
- `remove` issues `["machine","rm",name,"--force","--yes"]` then `["machine","ps"]`, and rejects with `machine still present` if the `ps` output still lists the name.

- [ ] **Step 2: Run, expect FAIL** — `bun test tests/unit/mvm.test.ts`.

- [ ] **Step 3: Implement `sandbox/sandbox.ts` and `sandbox/mvm.ts`.**

- [ ] **Step 4: Run, expect PASS** — `bun test tests/unit/mvm.test.ts`.

- [ ] **Step 5: Write the real-mvm tests in `tests/contain/exec.test.ts`** (each test creates `rts-<fresh id>`, removes it in `afterEach`; the suite skips with a printed reason when `mvmctl doctor` fails)

- `sh -c "exit 3"` reports `exitCode` 3, then `echo ok` returns `ok` (spec testing item 3).
- `sleep 30` with `timeoutMs` 3000: `timedOut` true, `exitCode` 137, and the next exec succeeds.
- `head -c 2097152 /dev/zero` with `maxOutputBytes` 65536: 65,536 bytes back, `truncated` true, `stdoutBytes` 2,097,152.
- `ip -o link` lists only `lo`, and `wget -q -T 5 -O- http://1.1.1.1` exits nonzero.

- [ ] **Step 6: Run** — `bun test tests/contain/exec.test.ts`, expect 4 pass. Then `mvmctl machine ps` shows no `rts-` entries.

- [ ] **Step 7: Commit** — `git commit -m "Add MvmSandbox with fail-closed exec"`

---

### Task 3: Hostile tar extractor

Pure host code; no mvm.

**Files:**
- Create: `sandbox/untar.ts`
- Test: `tests/unit/untar.test.ts`

**Interfaces:**
- Produces: `extractTar(archive: Uint8Array, destDir: string, limits: { maxBytes: number; maxEntries: number }): Promise<{ files: number; bytes: number }>`, rejecting with `TarRejected` (message names the entry and the reason).

- [ ] **Step 1: Write failing tests.** Build fixture archives in the test with `Bun.spawn(["tar", ...])` (the host's bsdtar) from a temp tree, or by hand-writing 512-byte ustar headers for entry types bsdtar will not produce.

- A directory plus two regular files extract byte-exact.
- Each of these rejects, and afterwards `destDir` does not exist: a symlink to `/etc/passwd` (type `2`); a hardlink (type `1`); an entry named `../escape`; an entry named `/abs`; a character device (type `3`); a GNU long-name entry (type `L`, Review Focus 2); a pax header (type `x`); total size over `maxBytes`; more than `maxEntries` entries; a bad header checksum.
- A file is never written outside `destDir`: after every rejecting case, a sentinel file beside `destDir` is unchanged.

- [ ] **Step 2: Run, expect FAIL** — `bun test tests/unit/untar.test.ts`.

- [ ] **Step 3: Implement `extractTar`.** Accept only typeflags `0`, `\0` and `5`. Validate each header checksum. Normalize each name, refusing absolute paths, `..` segments and NUL bytes. Create files with `O_CREAT|O_EXCL` (`fs.open(path, "wx")`) so an existing path is never followed. Extract into `destDir + ".partial"` and rename it into place only on success; on any rejection, `rm -rf` the partial directory.

- [ ] **Step 4: Run, expect PASS.**

- [ ] **Step 5: Commit** — `git commit -m "Add a tar extractor that refuses links and escapes"`

---

### Task 4: Guest file primitives

**Files:**
- Create: `sandbox/files.ts`
- Test: `tests/unit/files.test.ts`, `tests/contain/files.test.ts`

**Interfaces:**
- Consumes: `Sandbox.exec`.
- Produces:
  - `guestWrite(sb: Sandbox, path: string, data: Uint8Array): Promise<void>`: chunks the base64 at 49,152 characters; the first chunk truncates `<path>.rts-<nonce>.tmp`, later chunks append; finishes with `mv -f -- tmp path`; `mkdir -p -- "$(dirname -- "$1")"` first.
  - `guestRead(sb: Sandbox, path: string, maxBytes: number): Promise<{ kind: "file"; data: Uint8Array; size: number; truncated: boolean } | { kind: "dir"; entries: string[] } | { kind: "missing" }>`
  - `guestSha256(sb: Sandbox, path: string): Promise<string>`

- [ ] **Step 1: Write failing unit tests with a fake `Sandbox`** that records argv: a 120 KiB write produces 4 execs (3 chunks plus `mv`); every exec places `--` before the path; a path of `-rf` stays an operand (Review Focus 1).

- [ ] **Step 2: Run, expect FAIL.**

- [ ] **Step 3: Implement `sandbox/files.ts`.** Each guest script is fixed text and reads operands from `"$1"`, `"$2"` and so on.

- [ ] **Step 4: Run, expect PASS.**

- [ ] **Step 5: Write the real-mvm tests:** a 200 KiB random write matches its sha256 in the guest; paths `/tmp/a b`, `/tmp/-x`, `/tmp/q'"q`, `/tmp/ünï` and `/tmp/new\nline` round-trip through write, read and sha256 (Review Focus 1); reading a directory lists its entries; reading a missing path returns `missing`.

- [ ] **Step 6: Run** — `bun test tests/contain/files.test.ts`, expect PASS.

- [ ] **Step 7: Commit** — `git commit -m "Add chunked guest file read and write"`

---

### Task 5: The six tool implementations

**Files:**
- Create: `plugin/tools.ts`
- Test: `tests/unit/tools.test.ts`

**Interfaces:**
- Consumes: `Sandbox`, `guestRead`, `guestWrite`, and `exec`'s result type.
- Produces: `makeTools(sb: Sandbox, limits: { timeoutMs: number; maxOutputBytes: number }): Record<"shell"|"read"|"write"|"edit"|"glob"|"grep", (input: any) => Promise<string>>`, plus the pure `applyEdit(text: string, oldString: string, newString: string, replaceAll?: boolean): string`.

Input field names are opencode v2.1.4's (from `packages/core/src/tool/plugin/*.ts` at that tag):

| Tool | Input fields |
|---|---|
| `shell` | `command`, `workdir?`, `timeout?` (ms; 0 means no limit, which is mapped to the default instead), `background?` |
| `read` | `path`, `offset?` (1-based), `limit?` (default and cap 2000) |
| `write` | `path`, `content` |
| `edit` | `path`, `oldString`, `newString`, `replaceAll?` |
| `glob` | `pattern`, `path?`, `hidden?`, `limit?` |
| `grep` | `pattern`, `path?`, `include?`, `literal?`, `caseSensitive?`, `limit?` |

- [ ] **Step 1: Write failing tests against a fake `Sandbox`.**

- `shell` output ends with `exit status: 3` for exit 3, with `[timed out after 120s]` on timeout, and with `[output truncated: 2097152 bytes total]` when truncated.
- `shell` with `background: true` throws `background commands are not supported in the sandbox`.
- `read` prefixes lines as `<n>: <text>` honouring `offset` and `limit`, lists a directory one entry per line, throws `not found: <path>` when missing, and decodes invalid UTF-8 with U+FFFD rather than throwing (Review Focus 3).
- `applyEdit` throws `oldString not found`, throws `oldString matches 2 times; set replaceAll` when ambiguous, and replaces every match with `replaceAll`.
- `edit` on a truncated read throws `file larger than 65536 bytes; edit refused` and issues no write exec.
- `glob` matches `**/*.ts` with `Bun.Glob` over the guest `find` listing, drops dot paths unless `hidden`, and applies `limit`.
- `grep` maps the options to `-F`, `-i` and `--include=`, places `--` before the pattern, and returns `no matches` for exit 1 without throwing.

- [ ] **Step 2: Run, expect FAIL.** **Step 3: Implement.** **Step 4: Run, expect PASS.**

- [ ] **Step 5: Commit** — `git commit -m "Add sandboxed shell, read, write, edit, glob, grep"`

---

### Task 6: copyIn and copyOut

**Files:**
- Modify: `sandbox/mvm.ts` (replace the Task 2 stubs)
- Test: `tests/contain/copy.test.ts`

**Interfaces:**
- Consumes: `guestWrite`, `extractTar`, `exec`.
- Produces: working `MvmSandbox.copyIn(hostDir, "/in")` and `copyOut("/out", hostDir): Promise<{ status: "exported"; files: number; bytes: number } | { status: "nothing to export" }>`.

- [ ] **Step 1: Write the failing real-mvm tests.**

- `copyIn`: a host tree with nested directories and a 300 KiB file arrives under `/in` with matching guest sha256s.
- `copyOut`: guest files written into `/out` arrive in the host directory byte-exact.
- `copyOut` on a missing `/out`, and on an empty one, returns `nothing to export` (Review Focus 4).
- Hostile `/out` (spec testing item 2): a symlink to the host's sentinel path, a hardlink, a file with a 120-byte name, and a file over the size cap each reject with `TarRejected`, the host destination does not exist afterwards, and the host sentinel is unchanged.

- [ ] **Step 2: Run, expect FAIL.**

- [ ] **Step 3: Implement.** `copyIn` runs host `tar -cf - -C hostDir .` (the host and the inputs are trusted), sends the archive with `guestWrite` to `/tmp/rts-in.tar`, then runs `mkdir -p /in && tar -xf /tmp/rts-in.tar -C /in`. `copyOut` runs `tar -cf /tmp/rts-out.tar -C /out .` and reads its size and `sha256sum` back. It then reads 524,288-byte slices as `tail -c +<offset+1> | head -c 524288 | base64`, checks the reassembled length and sha256 against what the guest reported, and calls `extractTar`.

- [ ] **Step 4: Run, expect PASS.** **Step 5: Commit** — `git commit -m "Add copyIn and a hostile-guest copyOut"`

---

### Task 7: The opencode plugin

**Files:**
- Create: `plugin/package.json` (`{ "name": "rts-sandbox", "version": "0.0.0", "type": "module", "main": "index.ts", "exports": { ".": "./index.ts" } }`, because the loader needs a directory)
- Create: `plugin/index.ts` (default export `{ id: "rts-sandbox", setup }`, with no imports from `@opencode/*`)
- Create: `plugin/audit.ts`
- Test: `tests/unit/plugin.test.ts`

**Interfaces:**
- Consumes: `makeTools`, `MvmSandbox.attach`, `spawnRunner`.
- Produces: plugin options `{ machine: string; nonce: string; readyFile: string; auditFile: string; mvmctl: string; emptyGitConfig: string; provider: string; timeoutMs: number; maxOutputBytes: number }`, and the ready file containing exactly the nonce.
- `appendAudit(file, { tool, callID, inputSha256, status, durationMs })`, one JSON object per line.

- [ ] **Step 1: Write failing tests with a fake `ctx`.** The fake implements `tool.transform` / `tool.list` / `tool.hook`, `mcp.transform` / `mcp.list`, and `model.transform`, holding the 20 v2.1.4 tool IDs (spec, probe 2), MCP servers `g` and `p`, and models from providers `opencode` and `nearai`.

- After `setup`, `tool.list()` IDs equal the seven-tool allowlist; `mcp.list()` is empty; every model's `providerID` is `nearai`; the ready file contains the nonce.
- Running the transform twice gives the same result (idempotent).
- Each sandboxed tool keeps its original `input` schema, has `output` set to `undefined`, and its `execute` calls the `makeTools` function.
- If the fake's `tool.list()` still returns `webfetch` after the transform, `setup` throws `tool allowlist mismatch: webfetch` and no ready file exists. The same holds for an MCP server left over, and for a non-`nearai` model.
- `execute.before` for tool `webfetch` throws `tool not allowed in sandbox: webfetch`.
- `execute.after` appends one audit line with `inputSha256` = sha256 of `JSON.stringify(input)` and no raw input text.

- [ ] **Step 2: Run, expect FAIL.** **Step 3: Implement.** **Step 4: Run, expect PASS.**

- [ ] **Step 5: Commit** — `git commit -m "Add the sandbox plugin with allowlist and handshake"`

---

### Task 8: The launcher

**Files:**
- Create: `launcher/config.ts` (operator config: `image`, `inputsDir?`, `provider: { id: string; baseURL: string; models: string[]; apiKeyEnv: string }`, plus the limits)
- Create: `launcher/session.ts`
- Create: `launcher/main.ts` (CLI entry: `bun launcher/main.ts --config <path>`)
- Create: `opencode/README.md` (the pin, and how the generated config looks)
- Test: `tests/unit/session.test.ts`

**Interfaces:**
- Consumes: `MvmSandbox`, `spawnRunner`, the plugin's option shape.
- Produces: `writeOpencodeConfig(dir, o): string`, `preflight(o): Promise<void>`, `runSession(o): Promise<number>`.

- [ ] **Step 0: Verify the NEAR AI facts before coding.** Confirm from NEAR AI's current documentation, not from memory, the OpenAI-compatible base URL and one model ID, and record both with the source URL in `opencode/README.md`. Also confirm the provider-block shape that opencode v2.1.4's config schema accepts, at `packages/schema/src/config` for tag `v2.1.4`. If either can't be confirmed, stop and ask Zaki.

- [ ] **Step 1: Write failing unit tests.**

- `writeOpencodeConfig` produces JSON whose `plugin` is `[[<abs plugin dir>, options]]`, and the plugin path is a directory.
- The generated config contains no `mcp` key, and the API key appears only as an `{env:...}` reference, never as a value.
- The child env sets all four `XDG_*_HOME` variables under the session dir, cwd is an empty session `work/` dir, and argv includes `--standalone`.
- `preflight` rejects with `opencode 2.1.4 required, found 2.2.0` and with `mvmctl doctor failed` (fake runners).
- Orphan sweep: `machine ps` listing `rts-aaaaaaaaaaaa` and `web` removes only the first.
- The handshake rejects with `plugin did not report ready` when the ready file is missing at the deadline, and also when it holds a different nonce.

- [ ] **Step 2: Run, expect FAIL.**

- [ ] **Step 3: Implement `runSession`.** In order:
  1. Preflight, then the orphan sweep.
  2. `create`, then `copyIn` when `inputsDir` is set.
  3. Write the config and spawn `opencode --standalone` with inherited stdio.
  4. Wait for the ready file; if the deadline passes, kill opencode and go to teardown.
  5. Sample host RSS every 5 s.
  6. On child exit, SIGINT or SIGTERM: `copyOut` to `sessions/<id>/out`, then `remove`. Teardown runs once and logs each step's outcome.

  For RSS: before using `ps -o rss= -p <pid>`, find the per-machine `mvm-hvf-supervisor` PID from `machine inspect <name>` output. If v0.22.0 doesn't expose it, fall back to `pgrep -f` with the machine name and record which method worked in `opencode/README.md`.

- [ ] **Step 4: Run, expect PASS.** **Step 5: Commit** — `git commit -m "Add the session launcher"`

---

### Task 9: End-to-end containment and the leak check

**Files:**
- Create: `tests/contain/session.test.ts`
- Create: `tests/contain/leak.test.ts`

**Interfaces:**
- Consumes: `runSession` pieces, the plugin, `MvmSandbox`. To load the plugin without spending inference, these tests run `opencode run --standalone --model none/none "probe"`, the way probes 1 to 3 did: plugins load and the run fails at model resolution, before any request.

- [ ] **Step 1: Write the tests.**

- Allowlist through real opencode: with the generated config, the ready file appears, and `tools.jsonl` and the plugin's own debug line show exactly the seven tools.
- Refusals through real opencode, each leaving no ready file, so `runSession` refuses: a project `opencode.json` declaring an MCP server placed in the session's `work/` dir (and its sentinel is not created); a second plugin directory in the config that adds a tool named `stray`; the plugin configured as a file path instead of a directory.
- Sentinels through the real plugin tools: `write` to `/tmp/rts-sentinel-<id>` and `shell` running `touch /tmp/rts-sentinel2-<id>` both exist in the guest per `guestSha256` / `test -e`, and neither exists on the host.
- Lost VM: after `mvmctl machine stop` mid-session, the next tool call rejects with `SandboxUnavailable` and the host sentinel check is still clean.
- Teardown: sending SIGINT to `runSession` leaves no `rts-` machine and exports `/out`.
- Leak check (`leak.test.ts`): with `RTS_TEST_LEAK=shell`, the `makeTools` test seam swaps `shell` for a host `Bun.spawn`. The sentinel test is then run against it and must fail. The test asserts the inner run fails and passes only on that failure.

- [ ] **Step 2: Run** — `bun test tests/contain`, expect PASS, and `mvmctl machine ps` shows no `rts-` entries afterwards.

- [ ] **Step 3: Live smoke, opt-in, manual.** With `RTS_LIVE=1` and a NEAR AI key in the env named by `apiKeyEnv`, run one session with the prompt `create /out/hello.txt containing hi, then stop`. Confirm `sessions/<id>/out/hello.txt` contains `hi` and `tools.jsonl` has a `write` line. Paste the output into the PR.

- [ ] **Step 4: Commit** — `git commit -m "Add end-to-end containment tests and the leak check"`

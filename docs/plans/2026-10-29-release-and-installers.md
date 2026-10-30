# Releases, the curl installer, and the Homebrew tap: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An operator on an Apple silicon Mac gets a working `rts launch` from `curl ... | bash` or `brew install nearai/tap/rts`: a signed, notarized `rts` and patched supervisor from a GitHub release, then `rts setup` fetches mvm v0.22.0, opencode v2.2.2 and the guest image, each pinned by digest.

**Architecture:** `rts` learns where it is installed (`src/install.rs`: `current_exe`, `canonicalize`, parent of `bin/`) and resolves the plugin, supervisor, mvmctl, opencode and sessions directory from that prefix, the home directory, or the source checkout, with explicit settings first. A new `rts setup` (`src/setup.rs`) downloads through a one-hop `Fetch` seam that follows at most five redirects, each to one of three exact GitHub hosts, streams with a size cap through `sha2`, checks the pinned digest before unpacking with `/usr/bin/tar` or `/usr/bin/ditto` into a temp directory, and renames it into place; then it runs `mvmctl env sign`, `mvmctl doctor`, the supervisor probes, `opencode --version` and `mvmctl image pull`. The release workflow (`.github/workflows/release.yml`) runs the test gate, builds, signs, notarizes, packages with `scripts/package-release.sh` (runnable locally), attests, publishes, and commits the rendered formula to `nearai/homebrew-tap`. `install.sh` checks `SHA256SUMS` and, when `gh` exists, the provenance attestation, then places only the files the tarball owns and runs `rts setup`.

**Tech Stack:** Rust 2024 (`rts`, `cargo test`), `reqwest` 0.12 blocking, `sha2` 0.11, `url` 2, `tempfile` 3 (all already direct, `Cargo.toml:36-43`); bash for `install.sh` and the release scripts (`shellcheck` 0.11.0 and `actionlint` 1.7.12 are installed on this host); bun 1.3.3 for the script tests; GitHub Actions on `macos-26` (superseded during implementation: this line first said `macos-15`; the Global Constraints below set `macos-26`); Ruby only as `ruby -c` on the rendered formula.

**Spec:** `docs/specs/2026-10-29-release-and-installers-design.md`, all sections (read it first; this plan does not restate the rationale). The re-pin gate also reads `docs/specs/2026-10-27-sandboxed-opencode-design.md`, checks 1 to 3 and the sandbox plugin section.

## Global Constraints

- Before Task 1: `git fetch nearai`. If `near-production` has merged into `nearai/main`, merge `nearai/main` into `release-installers` first (it changes the TLS pin to SPKI, `DEFAULT_MODELS` to `deepseek-ai/DeepSeek-V4.1-Flash-1017-abliterated`, `opencode/attestation-policy.json`, `opencode/session.example.json`, and makes the attestation report key optional; it does not change the opencode version check or path discovery). It also fixes the plugin's model check: on 2026-10-29 a real launch failed with `model allowlist mismatch: missing nearai-red-embedded/deepseek-ai/DeepSeek-V4.1-Flash-1017-abliterated` because opencode listed no provider models at plugin setup (its `model.updated` events came after the plugin load), so the plugin now refuses only extra models, and `rts`'s `check_provider` remains the presence check. With that ordering, the containment suite's `debug["providerModels"] == 1` assertion may see 0 at setup; if it does, record the measurement and change the assertion to the filtered model list after load, not back to a presence check in the plugin. If it has not merged, proceed and note in the PR that a later merge may conflict in `src/config.rs` and `opencode/session.example.json`. Check for divergence before merging and stop and ask if `git merge` reports conflicts outside those two files.
- Signing, notarization and release conventions follow TraceCommons/trace-commons `.github/workflows/release-contributor.yml` (read it with `gh api repos/TraceCommons/trace-commons/contents/.github/workflows/release-contributor.yml --jq .content | base64 -d`), decided by Zaki 2026-10-29. This overrides the spec's secret names, runner and job layout where they differ:
  - Secret names, identical to trace-commons so the values can be copied: `MACOS_CERTIFICATE_P12_BASE64`, `MACOS_CERTIFICATE_PASSWORD`, `MACOS_SIGNING_IDENTITY`, `MACOS_NOTARY_ASC_KEY_P8_BASE64`, `MACOS_NOTARY_ASC_KEY_ID`, `MACOS_NOTARY_ASC_ISSUER_ID`, `HOMEBREW_TAP_TOKEN` (superseded 2026-10-30: the operator cannot create a fine-grained token on the `nearai` org, so `HOMEBREW_TAP_TOKEN` was replaced by `HOMEBREW_TAP_DEPLOY_KEY`, the private half of a write deploy key on `nearai/homebrew-tap`, and the tap is updated by an SSH push to its `main`; see the spec's pipeline step 10 and the workflow).
  - Runner `macos-26` (retired labels such as `macos-13` queue forever instead of failing). Actions pinned by commit SHA.
  - Workflow-level `permissions: contents: read, id-token: write, attestations: write`; the signing job declares `environment: release`; only the separate publish job (ubuntu) gets `contents: write`.
  - A first `release-config` job fails a tag push early when `HOMEBREW_TAP_TOKEN` is missing (superseded 2026-10-30: `HOMEBREW_TAP_DEPLOY_KEY`).
  - Temporary keychain: capture `security list-keychains -d user` before changing it and restore it in an EXIT trap; decode the .p12 and .p8 under `umask 077` with `chmod 600`, delete them in the trap; `security set-key-partition-list -S apple-tool:,apple:,codesign:`.
  - `xcrun notarytool submit --wait --output-format json`, then refuse unless the JSON `status` is exactly `Accepted` (the exit status is not reliable).
  - Recompute every checksum after `codesign` (signing rewrites the bytes); SHA256SUMS and the attestations cover the signed artifacts.
  - Tap update: clone `nearai/homebrew-tap` with the token in the remote URL (`https://x-access-token:${GH_TOKEN}@github.com/...`; GH_TOKEN alone does not authenticate `git push`), `--depth 1 --single-branch`, rebuild the bump branch from the default branch each run, force-push it, open a pull request and merge it in the workflow; hashes come only from this run's artifacts. (Superseded 2026-10-30: the workflow now writes `HOMEBREW_TAP_DEPLOY_KEY` to a 0600 file deleted in an EXIT trap, pins GitHub's published SSH host keys with `StrictHostKeyChecking=yes`, clones `git@github.com:nearai/homebrew-tap.git` `--depth 1 --single-branch --branch main`, commits as `github-actions[bot]`, and pushes to `main` with no pull request and no force-push, re-cloning and retrying once on a rejected push.)
- Every cargo command uses `RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0`. Below, `T` stands for `RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0 cargo test`.
- Baseline, measured 2026-10-29: `T --lib` = 230 passed, 5 failed, 1 ignored; `T --bin rts` = 17 passed; `bun test tests/unit` = 23 pass, 0 fail. The five failures are pre-existing and out of scope: `copy::tests::a_long_name_is_refused`, `copy::tests::a_symlink_to_a_host_path_is_refused`, `copy::tests::a_hardlink_is_refused`, `copy::tests::copy_out_is_byte_exact_across_slices`, `copy::tests::an_oversized_file_is_refused`. Before Task 1, re-run all three and paste the summary lines; if they differ, stop and report. After every task, `T --lib` shows exactly these five failures and no others, `T --bin rts` and `bun test tests/unit` pass in full. Never report "tests pass" from a filtered run.
- No new crates (spec Decisions). Zip extraction uses `/usr/bin/ditto`, tar uses `/usr/bin/tar`. `git diff Cargo.lock` must be empty after every task; anything else is a stop-and-ask. No new GitHub Actions beyond the four pinned below.
- Pinned values, copied from the spec:

| Item | Value |
|---|---|
| Target | `aarch64-apple-darwin` only |
| mvm | v0.22.0, `https://github.com/tinylabscom/mvm/releases/download/v0.22.0/mvmctl-aarch64-apple-darwin.tar.gz`, sha256 `1f2c80b253add28c3856080e3f3a10aa1163f1aef0a7d413ded15100bdcd0c69`, installed to `~/.local/mvm/v0.22.0/` |
| opencode | v2.2.2, `https://github.com/anomalyco/opencode/releases/download/v2.2.2/opencode-darwin-arm64.zip`, sha256 `c1c901a6379d667b7a30a3eea5a8f6e93416dba43e889e834771f6fb174f35c9`, installed to `~/.local/share/nearai-red-sandbox/opencode/2.2.2/opencode` |
| Guest image | `config::DEFAULT_IMAGE` (`src/config.rs:13`), via `mvmctl image pull` |
| Redirect hosts | exactly `github.com`, `objects.githubusercontent.com`, `release-assets.githubusercontent.com` |
| Supervisor marker | `rts-vsock-drain-v1`; contract `mvm-hvf-supervisor contract-version=4` (`scripts/build-patched-mvm-supervisor.sh:105-106`) |
| Tarball | `rts-<version>-aarch64-apple-darwin.tar.gz` holding `bin/rts`, `libexec/nearai-red-sandbox/mvm-hvf-supervisor`, `libexec/nearai-red-sandbox/mvm-hvf-supervisor.build-info`, `share/nearai-red-sandbox/plugin/`, `share/nearai-red-sandbox/opencode/session.example.json`, `LICENSE`, `README.md` |
| Release base | `https://github.com/nearai/nearai-red-sandbox/releases/download/v<version>`; `RTS_RELEASE_BASE` overrides |
| Install prefix | `~/.local` for `install.sh` (`RTS_INSTALL_PREFIX` overrides); the keg for Homebrew |
| Signing | `codesign --sign "Developer ID Application: ..." --options runtime --timestamp`; supervisor adds an entitlements file with `com.apple.security.hypervisor`; verify with `codesign --verify --strict` and, after notarization, `spctl --assess --type install -vv` whose output must contain `source=Notarized Developer ID` (not `--type execute`, which rejects every bare Mach-O CLI as "not an app", exit 3) |
| Secrets | The trace-commons names from the Global Constraints: `MACOS_CERTIFICATE_P12_BASE64`, `MACOS_CERTIFICATE_PASSWORD`, `MACOS_SIGNING_IDENTITY`, `MACOS_NOTARY_ASC_KEY_P8_BASE64`, `MACOS_NOTARY_ASC_KEY_ID`, `MACOS_NOTARY_ASC_ISSUER_ID` (may live in the `release` environment), and `HOMEBREW_TAP_TOKEN` (must be a repository or organization secret: `release-config` and publish run without an environment). Superseded during implementation: this row first listed `APPLE_*` names copied from the spec. Superseded 2026-10-30: `HOMEBREW_TAP_TOKEN` is replaced by `HOMEBREW_TAP_DEPLOY_KEY` (the private half of the write deploy key on `nearai/homebrew-tap`), under the same repository-or-organization rule. |

- Measured 2026-10-29 for this plan: the mvm asset is 26,900,038 bytes and unpacks under one top-level directory `mvmctl-aarch64-apple-darwin/` (so `tar --strip-components 1`); the opencode asset is 103,297,720 bytes and holds one entry, `opencode`. Size caps: mvm `64 << 20`, opencode `256 << 20`. Both digests were re-checked against GitHub's `digest` field and a local `shasum -a 256`. `mvmctl image inspect <ref>` exits 0 for a cached image and 1 otherwise. The patched supervisor links only system frameworks and `/usr/lib` (`otool -L`). mvm wrote `mvm-hvf-supervisor.mvm-hvf-signed` beside the patched supervisor without changing its hash, so the supervisor's directory must stay user-writable.
- Pinned actions (looked up 2026-10-29 with `gh api`): `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` (v7.0.1), `oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6` (v2.2.0), `actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8` (v4.2.2), `actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9` (v7.0.2).
- `rts setup` never deletes anything outside `~/.local/mvm/v0.22.0`, `~/.local/share/nearai-red-sandbox/opencode/2.2.2` and its own `.rts-setup-*` temp directories beside them. An existing target that fails verification is refused with the path and "remove it and re-run rts setup", never replaced. Nothing falls back to an unverified copy or an unpinned version. Every error names the component, the URL or path, and the fix.
- Task 1 runs real mvm (v0.22.0 and the patched supervisor are installed; no other session owns VMs now). It runs `tests/contain` and `mvmctl`, and must leave no `rts-*` machine: `mvmctl machine ls` before and after shows none it created. No other task starts a VM. Do not touch other worktrees or `/private/tmp/nearai-red-sandbox.*`.
- Commit style: short imperative subject, no prefix, no emojis, ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Do not push.

## Review Focus

1. `install.sh` replaces only what the tarball owns. With prefix `~/.local`, `share/nearai-red-sandbox/` is also where `rts setup` puts opencode (`opencode/2.2.2/`), where the source-built supervisor lives, and possibly sessions; replacing the whole directory would delete them. It replaces exactly `bin/rts`, `libexec/nearai-red-sandbox/`, `share/nearai-red-sandbox/plugin/` and `share/nearai-red-sandbox/opencode/session.example.json`. Test in Task 6.
2. Digest before unpack, and no partial version: a mismatch deletes the download and leaves no target; a failed unpack leaves no target and no temp directory; a stale `.rts-setup-*` from a killed run is removed; an existing target that fails verification is refused, not replaced. Tests in Task 3.
3. The redirect allowlist is exact: `https` only, host equal (not suffix) to one of three names, no explicit port other than 443, no userinfo, at most five hops, each hop checked before it is fetched. Tests in Task 3.
4. Homebrew's `bin/rts` is a symlink into the Cellar: `install_prefix` canonicalizes before taking the parent of `bin/`, and a source build (`target/debug/rts`, `target/debug/deps/rts-<hash>`) yields no prefix, so it keeps finding `plugin/` and `sessions/` in the checkout. Explicit config and environment always win. Tests in Task 2.
5. `rts setup --check` downloads nothing and runs no mutating command (`env sign`, `image pull`); `--check --offline` runs no `mvmctl` at all. `env sign` never receives `MVM_HVF_SUPERVISOR_PATH`, so mvm cannot re-sign the Developer ID supervisor. Tests in Task 4.

---

### Task 1: Re-pin opencode to 2.2.2 behind the probes (real mvm)

A gate: the constant moves only after the probes pass on 2.2.2. If 2.2.2 behaves differently, record the measurement and fix the plugin in this task.

**Files:**
- Modify: `src/session.rs` (`OPENCODE_VERSION`, `:24`; comments `:89`, `:107`; fake `--version` output `:902`)
- Modify: `src/main.rs` (fake `--version` output `:605`)
- Modify: `src/terminal.rs` (ignored test text and version match `:496`, `:504`, `:542`)
- Modify: `tests/contain/harness.rs` (`:3`, `:216`, `:231`), `tests/contain/main.rs` (`:1`), `tests/contain/session.rs` (`:1`, two new tests)
- Modify: `plugin/index.ts` (header `:1`, `:11`), `tests/unit/plugin.test.ts` (`V214_TOOLS` `:8-15`, `:19`)
- Modify: `opencode/README.md` (`:34`, Pin `:65-71`, config shape `:91-94`)
- Modify: `docs/specs/2026-10-27-sandboxed-opencode-design.md` (new check 8 recording the 2.2.2 measurements)

**Interfaces:**
- Consumes: `session::OPENCODE_VERSION`; the contain harness `opencode()` (`tests/contain/harness.rs:78-94`, reads `RTS_OPENCODE`); `probe`, `configure`, `edit_config`, `ready_holds` (`tests/contain/session.rs:66-88`); the stray-plugin pattern (`tests/contain/session.rs:124-145`); the plugin's `debugFile` JSON `{ tools, mcp, providerModels }` (`plugin/index.ts:157-159`).
- Produces: `pub const OPENCODE_VERSION: &str = "2.2.2";` and, in `tests/contain/session.rs`, `const BUILTIN_TOOLS: &[&str]` holding the measured 2.2.2 IDs.

- [ ] **Step 1: Stage 2.2.2 outside the home layout.** Download the opencode URL above into a new scratch directory, check `shasum -a 256` equals the pinned digest (stop if not), `ditto -x -k` it into a separate empty directory, and confirm `<dir>/opencode --version` prints `2.2.2` (with or without a leading `opencode v`). Record `mvmctl machine ls` (with `GIT_CONFIG_GLOBAL` pointing at an empty file).

- [ ] **Step 2: Write the tool-inventory probe and prove it on 2.1.4 (check 2).** Add a contain test that loads a probe plugin before ours (stray-plugin pattern) whose `setup` writes the IDs from `ctx.tool.transform(editor => editor.list())` to `<root>/tools.json`, then runs `probe`:

```rust
const BUILTIN_TOOLS: &[&str] = &[/* the 20 IDs of V214_TOOLS, tests/unit/plugin.test.ts:10-15, until Step 4 */];
#[test]
#[ignore = "real mvm and opencode"]
fn opencode_offers_exactly_the_recorded_built_in_tools() {
    // ...probe plugin first, ours second, probe(&oc, &s.p)...
    let mut seen: Vec<String> = serde_json::from_str(&fs::read_to_string(s.root.join("tools.json")).unwrap()).unwrap();
    seen.sort();
    let mut want: Vec<String> = BUILTIN_TOOLS.iter().map(|t| t.to_string()).collect();
    want.sort();
    assert_eq!(seen, want);
    assert!(ready_holds(&s.p, &nonce));
}
```

  Run it against `PATH`'s opencode 2.1.4 before anything moves (`... cargo test --test contain opencode_offers -- --ignored`). Expected: it passes if `V214_TOOLS` holds the real IDs, or FAILs printing the real 2.1.4 list (the unit test says some IDs are stand-ins); either way the probe plugin is shown to work. Fix `BUILTIN_TOOLS` to the printed 2.1.4 list if it differed.

- [ ] **Step 3: Add the global-config MCP probe (check 3).** Today only project config is covered (`tests/contain/session.rs:106-121`).

```rust
#[test]
#[ignore = "real mvm and opencode"]
fn an_mcp_server_in_the_global_config_never_spawns() {
    // configure(), then edit_config(&file, |c| c["mcp"] = json!({ "evil": { "type": "local",
    //   "command": ["sh", "-c", "touch '<root>/mcp-global'; sleep 5"] } }))
    // probe; sleep 2 s
    assert!(!sentinel.exists());
    assert!(ready_holds(&s.p, &nonce));
    assert_eq!(debug["mcp"], json!([]));
}
```

  Run it on 2.1.4: expect PASS. Measure the control the spec's check 3 describes as a one-off, not a test: with our plugin removed from the config, the sentinel appears.

- [ ] **Step 4: Move the pin, then measure 2.2.2.** `OPENCODE_VERSION = "2.2.2"` (the harness panics on any other version, `tests/contain/harness.rs:83-93`, so the pin moves before the 2.2.2 runs; if the probes cannot be made to pass in Step 5, revert the whole task and stop: nothing lands). Update every `2.1.4` site listed under Files, including the fakes (`"2.2.2\n"`), and `tests/contain/harness.rs:231`'s rejected versions to `["2.2.0\n", "2.2.20\n"]` plus the existing exit-code and killed cases on `"2.2.2\n"`. Run `T --lib` and `T --bin rts`: expect only the five baseline failures. `grep -rn "2\.1\.4" src tests plugin` returns nothing; in `opencode/README.md` it survives only in a note saying the pin moved from 2.1.4; the spec files keep their history. Export `RTS_OPENCODE=<dir>/opencode`, run `opencode_offers_exactly_the_recorded_built_in_tools` again, and if it FAILs, pin the printed 2.2.2 list in `BUILTIN_TOOLS`, mirror it into `tests/unit/plugin.test.ts` (rename `V214_TOOLS` to `BUILTIN_TOOLS`, comment naming 2.2.2 and this test), and record the count and IDs in the new check 8. If `question` is absent or a new ID is not plainly a non-sandboxed built-in, stop and ask: the allowlist (`plugin/index.ts:22`) is a design decision.

- [ ] **Step 5: Run the full containment suite on 2.2.2.** `RTS_OPENCODE=<dir>/opencode RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0 cargo test --test contain -- --ignored --test-threads=1`. Expected: every test passes, including the ready-file handshake (`the_plugin_loads_reports_ready_and_leaves_exactly_the_seven_tools`), `--standalone` probing, the file-path skip, the model allowlist (`debug["providerModels"] == 1`), and the two new tests. Run the leak check the suite documents (`tests/contain/session.rs:159-161`). If anything fails because 2.2.2 changed an API (`ctx.tool`, `ctx.mcp`, `ctx.model`, plugin config shape), read `packages/plugin/src/promise/*.ts` and `packages/core/src/config/normalize.ts` at tag `v2.2.2`, fix `plugin/index.ts` and `tests/unit/plugin.test.ts` here, and record what changed in check 8 and `opencode/README.md`. A failure unrelated to opencode (one that also fails on 2.1.4 with the pin reverted) is recorded separately in the PR, not treated as a 2.2.2 regression; stop and ask before working around it.

- [ ] **Step 6: Clean up and record.** `mvmctl machine ls` shows no `rts-*` machine that was not there in Step 1; remove any this task created with `mvmctl machine rm --force --yes <name>`. Write check 8 ("Done 2026-10-29: opencode v2.2.2 ...") with the tool IDs, MCP results (global, project, control), model allowlist, handshake, `--standalone`, and the suite's summary line. Update `opencode/README.md`'s Pin section to v2.2.2 with the source paths at tag `v2.2.2`.

- [ ] **Step 7: Run, expect PASS** — `T --lib`: the five baseline failures only; `T --bin rts` 17 passed; `bun test tests/unit` passes.

- [ ] **Step 8: Commit** — `git add src tests plugin opencode/README.md docs/specs/2026-10-27-sandboxed-opencode-design.md && git commit -m "Pin opencode 2.2.2 after re-running the plugin probes"`

---

### Task 2: Install layout and path discovery

**Files:**
- Create: `src/install.rs`; Modify: `src/lib.rs` (`pub mod install;`)
- Modify: `src/config.rs` (`Defaults` `:195-214`, its uses in `parse_config` `:310-317`, test helper `:332-338`)
- Modify: `src/session.rs` (`supervisor_path` `:266-279`, its call `:543`, `SUPERVISOR_INSTALL` `:262`, opencode errors `:303-313`, doctor error `:325-329`, tests `:945-958`, `:1003`, `:719`, `:1192`)
- Modify: `src/main.rs` (`local_preflight` `:160`, `launch` `:256`, `default_config` `:397`)
- Modify: `tests/contain/harness.rs` (`supervisor_path` call `:34`)

**Interfaces:**
- Consumes: `std::env::current_exe`, `std::fs::canonicalize`; `Deps.rts` (`src/session.rs:435`, the current exe).
- Produces (`src/install.rs`):

```rust
pub const MVM_VERSION: &str = "0.22.0";
/// <prefix> when `exe`, canonicalized, sits in a directory named exactly `bin`.
pub fn install_prefix(exe: &Path) -> Option<PathBuf>;
/// install_prefix(current_exe()), None on any error.
pub fn current_prefix() -> Option<PathBuf>;
pub fn prefix_plugin(prefix: &Path) -> PathBuf;      // <prefix>/share/nearai-red-sandbox/plugin
pub fn prefix_supervisor(prefix: &Path) -> PathBuf;  // <prefix>/libexec/nearai-red-sandbox/mvm-hvf-supervisor
pub fn home_supervisor(home: &Path) -> PathBuf;      // <home>/.local/share/nearai-red-sandbox/mvm-hvf-supervisor
pub fn mvm_dir(home: &Path) -> PathBuf;              // <home>/.local/mvm/v0.22.0
pub fn opencode_dir(home: &Path) -> PathBuf;         // <home>/.local/share/nearai-red-sandbox/opencode/2.2.2
pub struct Lookup<'a> {
    pub source: &'a Path,              // env!("CARGO_MANIFEST_DIR")
    pub prefix: Option<&'a Path>,
    pub home: &'a Path,
    pub cwd: &'a Path,
    pub rts_mvmctl: Option<&'a Path>,  // RTS_MVMCTL
}
pub fn defaults(l: &Lookup) -> crate::config::Defaults;
```

- Produces (`src/config.rs`), replacing `Defaults { repo, mvmctl }`:

```rust
pub struct Defaults {
    pub mvmctl: PathBuf,
    pub plugin_dir: PathBuf,
    pub opencode: String,
    pub sessions_dir: PathBuf,
}
impl Defaults { pub fn from_env() -> Result<Self, String> } // HOME, RTS_MVMCTL, current_dir, current_prefix
```

  `defaults` follows the spec's lookup table after config values (which `parse_config` already applies first): `plugin_dir` is `prefix_plugin(p)` if it is a directory, else `source/plugin`; `mvmctl` is `rts_mvmctl`, else `mvm_dir(home)/mvmctl`; `opencode` is `opencode_dir(home)/opencode` if it is a file, else `"opencode"`; `sessions_dir` is `cwd/sessions` when `prefix_plugin(p)` is a directory (an installed `rts`), else `source/sessions`. The sessions default is not in the spec: a release binary's `CARGO_MANIFEST_DIR` is the CI runner's checkout, so it cannot stay `repo/sessions` (see the report's open questions).

- Produces (`src/session.rs`):

```rust
pub fn supervisor_path(env: &[(String, String)], prefix: Option<&Path>) -> Result<PathBuf, String>;
pub fn check_opencode(host: &dyn Host, opencode: &str) -> Result<(), String>; // extracted from preflight :303-313
```

  `supervisor_path` order: `MVM_HVF_SUPERVISOR_PATH` (unchanged rules, no fallback from an empty or relative value); `prefix_supervisor(prefix)` if it is a file; `home_supervisor(HOME)`. Callers: `local_preflight` passes `install::current_prefix().as_deref()`; `run_session` passes `install::install_prefix(&deps.rts).as_deref()`; the contain harness passes `None`. `SUPERVISOR_INSTALL` becomes `"Run rts setup; from a source checkout, run scripts/build-patched-mvm-supervisor.sh to install the patched mvm v0.22.0 supervisor in ~/.local/share/nearai-red-sandbox/mvm-hvf-supervisor, or set MVM_HVF_SUPERVISOR_PATH to its absolute path"`. `check_opencode`'s three errors end with `; run rts setup`. A doctor failure whose spawn error is `NotFound` says `mvmctl not found at <path>; run rts setup`.

- [ ] **Step 1: Write the failing tests** (`src/install.rs`; temp dirs from `tempfile`).

```rust
#[test]
fn a_symlinked_bin_rts_resolves_to_its_keg() {
    // <t>/Cellar/rts/1.0.0/bin/rts (file), <t>/brew/bin/rts -> that file
    assert_eq!(install_prefix(&t.join("brew/bin/rts")), Some(t.join("Cellar/rts/1.0.0").canonicalize().unwrap()));
    assert_eq!(install_prefix(&t.join("Cellar/rts/1.0.0/bin/rts")), Some(t.join("Cellar/rts/1.0.0").canonicalize().unwrap()));
}
#[test]
fn source_builds_have_no_prefix() {
    for p in ["target/debug/rts", "target/release/rts", "target/debug/deps/rts-0123abcd", "binx/rts"] {
        // created under <t>
        assert_eq!(install_prefix(&t.join(p)), None, "{p}");
    }
    assert_eq!(install_prefix(&t.join("missing/bin/rts")), None);
}
#[test]
fn an_installed_layout_supplies_plugin_and_sessions() {
    // <t>/prefix/share/nearai-red-sandbox/plugin/ exists
    let d = defaults(&Lookup { source: Path::new("/src"), prefix: Some(&prefix), home: &home, cwd: Path::new("/work"), rts_mvmctl: None });
    assert_eq!(d.plugin_dir, prefix.join("share/nearai-red-sandbox/plugin"));
    assert_eq!(d.sessions_dir, PathBuf::from("/work/sessions"));
    assert_eq!(d.mvmctl, home.join(".local/mvm/v0.22.0/mvmctl"));
    assert_eq!(d.opencode, "opencode");
    // after creating <home>/.local/share/nearai-red-sandbox/opencode/2.2.2/opencode:
    assert_eq!(d2.opencode, home.join(".local/share/nearai-red-sandbox/opencode/2.2.2/opencode").to_str().unwrap());
}
#[test]
fn a_source_build_keeps_the_checkout_paths_and_rts_mvmctl_wins() {
    let d = defaults(&Lookup { source: Path::new("/src"), prefix: None, home: &home, cwd: Path::new("/work"), rts_mvmctl: Some(Path::new("/x/mvmctl")) });
    assert_eq!((d.plugin_dir, d.sessions_dir, d.mvmctl), ("/src/plugin".into(), "/src/sessions".into(), "/x/mvmctl".into()));
    // a prefix without share/nearai-red-sandbox/plugin behaves like a source build
}
```

  In `src/config.rs` add `config_values_win_over_installed_defaults`: with `Defaults { plugin_dir: "/p/plugin", sessions_dir: "/p/sessions", opencode: "/p/opencode", mvmctl: "/p/mvmctl" }`, a config `{ "pluginDir": "pl", "sessionsDir": "s", "opencode": "/oc", "mvmctl": "/m", "provider": { "models": ["m"] } }` parsed with base `/cfg` yields `/cfg/pl`, `/cfg/s`, `/oc`, `/m`; `{}` yields the four `Defaults` values. In `src/session.rs` extend `supervisor_selection_uses_only_the_operator_environment_and_never_falls_back_from_an_override` (`:945`): with a temp prefix holding `libexec/nearai-red-sandbox/mvm-hvf-supervisor`, `supervisor_path(&env, Some(&prefix))` is that file; with the env override set it is the override; with a prefix lacking the file it is the home path; `MVM_HVF_SUPERVISOR_PATH=""` still errs. Add `missing_prerequisites_name_rts_setup`: `check_opencode` with a host whose `--version` errors, exits 1, or prints `2.1.4` returns errors containing `run rts setup`; the supervisor-marker failure contains both `rts setup` and `scripts/build-patched-mvm-supervisor.sh` (keep the assertion at `:1003`).

- [ ] **Step 2: Run, expect FAIL** — `T --lib install:: config::tests session::tests` fails to compile: `error[E0432]: unresolved import` / `cannot find function \`install_prefix\``, and `struct \`Defaults\` has no field named \`plugin_dir\``.

- [ ] **Step 3: Implement.** `install.rs` as above. `Defaults::from_env` builds a `Lookup` from `HOME` (empty path if unset, as today), `RTS_MVMCTL`, `current_dir()` (error `"Cannot determine current directory"`), `current_prefix()`, and `env!("CARGO_MANIFEST_DIR")`. `parse_config` uses `d.sessions_dir`, `d.opencode`, `d.plugin_dir`, `d.mvmctl` where it used `d.repo`/`"opencode"`. `launch` (`src/main.rs:256`) uses `config::Defaults::from_env()?`. The four test constructors (`src/config.rs:333`, `src/main.rs:397`, `src/session.rs:719`, `:1192`) become literals with `plugin_dir: "<repo>/plugin"`, `sessions_dir: "<repo>/sessions"`, `opencode: "opencode"` so their assertions (`src/config.rs:374-375`) hold. `preflight` calls `check_opencode`.

- [ ] **Step 4: Run, expect PASS** — `T --lib`: the five baseline failures only, with the new tests passing; `T --bin rts` passes; `T --test contain --no-run` compiles.

- [ ] **Step 5: Commit** — `git add src tests/contain/harness.rs && git commit -m "Find the plugin, supervisor and opencode from the install prefix"`

---

### Task 3: `rts setup` downloads: fetch, digest, unpack

**Files:**
- Create: `src/setup.rs`; Modify: `src/lib.rs` (`pub mod setup;`)

**Interfaces:**
- Consumes: `session::Host` (`src/session.rs:54-56`) for `/usr/bin/tar` and `/usr/bin/ditto`; `reqwest::blocking`, `sha2::Sha256`, `url::Url`, `tempfile::Builder`; `install::{mvm_dir, opencode_dir}`.
- Produces:

```rust
pub const ALLOWED_HOSTS: [&str; 3] = ["github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"];
pub const MAX_REDIRECTS: usize = 5;
pub fn allowed_url(url: &str) -> Result<url::Url, String>;
pub enum Hop { Redirect(String), Body(Box<dyn std::io::Read + Send>) }
pub trait Fetch: Send + Sync { fn get(&self, url: &url::Url) -> Result<Hop, String>; }
pub struct HttpsFetch { client: reqwest::blocking::Client } // redirect Policy::none(), connect 30 s, total 600 s, https_only
impl HttpsFetch { pub fn new() -> Result<Self, String> }
impl Fetch for HttpsFetch // 3xx with Location (resolved against the URL) -> Redirect; 2xx -> Body; else Err naming URL and status
pub struct Downloaded { pub sha256: String, pub bytes: u64 }
pub fn download(f: &dyn Fetch, url: &str, max_bytes: u64, out: &mut dyn std::io::Write) -> Result<Downloaded, String>;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unpack { TarGzStrip1, Zip }
#[derive(Debug, Clone)]
pub struct Component { pub name: &'static str, pub version: &'static str, pub url: String, pub sha256: String, pub max_bytes: u64, pub unpack: Unpack, pub binary: &'static str }
pub fn mvm() -> Component;      // "mvm", "0.22.0", pinned URL and digest, 64 << 20, TarGzStrip1, "mvmctl"
pub fn opencode() -> Component; // "opencode", "2.2.2", pinned URL and digest, 256 << 20, Zip, "opencode"
/// Download, check the digest, unpack into <parent>/.rts-setup-XXXX/unpacked, check `binary`, rename to `target`.
pub fn install_component(c: &Component, target: &Path, f: &dyn Fetch, host: &dyn crate::session::Host) -> Result<(), String>;
#[cfg(test)] pub struct FakeFetch { /* url -> Hop factory; recorded calls */ }
#[cfg(test)] impl FakeFetch { pub fn new() -> Self; pub fn body(&self, url: &str, bytes: Vec<u8>); pub fn redirect(&self, url: &str, to: &str); pub fn calls(&self) -> Vec<String>; }
```

  `allowed_url` errors (each naming the URL): not `https`; host not exactly in `ALLOWED_HOSTS`; explicit port other than 443; userinfo present. `download` checks every URL, the first included, with `allowed_url` before calling `get`; more than `MAX_REDIRECTS` redirects errs; it streams in 64 KiB chunks into `out` and the hasher and errs once the count exceeds `max_bytes` (`"<url> exceeds <max_bytes> bytes"`). `install_component`: first removes stale `.rts-setup-*` entries in `target.parent()` (only that prefix, only directories); creates the parent with `0o700` if missing; makes the temp dir with `tempfile::Builder::new().prefix(".rts-setup-").tempdir_in(parent)`; downloads to `<tmp>/download`; on digest mismatch deletes `<tmp>/download` and errs `"<name> <version>: sha256 mismatch for <url>: expected <want>, got <got>; nothing was installed"`; unpacks with `["/usr/bin/tar", "-xzf", <download>, "-C", <tmp>/unpacked, "--strip-components", "1"]` or `["/usr/bin/ditto", "-x", "-k", <download>, <tmp>/unpacked]` (600 s), refusing a nonzero exit or kill with the tool's stderr tail; requires `<tmp>/unpacked/<binary>` to be a regular file; `std::fs::rename(<tmp>/unpacked, target)`; the `TempDir` drop removes the rest. If `target` exists it errs `"<target> already exists"` (the caller decides skip or refuse before calling).

- [ ] **Step 1: Write the failing tests.** Fixtures are built in the test: a tar.gz made with `/usr/bin/tar -czf` over `top/mvmctl` (a two-line shell script) and a zip made with `/usr/bin/ditto -c -k` over `opencode`; each test builds a `Component` whose `sha256` is the fixture's digest and whose URL is `https://github.com/x/<name>`. `RealHost` runs the real `tar` and `ditto`.

```rust
#[test] fn allowed_urls_are_exact() {
    for ok in ["https://github.com/a/b", "https://objects.githubusercontent.com/x", "https://release-assets.githubusercontent.com/x?sig=1", "https://github.com:443/a"] { assert!(allowed_url(ok).is_ok(), "{ok}"); }
    for bad in ["http://github.com/a", "https://evil.example/a", "https://github.com.evil.example/a", "https://evilgithub.com/a",
                "https://sub.github.com/a", "https://github.com:8443/a", "https://u:p@github.com/a", "file:///etc/passwd", "not a url"] {
        assert!(allowed_url(bad).is_err(), "{bad}");
    }
}
#[test] fn a_redirect_to_an_unlisted_host_fails_before_it_is_fetched() {
    // FakeFetch: github.com/x/mvm -> redirect https://evil.example/m
    let e = download(&f, "https://github.com/x/mvm", 1 << 20, &mut Vec::new()).unwrap_err();
    assert!(e.contains("evil.example"), "{e}");
    assert_eq!(f.calls(), ["https://github.com/x/mvm"]);
}
#[test] fn redirects_within_the_allowlist_are_followed_up_to_five() {
    // a chain of 5 redirects ending in a body succeeds; 6 fails with "redirects"
}
#[test] fn an_oversized_body_fails() { /* body 1025 bytes, max 1024 -> Err contains "exceeds 1024 bytes" */ }
#[test] fn a_digest_mismatch_deletes_the_download_and_installs_nothing() {
    let mut c = fixture_component(); c.sha256 = "00".repeat(32);
    let e = install_component(&c, &target, &f, &RealHost).unwrap_err();
    assert!(e.contains(&"00".repeat(32)) && e.contains(&real_digest) && e.contains("sha256 mismatch"), "{e}");
    assert!(!target.exists());
    assert_eq!(leftovers(&parent), Vec::<String>::new()); // no .rts-setup-* entries
}
#[test] fn a_tarball_is_unpacked_flat_and_renamed_into_place() { /* target/mvmctl exists and is executable; no .rts-setup-* left */ }
#[test] fn a_zip_is_unpacked_with_ditto() { /* target/opencode exists */ }
#[test] fn an_interrupted_unpack_leaves_no_partial_version() {
    // a Host whose tar writes <tmp>/unpacked/partial and returns RunOutput { killed: true, .. }
    assert!(install_component(&c, &target, &f, &killing_host).is_err());
    assert!(!target.exists());
    assert_eq!(leftovers(&parent), Vec::<String>::new());
}
#[test] fn a_stale_temp_dir_from_a_killed_run_is_removed() {
    // <parent>/.rts-setup-old/unpacked/mvmctl and <parent>/keep-me exist beforehand
    install_component(&c, &target, &f, &RealHost).unwrap();
    assert!(!parent.join(".rts-setup-old").exists());
    assert!(parent.join("keep-me").exists());
}
#[test] fn an_archive_without_the_binary_is_refused() { /* binary "mvmctl" absent -> Err names it; target absent */ }
#[test] fn the_pinned_components_match_the_spec() {
    assert_eq!(mvm().sha256, "1f2c80b253add28c3856080e3f3a10aa1163f1aef0a7d413ded15100bdcd0c69");
    assert_eq!(opencode().sha256, "c1c901a6379d667b7a30a3eea5a8f6e93416dba43e889e834771f6fb174f35c9");
    assert!(allowed_url(&mvm().url).is_ok() && allowed_url(&opencode().url).is_ok());
    assert_eq!((mvm().max_bytes, opencode().max_bytes), (64 << 20, 256 << 20));
}
```

- [ ] **Step 2: Run, expect FAIL** — `T --lib setup::` fails to compile: `error[E0583]: file not found for module \`setup\``.

- [ ] **Step 3: Implement** `src/setup.rs` as specified. No network in any test; `HttpsFetch` is exercised only in Task 4's live check.

- [ ] **Step 4: Run, expect PASS** — `T --lib`: the five baseline failures only. `git diff Cargo.lock` is empty.

- [ ] **Step 5: Commit** — `git add src/lib.rs src/setup.rs && git commit -m "Download and unpack pinned components for rts setup"`

---

### Task 4: `rts setup` checks, flags and the CLI

**Files:**
- Modify: `src/setup.rs` (checks and `run`)
- Modify: `src/session.rs` (supervisor probes as functions, contract constants next to `:260-262`)
- Modify: `src/main.rs` (`Action` `:14-24`, `parse_args` `:26-124`, `USAGE` `:143`, `main` `:346-386`, tests `:758-811`)

**Interfaces:**
- Consumes: `install_component`, `mvm()`, `opencode()`, `HttpsFetch` (Task 3); `install::*`, `Defaults::from_env`, `supervisor_path(env, prefix)`, `check_opencode` (Task 2); `mvm::{Runner, SpawnRunner, RunOutput}` (`src/mvm.rs:27-91`); `session::mvm_environment` (`src/session.rs:282-288`); `config::DEFAULT_IMAGE`.
- Produces (`src/session.rs`):

```rust
pub const SUPERVISOR_CONTRACT_PROBE: &str = "--contract-version";
pub const SUPERVISOR_CONTRACT: &str = "mvm-hvf-supervisor contract-version=4";
pub fn check_supervisor_marker(host: &dyn Host, path: &Path) -> Result<(), String>;   // extracted from preflight :316-324, same rules and messages
pub fn check_supervisor_contract(host: &dyn Host, path: &Path) -> Result<(), String>; // exact stdout, optional one trailing "\n", 5 s, exit 0, not killed
```

  `preflight` keeps calling only the marker check (the spec leaves preflight's requirements unchanged).

- Produces (`src/setup.rs`):

```rust
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SetupOptions { pub check: bool, pub offline: bool }
pub struct SetupContext<'a> {
    pub home: &'a Path,
    pub defaults: &'a crate::config::Defaults,
    pub explicit_mvmctl: bool,                  // RTS_MVMCTL set: verify it, never download
    pub supervisor: &'a Path,                   // from supervisor_path(env, prefix)
    pub rts: &'a Path,                          // current exe
    pub fetch: &'a dyn Fetch,
    pub host: &'a dyn crate::session::Host,     // opencode, supervisor, tar, ditto, codesign
    pub mvm_plain: &'a dyn crate::mvm::Runner,  // env: HOME and MVM_HOME only; for env sign
    pub mvm: &'a dyn crate::mvm::Runner,        // env: mvm_environment(env, supervisor); doctor, image
}
/// Ok: one summary line per component ("<name> <version> <path>"). Err: every failure, one per line.
pub fn run(o: &SetupOptions, c: &SetupContext) -> Result<Vec<String>, String>;
/// `run` with the two components supplied, so tests serve fixtures; `run` passes `(&mvm(), &opencode())`.
pub(crate) fn run_with(o: &SetupOptions, c: &SetupContext, components: (&Component, &Component)) -> Result<Vec<String>, String>;
/// The environment for `mvm_plain`: only HOME and MVM_HOME from `env`, never MVM_HVF_SUPERVISOR_PATH.
pub fn plain_mvm_env(env: &[(String, String)]) -> std::collections::HashMap<String, String>;
pub fn verify_mvm(mvm: &dyn crate::mvm::Runner) -> Result<(), String>; // ["--version"] through mvm_plain (keeps GIT_CONFIG_GLOBAL empty); stdout trimmed == "mvmctl 0.22.0"
```

  `run` without `--check`, stopping at the first failure: (1) mvm: if `explicit_mvmctl`, `verify_mvm`; else if `mvm_dir(home)` exists, `verify_mvm` or err `"<dir> exists but is not mvm 0.22.0: remove it and re-run rts setup"`; else `install_component(&mvm(), &mvm_dir(home), ..)` then `verify_mvm`. (2) `mvm_plain`: `["env", "sign"]` (120 s), exit 0. (3) `mvm`: `["doctor"]` (60 s), exit 0. (4) `check_supervisor_marker` then `check_supervisor_contract` on `supervisor`. (5) opencode at `opencode_dir(home)/opencode`: present and `check_opencode` passes, skip; present and fails, refuse as for mvm; absent, `install_component(&opencode(), &opencode_dir(home), ..)` then `check_opencode`. (6) `mvm`: `["image", "inspect", DEFAULT_IMAGE]` (60 s) exit 0 skips; else `["image", "pull", DEFAULT_IMAGE]` (1800 s) exit 0. With `--check`: (1), (4) and (5) always run, (3) and (6) run only when (1) passed (a missing or wrong mvmctl already failed, and running it again only repeats that), and (2) is skipped; there is no `install_component`, no `env sign`, no `image pull`; a missing component is a failure naming `run rts setup`; failures are collected. (Superseded during implementation: this first said every check in (1) to (6) runs; `src/setup.rs` `run_with` is the reference.) With `--check --offline`: only `<plugin_dir>/package.json` and `<plugin_dir>/index.ts` are files, both supervisor probes, and `["/usr/bin/codesign", "--verify", "--strict", <path>]` exits 0 for `rts` and the supervisor; no `mvm_plain` or `mvm` call at all.

- Produces (`src/main.rs`): `Action::Setup(setup::SetupOptions)` and `Action::Version`; `fn setup_command(o: &setup::SetupOptions) -> Result<i32, String>` builds the real context (`HttpsFetch::new()?`, `RealHost`, two `SpawnRunner`s, `extra_env` `plain_mvm_env(&env)` and `mvm_environment(&env, &supervisor)`, with an empty `GIT_CONFIG_GLOBAL` file in a private temp dir as `local_preflight` does at `src/main.rs:147-157`), prints each summary line, and returns 0. `--version`/`-V` prints `rts <CARGO_PKG_VERSION>`. `USAGE` gains `rts setup [--check [--offline]]` and `rts --version`.

- [ ] **Step 1: Write the failing tests** (`src/setup.rs`). A `Recorder` implements `Host` and `Runner`, answering from a closure and recording argv. Fixtures: a temp home; a supervisor path the recorder answers for; `FakeFetch` serving Task 3-style fixtures, passed to `run_with` as fixture `Component`s.

```rust
#[test] fn a_fresh_setup_installs_signs_checks_and_pulls_in_order() {
    // calls: fetch mvm; mvm_plain ["--version"]; mvm_plain ["env","sign"]; mvm ["doctor"]; host <sup> --rts-vsock-drain-fix-version, <sup> --contract-version;
    //        fetch opencode; host <oc> --version; mvm ["image","inspect",DEFAULT_IMAGE] (exit 1); mvm ["image","pull",DEFAULT_IMAGE]
    assert_eq!(lines.len(), 4); // mvm, supervisor, opencode, image
    assert!(lines[0].contains("mvm 0.22.0") && lines[0].contains(".local/mvm/v0.22.0"));
}
#[test] fn a_correct_install_is_skipped() { /* second run: f.calls() is empty; no "pull" */ }
#[test] fn env_sign_never_sees_the_supervisor_override() {
    let env = [("HOME".into(), "/h".into()), ("MVM_HOME".into(), "/m".into()), ("MVM_HVF_SUPERVISOR_PATH".into(), "/s".into()), ("SECRET".into(), "x".into())];
    let e = plain_mvm_env(&env);
    assert_eq!(e.len(), 2);
    assert!(!e.contains_key("MVM_HVF_SUPERVISOR_PATH"));
    // and in the fresh-setup test, ["env","sign"] went to mvm_plain, never to mvm
}
#[test] fn a_missing_or_old_supervisor_marker_fails_with_the_fix() {
    for out in [out(0, "", ""), out(0, "rts-vsock-drain-v0\n", ""), out(1, "rts-vsock-drain-v1\n", "")] {
        let e = run(&SetupOptions::default(), &ctx).unwrap_err();
        assert!(e.contains("rts-vsock-drain-v1") && e.contains("rts setup"), "{e}");
    }
    // contract "mvm-hvf-supervisor contract-version=3" -> Err contains "contract-version=4"
}
#[test] fn a_wrong_opencode_version_fails() { /* installed opencode prints 2.1.4 -> Err contains "2.2.2" and the path; f.calls() lacks the opencode URL */ }
#[test] fn an_existing_mvm_that_does_not_verify_is_refused_not_replaced() { /* mvmctl --version prints "mvmctl 0.21.0" -> Err contains "remove it"; the dir and its files are unchanged */ }
#[test] fn check_makes_no_network_calls_and_changes_nothing() {
    let e = run(&SetupOptions { check: true, offline: false }, &ctx_with_nothing_installed).unwrap_err();
    assert!(f.calls().is_empty());
    assert!(!mvm_calls.iter().any(|a| a.contains(&"sign".to_string()) || a.contains(&"pull".to_string())));
    assert!(e.lines().count() >= 2 && e.contains("run rts setup"), "{e}"); // every failure reported, not just the first
    assert!(!home.join(".local").exists());
}
#[test] fn offline_check_reads_only_the_installed_layout() {
    // plugin dir with package.json and index.ts, recorder passes probes and codesign
    run(&SetupOptions { check: true, offline: true }, &ctx).unwrap();
    assert!(mvm_calls.is_empty() && f.calls().is_empty());
    assert_eq!(host_programs, ["<sup>", "<sup>", "/usr/bin/codesign", "/usr/bin/codesign"]);
    // remove index.ts -> Err names the plugin path
}
```

  In `src/main.rs`: `setup_and_version_parse` asserts `["setup"]` → `Setup(SetupOptions::default())`, `["setup", "--check"]`, `["setup", "--check", "--offline"]`, `["--version"]` and `["-V"]` → `Version`, `["setup", "--help"]` → `Help`; add to the malformed list `["setup", "--offline"]` (error contains `--offline requires --check`), `["setup", "--check", "--check"]`, `["setup", "--config", "x"]`, `["setup", "extra"]`, `["--version", "x"]`.

- [ ] **Step 2: Run, expect FAIL** — `T --lib setup::` and `T --bin rts` fail to compile: `cannot find type \`SetupOptions\``, `no variant named \`Setup\``.

- [ ] **Step 3: Implement** as specified. Keep `preflight`'s behaviour and messages for the marker identical apart from Task 2's text.

- [ ] **Step 4: Run, expect PASS** — `T --lib`: the five baseline failures only; `T --bin rts` passes with the new tests.

- [ ] **Step 5: Live, read-only check.** `RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0 cargo build --release`, then `./target/release/rts --version` prints `rts 0.1.0`; `./target/release/rts setup --check` on this host is expected to exit 1 listing only `opencode 2.2.2` (absent from the home path, and `PATH`'s `opencode` is 2.1.4 until the operator runs setup); `./target/release/rts setup --check --offline` exits 0 using the source `plugin/` and the home supervisor. Paste both outputs into the PR. Do not run a mutating `rts setup` against the real home; the full run belongs to the pre-tag clean-account test.

- [ ] **Step 6: Commit** — `git add src && git commit -m "Add rts setup with check and offline modes"`

---

### Task 5: Release packaging script and supervisor entitlements

**Files:**
- Create: `scripts/package-release.sh`
- Create: `packaging/macos/mvm-hvf-supervisor.entitlements` (byte-identical to upstream `assets/mvm-supervisor.entitlements` at `b6b77f83730bed54d52f5f8b9cdcd8d5136ca1de`, which `scripts/build-patched-mvm-supervisor.sh:107` uses; it grants only `com.apple.security.hypervisor`)
- Create: `tests/unit/release.test.ts`

**Interfaces:**
- Consumes: `scripts/build-patched-mvm-supervisor.sh --install-dir <abs dir>` (writes `mvm-hvf-supervisor` and `mvm-hvf-supervisor.build-info`, `:110-131`). `install.sh` arrives in Task 6, so this task's tests pass `--install-sh` a stand-in template `RTS_DEFAULT_VERSION="@RTS_VERSION@"`.
- Produces: `scripts/package-release.sh --version <semver> --rts <path> --supervisor <path> --build-info <path> --out <dir> [--install-sh <template>]` (default template: the repository's `install.sh`), writing into `<dir>`:
  - `rts-<version>-aarch64-apple-darwin.tar.gz`: the spec's layout exactly, no top-level directory, no `._*` entries (`COPYFILE_DISABLE=1`), built with `/usr/bin/tar --uid 0 --gid 0 --uname root --gname wheel`; `bin/rts` and the supervisor `0755`, everything else `0644`/`0755` for directories; `share/nearai-red-sandbox/plugin/` holds `index.ts`, `audit.ts`, `package.json` from `plugin/`.
  - the build-info copy with its single `signed_binary_sha256=` line rewritten to the sha256 of the supervisor being packaged (the release re-signs after the build script wrote it); a build-info with zero or several such lines is refused.
  - `install.sh`: the template with `@RTS_VERSION@` replaced by `<version>`; refused if the placeholder count is not exactly one.
  - `SHA256SUMS`: `shasum -a 256` lines for the tarball and `install.sh`, in that order, names without directories.
  - Refuses (exit 1, message naming the flag): a missing flag, a version not matching `^[0-9]+\.[0-9]+\.[0-9]+$`, a missing or non-executable binary, an existing non-empty `<dir>`.

- [ ] **Step 1: Write the failing tests** (`tests/unit/release.test.ts`, `bun:test`, `spawnSync("bash", [...])`, temp dirs). Fake binaries are `#!/bin/sh` scripts; a fake build-info has `signed_binary_sha256=stale`.

```ts
test("the tarball has exactly the spec's layout", () => {
  const out = pkg("0.1.0")
  const list = tarList(`${out}/rts-0.1.0-aarch64-apple-darwin.tar.gz`) // tar -tzf, sorted, trailing "/" stripped
  expect(list).toEqual(["LICENSE", "README.md", "bin", "bin/rts", "libexec", "libexec/nearai-red-sandbox",
    "libexec/nearai-red-sandbox/mvm-hvf-supervisor", "libexec/nearai-red-sandbox/mvm-hvf-supervisor.build-info",
    "share", "share/nearai-red-sandbox", "share/nearai-red-sandbox/opencode", "share/nearai-red-sandbox/opencode/session.example.json",
    "share/nearai-red-sandbox/plugin", "share/nearai-red-sandbox/plugin/audit.ts", "share/nearai-red-sandbox/plugin/index.ts",
    "share/nearai-red-sandbox/plugin/package.json"])
})
test("binaries are executable and build-info names the packaged supervisor", () => { /* tar -tvzf modes; extracted build-info signed_binary_sha256 == sha256(extracted supervisor) */ })
test("SHA256SUMS verifies both files", () => { /* shasum -a 256 -c SHA256SUMS in <out> exits 0; exactly 2 lines */ })
test("install.sh has the version baked in", () => { /* contains RTS_DEFAULT_VERSION="0.1.0", no @RTS_VERSION@; a template with two placeholders is refused */ })
for (const bad of [["--version", "v0.1.0"], ["--version", "0.1"], ["--rts", "/nonexistent"]]) {
  test(`refuses ${bad.join(" ")}`, () => { /* exit 1, stderr names the flag, <out> has no tarball */ })
}
test("the entitlements file grants only the hypervisor", () => {
  /* plutil -convert json -o - packaging/macos/mvm-hvf-supervisor.entitlements == {"com.apple.security.hypervisor": true} */
})
```

- [ ] **Step 2: Run, expect FAIL** — `bun test tests/unit` fails: `bash: scripts/package-release.sh: No such file or directory`.

- [ ] **Step 3: Implement** the script (`set -euo pipefail`, `umask 022`, stage under `mktemp -d`, cleanup trap as in the build script) and copy the entitlements file. Verify the copy: `gh api "repos/tinylabscom/mvm/contents/assets/mvm-supervisor.entitlements?ref=b6b77f83730bed54d52f5f8b9cdcd8d5136ca1de" --jq .content | base64 -d | diff - packaging/macos/mvm-hvf-supervisor.entitlements` prints nothing.

- [ ] **Step 4: Run, expect PASS** — `bun test tests/unit` passes in full; `shellcheck scripts/package-release.sh` prints nothing; `T --lib` unchanged.

- [ ] **Step 5: Commit** — `git add scripts/package-release.sh packaging/macos tests/unit/release.test.ts && git commit -m "Add the release packaging script"`

---

### Task 6: The curl installer

**Files:**
- Create: `install.sh` (the template the packager renders)
- Create: `tests/unit/install.test.ts`

**Interfaces:**
- Consumes: `scripts/package-release.sh` (Task 5) to build fake releases; `rts setup` (Task 4) as the last step.
- Produces: `install.sh`, plain bash, `set -euo pipefail`, whole body in `main() { ... }` with `main "$@"` as the last line; `RTS_DEFAULT_VERSION="@RTS_VERSION@"`; no `sudo`; never edits shell profiles.
  1. `uname -s` must be `Darwin` and `uname -m` `arm64`, else exit 1 with `"rts supports macOS on Apple silicon (aarch64-apple-darwin) only; this is <s> <m>"`.
  2. `version="${RTS_VERSION:-$RTS_DEFAULT_VERSION}"`; an unrendered placeholder with no `RTS_VERSION` exits 1 (`"this install.sh is an unrendered template; set RTS_VERSION"`). `base="${RTS_RELEASE_BASE:-https://github.com/nearai/nearai-red-sandbox/releases/download/v$version}"`; `prefix="${RTS_INSTALL_PREFIX:-$HOME/.local}"`.
  3. `curl -fsSL` the tarball and `SHA256SUMS` into `mktemp -d` (removed by an `EXIT` trap); copy only the tarball's line into a file and `shasum -a 256 -c` it (a piped install has no `install.sh` on disk to check). Failure exits 1 before any unpack.
  4. If `command -v gh`: `gh attestation verify <tarball> --repo nearai/nearai-red-sandbox`, failure exits 1 before unpack; else print `"provenance not checked: install the GitHub CLI (gh) to verify the release attestation"`.
  5. Create `$prefix` if missing (a fresh account may have no `~/.local`), then unpack into a staging dir `mktemp -d "$prefix/.rts-install.XXXXXX"` (same filesystem); then for each owned path, `bin/rts`, `libexec/nearai-red-sandbox`, `share/nearai-red-sandbox/plugin`, `share/nearai-red-sandbox/opencode/session.example.json`: create the parent, move any existing one aside into the staging dir, move the new one in. Nothing else under the prefix is touched.
  6. `"$prefix/bin/rts" setup`; its failure exits with its status.
  7. If `$prefix/bin` is not on `PATH`, print `export PATH="<prefix>/bin:$PATH"` as the line to add.

- [ ] **Step 1: Write the failing tests** (`tests/unit/install.test.ts`). Each test builds a fake release with `scripts/package-release.sh` whose `bin/rts` is `#!/bin/sh` appending `"$@"` and its version to `$RTS_TEST_LOG`; runs `bash install.sh` with `env` set to `PATH=<fakebin>:/usr/bin:/bin`, `HOME=<tmp>`, `RTS_INSTALL_PREFIX=<tmp>/prefix`, `RTS_VERSION`, `RTS_RELEASE_BASE=file://<release dir>`; `<fakebin>` holds a `uname` stub when needed and a `gh` stub when needed, so the host's real `gh` is never on `PATH`.

```ts
test("a fake release installs into the prefix and runs rts setup once", () => {
  const r = install("0.1.0")
  expect(r.status).toBe(0)
  expect(readFileSync(log, "utf8").trim().split("\n")).toEqual(["0.1.0 setup"])
  expect(existsSync(`${prefix}/libexec/nearai-red-sandbox/mvm-hvf-supervisor`)).toBe(true)
  expect(r.stdout + r.stderr).toContain("provenance not checked")
  expect(r.stdout).toContain(`export PATH="${prefix}/bin:$PATH"`)
})
test("a tampered tarball is refused before unpacking", () => { /* append a byte after packaging; status 1; no <prefix>/bin; log absent */ })
test("a failing attestation check stops the install", () => { /* gh stub exits 1; status 1; no <prefix>/bin */ })
for (const [s, m] of [["Linux", "aarch64"], ["Darwin", "x86_64"]]) {
  test(`${s} ${m} is refused`, () => { /* uname stub; status 1; stderr contains "aarch64-apple-darwin"; nothing downloaded */ })
}
test("a re-run upgrades in place and keeps files it does not own", () => {
  install("0.1.0")
  // seed <prefix>/share/nearai-red-sandbox/opencode/2.2.2/opencode, .../mvm-hvf-supervisor, .../sessions/x, <prefix>/bin/other
  install("0.1.1")
  expect(readFileSync(log, "utf8").trim().split("\n")).toEqual(["0.1.0 setup", "0.1.1 setup"])
  for (const kept of [opencodeBin, homeSupervisor, sessionFile, `${prefix}/bin/other`]) expect(existsSync(kept)).toBe(true)
  expect(readdirSync(prefix).filter((n) => n.startsWith(".rts-install"))).toEqual([])
})
test("a truncated download runs nothing", () => {
  // first half of install.sh (cut inside main) piped to bash: no curl call (curl stub logs), log absent, prefix absent
})
test("an unrendered template without RTS_VERSION is refused", () => { /* run the repo's install.sh with RTS_VERSION unset; status 1 */ })
```

- [ ] **Step 2: Run, expect FAIL** — `bun test tests/unit` fails: `bash: install.sh: No such file or directory`.

- [ ] **Step 3: Implement** `install.sh`.

- [ ] **Step 4: Run, expect PASS** — `bun test tests/unit` passes in full; `shellcheck install.sh` prints nothing; `T --lib` unchanged.

- [ ] **Step 5: Commit** — `git add install.sh tests/unit && git commit -m "Add the curl installer"`

---

### Task 7: Test gate, Homebrew formula template, release workflow, and docs

**Files:**
- Create: `scripts/release/check-tests.sh`, `scripts/release/render-formula.sh`, `scripts/release/check-existing-release.sh` (added during implementation: the publish job's re-run guard)
- Create: `packaging/homebrew/rts.rb.template`
- Create: `.github/workflows/release.yml`
- Create: `tests/unit/release-gate.test.ts`, `tests/fixtures/release/` (canned cargo logs)
- Modify: `README.md` (install section), `opencode/README.md` (installed layout, `rts setup`), `docs/mvm-supervisor.md` (released supervisor vs. source build)

**Interfaces:**
- Consumes: `scripts/package-release.sh` (Task 5), `install.sh` (Task 6), `scripts/build-patched-mvm-supervisor.sh`, `packaging/macos/mvm-hvf-supervisor.entitlements`, `rts --version` and `rts setup --check --offline` (Task 4).
- Produces:
  - `scripts/release/check-tests.sh`: runs `cargo test --lib` (with the repository flags) into a log, then `--parse <log>`; also runs `cargo test --bin rts` and `bun test tests/unit`, which must pass in full, and `shellcheck install.sh scripts/*.sh scripts/release/*.sh`. `check-tests.sh --parse <log>` exits 0 only when the log has a `test result:` line and every `^test (\S+) \.\.\. FAILED$` name is one of the five allowed names (allowed is a subset, not required); otherwise exit 1 naming each unexpected failure or `no test result line`.
  - `scripts/release/render-formula.sh --version <v> --sha256 <hex> --out <file>`: replaces `@VERSION@` and `@SHA256@` in the template; refuses a non-semver version, a sha256 that is not 64 lowercase hex, or any `@` placeholder left.
  - `packaging/homebrew/rts.rb.template`: `class Rts < Formula` with `desc`, `homepage "https://github.com/nearai/nearai-red-sandbox"`, `url "https://github.com/nearai/nearai-red-sandbox/releases/download/v@VERSION@/rts-@VERSION@-aarch64-apple-darwin.tar.gz"`, `sha256 "@SHA256@"`, `license "Apache-2.0"`, `depends_on arch: :arm64`, `depends_on :macos`; `def install` → `prefix.install "bin", "libexec", "share"`; `def caveats` → run `rts setup` once (Homebrew's sandbox forbids writing to the home directory during install) and the paths to delete for a full removal: `~/.local/mvm/v0.22.0`, `~/.local/share/nearai-red-sandbox`; `test do` → `assert_match "rts #{version}", shell_output("#{bin}/rts --version")` and `system bin/"rts", "setup", "--check", "--offline"`.
  - `.github/workflows/release.yml` (superseded during implementation: this interface first described one `macos-15` job with workflow-level `contents: write`, `APPLE_*` secrets, attestation, release and tap steps skipped on a dry run, and an `if: always()` cleanup step; the trace-commons layout from the Global Constraints, described below, is what was built, and the workflow file is the reference): `on: push: tags: ["v*"]` and `workflow_dispatch` with input `dry_run` (boolean, default `true`). Workflow-level `permissions: contents: read, id-token: write, attestations: write`; `concurrency` per ref without cancelling. Three jobs:
    1. `release-config` (`ubuntu-24.04`, no environment): refuses a dispatch with `dry_run: false` (a dispatch never publishes; push a tag); on a tag push, refuses when the repository secret `HOMEBREW_TAP_TOKEN` is empty (superseded 2026-10-30: `HOMEBREW_TAP_DEPLOY_KEY`).
    2. `build` (`macos-26`, `environment: release`, `timeout-minutes: 90`, `RUSTFLAGS="-D warnings"`, `CARGO_INCREMENTAL=0` in the job `env`), steps in order: checkout and setup-bun (`bun-version: 1.3.3`) by the pinned SHAs; Version (`V` from `Cargo.toml`, X.Y.Z only; on a tag push `GITHUB_REF_NAME` must equal `v$V`); `brew install coreutils gnu-tar shellcheck`; the test gate `scripts/release/check-tests.sh` with the GNU `gnubin` dirs first on `PATH` for that step only (never through `GITHUB_PATH`, so later steps use BSD `stat` and `tar`); `cargo build --release --locked`; `scripts/build-patched-mvm-supervisor.sh --install-dir "$RUNNER_TEMP/supervisor"`; one Sign and notarize step reading the `MACOS_*` secrets through `env` (temporary keychain with the search list captured and restored in an EXIT trap, exactly one identity matching `MACOS_SIGNING_IDENTITY`, `codesign --options runtime --timestamp` on both binaries with the entitlements on the supervisor, hypervisor entitlement, marker and contract checks, `notarytool submit --wait --output-format json` accepted only on status `Accepted`, then `spctl --assess --type install -vv` requiring `source=Notarized Developer ID`); `scripts/package-release.sh` into `$RUNNER_TEMP/dist` and `shasum -a 256 -c SHA256SUMS`; `actions/attest-build-provenance` on the tarball and `install.sh` on every run, dry runs included, so `gh attestation verify` works on the dry-run artifacts; `actions/upload-artifact` of `dist/` as `dist`.
    3. `publish` (`ubuntu-24.04`, no environment, only on a tag push; `permissions: contents: write, actions: read`): downloads this run's `dist` artifact and checks `SHA256SUMS`; creates release `v$V` with `gh release create --verify-tag` (`GH_TOKEN: ${{ github.token }}`), or, when it already exists, skips creation only if `scripts/release/check-existing-release.sh` finds its assets' digests exactly equal to this run's and fails otherwise; then clones `nearai/homebrew-tap` with `HOMEBREW_TAP_TOKEN`, renders `Formula/rts.rb` with the tarball sha256 from this run's `SHA256SUMS`, force-pushes `bump-rts-$V` rebuilt from the default branch, and opens and merges a pull request (superseded 2026-10-30: pushes the bump straight to the tap's `main` over SSH with the `HOMEBREW_TAP_DEPLOY_KEY` deploy key, never force-pushing).
  Secrets are passed to steps through `env`, never interpolated into `run:` text.

- [ ] **Step 1: Write the failing tests** (`tests/unit/release-gate.test.ts`). Fixture logs under `tests/fixtures/release/`: `baseline.log` (the five `test copy::tests::... ... FAILED` lines and `test result: FAILED. 230 passed; 5 failed; 1 ignored`), `sixth.log` (baseline plus `test session::tests::x ... FAILED`), `ok.log` (`test result: ok.`), `fewer.log` (two of the five), `no-result.log` (a compile error, no `test result:`).

```ts
for (const [log, status] of [["baseline", 0], ["ok", 0], ["fewer", 0], ["sixth", 1], ["no-result", 1]] as const) {
  test(`check-tests --parse ${log} exits ${status}`, () => {
    const r = run("scripts/release/check-tests.sh", ["--parse", `tests/fixtures/release/${log}.log`])
    expect(r.status).toBe(status)
    if (log === "sixth") expect(r.stderr).toContain("session::tests::x")
  })
}
test("a substring of an allowed name is not allowed", () => { /* log failing copy::tests::a_long_name_is_refused_too -> 1 */ })
test("the formula renders and parses", () => {
  const r = run("scripts/release/render-formula.sh", ["--version", "0.1.0", "--sha256", "a".repeat(64), "--out", f])
  expect(r.status).toBe(0)
  const text = readFileSync(f, "utf8")
  expect(text).toContain('url "https://github.com/nearai/nearai-red-sandbox/releases/download/v0.1.0/rts-0.1.0-aarch64-apple-darwin.tar.gz"')
  expect(text).toContain(`sha256 "${"a".repeat(64)}"`)
  expect(text).not.toContain("@")
  expect(spawnSync("ruby", ["-c", f]).status).toBe(0)
})
for (const bad of [["--version", "v0.1.0"], ["--sha256", "A".repeat(64)], ["--sha256", "abc"]]) {
  test(`render-formula refuses ${bad.join(" ")}`, () => { /* status 1, no output file */ })
}
```

- [ ] **Step 2: Run, expect FAIL** — `bun test tests/unit` fails: the scripts do not exist.

- [ ] **Step 3: Implement** the two scripts, the template and the workflow. Write the doc sections: README "Install" (both one-liners, what `rts setup` fetches, `rts setup --check`); `opencode/README.md` (installed layout and the lookup table, sessions under `./sessions` for an installed `rts`); `docs/mvm-supervisor.md` (releases ship a Developer ID-signed, notarized supervisor under `libexec/nearai-red-sandbox/`; the build script remains the source-build path and its ad-hoc note applies only there).

- [ ] **Step 4: Validate what can run locally.** `bun test tests/unit` passes in full. `actionlint .github/workflows/release.yml` prints nothing (it also shellchecks the `run:` blocks). `shellcheck install.sh scripts/*.sh scripts/release/*.sh` prints nothing. `scripts/release/check-tests.sh` against the working tree exits 0 and its log shows the five baseline failures. Local packaging dry run without signing: `cargo build --release`; copy `~/.local/share/nearai-red-sandbox/mvm-hvf-supervisor` and its `.build-info` into `<scratch>/sup` (the workflow builds it from source; rebuilding here only repeats the build script); then `scripts/package-release.sh --version 0.1.0 --rts target/release/rts --supervisor <scratch>/sup/mvm-hvf-supervisor --build-info <scratch>/sup/mvm-hvf-supervisor.build-info --out <scratch>/dist`; extract the tarball into a scratch prefix and run `<prefix>/bin/rts --version` (`rts 0.1.0`) and `<prefix>/bin/rts setup --check --offline` (exit 0, plugin and supervisor from that prefix). The signing, notarization, attestation, release and tap steps cannot run locally; they are covered by the `dry_run` dispatch once the secrets exist (open items).

- [ ] **Step 5: Run, expect PASS** — `T --lib`: the five baseline failures only; `T --bin rts` passes; `bun test tests/unit` passes.

- [ ] **Step 6: Commit** — `git add scripts/release packaging/homebrew .github tests/unit tests/fixtures/release README.md opencode/README.md docs/mvm-supervisor.md && git commit -m "Add the release workflow, test gate and Homebrew formula template"`

---

## After the plan (not tasks here)

From the spec's Testing and Open items, for Zaki: create `nearai/homebrew-tap` and `HOMEBREW_TAP_TOKEN` (a repository or organization secret; superseded 2026-10-30: done, as the write deploy key 168148229 on the tap and the repository secret `HOMEBREW_TAP_DEPLOY_KEY`); add the `MACOS_*` signing and notary secrets (the `release` environment or the repository) and confirm the identity name and team ID; make the repository public; run the `dry_run` dispatch; install with each method on a clean macOS user account (`install.sh` against the dry-run artifacts with `RTS_RELEASE_BASE=file://...`, the formula from a local tap checkout) and check `codesign -dvv` on the installed `rts` and supervisor still shows the Developer ID; then `rts launch` against NEAR AI production; then tag.

# Releases, the curl installer, and the Homebrew tap: design

Date: 2026-10-29
Status: draft for review

## Purpose

An operator on an Apple silicon Mac gets a working `rts launch` with one
command, either `curl ... | bash` or `brew install nearai/tap/rts`. Today
`rts` runs only from a source checkout, and its three runtime dependencies
(mvm, the patched mvm supervisor, opencode) are installed by hand.

## Decisions

| Topic | Decision |
|---|---|
| Hosting | GitHub releases on `nearai/nearai-red-sandbox`, which is being made public. |
| Scope | Full stack: `rts`, the plugin shim, the patched supervisor, mvm v0.22.0, opencode v2.2.2, and the guest image. |
| Structure | Both installers place the release files, then run `rts setup`, which does all download and verification work in tested Rust. |
| Platforms | macOS on Apple silicon (`aarch64-apple-darwin`) only. |
| Signing | `rts` and the supervisor are signed with iqlusion's Developer ID Application identity (hardened runtime, secure timestamp) and notarized with `notarytool`. |
| Provenance | `SHA256SUMS` plus GitHub build-provenance attestations for every published artifact. |
| Homebrew | Tap `nearai/homebrew-tap`, formula `rts`, updated by the release workflow. |
| opencode pin | Moves from 2.1.4 to 2.2.2: 2.1.4 has a tag but no downloadable release; releases with macOS assets start at v2.2.0 (checked 2026-10-29). |
| License | Apache-2.0 (decided 2026-10-29): `LICENSE` holds the text from apache.org, and `Cargo.toml` and both `package.json` files declare it. The vendored `dcap-qvl` keeps its MIT license. |
| New dependencies | None. `rts setup` uses `reqwest` and `sha2`, already direct; zip extraction uses `/usr/bin/ditto` and tar uses `/usr/bin/tar`. |

## Release pipeline (`.github/workflows/release.yml`)

Trigger: a pushed tag `v<semver>`. A `workflow_dispatch` run with
`dry_run: true` builds, signs and notarizes but publishes nothing and does
not touch the tap; it is how the signing secrets are validated. The run
refuses when the tag differs from the `Cargo.toml` version.

Runner: GitHub-hosted `macos-26`, as trace-commons uses.

Steps:

1. Tests with the repository's flags (`RUSTFLAGS="-D warnings"
   CARGO_INCREMENTAL=0`): `cargo test --lib`, `cargo test --bin rts`,
   `bun test tests/unit`. The five known `copy::tests` failures
   (a_long_name_is_refused, a_symlink_to_a_host_path_is_refused,
   a_hardlink_is_refused, copy_out_is_byte_exact_across_slices,
   an_oversized_file_is_refused) are allowed by name until they are fixed;
   any other failure stops the release. `shellcheck install.sh`.
2. `cargo build --release`.
3. Build the patched supervisor with `scripts/build-patched-mvm-supervisor.sh`
   (pinned mvm source revision and `patches/mvm-v0.22.0-hvf-drain.patch`).
4. Sign `rts` and the supervisor with `codesign --sign "Developer ID
   Application: ..." --options runtime --timestamp`; the supervisor also gets
   an entitlements file with `com.apple.security.hypervisor`. Verify with
   `codesign --verify --strict`; after notarization, `spctl --assess --type
   install -vv` must report `source=Notarized Developer ID`. (`--type
   execute` assesses app bundles and rejects every bare Mach-O CLI as "does
   not seem to be an app", notarized or not.)
5. Notarize: zip both binaries, `xcrun notarytool submit --wait` with the App
   Store Connect API key. A rejection fails the release and prints the
   notarization log. Bare Mach-O binaries cannot be stapled; Gatekeeper
   looks the ticket up online on first run.
6. Package `rts-<version>-aarch64-apple-darwin.tar.gz`:

   ```
   bin/rts
   libexec/nearai-red-sandbox/mvm-hvf-supervisor
   libexec/nearai-red-sandbox/mvm-hvf-supervisor.build-info
   share/nearai-red-sandbox/plugin/
   share/nearai-red-sandbox/opencode/session.example.json
   LICENSE
   README.md
   ```

7. Render `install.sh` from the repository template with the version baked
   in.
8. `SHA256SUMS` over the tarball and `install.sh`; attest both with
   `actions/attest-build-provenance`.
9. Create the GitHub release with the tarball, `install.sh` and `SHA256SUMS`.
   If release `v<version>` already exists (a re-run after a later step
   failed), skip creation only when its assets are exactly those three files
   with GitHub sha256 digests equal to this run's (`SHA256SUMS` lines, and
   the hash of `SHA256SUMS` itself); fail otherwise.
10. Update the tap: commit `Formula/rts.rb` with the new version, URL and
    sha256 to `nearai/homebrew-tap` using `HOMEBREW_TAP_TOKEN`.

Secrets, named as in TraceCommons/trace-commons so the values can be copied: `MACOS_CERTIFICATE_P12_BASE64`, `MACOS_CERTIFICATE_PASSWORD`,
`MACOS_SIGNING_IDENTITY`, `MACOS_NOTARY_ASC_KEY_P8_BASE64`, `MACOS_NOTARY_ASC_KEY_ID`,
`MACOS_NOTARY_ASC_ISSUER_ID`, `HOMEBREW_TAP_TOKEN` (fine-grained, contents and pull-request
write on `nearai/homebrew-tap` only). The `MACOS_*` secrets are read only by
the signing job, so they may live in the `release` environment (or at
repository or organization level). `HOMEBREW_TAP_TOKEN` must be a repository or organization secret: the `release-config` preflight and the publish job
read it and run without an environment, so an environment secret is invisible
to them. The workflow follows trace-commons' `release-contributor.yml`: `environment: release` on the signing job, a separate publish job with `contents: write`, a `release-config` preflight, runner `macos-26`, notarization accepted only on a JSON status of `Accepted`, checksums recomputed after signing, and the tap updated by a pull request the workflow merges. The certificate is imported into a
temporary keychain that the job deletes at the end.

### Recovering a partly published release

The publish job creates the release, then bumps the tap. If the tap step
fails after the release exists:

1. Use "Re-run failed jobs" on the same workflow run. The publish job
   downloads the same `dist` artifact, finds release `v<version>` holding
   exactly those assets, skips creation and retries the tap. The tap hash
   still comes only from that run's `SHA256SUMS`.
2. A full re-run (or a new run for the same tag) rebuilds and re-signs, so its
   digests differ and the guard refuses: it never overwrites a published
   release. The same applies if the run's artifact has expired.
3. Then either bump the tap by hand, taking the sha256 from the published
   release's `SHA256SUMS` after checking it against the tarball
   (`gh release download v<version> --repo nearai/nearai-red-sandbox` then
   `shasum -a 256 -c SHA256SUMS`), with
   `scripts/release/render-formula.sh --version <version> --sha256 <hex> --out Formula/rts.rb`
   in a `nearai/homebrew-tap` checkout and a pull request; or, if nobody can
   have installed it yet, delete the release (`gh release delete v<version>
   --repo nearai/nearai-red-sandbox --yes`, keeping the tag) and use "Re-run
   all jobs" on the tag's workflow run.

## Install layout and path discovery

Both installers produce the same layout under one prefix: `~/.local` for the
curl installer (overridable with `RTS_INSTALL_PREFIX`), the keg for Homebrew
(with `bin/rts` linked into Homebrew's prefix).

`rts` resolves its own executable with `std::env::current_exe` followed by
`std::fs::canonicalize` (Homebrew's `bin/rts` is a symlink into the Cellar),
and takes `<prefix>` as the parent of its `bin/` directory. Explicit settings
always win, and source builds keep working:

| Item | Lookup order |
|---|---|
| plugin | config `pluginDir`; `<prefix>/share/nearai-red-sandbox/plugin` if it is a directory; the compiled-in source path (`CARGO_MANIFEST_DIR/plugin`) |
| supervisor | `MVM_HVF_SUPERVISOR_PATH`; `<prefix>/libexec/nearai-red-sandbox/mvm-hvf-supervisor` if present; `~/.local/share/nearai-red-sandbox/mvm-hvf-supervisor` |
| mvmctl | `RTS_MVMCTL`; `~/.local/mvm/v0.22.0/mvmctl` |
| opencode | config `opencode`; `~/.local/share/nearai-red-sandbox/opencode/2.2.2/opencode` if present; `opencode` on `PATH` |

mvm and opencode live under the home directory rather than a prefix, so
both install methods share one copy of each pinned version.

## `rts setup`

Idempotent; each step is skipped when the pinned version is already in place
and verifies.

| Component | Source | Pinned digest (sha256) | Installed to |
|---|---|---|---|
| mvm v0.22.0 | `https://github.com/tinylabscom/mvm/releases/download/v0.22.0/mvmctl-aarch64-apple-darwin.tar.gz` | `1f2c80b253add28c3856080e3f3a10aa1163f1aef0a7d413ded15100bdcd0c69` | `~/.local/mvm/v0.22.0/` |
| opencode v2.2.2 | `https://github.com/anomalyco/opencode/releases/download/v2.2.2/opencode-darwin-arm64.zip` | `c1c901a6379d667b7a30a3eea5a8f6e93416dba43e889e834771f6fb174f35c9` | `~/.local/share/nearai-red-sandbox/opencode/2.2.2/opencode` |
| guest image | the digest-pinned image `rts` already uses | its digest | `mvmctl image pull` |

Digests measured 2026-10-29. The mvm digest equals the entry in mvm's
`checksums-sha256.txt`, which was cosign-verified on 2026-10-27 against the
release workflow identity (see the sandbox design's host setup notes); the
opencode digest equals the `digest` field GitHub reports for the asset. A
fixed digest admits exactly one file, so no cosign runs at install time.

Per component:

1. Download to a temp file over HTTPS: redirects only to
   `github.com`, `objects.githubusercontent.com` and
   `release-assets.githubusercontent.com`; a size cap per asset.
2. Check the sha256 before unpacking. A mismatch deletes the file and fails
   setup, printing the expected and actual digests.
3. Unpack into a temp directory beside the target and `rename` it into
   place, so an interrupted setup leaves no partial version.

Then: `mvmctl env sign`; `mvmctl doctor` must pass; the supervisor found by
the lookup above must report `rts-vsock-drain-v1` and the contract version
`rts` expects; `opencode --version` must print `2.2.2`; `mvmctl image pull`
of the pinned guest image. Setup ends with a summary of each component's
path and version.

Flags:

- `--check`: run every check, download nothing, exit nonzero on any failure.
- `--offline`: with `--check`, check only the installed `rts` layout (plugin,
  supervisor, signatures), for Homebrew's `test do`.

The launcher's preflight is unchanged in what it requires; its errors for a
missing mvm, supervisor or opencode now say `run rts setup`.

## The opencode 2.2.2 re-pin

This is a gate, not a constant change. Before the pin moves:

- Re-run the plugin probes from the sandbox design against 2.2.2: the 20
  built-in tool IDs and their removal through `ctx.tool.transform`; MCP
  removal through `ctx.mcp.transform` with servers in global and project
  config; the model transform and the exact-ID allowlist; the ready-file
  handshake; `--standalone`.
- Run the containment suite (`tests/contain`) against 2.2.2.
- Record what was measured in the sandbox design's checks list. Any plugin
  change the new version needs lands in the same branch.

## curl installer (`install.sh`)

```
curl -fsSL https://github.com/nearai/nearai-red-sandbox/releases/latest/download/install.sh | bash
```

Plain bash with `set -euo pipefail`; the body is one function called on the
last line, so a truncated download runs nothing. No `sudo`.

1. Refuse anything other than Darwin on arm64, with a message naming the
   supported platform.
2. Version: baked in at release time; `RTS_VERSION` overrides it. The base
   URL is `https://github.com/nearai/nearai-red-sandbox/releases/download/v<version>`;
   `RTS_RELEASE_BASE` overrides it (used by the tests).
3. Download the tarball and `SHA256SUMS` into a temp directory removed on
   exit; check the tarball with `shasum -a 256 -c`.
4. If `gh` is available, `gh attestation verify <tarball> --repo
   nearai/nearai-red-sandbox`; a failure stops the install. Without `gh`,
   print one line saying provenance was not checked.
5. Create `<prefix>/share/nearai-red-sandbox` and any missing parents with
   mode 0700 (directories that already exist keep their modes;
   `scripts/build-patched-mvm-supervisor.sh` refuses
   `~/.local/share/nearai-red-sandbox` unless it is mode 700). Unpack into a
   staging directory under the prefix, then replace exactly the paths the
   tarball owns: `bin/rts`, `libexec/nearai-red-sandbox`,
   `share/nearai-red-sandbox/plugin` and
   `share/nearai-red-sandbox/opencode/session.example.json`. Each earlier copy
   of those paths is moved aside first and put back if a later move fails.
   Nothing else under the prefix is touched: other files in `bin`, opencode
   under `share/nearai-red-sandbox/opencode/<version>`, sessions and a
   source-built supervisor in `share/nearai-red-sandbox` survive an upgrade.
   `LICENSE` and `README.md` stay in the tarball.
6. Run `<prefix>/bin/rts setup`.
7. If `<prefix>/bin` is not on `PATH`, print the line to add to the shell
   profile. The script never edits profiles.

`SHA256SUMS` comes from the same release, so it protects integrity, not
authenticity; authenticity comes from the attestation check or from pinning
a specific version's `install.sh`.

## Homebrew formula (`nearai/homebrew-tap`, `Formula/rts.rb`)

`brew install nearai/tap/rts`. The formula holds the tarball URL, version and
sha256, written by the release workflow; the tap commit is the trust anchor.

- `install`: copy `bin`, `libexec` and `share` into the keg.
- `caveats`: run `rts setup` once to fetch mvm and opencode into the home
  directory (Homebrew's build sandbox forbids writing there during install),
  and the paths to delete for a full removal.
- `test do`: `rts --version` and `rts setup --check --offline`.
- `brew uninstall` removes the keg only.

## Error handling

- Every failure names the component, the URL or path, and the fix.
- Nothing falls back to an unverified copy or an unpinned version.
- `rts setup` never deletes anything outside the paths it owns
  (`~/.local/mvm/v0.22.0`, `~/.local/share/nearai-red-sandbox/opencode/2.2.2`,
  and its temp directories).

## Testing

- `rts setup` (Rust, offline, injected HTTP and runner): digest mismatch
  deletes and fails; a correct install is skipped; an interrupted unpack
  leaves no partial version; a missing or old supervisor marker fails with
  the fix; a wrong opencode version fails; `--check` makes no network calls;
  `--offline` checks only the layout; a redirect to an unlisted host fails.
- Path discovery: binaries in a temp `<prefix>/bin`, including a symlinked
  `bin/rts` as Homebrew installs it, resolve the plugin and supervisor under
  that prefix; explicit config and environment win; source builds still find
  `plugin/`.
- `install.sh`: shellcheck; a test runs it against a local fake release
  (`RTS_RELEASE_BASE=file://...`) into a temp prefix with `rts setup`
  stubbed; a tampered tarball is refused before unpacking; non-arm64 and
  non-Darwin hosts are refused; a re-run upgrades in place.
- Release workflow: the `dry_run` dispatch builds, signs and notarizes.
- Before the first tag: the opencode 2.2.2 probes and containment suite; one
  install with each method on a clean macOS user account (`install.sh`
  against the dry-run artifacts, the formula from a local tap checkout);
  then `rts launch` against NEAR AI production.

## Open items

- Create `nearai/homebrew-tap` and the `HOMEBREW_TAP_TOKEN` repository (or organization) secret.
- Add the Apple signing and notary secrets; confirm the exact Developer ID
  Application identity name and team ID.
- Make the repository public before the first tag; the installers cannot
  download from a private repository.

## Out of scope for v1

Intel Macs, Linux, homebrew-core, auto-update, and uninstall beyond the
caveats text.

# Update notices and `rts update`: design

Date: 2026-10-30
Status: draft for review

## Purpose

An operator who installed `rts` from a release learns, at launch, that a
newer release exists, and installs it with one command, `rts update`. The
release is accepted only when a manifest signed with a key that GitHub does
not hold says so. Today an installed `rts` never learns about new releases,
and upgrading means re-running the curl installer by hand.

This is notify plus an explicit command, not a silent self-update: `rts`
never replaces itself during `rts launch`.

## Decisions

| Topic | Decision |
|---|---|
| Model | Notify at launch; install only on `rts update`. Decided by Zaki 2026-10-30. |
| Cadence | At most one launch check per 24 h, cached at `~/.local/share/nearai-red-sandbox/update-check.json` with `ironwire_update::{should_check, load_cache, save_cache}`. |
| Launch budget | 3 s total for the check; any failure is written to the session log only and never blocks or fails the launch. |
| Who updates | Curl installs: `rts update`. Homebrew installs: the notice says `run brew upgrade rts` and `rts update` refuses with that message. Source builds and builds without a compiled-in key: no launch check, and `rts update` refuses. |
| Manifest | Release asset `latest.json`: `ironwire_update::Manifest` (`latest`, optional `minimum_supported`, optional `summary`) plus `tarball {name, sha256}`, `install_sh {sha256}` and `published` (RFC 3339). |
| Signature | Release asset `latest.json.sig`: base64 of the raw 64-byte Ed25519 signature over the exact bytes of `latest.json`. Verified with `ed25519-dalek`'s `verify_strict`. |
| Public key | Compiled in from the build-time environment variable `RTS_UPDATE_PUBLIC_KEY_HEX` with `option_env!`; a malformed value is a build error. The repository variable holds `9b4a81b8bd017898c36871c6bd1cb890faf95b6e378e72eb99b9c15841f02ac9`, also published in `README.md` for out-of-band checks. |
| Private key | Environment secret `RTS_UPDATE_SIGNING_KEY_PEM_BASE64` (an OpenSSL Ed25519 PEM, base64) in the `release` environment, read only by the build job. |
| Signing tool | OpenSSL 3 from Homebrew (`openssl@3`): the runner's `/usr/bin/openssl` is LibreSSL, whose `pkeyutl` has no `-rawin` (LibreSSL 3.3.6, measured on this host 2026-10-30). |
| Install path | `rts update` runs the new release's own `install.sh`, pinned by the manifest's digest, so upgrades and fresh installs share one code path. |
| Opt-out | `RTS_NO_UPDATE_CHECK` (any non-empty value) or operator config `"updateCheck": false` disables the launch check; neither affects `rts update`. |
| New dependencies | None. `ironwire_update` (already in `Cargo.lock` via `ironwire_proxy`, same rev `bf8b90b`) and `chrono` 0.4.45 (already in `Cargo.lock`) become direct; no new package enters `Cargo.lock`. `semver` stays indirect: `ironwire_update::evaluate` does the comparison. |

## Operator behaviour

### Install channel

`rts` classifies itself from `std::env::current_exe`, canonicalized
(`src/install.rs:18-25`):

| Channel | Rule | `ironwire_update::InstallMethod` |
|---|---|---|
| Homebrew | `install_prefix` is `<...>/Cellar/rts/<version>`: the prefix's grandparent directory is named exactly `Cellar` | `Homebrew` |
| Release | a prefix whose `share/nearai-red-sandbox/plugin` is a directory (the rule `install::defaults` already uses, `src/install.rs:70-71`) | `ShellInstaller` |
| Source | anything else (`target/debug/rts`, a copied binary with no layout) | `Unmanaged` |

`InstallMethod::detect` is not used: it matches substrings of an
uncanonicalized path (`/homebrew/` would also match a curl install under
`/opt/homebrew`), and the result here gates an action, not only a message.
`InstallMethod::upgrade_command` names IronWire's commands, so `rts` prints
its own.

A build whose `RTS_UPDATE_PUBLIC_KEY_HEX` was unset at compile time behaves
as Source for both the launch check and `rts update`.

### Launch check

Runs in `rts launch` after the config is loaded and `check_launch` passes,
before credentials are read, attestation runs, or any VM exists
(`src/main.rs:305-308`).

1. Skip entirely, reading nothing and fetching nothing, when the channel is
   Source, the build has no key, `RTS_NO_UPDATE_CHECK` is set and non-empty,
   the config says `"updateCheck": false`, or `HOME` is unset or relative.
2. Load the cache. `should_check(true, cache, now)` decides whether to fetch;
   a cache whose `at` is in the future counts as due (a clock that was wrong
   once must not suppress checks indefinitely). A corrupt cache is no cache.
3. When due, fetch and verify the manifest (below) on a worker thread and
   wait at most 3 s for it (`recv_timeout`). The HTTP client also has a 3 s
   total timeout; the thread bound holds even if the client does not. On
   timeout the worker is left to finish on its own and its result is
   discarded.
4. Save the cache: on success `{at: now, status: evaluate(...)}`; on any
   failure `{at: now, status: <the previous status, or unknown>}`, so a dead
   network costs at most one 3 s wait per 24 h and does not erase a pending
   notice. Before saving, `rts` creates `~/.local/share/nearai-red-sandbox`
   with mode 0700 if it is missing: `save_cache` would otherwise create it
   with the umask's mode, and `scripts/build-patched-mvm-supervisor.sh` and
   `install.sh` require 0700 there.
5. The notice comes from the current status, re-evaluated against the
   running version (`evaluate(CARGO_PKG_VERSION, {latest, minimum_supported},
   method)`), so a stale cached notice disappears once the operator has
   updated. It is printed to stderr with the `[rts] ` prefix, then launch
   continues:

   | Status | Release channel | Homebrew channel |
   |---|---|---|
   | `Available` | `rts <latest> is available (you have <current>): run rts update` | `rts <latest> is available (you have <current>): run brew upgrade rts` |
   | `Unsupported` | `rts <current> is older than the oldest supported release, <minimum>, and may not work: run rts update to install <latest>` | the same, ending `run brew upgrade rts to install <latest>` |
   | `UpToDate`, `Unknown` | nothing | nothing |

6. Failures (network, HTTP status, redirect outside the allowlist, size cap,
   timeout, signature, parse, cache read or write) are appended to the
   session's `launcher.log` as `<unix secs> update check: <reason>`, the
   format `session::Logger` uses (`src/session.rs:505-519`), and nowhere
   else. The update module writes the file itself: the session directory is
   created first with mode 0700, as `AttestationRecord::create` does
   (`src/attest/record.rs:57-64`), and `prepare_session_dirs` later accepts
   the existing directory (`src/session.rs:175-180`). A log write failure is
   ignored.

The manifest's `summary` is parsed but not printed in this version.

### `rts update`

```
rts update [--check | --force]
```

1. Refuse on the Homebrew channel: `rts was installed with Homebrew: run brew upgrade rts`.
   Refuse on Source or a keyless build: `this build has no update key; install a release`
   (Source builds get `this is a source build; install a release` when the
   key is present).
2. Fetch and verify the manifest. Any failure is an error naming the URL and
   the reason.
3. Compare with `ironwire_update::evaluate`:
   - `Available` or `Unsupported`: proceed.
   - `UpToDate`: with `--check`, report `rts <current> is up to date (latest
     release <latest>)`; otherwise refuse `rts <latest> is not newer than the
     running <current>; pass --force to reinstall it`, unless `--force`.
   - `Unknown`: refuse, even with `--force`.
4. `--check` stops here and reports what step 3 found; exit 0.
5. In a fresh private temp directory (`tempfile`, removed on exit), download
   `https://github.com/nearai/nearai-red-sandbox/releases/download/v<latest>/install.sh`
   (the versioned URL, never `latest/download`, so a release published
   meanwhile cannot substitute its script), capped at 64 KiB, and compare its
   sha256 with `install_sh.sha256`. A mismatch is refused before the file is
   made executable or run.
6. Print `installing rts <latest> over <current> to <prefix>`, then run
   `/bin/bash <tmp>/install.sh` with stdio inherited, no timeout (it runs
   `rts setup`, which may pull the guest image for up to 1800 s), the
   operator's environment minus `RTS_RELEASE_BASE`, and:
   - `RTS_VERSION=<latest>`
   - `RTS_INSTALL_PREFIX=<this install's prefix>`
   - `RTS_TARBALL_SHA256=<tarball.sha256>`

   `install.sh` then downloads the tarball and `SHA256SUMS`, checks the
   tarball against both `SHA256SUMS` and `RTS_TARBALL_SHA256`, checks the
   attestation when `gh` exists, swaps the owned paths with rollback, and
   runs `<prefix>/bin/rts setup`. A nonzero exit is reported as `install.sh
   for rts <latest> exited <n>; see its output above` and `rts update` exits 1.
7. Verify the new `<prefix>/bin/rts`:
   - `/usr/bin/codesign --verify --strict '-R=anchor apple generic and certificate leaf[subject.OU] = "KXSWJN7WY8"' <prefix>/bin/rts`
     exits 0 (the `-R=` form was checked on this host 2026-10-30: it
     accepts Apple's `/bin/ls` against `anchor apple generic` and refuses it,
     exit 3, against the team requirement);
   - `<prefix>/bin/rts --version` prints exactly `rts <latest>`.

   Either failure is reported as `rts <latest> was installed to <prefix> but
   <check> failed: <detail>; reinstall with the curl installer` and exits 1.
8. Success: `rts updated from <current> to <latest> (<prefix>/bin/rts)`.

`--force` reinstalls the signed `latest` when it is not newer. It never skips
the signature, the digests, or the post-install checks. `--check` and
`--force` together are a usage error.

The running `rts` is replaced while it runs; macOS keeps the old inode
mapped, and nothing in `rts update` after step 6 executes the old binary's
files from disk.

## Manifest

Fetched from
`https://github.com/nearai/nearai-red-sandbox/releases/latest/download/latest.json`
and `.../latest.json.sig`, through `setup::download` (`src/setup.rs:107-140`):
`https` only, redirects only to `github.com`,
`objects.githubusercontent.com` and `release-assets.githubusercontent.com`
(exact host match, `src/setup.rs:20-46`), at most five redirects, each
checked before it is fetched. Caps: 64 KiB for `latest.json`, 1 KiB for the
signature, refused as soon as the body exceeds them.

Example (the layout `scripts/release/sign-manifest.sh` writes byte for byte):

```json
{
  "latest": "0.2.0",
  "minimum_supported": "0.1.0",
  "published": "2026-11-02T18:04:11Z",
  "tarball": {
    "name": "rts-0.2.0-aarch64-apple-darwin.tar.gz",
    "sha256": "3f1c0d2a9e5b7c4d6f8a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e"
  },
  "install_sh": {
    "sha256": "8e2b1f0c3d4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c"
  }
}
```

`minimum_supported` is omitted when no floor is set. `summary` is never
written by the release workflow in this version. The field is
`minimum_supported`, not `minimum`, because `rts` reuses
`ironwire_update::Manifest` (`ironwire_update/src/lib.rs:89-102`) through
`#[serde(flatten)]` in an rts wrapper. serde does not allow
`deny_unknown_fields` with `flatten`, so unknown fields are ignored, which
also lets a later release add fields without breaking older clients.

Rules `rts` enforces after the signature verifies:

- `latest` matches `^[0-9]+\.[0-9]+\.[0-9]+$` (no `v`; it becomes
  `RTS_VERSION` and a URL path segment). `ironwire_update` would accept a
  leading `v`; `rts` does not.
- `minimum_supported`, when present, matches the same pattern.
- `tarball.name` is exactly `rts-<latest>-aarch64-apple-darwin.tar.gz`.
- `tarball.sha256` and `install_sh.sha256` are 64 lowercase hex characters.
- `published` parses as RFC 3339. It is informational; `rts` does not compare
  it with the clock.

## Signing in CI

A new script, `scripts/release/sign-manifest.sh`, runs locally and in CI:

```
sign-manifest.sh --version X.Y.Z --dir DIST --public-key-hex HEX
                 [--minimum X.Y.Z] [--published RFC3339] [--openssl PATH]
```

The private key comes only from the environment variable
`RTS_UPDATE_SIGNING_KEY_PEM_BASE64`. The script:

1. Refuses a missing or malformed argument, an empty key variable, a public
   key that is not 64 hex characters, a `--minimum` above `--version`, and an
   OpenSSL whose `version` output does not start with `OpenSSL 3` or a later
   major version (LibreSSL is refused by name). Default OpenSSL:
   `$(brew --prefix openssl@3)/bin/openssl`.
2. Checks `DIST/SHA256SUMS` with `shasum -a 256 -c`, and takes the tarball's
   and `install.sh`'s digests from it (exactly one line each).
3. Writes `DIST/latest.json` in the layout above. Every value is checked
   against a fixed pattern first, so no JSON escaping is needed.
4. Decodes the key under `umask 077` into a `mktemp -d` directory removed by
   an EXIT trap, signs with `openssl pkeyutl -sign -rawin`, and writes the
   base64 of the 64 raw bytes, without line breaks or a trailing newline, to
   `DIST/latest.json.sig`.
5. Verifies the signature with the public key from `--public-key-hex`
   (wrapped as an Ed25519 SubjectPublicKeyInfo: DER prefix
   `302a300506032b6570032100` then the 32 key bytes) using `openssl pkeyutl
   -verify -pubin -rawin`. On failure it deletes `latest.json` and
   `latest.json.sig` and exits 1: a secret that does not match the
   compiled-in key cannot ship.
6. Appends both files to `SHA256SUMS` and re-runs `shasum -a 256 -c`.

The floor comes from `packaging/update/minimum-version`, one `X.Y.Z` line, or
the file is absent for no floor. Raising it is a reviewed commit.

Workflow changes (`.github/workflows/release.yml`), keeping every existing
step and its order:

- `release-config`: on a tag push, refuse unless `vars.RTS_UPDATE_PUBLIC_KEY_HEX`
  is 64 lowercase hex characters.
- `build`, "Install test tools": also `openssl@3`.
- `build`, "Build rts": `RTS_UPDATE_PUBLIC_KEY_HEX: ${{ vars.RTS_UPDATE_PUBLIC_KEY_HEX }}`
  in the step's environment. The test gate does not see it, so tests never
  depend on the release key.
- `build`, a new "Sign the update manifest" step after "Package" and before
  attestation: refuses an empty `RTS_UPDATE_PUBLIC_KEY_HEX` for every event
  (so a dry run cannot quietly build a keyless binary), then runs
  `sign-manifest.sh` with the secret. Dry runs sign with the real key and
  publish nothing, as today.
- Attestation subjects add `latest.json` and `latest.json.sig`; the uploaded
  `dist` artifact carries them.
- `publish`: the required-file loop adds both names; `gh release create`
  already uploads everything in `dist`. `check-existing-release.sh` needs no
  change: it derives the expected assets from `SHA256SUMS`, which now lists
  both. The formula step reads only the tarball's line.

The order is now: test gate, build, sign and notarize binaries, package,
sign the manifest, attest, upload, publish, tap.

## Verification in `rts`

1. Fetch `latest.json` and `latest.json.sig` as above.
2. Signature: strip at most one trailing `\n` from the `.sig` body; decode
   with standard base64 (`base64` 0.23, already direct); the result must be
   exactly 64 bytes; `VerifyingKey::from_bytes(key)?.verify_strict(manifest_bytes,
   &Signature::from_bytes(&sig))`. This runs before the manifest is parsed,
   over the bytes exactly as fetched: no re-serialization, no trimming.
3. Parse and check the rules above.

The compiled-in key is a `const Option<[u8; 32]>` built by a `const fn` from
`option_env!("RTS_UPDATE_PUBLIC_KEY_HEX")`. Any value that is not exactly 64
hex characters panics in const evaluation, which is a compile error. Every
function that verifies takes the key as a parameter, so tests use a
throwaway key and never the release key.

## Failure handling

- Launch: never fails, never waits more than 3 s, prints only the notice.
  Every failure goes to `launcher.log` with its reason.
- `rts update`: every failure exits 1 with one line naming the step, the URL
  or path, and the next action. Nothing is run before its digest is checked.
  A failure before `install.sh` runs leaves the install untouched. A failure
  inside `install.sh` is handled by its rollback (it restores the earlier
  owned paths if a move fails) and reported. A failure after `install.sh`
  succeeded (codesign or version) leaves the new files in place and says so;
  the remedy is the curl installer, which does not depend on the running
  binary.

## Security notes

Assets on GitHub releases are integrity-checked by `SHA256SUMS`, which lives
in the same release, so an attacker who can write releases can rewrite both.
The update key adds authenticity that does not depend on GitHub.

An attacker who controls GitHub releases (or the network path to them) but
not the update key:

- Cannot make `rts update` install anything the key did not sign:
  `install.sh` is pinned by the signed `install_sh.sha256` before it runs,
  and the tarball by the signed `tarball.sha256`, which `install.sh` enforces
  through `RTS_TARBALL_SHA256` before unpacking. The installed `rts` must also
  carry a Developer ID signature from team `KXSWJN7WY8` and report the signed
  version. mvm, opencode and the guest image stay pinned by digests compiled
  into `rts` (`rts setup`).
- Cannot forge a notice: an unsigned or altered manifest is logged and
  ignored.
- Can withhold updates: serve nothing, an error, or an older correctly
  signed manifest (a replay). The launch check then shows no notice, and
  `rts update` refuses because the replayed version is not newer. There is
  no expiry in the manifest, so freezing is undetectable by `rts`; the
  operator can compare with the releases page.
- Can, with `--force` and a replayed older manifest, make `rts update`
  reinstall an older signed release. `rts update` prints the version it is
  installing, and `--force` is for repair, not routine use.
- Can see that a client checked (one request per 24 h per install, which the
  opt-outs disable).

Without `gh`, `install.sh` cannot check the build-provenance attestation, but
the signed digests still bind every file it installs.

Key loss: no new manifest can be signed, so the launch check stops finding
updates (each failure is logged) and `rts update` reports the signature
failure. Recovery: generate a new key, set the variable and the secret,
release, and tell operators to reinstall with the curl installer or `brew
upgrade`; a binary built with the new key resumes normal updates.

Rotation (planned): one transition release built with the new public key
compiled in but whose manifest is signed with the old key, so existing
installs accept it. The workflow verifies the signature against the same
variable `cargo build` compiles in, so this release needs a one-off reviewed
workflow edit: "Build rts" reads the new key, and "Sign the update
manifest" passes the old public key to `--public-key-hex` with the old
secret. After it ships, revert that edit and switch the secret to the new
key. There
is no revocation: a leaked key stays trusted by every binary that compiled
it in, so a compromise is handled like key loss, with a reinstall notice.

The public key is printed in `README.md` so anyone can check a manifest by
hand:

```sh
printf '302a300506032b6570032100%s' 9b4a81b8bd017898c36871c6bd1cb890faf95b6e378e72eb99b9c15841f02ac9 | xxd -r -p > pub.der
openssl pkey -pubin -inform DER -in pub.der -out pub.pem
base64 --decode < latest.json.sig > sig.bin
openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in latest.json -sigfile sig.bin
```

## Testing

Rust, offline, with `setup::FakeFetch`, a fake `Host`, a fake installer, an
injected clock and a throwaway key `SigningKey::from_bytes(&[7; 32])`:

- Manifest: a valid manifest and signature verify; a tampered byte, an added
  trailing newline, or a re-serialized equal JSON fails; a wrong key fails; a
  truncated, 63- or 65-byte, or non-base64 signature fails; a missing
  signature URL fails; a body over 64 KiB or a signature over 1 KiB fails;
  `latest` with a `v`, a wrong tarball name, or an uppercase digest fails;
  unknown fields are accepted.
- Compiled key: `parse_key_hex` accepts 64 hex characters and panics on 63,
  65 and a non-hex character (const panics tested at runtime with
  `#[should_panic]`).
- Channel: a Cellar keg is Homebrew; a prefix with the plugin directory is
  Release; `target/debug/rts` and a bare `bin/rts` are Source.
- Launch check: no fetch on Source, keyless, `RTS_NO_UPDATE_CHECK=1`, or
  `updateCheck: false` (and the cache is not read); cadence (1 h after a check
  no fetch, 25 h after a fetch, a future `at` fetches); a fetch that sleeps
  10 s returns within the deadline and logs a timeout; a failure keeps the
  previous status; the notice texts for both channels and the floor; a stale
  cached `Available` below the running version prints nothing; the cache
  directory is created 0700; failures land in `launcher.log` and not in the
  notice.
- `rts update`: Homebrew and Source refusals; not-newer refused, `--force`
  allowed, `Unknown` refused with `--force`; `--check` downloads only the
  manifest; an `install.sh` digest mismatch is refused and the installer is
  never called; the installer receives `RTS_VERSION`, `RTS_INSTALL_PREFIX`,
  `RTS_TARBALL_SHA256` and has `RTS_RELEASE_BASE` removed; a nonzero
  installer exit is reported; a failing codesign requirement and a wrong
  `--version` are reported as failures with exit 1; the exact codesign argv.
- Config: `"updateCheck": false` parses; a non-boolean is refused.
- CLI: `rts update`, `--check`, `--force` parse; `--check --force`, duplicates
  and unknown flags are refused.
- `install.sh` (bun, `tests/unit/install.test.ts`): a `RTS_TARBALL_SHA256`
  that differs from the tarball is refused before unpacking; a malformed one
  is refused; unset keeps today's behaviour.
- Signing script (bun, `tests/unit/release.test.ts`, throwaway key from
  `openssl genpkey`): the manifest has the exact layout; the signature
  verifies with OpenSSL and with the public key; a wrong public key is
  refused and leaves no `latest.json`; an empty secret, LibreSSL, a bad
  `--minimum` are refused; `SHA256SUMS` gains exactly two lines and still
  checks; no key material is left in `TMPDIR`.
- Workflow (bun): "Sign the update manifest" comes after "Package" and
  before attestation; both files are attestation subjects and in publish's
  required list; "Build rts" passes `vars.RTS_UPDATE_PUBLIC_KEY_HEX`;
  `release-config` refuses a tag push without it.
- Before the first release that carries this: a dry run signs and verifies
  with the real key; after the next tag, `rts update --check` on an install of
  the previous release reports it, and `rts update` installs it.

## Out of scope

Automatic installation, background or in-session checks, prerelease or
channel selection, manifest expiry and freeze detection, key revocation,
multiple signing keys, delta updates, Homebrew-side update logic (the
formula is unchanged), Linux and Intel Macs, and showing `summary`.

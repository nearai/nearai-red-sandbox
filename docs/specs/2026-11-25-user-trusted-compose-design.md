# Trusting an unreviewed NEAR AI build at launch

Status: draft, 2026-11-25. Builds on the signed attestation policy feed (#66).

## Why

NEAR AI redeploys the production gateway and models to new TEE builds, and
each build has a new compose hash. Today a build that is neither pinned in
`opencode/attestation-policy.json` nor endorsed by the signed feed refuses the
launch, with an error that points at a CLI flag the Gateway app cannot pass.
The user can do nothing except wait for an rts or Gateway release.

The feed (#66) endorses most redeploys automatically. What still reaches the
user is a **held** build, one whose content differs from a reviewed baseline.
For those, the owner wants the user to be able to decide for themselves,
with a way to check the build independently, instead of the launch failing.

Once that exists, a production redeploy no longer blocks a release, so the
Gateway's live-attestation release gate can stop blocking on production pins
(see "Gateway").

## Goals

- A launch that would fail only because a compose hash is unlisted asks the
  user, on the terminal the session runs in, whether to trust that build.
- Trust covers that exact hash, for that role, in that NEAR AI environment,
  on that device. Nothing broader.
- Every other check still applies to a trusted build: TDX quote, TCB policy,
  report_data and nonce binding, `mr_config_id == sha256(app_compose)`, and for
  models the GPU verdict.
- The prompt links to an independent record of the same build.
- A trusted build is never silent: each launch that relies on one says so,
  and attestation.json records it.

## Non-goals

- Staging. Staging builds of the Gateway already accept any measured build
  (`MrConfigOnly`).
- A native app dialog. The prompt is terminal text in the Red Sandbox window,
  so one implementation covers macOS, Windows and the `rts` CLI.
- Prompting mid-session. Re-attestation keeps today's behaviour (key
  continuity, otherwise the session ends), plus it accepts builds the user
  already trusted.
- Trusting by anything other than the exact hash: no instance-label
  normalization, no "trust all builds", no expiry-free blanket mode.

## Anti-goals

- A prompt that can be answered by default, by a script, or without a
  terminal. Non-interactive launches refuse exactly as today.
- Trust that survives revocation. A hash the feed revokes is refused even if
  the user trusted it.
- Trust that crosses environments or roles. A staging trust never applies to
  production; a gateway trust never admits a model compose.

## Approaches considered

1. **Retry with `MrConfigOnly` after the user agrees.** Rejected: the retry
   fetches a new report, which may be a different build from the one shown,
   and it accepts any build for the whole session.
2. **Native dialog in the Gateway app.** Rejected for now: needs a typed error
   through the daemon, the C ABI, Swift and C#, plus a retry flow, for the
   same decision the terminal can ask.
3. **Chosen: a user-trusted set, prompted in rts.** rts returns a typed
   "not trusted" failure carrying the role, hash and build name. If the launch
   is interactive and in `Pinned` mode, it shows the prompt; on yes it saves the
   hash and attests again from scratch with the hash in the trusted set. The
   retry runs every check, so the prompt never vouches for anything but the
   compose.

## Design

### rts library

- `report::check_compose` gains a fourth source after pinned and endorsed:
  `policy.user_trusted`, a set of `(role, hash)`. A match returns a new
  `ComposeAcceptance::UserTrusted` (`"user-trusted"`). Revocation is checked
  first, as today.
- The final refusal becomes typed: `AttestationFailure::ComposeNotTrusted {
  model, role, hash, app_name }`, raised only in `Pinned` mode without key
  continuity. `message()` keeps today's text, so the CLI and logs read the same.
- `Attestor::real` takes the user-trusted set for its environment alongside the
  feed document, for both launch and re-attestation.
- `refresh-attestation-policy.py` adds `user-trusted` to `UNPINNED`, so such
  evidence can be proposed as a pin.

### The trust store

- `<rts home>/trusted-composes.json`, beside the feed cache: a list of
  `{environment, role, sha256, app_name, trusted_at}`. Created owner-only
  (0600, and the owner-only ACL on Windows, as the session directories are),
  written atomically.
- An unreadable, malformed, or wrongly permissioned store is treated as empty,
  with one `[rts]` line saying so. It never fails a launch that does not need it.
- `rts trust list` prints it. `rts trust forget <hash-prefix>` removes entries
  (a prefix must match exactly one).

### The prompt

Shown only when all of these hold: the failure is `ComposeNotTrusted`, the
compose policy is `Pinned`, the environment is production, and stdin and
stderr are both terminals. The progress display is paused while it shows.
Anything but `y` or `yes` (case-insensitive) refuses. At most three prompts
per launch, then refuse, so a gateway flapping between builds cannot loop.

After a yes, rts saves the entry, then attests again with a fresh nonce. If the
retry meets a different unlisted build, it prompts again for that one.

### Gateway

- Bump `rts` to the release that carries this.
- The production compose policy stays `Pinned`; the app passes nothing new.
  The Red Sandbox window is the terminal, so the prompt appears there.
- `release-apps`: verify production twice. `mr-config-only` stays blocking (a
  broken verifier still stops a release); `pinned` becomes non-blocking and
  reports drift, since an unlisted production build now prompts instead of
  failing.

## Wording (approved by the owner 2026-11-25)

The prompt and the per-launch line say only that the build is new and that
the user trusted it. They never mention review: what the user decides on is
the build, the checks that ran and the Compare link.

The prompt, for a gateway build:

```
NEAR AI moved its production gateway to a new build.

  Build    dstack-0.5.15
  Hash     f4a9b4803216afe5fe6a59df20790d6c12cfaf64055e121ba9375756398fb2b5
  Checked  TDX quote, TCB status, this launch's nonce, compose hash
  Compare  https://github.com/nearai/nearai-red-sandbox/issues?q=f4a9b4803216

Trust this build on this device? Red Sandbox will use it without asking
again until you run `rts trust forget f4a9b480`. [y/N]
```

For a model build, only the first line changes: `NEAR AI moved <model> to a new build.`
The prompt lists only checks that have run when it appears; the GPU verdict
runs in the full re-attestation after a yes.

Each launch that relies on a trusted build (one line, in the launch progress):

```
[rts] NEAR AI gateway build f4a9b480: you trusted it on 2026-11-25
```

On a refusal, today's error is unchanged.

## Left to the builder

- Where the pause/resume hook into `brand::progress` goes.
- The exact Windows ACL call (reuse what the session directory uses).
- Tests: check_compose ordering (revoked beats user-trusted, pinned and
  endorsed beat it, role and environment are both keys); the prompt refuses
  without a TTY, on empty input and on anything but y/yes; the three-prompt
  cap; the retry is a full re-attestation with a new nonce; a corrupt or
  world-readable store is ignored with a message.

## Open

- The Gateway has no UI to list or forget trusted builds; the file and the
  `rts trust` CLI are the only way. Acceptable for v1?
- Hold issues are created only once the publisher leaves dry-run mode; until
  then the Compare link finds nothing.

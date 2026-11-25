# Signed attestation policy feed: design

Date: 2026-11-24
Status: draft for review. Decided by Zaki on 2026-11-24: a live policy feed
signed by us, signed automatically by CI when a new build passes content
rules, and held for a person when it does not. Decided 2026-11-24 after
review of PR #64: strict rules only (no Tier E), and two compiled-in keys.

Read "Validation against real redeploys" first. With strict rules, every
real redeploy we have on record would have been held. Only per-instance
variation is signed without a person.

## Problem

`rts` pins NEAR AI compose hashes in `opencode/attestation-policy.json` and
`opencode/attestation-policy-staging.json`, compiled in with `include_str!`
(`src/attest.rs`, `policy_json`). Under the default `--compose-policy pinned`,
`check_compose` (`src/attest/report.rs`) refuses any compose that is not on
the list. Key continuity (#41) keeps a running session alive across a
redeploy, but a new session started after a redeploy still fails.

The list does not stay current:

- Production pins went from 2 (2026-10-29) to 7 (2026-11-23), all added by
  hand from `mr-config-only` sessions with `scripts/refresh-attestation-policy.py`.
  The gateway alone took three hashes in that time.
- Each new hash needs an `rts` release, and releases are now gated on a live
  attestation check (b429edc), so a NEAR redeploy blocks our releases as well
  as our users' launches.
- The model compose hash differs per instance, not just per build. Pins
  `e3902667a262` and `edabf8039210` are the same DeepSeek build on two hosts.
  Their `app_compose` differs in one line of `docker_compose_file`:
  `INSTANCE_LABEL=gpu04` versus `INSTANCE_LABEL=gpu02`. Adding a GPU host
  creates a new hash with no build change, and nobody sees that host until a
  session lands on it.

## What a model compose hash proves

This bounds what any compose policy, pinned or fed, can promise.

Measured on the 2026-11-20 production DeepSeek composes, the model CVM's
`app_compose` does not contain the inference server. It contains a
management plane:

- `compose-manager` (`nearaidev/compose-manager@sha256:ae4332fd...`) clones
  `https://github.com/nearai/cvm-compose-files` at runtime and runs the model
  compose it finds there. It has `/var/run/docker.sock`, `pid: host`,
  `SYS_ADMIN` and `SYS_PTRACE`, and it can `nsenter` into PID 1.
- `compose-manager-launcher` swaps the compose-manager and collector images at
  runtime: `LAUNCHER_CHANNEL=${LAUNCHER_CHANNEL:-latest}`, accepting images
  whose cosign identity matches
  `https://github.com/nearai/compose-manager/.github/workflows/.*`.
- `pre_launch_script` restores the launcher's last swapped image across
  reboots, so the image that runs can differ from the digest in the compose.

So a model compose hash proves which bootstrap a host booted. It does not
prove which model server is running. The image that serves inference is
chosen at runtime by NEAR's GitHub repository and NEAR's cosign-signed build
pipeline. The feed cannot change that. What the content rules can do is make
sure those trust anchors never change without a person seeing it.

The production gateway compose is different (checked on `1787a4af87ea`,
2026-11-23). Its four images (`nearaidev/cloud-api`, `nearaidev/cvm-ingress`,
`otel/opentelemetry-collector-contrib`, `alpine`) are pinned by digest with
no `${...}` substitution, and there is no `pre_launch_script`. There the hash
does pin the workload.

A note to NEAR asking whether the model CVM can measure its workload (pinned
model compose in `app_compose`, or the runtime-loaded compose recorded in an
event log RTMR) is a separate follow-up. It is outside this spec.

## Decisions

| Topic | Decision |
|---|---|
| Trust | A policy document signed with a key we hold, verified by `rts` against public keys compiled in. Where it is hosted is not trusted. |
| Who signs | A scheduled GitHub Actions workflow in `nearai/nearai-red-sandbox`. It signs a new hash automatically only when every content rule passes. Anything else is held. A person approves a held build only through a reviewed pull request that adds it to the baselines. The next run then signs it, with no `rts` release. |
| Scope | Extends the compiled-in lists. It never removes a local check: TDX quote, TCB policy, `report_data` binding, `mr_config_id == sha256(app_compose)`, and the NVIDIA GPU verdict all still run in `rts`. |
| Environments | One feed per NEAR environment (production, staging), with the environment inside the signed body. A staging document is refused for production and the reverse, as the compiled-in lists already are. |
| Per-instance variation | A fixed, compiled-in normalization in `rts` (`instance-label-v1`): before hashing, the value of each `INSTANCE_LABEL=` line in `docker_compose_file` is replaced with `*`. The feed can name a normalization; it cannot define one. |
| Freshness | Every document has `expires`, 72 hours after `issued`. CI publishes hourly. `rts` refuses an expired document. |
| Rollback | Every document has a `version` (unix seconds at signing). `rts` stores the highest version it accepted per environment and refuses lower ones. |
| Revocation | `revoked` hashes in the document override both the feed and the compiled-in lists. |
| Failure | Fetch or verify failure falls back to the cached document if it has not expired, then to the compiled-in list and key continuity. It never falls back to accepting an unlisted compose. |
| Keys | Separate from the update key. Two public keys compiled in: the CI signing key and an offline recovery key. Either signature is accepted. |
| Log | Each published document is committed to a `attestation-policy-log` branch with `createCommitOnBranch` (GitHub-signed, as `scripts/release/bump-tap.sh` does). |
| Dependencies | None new: `ed25519-dalek`, `reqwest`, `sha2`, `serde_json` and `hex` are already in `Cargo.toml`. CI uses OpenSSL 3 and `cosign`. |

## The document

Published as assets of a fixed release tag, `attestation-policy`, in
`nearai/nearai-red-sandbox`:

```
https://github.com/nearai/nearai-red-sandbox/releases/download/attestation-policy/production.json
https://github.com/nearai/nearai-red-sandbox/releases/download/attestation-policy/production.json.sig
https://github.com/nearai/nearai-red-sandbox/releases/download/attestation-policy/staging.json
https://github.com/nearai/nearai-red-sandbox/releases/download/attestation-policy/staging.json.sig
```

Fetched through `setup::download`, which already restricts redirects to
GitHub's release hosts. Caps: 256 KiB for the document, 1 KiB for the
signature. The signature is base64 of the raw 64-byte Ed25519 signature over
the exact bytes of the document, verified with `verify_strict`, the same
format as `latest.json.sig`.

```json
{
  "schema": 1,
  "environment": "production",
  "version": 1764028800,
  "issued": "2026-11-25T00:00:00Z",
  "expires": "2026-11-28T00:00:00Z",
  "entries": [
    {
      "role": "gateway",
      "match": "exact",
      "sha256": "1787a4af87ea...",
      "app_name": "dstack-0.5.12",
      "first_seen": "2026-11-23T17:02:11Z",
      "endorsed_by": "rules:gateway-v1"
    },
    {
      "role": "model",
      "match": "instance-label-v1",
      "sha256": "<sha256 of the normalized app_compose>",
      "app_name": "dstack-nvidia-0.5.11",
      "first_seen": "2026-11-20T09:14:40Z",
      "endorsed_by": "rules:model-v1"
    }
  ],
  "revoked": []
}
```

Rules `rts` enforces after the signature verifies:

- `schema` is 1 and `environment` is the session's environment.
- `issued` <= now + 5 minutes and now < `expires`, and `expires` - `issued`
  is at most 7 days.
- `version` >= the stored high-water mark for that environment.
- `role` is `gateway` or `model`. `match` is `exact` or a normalization this
  build knows. Unknown `match` values are skipped, not errors, so a later
  normalization does not break older clients.
- Every `sha256` is 64 lowercase hex characters.

Unknown fields are ignored. `app_name`, `first_seen` and `endorsed_by` are for
people and the log. `rts` does not act on them.

## `rts` changes

1. `Policy` (`src/attest.rs`) gains a role for each hash and a revoked set.
   The compiled-in JSON files gain an optional `role` field. Entries without
   one keep matching any role until they are backfilled, which is one
   commit: the `source` text already says gateway or model.
2. New `src/attest/feed.rs`: fetch, verify, parse, and merge into `Policy`.
   It caches the last accepted document and its signature in `rts`'s
   per-user state, next to the update cache (`feed/<environment>.json`,
   directory created 0700), along with the
   high-water `version`. The cache is re-verified on every read, so a local
   edit is refused.
3. `check_compose` checks in this order:
   1. Refuse if `sha256(app_compose)` is revoked.
   2. Accept as `pinned` if the exact hash is pinned for this role.
   3. Accept as `endorsed` if the exact hash, or the `instance-label-v1`
      hash, is endorsed for this role by the feed.
   4. Otherwise, use the existing `mr-config-only` and key-continuity paths.
4. `ComposeAcceptance` gains `Endorsed`. `attestation.json` records
   `compose_acceptance: "endorsed"`, the feed `version` and the match used,
   so every session's evidence names the document that admitted it.
5. When fetched: at launch, before attestation, on a worker bounded by 5
   seconds. And in the forwarder's re-attestation, when this session last
   loaded its document more than an hour ago, or that document has expired.
   The hour is the session's own, not the cache file's age, which another
   session can keep fresh. Launch prints one line naming the source used:
   feed version, cached version, or compiled-in only.
6. `RTS_ATTESTATION_POLICY_FEED=off` skips the fetch and uses only the
   compiled-in lists, for offline and reproducible runs.
7. Public keys come from the build-time variable
   `RTS_ATTESTATION_POLICY_PUBLIC_KEYS_HEX` (comma-separated, one or two keys)
   through `option_env!`, as the update key does. A malformed value is a
   build error. A build without keys never fetches.

`scripts/refresh-attestation-policy.py` stays as the manual path. It also
treats `endorsed` as already accepted.

## Normalization `instance-label-v1`

Input is the `app_compose` string from the quote-verified report, after
`mr_config_id` has been checked against its exact bytes. Then:

1. Parse it as JSON. It must be an object with a string `docker_compose_file`.
2. In `docker_compose_file`, replace the line matching
   `^(\s*-\s*INSTANCE_LABEL=)[A-Za-z0-9._-]{1,64}$` with `$1*`. Exactly one
   line must match. Any other line containing `INSTANCE_LABEL` must be a YAML
   comment (`^\s*#`). The real compose has one, explaining the label. If
   either condition fails, the normalization does not apply.
3. Serialize with keys sorted recursively and no insignificant whitespace,
   then take SHA-256. Sort explicitly: `serde_json`'s `preserve_order`
   feature is enabled in this workspace through feature unification
   (`cargo tree -e features -i serde_json`), so `Map` keeps insertion order.

Checked on 2026-11-24 against the real composes: `e3902667a262` (`gpu04`) and
`edabf8039210` (`gpu02`) each have one matching line and one comment line,
and both normalize to the same hash.

The label is a Slack display name. The 2026-11-20 compose's comment says it
identifies the host in deploy notifications (nearai/infra#141). Allowing any
value of it changes nothing about what runs. Any future normalization goes
through code review in `rts`, never through the feed.

## CI: the publisher

New workflow `.github/workflows/attestation-policy.yml`:

- Triggers: `schedule` hourly, `push` to `main` touching
  `opencode/attestation-baselines/**` (so an approved baseline is signed within
  minutes), and `workflow_dispatch` with no inputs.
- Two jobs, so the signing key never shares a job with network input or a
  freshly built `rts`, as in the update-key design:
  - **`evaluate`**: no environment, `contents: read`, and no secrets except a
    NEAR AI API key for the attestation endpoint. It builds `rts` from `main`
    on `macos-26`, the release runner, collects, and runs the rules. It uploads
    an artifact holding each candidate's raw `app_compose`, plus its proposed
    next document.
  - **`sign`**: in a new environment, `attestation-policy`, restricted to
    `main`. The environment cannot require reviewers, because it runs
    unattended. It holds the only copy of the CI private key
    (`RTS_ATTESTATION_POLICY_SIGNING_KEY_PEM_BASE64`), so the release workflow,
    pull requests and forks never see it. `sign` does not trust the proposed
    document. It recomputes every new entry from the raw `app_compose` in the
    artifact: sha256 of the bytes, normalization, and the content rules in a
    stdlib-only Python script checked into the repository. It signs only
    what it reproduces. A compromised `evaluate` job can withhold entries,
    but it cannot get one signed that fails the rules.
- There is no "approve this hash" input. A held build is approved only by
  merging a reviewed pull request to the baselines.

### Steps

1. **Collect** (`evaluate`). For each environment, and for the gateway and
   every model in `config::DEFAULT_MODELS`, run the existing live test
   `tests/live_attest.rs` with `RTS_LIVE_NEAR_ENVIRONMENT=<env>`,
   `RTS_LIVE_COMPOSE_POLICY=mr-config-only` and `RTS_LIVE_RECORD_DIR`. It
   runs the same `Attestor` as a launch, with no session or VM, and writes
   `rts`'s own `attestation.json`, the same evidence the release gate
   checks. No new subcommand. Each model is sampled 8 times per run, because each
   call lands on whichever instances the gateway picks. Only entries that
   passed every check reach step 2.
2. **Diff** (`evaluate`). Drop hashes already pinned or endorsed. For each
   new `app_compose`, run the content rules below against every baseline in
   its role's set.
3. **Sign** (`sign`). If at least one entry is new, or the current document
   is more than 24 hours old, write the next document. It contains everything
   still in the current document plus the new entries that `sign` reproduced.
   Sign it with OpenSSL 3 `pkeyutl -sign -rawin` under `umask 077`, verify it
   with the public key, then upload it with `gh release upload --clobber` and
   commit it to the log branch.
4. **Hold** (`evaluate`). For each entry that failed a rule, open or update
   one issue per compose hash. The issue names the rule, gives the field-level
   diff against the closest baseline, and links the run. It also includes the
   commands that open a pull request adding the compose to the baselines
   (`evaluate` has no write access, so it does not open the PR itself). A
   person reviews that diff and merges it or closes it. Merging triggers a run
   that signs the entry.

Entries leave the document only through `revoked` or through a reviewed
change to the baseline. Old hashes are not removed when a newer build
appears, because NEAR runs mixed fleets during rollouts.

### Baselines

`opencode/attestation-baselines/<environment>/<role>/<sha256>.json` each hold
one reviewed `app_compose`, exactly as NEAR served it. Each role has a set
of baselines, not one, because NEAR runs different templates at the same
time. On 2026-11-23, Qwen ran `dstack-nvidia-0.5.12` while DeepSeek ran
`0.5.11`, and rollouts mix builds. A candidate passes if it passes the rules
against any one member of its role's set.

The sets are seeded from every compose already pinned in the compiled-in
lists for which we hold the raw `app_compose`. Production pins `e4b83d924284`
(Qwen, pinned in both environments), `10d29b736472` and `85c10cc2c733`
(staging gateways) are not on hand locally. They are captured from a live session before seeding. Changing a
baseline is a normal pull request, and that review is where a person
approves a structural change. A baseline is removed in the same pull
request that revokes its hash.

### Content rules

All rules compare the candidate's parsed `app_compose` with the baseline.
`digest-blind(x)` means `x` with every `@sha256:<64 hex>` replaced by
`@sha256:*`.

Both roles:

- **C1** Every top-level field except `docker_compose_file` and `name` is
  equal to the baseline. This covers `allowed_envs`, `kms_enabled`,
  `local_key_provider_enabled`, `key_provider_id`, `public_logs`,
  `public_sysinfo`, `no_instance_id`, `secure_time`, `gateway_enabled`,
  `runner`, `manifest_version`, `port_policy` and `pre_launch_script`.
- **C2** `name` matches `^dstack(-nvidia)?-\d+\.\d+\.\d+$`. A change in the
  dstack version is allowed.
- **C3** Every `image:` reference ends in `@sha256:<64 hex>`. Interpolated
  defaults (`${VAR:-repo@sha256:...}`) count, and must have the same `VAR` and
  repository as the baseline.
- **C4** The set of image repositories equals the baseline's. A new
  repository holds the entry.

Gateway (`rules:gateway-v1`):

- **G1** `digest-blind(docker_compose_file)` is byte-equal to the baseline's.
  Only image digests may change.
- **G2** Each changed digest of a `nearaidev/*` image verifies with
  `cosign verify` against an identity regexp under
  `https://github.com/nearai/`. A changed digest of a third-party image
  (`alpine`, `otel/opentelemetry-collector-contrib`) holds the entry, since
  those change rarely and have no NEAR provenance.

Model (`rules:model-v1`):

- **M1** `digest-blind` of the `instance-label-v1`-normalized
  `docker_compose_file` is byte-equal to the baseline's, and so is
  `digest-blind(pre_launch_script)`.
- **M2** Each changed `nearaidev/compose-manager*` digest verifies with
  `cosign verify --certificate-identity-regexp 'https://github.com/nearai/compose-manager/.github/workflows/.*'`.
  This is the same anchor the launcher uses. Since the launcher already
  trusts that identity at runtime, this check adds nothing to the TEE's
  guarantee. What it adds is that we notice an unsigned digest.
- M1 covers the trust anchors without listing them: `GITHUB_REPO`,
  `LAUNCHER_COSIGN_IDENTITY_REGEXP`, `COMPOSE_MANAGER_IMAGE_REPO`,
  `OTELCOL_IMAGE_REPO`, `LAUNCHER_CHANNEL`, the capability grants and the
  `docker.sock` mounts. Any change to them holds the entry.

Whether `nearaidev/cloud-api` and `nearaidev/cvm-ingress` images carry cosign
signatures has not been checked. That is the first task of the plan. If they
are not signed, G2 holds every gateway digest change, and we decide then
whether to accept digest-only changes without provenance.

### Validation against real redeploys

These rules were run on 2026-11-24 against every pair of consecutive
composes we hold. That is every compose in local session evidence and
`tests/fixtures/near-prod/live-run-2026-10-29.json`, keyed by
`sha256(app_compose)`. The script and its output are not committed, and are
rerun in plan step 1.

| Pair | What changed | Result |
|---|---|---|
| Gateway `f571e5dafe8f` -> `53cd435edbc1` (prod, 10-29 -> 11-20) | `dstack-vpc` and `dstack-vpc-client` (Tailscale, `NET_ADMIN`, `/dev/net/tun`) removed. `port_policy` added. `allowed_envs` renamed 2 and added 5. 3 digests changed. | Held: C1, C4, G1 |
| Gateway `53cd435edbc1` -> `1787a4af87ea` (prod, 11-20 -> 11-23) | One line added to `cloud-api`'s environment: `AUTH_ADMIN_TOKENS_ONLY=${AUTH_ADMIN_TOKENS_ONLY:-false}`. No digest change. | Held: G1 |
| Gateway `1787a4af87ea` -> `d686bb1df6c0` (prod -> staging, cross-environment, for reference) | Environment names and domains, 7 added `allowed_envs`, dstack 0.5.12 -> 0.5.15 | Held: C1, G1 |
| Model `ae66f844658a` -> `e3902667a262` (10-29 -> 11-20) | Collector moved to a launcher-swappable `nearaidev/compose-manager-otelcol`. 4 AWS `allowed_envs` removed. `pre_launch_script` rewritten. | Held: C1, C4, M1 |
| Model `e3902667a262` -> `edabf8039210` (same build, two hosts) | `INSTANCE_LABEL` only | Signed |

So with strict rules, the feed signs per-instance variation automatically.
Every real redeploy still needs a person, but approving one is a pull
request to the baselines, signed within minutes, instead of an `rts`
release. The holds were not false alarms: the first and fourth rows are
changes a reviewer should see.

The second row is the routine case the rules could safely let through, and
it leads to the open decision below.

### Not adopted: a second rule tier

**Tier E** (environment-only) would auto-sign a candidate whose only
difference from a baseline, after digest-blinding and normalization, is in
`environment:` list entries of services that already exist. Each changed or
added entry must:

- keep a variable name that does not end in `_URL`, `_HOST`, `_ENDPOINT`,
  `_DOMAIN`, `_PATH`, `_FILE` or `_DIR`, and
- have a value that is a number, `true`/`false`, or `${VAR}` / `${VAR:-x}`
  where `x` is a number or boolean, and `VAR` is the entry's own name.

`allowed_envs`, images, mounts, capabilities, ports and `pre_launch_script`
stay under the strict rules.

On the data above, Tier E would have signed row 2 and nothing else. The
risk is that an environment flag can change behaviour that matters,
`AUTH_ADMIN_TOKENS_ONLY` itself being an example. Tier E trusts NEAR's
choice of flag values without a person seeing them, though the change stays
in the public log. Not adopted (2026-11-24): strict rules only. Revisit
only if the hold issues show that most holds are flag flips.

## What this guarantees, and what it does not

With the feed, a new session is admitted on a compose that:

- passed every local check in `rts`, and
- differs from a build a person reviewed only by image digests NEAR's CI
  signed (gateway), or by those digests and the instance label (model).

Every admitted hash is in a public, GitHub-signed log, and can be revoked
within an hour of us deciding to.

It does not guarantee:

- **What serves model inference.** See "What a model compose hash proves".
- **Protection against a compromised CI key.** That key can admit any compose
  until it is rotated. The mitigations are that the key exists only in the
  `attestation-policy` environment on `main`, the log is public, and the
  recovery key can sign a document that revokes the attacker's entries.
  Rotating the CI key needs an `rts` release, because both keys are compiled
  in. A root key that delegates to the CI key would remove that need, at the
  cost of a second document format. That is deferred (see Open questions).
- **Freshness while offline.** With the feed offline for more than 72 hours,
  `rts` falls back to the compiled-in lists, which is today's behaviour.

## Tests (written first)

`rts`:

- Signature: accepts either compiled-in key. Refuses a flipped byte in the
  document or the signature, a non-canonical signature (`verify_strict`), and
  a document signed by the update key.
- Rules: refuses the wrong `environment`, an expired document, `issued` in
  the future, a validity window over 7 days, and a lower `version` than the
  stored mark. Accepts an equal `version`.
- Precedence: revoked beats pinned and endorsed. A gateway entry does not
  admit a model compose, nor the reverse.
- Normalization: the two 2026-11-20 DeepSeek composes (`gpu04` and `gpu02`,
  added as fixtures) normalize to one hash. A second uncommented
  `INSTANCE_LABEL` line refuses, and a commented one does not. A label of 65
  characters refuses. Two documents with the same keys in different orders
  normalize to the same hash.
- Fallback: fetch failure with a valid cache uses the cache. With an expired
  cache it uses compiled-in only and does not error. A tampered cache is
  refused and deleted.
- Evidence: `attestation.json` records `endorsed`, the feed version and the
  match type.
- `RTS_ATTESTATION_POLICY_FEED=off` makes no network call.

Publisher (Python, next to `scripts/test_refresh_attestation_policy.py`):

- Each of C1-C4, G1, M1 rejects a one-field mutation of the real baseline.
- The real `edabf8039210` compose passes M1 against the `e3902667a262`
  baseline.
- The validation table reproduces: each real pair gets the result and the
  rule IDs listed there.
- `sign` refuses an artifact whose proposed document lists an entry it
  cannot reproduce from the raw `app_compose`.
- A digest-only change passes. The same change plus one `allowed_envs` entry
  holds.
- The signed document round-trips through the `rts` verifier, with a fixture
  key in tests only.

## Rollout

0. Capture the missing raw composes (Qwen `e4b83d924284`, staging gateways
   `10d29b736472` and `85c10cc2c733`). Commit the rules script with the
   validation table as its test fixture, and check whether the
   `nearaidev/cloud-api` and `nearaidev/cvm-ingress` images are cosign-signed.
1. Land the `rts` side with the feed URL compiled in but no keys set, so
   release builds never fetch. Backfill `role` in both compiled-in lists.
2. Generate the CI and recovery keys. Keep the recovery key offline, and
   publish both public keys in `README.md`, as the update key is.
3. Land the publisher. Run it with `workflow_dispatch` against staging until
   it has produced a week of documents with no false holds that we can't
   explain.
4. Set `RTS_ATTESTATION_POLICY_PUBLIC_KEYS_HEX` in the release workflow and
   ship. Change the release gate (b429edc) to accept `endorsed` as well as
   `pinned`.
5. Stop adding hashes to the compiled-in lists by hand. Keep the lists as the
   offline floor.

## Open questions

- Root-plus-delegation keys instead of two compiled-in keys. That would let
  us rotate the CI key without an `rts` release. Deferred until the two-key
  version has run for a while.
- Whether to sample instances more aggressively, for example per GPU host if
  NEAR exposes a way to target one, so a new host is endorsed before a user
  lands on it, rather than on our next hourly run.
- Whether to ask NEAR to publish their own signed build manifest. If they
  did, G2 and M2 could check it in addition to cosign.

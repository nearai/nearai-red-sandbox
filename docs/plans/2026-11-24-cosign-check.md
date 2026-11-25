# Cosign check and compose capture (plan Task 1, Steps 1-2)

Date: 2026-11-24. Tool: `cosign` v3.1.4 (Homebrew), unauthenticated Docker Hub.

## Result

All four current `nearaidev/*` digests verify under the plan's command:

```
cosign verify --certificate-identity-regexp 'https://github.com/nearai/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com <image@digest>
```

| Image (where it runs) | Digest | Exit | Signatures | Payload `type` |
|---|---|---|---|---|
| `nearaidev/cloud-api` (prod gateway `1787a4af87ea`, `a1c3d2e1455e`) | `sha256:d996bb08f36f0cc913ed7763f7c42bf4124e386a679e397a9acd8a3e69f3a704` | 0 | 6 | `https://slsa.dev/provenance/v1` |
| `nearaidev/cloud-api` (staging gateway `0cf678004e2d`) | `sha256:cabf2003c1b3e3f317b462025d17239c76868dd334294aa6404691bd7993e39f` | 0 | 4 | `https://slsa.dev/provenance/v1` |
| `nearaidev/cvm-ingress` (both gateways) | `sha256:9e9aacb7866a06aa6959fe1c6064f4c3ed62609af35e955df1b95e7325578435` | 0 | 1 | `https://slsa.dev/provenance/v1` |
| `nearaidev/compose-manager` (model composes) | `sha256:ae4332fdb0bfccf6410bc153a58d0b72a596a989cbb98fd5b6461fe32e079814` | 0 | 2 | `https://sigstore.dev/cosign/sign/v1` |

So `cloud-api` and `cvm-ingress` are not unsigned: G2 does not hold every
gateway digest change by default.

### Identity

The JSON output (`--output json`) carried no `optional` claims, so the
certificate subject was narrowed with regexps instead. Only the OK lines are
evidence:

| Image | Regexp that verified (exit 0) |
|---|---|
| `cloud-api` (both digests) | `^https://github.com/nearai/cloud-api/\.github/workflows/.*`, `@refs/heads/main$`, `/\.github/workflows/build[^/]*@` |
| `cvm-ingress` | `^https://github.com/nearai/cvm-ingress/\.github/workflows/.*`, `@refs/heads/main$`, `/\.github/workflows/build[^/]*@` |
| `compose-manager` | `^https://github.com/nearai/compose-manager/\.github/workflows/.*` (the launcher's own anchor) |

`^https://github.com/nearai/cloud-api/\.github/workflows/.*` did not verify
`cvm-ingress`, so each image is signed from its own repository. So far:
`cloud-api` and `cvm-ingress` are signed by a workflow whose file name starts
with `build`, on `refs/heads/main`, in `nearai/cloud-api` and
`nearai/cvm-ingress`.

**The exact identity was not obtained.** Docker Hub started returning
`TOOMANYREQUESTS` (unauthenticated pull limit) part-way through the probing,
and the probe script discarded stderr, so every FAIL from that run is
inconclusive, including the exact-name guesses (`build.yml`, `build.yaml`, ...)
and every narrower `compose-manager` pattern. To finish: after the limit
resets, fetch the certificate once per image with stderr visible (or log in to
Docker Hub) and read the SAN offline.

### Caveat for G2

The gateway images verify through a payload of type
`https://slsa.dev/provenance/v1`. That looks like a build-provenance
attestation (for example GitHub's `attest-build-provenance`), not a
`cosign sign` image signature; `compose-manager` has a `cosign sign`
payload. cosign v3 accepted the attestation under `cosign verify`. Whether a
different cosign version in CI does the same is not checked. Task 7 should pin
the cosign version in CI and, if needed, use `cosign verify-attestation
--type slsaprovenance1` for `cloud-api` and `cvm-ingress`.

## Compose capture (Step 1)

Captured with `tests/live_attest.rs` (`RTS_LIVE_COMPOSE_POLICY=mr-config-only`,
both environments, both default models; `test result: ok. 2 passed` each) and
read from `attestation.json` evidence, plus the committed fixtures
`tests/fixtures/near-prod/live-run-2026-10-29.json` and
`tests/fixtures/near-staging/live-run-2026-11-20.json`, plus local session
evidence. All 11 are in `tests/fixtures/compose-history/`.

| sha256 (12) | Role | Pinned in | Source |
|---|---|---|---|
| `f571e5dafe8f` | gateway | production | 10-29 fixture |
| `53cd435edbc1` | gateway | production | local session evidence |
| `1787a4af87ea` | gateway | production | local session evidence |
| `ae66f844658a` | model | production | 10-29 fixture |
| `e3902667a262` | model (gpu04) | both | live 11-24, 11-20 staging fixture |
| `edabf8039210` | model (gpu02) | both | live 11-24, 11-20 staging fixture |
| `e4b83d924284` | model (Qwen, gpu13) | both | live 11-24 |
| `10d29b736472` | gateway | staging | 11-20 staging fixture |
| `d686bb1df6c0` | gateway | none | local session evidence (staging, dstack 0.5.15) |
| `a1c3d2e1455e` | gateway | none | live 11-24, production |
| `0cf678004e2d` | gateway | none | live 11-24, staging |

**Not captured: `85c10cc2c733` (staging gateway, pinned 2026-11-23).** The
staging gateway has moved on to `0cf678004e2d`, and the compose is in no
local source. The staging gateway baseline set is seeded with `10d29b736472`
only.

The live gateways on 2026-11-24 are in neither compiled-in list:

- Production `a1c3d2e1455e` against `1787a4af87ea`: held, G1. The
  `otel/opentelemetry-collector-contrib` digest changed and its config gained
  a `readers: - pull: exporter: prometheus` block. G2 would also hold it
  (third-party digest change).
- Staging `0cf678004e2d` against `10d29b736472`: held, C1 and G1.

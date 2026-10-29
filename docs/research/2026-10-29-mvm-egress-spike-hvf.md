# Spike: mvm v0.22.0 TLS interception (`intercept = true`) as an SNI/Host-fronting control on HVF

Date: 2026-10-29. Host: macOS, mvm v0.22.0 (`~/.local/mvm/v0.22.0/mvmctl`), HVF backend, `MVM_HVF_SUPERVISOR_PATH=~/.local/share/nearai-red-sandbox/mvm-hvf-supervisor`. Guest image: the rts guest `us-west1-docker.pkg.dev/nearai-red-sandbox/sandbox-images/guest@sha256:56406743…` (Alpine 3.24, apk-tools 3.0.8, BusyBox; **no curl, python, node**). Guest runtime overlay/initramfs reported as 0.18.3.

Every mvmctl call went through a wrapper: `GIT_CONFIG_GLOBAL=<empty file>`, `MVM_HVF_SUPERVISOR_PATH=…`, stdin `</dev/null`. Guest commands were always `sh -c '…; echo "rc=$?"; exit 0'`. Raw outputs are in the scratchpad (`t0.out` … `t6.out`), along with the scripts (`t*.sh`, `guest-setup.sh`) and the policies (`policy-A.toml`, `policy-B.toml`, `policy-C.toml`, `mf/mvm.toml`).

## Verdict

**Does not work** as a fronting control. It also has serious caveats as a general egress mode.

1. **Interception does not close the bypass.** It is keyed on the hostname in the CONNECT or SOCKS request. If the guest connects to a pinned **IP literal** (`curl --connect-to X:443:151.101.0.223:443`, or `-x socks5://` with `--resolve`), the gate admits the flow as opaque TCP, because the IP is in the pin set, and it is not terminated. Both SNI fronting and Host fronting still reach `www.fastly.com` through pypi's IPs. Interception only stops fronting attempts that address the allowed host *by name*: mismatched Host gets 421, and a mismatched SNI ends with a Host-mismatch refusal.
   - Partial workaround: add extra `intercept` routes whose `host` is each pinned IPv4 literal. The route validator accepts dotted-quad strings. That closed IPv4-literal fronting (421).
   - **IPv6 literals stay open.** `[2a04:4e42::223]:443` still reached Fastly, because a route host with `:` is rejected by validation and the pin set includes the AAAA records. The workaround is also brittle: the IPs are hard-coded in the policy but re-pinned from DNS at each boot.
2. **Persistent machines get no working egress at all on HVF** (affects `--allow-host` too, not just interception). `machine start` spawns `mvm-network-endpoint` as a child of the `mvmctl` process. The endpoint's `parent_death::exit_when_orphaned()` (a kqueue NOTE_EXIT watcher on macOS) makes it exit as soon as `mvmctl machine start` returns, about 0.5 s. The guest then logs `FlowMux reconnect failed … Connection reset by peer`, ×10, and after that `guest egress is down`. Reproduced twice: `spike-base` (plain `--allow-host`) and `spike-mf` (manifest with routes). Egress only works for the life of a foreground `mvmctl machine run`/`run`.
3. **Intercepted traffic is rewritten.** The always-on PII redaction rewrites response bodies. In `six-1.17.0…whl.metadata`, `Author-email: benjamin@python.org` came back as `Author-email: XXX`, so **pip fails hash verification** for any package whose PEP 658 metadata contains an email, which is nearly all of them. No knob exists in the v0.22.0 policy schema, the manifest or the `run`/`machine run` flags to turn this off.
4. **The forwarder buffers each response with a 16 MiB cap.** `https://pypi.org/simple/` returned 502 `forward failed: response body exceeds the 16777216 byte limit`. Any larger wheel or tarball would hit the same cap.
5. **registry.npmjs.org cannot be intercepted.** The forward leg's TLS to Cloudflare fails with 502 `forward failed: tls handshake with registry.npmjs.org failed: received fatal alert: ProtocolVersion`.

## How routes can and cannot be supplied (step 3)

- `machine create … --policy <profile with [[network.routes]]>` is **refused**:
  ```
  Error: the policy's network.routes cannot be recorded on a persistent machine's spec yet, so a restart would drop them. Run it with `mvmctl run` or `machine run`, which apply them per launch
  ```
  The source is `crates/mvm-cli/src/commands/machine/create_policy.rs` `refuse_unrecordable()`, which lists `network.routes` alongside secrets, shares, env and tools.
- `machine create --manifest mvm.toml` with top-level `image = …`, `[network] allow_hosts` and `[[network.routes]] intercept = true` is **accepted**. The routes are recorded in `machine.json` (`routes[]` with `intercept: true`). On `machine start` the per-VM CA is minted (`~/.mvm/vms/<n>/egress-ca.json`), and the guest gets `/run/mvm/egress-ca.crt` (664 B) and a combined `/run/mvm/ca-bundle.crt` (119 certs). Source: `machine/manifest_source.rs` and `machine/mod.rs` `build_machine_spec` (`routes: routes.routes`). This path is unusable today because of the endpoint-death bug above.
- `machine run --policy <profile>` (foreground) **works**: routes are applied, the CA is minted, and the env is set. All checks below used this path.
- `machine exec` env does **not** include the proxy or CA env vars. `env` in exec showed only HOME, PATH and similar, and `/etc/resolv.conf` is absent: the guest log says `could not point resolv.conf … Read-only file system`. `machine run` argv does get `HTTP(S)_PROXY`, `ALL_PROXY`, `NO_PROXY`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE` and `NODE_EXTRA_CA_CERTS`, which mvm injects as `export …` lines in the exec script. rts would need to export these itself in exec.
- Host config check: `~/.mvm/config/config.toml` has only `dev_vm_cpus`, `dev_vm_mem_gib`, `default_cpus`, `default_memory_mib`, `trusted_plan_signers = []` and `[tenant] name = ""`. It has **no grants or egress section, so there is no default egress grant**. No `*_PROXY` is set in the host env.

## The policy file used (profile format; passes `mvmctl policy validate --strict`)

`policy-A.toml` (`policy-B.toml` adds the same block for `dl-cdn.alpinelinux.org`):
```toml
description = "spike: TLS-intercept pypi/npm/alpine; any method, any path; otherwise deny"

[overrides.network]
allow = ["pypi.org:443", "files.pythonhosted.org:443", "registry.npmjs.org:443", "dl-cdn.alpinelinux.org:443"]

[[overrides.network.routes]]
id = "pypi"
host = "pypi.org"
intercept = true
otherwise = "deny"
rules = [{ path = "/**", outcome = "allow" }]

[[overrides.network.routes]]
id = "pythonhosted"
host = "files.pythonhosted.org"
intercept = true
otherwise = "deny"
rules = [{ path = "/**", outcome = "allow" }]

[[overrides.network.routes]]
id = "npm"
host = "registry.npmjs.org"
intercept = true
otherwise = "deny"
rules = [{ path = "/**", outcome = "allow" }]
```
Launch (foreground; tools installed per run, see below):
```
mvmctl machine run --name spike-t1 --image <guest digest> --profile dev --cpus 2 --memory 2048M \
  --allow-host pypi.org --allow-host files.pythonhosted.org --allow-host registry.npmjs.org \
  --allow-host dl-cdn.alpinelinux.org --policy $PWD/policy-A.toml \
  --mount $PWD/share:/work/s:ro -e "PKGS=curl python3 py3-pip nodejs npm" -- sh -c '. /work/s/t1.sh; echo "rc=$?"; exit 0'
```
(`--mount` targets must be under `/data` or `/work`.)

How tools were installed: the image has no curl, python or node, and exec runs as uid 901 `mvm-worker` with no root. Every run first did `apk add --usermode --root /tmp/r --initdb --no-scripts $PKGS`, with `HTTPS_PROXY=http://127.0.0.1:1080` and `dl-cdn.alpinelinux.org` allowed. In policy A, dl-cdn was opaque. It then set `PATH`/`LD_LIBRARY_PATH` into `/tmp/r`. `pip` was run as `python3 -m pip` because the shebang points at the missing `/usr/bin/python3`.

## Fronting targets chosen

pypi.org resolves to 151.101.{0,64,128,192}.223 (Fastly). The co-tenant used was `www.fastly.com`, which is on Fastly at 151.101.x.57 and is a different customer. From the host, with no mvm involved: `curl -H "Host: www.fastly.com" https://pypi.org/` returns `<title>Powering the best of the internet | Fastly`. `Host: www.reddit.com` gives the Reddit page the same way. `--resolve www.fastly.com:443:151.101.0.223` with `-k` also gives 200. Fastly does domain fronting freely on these IPs.

## Per-check results

### Step 0: baseline, plain `--allow-host pypi.org` (+ dl-cdn for apk), `machine run` (`t0.out`)
| Check | Command (in guest) | Result |
|---|---|---|
| T0a allowed | `curl https://pypi.org/simple/` | `200` |
| T0b SNI front via pinned IP (HTTP CONNECT to IP) | `curl -k --connect-to www.fastly.com:443:151.101.0.223:443 https://www.fastly.com/` | `<title>Powering the best of the internet \| Fastly` **(bypass works)** |
| T0b2 same without -k | | curl (60) cert name mismatch: only the client-side check stops it |
| T0b3 SOCKS5 with IP literal | `curl -k -x socks5://127.0.0.1:1080 --resolve www.fastly.com:443:151.101.0.223 …` | Fastly title **(bypass works)** |
| T0c Host-header front | `curl -H "Host: www.fastly.com" https://pypi.org/` | Fastly title, valid TLS **(bypass works)** |
| T0d non-allowed name | `curl https://www.fastly.com/` | `CONNECT tunnel failed, response 403`; stderr `[mvm] egress blocked: www.fastly.com:443 (not in the allow-list)` |

Audit (`~/.mvm/audit/local.jsonl`, filtered by `labels.vm_name == "spike-t0"`): the front attempts are just `host.flow.allowed {"class":"tcp","route":"egress","target":"151.101.0.223:443","resolved_ips":"151.101.0.223,…"}`, and the Host-header front looks like a normal `target: "pypi.org:443"` flow. Nothing marks either as fronting. Denial: `host.flow.denied {"reason":"policy_denied","target":"www.fastly.com:443"}`.

Persistent-machine attempt (`spike-base`, `machine create … --allow-host pypi.org` + `machine start`): `apk fetch` failed with `HTTP 502` and then `Connection refused`. Guest console: `FlowMux peer closed session`, then 10× `FlowMux reconnect failed … Connection reset by peer`, then `FlowMux session to the host lost and not re-established; guest egress is down`. `/tmp/mvm-network-endpoint-spike-base.log` shows `FlowMux handshake complete` and then nothing. The endpoint pid in `substitution.pid` was already gone, while the supervisor (ppid 1) stayed up. Cause: `mvm-network-endpoint.rs:57-59` calls `parent_death::exit_when_orphaned()`, and `network_endpoint_spawn.rs` spawns the endpoint from the `mvmctl` process (setsid does not help, because the watcher keys on parent exit). No upstream issue found for this.

### Step 1: interception, `--policy policy-A.toml`, `machine run` (`t1.out`, `t2.out`)
- Accepted on HVF via `machine run`. Guest env: `SSL_CERT_FILE=CURL_CA_BUNDLE=REQUESTS_CA_BUNDLE=/run/mvm/ca-bundle.crt`, `NODE_EXTRA_CA_CERTS=/run/mvm/egress-ca.crt`, plus the proxy vars. `curl -v` shows `subject: CN=pypi.org`, `issuer: CN=mvm per-VM egress CA`, TLSv1.3.

| Check | Result |
|---|---|
| `curl https://pypi.org/simple/` | **502** `forward failed: response body exceeds the 16777216 byte limit` (body is 47.8 MB) |
| `curl https://pypi.org/simple/six/` (default / `--http1.1`) | 200 / 200, 16337 B |
| `curl --http2 …` | Works. ALPN: "server did not agree on a protocol", so curl falls back to HTTP/1.1 (`http=1.1`). No breakage. |
| `/simple/numpy/` (2.2 MB), `/pypi/numpy/json --compressed` | 200 / 200 |
| POST (rule allows any method) | 405 from pypi (forwarded) |
| T1c Host-header front by name `-H "Host: www.fastly.com" https://pypi.org/` | **421** from mvm. Endpoint log: `terminated request refused: request Host does not match the flow authority "pypi.org"` (closed) |
| T1b1 SNI front by name `-k --connect-to www.fastly.com:443:pypi.org:443` | Refused (`[mvm] egress blocked: pypi.org (request the host could not read as HTTP/1.1)` plus the Host-mismatch log). Closed. |
| **T1b SNI front via IP literal** `-k --connect-to www.fastly.com:443:151.101.0.223:443` | **Fastly title: bypass still works** |
| **T1b3 SOCKS5 + `--resolve` to IP** | **Fastly title: still works** |
| **T1b4 IP literal + real pypi cert (no -k) + `Host: www.fastly.com`** | **Fastly title: still works, with valid TLS** |
| non-allowed name | 403, as baseline |

Audit for the IP-literal flows: `host.flow.allowed {"target":"151.101.0.223:443", …}` with **no `termination` label**. Name flows instead show `"termination":"tls"` plus `host.route.decided {"route":"pypi","rule":"rule-1","method":"GET","outcome":"allow","verdict":"forwarded"}`.

### Step 1b: IP-literal routes as a mitigation, `policy-C.toml` = A + four routes `host = "151.101.{0,64,128,192}.223"` with `intercept = true` (`t6.out`)
| Check | Result |
|---|---|
| IPv4 literal SNI front `-k` | **421** (terminated, Host ≠ authority). Audit: `target 151.101.0.223:443, termination: tls` |
| IPv4 literal + `Host:` front without -k | TLS verify failure. Blocked. |
| SOCKS5 IPv4 literal `-k` | 421 |
| **IPv6 literal** `-k --connect-to www.fastly.com:443:[2a04:4e42::223]:443` | **Fastly title: open.** Audit `target "[2a04:4e42::223]:443"`, not terminated |
| IPv6 route host | `mvmctl policy validate`: `host "2a04:4e42::223" must be a lower-case host name or a *.suffix wildcard over two or more labels` |
| pypi by name | 200 |

### Step 2: real clients (`t2.out`, `t3.out`, `t4.out`, `t5.out`)
- **pip** (`python3 -m pip download --no-deps six -d /tmp/x`) honours `REQUESTS_CA_BUNDLE`/`SSL_CERT_FILE` (TLS succeeds; with those unset it fails, `No matching distribution`). It then fails with `THESE PACKAGES DO NOT MATCH THE HASHES … six-1.17.0-py2.py3-none-any.whl.metadata Expected sha256 5620420… Got 84fa1ba…`. A diff against the host copy shows the only change is `-Author-email: benjamin@python.org` / `+Author-email: XXX`: mvm's default PII redaction on the response. The same thing happened with numpy. A gzip-encoded request (`Accept-Encoding: gzip`) came back byte-exact (8ba14b…), and the binary wheel itself came through intact (4721f3…, matching the host). Only identity-encoded text gets rewritten, and pip asks for identity.
- **npm** (`npm view is-number version`, Node 24.22.1, npm 11.12.1): fails. `curl https://registry.npmjs.org/is-number` gives 502 `forward failed: tls handshake with registry.npmjs.org failed: received fatal alert: ProtocolVersion`, so the host→Cloudflare leg is broken. npm retries until `timeout 45` (rc 143). Plain `node https.get` ignores the proxy env (`ENETUNREACH`) unless `NODE_USE_ENV_PROXY=1`; with it set it also gets the 502. Side effect: running `npm view` in a `machine run` without `</dev/null` twice killed the run with `Error: control frame read failed … failed to fill whole buffer`.
- **apk** (`apk add --usermode --root /tmp/r2 … curl`, with dl-cdn intercepted, `policy-B.toml`): **works**. apk-tools 3 uses the proxy env and honours `SSL_CERT_FILE`. With `SSL_CERT_FILE` unset it fails closed (`jq (no such package)`, and the endpoint logs `UnknownCA`). apk add as root was not possible (exec is uid 901), so usermode was used.

## Client compatibility under `intercept = true` (machine run, HVF, v0.22.0)
| Client | Result |
|---|---|
| curl (default, offers h2) | Works for responses under 16 MiB. Falls back to HTTP/1.1. Identity-encoded text bodies are PII-redacted. |
| curl `--http1.1` | Same as default. |
| pip 26.1.2 | **Fails**: redacted METADATA fails hash check. TLS and CA handling work. |
| npm 11 / Node 24 | **Fails**: upstream TLS to registry.npmjs.org (Cloudflare) `ProtocolVersion` alert, 502. Node also needs `NODE_USE_ENV_PROXY=1` for raw `https`. |
| apk 3.0.8 | Works (usermode), via proxy env and `SSL_CERT_FILE`. Signed packages arrived intact. |

## Audit-log evidence
Filter: `labels.vm_name`, events `host.flow.allowed|denied`, `host.route.decided` (see `audit.py` in the scratchpad). Intercepted name flows show `termination: "tls"` and one `host.route.decided` per request (route id, rule id, method, verdict). IP-literal flows to pinned IPs show `host.flow.allowed` with `target: "<ip>:443"` and no termination. Host-mismatch refusals appear only in the endpoint stderr log `/tmp/mvm-network-endpoint-<vm>.log` (`terminated request refused: request Host does not match the flow authority`); I saw no signed audit event for them. That log is also where the forward errors (16 MiB cap, npm TLS) show up. Non-allowed names give `host.flow.denied reason=policy_denied`.

## Cleanup
Machines created: `spike-base`, `spike-mf` (persistent, removed with `machine rm --force --yes`) and `spike-t0`…`spike-t6` (foreground `machine run`, torn down by mvm). `spike-pol` was refused at create. Final `mvmctl machine ps` printed `no machines`. `~/.mvm/machines/` and `~/.mvm/vms/` are empty, and no `mvm-hvf-supervisor` or `mvm-network-endpoint` processes remain. mvm left endpoint logs at `/tmp/mvm-network-endpoint-spike-*.log`. No repository or worktree was modified.

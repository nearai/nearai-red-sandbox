# Controlled network access from the sandbox: design

Date: 2026-10-29
Status: approved 2026-10-29; blocker 1 worked around (see Attached start), upstream fix tracked in tinylabscom/mvm#4860. Amended 2026-10-30 with the session limit and the pinned-IP check (plan Tasks 9a and 9b, approved by Zaki 2026-10-29) and the order of that check measured in Task 10.

## Purpose

Today the guest has no network at all (sandbox design, Decisions: "VM egress:
None"; measured: only `lo`, blackholed routes). Operators doing red-team work
need some sessions to reach the network: to install packages, to fetch public
data, to reach an in-scope target, and to reach services on their own machine
or LAN. This adds an explicit, per-session allowlist on top of mvm's egress
controls, keeps "no network" as the default, and documents how to use it.

## Decisions

| Topic | Decision |
|---|---|
| Default | No network. A session gets egress only from an allowlist its operator declares before launch. |
| Mechanism | mvm v0.22.0 `machine create --allow-host` only. `rts` never passes `--net`, `--peer`, `--grants-file` or `--policy`. |
| Granularity | Exact host names or IP addresses, each with a TCP port (443 when omitted). No wildcards, no UDP, no mid-session changes (mvm supports none of these). |
| Presets | One built-in preset in v1, `packages`. Other needs are named host by host. |
| Approach | A thin layer over mvm's allowlist (chosen 2026-10-29 over an rts-owned SNI-checking proxy reached through `--peer`, and over mvm's `--net` preset). |
| Session limit | `limits.sessionHours`, an integer from 1 to 720 (720 h is mvm's inclusive 30-day `MAX_TTL`), default 24. Every session, with or without network, stops with `session-limit` once that many hours have passed since boot (export `/out`, remove the VM). A network session's attached `machine run` gets the same limit as `--ttl <hours>h`. |
| Pinned-IP check | mvm resolves each name again when its endpoint starts and pins those answers. After the probes, `rts` compares what mvm pinned with what it resolved and validated, and stops with `network-mismatch` on any difference it does not allow (Launch sequence step 6). |
| Audit | The allowlist, its resolved IPs and the IPs mvm pinned in `sessions/<id>/session.json`; every allowed and denied flow for this VM copied from mvm's signed audit log into `sessions/<id>/network.jsonl`. |

## How mvm v0.22.0 enforces egress (read from source, 2026-10-29)

Full notes with file:line citations:
`docs/research/2026-10-29-mvm-v0.22.0-egress.md`. The facts this design depends on:

- **Default deny.** With no network flags, mvm starts no egress path at all
  (`hvf_process.rs:186-199`).
- **Path.** The guest gets an HTTP(S) proxy on `127.0.0.1:1080` and a DNS stub
  on `:53`, injected by mvm into any OCI image. Traffic crosses vsock (port
  5253) to the HVF supervisor and then to a per-VM host process,
  `mvm-network-endpoint`, which makes every decision. Only proxy-aware
  programs get out; nothing needs installing in the guest.
- **Matching.** `--allow-host HOST[:PORT]`: exact names or IPs, port 443 when
  omitted, port 22 refused (`run_network.rs:92-104,153-170`;
  `network_policy.rs:617-635`). The host resolves each name once at boot and
  pins the IPs for 24 hours; the guest never resolves anything
  (`dns_pin.rs:47-68`). The check is destination IP plus port, with no SNI or
  Host check (`classify.rs:91-104`; `egress_gate.rs:594-705`).
- **Always refused:** cloud metadata, the host's loopback, link-local
  addresses and `100.64.0.0/10`. The host's LAN is reachable only when an
  entry names it.
- **TLS** is end to end; mvm intercepts only for `--secret` hosts or
  `--allow-endpoint` routes, which `rts` does not use.
- **Logging.** Every decision is a chain-signed entry in
  `~/.mvm/audit/local.jsonl` (events `host.flow.allowed`, `host.flow.denied`,
  `dns.resolved`, `dns.refused`, `host.route.decided`), tagged with
  `entry.labels.vm_name`. All machines share the file.
- **Limits.** TCP only; concurrency caps (4096 TCP); no byte or bandwidth
  caps; connection-rate limits default to off.
- **Changes** to egress need a VM restart (`machine reconfigure`), so a
  session's allowlist is fixed for its life.

## Blockers measured 2026-10-29 (spike on this host)

Full record: `docs/research/2026-10-29-mvm-egress-spike-hvf.md`.

1. **Egress does not work on persistent machines on HVF in v0.22.0**, even with
   plain `--allow-host`. `machine start` spawns `mvm-network-endpoint` as a
   child of the `mvmctl` process, and the endpoint's parent-death watchdog
   makes it exit about 0.5 s after `machine start` returns; the guest then
   logs "guest egress is down". Reproduced on two machines. No upstream issue
   or newer release (v0.22.0 is the latest stable) covered it; filed upstream as tinylabscom/mvm#4860 on 2026-10-29 (reproduced with the stock supervisor). `rts` uses
   persistent machines (`create`, `start`, `exec`, `rm`), so `machine start` cannot be used for network sessions; see Attached start.
2. **mvm's TLS interception does not close CDN fronting**, so it is not part
   of this design:
   - Routes with `intercept = true` close fronting only when the guest
     connects by name: a mismatched `Host` gets 421 and a mismatched SNI is
     refused. A guest that connects to a pinned IP (`curl --connect-to`, or
     SOCKS5 with a resolved address) is admitted without termination, and
     fronting works again with the real certificate. IP routes close IPv4
     only; IPv6 route hosts fail validation.
   - Routes cannot be recorded on a persistent machine (`machine create
     --policy` refuses: "network.routes cannot be recorded on a persistent
     machine's spec yet"); only a foreground `machine run --policy` enforces
     them.
   - Under interception, pip fails (mvm's always-on PII redaction rewrites
     response bodies, breaking pip's hash checks), npm fails (mvm's upstream
     TLS to Cloudflare is rejected with a ProtocolVersion alert), and any
     response over 16 MiB returns 502. curl and apk work.
3. **`machine exec` gets none of mvm's proxy environment**, so `rts` must set
   `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` itself for tool calls.
4. **The rts guest image has no curl, python or node**, and exec runs as uid
   901 without root; tools must come from the image or `apk add --usermode`.

Consequences for this design: risk 2 (IP-level filtering, CDN co-tenancy)
stays an accepted, documented limitation in v1. Closing it needs an
rts-owned SNI-checking path, which is out of scope until blocker 1 is solved.

## Attached start (workaround for blocker 1, measured 2026-10-29)

Full record: `docs/research/2026-10-29-mvm-attached-run-spike.md`.

For a session with a non-empty allowlist, `rts` keeps `machine create` as it
is and replaces `machine start` with a background
`mvmctl machine run --name rts-<id> --ttl <limits.sessionHours>h` (no `--image`, no
argv, no `-d`). That process boots the persistent machine and stays attached;
as the network endpoint's parent it keeps egress alive. Measured: allowlisted
`pypi.org` answered 200 at 45 s, 3 min and 31 min, a non-listed host was
refused each time, and `machine exec`, base64 argv file writes and reads,
and the always-exit-0 wrapper behave as with `machine start`. Sessions with
no allowlist keep `machine start`.

Requirements this places on `rts`:

- **Supervise the attach process.** If it exits for any reason, the endpoint
  exits with it and egress fails closed while `exec` keeps working, so the
  failure would be silent. `rts` treats the attach process's exit as fatal:
  the session ends with `network-lost` (export `/out`, remove the VM).
  Re-attaching does not restore egress.
- **Teardown order.** `machine rm --force --yes`, then SIGTERM to the attach
  process (`rm` does not stop it), then confirm no endpoint or supervisor
  process for the machine remains.
- **Its output.** The attach process echoes every exec's argv, including the
  base64 chunks of files written into the guest. Its stdout and stderr go to
  `sessions/<id>/mvm-attach.log` (0600), never to the operator's terminal.
- **One start at a time.** Two attach starts launched back to back raced on a
  `plan.json.tmp` rename; `rts` runs one session at a time, and the start is
  retried once if it fails before boot.
- **TTL.** `--ttl` is `limits.sessionHours` as `<hours>h` (1 to 720 hours, so
  at most mvm's 30 days). The `session-limit` clock starts just before
  `machine create`, so `rts` stops the session no later than mvm's TTL would.
  Expiry of the TTL itself was not measured and is treated as `network-lost`.
- **Not used:** a fully foreground `machine run --image … -- <argv>` died
  about 60 s after boot in three of three tries ("control frame read
  failed"), cause not found.

When #4860 is fixed upstream, `machine start` replaces the attached start and
this section is removed.

## Risks accepted with this design

These were presented and accepted on 2026-10-29 when approach A was chosen.
The README states the operator-facing ones.

1. **An unsandboxed host process.** A session with any allowlist entry starts
   `mvm-network-endpoint`, which parses traffic from the hostile guest and, on
   macOS, runs as the operator with no sandbox (the Linux Landlock/seccomp step
   is a no-op there, `mvm-network-endpoint.rs:568-578`). Sessions without an
   allowlist never start it.
2. **IP-level filtering.** Allowing a host behind a shared CDN admits every
   other site served on the same pinned IPs. Measured 2026-10-29: the Alpine,
   PyPI and crates hosts resolve to Fastly (`151.101.*`) and the npm registry to
   Cloudflare (`104.16.*`), so the `packages` preset in practice admits a large
   share of those CDNs' sites on port 443. It is a convenience preset, not a
   narrow one.
3. **Exfiltration.** Any allowed destination can receive whatever the model
   sends, including the contents of `/in`. Write-capable services (code hosts,
   paste sites, LLM APIs) are the obvious channels, and through risk 2 so are
   sites that share a CDN with an allowed host.
4. **No byte caps** and no rate limits on TCP.
5. **The open mvm advisories** (all versions through 0.24.2, no fix), in
   particular GHSA-x85r-49ww-2pxq (guest-driven host memory growth over
   vsock). The host RSS ceiling the launcher already enforces still applies.

## Operator interface

Session config:

```json
"network": {
  "allow": ["packages", "api.example-target.com", "198.51.100.7:8443", "192.168.1.20:8080"]
}
```

Each entry is a preset name, a host name (`name` or `name:port`), or an IP
address with a port (`ip:port`; IPv6 as `[addr]:port`).

Command line, merged with the config:

- `rts launch --allow-host <entry>` (repeatable; presets allowed).
- `rts launch --no-network` drops every entry from the config and the flags,
  and is refused together with `--allow-host`.

Built-in preset `packages` (hosts verified to resolve and serve HTTPS on
2026-10-29; port 443): `dl-cdn.alpinelinux.org`, `pypi.org`,
`files.pythonhosted.org`, `registry.npmjs.org`, `index.crates.io`,
`static.crates.io`, `crates.io`. GitHub and other write-capable APIs are left
out deliberately. The containment gate below may remove `dl-cdn.alpinelinux.org`
(see Testing).

Reaching a service on the operator's machine: mvm always refuses the host's
loopback, so the service must listen on a LAN address and the entry names that
address and port (`192.168.1.20:8080`). This is also what keeps the guest away
from IronWire and the attested forwarder, which listen on `127.0.0.1` and hold
the inference key.

Startup line, printed before opencode starts:

```
network: 10 hosts allowed (packages, api.example-target.com, 198.51.100.7:8443, 192.168.1.20:8080); TCP only; every connection is logged
network: none
```

Session limit, in the same config:

```json
"limits": { "sessionHours": 24 }
```

An integer from 1 to 720, default 24; anything else refuses the config with
`config: limits.sessionHours must be an integer from 1 to 720`.

Stop reasons this design adds. Each one exports `/out` and removes the VM:

- `network-lost`: the attached `mvmctl machine run` exited, at any point
  (Attached start).
- `network-mismatch`: the addresses mvm pinned for a name include one `rts`
  did not resolve and validate, or one in a refused range, or mvm recorded
  none for it (Launch sequence step 6).
- `session-limit`: `limits.sessionHours` have passed since boot, with or
  without network.

## Launch sequence

Steps 1 to 3 run before `machine create`, step 4 is the create, and steps 5
and 6 run after boot, before anything else runs in the guest (storage set-up,
the copy into `/in`, opencode). Any failure refuses or ends the session with a
message naming the entry and the reason, and nothing falls back to wider
access.

1. **Parse and validate.** Expand presets; parse hosts, IPs and ports; refuse
   port 22, port 0 and ports above 65535; refuse loopback, link-local, metadata
   (`169.254.169.254`, `fd00:ec2::254`), unspecified, multicast and
   `100.64.0.0/10` addresses, and host names that resolve only to them (step 2);
   refuse more than 64 entries after expansion; deduplicate.
2. **Resolve on the host.** Resolve every name with the system resolver. A name
   that fails to resolve refuses the session (mvm would otherwise give the
   whole machine no egress without saying so). Record the IPs.
3. **Refuse a default egress grant.** If mvm's host configuration supplies a
   default egress grant (`run_grants.rs:80-101`), refuse every launch, with or
   without an allowlist, because it would grant egress outside `rts`'s control.
   Also refuse when an `HTTPS_PROXY` or `HTTP_PROXY` is set in the environment
   `rts` passes to `mvmctl`, since mvm would route allowed traffic through it.
4. **Create the machine** with one `--allow-host <host-or-ip>:<port>` per
   validated entry and no other network flag. The existing guard in
   `src/mvm.rs` (which today forbids `--net`, `--allow-host`, `--peer` and
   `--gpu`) changes to: `--allow-host` only, only with values from the
   validated list; `--net`, `--peer`, `--gpu`, `--grants-file` and `--policy`
   stay forbidden.
5. **Probe after boot.** For each allowed entry, one TCP connection from the
   guest through mvm's proxy (`HTTPS_PROXY` set by mvm), with a 10-second
   timeout. Any failure ends the session, naming the entry. With no allowlist,
   probe that `1.1.1.1:443` is unreachable (the address the original no-egress measurement used), so a no-network
   session proves deny-all on every launch.
6. **Check mvm's pins.** mvm resolves each name again when its endpoint
   starts and pins those answers, so a changed or hostile DNS answer at that
   moment could pin an address `rts` never validated. After the probes, `rts`
   reads this VM's entries from mvm's audit log, waiting up to 10 s for a pin
   for every host name in the allowlist (IP-literal entries pin to themselves
   and are not checked). It reads `labels.resolved_ips` from
   `host.flow.allowed` (keyed by the host half of `labels.target`) and from
   `dns.resolved` (keyed by `labels.qname`). Measured on mvm v0.22.0 in Task
   10: the pins appear only in `host.flow.allowed`, and only once a flow has
   succeeded; the guest does no DNS of its own through the proxy, so no
   `dns.resolved` entry appears. That is why the check follows the probes
   rather than preceding them, and why one probe connection to whatever mvm
   pinned precedes a refusal. The session ends with `network-mismatch` when
   the audit log never appears, when a name has no pin, when a pinned IP is
   in a refused range (step 1's ranges), or when a pinned IP is not among the
   IPs `rts` resolved for that name. mvm pinning a subset of `rts`'s IPs
   passes. The pins are written to `session.json` before the check, so a
   refused session records them too.

## Audit

- `sessions/<id>/session.json` gains `network`: the entries as written, the
  expanded list, each name's resolved IPs, the IPs mvm pinned for each name
  (step 6, written before the check), and the probe results.
- At teardown, `rts` reads `~/.mvm/audit/local.jsonl` (and any rotated
  `local.seg-*.jsonl` written during the session) and copies the entries whose
  `entry.labels.vm_name` is `rts-<id>` and whose event is `host.flow.*`,
  `dns.*`, `icmp.*` or `host.route.*` into `sessions/<id>/network.jsonl`, as
  written (still signed). It never writes to mvm's log. A read failure is
  reported at teardown and does not stop the export of `/out` or the VM removal.

## Documentation

- README, new section "Network access": the default; the config and flags;
  examples for installing packages, reaching one target, and reaching a
  service on the operator's machine (with why `127.0.0.1` does not work); the
  exfiltration and CDN caveats; where the audit lands.
- `rts launch --help`: the flags and three one-line examples.
- The sandbox design spec: the VM egress row changes from "None" to this
  design, and its out-of-scope "VM egress allowlists" line moves here.

## Testing

- Unit:
  - preset expansion and deduplication;
  - each validation refusal (port 22, bad ports, each refused address range,
    too many entries, `--no-network` with `--allow-host`);
  - a name that fails to resolve, and a name resolving only to a refused
    range;
  - the exact `machine create` argv: one `--allow-host` per entry and none of
    the forbidden flags;
  - refusal on a default egress grant and on a proxy variable in the `mvmctl`
    environment;
  - audit filtering by `vm_name` and event, across a rotated segment;
  - the startup line for none, one and many entries;
  - `limits.sessionHours`: absent gives 24, 1 and 720 are accepted, 0, 721
    and a non-integer are refused; the attach argv is
    `machine run --name <name> --ttl <hours>h`, and create refuses a limit
    outside 1 to 720 and runs nothing;
  - the session limit is reached at exactly its hours since boot; a session
    past its limit (injected clock), with or without network and during the
    plugin handshake, stops with `session-limit` and tears down in the usual
    order (rm before SIGTERM to the attach); a session within it is not
    stopped;
  - the pinned-IP check: identical sets pass, a subset passes, IP-literal
    entries pass; a pinned IP `rts` did not validate, a pinned LAN IP for a
    public name, a pin in a refused range even when `rts` resolved it, and a
    name with no pin each fail with `network-mismatch`;
  - reading pins from `dns.resolved` and `host.flow.allowed` for this VM only,
    across a rotated segment, and failing on an unparseable address;
  - at session level: matching pins are recorded in `session.json` and the
    session proceeds; a pinned LAN IP, and a name mvm never pinned (after the
    wait), end the session with `network-mismatch` and still export `/out`
    and remove the VM.
- Containment (real mvm on this host):
  - no allowlist: the guest reaches nothing, and the deny-all probe passes;
  - one allowed host: that host and port connect; another host, another port
    on the same host, the host's `127.0.0.1`, the host's LAN address, and
    `169.254.169.254` are refused, and the denials appear in `network.jsonl`;
  - `packages`: `pip download` of a small package and `apk add` of a small
    package succeed. This is also the gate for mvm issue #3962 (egress
    handshake failures in v0.22.0) on HVF. If `apk` does not use the proxy, the
    preset drops `dl-cdn.alpinelinux.org` and the spec records the
    measurement;
  - leak check: with an allowlist, the guest cannot reach the IronWire or
    forwarder loopback ports;
  - one allowed host: the IPs mvm pinned, read from the real audit log, pass
    the pinned-IP check;
  - losing the attach is detected, and teardown leaves no endpoint or
    supervisor process;
  - through the launcher, with opencode: killing the attach mid-session ends
    the session with `network-lost`, `/out` is exported, the machine is
    removed and the attach output stays out of the terminal; and a session
    whose limit is set to 1 hour with an injected clock ends with
    `session-limit` (attach `--ttl 1h`), records matching pinned IPs in
    `session.json` and leaves no machine or network process.

## Out of scope for v1

Wildcards, UDP, mid-session changes, byte or rate caps, SNI checking, presets
beyond `packages`, and any interception of TLS.

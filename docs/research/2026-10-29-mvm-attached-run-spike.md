# Spike: holding a foreground mvmctl open to keep HVF guest egress alive (mvm v0.22.0)

Date: 2026-10-29. Host: macOS, `~/.local/mvm/v0.22.0/mvmctl`, HVF, `MVM_HVF_SUPERVISOR_PATH=~/.local/share/nearai-red-sandbox/mvm-hvf-supervisor`.
Image: `us-west1-docker.pkg.dev/nearai-red-sandbox/sandbox-images/guest@sha256:56406743…`.
Every mvmctl call went through a wrapper (`scratchpad/fg/m.sh`) that sets `GIT_CONFIG_GLOBAL=<empty>` and the supervisor path, and runs with stdin `</dev/null`. The raw logs are in `scratchpad/fg/` (`a.log` … `f4.log`) and in `/tmp/mvm-network-endpoint-spike-fg*.log`.

## Verdict: viable with caveats

The mode that works is the **persistent attach mode**, not the transient `machine run -- <argv>` mode. Keep `machine create` exactly as rts does it today. Replace `machine start <name>` with a long-lived background process:

    mvmctl machine run --name <name> --ttl <D>      # no --image, no argv, no -d

`--ttl` (or `--port`/`--healthcheck`) without `-d` puts `machine run` into `MachineRunMode::Persistent` with `PostStart::Attach` (`crates/mvm-cli/src/commands/machine/runtime.rs`, `mod.rs::persistent()`/`resolve_mode`). It boots the existing persistent spec through the same `lifecycle::start_machine` path as `machine start`. It then blocks in `attach_to_output`, following the console. Because that mvmctl process stays alive, the endpoint's watched parent stays alive and egress keeps working. `machine exec`, `machine stop` and `machine rm` work unchanged against `<name>`. The allow-list recorded at `machine create` is honoured.

The transient foreground mode (`machine run --name X --image … -- sh -c 'sleep 3000'`) is **not viable**. It is exec-able by name (it shows as `transient` in `machine ps`), and egress works at first. But it died about 60 s after boot in 3 of 3 runs: with exec, without exec, and with `--timeout 7200`. Each time it failed with `Error: control frame read failed … session i/o error: failed to fill whole buffer` (`a.log`, `b.log`, `c.log`). I did not find the cause. It also leaves `~/.mvm/machines/<name>/input-journal*` behind, which I removed by hand.

## Why (source, v0.22.0)
- `crates/mvm-hostd/src/bin/mvm-network-endpoint.rs:59` calls `mvm_hostd::parent_death::exit_when_orphaned()` as the first thing in `main`, and nothing gates it (no env var, no flag).
- `crates/mvm-hostd/src/parent_death.rs`: it records `getppid()` at startup. On macOS it blocks on a kqueue `EVFILT_PROC/NOTE_EXIT` for **that pid** and calls `_exit(0)` when it fires. It falls back to 1 s `getppid()<=1` polling. It watches the **direct parent pid**, not the session, process group or supervisor.
- `crates/mvm-vmm/src/host/network_endpoint_spawn.rs::spawn_network_endpoint` spawns the endpoint from the calling mvmctl with `pre_exec(setsid)`. The comment there says "so it survives this `mvmctl` process". But setsid does not change the ppid, so the watchdog kills it the moment that mvmctl exits. The two pieces contradict each other, and that is the upstream bug.
- The supervisor is also a child of that mvmctl, but it survives being reparented to launchd (pid 1). Only the endpoint (egress) dies.
- Observed process tree while attached: `mvmctl machine run --name spike-fgd --ttl 2h` (pid 11071) is the parent of both `mvm-network-endpoint` (11156) and `mvm-hvf-supervisor` (11158).

## Exact command sequence that works
```
mvmctl machine create spike-fge --image <digest-ref> --profile dev --cpus 2 --memory 2048M \
    --allow-host dl-cdn.alpinelinux.org --allow-host pypi.org          # unchanged from rts
nohup mvmctl machine run --name spike-fge --ttl 4h </dev/null >run.log 2>&1 &   # replaces `machine start`; keep PID
# wait until it prints "started machine spike-fge" / "attached to machine …" (~5-10 s) or poll `machine exec … true`
mvmctl machine exec spike-fge -- sh -c '<cmd>; echo "rc=$?"; exit 0'   # every tool call, unchanged
mvmctl machine rm spike-fge --force --yes                              # teardown
kill -TERM <run PID>                                                   # REQUIRED: the attach does not exit on rm
```
`machine run --name X --image … --ttl D` (create and boot in one step) also works (`spike-fgd`). stderr prints `warning: piped stdin is ignored for a persistent (-d/--name) machine`, which is harmless. The run log fills with guest console output: kernel boot and `[audit] exec request: …` lines that include each exec's argv. So send it to a file you rotate or discard, and note that it echoes the base64 chunks. `MAX_TTL` is 30 days (`mvm-core/src/crypto/policy/ttl.rs`). I did not test what happens at TTL expiry, so set the TTL above the session cap and treat it as a backstop.

## Egress over time (attach mode, `spike-fgd`, `--allow-host dl-cdn.alpinelinux.org --allow-host pypi.org`)
Probe (`fg/egress.sh`): `HTTPS_PROXY=http://127.0.0.1:1080 …`, `apk add --usermode --root /tmp/r --initdb --no-scripts --keys-dir /etc/apk/keys --repositories-file /etc/apk/repositories curl`, then `curl https://pypi.org/simple/requests/`, then `curl https://example.com/` as the negative control.

| time since boot | pypi | example.com |
|---|---|---|
| ~45 s (t0) | `http=200 bytes=82826` | `CONNECT tunnel failed, response 403` |
| ~3 min | 200, 82826 B | 403 |
| ~31 min by `etime` (the 10-min mark; the host clock jumped during the wait, likely sleep) | 200, 82826 B | 403 |

`spike-fge` (create, then attach) and `spike-fgf` (after a restart) gave the same t0 results.

## exec compatibility
- `machine exec <name>` works against the attach-run machine. It runs as uid 901 with no proxy env, as before.
- Chunked copy-in works: 300,000 random bytes, base64-encoded, sent as 7 argv chunks of 60,000 chars each with `sh -c 'printf %s "$1" >>/tmp/blob.b64; …' sh "<chunk>"`, then decoded with `base64 -d`. Guest sha256 matched the host: `efe69f96…6d4b`. Copy-out also works: `base64 /tmp/blob.bin` returned the same sha256 on the host.
- Poisoning is unchanged:
  - The wrapped `false` gave host rc 0 and printed `rc=1`, and the next exec worked.
  - The bare `sh -c 'exit 3'` gave host rc 3, and **every** later exec failed with `Error: machine input sequence 4 has no durable finish; refuse exec and checkpoint until the ambiguous operation is recovered`.
  - So the existing `sh -c '…; echo rc=$?; exit 0'` wrapper is still necessary, and sufficient.

## Failure and teardown behaviour
| Action | Result |
|---|---|
| `machine rm --force --yes` while the attach is alive (`spike-fge`, also `spike-fgf`) | VM, endpoint and supervisor are gone, and the dirs are removed. **The attach mvmctl keeps running** until signalled. SIGTERM ends it with `Interrupted, cleaning up...`. |
| SIGINT or SIGTERM to the attach while the VM runs (`spike-fgd`, `spike-fgf`) | The attach exits ("Ctrl-C detaches (it keeps running)"). **The endpoint exits with it.** The supervisor is reparented to pid 1 and the VM stays `running`. |
| `kill -9` the attach (`spike-fgg`) | Same: the endpoint dies, and the supervisor and VM keep running. |
| egress after the attach dies | **Fails closed.** `curl … pypi.org` got `Connection timed out after 30001 ms` or `CONNECT tunnel failed, response 502`, and later `Failed to connect … over proxy 127.0.0.1 after 0 ms`. The disallowed host also failed. |
| `machine exec` after the attach dies | **Still works** (`echo alive`, host rc 0). So the death is silent from exec's point of view, and rts must watch the PID itself. |
| re-run `machine run --name X --ttl D` on the still-running VM | `machine X already running`. It attaches but **does not respawn the endpoint**, so egress stays down. |
| recovery | `machine stop X --yes` (without `--yes` it refuses), then `machine run --name X --ttl D`. That is a fresh boot with egress back. **Guest `/tmp` state is lost**: curl had to be reinstalled. |
| `machine rm --force --yes` after the attach died (`spike-fgd` after SIGINT, `spike-fgg` after kill -9) | Cleans up fully. It also reaps the orphaned supervisor (pids 11158 and 60942 gone). |

Implications for rts:
- Spawn the attach and keep its PID.
- Treat its exit as "egress down" and fail the session, or stop and restart it, accepting the lost state.
- At teardown, run `machine rm --force --yes` and then SIGTERM the attach (SIGKILL if it lingers).
- Do not start two machines at the same instant. Launching `spike-fgf` and `spike-fgg` back to back made fgf fail with `rename ~/.mvm/vms/spike-fgf/plan.json.tmp -> plan.json: No such file or directory`. It booted fine when retried alone. Serialize starts, or retry once.

## Alternatives without patching mvm
- I found no env var or flag that disables the watchdog: `exit_when_orphaned()` runs unconditionally, and `parent_death.rs` has no opt-out.
- The watchdog watches whichever process spawned the endpoint. With `machine start`, that mvmctl exits on purpose. A wrapper cannot make the endpoint's parent long-lived: the parent must be the mvmctl process that calls `spawn_network_endpoint`, so the only way is to keep that mvmctl alive. That is exactly what the attach mode does, so it is the no-patch option. `machine run -d` returns at once, so it has the same bug as `machine start`.
- The upstream fix is either to drop `exit_when_orphaned()` for endpoints spawned by the setsid "detached" path, or to have the endpoint watch the supervisor pid.

## Process-cleanup proof
Final state after everything I created was removed:
- `mvmctl machine ps` printed `no machines`.
- `ls ~/.mvm/vms` is empty.
- `ls -A ~/.mvm/machines` is empty, after I removed the leftover `spike-fga`/`spike-fgc` journal dirs from the transient runs.
- `ps -ax | grep -E 'mvm(ctl|-network|-hvf)' | grep -v grep | wc -l` gave `0`.

mvm left endpoint logs at `/tmp/mvm-network-endpoint-spike-fg{a..g}.log`. Machines created: spike-fga, spike-fgb, spike-fgc (transient), and spike-fgd, spike-fge, spike-fgf, spike-fgg (persistent). I did not touch any `rts-*` or other machines; another agent's `repro-egress` was running and was left alone. No repository or worktree was modified.

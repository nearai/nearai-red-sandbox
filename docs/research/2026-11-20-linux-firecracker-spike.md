# Linux/Firecracker spike, 2026-11-20

Phase 1 of `docs/design/linux-windows-backends.md`: run the rts Firecracker
flavor on a real KVM host with mvm v0.22.0 and the non-elevating `sudo`
shim. If v0.22.0's guest egress fails (tinylabscom/mvm#3962), repeat with
mvm v0.28.0-rc.11 built from source. No NEAR AI keys or other secrets were
put on the host; nothing here exercises attestation or inference.

## Host

Azure Standard_D4s_v4 (4 vCPU, 16 GB, nested virtualization), Ubuntu
24.04.5, kernel `7.0.0-1020-azure`, x86_64. User `rts` (uid 1000) is in
the `kvm` group (`/dev/kvm` is `crw-rw---- root kvm`). The user also has
NOPASSWD sudo. That makes this a real test of the shim: without it, mvm's
`sudo` would succeed and Firecracker would run as root.

## Results

| Question | Answer |
|---|---|
| Does rts build and its unit tests pass on Linux? | Yes, after the gating commit: lib 564 passed, 0 failed, 17 ignored. The 5 `copy::tests` that fail on macOS (bsdtar PAX headers) pass on Linux. `forwarder::tests::a_second_connection_to_a_different_certificate_fails_the_pin` is flaky here, also when run alone (1 of 4): the record still reads `verified` when the test checks it, after the 502 and the fatal were already asserted. This is a pre-existing ordering race between raising the fatal and writing `pin-failed`. |
| Does Firecracker run without root? | Yes. mvm v0.22.0 calls `sudo rm -f fc.socket`, `sudo setsid nohup sh -c 'echo $$ > fc.pid; exec firecracker --api-sock …'`, `sudo chown -- 1000:1000 fc.socket` and `… runtime/v.sock`, and `sudo kill <pid>`. With the shim first on PATH, every one ran as uid 1000. `firecracker` ran as uid 1000, and the uid check in rts accepted it. `machine exec` makes no sudo calls. |
| Firecracker install | Not bundled with mvmctl. `mvmctl bootstrap` downloads Firecracker v1.17.0 and moves it to `/usr/local/bin` with `sudo mv`, which the shim refuses (fails closed). rts must install a pinned, checksum-verified Firecracker into its own prefix and put it on mvmctl's PATH. |
| Process tree | `mvmctl machine run` → child `mvm-network-endpoint`. Firecracker is not a child (parent 1, detached by `setsid`). `ps -o comm=` shows `mvm` for both mvmctl and the endpoint, and the kernel comm is truncated to `mvm-network-end`. rts names processes by `/proc/<pid>/exe`, which gives the full name. |
| Guest egress on v0.22.0 (#3962) | Fails. `mvm-network-endpoint` is killed by SIGSYS (apport reports signal 31) right after start and stays a zombie. The guest's FlowMux handshake and reconnects get "Connection reset by peer", and a CONNECT to `127.0.0.1:1080` times out. rts fails closed: the allowlist probe times out and the session is refused. |
| Guest egress on v0.28.0-rc.11 | Not established. rc.11 has no GitHub release or assets, only a tag. A release-channel build (mirroring `release.yml`) refuses to boot without the published `mvm-guest-bins-v0.28.0-rc.11` runtime: a locally built archive placed beside mvmctl still fails with `guest runtime io: No such file or directory`. A contributor build (`cargo build --release --bin mvmctl`, then `MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build mvmctl bootstrap`, 18 min) boots an x86_64 guest as uid 1000. With an allowlist, though, `machine run` stops at `the egress endpoint refused the gate probe: the endpoint reply is not a gate-probe response: missing field 'results'`, with both the glibc and the musl endpoint from the same commit. Whether that is the contributor build or rc.11 itself needs mvm's maintainers or a published rc. |
| rc.11 differences that matter to rts | It downloads Firecracker into `<MVM_HOME>/cache/firecracker/v1.17.0/` and starts it with no `sudo` calls at all; `bootstrap` still runs `sudo mkdir -p /var/lib/mvm/tenants`. It runs a standby pool: a detached `mvmctl pool refill` and idle Firecracker VMs under `<MVM_HOME>/fc-idle/` that outlive `machine rm`. rts's teardown, sweep and RSS accounting assume one VMM per session, so this needs a design decision before rts moves to 0.28 (disable the pool, or account for it). |
| Guest image | The pinned `DEFAULT_IMAGE` is arm64-only (config `architecture: arm64`), and so is the alpine base digest in `guest/Dockerfile` (a per-platform manifest, not an index; no current alpine tag's index contains it). x86_64 needs a multi-arch guest image built from an alpine index digest. |
| Pulling from Artifact Registry | mvm v0.22.0's OCI client follows only 307/308 blob redirects (`mvm-fs/src/oci/registry.rs`, `is_preserving_redirect`). `us-west1-docker.pkg.dev` answers blob GETs with 302, so `mvmctl image pull` of `DEFAULT_IMAGE` fails on a host without the image cached. This affects `rts setup`'s image step on any fresh install, macOS too (not re-checked on macOS here). |

## Live invariants on Firecracker (`tests/contain/invariants.rs`)

| mvm | no route out | no host files | VMM non-root, RSS ceiling | allowlist exact and pinned |
|---|---|---|---|---|
| v0.22.0 | pass | pass | pass | fail: probe `pypi.org:443` timed out (#3962) |
| v0.28.0-rc.11 | not run: no rc.11 build here gets egress past the gate probe | | | |

## Commands

Install build tools, Rust, Docker (throwaway host):

```sh
sudo apt-get update && sudo apt-get install -y build-essential pkg-config curl netcat-openbsd docker.io docker-buildx
curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
```

rts from the PR branch (public repo, no credentials):

```sh
git clone --branch linux-windows-backends https://github.com/nearai/nearai-red-sandbox.git ~/rts
cd ~/rts && cargo build --tests --bins && cargo test --no-fail-fast
```

mvm v0.22.0 (the pinned asset; digest matches `setup::mvm_for(Target::LinuxX86_64)`):

```sh
curl -sSfLO https://github.com/tinylabscom/mvm/releases/download/v0.22.0/mvmctl-x86_64-unknown-linux-gnu.tar.gz
echo "502e84ea3fa1ff04b0138fb6c3cb47b3a72c730d72c8f468df55e01d99c94d64  mvmctl-x86_64-unknown-linux-gnu.tar.gz" | sha256sum -c
mkdir -p ~/.local/mvm/v0.22.0 && tar -xzf mvmctl-x86_64-unknown-linux-gnu.tar.gz -C ~/.local/mvm/v0.22.0 --strip-components 1
```

The rts shim, extracted from `SUDO_SHIM` in `src/backend/kvm.rs`, plus a
logging wrapper used only for the manual mvmctl runs:

```sh
mkdir -p ~/shim
python3 -c 'import re;s=open("src/backend/kvm.rs").read();print(re.search(r"pub const SUDO_SHIM: &str = r#\"(.*?)\"#;",s,re.S).group(1),end="")' > ~/shim/sudo-real-shim
chmod 700 ~/shim/sudo-real-shim
printf '#!/bin/sh\necho "$(date +%%T) uid=$(id -u) sudo $*" >> ~/sudo-calls.log\nexec ~/shim/sudo-real-shim "$@"\n' > ~/shim/sudo; chmod 700 ~/shim/sudo
PATH=~/shim:$PATH ~/.local/mvm/v0.22.0/mvmctl doctor --workflow bundle-run   # exit 0, backend firecracker
```

Firecracker (what `mvmctl bootstrap` would fetch, installed per-user and
verified against the release's `.sha256.txt`):

```sh
curl -sSfLO https://github.com/firecracker-microvm/firecracker/releases/download/v1.17.0/firecracker-v1.17.0-x86_64.tgz
curl -sSfLO https://github.com/firecracker-microvm/firecracker/releases/download/v1.17.0/firecracker-v1.17.0-x86_64.tgz.sha256.txt
sha256sum -c firecracker-v1.17.0-x86_64.tgz.sha256.txt   # 06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558
tar -xzf firecracker-v1.17.0-x86_64.tgz
install -m 0755 release-v1.17.0-x86_64/firecracker-v1.17.0-x86_64 ~/.local/firecracker/v1.17.0/firecracker
```

amd64 guest image: `guest/Dockerfile` with the base changed to the
`alpine:3.23` index digest
`sha256:469c9ea410b9215eaee7976ba6c0639039b444be8e5d638f7abbada189971eb2`.
It is served from a local registry with a spike-only CA, because rts only
accepts `name@sha256:` references and mvm v0.22.0 cannot pull ours from
Artifact Registry (302):

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 7 -subj /CN=rts-spike-ca -keyout ca.key -out ca.crt
# leaf for reg.rts.test signed by ca.crt; ca.crt into /usr/local/share/ca-certificates; 127.0.0.1 reg.rts.test in /etc/hosts
sudo docker run -d --name rts-reg -p 127.0.0.1:443:5443 -v ~/reg/certs:/certs \
  -e REGISTRY_HTTP_ADDR=0.0.0.0:5443 -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/reg.crt -e REGISTRY_HTTP_TLS_KEY=/certs/reg.key registry:2
sudo docker build --platform linux/amd64 -t reg.rts.test/rts/guest:amd64 ~/guest-amd64 && sudo docker push reg.rts.test/rts/guest:amd64
~/.local/mvm/v0.22.0/mvmctl image pull reg.rts.test/rts/guest@sha256:db03f96487950e218d5d0e840ed39d3a70d28c6ad00046336d9028ab3f2b4593
```

Manual mvmctl runs (no-network machine, then an attached network machine as
rts creates it):

```sh
export PATH=~/shim:~/.local/firecracker/v1.17.0:/usr/bin:/bin
M=~/.local/mvm/v0.22.0/mvmctl
$M machine create spike-1 --image oci-archive:/home/rts/guest-amd64.oci.tar --profile dev --cpus 1 --memory 512M
$M machine start spike-1          # firecracker runs as uid 1000
PATH=/usr/bin:/bin $M machine exec spike-1 -- sh -c 'uname -m; id; ip -o link'   # x86_64, mvm-worker, lo only
$M machine create spike-net --image oci-archive:/home/rts/guest-amd64.oci.tar --profile dev --cpus 1 --memory 512M --allow-host pypi.org:443
$M machine run --name spike-net --ttl 1h > ~/spike-net-attach.log 2>&1 &
$M machine exec spike-net -- sh -c 'printf "CONNECT pypi.org:443 HTTP/1.1\r\nHost: pypi.org:443\r\n\r\n" | nc -w 10 127.0.0.1 1080 | head -1'   # times out
```

Live invariants through rts (rts installs its own shim; `~/shim` is not on PATH):

```sh
cd ~/rts
PATH=$HOME/.local/firecracker/v1.17.0:$PATH RTS_MVMCTL=$HOME/.local/mvm/v0.22.0/mvmctl \
RTS_IMAGE=reg.rts.test/rts/guest@sha256:db03f96487950e218d5d0e840ed39d3a70d28c6ad00046336d9028ab3f2b4593 \
  cargo test --test contain invariants:: -- --ignored --test-threads=1
```

mvm v0.28.0-rc.11 from source, mirroring its `release.yml` for
`x86_64-unknown-linux-musl`. Zig 0.13.0 and cargo-zigbuild 0.23.0 were
installed by running the steps of mvm's `.github/actions/install-zigbuild`,
which pin and sha256-check both:

```sh
git clone --depth 1 --branch v0.28.0-rc.11 https://github.com/tinylabscom/mvm.git ~/mvm-src   # 3070cd7
cd ~/mvm-src
export BUILD_TARGET=x86_64-unknown-linux-musl OPENSSL_STATIC=1 OPENSSL_VENDORED=1
cargo zigbuild --profile release-min --target $BUILD_TARGET --features host,user,release-artifact-bootstrap,release-channel,embed-host-bins
cargo zigbuild --release --target $BUILD_TARGET -p mvm-hostd -p mvm-gpu --bin mvm-host-agent --bin mvm-policy-coordinator \
  --bin mvm-signer-helper --bin mvm-network-endpoint --bin mvm-broker --bin mvm-audit-signer --bin mvm-mailbox --bin mvm-gpu-endpoint
```

Contributor build of v0.28.0-rc.11 (README "From source"). Its bootstrap
builds the guest runtime from the checkout; zig must be on PATH:

```sh
cd ~/mvm-src
cargo build --release --bin mvmctl
cargo build --release -p mvm-hostd --bin mvm-network-endpoint
export MVM_HOME=~/.mvm-dev PATH=~/shim:~/.local/firecracker/v1.17.0:$HOME/.cargo/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MVM_RUNTIME_OVERLAY_ACQUIRE_MODE=build target/release/mvmctl bootstrap
target/release/mvmctl image pull reg.rts.test/rts/guest@sha256:db03f96487950e218d5d0e840ed39d3a70d28c6ad00046336d9028ab3f2b4593
target/release/mvmctl machine run --image reg.rts.test/rts/guest@sha256:db03f96487950e218d5d0e840ed39d3a70d28c6ad00046336d9028ab3f2b4593 -- uname -m   # x86_64
target/release/mvmctl machine create spike-dev --image <same> --profile dev --cpus 1 --memory 512M --allow-host pypi.org:443
target/release/mvmctl machine run --name spike-dev --ttl 1h   # Error: the egress endpoint refused the gate probe ...
```

The release-channel build also needs mvm's guest runtime archive, built as
its `guest-bins.yml` does (72 min here, both architectures):

```sh
cargo run --locked -p mvmctl -- dev guest-bins --out dist
```

## Follow-ups for rts

1. Publish a multi-arch guest image from an alpine index digest; pin the index digest.
2. `rts setup` on Linux: install a pinned, checksum-verified Firecracker
   into the rts prefix and put it on mvmctl's PATH (or rely on 0.28's own
   download); check `/dev/kvm`; skip the HVF supervisor and codesign steps.
3. Make sure `/usr/sbin` stays on mvmctl's PATH (`mkfs.ext4`, which bootstrap needs).
4. Image pulls from Artifact Registry fail on mvm v0.22.0 (302). Pre-pull
   during setup through another client, serve the image from a registry
   that redirects with 307, or wait for an mvm release that follows 302.
5. Move to mvm 0.28 only once a published release passes this spike's
   egress test. Decide how to handle its standby pool.
6. `forwarder::tests::a_second_connection_to_a_different_certificate_fails_the_pin`:
   make `pin-failed` durable before the fatal is observable, or make the
   test wait for it.

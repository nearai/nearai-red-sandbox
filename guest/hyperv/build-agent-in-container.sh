#!/bin/bash
# The container half of build-agent.sh. Do not run on a host.
set -euo pipefail
# A private copy: the build writes target/ and must not see the host's.
mkdir -p /build/guest/hyperv /build/src
cp -r /repo/guest/hyperv/agent /build/guest/hyperv/agent
cp -r /repo/src/hvexec /build/src/hvexec
rm -rf /build/guest/hyperv/agent/target
rustup target add x86_64-unknown-linux-musl >/dev/null
cd /build/guest/hyperv/agent
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld
export SOURCE_DATE_EPOCH=0
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=/build=/rts"$'\x1f'"--remap-path-prefix=${CARGO_HOME:-/usr/local/cargo}=/cargo"
cargo build --quiet --release --locked --target x86_64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/release/rts-guest /out/rts-guest
(cd /out && sha256sum rts-guest | tee rts-guest.sha256)

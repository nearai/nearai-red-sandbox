#!/bin/bash
# Reproducibly build the rts-guest agent (static musl, x86_64).
#
#   guest/hyperv/build-agent.sh <out-dir>
#
# Builds in a digest-pinned Rust image with the Cargo.lock in
# guest/hyperv/agent, linking with rust-lld and remapping build paths, so
# the same source gives the same bytes on any docker host. Needs docker.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
out="$(mkdir -p "${1:?usage: build-agent.sh <out-dir>}" && cd "$1" && pwd)"

# rust:1.100.0-slim-trixie
IMAGE=docker.io/library/rust@sha256:6f14b2b4b278ec0d50aa1d69541c304ce0f95e0f6268487aa9924af1c2e9aebe

docker run --rm --platform linux/amd64 \
  -v "$repo/guest/hyperv/agent:/repo/guest/hyperv/agent:ro" \
  -v "$repo/src/hvexec:/repo/src/hvexec:ro" \
  -v "$here/build-agent-in-container.sh:/build-agent-in-container.sh:ro" \
  -v "$out:/out" "$IMAGE" bash /build-agent-in-container.sh

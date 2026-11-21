#!/bin/bash
# Reproducibly build the rts Hyper-V guest kernel.
#
#   guest/hyperv/build.sh <out-dir>
#
# Runs the build in a digest-pinned Debian image with packages from a fixed
# snapshot.debian.org date, from a kernel.org tarball checked against the
# sha256 below, with fixed build timestamp, user and host. Two runs give the
# same bzImage bytes. Needs docker.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="$(mkdir -p "${1:?usage: build.sh <out-dir>}" && cd "$1" && pwd)"

KERNEL_VERSION=6.18.64
KERNEL_SHA256=020d45510c539972e6f14c5c71566878d3b7ef56fb082b3e09134f2ebaade562
# debian:trixie-20261104-slim
IMAGE=docker.io/library/debian@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
SNAPSHOT=20261104T000000Z
SOURCE_DATE_EPOCH=1793750400 # 2026-11-04T00:00:00Z

docker run --rm --network=host --platform linux/amd64 \
  -e KERNEL_VERSION="$KERNEL_VERSION" -e KERNEL_SHA256="$KERNEL_SHA256" \
  -e SNAPSHOT="$SNAPSHOT" -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  -v "$here:/recipe:ro" -v "$out:/out" "$IMAGE" bash /recipe/build-in-container.sh

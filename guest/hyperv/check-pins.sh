#!/bin/bash
# Fail unless the built guest files match the digests rts pins.
#
#   guest/hyperv/check-pins.sh <dir with vmlinuz and initramfs.cpio.gz>
#
# The pins are read from src/backend/hyperv/backend.rs, the same constants
# rts checks before booting a VM, so CI proves the recipe reproduces
# exactly what rts will accept.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
dir="${1:?usage: check-pins.sh <dir>}"
pins="$here/../../src/backend/hyperv/backend.rs"
pin() { sed -n "s/^pub const $1: &str = \"\([0-9a-f]\{64\}\)\";/\1/p" "$pins"; }
fail=0
for pair in "vmlinuz:KERNEL_SHA256" "initramfs.cpio.gz:INITRD_SHA256"; do
  file="${pair%%:*}"; const="${pair##*:}"
  want="$(pin "$const")"
  [ -n "$want" ] || { echo "no $const pin in $pins" >&2; exit 1; }
  got="$(sha256sum "$dir/$file" | cut -d' ' -f1)"
  if [ "$got" = "$want" ]; then
    echo "$file: $got (pinned)"
  else
    echo "$file: built $got, pinned $want" >&2
    fail=1
  fi
done
exit "$fail"

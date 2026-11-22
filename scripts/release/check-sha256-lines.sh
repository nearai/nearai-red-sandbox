#!/bin/bash
# Refuse a checksum file whose lines are not exactly `<sha256>  <name>`:
#
#   scripts/release/check-sha256-lines.sh FILE...
#
# 64 lowercase hex digits, two spaces, then a bare file name (no path, no
# leading `*`, no spaces). sha256sum on Windows writes ` *<name>` (binary
# mode), which `sha256sum -c` accepts but which breaks anything that reads
# SHA256SUMS by field, such as an embedder pinning an archive's digest.
# Each name must appear once per file.
set -euo pipefail

[ $# -ge 1 ] || { echo "usage: $0 FILE..." >&2; exit 2; }
status=0
for f in "$@"; do
  [ -s "$f" ] || { echo "check-sha256-lines: $f is missing or empty" >&2; status=1; continue; }
  n=0
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    if ! [[ "$line" =~ ^[0-9a-f]{64}\ \ [A-Za-z0-9._+-]+$ ]]; then
      echo "check-sha256-lines: $f line $n is not '<64 hex>  <name>': $line" >&2
      status=1
    fi
  done < "$f"
  dups="$(awk '{print $2}' "$f" | LC_ALL=C sort | uniq -d)"
  if [ -n "$dups" ]; then
    echo "check-sha256-lines: $f lists a name more than once: $dups" >&2
    status=1
  fi
done
exit "$status"

#!/bin/bash
# Package the Windows rts release archive:
#
#   scripts/package-windows.sh --version V --rts PATH --egress PATH --out DIR
#
# writes DIR/rts-V-x86_64-pc-windows-msvc.tar and its .sha256. The archive is
# a plain ustar tar (no compression, no pax or GNU extensions: rts unpacks it
# with its own untar, which refuses those) holding
#
#   bin/rts.exe
#   libexec/nearai-red-sandbox/rts-egress.exe   (built with --profile egress)
#   share/nearai-red-sandbox/plugin/...
#
# An embedder's `rts setup` (run_in_prefix) installs the libexec and plugin
# parts into its prefix after checking the archive against its pinned sha256.
# Used by windows-check (so pull requests exercise it) and release.yml.
set -euo pipefail

version="" rts="" egress="" out=""
while [ $# -gt 0 ]; do
  case "$1" in
    --version) version="$2"; shift 2 ;;
    --rts) rts="$2"; shift 2 ;;
    --egress) egress="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$version" ] && [ -f "$rts" ] && [ -f "$egress" ] && [ -n "$out" ] || {
  echo "usage: $0 --version V --rts PATH --egress PATH --out DIR" >&2
  exit 2
}
here="$(cd "$(dirname "$0")/.." && pwd)"
plugin="$here/plugin"
[ -f "$plugin/index.ts" ] || { echo "no plugin at $plugin" >&2; exit 1; }
# GNU tar: --format=ustar, --sort and --mtime are what make the archive plain
# and reproducible (bsdtar, System32's tar.exe, writes pax headers).
tar --version 2>/dev/null | grep -q "GNU tar" || { echo "GNU tar is required" >&2; exit 1; }

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/bin" "$stage/libexec/nearai-red-sandbox" "$stage/share/nearai-red-sandbox"
cp "$rts" "$stage/bin/rts.exe"
cp "$egress" "$stage/libexec/nearai-red-sandbox/rts-egress.exe"
cp -R "$plugin" "$stage/share/nearai-red-sandbox/plugin"

mkdir -p "$out"
name="rts-$version-x86_64-pc-windows-msvc.tar"
epoch="${SOURCE_DATE_EPOCH:-$(git -C "$here" log -1 --format=%ct)}"
tar --format=ustar --sort=name --owner=0 --group=0 --numeric-owner \
  --mode='u+rwX,go+rX,go-w' --mtime="@$epoch" \
  -C "$stage" -cf "$out/$name" bin libexec share
(cd "$out" && sha256sum "$name" > "$name.sha256" && cat "$name.sha256")
tar -tvf "$out/$name"

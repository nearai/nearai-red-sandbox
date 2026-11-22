#!/bin/bash
# Package the Linux rts release archive:
#
#   scripts/package-linux.sh --version V --rts PATH --out DIR [--target T]
#
# writes DIR/rts-V-T.tar.gz and its .sha256, where T is
# x86_64-unknown-linux-gnu (the default) or aarch64-unknown-linux-gnu and
# must match the --rts binary's architecture. The
# archive is a gzipped plain ustar tar, reproducible from the same inputs
# (sorted names, owner 0, the last commit's mtime, gzip -n), holding
#
#   bin/rts
#   share/nearai-red-sandbox/plugin/...   (the files the macOS archive ships)
#
# and no supervisor: on Linux mvm runs Firecracker, which needs none. An
# embedder's `rts setup` (run_in_prefix) installs the plugin into its prefix
# after checking the archive against its pinned sha256; the embedder links
# rts itself. Used by linux-check (so pull requests exercise it) and
# release.yml. Members are named bin and share, never ./bin: the installer
# extracts share/nearai-red-sandbox/plugin by name.
set -euo pipefail
umask 022

version="" rts="" out="" target="x86_64-unknown-linux-gnu"
while [ $# -gt 0 ]; do
  case "$1" in
    --version|--rts|--out|--target)
      [ $# -ge 2 ] && [ -n "$2" ] || { echo "$1 needs a value" >&2; exit 2; }
      case "$1" in
        --version) version="$2" ;;
        --rts) rts="$2" ;;
        --out) out="$2" ;;
        --target) target="$2" ;;
      esac
      shift 2
      ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$version" ] && [ -f "$rts" ] && [ -x "$rts" ] && [ -n "$out" ] || {
  echo "usage: $0 --version V --rts PATH --out DIR [--target T]" >&2
  exit 2
}
case "$target" in
  x86_64-unknown-linux-gnu) machine="x86-64" ;;
  aarch64-unknown-linux-gnu) machine="ARM aarch64" ;;
  *) echo "unknown --target: $target (x86_64-unknown-linux-gnu or aarch64-unknown-linux-gnu)" >&2; exit 2 ;;
esac
# The archive is named for its target; a binary for another one is refused.
if command -v file >/dev/null 2>&1; then
  desc="$(file --brief --dereference "$rts")"
  case "$desc" in
    *ELF*"$machine"*) ;;
    *) echo "--rts is not an ELF for $target: $desc" >&2; exit 1 ;;
  esac
fi
here="$(cd "$(dirname "$0")/.." && pwd -P)"
tar --version 2>/dev/null | grep -q "GNU tar" || { echo "GNU tar is required" >&2; exit 1; }
plugin_files=(index.ts audit.ts package.json branding/tui.tsx branding/footer.ts branding/startup.ts branding/theme/nearai-red.json)
for f in "${plugin_files[@]}"; do
  [ -f "$here/plugin/$f" ] || { echo "repository file missing: $here/plugin/$f" >&2; exit 1; }
done

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
plugin="$stage/share/nearai-red-sandbox/plugin"
mkdir -p "$stage/bin" "$plugin"
cp "$rts" "$stage/bin/rts"
for f in "${plugin_files[@]}"; do
  mkdir -p "$(dirname "$plugin/$f")"
  cp "$here/plugin/$f" "$plugin/$f"
done
find "$stage" -type d -exec chmod 0755 {} +
find "$stage" -type f -exec chmod 0644 {} +
chmod 0755 "$stage/bin/rts"

mkdir -p "$out"
name="rts-$version-$target.tar.gz"
epoch="${SOURCE_DATE_EPOCH:-$(git -C "$here" log -1 --format=%ct)}"
tar --format=ustar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
  -C "$stage" -cf - bin share | gzip -n -9 > "$out/$name"
(cd "$out" && sha256sum "$name" > "$name.sha256" && cat "$name.sha256")
tar -tvzf "$out/$name"

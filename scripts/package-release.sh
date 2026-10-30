#!/bin/bash
# Package a release: the rts tarball, the rendered install.sh and SHA256SUMS.
# Runs the same locally and in CI; it signs nothing and reads no secrets.
set -euo pipefail
umask 022

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly ROOT
readonly TARGET=aarch64-apple-darwin
version=
rts=
supervisor=
build_info=
out=
install_sh="$ROOT/install.sh"
stage=

die() { printf 'refusing: %s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'EOF'
Usage: package-release.sh --version X.Y.Z --rts PATH --supervisor PATH
                          --build-info PATH --out DIR [--install-sh TEMPLATE]

Writes rts-X.Y.Z-aarch64-apple-darwin.tar.gz, install.sh (the template with
@RTS_VERSION@ replaced) and SHA256SUMS into DIR, which must be missing or
empty. Pass the binaries after signing: the build-info's
signed_binary_sha256 is rewritten to the packaged supervisor's digest.
Default template: install.sh in the repository root.
EOF
}
cleanup() {
  # Populated only by a successful mktemp below.
  if [[ -n "$stage" ]]; then rm -rf -- "$stage"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version|--rts|--supervisor|--build-info|--out|--install-sh)
      [[ $# -ge 2 && -n "$2" ]] || die "$1 needs a value"
      case "$1" in
        --version) version=$2 ;;
        --rts) rts=$2 ;;
        --supervisor) supervisor=$2 ;;
        --build-info) build_info=$2 ;;
        --out) out=$2 ;;
        --install-sh) install_sh=$2 ;;
      esac
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

for flag in version rts supervisor build_info out; do
  [[ -n "${!flag}" ]] || die "--${flag//_/-} is required"
done
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "--version must be X.Y.Z (digits only, no leading v): $version"
[[ -f "$rts" && -x "$rts" ]] || die "--rts is not an executable file: $rts"
[[ -f "$supervisor" && -x "$supervisor" ]] || die "--supervisor is not an executable file: $supervisor"
[[ -f "$build_info" && -r "$build_info" ]] || die "--build-info is not a readable file: $build_info"
[[ -f "$install_sh" && -r "$install_sh" ]] || die "--install-sh is not a readable file: $install_sh"
if [[ -e "$out" ]]; then
  [[ -d "$out" ]] || die "--out exists and is not a directory: $out"
  [[ -z "$(ls -A -- "$out")" ]] || die "--out is not empty: $out"
fi

info_lines=$(grep -c '^signed_binary_sha256=' -- "$build_info" || true)
[[ "$info_lines" == 1 ]] || die "--build-info must have exactly one signed_binary_sha256= line, found $info_lines: $build_info"
placeholders=$(grep -o '@RTS_VERSION@' -- "$install_sh" | wc -l | tr -d ' ' || true)
[[ "$placeholders" == 1 ]] || die "--install-sh template must hold @RTS_VERSION@ exactly once, found $placeholders: $install_sh"
for f in LICENSE README.md plugin/index.ts plugin/audit.ts plugin/package.json opencode/session.example.json; do
  [[ -f "$ROOT/$f" ]] || die "repository file missing: $ROOT/$f"
done

stage=$(mktemp -d "${TMPDIR:-/tmp}/rts-package.XXXXXXXX")
tree="$stage/tree"
dist="$stage/dist"
mkdir -p "$tree/bin" "$tree/libexec/nearai-red-sandbox" \
  "$tree/share/nearai-red-sandbox/plugin" "$tree/share/nearai-red-sandbox/opencode" "$dist"

cp -- "$rts" "$tree/bin/rts"
cp -- "$supervisor" "$tree/libexec/nearai-red-sandbox/mvm-hvf-supervisor"
supervisor_sha=$(shasum -a 256 "$tree/libexec/nearai-red-sandbox/mvm-hvf-supervisor" | awk '{print $1}')
awk -v sha="$supervisor_sha" '/^signed_binary_sha256=/ { print "signed_binary_sha256=" sha; next } { print }' \
  "$build_info" > "$tree/libexec/nearai-red-sandbox/mvm-hvf-supervisor.build-info"
cp -- "$ROOT/plugin/index.ts" "$ROOT/plugin/audit.ts" "$ROOT/plugin/package.json" "$tree/share/nearai-red-sandbox/plugin/"
cp -- "$ROOT/opencode/session.example.json" "$tree/share/nearai-red-sandbox/opencode/"
cp -- "$ROOT/LICENSE" "$ROOT/README.md" "$tree/"

find "$tree" -type d -exec chmod 0755 {} +
find "$tree" -type f -exec chmod 0644 {} +
chmod 0755 "$tree/bin/rts" "$tree/libexec/nearai-red-sandbox/mvm-hvf-supervisor"

tarball="rts-$version-$TARGET.tar.gz"
COPYFILE_DISABLE=1 /usr/bin/tar --no-xattrs --no-mac-metadata --uid 0 --gid 0 --uname root --gname wheel \
  -czf "$dist/$tarball" -C "$tree" LICENSE README.md bin libexec share
sed "s/@RTS_VERSION@/$version/" "$install_sh" > "$dist/install.sh"
chmod 0644 "$dist/$tarball" "$dist/install.sh"
(cd "$dist" && shasum -a 256 "$tarball" install.sh > SHA256SUMS)

mkdir -p -- "$out"
mv -- "$dist/$tarball" "$dist/install.sh" "$dist/SHA256SUMS" "$out/"
printf 'Packaged %s\n' "$out/$tarball"

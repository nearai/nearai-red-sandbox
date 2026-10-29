#!/bin/bash
# Build the reviewed source patch; never modify the operator's mvm install.
set -euo pipefail
umask 077

readonly UPSTREAM=https://github.com/tinylabscom/mvm.git
readonly REV=b6b77f83730bed54d52f5f8b9cdcd8d5136ca1de
readonly PATCH_VERSION=rts-vsock-drain-v1
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly ROOT
readonly PATCH="$ROOT/patches/mvm-v0.22.0-hvf-drain.patch"
source_dir=
install_dir="${HOME:?HOME must be set}/.local/share/nearai-red-sandbox"
work=
staged=
staged_info=

die() { printf 'refusing: %s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'EOF'
Usage: build-patched-mvm-supervisor.sh [--source CLEAN_CHECKOUT] [--install-dir ABSOLUTE_DIR]

Builds a pinned mvm supervisor with the repository's HVF drain patch on
Apple-silicon macOS. A supplied checkout is read only and must be clean at
the exact pinned commit. Otherwise clones upstream into a temporary directory.
Default install: $HOME/.local/share/nearai-red-sandbox/mvm-hvf-supervisor
EOF
}
cleanup() {
  # These names are populated only by successful mktemp calls below.
  if [[ -n "$staged" ]]; then rm -f -- "$staged"; fi
  if [[ -n "$staged_info" ]]; then rm -f -- "$staged_info"; fi
  if [[ -n "$work" ]]; then rm -rf -- "$work"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

while [[ $# -gt 0 ]]; do
  case "$1" in
    --source|--install-dir)
      [[ $# -ge 2 && -n "$2" ]] || die "$1 requires a path"
      if [[ "$1" == --source ]]; then source_dir=$2; else install_dir=$2; fi
      shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

# Do not follow an installation directory or destination supplied as a symlink.
check_install_path() {
  local rest component current=
  [[ "$install_dir" == /* ]] || die "install directory must be absolute"
  rest=${install_dir#/}
  while [[ -n "$rest" ]]; do
    component=${rest%%/*}
    if [[ "$rest" == */* ]]; then rest=${rest#*/}; else rest=; fi
    [[ "$component" != . && "$component" != .. ]] || die "install path contains . or .."
    [[ -n "$component" ]] || continue
    current="$current/$component"
    [[ ! -L "$current" ]] || die "install path contains a symlink: $current"
    [[ ! -e "$current" || -d "$current" ]] || die "install path component is not a directory: $current"
  done
  for component in mvm-hvf-supervisor mvm-hvf-supervisor.build-info; do
    current="$install_dir/$component"
    [[ ! -L "$current" ]] || die "install destination is a symlink: $current"
    [[ ! -e "$current" || ( -f "$current" && -O "$current" ) ]] || die "install destination is not an owned regular file: $current"
  done
}
check_install_path
if [[ -n "$source_dir" ]]; then
  [[ -d "$source_dir" ]] || die "source checkout does not exist: $source_dir"
  [[ "$(git -C "$source_dir" rev-parse --show-toplevel 2>/dev/null)" == "$(cd "$source_dir" && pwd -P)" ]] || die "source must name a checkout root"
  [[ "$(git -C "$source_dir" rev-parse HEAD)" == "$REV" ]] || die "source HEAD must be $REV"
  [[ -z "$(git -C "$source_dir" status --porcelain --untracked-files=all)" ]] || die "source checkout must be clean"
fi
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || die "Apple-silicon macOS is required (other targets build a stub)"
[[ -f "$PATCH" && ! -L "$PATCH" ]] || die "missing regular repository patch: $PATCH"
for command in git cargo shasum tar; do command -v "$command" >/dev/null || die "missing command: $command"; done
[[ -x /usr/bin/codesign ]] || die "codesign is required"

work=$(mktemp -d "${TMPDIR:-/tmp}/rts-mvm-build.XXXXXXXX")
if [[ -z "$source_dir" ]]; then
  git -c core.hooksPath=/dev/null clone --no-checkout "$UPSTREAM" "$work/upstream"
  git -C "$work/upstream" -c core.hooksPath=/dev/null checkout --detach "$REV"
  source_dir="$work/upstream"
fi
[[ "$(git -C "$source_dir" rev-parse HEAD)" == "$REV" ]] || die "source HEAD changed"
[[ -z "$(git -C "$source_dir" status --porcelain --untracked-files=all)" ]] || die "source checkout must be clean"

# git archive excludes untracked/ignored files and leaves the supplied tree alone.
mkdir "$work/source"
git -C "$source_dir" archive --format=tar "$REV" > "$work/source.tar"
tar -xf "$work/source.tar" -C "$work/source"
cp "$PATCH" "$work/reviewed.patch"
git -C "$work/source" apply --check --whitespace=error-all "$work/reviewed.patch"
git -C "$work/source" apply --whitespace=error-all "$work/reviewed.patch"
printf 'Building mvm %s + %s (this can take several minutes)\n' "$REV" "$PATCH_VERSION" >&2
(
  cd "$work/source"
  RUSTFLAGS='-D warnings' CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$work/target" \
    cargo --locked build --release --target aarch64-apple-darwin -p mvm-hostd --bin mvm-hvf-supervisor
)
binary="$work/target/aarch64-apple-darwin/release/mvm-hvf-supervisor"
[[ -x "$binary" ]] || die "build did not produce the supervisor"
[[ "$("$binary" --rts-vsock-drain-fix-version)" == "$PATCH_VERSION" ]] || die "built supervisor lacks required patch marker"
[[ "$("$binary" --contract-version)" == 'mvm-hvf-supervisor contract-version=4' ]] || die "unexpected helper contract"
/usr/bin/codesign --force --sign - --entitlements "$work/source/assets/mvm-supervisor.entitlements" "$binary"
/usr/bin/codesign --verify --strict "$binary"

check_install_path
mkdir -p "$install_dir"
[[ -O "$install_dir" && "$(stat -f %Lp "$install_dir")" == 700 ]] || die "install directory must be owned by you with mode 700: $install_dir"
staged=$(mktemp "$install_dir/.mvm-supervisor.XXXXXXXX")
staged_info=$(mktemp "$install_dir/.mvm-supervisor-info.XXXXXXXX")
cp "$binary" "$staged"
chmod 700 "$staged"
/usr/bin/codesign --verify --strict "$staged"
[[ "$("$staged" --rts-vsock-drain-fix-version)" == "$PATCH_VERSION" ]] || die "staged supervisor lacks required patch marker"
{
  printf 'upstream=%s\nrevision=%s\npatch_version=%s\n' "$UPSTREAM" "$REV" "$PATCH_VERSION"
  printf 'patch_sha256=%s\n' "$(shasum -a 256 "$work/reviewed.patch" | awk '{print $1}')"
  printf 'signed_binary_sha256=%s\n' "$(shasum -a 256 "$staged" | awk '{print $1}')"
  printf 'rustflags=-D warnings\ncargo_incremental=0\ntarget=aarch64-apple-darwin\n'
  (cd "$work/source" && cargo --version && rustc --version)
} > "$staged_info"
check_install_path
# Rename within the installation directory publishes complete files atomically.
mv -f "$staged" "$install_dir/mvm-hvf-supervisor"
staged=
mv -f "$staged_info" "$install_dir/mvm-hvf-supervisor.build-info"
staged_info=
printf 'Installed %s\n' "$install_dir/mvm-hvf-supervisor"
if [[ "$install_dir" == "$HOME/.local/share/nearai-red-sandbox" ]]; then
  printf 'rts selects this default path when MVM_HVF_SUPERVISOR_PATH is unset.\n'
else
  printf 'Set this absolute override when launching rts:\n'
  printf 'export MVM_HVF_SUPERVISOR_PATH=%q\n' "$install_dir/mvm-hvf-supervisor"
fi

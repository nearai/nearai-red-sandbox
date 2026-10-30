#!/bin/bash
# Install rts from a GitHub release:
#   curl -fsSL https://github.com/nearai/nearai-red-sandbox/releases/latest/download/install.sh | bash
#
# Environment: RTS_VERSION (default: the release this file came from),
# RTS_RELEASE_BASE (default: that release's download URL), RTS_INSTALL_PREFIX
# (default: ~/.local). Needs no sudo and never edits shell profiles.
#
# The whole body is one function called on the last line, so a truncated
# download defines nothing it can run.
set -euo pipefail

download_dir=
stage_dir=

cleanup() {
  # Populated only by a successful mktemp in main.
  if [[ -n "$download_dir" ]]; then rm -rf -- "$download_dir"; fi
  if [[ -n "$stage_dir" ]]; then rm -rf -- "$stage_dir"; fi
}

main() {
  local RTS_DEFAULT_VERSION="@RTS_VERSION@"
  local repo=nearai/nearai-red-sandbox
  local target=aarch64-apple-darwin
  # Exactly the paths the tarball owns. Nothing else under the prefix is
  # touched: share/nearai-red-sandbox also holds opencode, sessions and a
  # source-built supervisor that rts setup and rts launch keep there.
  local owned=(
    bin/rts
    libexec/nearai-red-sandbox
    share/nearai-red-sandbox/plugin
    share/nearai-red-sandbox/opencode/session.example.json
  )

  die() { printf 'rts install: %s\n' "$*" >&2; exit 1; }

  local os arch
  os=$(uname -s)
  arch=$(uname -m)
  if [[ "$os" != Darwin || "$arch" != arm64 ]]; then
    die "rts supports macOS on Apple silicon ($target) only; this is $os $arch"
  fi

  if [[ -z "${RTS_VERSION:-}" && "$RTS_DEFAULT_VERSION" == *@* ]]; then
    die "this install.sh is an unrendered template; set RTS_VERSION"
  fi
  local version="${RTS_VERSION:-$RTS_DEFAULT_VERSION}"
  if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    die "RTS_VERSION must be X.Y.Z (digits only, no leading v): $version"
  fi
  local base="${RTS_RELEASE_BASE:-https://github.com/$repo/releases/download/v$version}"
  local prefix="${RTS_INSTALL_PREFIX:-$HOME/.local}"
  if [[ "$prefix" != /* ]]; then
    die "RTS_INSTALL_PREFIX must be an absolute path: $prefix"
  fi
  local tarball="rts-$version-$target.tar.gz"

  trap cleanup EXIT
  download_dir=$(mktemp -d "${TMPDIR:-/tmp}/rts-install.XXXXXX")

  local name
  for name in "$tarball" SHA256SUMS; do
    if ! curl -fsSL --proto '=https,file' --proto-redir '=https' -o "$download_dir/$name" "$base/$name"; then
      die "could not download $base/$name; check the version ($version) and your network, then re-run"
    fi
  done

  # A piped install has no install.sh on disk, so check only the tarball's line.
  awk -v f="$tarball" '$2 == f' "$download_dir/SHA256SUMS" > "$download_dir/tarball.sha256"
  local count
  count=$(wc -l < "$download_dir/tarball.sha256" | tr -d ' ')
  if [[ "$count" != 1 ]]; then
    die "SHA256SUMS from $base has $count lines for $tarball, expected 1; the release is incomplete, do not install it"
  fi
  if ! (cd "$download_dir" && shasum -a 256 -c tarball.sha256 >/dev/null 2>&1); then
    die "$tarball from $base does not match its SHA256SUMS entry; refusing to install it (re-run; if it persists, report it)"
  fi

  if command -v gh >/dev/null 2>&1; then
    if ! gh attestation verify "$download_dir/$tarball" --repo "$repo"; then
      die "gh attestation verify failed for $tarball from $base against $repo; refusing to install it"
    fi
  else
    printf 'rts install: provenance not checked: install the GitHub CLI (gh) to verify the release attestation\n' >&2
  fi

  # Directories created here, the prefix chain included, are 0700:
  # scripts/build-patched-mvm-supervisor.sh refuses
  # ~/.local/share/nearai-red-sandbox unless it is mode 700. Directories that
  # already exist keep their modes.
  if ! (umask 077 && mkdir -p -- "$prefix/share/nearai-red-sandbox"); then
    die "could not create the install prefix $prefix; create it or set RTS_INSTALL_PREFIX"
  fi
  # Same filesystem as the prefix, so the moves below are renames.
  stage_dir=$(mktemp -d "$prefix/.rts-install.XXXXXX")
  mkdir -- "$stage_dir/new" "$stage_dir/old"
  if ! /usr/bin/tar -xzf "$download_dir/$tarball" -C "$stage_dir/new" -- "${owned[@]}"; then
    die "could not unpack $tarball into $stage_dir/new; nothing under $prefix was changed"
  fi

  local p q i
  for p in "${owned[@]}"; do
    if [[ ! -e "$stage_dir/new/$p" ]]; then
      die "$tarball has no $p; nothing under $prefix was changed"
    fi
  done
  local swapped=" "
  for p in "${owned[@]}"; do
    if ! swap "$prefix" "$stage_dir" "$p"; then
      # Put back every earlier copy already moved aside, newest first, and
      # drop new copies that had no earlier one.
      for ((i = ${#owned[@]} - 1; i >= 0; i--)); do
        q=${owned[i]}
        if [[ -e "$stage_dir/old/$q" || -L "$stage_dir/old/$q" ]]; then
          rm -rf -- "${prefix:?}/$q"
          mv -- "$stage_dir/old/$q" "$prefix/$q" || true
        elif [[ "$swapped" == *" $q "* ]]; then
          rm -rf -- "${prefix:?}/$q"
        fi
      done
      die "could not move $p into $prefix; the earlier install was restored"
    fi
    swapped+="$p "
  done

  local status=0
  "$prefix/bin/rts" setup || status=$?
  if [[ "$status" != 0 ]]; then
    printf 'rts install: rts was installed to %s but "rts setup" failed (exit %s); fix the error above and run %s setup\n' \
      "$prefix" "$status" "$prefix/bin/rts" >&2
    exit "$status"
  fi

  case ":$PATH:" in
    *":$prefix/bin:"*) ;;
    *)
      printf '%s/bin is not on your PATH. Add this line to your shell profile:\n' "$prefix"
      printf "  export PATH=\"%s/bin:\$PATH\"\n" "$prefix"
      ;;
  esac
  printf 'rts %s installed to %s\n' "$version" "$prefix/bin/rts"
}

# Move the installed $3 under prefix $1 aside into stage $2/old, then move the
# unpacked one from $2/new into place.
swap() {
  local prefix=$1 stage=$2 p=$3
  mkdir -p -- "$(dirname -- "$prefix/$p")" || return 1
  if [[ -e "$prefix/$p" || -L "$prefix/$p" ]]; then
    mkdir -p -- "$(dirname -- "$stage/old/$p")" || return 1
    mv -- "$prefix/$p" "$stage/old/$p" || return 1
  fi
  mv -- "$stage/new/$p" "$prefix/$p"
}

main "$@"

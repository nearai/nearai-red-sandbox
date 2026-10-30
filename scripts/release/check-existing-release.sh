#!/bin/bash
# Decide whether an existing GitHub release is this run's own earlier upload.
#
#   check-existing-release.sh --repo OWNER/NAME --tag vX.Y.Z --dir DIST
#
# DIST holds this run's SHA256SUMS and the files it lists. Exits 0 only when
# the release's assets are exactly those files plus SHA256SUMS, each with a
# GitHub-computed sha256 digest equal to this run's: then a re-run of the
# publish job can skip `gh release create` and go on to the tap. Anything else
# (a missing, extra or digestless asset, a different digest, an unreadable
# release) exits 1.
set -euo pipefail

repo=
tag=
dist=

die() { printf 'check-existing-release: refusing: %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo|--tag|--dir)
      [[ $# -ge 2 && -n "$2" ]] || die "$1 needs a value"
      case "$1" in
        --repo) repo=$2 ;;
        --tag) tag=$2 ;;
        --dir) dist=$2 ;;
      esac
      shift 2
      ;;
    -h|--help) sed -n '2,11p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -n "$repo" && -n "$tag" && -n "$dist" ]] || die "--repo, --tag and --dir are required"
[[ -f "$dist/SHA256SUMS" ]] || die "no SHA256SUMS in $dist"
(cd "$dist" && shasum -a 256 -c SHA256SUMS >/dev/null) || die "the files in $dist do not match its SHA256SUMS"

expected=$(
  {
    awk '{ print "sha256:" $1 " " $2 }' "$dist/SHA256SUMS"
    printf 'sha256:%s SHA256SUMS\n' "$(shasum -a 256 "$dist/SHA256SUMS" | awk '{ print $1 }')"
  } | LC_ALL=C sort
)

if ! actual=$(gh api "repos/$repo/releases/tags/$tag" --jq '.assets[] | "\(.digest // "none") \(.name)"'); then
  die "could not read release $tag of $repo"
fi
actual=$(printf '%s\n' "$actual" | sed '/^$/d' | LC_ALL=C sort)

if [[ "$actual" != "$expected" ]]; then
  {
    printf 'check-existing-release: refusing: release %s of %s does not hold exactly this run'"'"'s assets\n' "$tag" "$repo"
    printf 'expected (this run):\n%s\n' "$expected"
    printf 'published:\n%s\n' "${actual:-<no assets>}"
    printf 'see "Recovering a partly published release" in docs/specs/2026-10-29-release-and-installers-design.md\n'
  } >&2
  exit 1
fi
printf 'release %s of %s already holds exactly this run'"'"'s assets; not re-creating it\n' "$tag" "$repo"

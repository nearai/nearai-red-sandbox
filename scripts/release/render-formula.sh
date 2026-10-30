#!/bin/bash
# Render the Homebrew formula for one release from
# packaging/homebrew/rts.rb.template.
#
#   render-formula.sh --version X.Y.Z --sha256 HEX --out FILE [--template FILE]
#
# Refuses a version that is not X.Y.Z, a sha256 that is not 64 lowercase hex
# digits, or a rendered file with any @ left in it; nothing is written then.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly ROOT
version=
sha256=
out=
template="$ROOT/packaging/homebrew/rts.rb.template"
tmp=

die() { printf 'render-formula: refusing: %s\n' "$*" >&2; exit 1; }
cleanup() { if [[ -n "$tmp" ]]; then rm -f -- "$tmp"; fi; }
trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version|--sha256|--out|--template)
      [[ $# -ge 2 && -n "$2" ]] || die "$1 needs a value"
      case "$1" in
        --version) version=$2 ;;
        --sha256) sha256=$2 ;;
        --out) out=$2 ;;
        --template) template=$2 ;;
      esac
      shift 2
      ;;
    -h|--help) sed -n '2,8p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -n "$version" && -n "$sha256" && -n "$out" ]] || die "--version, --sha256 and --out are required"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "--version must be X.Y.Z (digits only, no leading v): $version"
[[ "$sha256" =~ ^[0-9a-f]{64}$ ]] || die "--sha256 must be 64 lowercase hex digits: $sha256"
[[ -f "$template" && -r "$template" ]] || die "--template is not a readable file: $template"

tmp=$(mktemp "${TMPDIR:-/tmp}/rts-formula.XXXXXXXX")
sed -e "s/@VERSION@/$version/g" -e "s/@SHA256@/$sha256/g" -- "$template" > "$tmp"
if grep -n '@' -- "$tmp" >&2; then
  die "the rendered formula still holds @ on the lines above (template: $template)"
fi
chmod 0644 "$tmp"
mv -- "$tmp" "$out"
tmp=
printf 'Rendered %s\n' "$out"

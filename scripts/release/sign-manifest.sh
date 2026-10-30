#!/bin/bash
# Write and sign the update manifest (latest.json, latest.json.sig) for a
# packaged release in DIST, then add both to DIST/SHA256SUMS.
#
# The private key is read only from RTS_UPDATE_SIGNING_KEY_PEM_BASE64 (an
# OpenSSL Ed25519 PEM, base64). The signature is checked against
# --public-key-hex before anything lands in DIST, so a secret that does not
# match the key compiled into rts cannot ship. Every refusal leaves DIST as it
# was. See docs/specs/2026-10-30-auto-update-design.md, "Signing in CI".
set -euo pipefail
umask 022

readonly TARGET=aarch64-apple-darwin
readonly SPKI_PREFIX=302a300506032b6570032100
readonly VERSION_RE='^[0-9]+\.[0-9]+\.[0-9]+$'
version=
dist=
public_hex=
minimum=
published=
openssl=
work=
manifest_tmp=
sig_tmp=
sums_tmp=
placed=

die() { printf 'sign-manifest: refusing: %s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'EOF'
Usage: sign-manifest.sh --version X.Y.Z --dir DIST --public-key-hex HEX
                        [--minimum X.Y.Z] [--published YYYY-MM-DDTHH:MM:SSZ]
                        [--openssl PATH]

Reads the signing key from RTS_UPDATE_SIGNING_KEY_PEM_BASE64. Writes
DIST/latest.json and DIST/latest.json.sig and appends both to
DIST/SHA256SUMS. Default --published: now (UTC). Default --openssl:
$(brew --prefix openssl@3)/bin/openssl; LibreSSL cannot sign raw Ed25519.
EOF
}
cleanup() {
  local status=$?
  # Populated only by a successful mktemp below; holds the decoded key.
  if [[ -n "$work" ]]; then rm -rf -- "$work"; fi
  if [[ -n "$manifest_tmp" ]]; then rm -f -- "$manifest_tmp"; fi
  if [[ -n "$sig_tmp" ]]; then rm -f -- "$sig_tmp"; fi
  if [[ -n "$sums_tmp" ]]; then rm -f -- "$sums_tmp"; fi
  # Placed but SHA256SUMS not yet replaced: take them back out.
  if [[ -n "$placed" ]]; then rm -f -- "$dist/latest.json" "$dist/latest.json.sig"; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version|--dir|--public-key-hex|--minimum|--published|--openssl)
      [[ $# -ge 2 && -n "$2" ]] || die "$1 needs a value"
      case "$1" in
        --version) version=$2 ;;
        --dir) dist=$2 ;;
        --public-key-hex) public_hex=$2 ;;
        --minimum) minimum=$2 ;;
        --published) published=$2 ;;
        --openssl) openssl=$2 ;;
      esac
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

# Validate everything before writing anything.
[[ -n "$version" ]] || die "--version is required"
[[ -n "$dist" ]] || die "--dir is required"
[[ -n "$public_hex" ]] || die "--public-key-hex is required"
[[ "$version" =~ $VERSION_RE ]] || die "--version must be X.Y.Z (digits only, no leading v): $version"
[[ "$public_hex" =~ ^[0-9a-f]{64}$ ]] || die "--public-key-hex must be 64 lowercase hex characters"
if [[ -n "$minimum" ]]; then
  [[ "$minimum" =~ $VERSION_RE ]] || die "--minimum must be X.Y.Z (digits only, no leading v): $minimum"
  # Three integers, base 10 (a leading zero is not octal); never sort -V.
  IFS=. read -r v1 v2 v3 <<<"$version"
  IFS=. read -r m1 m2 m3 <<<"$minimum"
  if (( 10#$m1 > 10#$v1 || (10#$m1 == 10#$v1 && (10#$m2 > 10#$v2 || (10#$m2 == 10#$v2 && 10#$m3 > 10#$v3))) )); then
    die "--minimum $minimum is above --version $version"
  fi
fi
if [[ -z "$published" ]]; then published=$(date -u +%Y-%m-%dT%H:%M:%SZ); fi
[[ "$published" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] \
  || die "--published must be YYYY-MM-DDTHH:MM:SSZ: $published"
[[ -n "${RTS_UPDATE_SIGNING_KEY_PEM_BASE64:-}" ]] || die "RTS_UPDATE_SIGNING_KEY_PEM_BASE64 is empty or unset"

if [[ -z "$openssl" ]]; then
  prefix=$(brew --prefix openssl@3 2>/dev/null) || die "no --openssl given and brew --prefix openssl@3 failed (brew install openssl@3)"
  openssl="$prefix/bin/openssl"
fi
[[ -f "$openssl" && -x "$openssl" ]] || die "--openssl is not an executable file: $openssl"
openssl_version=$("$openssl" version 2>/dev/null) || die "$openssl version failed"
case "$openssl_version" in
  LibreSSL*) die "$openssl is LibreSSL ($openssl_version), which cannot sign raw Ed25519 (pkeyutl -rawin); use OpenSSL 3 (brew install openssl@3)" ;;
esac
[[ "$openssl_version" =~ ^OpenSSL\ ([3-9]|[1-9][0-9]+)\. ]] || die "$openssl is not OpenSSL 3 or later: $openssl_version"

[[ -d "$dist" ]] || die "--dir is not a directory: $dist"
tarball="rts-$version-$TARGET.tar.gz"
for f in "$tarball" install.sh SHA256SUMS; do
  [[ -f "$dist/$f" ]] || die "$f is missing from --dir: $dist"
done
for f in latest.json latest.json.sig; do
  [[ ! -e "$dist/$f" && ! -L "$dist/$f" ]] || die "$f already exists in --dir: $dist"
done
(cd "$dist" && shasum -a 256 -c SHA256SUMS >/dev/null 2>&1) || die "SHA256SUMS does not check in --dir: $dist"

# Exactly one SHA256SUMS line each for the tarball and install.sh.
digest_of() {
  local name=$1 lines
  lines=$(awk -v f="$name" '$2 == f' "$dist/SHA256SUMS")
  [[ -n "$lines" && "$lines" != *$'\n'* ]] || die "SHA256SUMS must list $name exactly once"
  [[ "$lines" =~ ^([0-9a-f]{64})\ \ ${name//./\\.}$ ]] || die "SHA256SUMS line for $name is malformed"
  printf '%s' "${BASH_REMATCH[1]}"
}
tarball_sha=$(digest_of "$tarball")
install_sh_sha=$(digest_of install.sh)
if grep -qE '  latest\.json(\.sig)?$' "$dist/SHA256SUMS"; then die "SHA256SUMS already lists the manifest"; fi

work=$(mktemp -d "${TMPDIR:-/tmp}/rts-sign-manifest.XXXXXXXX")

# The key: decoded under umask 077, removed with $work on exit.
( umask 077; printf '%s' "$RTS_UPDATE_SIGNING_KEY_PEM_BASE64" | base64 --decode > "$work/key.pem" ) 2>/dev/null \
  || die "RTS_UPDATE_SIGNING_KEY_PEM_BASE64 is not valid base64"
"$openssl" pkey -in "$work/key.pem" -noout >/dev/null 2>&1 \
  || die "RTS_UPDATE_SIGNING_KEY_PEM_BASE64 does not decode to a private key PEM"

# The public key, from the hex alone: SPKI DER prefix then the 32 key bytes.
printf '%s%s' "$SPKI_PREFIX" "$public_hex" | xxd -r -p > "$work/pub.der"
"$openssl" pkey -pubin -inform DER -in "$work/pub.der" -out "$work/pub.pem" >/dev/null 2>&1 \
  || die "--public-key-hex is not an Ed25519 public key"

# Every value matched a fixed pattern above, so none needs JSON escaping.
manifest_tmp="$dist/.latest.json.tmp"
sig_tmp="$dist/.latest.json.sig.tmp"
sums_tmp="$dist/.SHA256SUMS.tmp"
{
  printf '{\n'
  printf '  "latest": "%s",\n' "$version"
  if [[ -n "$minimum" ]]; then printf '  "minimum_supported": "%s",\n' "$minimum"; fi
  printf '  "published": "%s",\n' "$published"
  printf '  "tarball": {\n'
  printf '    "name": "%s",\n' "$tarball"
  printf '    "sha256": "%s"\n' "$tarball_sha"
  printf '  },\n'
  printf '  "install_sh": {\n'
  printf '    "sha256": "%s"\n' "$install_sh_sha"
  printf '  }\n'
  printf '}\n'
} > "$manifest_tmp"

"$openssl" pkeyutl -sign -rawin -inkey "$work/key.pem" -in "$manifest_tmp" -out "$work/sig.bin" >/dev/null 2>&1 \
  || die "openssl pkeyutl -sign failed (is the key Ed25519?)"
sig_len=$(wc -c < "$work/sig.bin" | tr -d ' ')
[[ "$sig_len" == 64 ]] || die "the signature is $sig_len bytes, not 64 (is the key Ed25519?)"
# One line, no trailing newline (GNU base64 wraps at 76 columns).
printf '%s' "$(base64 < "$work/sig.bin" | tr -d '\n')" > "$sig_tmp"

# Verify what was written: decode the .sig back and check it with the public key.
base64 --decode < "$sig_tmp" > "$work/check.bin" 2>/dev/null || die "the written signature does not decode"
"$openssl" pkeyutl -verify -pubin -inkey "$work/pub.pem" -rawin -in "$manifest_tmp" -sigfile "$work/check.bin" >/dev/null 2>&1 \
  || die "the signature does not verify with --public-key-hex: RTS_UPDATE_SIGNING_KEY_PEM_BASE64 is not the matching private key"

chmod 0644 "$manifest_tmp" "$sig_tmp"
placed=1
mv -- "$manifest_tmp" "$dist/latest.json"
manifest_tmp=
mv -- "$sig_tmp" "$dist/latest.json.sig"
sig_tmp=
{
  cat "$dist/SHA256SUMS"
  (cd "$dist" && shasum -a 256 latest.json latest.json.sig)
} > "$sums_tmp"
(cd "$dist" && shasum -a 256 -c "$(basename "$sums_tmp")" >/dev/null 2>&1) || die "the extended SHA256SUMS does not check"
chmod 0644 "$sums_tmp"
mv -- "$sums_tmp" "$dist/SHA256SUMS"
sums_tmp=
placed=
(cd "$dist" && shasum -a 256 -c SHA256SUMS >/dev/null) || die "SHA256SUMS does not check after signing"
printf 'Signed %s\n' "$dist/latest.json"

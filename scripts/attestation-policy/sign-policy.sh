#!/bin/bash
# Sign one attestation policy document: copy it to DIR/<environment>.json and
# write DIR/<environment>.json.sig, base64 of the raw 64-byte Ed25519
# signature over the exact bytes, the format rts verifies (as latest.json.sig).
#
# The key is either a Cloud KMS EC_SIGN_ED25519 key version (--kms-key, signed
# through gcloud, so the private key never leaves KMS) or, without --kms-key,
# RTS_ATTESTATION_POLICY_SIGNING_KEY_PEM_BASE64 (an OpenSSL Ed25519 PEM,
# base64). Never both. The signature is checked against
# --public-key-hex before anything lands in DIR, so a secret that does not
# match the key compiled into rts cannot publish. Every refusal leaves DIR as
# it was. Key handling follows scripts/release/sign-manifest.sh. See
# docs/specs/2026-11-24-signed-attestation-policy-feed-design.md, "CI: the
# publisher".
set -euo pipefail
umask 022

readonly SPKI_PREFIX=302a300506032b6570032100
readonly MAX_DOCUMENT_BYTES=262144
environment=
input=
public_hex=
dir=.
openssl=
kms_key=
gcloud=
work=
doc_tmp=
sig_tmp=
placed=

die() { printf 'sign-policy: refusing: %s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'EOF'
Usage: sign-policy.sh --environment production|staging --in document.json
                      --public-key-hex HEX [--dir DIR] [--openssl PATH]
                      [--kms-key projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/N
                       [--gcloud PATH]]

With --kms-key, signs with that Cloud KMS Ed25519 key version through gcloud
(default --gcloud: gcloud on PATH). Otherwise reads the signing key from
RTS_ATTESTATION_POLICY_SIGNING_KEY_PEM_BASE64.
Writes DIR/<environment>.json (a byte copy of --in) and
DIR/<environment>.json.sig. Default --dir: the current directory. Default
--openssl: openssl on PATH, which must be OpenSSL 3 or later (LibreSSL cannot
sign raw Ed25519).
EOF
}
cleanup() {
  local status=$?
  # Populated only by a successful mktemp below; holds the decoded key.
  if [[ -n "$work" ]]; then rm -rf -- "$work"; fi
  if [[ -n "$doc_tmp" ]]; then rm -f -- "$doc_tmp"; fi
  if [[ -n "$sig_tmp" ]]; then rm -f -- "$sig_tmp"; fi
  # The document placed but not its signature: take it back out.
  if [[ -n "$placed" ]]; then rm -f -- "$dir/$environment.json" "$dir/$environment.json.sig"; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

while [[ $# -gt 0 ]]; do
  case "$1" in
    --environment|--in|--public-key-hex|--dir|--openssl|--kms-key|--gcloud)
      [[ $# -ge 2 && -n "$2" ]] || die "$1 needs a value"
      case "$1" in
        --environment) environment=$2 ;;
        --in) input=$2 ;;
        --public-key-hex) public_hex=$2 ;;
        --dir) dir=$2 ;;
        --openssl) openssl=$2 ;;
        --kms-key) kms_key=$2 ;;
        --gcloud) gcloud=$2 ;;
      esac
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

# Validate everything before writing anything.
[[ "$environment" == production || "$environment" == staging ]] || die "--environment must be production or staging"
[[ -n "$input" ]] || die "--in is required"
[[ "$public_hex" =~ ^[0-9a-f]{64}$ ]] || die "--public-key-hex must be 64 lowercase hex characters"
readonly KMS_NAME='[A-Za-z0-9_-]{1,63}'
readonly KMS_VERSION_RE="^projects/($KMS_NAME)/locations/($KMS_NAME)/keyRings/($KMS_NAME)/cryptoKeys/($KMS_NAME)/cryptoKeyVersions/([1-9][0-9]{0,8})$"
if [[ -n "$kms_key" ]]; then
  [[ -z "${RTS_ATTESTATION_POLICY_SIGNING_KEY_PEM_BASE64:-}" ]] \
    || die "--kms-key and RTS_ATTESTATION_POLICY_SIGNING_KEY_PEM_BASE64 are both set: give one key, not both"
  [[ "$kms_key" =~ $KMS_VERSION_RE ]] \
    || die "--kms-key must be projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/N"
  kms_project=${BASH_REMATCH[1]}
  kms_location=${BASH_REMATCH[2]}
  kms_keyring=${BASH_REMATCH[3]}
  kms_cryptokey=${BASH_REMATCH[4]}
  kms_version=${BASH_REMATCH[5]}
  if [[ -z "$gcloud" ]]; then
    gcloud=$(command -v gcloud) || die "no --gcloud given and gcloud is not on PATH"
  fi
  [[ -f "$gcloud" && -x "$gcloud" ]] || die "--gcloud is not an executable file: $gcloud"
else
  [[ -z "$gcloud" ]] || die "--gcloud is given without --kms-key"
  [[ -n "${RTS_ATTESTATION_POLICY_SIGNING_KEY_PEM_BASE64:-}" ]] || die "RTS_ATTESTATION_POLICY_SIGNING_KEY_PEM_BASE64 is empty or unset (or pass --kms-key)"
fi
command -v python3 >/dev/null || die "python3 is not on PATH"

if [[ -z "$openssl" ]]; then
  openssl=$(command -v openssl) || die "no --openssl given and openssl is not on PATH"
fi
[[ -f "$openssl" && -x "$openssl" ]] || die "--openssl is not an executable file: $openssl"
openssl_version=$("$openssl" version 2>/dev/null) || die "$openssl version failed"
case "$openssl_version" in
  LibreSSL*) die "$openssl is LibreSSL ($openssl_version), which cannot sign raw Ed25519 (pkeyutl -rawin); use OpenSSL 3" ;;
esac
[[ "$openssl_version" =~ ^OpenSSL\ ([3-9]|[1-9][0-9]+)\. ]] || die "$openssl is not OpenSSL 3 or later: $openssl_version"

[[ -f "$input" && ! -L "$input" ]] || die "--in is not a regular file: $input"
[[ -d "$dir" ]] || die "--dir is not a directory: $dir"
for f in "$environment.json" "$environment.json.sig"; do
  [[ ! -e "$dir/$f" && ! -L "$dir/$f" ]] || die "$f already exists in --dir: $dir"
done

work=$(mktemp -d "${TMPDIR:-/tmp}/rts-sign-policy.XXXXXXXX")

# Sign a private copy, so the bytes signed are the bytes published.
cp -- "$input" "$work/doc.json"
size=$(wc -c < "$work/doc.json" | tr -d ' ')
(( size <= MAX_DOCUMENT_BYTES )) || die "--in is $size bytes, over rts's cap of $MAX_DOCUMENT_BYTES"
python3 -I - "$work/doc.json" "$environment" <<'EOF' || die "--in is not a schema 1 document for --environment $environment"
import json, sys
doc = json.loads(open(sys.argv[1], "rb").read().decode("utf-8"))
ok = isinstance(doc, dict) and doc.get("schema") == 1 and doc.get("environment") == sys.argv[2]
sys.exit(0 if ok else 1)
EOF

if [[ -z "$kms_key" ]]; then
  # The key: decoded under umask 077, removed with $work on exit.
  ( umask 077; printf '%s' "$RTS_ATTESTATION_POLICY_SIGNING_KEY_PEM_BASE64" | base64 --decode > "$work/key.pem" ) 2>/dev/null \
    || die "RTS_ATTESTATION_POLICY_SIGNING_KEY_PEM_BASE64 is not valid base64"
  "$openssl" pkey -in "$work/key.pem" -noout >/dev/null 2>&1 \
    || die "RTS_ATTESTATION_POLICY_SIGNING_KEY_PEM_BASE64 does not decode to a private key PEM"
fi

# The public key, from the hex alone: SPKI DER prefix then the 32 key bytes.
python3 -I -c 'import sys; sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]))' "$SPKI_PREFIX$public_hex" > "$work/pub.der"
"$openssl" pkey -pubin -inform DER -in "$work/pub.der" -out "$work/pub.pem" >/dev/null 2>&1 \
  || die "--public-key-hex is not an Ed25519 public key"

if [[ -n "$kms_key" ]]; then
  # Cloud KMS signs an EC_SIGN_ED25519 key's input as PureEdDSA over the exact
  # bytes, the same 64-byte signature openssl pkeyutl -rawin makes.
  "$gcloud" kms asymmetric-sign \
    --project "$kms_project" --location "$kms_location" --keyring "$kms_keyring" \
    --key "$kms_cryptokey" --version "$kms_version" \
    --input-file "$work/doc.json" --signature-file "$work/sig.bin" >&2 \
    || die "gcloud kms asymmetric-sign failed for --kms-key $kms_key"
else
  "$openssl" pkeyutl -sign -rawin -inkey "$work/key.pem" -in "$work/doc.json" -out "$work/sig.bin" >/dev/null 2>&1 \
    || die "openssl pkeyutl -sign failed (is the key Ed25519?)"
fi
sig_len=$(wc -c < "$work/sig.bin" | tr -d ' ')
[[ "$sig_len" == 64 ]] || die "the signature is $sig_len bytes, not 64 (is the key Ed25519?)"

doc_tmp="$dir/.$environment.json.tmp"
sig_tmp="$dir/.$environment.json.sig.tmp"
cp -- "$work/doc.json" "$doc_tmp"
# One line, no trailing newline (GNU base64 wraps at 76 columns).
printf '%s' "$(base64 < "$work/sig.bin" | tr -d '\n')" > "$sig_tmp"

# Verify what was written: decode the .sig back and check it with the public key.
base64 --decode < "$sig_tmp" > "$work/check.bin" 2>/dev/null || die "the written signature does not decode"
"$openssl" pkeyutl -verify -pubin -inkey "$work/pub.pem" -rawin -in "$doc_tmp" -sigfile "$work/check.bin" >/dev/null 2>&1 \
  || die "the signature does not verify with --public-key-hex: ${kms_key:-RTS_ATTESTATION_POLICY_SIGNING_KEY_PEM_BASE64} is not the matching private key"
cmp -s -- "$input" "$doc_tmp" || die "--in changed while it was being signed"

chmod 0644 "$doc_tmp" "$sig_tmp"
placed=1
mv -- "$doc_tmp" "$dir/$environment.json"
doc_tmp=
mv -- "$sig_tmp" "$dir/$environment.json.sig"
sig_tmp=
placed=
printf 'Signed %s\n' "$dir/$environment.json"

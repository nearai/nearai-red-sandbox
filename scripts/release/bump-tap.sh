#!/bin/bash
# Commit the Homebrew formula bump for one release to nearai/homebrew-tap.
#
#   bump-tap.sh --version X.Y.Z --sha256 HEX --run-id ID
#
# The nearai org requires verified signatures on every branch, so the commit
# is made with GraphQL createCommitOnBranch, which GitHub authors and signs
# as the credential's owner (the tap GitHub App), rather than by a git push.
# GH_TOKEN must be a token with contents: write on the tap. The commit is
# made only against the head it read (expectedHeadOid); if main moved, the
# head is re-read and the commit retried once. Exits 0 without committing
# when the tap already carries this formula (a re-run), and fails unless
# GitHub reports the new commit as verified.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly ROOT
readonly TAP=nearai/homebrew-tap BRANCH=main FILE=Formula/rts.rb
version=
sha256=
run_id=
tmp=

die() { printf 'bump-tap: refusing: %s\n' "$*" >&2; exit 1; }
cleanup() { if [[ -n "$tmp" ]]; then rm -rf -- "$tmp"; fi; }
trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version|--sha256|--run-id)
      [[ $# -ge 2 && -n "$2" ]] || die "$1 needs a value"
      case "$1" in
        --version) version=$2 ;;
        --sha256) sha256=$2 ;;
        --run-id) run_id=$2 ;;
      esac
      shift 2
      ;;
    -h|--help) sed -n '2,13p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "--version must be X.Y.Z"
[[ "$sha256" =~ ^[0-9a-f]{64}$ ]] || die "--sha256 must be 64 lowercase hex digits"
[[ "$run_id" =~ ^[0-9]+$ ]] || die "--run-id must be a number"
[[ -n "${GH_TOKEN:-}" ]] || die "GH_TOKEN (a token with contents: write on $TAP) is not set"

tmp="$(mktemp -d)"
bash "$ROOT/scripts/release/render-formula.sh" --version "$version" --sha256 "$sha256" --out "$tmp/rts.rb" >/dev/null
grep -qF "sha256 \"$sha256\"" "$tmp/rts.rb" || die "the rendered formula lacks this run's sha256"
want="$(base64 < "$tmp/rts.rb" | tr -d '\n')"

head_oid() {
  local oid
  oid="$(gh api "repos/$TAP/git/ref/heads/$BRANCH" --jq .object.sha)"
  [[ "$oid" =~ ^[0-9a-f]{40}$ ]] || die "unexpected head of $TAP $BRANCH: $oid"
  printf '%s' "$oid"
}

# The formula at that head, base64 without newlines; empty when absent.
current() {
  local out err
  if out="$(gh api "repos/$TAP/contents/$FILE?ref=$1" --jq .content 2>"$tmp/err")"; then
    printf '%s' "$out" | tr -d '\n'
  else
    err="$(cat "$tmp/err")"
    [[ "$err" == *"HTTP 404"* ]] || die "reading $FILE at $1: $err"
  fi
}

# One createCommitOnBranch against head $1. Prints the new oid; returns 2
# when the head moved.
commit() {
  jq -n --arg head "$1" --arg tap "$TAP" --arg branch "$BRANCH" --arg path "$FILE" --arg contents "$want" \
    --arg headline "rts $version" \
    --arg body "Release: https://github.com/nearai/nearai-red-sandbox/releases/tag/v$version

Tarball sha256 (rts-$version-aarch64-apple-darwin.tar.gz): $sha256

Committed by the nearai/nearai-red-sandbox release workflow, run $run_id." \
    '{query: "mutation($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $input) { commit { oid url } } }",
      variables: {input: {
        branch: {repositoryNameWithOwner: $tap, branchName: $branch},
        expectedHeadOid: $head,
        fileChanges: {additions: [{path: $path, contents: $contents}]},
        message: {headline: $headline, body: $body}}}}' > "$tmp/request.json"
  local out
  if out="$(gh api graphql --input "$tmp/request.json" 2>"$tmp/err")"; then
    printf '%s' "$out" | jq -er '.data.createCommitOnBranch.commit.oid'
    return 0
  fi
  if grep -q 'Expected branch to point to' "$tmp/err" <<<"$out$(cat "$tmp/err")"; then return 2; fi
  die "createCommitOnBranch failed: $out $(cat "$tmp/err")"
}

for attempt in 1 2; do
  head="$(head_oid)"
  if [[ "$(current "$head")" == "$want" ]]; then
    echo "the tap already carries rts $version with this sha256; nothing to commit."
    exit 0
  fi
  status=0
  oid="$(commit "$head")" || status=$?
  if [[ $status -eq 0 ]]; then break; fi
  [[ $status -eq 2 && $attempt -eq 1 ]] || die "$TAP $BRANCH moved again while committing; not retrying"
  echo "$TAP $BRANCH moved while committing; re-reading the head and retrying once" >&2
done

[[ "$oid" =~ ^[0-9a-f]{40}$ ]] || die "createCommitOnBranch returned no commit"
verified="$(gh api "repos/$TAP/commits/$oid" --jq .commit.verification.verified)"
[[ "$verified" == true ]] || die "commit $oid on $TAP is not verified by GitHub; check the tap app's installation"
echo "formula committed to $TAP $BRANCH: rts $version ($sha256), commit $oid, verified"

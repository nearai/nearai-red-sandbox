#!/bin/bash
# The release test gate. Runs the same locally and in CI.
#
#   check-tests.sh               run every check below; exit 0 only if all pass
#   check-tests.sh --parse LOG   judge a saved `cargo test --lib` log
#
# `cargo test --lib` may fail only with the five known copy::tests failures,
# allowed by exact name until they are fixed (a subset is fine). Every other
# check must pass in full: `cargo test --bin rts`, `bun test tests/unit`, and
# a shellcheck run over the release scripts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly ROOT
readonly ALLOWED=(
  copy::tests::a_long_name_is_refused
  copy::tests::a_symlink_to_a_host_path_is_refused
  copy::tests::a_hardlink_is_refused
  copy::tests::copy_out_is_byte_exact_across_slices
  copy::tests::an_oversized_file_is_refused
)

die() { printf 'check-tests: %s\n' "$*" >&2; exit 1; }

allowed() {
  local name=$1 a
  for a in "${ALLOWED[@]}"; do
    [[ "$name" == "$a" ]] && return 0
  done
  return 1
}

# Exit 0 only when LOG has a `test result:` line and every failed test in it
# is one of ALLOWED.
parse() {
  local log=$1 line have_result=0 unexpected=()
  [[ -f "$log" && -r "$log" ]] || die "log is not a readable file: $log"
  local re='^test ([^[:space:]]+) \.\.\. FAILED$'
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == "test result: "* ]]; then have_result=1; fi
    if [[ "$line" =~ $re ]] && ! allowed "${BASH_REMATCH[1]}"; then
      unexpected+=("${BASH_REMATCH[1]}")
    fi
  done < "$log"
  local status=0
  if [[ "$have_result" == 0 ]]; then
    printf 'check-tests: no test result line in %s (did the build fail?)\n' "$log" >&2
    status=1
  fi
  local name
  for name in ${unexpected[@]+"${unexpected[@]}"}; do
    printf 'check-tests: unexpected failure: %s\n' "$name" >&2
    status=1
  done
  return "$status"
}

full() {
  export RUSTFLAGS="-D warnings" CARGO_INCREMENTAL=0 CARGO_TERM_COLOR=never
  command -v shellcheck >/dev/null || die "shellcheck is not on PATH; install it (brew install shellcheck)"
  command -v bun >/dev/null || die "bun is not on PATH; install bun 1.3.3"
  cd "$ROOT"

  local log="${CHECK_TESTS_LOG:-$ROOT/target/check-tests-lib.log}"
  mkdir -p -- "$(dirname -- "$log")"
  printf '== cargo test --lib (log: %s)\n' "$log"
  # Allowed to exit non-zero: the five known failures fail it. parse decides.
  cargo test --lib > "$log" 2>&1 || true
  grep -E '^test .* \.\.\. FAILED$|^test result:' "$log" || true
  parse "$log" || die "cargo test --lib failed beyond the allowed copy::tests names; see $log"

  printf '== cargo test --bin rts\n'
  cargo test --bin rts
  printf '== bun test tests/unit\n'
  bun test tests/unit
  printf '== shellcheck\n'
  shellcheck install.sh scripts/*.sh scripts/release/*.sh
  printf 'check-tests: all release checks passed\n'
}

case "${1:-}" in
  --parse)
    [[ $# -eq 2 && -n "$2" ]] || die "usage: check-tests.sh --parse LOG"
    parse "$2"
    ;;
  "")
    full
    ;;
  -h|--help)
    sed -n '2,10p' "${BASH_SOURCE[0]}"
    ;;
  *)
    die "unknown argument: $1 (usage: check-tests.sh [--parse LOG])"
    ;;
esac

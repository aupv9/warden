#!/usr/bin/env bash
# Runs every Go fuzz target (func FuzzXxx in a _test.go file) for FUZZTIME
# each, one at a time: go test fuzzes one target per invocation. Stops at the
# first failure and says where the crashing input was written (the package's
# testdata/fuzz/FuzzXxx/, which then replays it as a regular test case).
# CI job `fuzz` runs it on every pull request; run longer locally, e.g.
# FUZZTIME=3m scripts/fuzz.sh.
#
# Usage: fuzz.sh [PACKAGE...]   (default ./... under backend/)
#   FUZZTIME          per target, a duration or Nx (default 30s)
#   FUZZMINIMIZETIME  per minimization (default 1000x): go's default of 60s
#                     per new input would eat a short run, and a crasher is
#                     written whether or not it is minimal
#   FUZZ_MATCH        only run targets whose name matches this regex
set -euo pipefail
FUZZTIME="${FUZZTIME:-30s}"
FUZZMINIMIZETIME="${FUZZMINIMIZETIME:-1000x}"
FUZZ_MATCH="${FUZZ_MATCH:-.}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/backend"
[ $# -gt 0 ] || set -- ./...

# `go test -list` prints a package's matching names, then its "ok" line.
targets=()
names=()
while read -r first second _; do
  case "$first" in
    Fuzz*) [[ "$first" =~ $FUZZ_MATCH ]] && names+=("$first") ;;
    ok)
      for n in ${names[@]+"${names[@]}"}; do targets+=("$second $n"); done
      names=()
      ;;
  esac
done < <(go test -list '^Fuzz' "$@")

[ ${#targets[@]} -gt 0 ] || { echo "no fuzz targets found" >&2; exit 1; }
echo "fuzzing ${#targets[@]} targets for ${FUZZTIME} each"

log="$(mktemp)"
trap 'rm -f "$log"' EXIT
for t in "${targets[@]}"; do
  pkg="${t% *}" name="${t#* }"
  echo "== $pkg $name"
  status=0
  go test "$pkg" -run '^$' -fuzz "^${name}\$" -fuzztime "$FUZZTIME" -fuzzminimizetime "$FUZZMINIMIZETIME" 2>&1 |
    tee "$log" | { grep -v '^fuzz: elapsed' || true; } || status=$?
  if [ "$status" -ne 0 ] || grep -q -e '^--- FAIL' -e '^FAIL' "$log"; then
    dir="$(go list -f '{{.Dir}}' "$pkg")"
    crasher="$(sed -n 's/.*Failing input written to \(testdata\/fuzz\/[^ ]*\).*/\1/p' "$log" | head -1)"
    echo >&2
    echo "FAIL: $pkg $name" >&2
    if [ -n "$crasher" ]; then
      echo "crasher: $dir/$crasher" >&2
      echo "replay:  go -C backend test $pkg -run '^${name}/$(basename "$crasher")\$'" >&2
    fi
    exit 1
  fi
done
echo "all fuzz targets passed"

#!/usr/bin/env bash
#
# mayhem/test.sh — RUN upstream's ThreadX regression suite (test/tx/regression), which
# mayhem/build.sh built with the project's normal flags into build-tests/bin. Each test binary
# prints a `Tests Passed: N Tests Failed: M System Errors: K` summary after the kernel services
# have been checked with asserted values; that summary is what is counted. A binary that exits
# early, crashes, hangs or prints no summary counts as a failure — exit status alone never passes.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

TB="$SRC/build-tests"
if [ ! -s "$TB/tests.list" ]; then
  echo "test.sh: $TB/tests.list is missing — mayhem/build.sh did not build the suite" >&2
  emit_ctrf "threadx-regression" 0 1 0
  exit 1
fi

results=$(mktemp -d)
trap 'rm -rf "$results"' EXIT

run_one() {
  local name="$1" out
  out=$(cd "$2" && timeout 120 "$2/bin/$name" 2>&1)
  # exactly one test passed, none failed, no system errors — as the binary itself reported it
  if printf '%s\n' "$out" | grep -q 'Tests Passed:  1   Tests Failed:  0    System Errors:   0$'; then
    : > "$3/$name.pass"
  else
    printf '%s\n' "$out" | tail -5 > "$3/$name.fail"
  fi
}
export -f run_one

xargs -P "$MAYHEM_JOBS" -I{} bash -c 'run_one "$@"' _ {} "$TB" "$results" < "$TB/tests.list"

passed=$(ls "$results" | grep -c '\.pass$')
total=$(wc -l < "$TB/tests.list")
failed=$(( total - passed ))
for f in "$results"/*.fail; do
  [ -e "$f" ] || continue
  echo "FAIL $(basename "$f" .fail):"; sed 's/^/    /' "$f"
done
emit_ctrf "threadx-regression" "$passed" "$failed" 0

#!/bin/sh
# Smoke test for the POSIX-shell port. Run: sh test.sh
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SH="$HERE/ossaudit.sh"
ROOT=$(CDPATH= cd -- "$HERE/../.." && pwd)
fail=0

# --version
v=$(sh "$SH" --version)
case "$v" in ossaudit*) : ;; *) echo "FAIL: version: $v"; fail=1 ;; esac

# audit a copyleft-contaminated manifest -> exit 2, RESULT: FAIL
set +e
out=$(sh "$SH" audit "$ROOT/demos/01-basic/deps.json" --policy proprietary)
rc=$?
set -e
[ "$rc" -eq 2 ] || { echo "FAIL: expected rc=2 on violations, got $rc"; fail=1; }
echo "$out" | grep -q "RESULT: FAIL" || { echo "FAIL: expected RESULT: FAIL"; fail=1; }
echo "$out" | grep -q "AGPL-3.0-only" || { echo "FAIL: AGPL not normalized/shown"; fail=1; }
echo "$out" | grep -q "Violations: 4" || { echo "FAIL: expected 4 violations"; fail=1; }

# audit an all-permissive manifest -> exit 0, RESULT: PASS
set +e
out2=$(sh "$SH" audit "$ROOT/demos/02-clean-license/licenses.json" --policy proprietary)
rc2=$?
set -e
[ "$rc2" -eq 0 ] || { echo "FAIL: expected rc=0 on clean, got $rc2"; fail=1; }
echo "$out2" | grep -q "RESULT: PASS" || { echo "FAIL: expected RESULT: PASS"; fail=1; }

if [ "$fail" -eq 0 ]; then
    echo "ok - shell port smoke tests passed"
else
    echo "shell port smoke tests FAILED"; exit 1
fi

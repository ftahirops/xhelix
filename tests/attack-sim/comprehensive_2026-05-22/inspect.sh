#!/bin/bash
# Quick-inspect harness: given a test ID, show its result + the
# raw alerts that landed in its window + the actual attack command.
# Usage: ./inspect.sh CRED-067
set -u
TID="${1:?usage: inspect.sh TEST-ID}"
DIR="$(dirname "$0")"

echo "=== Looking up $TID across all pass CSVs ==="
for csv in "$DIR"/mega-results-pass*.csv; do
    [ -f "$csv" ] || continue
    awk -F, -v t="$TID" -v src="$(basename $csv)" 'NR>1 && $1==t {print src": "$1" "$2" "$3" -> "$6" (matched="$7" noise="$8")"}' "$csv"
done

echo ""
echo "=== Debug log entries for $TID ==="
grep -A1 "^\[$TID\]" "$DIR"/mega-debug.log 2>/dev/null | head -20

echo ""
echo "=== Locked-pass status ==="
if awk -F, -v t="$TID" 'NR>1 && $1==t {found=1; exit} END {exit !found}' "$DIR/skip-pass4.csv" 2>/dev/null; then
    echo "  $TID is in the LOCKED PASS list (skipped in current pass)"
else
    echo "  $TID NOT locked — eligible for current/next pass"
fi

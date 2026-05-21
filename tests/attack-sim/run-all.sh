#!/bin/bash
# tests/attack-sim/run-all.sh
#
# Drives all three credential-theft simulations and then reports
# what xhelix caught. Designed to run as root on a host with xhelix
# already running.
#
# Usage:
#   sudo bash tests/attack-sim/run-all.sh
#
# Output:
#   - per-attack run log
#   - xhelix alert volume before/after
#   - xhelix soak ledger (per-rule fires)
#   - credbroker history (USG.1b)

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
XHELIXCTL=$(command -v xhelixctl || echo /usr/local/bin/xhelixctl)
ALERTS=/var/log/xhelix/alerts.jsonl

snap() {
    local label="$1"
    echo "================================================================"
    echo "=== $label"
    echo "================================================================"
    if [ -r "$ALERTS" ]; then
        echo "Alert lines in jsonl: $(wc -l < $ALERTS)"
    fi
    "$XHELIXCTL" status 2>&1 | grep -A3 "alert volume" | head -5
}

snap "BASELINE (before any attack)"

echo
echo "=== Running fake-vscode-extension (nx-console class) ==="
bash "$HERE/cred-steal-fake-vscode-ext.sh"
sleep 3

echo
echo "=== Running Megalodon-class payload ==="
bash "$HERE/cred-steal-megalodon-style.sh"
sleep 3

echo
echo "=== Running OFBiz-JIT-class (Python, no shell spawn) ==="
bash "$HERE/cred-steal-ofbiz-jit-style.sh"
sleep 5

snap "AFTER attacks (xhelix's response)"

echo
echo "=== Recent alerts (last 30 lines) ==="
if [ -r "$ALERTS" ]; then
    tail -n 30 "$ALERTS" | python3 -c "
import sys, json, collections
c = collections.Counter()
for line in sys.stdin:
    try:
        o = json.loads(line)
    except Exception:
        continue
    rule = o.get('rule_id', '?')
    cls = o.get('class', 0)
    c[(rule, cls)] += 1
print(f'{\"rule\":<40} {\"class\":<6} {\"count\":>6}')
for (rule, cls), n in c.most_common():
    print(f'{rule:<40} {cls:<6} {n:>6}')
"
fi

echo
echo "=== xhelixctl rules fp (per-class FP table) ==="
"$XHELIXCTL" rules fp 2>&1 | head -10

echo
echo "=== xhelixctl credbroker history (USG.1b) ==="
"$XHELIXCTL" credbroker history --limit=20 2>&1 | head -25

echo
echo "=== DONE. Inspect /var/log/xhelix/alerts.jsonl for full causal chains. ==="

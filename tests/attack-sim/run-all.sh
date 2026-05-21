#!/bin/bash
# tests/attack-sim/run-all.sh
#
# Drives the realistic credential-harvest attack simulation:
#   1. Seed ~50 fake real-format credentials at standard paths
#   2. Snapshot xhelix's baseline state
#   3. Run realistic-harvester.sh (daemonized, multi-stage, ~12
#      malware behaviour stages)
#   4. Wait for events to propagate
#   5. Report xhelix's response (alerts, soak, broker history)
#   6. Cleanup
#
# Usage:
#   sudo bash tests/attack-sim/run-all.sh
#
# Set CLEANUP=0 to skip the cleanup step (leave artifacts for
# manual inspection).

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
XHELIXCTL=$(command -v xhelixctl || echo /usr/local/bin/xhelixctl)
ALERTS=/var/log/xhelix/alerts.jsonl
CLEANUP="${CLEANUP:-1}"

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

echo "════════════════════════════════════════════════════════════════"
echo " xhelix attack-sim runner"
echo " marker: CANARYXHELIX"
echo " mode:   realistic credential harvester"
echo "════════════════════════════════════════════════════════════════"

snap "BASELINE (before seed)"

echo
echo "=== Step 1: seed fake credentials ==="
bash "$HERE/seed-fake-creds.sh"

snap "AFTER seed (no attack yet)"

echo
echo "=== Step 2: run realistic harvester ==="
# Run it explicitly; the script daemonizes itself via setsid so we
# wait for the detached PID below.
bash "$HERE/realistic-harvester.sh"
sleep 8  # let the daemonized stages run

snap "AFTER harvester (the real test)"

echo
echo "=== Recent xhelix alerts (last 80 lines, grouped) ==="
if [ -r "$ALERTS" ]; then
    tail -n 80 "$ALERTS" | python3 -c "
import sys, json, collections
c = collections.Counter()
samples = {}
for line in sys.stdin:
    try:
        o = json.loads(line)
    except Exception:
        continue
    rule = o.get('rule_id', '?')
    cls = o.get('class', 0)
    c[(rule, cls)] += 1
    if rule not in samples:
        ev = o.get('event', {})
        samples[rule] = {
            'sensor': ev.get('sensor'),
            'comm':   ev.get('comm'),
            'image':  ev.get('image'),
            'path':   ev.get('tags', {}).get('path', ''),
        }
print(f'{\"rule\":<32} {\"cls\":<3} {\"count\":>5}  sensor / comm / first-path')
for (rule, cls), n in c.most_common():
    s = samples.get(rule, {})
    snip = f\"{s.get('sensor','?')} / {s.get('comm','?')} / {s.get('path','')[:60]}\"
    print(f'{rule:<32} {cls:<3} {n:>5}  {snip}')
"
fi

echo
echo "=== xhelixctl rules fp (per-class FP table) ==="
"$XHELIXCTL" rules fp 2>&1 | head -10

echo
echo "=== xhelixctl rules soak (top by FIRES) ==="
"$XHELIXCTL" rules soak 2>&1 | head -15

echo
echo "=== xhelixctl credbroker history ==="
"$XHELIXCTL" credbroker history --limit=20 2>&1 | head -15

if [ "$CLEANUP" = "1" ]; then
    echo
    echo "=== Step 3: cleanup ==="
    bash "$HERE/cleanup-sim.sh"
else
    echo
    echo "(CLEANUP=0, leaving artifacts for inspection)"
fi

echo
echo "════════════════════════════════════════════════════════════════"
echo " DONE. Inspect /var/log/xhelix/alerts.jsonl for full causal chains."
echo " Search the alert file for 'CANARYXHELIX' to find marker hits."
echo "════════════════════════════════════════════════════════════════"

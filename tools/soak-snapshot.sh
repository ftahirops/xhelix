#!/usr/bin/env bash
# soak-snapshot.sh — record one point of the verdict-engine shadow soak.
#
# Appends a JSON line to $OUT capturing, since the last snapshot:
#   - total alert-log lines + delta (alerts emitted this interval)
#   - per-verdict-tier counts (critical/high/...) from verdict.incident tags
#   - top-5 emitting rule_ids this interval
#
# Designed to run hourly from cron on the dev box during the shadow soak,
# so "watch the real number over days" produces reviewable data instead of
# hoping someone eyeballs the log. Read-only on the alert log (never
# truncates/rotates it). State + output live under /var/lib/xhelix/soak/.
set -euo pipefail

LOG=${XHELIX_ALERT_LOG:-/var/log/xhelix/alerts.jsonl}
DIR=${XHELIX_SOAK_DIR:-/var/lib/xhelix/soak}
OUT="$DIR/metrics.jsonl"
STATE="$DIR/.last_line"

mkdir -p "$DIR"
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)

total=$(wc -l < "$LOG" 2>/dev/null || echo 0)
last=$(cat "$STATE" 2>/dev/null || echo 0)
# Guard against log rotation resetting the count below our cursor.
if [ "$total" -lt "$last" ]; then last=0; fi
delta=$((total - last))

# Tier + rule breakdown over just the new lines this interval.
breakdown=$(tail -n "$delta" "$LOG" 2>/dev/null | python3 -c '
import json,sys
from collections import Counter
tiers=Counter(); rules=Counter()
for line in sys.stdin:
    try: a=json.loads(line)
    except Exception: continue
    rid=a.get("rule_id","?"); rules[rid]+=1
    if rid=="verdict.incident":
        t=(a.get("event",{}).get("tags",{}) or {}).get("verdict_tier","?")
        tiers[t]+=1
top=dict(rules.most_common(5))
print(json.dumps({"tiers":dict(tiers),"top_rules":top}))
' 2>/dev/null || echo '{"tiers":{},"top_rules":{}}')

printf '{"at":"%s","total_lines":%s,"interval_alerts":%s,"breakdown":%s}\n' \
  "$now" "$total" "$delta" "$breakdown" >> "$OUT"

echo "$total" > "$STATE"
echo "soak: $now  interval_alerts=$delta  total=$total  -> $OUT"

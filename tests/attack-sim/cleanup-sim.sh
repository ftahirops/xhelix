#!/bin/bash
# tests/attack-sim/cleanup-sim.sh
#
# Removes everything seed-fake-creds.sh and realistic-harvester.sh
# leave on the host. Idempotent — safe to re-run.

set -u
MARKER="CANARYXHELIX"

log() { echo "[cleanup $(date +%H:%M:%S)] $*"; }
log "=== cleaning up attack-sim artifacts ==="

# Seeded credential files
rm -f \
    "$HOME/.aws/credentials" "$HOME/.aws/config" \
    "$HOME/.config/gcloud/application_default_credentials.json" \
    "$HOME/gcp-service-account.json" \
    "$HOME/.azure/azureProfile.json" "$HOME/.azure/accessTokens.json" "$HOME/.azure-sp.env" \
    "$HOME/.config/doctl/config.yaml" "$HOME/.linode-cli-token" \
    "$HOME/.hetzner-cloud-token" "$HOME/.vultr-api-token" \
    "$HOME/.cloudflare.cfg" \
    "$HOME/.kube/config" \
    "$HOME/.docker/config.json" \
    "$HOME/.anthropic" "$HOME/.openai" "$HOME/.ai-keys.env" \
    "$HOME/.config/gh/hosts.yml" "$HOME/.github-tokens" "$HOME/.gh-token" \
    "$HOME/.git-credentials" \
    "$HOME/.payment-keys.env" \
    "$HOME/.messaging-keys.env" \
    "$HOME/.email-keys.env" \
    "$HOME/.npmrc" "$HOME/.config/pip/pip.conf" "$HOME/.pypirc" \
    "$HOME/.gem/credentials" "$HOME/.cargo/credentials.toml" \
    "$HOME/.data-keys.env" \
    "$HOME/.db-conn-strings.env" \
    "$HOME/.config/op/config" \
    "$HOME/.config/Bitwarden CLI/data.json" \
    "$HOME/.age-key" \
    "$HOME/.app-secrets.env" \
    2>/dev/null
log "removed seeded credential files"

# SSH keys we generated
for f in \
    id_ed25519 id_ed25519.pub id_ed25519_canary id_ed25519_canary.pub \
    id_rsa id_rsa.pub id_rsa_canary id_rsa_canary.pub \
    id_rsa_2048 id_rsa_2048.pub \
    id_ecdsa id_ecdsa.pub id_ecdsa_521 id_ecdsa_521.pub \
    config \
    ; do
    rm -f "$HOME/.ssh/$f"
done
# authorized_keys: remove only our bait line
if [ -f "$HOME/.ssh/authorized_keys" ]; then
    sed -i "/${MARKER}/d" "$HOME/.ssh/authorized_keys" 2>/dev/null
    [ ! -s "$HOME/.ssh/authorized_keys" ] && rm -f "$HOME/.ssh/authorized_keys"
fi
log "removed seeded SSH keys + bait authorized_keys line"

# History files (restore empty so they don't keep leaking patterns)
for hist in "$HOME/.bash_history" "$HOME/.zsh_history"; do
    if [ -f "$hist" ] && grep -q "$MARKER" "$hist" 2>/dev/null; then
        sed -i "/$MARKER/d" "$hist"
        log "scrubbed $hist"
    fi
done

# Persistence drops
crontab -l 2>/dev/null | grep -v "$MARKER" | crontab - 2>/dev/null || crontab -r 2>/dev/null
[ -f /etc/cron.d/kitty-monitor-update ] && rm -f /etc/cron.d/kitty-monitor-update
[ -f /etc/profile.d/01-kitty-monitor.sh ] && rm -f /etc/profile.d/01-kitty-monitor.sh
[ -f /etc/ld.so.preload.canary ] && rm -f /etc/ld.so.preload.canary
# Strip bait line from .bashrc
if [ -f "$HOME/.bashrc" ]; then
    sed -i "/${MARKER}/d" "$HOME/.bashrc" 2>/dev/null
fi
log "removed persistence drops (cron, profile.d, ld.so, bashrc bait)"

# Tenant .env files (if root)
if [ "$EUID" -eq 0 ]; then
    rm -rf /var/www/tenant-a /var/www/tenant-b /var/www/tenant-c
    rm -rf /var/www/test-app
    rm -rf /etc/ssl/private-canary
fi
log "removed tenant + TLS canaries (root only)"

# /tmp scratch files
rm -f /tmp/.kitty-monitor* /tmp/.megalodon-test-* /tmp/.xh-sim-log /tmp/.hidden-* 2>/dev/null

log "=== cleanup complete. ==="

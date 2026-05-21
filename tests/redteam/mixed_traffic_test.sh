#!/usr/bin/env bash
# mixed_traffic_test.sh — concurrent legitimate workload + RCE chain.
#
# The single most important real-world test for an EDR: can xhelix
# distinguish ONE attacker lineage from N concurrent legitimate
# lineages? This script:
#
#   1. Spawns ~10 legitimate background jobs (node server, python
#      crypto, perl batch, go env, apt simulate, sudo calls, file
#      ops, network probes) — each in its own lineage.
#   2. Runs a single ATTACK lineage in the foreground, deliberately
#      crossing multiple detection primitives (memfd exec, base64
#      stage, FIM write, ptrace, /dev/tcp).
#   3. Marks the window in xhelix.out for replay.
#   4. After the window, groups alerts by lineage_id and reports:
#        - alerts per lineage
#        - attack lineage rank by takeover score
#        - false-positive rate on legitimate lineages
#
# Run: sudo bash tests/redteam/mixed_traffic_test.sh
# Output: /tmp/xhe-mixed-results-<ts>.txt + log lines tagged
#         ===MIXED_BEGIN=== / ===MIXED_END=== in xhelix.out.
#
# DESIGN NOTE: ptrace ATTACH on the parent shell SIGSTOPS it. We
# avoid that by running ptrace from a forked child whose only
# target is itself. memfd exec runs in a subshell to keep its
# lineage isolated.

set -u

DURATION="${DURATION:-30}"   # seconds of overlapping load
RESULTS="/tmp/xhe-mixed-results-$(date -u +%Y%m%dT%H%M%SZ).txt"
RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; CYA=$'\033[36m'; NC=$'\033[0m'

require_root() { [[ $EUID -eq 0 ]] || { echo "must run as root: sudo bash $0"; exit 1; }; }
require_root

MARK() { echo "===$1_$(date -u +%FT%TZ)===" >> /var/log/xhelix/xhelix.out; }

step() { printf "${CYA}[*]${NC} %s\n" "$*"; }
ok()   { printf "${GRN}[+]${NC} %s\n" "$*"; }
warn() { printf "${YEL}[!]${NC} %s\n" "$*"; }

# Ensure single xhelix daemon
count=$(pgrep -f '/usr/local/bin/xhelix run' | wc -l)
if (( count > 1 )); then
    warn "found $count xhelix daemons; killing extras"
    pgrep -f '/usr/local/bin/xhelix run' | tail -n +2 | xargs -r kill -TERM
    sleep 2
fi

# ────────────────────────────────────────────────────────────────
# Background LEGIT workload — each a separate lineage
# ────────────────────────────────────────────────────────────────
PIDS=()

# L-1: node http server doing internal pings
( node -e "
const http = require('http');
const s = http.createServer((req,res)=>{res.end('ok')});
s.listen(0,()=>{const p=s.address().port;
  for(let i=0;i<500;i++)setTimeout(()=>http.get('http://127.0.0.1:'+p+'/',r=>r.resume()), i*30);
  setTimeout(()=>s.close(),${DURATION}000);
});" &> /tmp/legit-node.log ) & PIDS+=($!)

# L-2: python crypto/hash loop
( python3 -c "
import hashlib, time, os
t = time.time() + ${DURATION}
while time.time() < t:
    hashlib.sha256(os.urandom(4096)).hexdigest()
" &> /tmp/legit-py.log ) & PIDS+=($!)

# L-3: perl batch
( perl -e "
my \$t = time() + ${DURATION};
while (time() < \$t) {
    my @x = map { rand() * \$_ } 1..1000;
    my \$s = 0; \$s += \$_ for @x;
}
" &> /tmp/legit-perl.log ) & PIDS+=($!)

# L-4: file system reader
( for i in $(seq 1 100); do
    find /etc -name '*.conf' 2>/dev/null | head -20 > /dev/null
    sleep 0.2
  done ) & PIDS+=($!)

# L-5: package mgmt simulate
( for i in $(seq 1 5); do
    apt list --installed 2>/dev/null | tail -50 > /dev/null
    dpkg -l | head -100 > /dev/null
    sleep 1
  done ) & PIDS+=($!)

# L-6: system queries
( for i in $(seq 1 10); do
    systemctl list-units --state=running 2>/dev/null | head -20 > /dev/null
    ss -tnp > /dev/null 2>&1
    journalctl -n 5 > /dev/null 2>&1
    sleep 1
  done ) & PIDS+=($!)

# L-7: sudo invocations (legit admin)
( for i in $(seq 1 5); do
    sudo -n true 2>/dev/null
    sleep 2
  done ) & PIDS+=($!)

# L-8: git operations
( cd /home/rctop/xhelix && for i in $(seq 1 10); do
    git status > /dev/null
    git log --oneline -5 > /dev/null
    sleep 0.5
  done ) & PIDS+=($!)

# L-9: go env
( for i in $(seq 1 5); do
    go env > /dev/null 2>&1
    sleep 1
  done ) & PIDS+=($!)

# L-10: legitimate base64 (NOT piped to sh)
( for i in $(seq 1 20); do
    echo "legit data $i" | base64 > /dev/null
    sleep 0.3
  done ) & PIDS+=($!)

ok "spawned ${#PIDS[@]} legitimate background lineages"
sleep 2

# ────────────────────────────────────────────────────────────────
# ATTACK chain — ONE clear lineage (single bash, all chained)
# ────────────────────────────────────────────────────────────────
MARK "MIXED_BEGIN"
step "starting attack chain in foreground (single lineage)"

ATTACK_LOG="/tmp/xhe-attack-chain.log"
(
    # Mark our pid so we can identify the lineage post-hoc
    echo "ATTACKER_LINEAGE_PID=$$" > /tmp/xhe-attacker-pid.txt
    echo "attack chain start: pid=$$" >> "$ATTACK_LOG"

    # A1: base64 stage piped to sh (cooccur encoded+exec)
    echo "ZWNobyBzdGFnZTEgY29tcGxldGUK" | base64 -d | sh >> "$ATTACK_LOG" 2>&1

    # A2: memfd exec (fileless pattern)
    python3 -c "
import os
fd = os.memfd_create('a2_stage', 0)
os.write(fd, b'#!/bin/sh\necho A2 memfd ran\n')
os.execv(f'/proc/self/fd/{fd}', ['stage'])
" >> "$ATTACK_LOG" 2>&1

    # A3: reverse-shell pattern (loopback, no listener — pattern still fires rule)
    timeout 2 bash -c 'exec 5<>/dev/tcp/127.0.0.1/12345; echo A3 >&5' >> "$ATTACK_LOG" 2>&1 || true

    # A4: SUID-class artifact drop in /tmp
    cp /bin/echo /tmp/.attack_suid 2>/dev/null
    chmod 4755 /tmp/.attack_suid 2>/dev/null
    rm -f /tmp/.attack_suid

    # A5: FIM-watched persistence write
    bash -c 'echo "*/5 * * * * root /usr/bin/id > /tmp/.attack_beacon" > /etc/cron.d/xhe-attack-test' 2>/dev/null
    sleep 1
    rm -f /etc/cron.d/xhe-attack-test 2>/dev/null

    # A6: ld.so.preload modify
    bash -c 'echo "/tmp/evil_attack.so" > /etc/ld.so.preload.attacker' 2>/dev/null
    rm -f /etc/ld.so.preload.attacker 2>/dev/null

    # A7: ptrace self-attach + detach (won't SIGSTOP shell since we attach to self)
    python3 -c "
import os, ctypes
libc = ctypes.CDLL('libc.so.6')
pid = os.fork()
if pid == 0:
    # child: become traceable to its own children? Simplest: ptrace TRACEME so parent ptraces
    libc.ptrace(0, 0, 0, 0)
    import time; time.sleep(0.1)
    os._exit(0)
else:
    os.waitpid(pid, 0)
" >> "$ATTACK_LOG" 2>&1

    # A8: process_vm_readv against unrelated PID
    python3 -c "
import os, ctypes
class iovec(ctypes.Structure):
    _fields_=[('base',ctypes.c_void_p),('len',ctypes.c_size_t)]
libc = ctypes.CDLL('libc.so.6')
buf = ctypes.create_string_buffer(64)
local = iovec(ctypes.addressof(buf), 64)
remote = iovec(0x400000, 64)
# Read from PID 1 (init) — known target
libc.process_vm_readv(1, ctypes.byref(local),1, ctypes.byref(remote),1, 0)
" >> "$ATTACK_LOG" 2>&1

    # A9: SSRF-style outbound to AWS metadata (loopback, won't reach)
    timeout 2 curl -s http://169.254.169.254/latest/meta-data/ -o /dev/null 2>/dev/null || true

    # A10: known-bad-ish outbound (Spamhaus DROP test range, won't connect)
    timeout 2 curl -s --max-time 1 http://192.0.2.1/ -o /dev/null 2>/dev/null || true

    echo "attack chain done: pid=$$" >> "$ATTACK_LOG"
) &
ATK_PID=$!
echo "attack-lineage-root-pid=$ATK_PID" > /tmp/xhe-attacker-pid.txt
wait $ATK_PID

sleep 5
MARK "MIXED_END"

ok "attack chain complete; waiting for legit jobs to finish"
wait "${PIDS[@]}" 2>/dev/null

# ────────────────────────────────────────────────────────────────
# ANALYSIS
# ────────────────────────────────────────────────────────────────
exec > "$RESULTS" 2>&1
echo "================================================================"
echo "xhelix Mixed-Traffic Test Results"
echo "================================================================"
echo "Run time:        $(date -u +%FT%TZ)"
echo "Window duration: ${DURATION}s legit overlap"
echo "Attack root pid: $ATK_PID"
echo "Legit pids:      ${PIDS[*]}"
echo
echo "Methodology: ${#PIDS[@]} concurrent legitimate lineages running"
echo "node/python/perl/go/apt/snap/sudo/git/file-io workloads, ONE"
echo "attack lineage (rooted at pid $ATK_PID) chaining base64+memfd+"
echo "reverse-shell+SUID+FIM+ld.preload+ptrace+vm_readv+SSRF."
echo

echo "================================================================"
echo "RULE FIRE DISTRIBUTION (alerts.jsonl, last 2000 entries)"
echo "================================================================"
tail -2000 /var/log/xhelix/alerts.jsonl > /tmp/mixed.jsonl
echo "Total alerts considered: $(wc -l < /tmp/mixed.jsonl)"
echo
echo "rule_id  ─ fires:"
grep -oE '"rule_id":"[a-z0-9_.]+' /tmp/mixed.jsonl | sort | uniq -c | sort -rn | head -25
echo

echo "================================================================"
echo "PER-LINEAGE / PER-PID GROUPING (Python analysis)"
echo "================================================================"
python3 <<PYEOF
import json, time, os

ATK_PID = int(open('/tmp/xhe-attacker-pid.txt').read().split('=')[1])

# Heuristic: alerts within the time window AROUND the attack window.
# Wide net: take alerts whose pid is in (ATK_PID +/- 200) or whose parent_pid is.
# Better: walk proctree, but for now use a simple PID-proximity heuristic.
# We'll group by (pid, comm, image).

attack_lineage_pids = set([ATK_PID])
legit_alerts = []
attack_alerts = []
unknown = []

events = []
for line in open('/tmp/mixed.jsonl'):
    try:
        events.append(json.loads(line))
    except: pass

# Pass 1: identify attack-lineage pids by parent_pid chain
# (alerts.jsonl carries parent_pid)
changed = True
while changed:
    changed = False
    for a in events:
        e = a.get('event', {})
        pid = e.get('pid', 0)
        ppid = e.get('parent_pid', 0)
        if ppid in attack_lineage_pids and pid not in attack_lineage_pids:
            attack_lineage_pids.add(pid)
            changed = True

print(f"Attack-lineage PIDs identified: {len(attack_lineage_pids)}")
print(f"  root: {ATK_PID}")
print(f"  descendants: {sorted(attack_lineage_pids - {ATK_PID})[:20]}")
print()

# Pass 2: sort alerts
for a in events:
    e = a.get('event', {})
    pid = e.get('pid', 0)
    rule = a.get('rule_id', '?')
    sev = e.get('severity', 0)
    comm = e.get('comm', '?')
    image = e.get('image', '?')
    if pid in attack_lineage_pids:
        attack_alerts.append((rule, pid, comm, image))
    else:
        legit_alerts.append((rule, pid, comm, image))

print(f"Attack-lineage alerts: {len(attack_alerts)}")
print(f"Legit/other alerts: {len(legit_alerts)}")
print()

# Distribution per group
from collections import Counter
print("ATTACK-LINEAGE rule distribution:")
c = Counter(r for r,_,_,_ in attack_alerts)
for r, n in c.most_common(20):
    print(f"  {n:5d} {r}")
print()
print("LEGIT/OTHER rule distribution (top 15):")
c = Counter(r for r,_,_,_ in legit_alerts)
for r, n in c.most_common(15):
    print(f"  {n:5d} {r}")
print()

# Per-comm in legit (FP suspects)
print("LEGIT comms producing alerts (top 15):")
c = Counter(comm for _,_,comm,_ in legit_alerts)
for comm, n in c.most_common(15):
    print(f"  {n:5d} {comm}")
print()

# Detection-recall on attack chain
expected_attack_rules = {
    'memfd_run_pattern': 'A2 memfd exec',
    'shell_with_socket_fd': 'A3 reverse shell',
    'binary_runs_from_tmp': 'A2/A3/A6',
    'cron_new_unit': 'A5 cron drop',
    'ld_so_preload_modified': 'A6 ld.so.preload',
    'ptrace_sensitive_target': 'A7 ptrace',
    'metadata_svc_unexpected': 'A9 SSRF',
}
hits_on_attack = {r: 0 for r in expected_attack_rules}
for r,_,_,_ in attack_alerts:
    if r in hits_on_attack:
        hits_on_attack[r] += 1
print("ATTACK CHAIN RECALL (expected rules):")
caught = 0
for r, desc in expected_attack_rules.items():
    n = hits_on_attack[r]
    mark = "✓" if n > 0 else "✗"
    print(f"  [{mark}] {r:32s}  {n:3d} fires  ({desc})")
    if n > 0: caught += 1
print(f"  Recall: {caught}/{len(expected_attack_rules)} = {100*caught//len(expected_attack_rules)}%")
print()

# Precision (% of alerts that landed on attack lineage)
total = len(attack_alerts) + len(legit_alerts)
if total > 0:
    precision = 100 * len(attack_alerts) / total
    print(f"Lineage precision (attack-alerts / all-alerts): {precision:.1f}%")
    print(f"  attack:{len(attack_alerts)} legit:{len(legit_alerts)}")
PYEOF

echo
echo "================================================================"
echo "RESPONSE ACTIONS (must be 0 — monitor mode)"
echo "================================================================"
grep -aE "response: (quarantined|killed|banned|remediated|locked)" /var/log/xhelix/xhelix.out | tail -5
echo "(empty above = monitor mode held)"

echo
echo "================================================================"
echo "TAKEOVER PLANNER SHADOW (per lineage)"
echo "================================================================"
sudo awk '/===MIXED_BEGIN/{p=1} /===MIXED_END/{p=0} p' /var/log/xhelix/xhelix.out 2>/dev/null \
    | grep "planner shadow" | tail -20

echo
echo "================================================================"
echo "RESULTS SAVED TO: $RESULTS"
echo "================================================================"

cat "$RESULTS"

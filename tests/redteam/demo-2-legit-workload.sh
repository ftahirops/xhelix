#!/usr/bin/env bash
# demo-2-legit-workload.sh — runs ~10 concurrent legitimate workloads
# for the configured duration. Use as background-noise during demos
# to show xhelix doesn't false-alarm on normal activity.
#
# Run: bash tests/redteam/demo-2-legit-workload.sh [duration-seconds]
# Default duration: 60s

set -uo pipefail

DURATION="${1:-60}"
CYAN=$'\033[36m'; GREEN=$'\033[32m'; NC=$'\033[0m'

step() { printf "${CYAN}[*]${NC} %s\n" "$*"; }
ok()   { printf "${GREEN}[+]${NC} %s\n" "$*"; }

step "spawning legitimate workloads for ${DURATION}s..."
PIDS=()

# L-1: node http server with internal pings
if command -v node >/dev/null; then
    ( node -e "
const http=require('http');
const s=http.createServer((q,r)=>r.end('ok'));
s.listen(0,()=>{const p=s.address().port;
  for(let i=0;i<200;i++)setTimeout(()=>http.get('http://127.0.0.1:'+p+'/',r=>r.resume()),i*100);
  setTimeout(()=>s.close(),${DURATION}000);
});
" &> /tmp/legit-node.log ) & PIDS+=($!)
fi

# L-2: python crypto loop
( python3 -c "
import hashlib, os, time
t=time.time()+${DURATION}
while time.time()<t: hashlib.sha256(os.urandom(4096)).hexdigest()
" &> /tmp/legit-py.log ) & PIDS+=($!)

# L-3: perl arithmetic batch
( perl -e "
my \$t=time()+${DURATION};
while(time()<\$t){my\$s=0;\$s+=\$_*rand() for 1..1000;}
" &> /tmp/legit-perl.log ) & PIDS+=($!)

# L-4: filesystem reader
( for i in $(seq 1 ${DURATION}); do
    find /etc -name '*.conf' 2>/dev/null | head -20 > /dev/null
    sleep 1
  done ) & PIDS+=($!)

# L-5: package mgmt
( for i in $(seq 1 5); do
    apt list --installed 2>/dev/null | tail -50 > /dev/null
    dpkg -l | head -100 > /dev/null
    sleep $((DURATION / 5))
  done ) & PIDS+=($!)

# L-6: system queries
( for i in $(seq 1 $((DURATION / 2))); do
    systemctl list-units --state=running 2>/dev/null | head -20 > /dev/null
    ss -tnp > /dev/null 2>&1
    journalctl -n 5 > /dev/null 2>&1
    sleep 2
  done ) & PIDS+=($!)

# L-7: sudo (legit admin operations)
( for i in $(seq 1 5); do
    sudo -n true 2>/dev/null
    sleep $((DURATION / 5))
  done ) & PIDS+=($!)

# L-8: git operations
if [ -d /home/rctop/xhelix/.git ]; then
    ( cd /home/rctop/xhelix && for i in $(seq 1 $((DURATION / 3))); do
        git status > /dev/null
        git log --oneline -5 > /dev/null
        sleep 3
      done ) & PIDS+=($!)
fi

# L-9: go env
if command -v go >/dev/null; then
    ( for i in $(seq 1 5); do go env > /dev/null 2>&1; sleep $((DURATION / 5)); done ) & PIDS+=($!)
fi

# L-10: legitimate base64 (NOT piped to sh)
( for i in $(seq 1 $((DURATION * 3))); do
    echo "legit data $i" | base64 > /dev/null
    sleep 0.3
  done ) & PIDS+=($!)

ok "spawned ${#PIDS[@]} legitimate workloads, pids: ${PIDS[*]}"
ok "running for ${DURATION}s — switch terminal to run demo-1 in parallel"

wait "${PIDS[@]}" 2>/dev/null
ok "all workloads complete"

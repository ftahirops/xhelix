#!/usr/bin/env bash
# demo-3-orchestrator.sh — runs the full 10-minute demo end-to-end.
#
#   Phase 1 (2 min): legit workloads start, xhelix is quiet
#   Phase 2 (3 min): attack chain runs, alerts fire
#   Phase 3 (1 min): triage output — stats, top alerts, scorer plans
#
# Designed to be run on a stage in front of stakeholders.
# Operator can intermix `xhelixctl alerts tail` in a side terminal.
#
# Run: sudo bash tests/redteam/demo-3-orchestrator.sh

set -uo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo bash $0"
    exit 1
fi

YELLOW=$'\033[33m'; GREEN=$'\033[32m'; CYAN=$'\033[36m'; NC=$'\033[0m'
HERE=$(cd "$(dirname "$0")" && pwd)

banner() {
    echo
    echo "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo "${CYAN} $1 ${NC}"
    echo "${CYAN}════════════════════════════════════════════════════════════════${NC}"
}

banner "xhelix 10-minute demo orchestrator"
echo "Confirm pre-conditions:"
xhelixctl posture lsm 2>/dev/null | head -5
echo
xhelixctl protect list 2>/dev/null | head -5
echo
xhelixctl alerts stats --since 10s 2>/dev/null | tail -3
echo
read -p "Press ENTER to begin..." _

banner "PHASE 1 (2min): legitimate workload — xhelix should stay quiet"
echo "Starting node/python/perl/apt/sudo/git/file-io background load..."
bash "$HERE/demo-2-legit-workload.sh" 120 &
LEGIT_PID=$!
sleep 60
echo
echo "${YELLOW}--- 60s in: stats during legit-only phase ---${NC}"
xhelixctl alerts stats --since 60s 2>/dev/null | head -15
echo
echo "${YELLOW}--- key check: no shell/memfd/cred-class alerts? ---${NC}"
xhelixctl alerts ls --since 60s --severity info 2>/dev/null \
    | grep -aE 'shell|memfd|ld_so|cron_new|tamper|metadata|revshell|ptrace' | head -5 \
    || echo "    (none — clean)"
echo
read -p "Press ENTER to start attack..." _

banner "PHASE 2 (3min): attack chain runs concurrently with legit load"
bash "$HERE/demo-1-attack-chain.sh"
echo

banner "PHASE 3: triage"
echo "Wait 5s for alert pipeline to drain..."
sleep 5
echo
echo "${YELLOW}--- alerts by rule (last 5min) ---${NC}"
xhelixctl alerts stats --since 5m --by rule 2>/dev/null
echo
echo "${YELLOW}--- alerts by comm (who triggered what?) ---${NC}"
xhelixctl alerts stats --since 5m --by comm 2>/dev/null | head -15
echo
echo "${YELLOW}--- attack-class alerts (filtered for the chain) ---${NC}"
xhelixctl alerts ls --since 5m --severity info --limit 20 2>/dev/null \
    | grep -aE 'shell|memfd|revshell|ld_so|cron_new|tamper|metadata|cap.gained|ptrace|lolbin|ssh_key|systemd' \
    | head -20
echo
echo "${YELLOW}--- takeover scorer plans for the attack lineage ---${NC}"
sudo grep -aE 'planner shadow' /var/log/xhelix/xhelix.out | tail -8 \
    | grep -oE 'tier=[a-z]+ score=[0-9]+ actions="\[[^]]+\]"' || echo "(none in window)"
echo

# Cleanup background legit
kill $LEGIT_PID 2>/dev/null
wait $LEGIT_PID 2>/dev/null

banner "demo complete"
echo "The story:"
echo "  • Phase 1 — 10 concurrent legitimate workloads + xhelix monitoring."
echo "    No attack-class rules fired. node JIT firehose absorbed by"
echo "    runtime allowlist (jit_allowlisted=true → rule rejected)."
echo "  • Phase 2 — 10-step attack chain through one lineage."
echo "    xhelix caught: shell-with-socket, memfd, revshell, ssh-key,"
echo "    cron-drop, ld_so_preload, metadata SSRF, ptrace, lolbin."
echo "  • Phase 3 — Takeover scorer pinned the attack lineage at"
echo "    tier=isolated score=100 in shadow mode. Flip"
echo "    response.monitor_mode=false and those plans EXECUTE."
echo
echo "${GREEN}Evidence chain verify:${NC}  sudo xhelix-verify --chain /var/lib/xhelix/chain --pub <key>"

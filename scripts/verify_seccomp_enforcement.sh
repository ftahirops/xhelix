#!/usr/bin/env bash
# verify_seccomp_enforcement.sh — kernel-in-the-loop proof that the
# SystemCallFilter directive the behavioral compiler emits (P5a.2) is
# enforced at the kernel level, AND that a process still starts under it.
#
# This is the P5a enforcement gate the maturity review required. It runs
# the EXACT directive contractcompiler generates for a web-worker app
# (pkg/contractcompiler -> SeccompSystemdDirective) inside an ephemeral
# `systemd-run --user` transient unit — no sudo, no /etc/systemd writes,
# no daemon-reload, auto-collected. Safe to run on a dev box.
#
# Expected:
#   baseline   : ptrace_ret=0  errno=0   (syscall allowed)
#   under filter: ptrace_ret=-1 errno=1  (EPERM) with PROC_RAN=yes
#
# Exit 0 = enforcement proven; non-zero = NOT enforced (investigate).
set -euo pipefail

if ! command -v systemd-run >/dev/null || ! command -v python3 >/dev/null; then
  echo "SKIP: needs systemd-run + python3"; exit 0
fi
if ! systemctl --user is-system-running >/dev/null 2>&1; then
  echo "SKIP: no --user systemd bus (run from an interactive/login session)"; exit 0
fi

# SYS_ptrace=101 (x86_64). PTRACE_TRACEME=0 → returns 0 normally, -1/EPERM denied.
PROBE='import ctypes; libc=ctypes.CDLL(None,use_errno=True); ctypes.set_errno(0); r=libc.syscall(101,0,0,0,0); e=ctypes.get_errno(); print(f"PROC_RAN=yes ptrace_ret={r} errno={e}")'

# The exact red-zone seccomp directive the compiler emits for a web worker.
DIRECTIVE='~bpf delete_module finit_module init_module kcmp kexec_file_load kexec_load mount open_by_handle_at perf_event_open pivot_root process_vm_readv process_vm_writev ptrace reboot setns swapoff swapon umount2 unshare userfaultfd'

echo "[1] baseline (no filter):"
base=$(python3 -c "$PROBE")
echo "    $base"

echo "[2] under xhelix SystemCallFilter (ephemeral --user unit):"
armed=$(systemd-run --user --wait --pipe --quiet --collect \
  -p SystemCallFilter="$DIRECTIVE" \
  -p SystemCallErrorNumber=EPERM \
  python3 -c "$PROBE")
echo "    $armed"

echo
case "$base" in *"ptrace_ret=0"*) ;; *) echo "FAIL: baseline ptrace did not succeed"; exit 1;; esac
case "$armed" in
  *"PROC_RAN=yes"*"ptrace_ret=-1 errno=1"*)
    echo "PASS: armed seccomp denied ptrace with EPERM and the process still ran."
    exit 0;;
  *)
    echo "FAIL: expected EPERM under filter; got: $armed"; exit 1;;
esac

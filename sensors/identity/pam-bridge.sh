#!/bin/sh
# xhelix PAM bridge producer.
#
# Invoked by pam_exec from /etc/pam.d/<service> (e.g. cron). Emits ONE
# newline-delimited JSON line to the xhelix PAM listener socket so the
# SourceMinter (pkg/source) can mint a non-admin lineage root (cron, etc.).
# The Go listener (sensors/identity/pam_bridge.go) is a Unix STREAM socket.
#
# FAIL-OPEN BY CONSTRUCTION: this script always exits 0 and never writes to
# stdout/stderr in a way pam_exec would treat as failure. Combined with the
# `optional` control in pam.d, a producer failure can NEVER block auth.
#
# Usage in pam.d (session stack):
#   session    optional   pam_exec.so quiet /usr/local/sbin/xhelix-pam-bridge.sh session_open
#
# $1 = pam_type to report (default session_open). PAM_SERVICE/PAM_USER/
# PAM_RHOST/PAM_TTY are supplied by pam_exec in the environment.
set -u

SOCK="/run/xhelix/pam.sock"
TYPE="${1:-session_open}"

[ -S "$SOCK" ] || exit 0

# $PPID = the process that loaded PAM (e.g. the cron child that will exec the
# job). Reporting it lets xhelix attribute the lineage root onto that process
# so the job's descendants inherit it (→ learnable workflows).
LINE=$(printf '{"type":"%s","service":"%s","user":"%s","rhost":"%s","tty":"%s","pid":%s}\n' \
  "$TYPE" "${PAM_SERVICE:-}" "${PAM_USER:-}" "${PAM_RHOST:-}" "${PAM_TTY:-}" "${PPID:-0}")

if command -v socat >/dev/null 2>&1; then
  printf '%s' "$LINE" | timeout 2 socat -t1 - UNIX-CONNECT:"$SOCK" >/dev/null 2>&1
elif command -v python3 >/dev/null 2>&1; then
  printf '%s' "$LINE" | timeout 2 python3 -c 'import socket,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(1)
try:
    s.connect(sys.argv[1]); s.sendall(sys.stdin.buffer.read()); s.close()
except Exception:
    pass' "$SOCK" >/dev/null 2>&1
fi

exit 0

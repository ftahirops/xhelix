"""
CAT 2 — Userspace rootkit techniques.

Subcategories:
  LDPRE    — LD_PRELOAD library hooks (readdir/getdents to hide files)
  COMM     — prctl(PR_SET_NAME) masquerading
  ARGV0    — argv[0] rewriting to impersonate system processes
  SETNS    — setns into other namespaces
  CHROOT   — chroot escape patterns
  PROCHIDE — /proc hiding tricks (proc_hidepid bypass)
"""


def gen():
    tests = []
    i = 0

    # ============ LDPRE — LD_PRELOAD hooking ============
    # Real rootkits ship a .so that hooks readdir/getdents/lstat to hide
    # files. We can't ship the actual .so on prod, but we can:
    # 1. Test the FILE-DROP: writing /etc/ld.so.preload (FIM should fire)
    # 2. Test the IN-PROC injection: LD_PRELOAD env var on a command
    legit_preloads = [
        "/lib/x86_64-linux-gnu/libdl.so.2",     # real lib, benign use
        "/usr/lib/x86_64-linux-gnu/libcap.so.2",
    ]
    for variant in range(15):
        i += 1
        # Write /etc/ld.so.preload (canonical persistent rootkit install)
        tests.append({
            "id": f"RKIT-LDPRE-{i:04d}",
            "category": "RKIT",
            "subcategory": "ld_so_preload_write",
            "malicious": True,
            "desc": f"/etc/ld.so.preload rootkit install v{variant}",
            "cmd": (
                f"[ -f /etc/ld.so.preload ] && cp /etc/ld.so.preload /tmp/.lp{variant}; "
                f"echo '/tmp/evil-rkit-{variant}.so' > /etc/ld.so.preload; "
                f"sleep 2; "
                f"if [ -f /tmp/.lp{variant} ]; then mv /tmp/.lp{variant} /etc/ld.so.preload; "
                f"else rm -f /etc/ld.so.preload; fi"
            ),
            "expect_rule": r"ld_so_preload_modified",
            "detector": "fim",
            "window": 15,
        })

    # LD_PRELOAD env-var injection on command exec
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"RKIT-LDPRE-{i:04d}",
            "category": "RKIT",
            "subcategory": "ld_preload_env",
            "malicious": True,
            "desc": f"LD_PRELOAD env injection v{variant}",
            "cmd": (
                f"LD_PRELOAD={legit_preloads[variant % len(legit_preloads)]} "
                f"/bin/true 2>/dev/null; true"
            ),
            "expect_rule": r"suspicious_interpreter_network|ld_preload",
            "detector": "rules.proc",
            "window": 6,
        })

    # ============ COMM — prctl PR_SET_NAME masquerading ============
    legit_comms = [
        "sshd", "systemd", "init", "kthreadd", "kworker/0:0", "systemd-network",
        "dbus-daemon", "rsyslogd", "cron", "auditd", "agetty", "login",
        "python3", "bash", "sh", "nginx", "apache2", "php-fpm",
        "mariadbd", "redis-server", "mysqld", "[kthread]",
    ]
    for legit_comm in legit_comms:
        for variant in range(2):
            i += 1
            tests.append({
                "id": f"RKIT-COMM-{i:04d}",
                "category": "RKIT",
                "subcategory": "prctl_set_name",
                "malicious": True,
                "desc": f"prctl(PR_SET_NAME, \"{legit_comm}\") v{variant}",
                "cmd": (
                    f"cp /bin/true /tmp/.fake-{legit_comm.replace('[','').replace(']','').replace('/','_')[:10]}-{variant}; "
                    f"python3 -c \""
                    f"import ctypes, os; "
                    f"libc=ctypes.CDLL('libc.so.6'); "
                    f"libc.prctl(15, b'{legit_comm}'.ljust(16, b'\\x00'), 0, 0, 0); "
                    f"import time; time.sleep(0.5)\" 2>/dev/null; "
                    f"rm -f /tmp/.fake-*; true"
                ),
                "expect_rule": r"web_server_spawns|hidden_process|baseline_known",
                "detector": "ebpf.proc",
                "window": 6,
            })

    # ============ ARGV0 — argv[0] rewriting ============
    for variant in range(20):
        i += 1
        fake_argv0 = ["/usr/sbin/sshd", "[kworker/u8:1]", "/usr/lib/systemd/systemd",
                      "/usr/bin/dbus-daemon", "/usr/sbin/cron"][variant % 5]
        tests.append({
            "id": f"RKIT-ARGV0-{i:04d}",
            "category": "RKIT",
            "subcategory": "argv0_rewrite",
            "malicious": True,
            "desc": f"argv[0]={fake_argv0} v{variant}",
            "cmd": (
                f"exec -a {fake_argv0!r} /bin/sh -c 'sleep 0.3' 2>/dev/null; true"
            ),
            "expect_rule": r"web_server_spawns|hidden_process",
            "detector": "ebpf.proc",
            "window": 6,
        })

    # ============ SETNS — namespace switching ============
    # Note: requires CAP_SYS_ADMIN and target proc to exist.
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"RKIT-SETNS-{i:04d}",
            "category": "RKIT",
            "subcategory": "setns",
            "malicious": True,
            "desc": f"setns into pid 1 namespaces v{variant}",
            "cmd": (
                f"nsenter -t 1 -m -u -i -n -p sh -c 'id' 2>/dev/null; true"
            ),
            "expect_rule": r"unshare|container_escape|setns",
            "detector": "ebpf.ns",
            "window": 8,
        })

    # ============ CHROOT — escape patterns ============
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"RKIT-CHROOT-{i:04d}",
            "category": "RKIT",
            "subcategory": "chroot_escape",
            "malicious": True,
            "desc": f"chroot+chdir escape pattern v{variant}",
            "cmd": (
                f"mkdir -p /tmp/jail-{variant}; "
                f"(unshare -r chroot /tmp/jail-{variant} /bin/sh -c 'cd ..; cd ..; cd ..; ls /' 2>/dev/null); "
                f"rmdir /tmp/jail-{variant} 2>/dev/null; true"
            ),
            "expect_rule": r"chroot|container_escape|pivot_root",
            "detector": "ebpf.ns",
            "window": 6,
        })

    # ============ PROCHIDE — /proc visibility tricks ============
    for variant in range(8):
        i += 1
        tests.append({
            "id": f"RKIT-PROCHIDE-{i:04d}",
            "category": "RKIT",
            "subcategory": "proc_hiding",
            "malicious": True,
            "desc": f"hidden-process readdir bypass v{variant}",
            "cmd": (
                f"sleep 30 & VPID=$!; "
                f"ls /proc/$VPID/status >/dev/null 2>&1; "
                f"# attempt direct stat to detect hidden process patterns "
                f"stat /proc/$VPID >/dev/null 2>&1; "
                f"kill $VPID; wait $VPID 2>/dev/null; true"
            ),
            "expect_rule": r"hidden_process|cred_proc_scrape",
            "detector": "procscrape",
            "window": 6,
        })

    # ============ BENIGN CONTROLS ============
    # B1: legitimate apt update which DOES use LD_PRELOAD internally
    for variant in range(5):
        i += 1
        tests.append({
            "id": f"RKIT-B-{i:04d}",
            "category": "RKIT",
            "subcategory": "benign_apt_update",
            "malicious": False,
            "desc": f"benign: apt-list (no LD_PRELOAD evil) v{variant}",
            "cmd": "apt list --installed > /dev/null 2>&1; true",
            "expect_rule": r"(?!.*)",
            "detector": "control",
            "window": 5,
        })

    # B2: legitimate gdb-batch on a daemon
    for variant in range(5):
        i += 1
        tests.append({
            "id": f"RKIT-B-{i:04d}",
            "category": "RKIT",
            "subcategory": "benign_admin_inspect",
            "malicious": False,
            "desc": f"benign: ps aux | grep + stat /proc v{variant}",
            "cmd": "ps aux | grep -v grep | head -5 > /dev/null; for p in $(pgrep -d' ' nginx | tr ' ' '\\n' | head -3); do stat /proc/$p >/dev/null 2>&1; done; true",
            "expect_rule": r"(?!.*)",
            "detector": "control",
            "window": 5,
        })

    # B3: legitimate exec-a usage (some scripts use it)
    for variant in range(5):
        i += 1
        tests.append({
            "id": f"RKIT-B-{i:04d}",
            "category": "RKIT",
            "subcategory": "benign_exec_a",
            "malicious": False,
            "desc": f"benign: exec -a with legitimate name v{variant}",
            "cmd": "bash -c 'exec -a myapp /bin/echo hi' > /dev/null 2>&1; true",
            "expect_rule": r"(?!.*)",
            "detector": "control",
            "window": 5,
        })

    return tests


if __name__ == "__main__":
    t = gen()
    print(f"CAT 2 RKIT: {len(t)} tests")
    from collections import Counter
    by_sub = Counter(x["subcategory"] for x in t)
    for sub, n in by_sub.most_common():
        print(f"  {sub:<22} {n}")
    mal = sum(1 for x in t if x["malicious"])
    ben = sum(1 for x in t if not x["malicious"])
    print(f"  malicious: {mal}, benign: {ben}")

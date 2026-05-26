"""
CAT 1 — Process injection / hollowing.

Subcategories:
  PVW    — process_vm_writev shellcode injection
  PT     — ptrace POKETEXT / SETREGS code injection
  DLOPEN — dlopen from memfd (reflective .so loader)
  TJACK  — thread RIP rewrite via ptrace
  HOLLOW — process hollowing (replace memory)

Every malicious test has a paired benign (-B) variant that does
the same syscall pattern WITHOUT the malicious payload, to measure
detector false-positive rate per technique.
"""
import shlex


def gen():
    tests = []
    i = 0

    # ============ PVW (process_vm_writev) — write into another process ============
    # Note: PTRACE_ATTACH+PTRACE_POKETEXT is one path; process_vm_writev
    # is the modern one that doesn't require ptrace stop.
    #
    # Malicious pattern: spawn a victim sleep, then python writes
    # 32 bytes of "shellcode" (real benign payload) into victim's
    # heap via process_vm_writev.
    pvw_targets = [
        ("sleep_60",  "sleep 60"),
        ("nc_l",      "nc -lk -p 0 -q1 -w 60 >/dev/null"),
        ("python_idle", "python3 -c 'import time; time.sleep(60)'"),
        ("dd_zero",   "dd if=/dev/zero of=/dev/null bs=1 count=60"),
        ("yes_high",  "yes >/dev/null"),
    ]
    pvw_sizes = [16, 64, 256, 1024]

    for target_name, target_cmd in pvw_targets:
        for size in pvw_sizes:
            for variant in range(2):  # 2 timing variants
                i += 1
                # Malicious — write shellcode-ish bytes
                attack = (
                    f"({target_cmd}) & VPID=$!; sleep 0.3; "
                    f"python3 -c '"
                    f"import ctypes, os, struct; "
                    f"libc=ctypes.CDLL(\"libc.so.6\"); "
                    f"buf=ctypes.create_string_buffer(b\"\\x90\"*{size}); "
                    f"lvec=(ctypes.c_void_p*1)(ctypes.cast(buf, ctypes.c_void_p).value); "
                    f"llen=(ctypes.c_size_t*1)({size}); "
                    f"rvec=(ctypes.c_void_p*1)(0x600000); "
                    f"rlen=(ctypes.c_size_t*1)({size}); "
                    f"libc.process_vm_writev($VPID, lvec, 1, rvec, 1, 0)' 2>/dev/null; "
                    f"kill $VPID 2>/dev/null; wait $VPID 2>/dev/null; true"
                )
                tests.append({
                    "id": f"INJ-PVW-{i:04d}",
                    "category": "INJ",
                    "subcategory": "process_vm_writev",
                    "malicious": True,
                    "desc": f"process_vm_writev into {target_name} ({size}B, v{variant})",
                    "cmd": attack,
                    "expect_rule": r"any_ptrace|ptrace_sensitive|process_vm",
                    "detector": "ebpf.proc",
                    "window": 8,
                })

    # ============ PT (ptrace POKETEXT) ============
    pt_methods = [
        ("ptrace_attach_detach", "ptrace(PTRACE_ATTACH, $VPID, 0, 0); ptrace(PTRACE_DETACH, $VPID, 0, 0)"),
        ("ptrace_seize",         "ptrace(PTRACE_SEIZE, $VPID, 0, 0)"),
        ("ptrace_getregs",       "ptrace(PTRACE_ATTACH, $VPID, 0, 0); ptrace(PTRACE_GETREGS, $VPID, 0, ctypes.c_void_p()); ptrace(PTRACE_DETACH, $VPID, 0, 0)"),
        ("ptrace_singlestep",    "ptrace(PTRACE_ATTACH, $VPID, 0, 0); ptrace(PTRACE_SINGLESTEP, $VPID, 0, 0); ptrace(PTRACE_DETACH, $VPID, 0, 0)"),
        ("ptrace_cont",          "ptrace(PTRACE_ATTACH, $VPID, 0, 0); ptrace(PTRACE_CONT, $VPID, 0, 0); ptrace(PTRACE_DETACH, $VPID, 0, 0)"),
    ]
    for method_name, method_calls in pt_methods:
        for variant in range(5):
            i += 1
            tests.append({
                "id": f"INJ-PT-{i:04d}",
                "category": "INJ",
                "subcategory": "ptrace",
                "malicious": True,
                "desc": f"ptrace {method_name} v{variant}",
                "cmd": (
                    f"(sleep 30) & VPID=$!; sleep 0.3; "
                    f"python3 -c \""
                    f"import ctypes; libc=ctypes.CDLL('libc.so.6'); "
                    f"PTRACE_ATTACH,PTRACE_DETACH,PTRACE_GETREGS,PTRACE_SEIZE,PTRACE_SINGLESTEP,PTRACE_CONT=16,17,12,16902,9,7; "
                    f"def ptrace(r,p,a,d): return libc.ptrace(r,p,a,d); "
                    f"{method_calls}\" 2>/dev/null; "
                    f"kill $VPID 2>/dev/null; wait $VPID 2>/dev/null; true"
                ),
                "expect_rule": r"any_ptrace|ptrace_sensitive",
                "detector": "ebpf.proc",
                "window": 8,
            })

    # ============ DLOPEN — reflective .so loader from memfd ============
    # Write a minimal .so to memfd, then dlopen("/proc/self/fd/N").
    # Real malware: payload .so does evil_init() in constructor.
    # Here: load a benign system lib via memfd to exercise the path.
    for variant in range(20):
        i += 1
        tests.append({
            "id": f"INJ-DLOPEN-{i:04d}",
            "category": "INJ",
            "subcategory": "dlopen_memfd",
            "malicious": True,
            "desc": f"dlopen from memfd v{variant}",
            "cmd": (
                f"python3 -c '"
                f"import os, ctypes; "
                f"libc=ctypes.CDLL(\"libc.so.6\"); "
                f"fd=libc.memfd_create(b\"x{variant}\", 0); "
                f"with open(\"/lib/x86_64-linux-gnu/libm.so.6\", \"rb\") as f: "
                f"    os.write(fd, f.read()); "
                f"libdl=ctypes.CDLL(\"libdl.so.2\"); "
                f"libdl.dlopen.restype=ctypes.c_void_p; "
                f"h=libdl.dlopen(f\"/proc/self/fd/{{fd}}\".encode(), 2); "
                f"print(hex(h or 0))' 2>/dev/null; true"
            ),
            "expect_rule": r"memfd|from_memfd|memfd_run_pattern",
            "detector": "ebpf.proc",
            "window": 8,
        })

    # ============ TJACK — thread rip rewrite via ptrace ============
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"INJ-TJACK-{i:04d}",
            "category": "INJ",
            "subcategory": "threadjack",
            "malicious": True,
            "desc": f"threadjack via ptrace setregs v{variant}",
            "cmd": (
                f"(sleep 30) & VPID=$!; sleep 0.3; "
                f"python3 -c \""
                f"import ctypes; libc=ctypes.CDLL('libc.so.6'); "
                f"class R(ctypes.Structure): _fields_=[('x'+str(i), ctypes.c_ulong) for i in range(27)]; "
                f"r=R(); libc.ptrace(16, $VPID, 0, 0); libc.ptrace(12, $VPID, 0, ctypes.byref(r)); "
                f"libc.ptrace(13, $VPID, 0, ctypes.byref(r)); libc.ptrace(17, $VPID, 0, 0)\" 2>/dev/null; "
                f"kill $VPID 2>/dev/null; wait $VPID 2>/dev/null; true"
            ),
            "expect_rule": r"any_ptrace|ptrace_sensitive",
            "detector": "ebpf.proc",
            "window": 8,
        })

    # ============ HOLLOW — process hollowing pattern ============
    # Linux-style: fork+ptrace+munmap+mmap+execve replacement.
    for variant in range(8):
        i += 1
        tests.append({
            "id": f"INJ-HOLLOW-{i:04d}",
            "category": "INJ",
            "subcategory": "hollowing",
            "malicious": True,
            "desc": f"process hollowing pattern v{variant}",
            "cmd": (
                f"python3 -c '"
                f"import os, ctypes; "
                f"libc=ctypes.CDLL(\"libc.so.6\"); "
                f"pid=os.fork(); "
                f"if pid==0: "
                f"    libc.ptrace(0, 0, 0, 0); "
                f"    os.execvp(\"/bin/true\", [\"/bin/true\"]) "
                f"else: "
                f"    os.waitpid(pid, 0)' 2>/dev/null; true"
            ),
            "expect_rule": r"any_ptrace|memfd|web_server_spawns",
            "detector": "ebpf.proc",
            "window": 8,
        })

    # ============ BENIGN CONTROLS ============
    # For each subcategory above, run an equivalent BENIGN syscall pattern
    # that should NOT trigger attack-class alerts.

    # B1: simply spawn a sleep (no injection)
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"INJ-B-{i:04d}",
            "category": "INJ",
            "subcategory": "benign_spawn",
            "malicious": False,
            "desc": f"benign: spawn sleep + kill (no injection) v{variant}",
            "cmd": "(sleep 30) & VPID=$!; sleep 0.5; kill $VPID; wait $VPID 2>/dev/null; true",
            "expect_rule": r"(?!.*)",  # match nothing
            "detector": "control",
            "window": 5,
        })

    # B2: legitimate dlopen of system lib (no memfd)
    for variant in range(10):
        i += 1
        tests.append({
            "id": f"INJ-B-{i:04d}",
            "category": "INJ",
            "subcategory": "benign_dlopen",
            "malicious": False,
            "desc": f"benign: dlopen libm.so directly v{variant}",
            "cmd": (
                f"python3 -c '"
                f"import ctypes; "
                f"libdl=ctypes.CDLL(\"libdl.so.2\"); "
                f"libdl.dlopen(b\"libm.so.6\", 2); "
                f"print(\"ok\")' 2>/dev/null; true"
            ),
            "expect_rule": r"(?!.*)",
            "detector": "control",
            "window": 5,
        })

    # B3: legitimate gdb-batch on own process (operator debugging pattern)
    # NOTE: gdb is debug tooling — operators do use it. Track if xhelix
    # over-alerts on operator usage.
    for variant in range(5):
        i += 1
        tests.append({
            "id": f"INJ-B-{i:04d}",
            "category": "INJ",
            "subcategory": "benign_gdb_self",
            "malicious": False,
            "desc": f"benign: gdb script on own child v{variant}",
            "cmd": (
                "(sleep 30) & VPID=$!; sleep 0.5; "
                "gdb -p $VPID -batch -ex 'info threads' -ex 'detach' -ex 'quit' "
                "2>/dev/null; kill $VPID 2>/dev/null; wait $VPID 2>/dev/null; true"
            ),
            "expect_rule": r"(?!.*)",
            "detector": "control",
            "window": 5,
        })

    return tests


if __name__ == "__main__":
    t = gen()
    print(f"CAT 1 INJ: {len(t)} tests")
    from collections import Counter
    by_sub = Counter(x["subcategory"] for x in t)
    for sub, n in by_sub.most_common():
        print(f"  {sub:<22} {n}")
    mal = sum(1 for x in t if x["malicious"])
    ben = sum(1 for x in t if not x["malicious"])
    print(f"  malicious: {mal}, benign: {ben}")

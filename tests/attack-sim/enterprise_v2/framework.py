"""
Enterprise EDR test framework — runner + isolation + result tracking.

Each test is a dict:
{
    "id":           "INJ-PVW-0001",          # unique id
    "category":     "INJ",                    # top-level group
    "subcategory":  "process_vm_writev",      # variant family
    "malicious":    True,                     # attack vs benign control
    "desc":         "human description",
    "cmd":          "shell command",          # run via SSH on prod
    "expect_rule":  "any_ptrace|...",         # regex over rule_id
    "detector":     "ebpf.proc",              # which detector
    "window":       8,                        # seconds to wait after attack
    "setup":        None,                     # optional pre-test setup (memoized)
    "teardown":     None,                     # optional cleanup
}

Output CSV columns:
  id, category, subcategory, malicious, desc, detector, expect_rule,
  status (PASS|FAIL|NO-RULE|ERROR), matched, noise, total, duration,
  started_at
"""
import csv, json, os, re, subprocess, sys, time, signal
from datetime import datetime, timezone
from collections import defaultdict, Counter

HOST = os.environ.get("HOST", "65.108.246.67")
C2_IP = os.environ.get("C2_IP", "135.181.79.27")
ALERTS = "/var/log/xhelix/alerts.jsonl"

_SSH_CTRL = f"/tmp/.entv2_ssh_ctrl_{os.getpid()}"
_seen_setups = set()


def ssh(cmd, timeout=30):
    """Run command on prod via SSH; return (rc, stdout, stderr)."""
    try:
        p = subprocess.run(
            ["ssh",
             "-o", "ConnectTimeout=10", "-o", "BatchMode=yes",
             "-o", "ServerAliveInterval=15",
             "-o", "ControlMaster=auto", "-o", f"ControlPath={_SSH_CTRL}",
             "-o", "ControlPersist=600",
             HOST, cmd],
            capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"


def alerts_offset():
    rc, out, _ = ssh(f"stat -c %s {ALERTS} 2>/dev/null || echo 0")
    try:
        return int(out.strip())
    except (ValueError, AttributeError):
        return 0


def run_test(test, results_csv, debug_fh):
    """Run one test, append result row to results_csv, debug to debug_fh."""
    tid = test["id"]
    cat = test["category"]
    subcat = test.get("subcategory", "-")
    malicious = test.get("malicious", True)
    desc = test["desc"]
    detector = test["detector"]
    expect = test["expect_rule"]
    win = test.get("window", 8)

    # Run setup if not yet seen.
    setup_cmd = test.get("setup")
    if setup_cmd and setup_cmd not in _seen_setups:
        ssh(setup_cmd, timeout=30)
        _seen_setups.add(setup_cmd)

    started_at = datetime.now(timezone.utc).isoformat()
    t0 = time.time()

    # Combined: capture offset, run attack, sleep, tail new alerts.
    combined = (
        f"OFF=$(stat -c %s {ALERTS} 2>/dev/null || echo 0); "
        f"{test['cmd']} > /dev/null 2>&1; "
        f"sleep {min(win, 90)}; "
        f"tail -c +$((OFF+1)) {ALERTS} 2>/dev/null"
    )
    status_pre = "OK"
    rc, out, err = ssh(combined, timeout=win + 30)
    if rc == -1:
        status_pre = "TIMEOUT"
        out = ""
        # Try to kill any lingering ControlMaster
        try:
            subprocess.run(
                ["ssh", "-O", "exit", "-o", f"ControlPath={_SSH_CTRL}", HOST],
                capture_output=True, timeout=5)
        except Exception:
            pass

    # Parse alerts
    alerts = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
            ev = d.get("event", {})
            alerts.append((d.get("rule_id", "(none)"),
                          ev.get("comm", ""),
                          ev.get("image", "")))
        except Exception:
            pass

    pat = re.compile(expect)
    matched = sum(1 for r, _, _ in alerts if pat.search(r))
    total = len(alerts)
    noise = total - matched

    # Determine status
    if status_pre == "TIMEOUT":
        status = "ERROR"
    elif malicious:
        # Malicious test — PASS if expected rule fired
        if matched > 0:
            status = "PASS"
        else:
            # Check if test is for a known NO-RULE detector
            no_rule_markers = ["raw_socket", "dns_exfil", "dga",
                              "integrity_unknown", "first_seen_image"]
            if any(m in expect for m in no_rule_markers):
                status = "NO-RULE"
            else:
                status = "FAIL"
    else:
        # Benign test — PASS if NO attack-class alert fired during this test
        # (low-FP) — i.e., expected_rule explicitly matches NOTHING
        attack_class_pat = re.compile(
            r"credbroker|cred_proc_scrape|mem_mprotect|memfd|"
            r"kernel_module|bpf_syscall|any_ptrace|shell_with_socket|"
            r"tls_no_sni|honey|cron_new_unit|ssh_key_added|ld_so_preload|"
            r"binary_runs_from_tmp|suid_binary|web_server_spawns|"
            r"unknown_binary|integrity"
        )
        # Exclude well-known background noise
        bg_pat = re.compile(r"^(cred_proc_scrape|deleted_binary_running|"
                           r"fim\.drift|cap\.gained)$")
        attack_fired = [r for r, _, _ in alerts
                       if attack_class_pat.search(r) and not bg_pat.match(r)]
        if not attack_fired:
            status = "PASS"  # benign passed (no FP)
            matched = 0
        else:
            status = "FAIL"  # FP detected
            matched = len(attack_fired)
            # For benign, "noise" is the count of attack-class FPs

    duration = time.time() - t0

    # Debug log
    debug_fh.write(f"[{tid}] {desc} -> {status} matched={matched} noise={noise} alerts={Counter(a[0] for a in alerts).most_common(5)}\n")
    debug_fh.flush()

    # Run teardown if any
    teardown = test.get("teardown")
    if teardown:
        ssh(teardown, timeout=15)

    # Append CSV
    with open(results_csv, "a", newline="") as f:
        w = csv.writer(f)
        w.writerow([tid, cat, subcat, "1" if malicious else "0", desc,
                   detector, expect, status, matched, noise, total,
                   f"{duration:.2f}", started_at])

    return status, matched, noise, duration


def init_csv(path):
    """Initialize the results CSV with the header."""
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "category", "subcategory", "malicious", "desc",
                   "detector", "expect_rule", "status", "matched", "noise",
                   "total", "duration", "started_at"])


def run_battery(tests, results_csv, debug_log, skip_ids=None, progress_cb=None):
    """Run a list of tests. skip_ids: set of test IDs to skip (already passed)."""
    skip_ids = skip_ids or set()

    # Filter
    to_run = [t for t in tests if t["id"] not in skip_ids]
    print(f"=" * 70)
    print(f"Battery start: {datetime.now().isoformat()}")
    print(f"Total tests:    {len(tests)}")
    print(f"Skipped (prev): {len(tests) - len(to_run)}")
    print(f"To run:         {len(to_run)}")
    print(f"=" * 70)

    # Write CSV header if not exists
    if not os.path.exists(results_csv):
        init_csv(results_csv)

    debug_fh = open(debug_log, "a")
    debug_fh.write(f"\n=== BATTERY START {datetime.now().isoformat()} ===\n")

    counts = Counter()
    started = time.time()

    for idx, test in enumerate(to_run):
        status, matched, noise, duration = run_test(test, results_csv, debug_fh)
        counts[status] += 1
        elapsed = time.time() - started
        eta = ((len(to_run) - idx - 1) * elapsed / (idx + 1)) / 60 if idx > 0 else 0
        rate = (idx + 1) * 60 / elapsed if elapsed > 0 else 0
        color = {"PASS": "\033[32m", "FAIL": "\033[31m",
                 "NO-RULE": "\033[33m", "ERROR": "\033[35m"}.get(status, "")
        print(f"[{idx+1:>4}/{len(to_run):<4}] {test['id']:<18} {test['category']:<8} "
              f"{color}{status:<8}\033[0m m={matched:<2} n={noise:<2} "
              f"d={duration:.0f}s | total: P={counts['PASS']} F={counts['FAIL']} "
              f"NR={counts['NO-RULE']} E={counts['ERROR']} rate={rate:.1f}/m ETA={eta:.0f}m",
              flush=True)
        if progress_cb:
            progress_cb(idx + 1, len(to_run), counts)

    debug_fh.write(f"=== BATTERY END {datetime.now().isoformat()} ===\n")
    debug_fh.close()

    print(f"\n{'=' * 70}\nBattery complete: {datetime.now().isoformat()}")
    for status, n in counts.most_common():
        pct = 100 * n // max(len(to_run), 1)
        print(f"  {status:<10} {n:>4} ({pct}%)")

    return counts


def load_passed_ids(csv_paths):
    """Return set of test IDs that have PASSed in any of the given CSVs."""
    ids = set()
    for path in csv_paths:
        if not os.path.exists(path):
            continue
        with open(path) as f:
            r = csv.DictReader(f)
            for row in r:
                if row.get("status") == "PASS":
                    ids.add(row["id"])
    return ids

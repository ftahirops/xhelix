# xhelix — Mixed-Traffic Test Results (Phase 2.4)

**Date**: 2026-05-21
**Host**: 135.181.79.27 (this box)
**Test**: `tests/redteam/mixed_traffic_test.sh` — 10 concurrent
legitimate lineages running alongside ONE attack lineage chained
through 10 detection primitives.
**Goal**: measure detection rate + lineage precision under realistic
mixed traffic.
**Result**: **test infrastructure surfaced critical platform bugs
that block clean measurement.** Detection-rate numbers will be
unreliable until they are fixed.

---

## 1. What we ran

10 background legitimate lineages (each its own PID tree):

| ID | Workload |
|----|---|
| L-1 | node http server doing 500 internal pings |
| L-2 | python sha256 loop over urandom |
| L-3 | perl arithmetic batch |
| L-4 | `find /etc -name *.conf` repeated |
| L-5 | `apt list --installed` + `dpkg -l` x5 |
| L-6 | systemctl + ss + journalctl polling |
| L-7 | `sudo -n true` x5 |
| L-8 | git log/status x10 |
| L-9 | go env x5 |
| L-10 | base64 of legit data (NOT piped to sh) |

ONE attack lineage (single rooted PID tree, 10 chained primitives):

| Step | Action | Expected rule |
|------|---|---|
| A1 | `echo ... \| base64 -d \| sh` | cooccur: encoded+exec |
| A2 | python `memfd_create + execv` | `memfd_run_pattern` |
| A3 | `bash exec 5<>/dev/tcp/127.0.0.1/12345` | `shell_with_socket_fd` |
| A4 | SUID copy of `/bin/echo` to `/tmp/.attack_suid` | `binary_runs_from_tmp` / suid baseline |
| A5 | drop `/etc/cron.d/xhe-attack-test` | `cron_new_unit` + FIM |
| A6 | write `/etc/ld.so.preload.attacker` | `ld_so_preload_modified` |
| A7 | `ptrace TRACEME` child | `ptrace_sensitive_target` |
| A8 | `process_vm_readv` against PID 1 | NeverLearnable signal |
| A9 | curl 169.254.169.254 | `metadata_svc_unexpected` |
| A10 | curl 192.0.2.1 (Spamhaus DROP-class) | `outbound_to_known_bad` |

---

## 2. What actually happened

### 2.1 xhelix did fire — but to the wrong stream

Total alert-line count across xhelix's lifetime on this host: **22,894**
(`grep -c '^\[[0-9:]+\] (notice|critical|warn|info|high)'`).

These all landed in `/var/log/xhelix/xhelix.out` (the daemon's
stderr/stdout). **None landed in `/var/log/xhelix/alerts.jsonl`**:

```
$ lsof on each xhelix daemon:
  daemon 392983: NO fd → alerts.jsonl
  daemon 424513: NO fd → alerts.jsonl
  daemon 464750: NO fd → alerts.jsonl
$ ls -la /var/log/xhelix/alerts.jsonl
  -rw-r-----  1 root root  68954047  May 21 09:26  alerts.jsonl
                                     ^^^^^^^^^^
                                     mtime frozen at 09:26, current time 11:51+
```

**`alerts.jsonl` has not been written since 09:26 UTC** (~2.5 hours).
The operator's primary triage file is dead. Alerts continue to fire
to stderr (via xhelix.out tail) but never reach the JSONL sink.

**Root cause hypothesis**: the YAML written by `scripts/test-setup.sh`
omits an `alerts.sinks[]` block, so the daemon falls back to default
behavior — which apparently is "stdout only" rather than "stdout +
file". The legacy config (`xhelix.yaml.bak`) had an explicit file sink.

This is **GAP-140** (new).

### 2.2 Three xhelix daemons running concurrently — GAP-130

```
$ pgrep -af xhelix
  392983  ./xhelix run --config /etc/xhelix/xhelix.yaml
  424513  ./xhelix run --config /etc/xhelix/xhelix.yaml
  464750  ./xhelix run --config /etc/xhelix/xhelix.yaml
```

`scripts/test-setup.sh` does not enforce a singleton. Each re-run
spawned a new daemon without killing the old. By the end of the
session we had 3 daemons racing on `hot.db` (the SQLITE_BUSY log
storm confirmed this).

Worse: `pkill -f '/usr/local/bin/xhelix run'` doesn't match daemons
whose path is `./xhelix run` (relative). The kill commands in the
test scripts silently failed to find their targets.

### 2.3 Mixed-traffic markers were lost

The `MARK` function in `mixed_traffic_test.sh` appended
`===MIXED_BEGIN_<ts>===` to `xhelix.out`. Post-test grep finds
**no occurrence** — they were either overwritten by concurrent
writers (3 daemons + redirect), or `xhelix.out` was rotated mid-test.

### 2.4 Measurement-script bug

The mixed-test analyzer read `tail -2000 alerts.jsonl`. Because
alerts.jsonl is frozen at 09:26, that pulls 2000 *stale* alerts from
hours ago — completely unrelated to the test window. The "0 attack
alerts, 2000 legit alerts" reading is bogus; it just reflects the
old file.

---

## 3. What we *can* say from the data

Despite the platform mess, three things are visible:

### 3.1 Rule distribution across xhelix's lifetime on this host

From the *stale* alerts.jsonl (representative of 09:00–09:26 attack
burst earlier in the session):

```
1028  fim.drift              (NEW — baseline-shift firehose)
 448  ungated
 403  mem_mprotect_rwx       (mostly node JIT FPs)
  47  memfd_run_pattern      (mostly Claude memfd-launched shells)
  45  bpf_syscall_unexpected (mostly runc → docker — out of scope this phase)
  14  cap.gained             (every sudo)
   9  shell_with_socket_fd   (attacker reverse-shell from Phase 1)
   6  contescape.detected    (runc — out of scope this phase)
```

### 3.2 `fim.drift` was firing 1028 times — new finding

Not previously seen in Phase 1. The FIM sensor is producing baseline-
drift alerts at high volume. Each event has `comm=?` (unattributed),
so triage is hard. **GAP-141 (new)**: investigate.

### 3.3 xhelix.out tail at 11:51 confirmed live activity

```
[11:51:50] notice    cap.gained gained capabilities: ... pid=464785 comm=sudo
```

Daemon is alive, eBPF is loaded, rules are firing — but the
measurement plumbing is broken.

---

## 4. What we CANNOT say yet

The questions the user asked — and the honest answer to each:

| Question | Honest answer right now |
|---|---|
| Detection rate on the attack chain? | unknown — the alert→file path is broken |
| Was every chain perfectly distinguished from legit? | unknown — without lineage_id in a reliable sink, we can't compute per-lineage isolation |
| Did the takeover scorer score the attack higher than legit? | unknown — scorer output goes to xhelix.out "planner shadow" lines, which DO appear; but linking them to a specific attack lineage requires the alerts to carry the same lineage_id consistently |
| FP rate on this host's mixed workload? | unknown — same reason |
| Six-nine accuracy progress? | 0% — we can't even measure phase α reliably right now |

This is the test infrastructure exposing the gap between "xhelix
fires alerts" (works) and "xhelix's measurement plumbing is
production-grade" (does not yet work).

---

## 5. Fix-list to unblock measurement

Priority order. Each must land before the mixed-traffic test gives
clean numbers.

| # | Fix | Effort | Why |
|---|---|---|---|
| F-1 | `scripts/test-setup.sh` must singleton xhelix — `pkill -9` BOTH `/usr/local/bin/xhelix` AND `./xhelix` patterns, then verify single pid before start | tiny | unblocks every test |
| F-2 | Add PID-file lock to `pkg/runtime/foundation.go` (or wherever foundation.go writes the pidfile) so a second daemon refuses to start | small | belt-and-braces |
| F-3 | Wire `alerts.sinks: [{kind: file, path: /var/log/xhelix/alerts.jsonl}]` into the YAML that `scripts/test-setup.sh` writes — and verify it via `lsof` after start | small | restores triage file |
| F-4 | Investigate `fim.drift` 1028-fire/window rate — either it's a real high-volume rule that needs allowlist, or its match is too broad | small-medium | reduces noise during tests |
| F-5 | `mixed_traffic_test.sh`: write the MIXED_BEGIN marker BEFORE backgrounding any work, use a dedicated marker-file in `/tmp` whose mtime delimits the window (not log-file inserts), and have the analyzer use the time window only | small | reproducible |
| F-6 | Time-window analyzer that pulls from xhelix.out (the only live alert stream right now) OR fixes alerts.jsonl first then reads it | small | reliable measurement |

---

## 6. Detection-mechanism subjective progress

Even without clean numbers, what we now know empirically:

| Capability | Status | Evidence |
|---|---|---|
| eBPF sensor — exec tracking | works | live data — memfd, shell_with_socket_fd, cap.gained all fired on real activity |
| Rule engine — CEL match | works | 9 distinct rule_ids fired across the session |
| `pkg/takeover` scorer | works | "planner shadow" lines in xhelix.out show isolated-tier plans at score=100 |
| Response engine — monitor mode | works | 0 destructive actions in this session post-P-PS.23 |
| FileSink → alerts.jsonl | **broken** | mtime frozen, no fd open |
| Daemon singleton | **broken** | 3 daemons running |
| Per-lineage alert tagging | likely works | events carry `parent_pid`, but the operator-facing stream that needs it (alerts.jsonl) is dead |
| Operator triage (`xhelixctl events tail`) | broken | returns `"not implemented yet"` (verified earlier in session) |

**Plain English**: the detection engine ITSELF is doing its job
(rules fire on attacks, no destructive FPs in monitor mode, takeover
scorer correctly produces isolation plans for high-score lineages).
The pipe from detection-engine → operator-triage is what's broken,
and that pipe is exactly what we need for empirical FP/TP
measurement.

---

## 7. Decision point for the user

Two paths forward, in order of cost:

**Path A — fix the measurement plumbing first (recommended).** ~3-4
hours: implement F-1 through F-6. Then the next mixed-traffic run
gives clean numbers we can stand behind. Without this, every
detection-rate number we produce will be a guess.

**Path B — parse xhelix.out as the live alert source.** ~30
minutes: write a `tests/redteam/parse_alerts_from_log.py` that
ingests xhelix.out, normalizes the bracket-format alerts into the
same schema as alerts.jsonl, and runs the lineage analysis on that.
Doesn't fix the platform bug but lets us measure NOW.

Recommendation: **B first** (cheap, gets numbers today), **then A**
(systematic). Path B is also valuable independently because operators
in the wild will need a way to read live alerts when alerts.jsonl is
absent / rotated / cold-stored.

---

## 8. New gaps surfaced this round

Added to `DETECTION_GAPS.md`:

- **GAP-140** (critical): `alerts.jsonl` sink not wired in default
  config. Operator triage file dead. F-3 fixes this.
- **GAP-141** (high): `fim.drift` firing 1028× in a short window
  with `comm=?` attribution. Needs investigation.
- **GAP-130 escalation**: pkill patterns mismatch the `./xhelix`
  relative-path daemons. F-1 + F-2 fix.

Carries forward from earlier rounds (still open):
- GAP-132 (`cap.gained` on every sudo)
- runtime allowlist (jit_engines, package_managed) — biggest single
  FP-reduction lever still un-implemented

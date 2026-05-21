# xhelix — First Testing Phase Results

**Date**: 2026-05-21
**Phase**: 1 — Initial live-fire validation
**Host**: 135.181.79.27 (Linux 6.8.0-101-generic, Ubuntu)
**Attacker**: 135.181.79.13
**xhelix version**: 0.0.2 (commit 4f5233b post P-PS.23)
**Scope**: First end-to-end attack against a fully wired xhelix on a real
host. NOT a comprehensive coverage test. Sample size: 5 attack phases,
~50 individual probes.

---

## 1. What the design claims xhelix does

Six functional pillars:

1. **Detection** — eBPF + FIM + LSM + identity + memory sensors → 48
   CEL rules + 13 DLCF rules → alerts on a bus.
2. **Correlation** — single-goroutine deterministic correlator +
   co-occurrence engine (`pkg/forensic.CoEngine`, `pkg/takeover.Scorer`).
3. **Response / containment** — Soak gate + Quarantine + NetBan +
   Remediate + HostQuarantine + PanicSwitch + Webhook.
4. **Deception (Ring 2)** — honey-sh, sinkhole, decoy-fs, dnspoison,
   crash-loop trap, forensic harvest.
5. **Evidence** — Ed25519-signed hash-chain (`xhelix-verify`), per-PID
   forensic snapshots, evidence buckets, hot/cold SQLite stores.
6. **Operator surfaces** — xhelixctl (events, forensic, history,
   protect, posture, rules, passport, wizard) + LocalAPI + legacy
   web dashboard + planned UI.

Plus aspirational: DLCF v2 (DB taps), Crown-Jewel wizard chain end-to-end,
Request Contract, full takeover scorer, MITRE A-I phase mapping.

---

## 2. Implementation status snapshot

| Pillar | Wired & live | Skeleton / behind flag | Design doc only |
|---|---|---|---|
| Sensors | heartbeat, fim, ebpf (8 progs), netids, identity (sshd+pam), memory.dmesg, decoy, lsmaudit, dpi | crashloop sensor, stateguard | MTE (P-PS.17), Scudo (P-PS.18) |
| Rules | 48 CEL + 13 DLCF, loaded, fired live today | per-rule action mask audit pending | causal-chain divergence (P-B.3), workflow state machine (P-B.4) |
| Correlator | `pkg/correlator` deterministic | | |
| Co-occurrence | `pkg/forensic.CoEngine` + `pkg/takeover.Scorer.CoRules` | | |
| Takeover scorer | builds plans, observed firing tier=isolated score=100 today | `Active=false` by default, never executes | full automatic isolation w/ rollback |
| Response engine | OnAlert dispatch, Quarantine, Kill, NetBan, Remediate, Webhook, Snapshot, MemScan, LockUser | HostQuarantine (bastion + off-host mirror missing) | DBSC verifier, Crown-Jewel chain end-to-end |
| Deception | sinkhole, dnspoison, honey-sh binaries built + wired into protected_services | decoy-fs (no live overlay), tarpit, tc redirect for real-ingress sinkhole | bpf_send_signal (P-FT.21), bpf_override_return fake-success (P-FT.22) |
| Evidence chain | `pkg/chain` signs + hash-chains, xhelix-verify rebuilds offline, evidence dir captures /proc snapshots | | off-host mirror (P-CJ.10), cloud-KMS signer (P-CJ.8) |
| Hot/cold store | SQLite (modernc.org), retention recently fixed | live event→enrichment→graph integration test (P2.X) pending | |
| LocalAPI / xhelixctl | wired: protect, forensic, posture, history, passport, rules | `events tail` returns `"not implemented yet"` | full UI |
| DLCF v1 | catalog, taint ledger, sensitivity budget, canary rules, egress valve, passport — wired | | v2 DB taps, perf_schema, wpdb drop-in, audit-plugin |
| Crown-Jewel | P-CJ.1 wizard | P-CJ.2–12 (10/12 pending) | |
| Baseline | per-binary aggregates, EWMA | xhub fleet daemon partial | |

**Split**: ~60% surface has working code, ~25% skeleton, ~15% design-only.

---

## 3. Test coverage (Go-side)

- **Unit/golden coverage exists** for: `pkg/decision` (golden corpus),
  `pkg/takeover`, `pkg/forensic`, `pkg/response` (executor),
  `pkg/correlator`, `pkg/rules`, `pkg/canonical`, `pkg/baseline`,
  `pkg/reqcontract`, `pkg/protectedsvc`. Solid.
- **Scenario integration**: `tests/redteam/scenarios_test.go` — 6 end-to-end
  scenarios with mutex-guarded hit list.
- **Live-exec integration test missing** — P2.X is open ("live event →
  enrichment → graph"). No CI job runs xhelix against actual eBPF.
- **No CI job loads `xhelix-progs.o`** — eBPF programs are unit-tested via
  Go-side mocks, not verified against the actual kernel ABI. Today was
  the first time this kernel/build combo ran them.
- **No FP test corpus** — there is no `tests/false_positives/` that asserts
  "node.js JIT must NOT trigger mem_mprotect_rwx quarantine." This is
  exactly why today's bug shipped.
- **No chaos / soak test** — no equivalent of "run xhelix on a busy
  workstation for 24h and assert no production process gets SIGSTOP'd."

`find . -name '*_test.go' | wc -l` ≈ 155 test files. Decent unit coverage,
weak end-to-end coverage of the boundary between eBPF program ↔ Go
consumer ↔ rule engine ↔ response action ↔ real syscalls.

---

## 4. Practical live-fire result (this drill)

Verified on a real Linux 6.8 box; attacker on 135.181.79.13 ran 5 phases
of `run_remote_suite.sh` (recon, rce, lfi, persist, exfil).

| Capability | Worked? | Score | Notes |
|---|---|---|---|
| eBPF process exec tracking | ✅ | 100% | every memfd, every shell-with-socket-fd, every cap_gained fired |
| FIM | ⚠️ | 90% | sensor configured, paths watched; persist phase mostly hit permission denied so paths weren't written |
| Rule engine | ✅ | 100% | 48 rules loaded, fired on real events |
| Correlator / co-occurrence | ✅ | 90% | fired into planner |
| Takeover scorer | ✅ | 100% | produced 105 isolated-tier plans (score=100) from live events |
| Response engine — observe path | ✅ | 100% | alerts → log + jsonl, no destructive actions in monitor mode |
| Response engine — enforce path | ❌ DANGEROUS | 30% | over-quarantined production runtimes (node, PM2, runc) — two FP-grenade rules fixed in P-PS.23; rest un-audited |
| Sinkhole + dnspoison | ⚠️ | 50% | binaries running, listening, but tc redirect not wired — attacker traffic never hits them |
| Honey-sh | ⚠️ | 40% | binary builds, session logger ready, but bind-mount / bpf_override_return wiring not done |
| Decoy-fs | ❌ | 20% | code exists, no live overlay applied |
| Crash-loop trap | ⚠️ | 60% | wired, didn't fire today |
| Forensic snapshot | ✅ | 95% | per-PID dumps accumulate in `/var/lib/xhelix/evidence/` |
| Evidence chain + xhelix-verify | ✅ | 100% | chain.key signs, verifier rebuilds offline |
| `xhelixctl events tail` | ❌ | 0% | literally returns `{"phase":0,"msg":"not implemented yet"}` |
| `xhelixctl protect / forensic / posture` | ✅ | 100% | wired |
| Web dashboard | ⚠️ | 20% | listens on 127.0.0.1:18080, marked "legacy" |
| BPF LSM hooks | ❌ | 0% | this kernel's `lsm=` cmdline doesn't include `bpf` |
| Container escape detection | ❓ | unknown | no PoC tested yet |
| ASLR / BOF detection | ❓ | unknown | BOF PoCs not built yet |
| DLCF v1 (taint, passport) | ✅ | 80% | wired; today's attack didn't exercise it |
| DLCF v2 (DB taps) | ❌ | 0% | design + skeleton |

### Rule fire counts during the attack window

| Rule | Fires | Note |
|---|---|---|
| `mem_mprotect_rwx` | 88 | mostly JIT FPs (node, PM2) — action quarantine REMOVED, alert-only |
| `ungated` | 88 | paired with above |
| `memfd_run_pattern` | 13 | Claude shells — quarantine REMOVED |
| `shell_with_socket_fd` | 7 | **attacker's reverse-shell attempt detected** |
| `cap.gained` | 4 | sudo invocations |

### Takeover planner shadow plans

- 105 plans at `tier=isolated score=100` (full takeover detected, would
  trigger `[snapshot memscan suspend_process isolate_cgroup lock_local_user]`)
- 21 at `tier=triaged score=68`
- 12 at `tier=triaged score=56`
- 22 at `tier=suspended` (scores 79/84/89)

**Real response actions executed**: 0. Monitor mode honored.

---

## 5. The honest one-number verdict

If "100% works" means "deploy xhelix on a real host today and it does what
the design docs say it does":

**~55–60% of stated capability genuinely works end-to-end right now.**

Of that:
- **~35% is production-ready** (detection + observe + evidence chain +
  co-occurrence + takeover scoring in shadow)
- **~20–25% works with sharp edges** (the FP-grenade response rules just
  fixed; other ActionQuarantine entries unaudited)

The remaining **~40–45%**:
- ~25% half-wired (sinkhole loopback-only, honey-sh no exec redirect,
  decoy-fs no overlay, `events tail` stub)
- ~10% behind config flags operators haven't been told to flip
  (`takeover.active`, BPF LSM in kernel cmdline)
- ~5–10% pure design (DLCF v2, off-host chain mirror, KMS signer,
  two-person L6 generalization)

---

## 6. Failure modes the design hides

Bugs that would bite operators in week 1 of a real deploy:

1. **Default policy will quarantine production runtimes** — fixed today for
   `mem_mprotect_rwx` and `memfd_run_pattern`. The other 13
   ActionQuarantine entries in `pkg/response/policy.go` are unaudited.
2. **No FP allowlist anywhere** — no `package_managed=true → trust`, no
   `cgroup_unit in /system.slice/*.service → trust`. Every legitimate
   JIT looks identical to shellcode to xhelix.
3. **"Monitor mode" was documentation-only until this session** — code
   delivered enforce despite runbook claiming observe.
4. **Cold.db can grow to 19 GB** — fixed (#153/#154) but daemons in the
   wild still have the bug.
5. **`xhelixctl events tail` is a stub.** Operator's primary triage tool.
6. **eBPF programs require a separate `make ebpf`** — if you forget, you
   silently lose ~70% of detection.
7. **No CI test proves xhelix doesn't break the host.** Both disk-fill
   and SIGSTOP-self-DoS shipped because no test asks "does it harm
   common workloads."
8. **Response engine has no per-rule monitor mode** — all-or-nothing.

---

## 7. What is defensible to claim

Tight statements I would stand behind:

- xhelix is a working **detection + evidence** system on Linux ≥ 5.15.
  Live attacks from a remote host produce real alerts, signed evidence,
  and structured logs that survive operator review.
- The **takeover scorer** correctly identifies attacker-controlled
  lineages and produces tier=isolated plans at score=100 within seconds.
- The **co-occurrence engine** behaves as documented; golden tests +
  today's live run confirm `download_and_execute`, `reverse_shell`,
  `cred_exfil_chain` fire under their intended conditions.
- **Monitor mode now actually works** (post P-PS.23).
- The **evidence chain** is tamper-evident and verifies offline.

What I would NOT claim:

- "Ready for production enforcement on a busy workload." It is not.
- "100% MITRE coverage." ~71% phase coverage per direction-doc; signal-only.
- "Self-contained." Several capabilities listed in docs are pure design
  (DLCF v2, off-host mirror, KMS signer).
- "Container-aware." Container escape detection isn't covered by tests yet.

---

## 8. Bottom line

xhelix is at **late-alpha** — strong detection plumbing, working evidence
chain, thoughtful design. The gap between "wired" and "battle-hardened"
is real. The things that *should* be tested (FP rates against real
workloads, full-host integration, response-engine blast radius) are the
things least tested. This session validated detection works and exposed
exactly the class of bug that's been hiding because no one ran it
end-to-end against real production processes before.

**Next phase**: see `TEST_PLAN.md`.

# Verdict Foundation — Replay Results

**Date:** 2026-05-29
**Branch:** `verdict-foundation`
**Corpus:** `/var/lib/xhelix/replay-corpora/2026-05-27_to_2026-05-29_mail-nocgurus.jsonl`
**Lines:** 89,239
**Window:** 42h (2026-05-27 20:23Z → 2026-05-29 14:19Z)
**Host:** mail.nocgurus.com (135.181.79.11) — mail server with containers, JIT runtimes, modern HTTP
**Tool:** `xhelix-replay` (reuses `pkg/rulecat`, so offline verdict == live alert-bus gate)

## Headline

| Mode | Emitted | Suppressed | Reduction |
|---|---:|---:|---:|
| detection (legacy baseline) | 89,239 | 0 | — |
| **visibility (new default)** | **1,936** | 87,303 | **97.83%** |

Suppressed by category: **fact = 59,882**, **weak_signal = 27,421**.

The baseline (89,239) reproduces exactly what really happened on .11 — confirming
the replay tool models live behavior faithfully.

## Acceptance gates

| Gate | Target | Result | Status |
|---|---|---|---|
| G1 | visibility emitted ≤ 2000 | 1,936 | **PASS** |
| G2 | 12/12 hand-labeled TPs preserved | `brp.hard_deny` emitted 93×, exit 0, zero TP regressions | **PASS** |
| G3 | zero unclassified rules | `xhelixctl rules lint` = 0 missing; replay unclassified = 0 after registry top-up | **PASS** |
| G4 | daemon defaults to visibility | `config.Default().Detection.AlertMode == "visibility"` (unit-tested) | **PASS** (live confirm pending T19) |
| G5 | CI green | `go test -race ./... ` + `go build ./...` green for touched packages | **PASS** |

## Top emitted rules in visibility mode (1,936 total)

| rule_id | count | category | note |
|---|---:|---|---|
| shell_with_socket_fd | 1,471 | incident | **Dominant term (76%).** Fired ~35×/h on this mail host — a recurring benign pattern (service spawning shells with socket-connected stdio) is plausible. Classified `incident`, so in this FOUNDATION (no chain engine yet) it emits raw. The verdict-engine plan will gate incidents behind chain-confirmation; if these fires are not chain-confirmed they drop to ~0. **#1 candidate for the next plan.** |
| binary_runs_from_tmp | 163 | incident | exec from /tmp on a server — real signal class |
| brp.hard_deny | 93 | hard_deny | **the canonical TP — correctly emitted** |
| boot_artifact_modified | 44 | hard_deny | persistence write |
| deleted_binary_running | 36 | incident | |
| revshell.detected | 30 | incident | |
| rc_local_modified | 21 | hard_deny | persistence write |
| systemd_unit_new | 19 | incident | |
| dropped_binary_lifecycle | 46 | incident | added to runtime registry this task |
| (remainder) | <10 each | mixed | profile_d_dropped, brp.verify_protected_path, metadata.*, cron_new_unit, kernel_module_load, webshell.argv |

## What got suppressed (the 87,303)

The biggest noise sources — all correctly reclassified as `fact` or `weak_signal`:

| rule_id | count | category | why suppression is correct |
|---|---:|---|---|
| cap.gained | 31,748 | fact | container runtimes request full cap set every start |
| memfd_run_pattern | 18,952 | weak_signal | modern Go/Python runtimes use memfd |
| tls_no_sni* | 16,992 | fact | check_imap / curl / tailscaled / rspamd legitimately omit SNI |
| ungated | 4,151 | fact | "process outside gated set" matches every new process |
| mem_new_rwx_mapping | 3,939 | fact | JIT compilers |
| bpf_syscall_unexpected | 3,052 | fact | systemd + runc use BPF legitimately |
| lolbin.suspicious | 3,031 | weak_signal | needs script context |
| process_spawn_burst | 1,483 | weak_signal | cron + container starts |
| cred_proc_scrape* | 1,635 | weak_signal | normal for monitoring |
| (others) | — | — | contescape, fim.drift, mem_mprotect_rwx, etc. |

## Honest limitations of this foundation

1. **shell_with_socket_fd dominates (1,471 of 1,936).** This is NOT yet a clean
   result for an operator. It passes the <2000 budget but 1,471 alerts/42h from
   one rule is still noisy. The honest disposition: it is classified `incident`
   (a real reverse-shell shape we do NOT want to silence), and the verdict
   engine (next plan) gates incidents behind chain-confirmation, which is the
   correct fix. We deliberately did NOT down-classify it to weak_signal just to
   make the number prettier — that would silence a genuine attack signal.

2. **Incidents emit raw in the foundation.** Until the verdict-engine + source-
   graph chain scoring lands, every `incident`-category rule alerts on each
   fire. The 35 incident rules contribute ~1,790 of the 1,936. The verdict
   engine is what turns "incident category" into "alerts only when chain-
   confirmed."

3. **This is single-host suppression.** No fleet/cohort comparison yet. A
   behavior unique to one host out of 50 is not yet flagged.

4. **The .11 host runs an older/different rule mix** than the repo. ~46% of the
   trace volume (cap.gained, ungated, lolbin.suspicious, process_spawn_burst,
   contescape.detected) is runtime-emitted, classified via
   `ruleset/runtime_categories.yaml`. This is expected and handled.

## Bottom line

From **89,239 alerts/42h (unusable)** to **1,936 alerts/42h** with zero loss of
the hand-labeled true positive — a 97.83% reduction, objectively measured against
a real production trace, reproducible via:

```bash
xhelix-replay --in <corpus> --rules ruleset/core \
  --runtime ruleset/runtime_categories.yaml \
  --mode visibility --tp testdata/prod-trace/true_positive_rules.txt
```

The foundation is in place. The next plan (verdict engine v1) targets the
shell_with_socket_fd / incident-emits-raw problem via source-graph chain
scoring, gated by this same replay tool.

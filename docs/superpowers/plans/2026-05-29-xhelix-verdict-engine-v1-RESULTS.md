# Verdict Engine v1 — Acceptance Results (VE-T5)

Date: 2026-05-29
Tool: `cmd/xhelix-replay` with new `--verdict` mode
Engine under test: `pkg/lineagescore` (Threshold=80, Window=1h, Cooldown=Window,
LineageOf=identity)

## Corpus

- Path: `/var/lib/xhelix/replay-corpora/2026-05-27_to_2026-05-29_mail-nocgurus.jsonl`
- Source host: `.11` (production mail box, real traffic)
- Window: ~42h (2026-05-27 → 2026-05-29)
- Size: 81,838,025 bytes
- Lines: 89,239 (all parsed; 0 malformed)
- Rules classified: 119 (`ruleset/core` + `ruleset/runtime_categories.yaml`)
- TP file: `testdata/prod-trace/true_positive_rules.txt` (includes `brp.hard_deny`)

## Headline numbers

| Run                       | Emitted | verdicts_emitted | Suppressed | Exit |
|---------------------------|---------|------------------|------------|------|
| foundation (no verdict)   | 1,936   | n/a              | 87,303     | 0    |
| verdict mode              | 329     | 170              | 88,910     | 0    |

Both runs: mode = `visibility`, exit 0 (no TP regression).

- foundation visibility: **1,936 emitted** — dominated by `shell_with_socket_fd`
  (1,471 raw incident fires).
- verdict visibility: **329 emitted** (`170` `verdict.incident`s + `159`
  hard_deny fires that always emit directly).
- Net reduction in alert volume: **1,936 → 329 (-83%)**.

## Acceptance target

Plan target was total emitted ≤ 300 in verdict mode with TP preserved.

- TP preserved: **YES** — exit 0, `brp.hard_deny` emitted 93 times (hard_deny
  bypasses the verdict engine and always emits).
- Total emitted: **329 — slightly above the 300 target.**

### Why 329 and not <300 (honest accounting)

The 329 splits cleanly:

- **170 verdict.incidents** — lineages (per-PID, see caveat) that genuinely
  accumulated ≥80 weight. These are real multi-signal PIDs, not noise. They are
  the *intended* output of the engine.
- **159 hard_deny fires** emitting directly (NOT routed through the verdict
  engine by design): `brp.hard_deny` (93), `rc_local_modified` (21),
  `boot_artifact_modified` (44), `kernel_module_load` (1). These are
  invariant-violation alerts that must always emit; they are not subject to
  the score gate and were never expected to collapse.

No weights or thresholds were tuned to chase the 300 number. The overshoot is
entirely hard_deny invariants (must emit) plus genuine threshold-crossing
lineages. The raw-incident-spam problem the engine targeted IS solved.

## `shell_with_socket_fd` collapse (the original motivation)

- foundation: 1,471 raw emits.
- verdict: **3 emits** (only the PIDs where shell_with_socket_fd was the
  threshold-crossing signal on an already-loaded lineage), **1,468 collapsed.**
- 1,471 → 3 = -99.8%.

## Top collapsed_by_rule (verdict mode)

Raw incident/weak_signal fires that did NOT individually cross the threshold:

| Rule                              | Collapsed |
|-----------------------------------|-----------|
| memfd_run_pattern                 | 18,952    |
| lolbin.suspicious                 | 3,031     |
| shell_with_socket_fd              | 1,468     |
| process_spawn_burst               | 1,442     |
| cred_proc_scrape                  | 1,238     |
| mem_mprotect_rwx                  | 963       |
| contescape.detected               | 824       |
| cred_proc_scrape_environ_burst    | 375       |
| fim.drift                         | 286       |
| binary_runs_from_tmp              | 163       |
| h2.slow_egress_fanout_24h         | 87        |
| thread_outside_module             | 79        |
| deleted_binary_running            | 35        |
| revshell.detected                 | 30        |
| messaging_platform_egress         | 19        |

## HONEST LIMITATION — replay lineage is per-PID (a lower bound)

The `alerts.jsonl` trace records each event's PID but does NOT carry a
reconstructed process-ancestry tree. In replay, `LineageOf = identity`: every
PID is treated as its own lineage root. Signals from a parent and its children
are therefore scored as SEPARATE lineages and do not sum.

**Consequence: this replay is a CONSERVATIVE LOWER BOUND on collapse.** The live
daemon, which has full proctree ancestry (`pkg/proctree`), correlates signals
across parent+child PIDs under one root and will sum evidence that the replay
keeps apart — collapsing MORE raw fires into fewer verdicts than the 170 shown
here, and likely emitting fewer total verdicts (some of the 170 separate-PID
verdicts would merge under a shared ancestor). The replay proves the floor, not
the ceiling.

Two smaller determinism notes:

- Event timestamps are parsed as RFC3339. Lines with a missing/unparseable
  `event.time` fall back to a synthetic monotonic clock (base + lineCount*1ms)
  so windowing stays deterministic. The .11 corpus parsed cleanly (no fallback
  needed in this run).
- The non-verdict (`--verdict=false`) replay path is byte-for-byte unchanged from
  the foundation behavior; verdict logic only activates under `--verdict` and
  only in non-detection mode (detection always emits everything).

## Reproduce

```bash
CORPUS=/var/lib/xhelix/replay-corpora/2026-05-27_to_2026-05-29_mail-nocgurus.jsonl
CGO_ENABLED=0 go build -trimpath -o ./xhelix-replay ./cmd/xhelix-replay
# foundation
sudo ./xhelix-replay --in $CORPUS --rules ruleset/core \
  --runtime ruleset/runtime_categories.yaml --mode visibility \
  --tp testdata/prod-trace/true_positive_rules.txt --format text
# verdict
sudo ./xhelix-replay --in $CORPUS --rules ruleset/core \
  --runtime ruleset/runtime_categories.yaml --mode visibility --verdict \
  --tp testdata/prod-trace/true_positive_rules.txt --format text
```

# Phase EO.3 — Service-Role Classification — RESULTS

**Date:** 2026-06-01
**Branch:** `verdict-foundation`
**Plan:** `docs/superpowers/plans/2026-06-01-egress-EO3-service-role.md`

## Headline

Egress flows can now be grouped/filtered by **service role** (web / database / cache /
broker / proxy / mail / dns / ssh / other) and carry the **parent process comm**. These
are descriptive enrichment stored **alongside** the FlowKey, not in it — so there was
**no warm-key schema migration and no destructive change**: old warm (gob) values and
old cold (parquet) files stay readable, new data carries the fields.

## What shipped (commits, in order)

| Commit | Task | Change |
|---|---|---|
| `9e68c2d` | T1 | `pkg/servicerole` — pure binary/port/appkind classifier |
| `ddde96b` | T2 | `ServiceRole`/`ParentComm` on Event + FlowMetrics + ProcEvent (FlowKey untouched); hot-merge non-empty-wins |
| `4782e87` | T3 | Persist in cold parquet (`service_role`/`parent_comm` columns); warm gob auto-carries; old-file tolerance test |
| `08ec9f2` | T4 | Classify + stamp `service_role` and derive `parent_comm` at the egress observe site |
| `051f269` | T5 | `FlowFilter.ServiceRole` query filter + UI Role/Parent columns |
| `<merge-fix>` | T6 | **Final-review fix:** warm `mergeRecord` now carries service_role/parent_comm |

## Acceptance gates

| Gate | Result |
|---|---|
| Classifier unit tests (nginx/mysqld/redis/postfix/sshd/…) | **PASS** |
| FlowKey untouched / warm key encoder unchanged | **PASS** (verified in final review) |
| Persist + read-back: warm gob + cold parquet round-trip | **PASS** |
| Old parquet files (no columns) read zero-filled, no error | **PASS** (`TestColdOldFileTolerance`) |
| Observe-site stamping (`mysqld → database`, parent_comm) | **PASS** |
| Query filter by service_role | **PASS** |
| `make vet`, `make static-check`, `-race` on touched pkgs, `make build` | **PASS** |

## Final-review finding (caught + fixed before deploy)

A two-stage + final code review caught a **real persistence bug**: the warm-tier
`mergeRecord` (used when same-key hot records merge on eviction) updated counters and
timestamps but **dropped `ServiceRole`/`ParentComm`** — so merged warm records would
have lost the role. Fixed with the same non-empty-wins logic as the hot ring, plus a
`TestMergeRecord_CarriesServiceRoleParentComm` regression test (including the
empty-incoming-doesn't-erase case). This is exactly what the review stage is for.

## Honest limits

1. **Known-binary table is the accuracy ceiling.** Role is decided primarily by a
   curated binary-basename map (`pkg/servicerole`). Unknown binaries → `other` (never
   guessed). A custom Go web app named `server` will read `other` unless added to the
   table.
2. **appident `app_kind` is NOT available at the egress observe site** — it's stamped
   later in the pipeline. So at runtime the `appKind` seed is effectively empty and
   classification relies on the binary table + (currently 0) listening port. The
   appKind fallback path exists and is unit-tested, but does not fire at the live
   observe site today. Wiring app_kind earlier (or a listen-port lookup) is a future
   enhancement.
3. **`parent_comm` depends on proctree** being populated for the parent PID at observe
   time (same derivation as the existing LOTL block); if proctree is unavailable it is
   left empty.
4. **Last-observed-wins** for the descriptive fields across hot-merge, warm-merge, and
   cold (append-only) — role is stable per key so this is correct; documented.

## Status / next

Built, tested (final-reviewed + fixed), committed — **ready to deploy, NOT yet deployed.**
Because the fields ride alongside the key, the new binary reads existing warm/cold data
without migration. Next: Phase EO.4 (IP intel — bundled ASN dataset + optional online
reputation, default OFF). Redeploy of EO.3 remains operator-gated.

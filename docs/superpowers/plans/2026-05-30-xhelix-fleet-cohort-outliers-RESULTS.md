# Fleet Cohort Outliers — Results (Verdict Engine v3)

**Date:** 2026-05-30
**Branch:** `verdict-foundation`

## The honest headline

This phase shipped a **correct, tested, conservatively-gated fleet-rarity-to-score
bridge that is OFF by default and a no-op until a real cohort is enrolled.** That
is the intended outcome, not a shortfall. The fleet *data plane* already existed
(agents upload → xhub computes per-cohort `RareList` → `/api/rare/`); this phase
built the missing agent-side consumer that feeds cohort rarity into the verdict
score. It changes nothing on a 2–3 host fleet — by design.

## Acceptance gates

| Gate | Target | Result | Status |
|---|---|---|---|
| F1 | rare +40, common neutral, unknown/small-cohort unchanged, cap 200 | unit-tested (`TestFleetWeightAdjust`, 5 cases) | **PASS** |
| F2 | hub client: query `/api/rare/`, cache per-binary, min-cohort gate, degrade to no-op on error/down | tested vs httptest fake hub (6 cases incl. hub-down, small-cohort, cache) | **PASS** |
| F3 | rare raises score / common doesn't / small cohort no-op | integration test (4 cases incl. nil-provider disabled) | **PASS** |
| F4 | default OFF; disabled path byte-identical to v2 | `FleetRarity` defaults false; nil client → no fleet calls (confirmed in router + test) | **PASS** |
| F5 | .11 replay --verdict UNCHANGED at 364, TP preserved | **364 emitted, 205 verdicts, exit 0, brp.hard_deny preserved** | **PASS** |

All five gates pass.

## The key-match guarantee (the highest risk in this phase)

The agent's fleet lookup key MUST equal the string the aggregator uploaded, or
every lookup silently misses. Eliminated by construction: the aggregator's
endpoint-key logic was extracted into a single exported `baseline.EndpointKey(dstIP, dstPort)`
( = `CIDR16(ip) + ":" + port`, e.g. `203.0.0.0/16:443`), and BOTH the upload path
and the verdict router now call it. They cannot drift. The binary identity also
matches (Image-then-Comm on both sides). Unit-tested by
`TestEndpointKey_MatchesAggregatorFormat`.

## What's live vs what's gated

- **Built & tested:** rare-endpoint → +40 weight; per-binary-cached hub client;
  min-cohort gate (default 5); error/down-hub → no-op; config flags
  (`detection.fleet_rarity`, `detection.fleet_min_cohort`); router integration.
- **Gated OFF until:** `detection.fleet_rarity: true` AND a hub is configured AND
  the cohort has ≥ `fleet_min_cohort` (5) hosts. Below that, it logs nothing
  alarming and contributes zero weight.
- **Replay can't exercise it:** the .11 trace has no hub and no cohort context, so
  `--verdict` is unchanged (364). Fleet rarity's value is proven by the
  integration test, not the replay — same honest limitation as v2's sensitivity
  weighting.

## Flagged follow-ups (not built — named so they're not lost)

1. **Hub-side clean-peer-only rarity.** `ComputeRare` counts ALL uploading hosts;
   a compromised peer dilutes rarity. Should exclude `TrustRanker.CanTeach==false`
   hosts. Hub change (`pkg/baselinehub` + `pkg/xhubfleet`), own plan. **Until this
   lands, fleet rarity is advisory weak evidence only** — it never alone creates a
   critical verdict and never auto-blocks.
2. **Common → −30 reduction.** Deliberately NOT built — silencing fleet-common
   behavior is unsafe before clean-peer rarity exists. v1 is rare-boosts-only.
3. **Per-feature fraction vs membership.** v1 uses rare-list membership (binary).
4. **Child-process / file-write rarity.** v1 only does egress endpoints.
5. **Enrolment.** Needs a real cohort of similar hosts uploading 7–14 days. Operational.

## Bottom line

Fleet cohort-outlier scoring is **implemented, correctly gated, secure-by-default,
and proven by tests** — and honestly does nothing in production until a real
cohort is enrolled and (for full trustworthiness) hub-side clean-peer rarity is
added. The .11 detection numbers are unchanged (364), as expected.

Reproduce F5:
```bash
xhelix-replay --in <corpus> --rules ruleset/core \
  --runtime ruleset/runtime_categories.yaml \
  --mode visibility --verdict --tp testdata/prod-trace/true_positive_rules.txt
# → 364 emitted, 205 verdicts, TP preserved (fleet off: no hub in replay)
```

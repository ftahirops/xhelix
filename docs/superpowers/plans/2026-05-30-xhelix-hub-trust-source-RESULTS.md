# Hub Trust-Feedback Source — Results

**Date:** 2026-05-30
**Branch:** `verdict-foundation`

## Honest headline

The trust→filter→rarity **mechanism is now complete and tested end to end**:
agents report verdict outcomes → the hub's trust ranker quarantines hosts that
produce critical verdicts and age-promotes quiet ones → cohort rarity can be
computed over only trusted ("clean") peers. But it remains **inert in
production** until (a) a real cohort of similar hosts is enrolled AND (b) those
hosts reach `TrustTrusted` (≥10 quiet days each) AND (c) the operator sets
`--clean-peer-rarity`. That conservatism is correct, not a defect.

## Acceptance gates

| Gate | Result | Status |
|---|---|---|
| TS1 | Hub instantiates + persists `TrustRanker` (`<datadir>/trust.json`); `See()`+`Evaluate()` on every upload; survives restart | **PASS** (persistence added; See/Evaluate already wired via `OnUpload`→`Engine.Ingest`) |
| TS2 | `Upload.VerdictSummary{Critical,High,Total}` optional; `Engine.Ingest` feeds `RecordAlert` (high) + quarantine (critical via `QuarantineOnCritical`); nil = no-op | **PASS** |
| TS3 | Agent tallies `verdict.incident` by tier (`pkg/verdictcount`) and drains it into `Upload.VerdictSummary` per upload (reset after build) | **PASS** |
| TS4 | `/api/rare/` uses `ComputeRareFiltered(CanTeach)` behind `--clean-peer-rarity` (default OFF = unchanged); both states tested | **PASS** |
| TS5 | full sweep green, race clean | **PASS** (10 packages ok, build ok, race clean on the trust-feedback chain) |

## The end-to-end chain now wired

```
agent verdict.incident (tier)            pkg/verdictcount.Counter.Record
  → uploader drains per upload           Upload.VerdictSummary{Critical,High,Total}
    → hub Engine.Ingest                  trust.RecordAlert("critical") → quarantine
      → trust.CanTeach(host) == false    (host excluded from teaching)
        → /api/rare ComputeRareFiltered  rarity computed over clean peers only
          → agent fleetrarity client     +40 weight for cohort-rare egress (v3)
            → lineagescore verdict        chain-confirmed incident
```
Every link is built and unit-tested. The chain is dormant end-to-end until a
trusted cohort exists.

## What this closes

The fleet-v3 follow-up flagged earlier ("hub computes rarity over ALL hosts incl.
possibly-compromised peers → fleet rarity is advisory-only") is now addressable:
with `--clean-peer-rarity`, a host that produces a critical verdict is quarantined
out of the teaching set, so its behavior no longer normalizes cohort rarity.

## Honest limits (unchanged + new)

1. **Inert until enrolment + maturity.** No trusted hosts today → with the flag
   ON, `ComputeRareFiltered` prunes all hosts → empty rare list. Default-OFF is
   the only safe shipping state until a cohort matures (≥10 quiet days/host).
2. **Trust source is verdict-self-report.** A host reports its OWN verdict counts.
   A fully-compromised agent could under-report. This is honest weak-trust, not
   attestation — adequate for FP-reduction, NOT a security boundary. Hardening
   (signed/independent trust signals) is future work.
3. **Two rarity paths still exist.** `/api/rare` (Store.ComputeRare[Filtered]) is
   what the agent queries; `xhubfleet.Engine` keeps its own trust-gated rarity
   index. They are not unified — a future cleanup, not load-bearing now.
4. **No UI / operator override of trust state** — future.

## Bottom line

Clean-peer cohort rarity is **implemented, tested, secure-by-default, and
correct** — and honestly does nothing until a real fleet is enrolled and matures.
Same shape as fleet v3 itself: the capability is real and waiting for fleet data,
not improving detection on a 2–3 host fleet today.

Default-OFF confirmed: `/api/rare` behavior is byte-unchanged unless
`--clean-peer-rarity` is passed to xhub.

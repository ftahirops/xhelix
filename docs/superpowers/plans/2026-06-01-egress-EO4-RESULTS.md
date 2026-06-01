# Phase EO.4 — IP Intelligence — RESULTS

**Date:** 2026-06-01 · **Branch:** `verdict-foundation`

## Headline
Two IP-intel improvements, fast/direct mode (no subagent ceremony — simple changes):
1. **Offline org-tier classification** — `destclass` now classifies cloud/CDN from the
   geoip **ASN org name** when CIDR/SNI tables miss. Uses data already present (the
   geoip seed carries the major cloud/CDN ASN orgs). No new dataset, no external calls.
2. **Optional online reputation** — config seam + guarded client (VirusTotal/AbuseIPDB),
   **default OFF**, with a test-proven contract: **disabled = zero network calls.**

## Commits
| Commit | What |
|---|---|
| `<org-tier>` | `destclass` OrgProvider tier (tier 5, between CIDR and fleet); `classByOrg` keyword map; geoip adapter wired into the pipeline DestClassifier; race-safe SetOrgProvider |
| `<rep-seam>` | `Detection.OnlineReputation{Enabled(false),Provider,APIKeyEnv}` + `pkg/ipreputation` guarded client; off-path makes no call (asserted) |

## Verification
- `pkg/destclass` org-tier tests: Cloudflare→cdn, Amazon/Hetzner→cloud_provider, unknown-org→unknown, no-provider default unchanged. PASS.
- `pkg/ipreputation`: `TestDisabled_MakesNoCall` (the safety contract), `TestEnabled_CallsProvider` (one call via injected Doer), nil-IP no-call. PASS.
- `pkg/config`: online_reputation validation (enabled requires known provider + api_key_env). PASS.
- **Replay regression vs the .11 trace: 364 emitted / 88,875 suppressed — UNCHANGED** from the prior baseline. The org tier did not regress FPs.
- `go build ./...`, `make vet` green.

## Honest limits / deferred
1. **Org tier uses a seed-loaded geoip instance** at the pipeline DestClassifier (the
   daemon-level CSV-enriched geoDB is in a different function scope). The seed already
   carries the major cloud/CDN ASN orgs, so cloud/CDN classification works; operator-CSV
   enrichment of the *org tier specifically* is a future hoist of geoDB. Country/ASN on
   the IP-info page still uses the full CSV-backed geoDB.
2. **Online reputation client is built but NOT wired into the live egress flow** — it's
   off by default and would do nothing, so wiring `Check()` into destclass/verdict is a
   follow-up for when an operator enables it. The capability, config, validation, and
   off-guarantee exist now.
3. **Bundled IP→ASN dataset deferred** — network sourcing works (iptoasn.com reachable),
   but bundling a ~5MB dataset into the deb is a size/build decision left for an explicit
   call. Current ASN coverage = geoip seed + operator CSV.

## Status
Built + tested + replay-clean, NOT yet deployed (batched with EO.3 for the next redeploy).

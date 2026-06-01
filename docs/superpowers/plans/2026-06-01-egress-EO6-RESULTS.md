# Phase EO.6 — Reverse-DNS Cache + rDNS-driven CDN/Org Detection — RESULTS

**Date:** 2026-06-01 · **Branch:** `verdict-foundation` · fast/direct mode

## What shipped
- **`pkg/rdnscache`** — bounded, TTL'd PTR cache (TTL 1h, cap 8192, negative-cache,
  oldest-eviction, hit/miss stats). The IP-info page previously issued a fresh
  `LookupAddr` on every load; the reverse-DNS adapter now fronts lookups with this
  cache. Unit-tested: hit/miss, negative caching, TTL expiry, stats.
- **`destclass.ClassFromPTR`** — pure rDNS-suffix → (class, operator) map
  (cloudfront/amazonaws/1e100/akamai/fastly/cloudflare/azure/hetzner/…). Unit-tested.
- **IP-info enrichment** — when the reverse name reveals a known cloud/CDN operator and
  class/org are otherwise unknown, the IP-info view fills them in (via a new
  `ClassFromPTR` method on the web `DestClassify` interface + daemon adapter, preserving
  the no-`pkg/destclass`-import boundary in `ui/web`).

## Verification
- `pkg/rdnscache`, `pkg/destclass`, `ui/web` tests green; `go build ./...`, `go vet` clean.
- No hot-path impact: rDNS + `ClassFromPTR` run only in the dashboard IP-info handler,
  never in the eBPF/observe path (which has no PTR without a blocking lookup).

## Honest limits
- rDNS-suffix table is a curated list (accuracy ceiling); unknown suffixes → no enrichment.
- Enrichment is display-only (IP-info page); it does not feed the verdict/alert path.
- PTR is spoofable by the IP owner — treated as a hint, not authority.

## Status
Built + tested, NOT yet deployed (batched with EO.3/EO.4 for the next redeploy).
Next: EO.5 Deep DPI L7 — the hard one — with full subagent review discipline.

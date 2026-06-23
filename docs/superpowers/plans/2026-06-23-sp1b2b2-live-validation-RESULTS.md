# SP-1b.2b.2 Live-Validation — RESULTS (2026-06-23)

**Run on:** dev box `135.181.79.27`, throwaway unit `xhelix-egress-validate.service`
(`sleep infinity`, auto-removed by `t.Cleanup`). Prod redis-server.service verified
active/untouched before+after. Command:
`go test -c -o /tmp/egv.test ./cmd/xhelix/ && sudo env XHELIX_LIVE_VALIDATE=1 /tmp/egv.test -test.run TestLiveEgressValidation -test.v`

## Verdict: **PASS** (2.80s)

`live validation OK: cold-start no-op, grow, rotation+grace, shrink — all live (MainPID 3078821 stable)`

All four ticks of the REAL `egressrefresh.Refresher` + `liveEgressApplier` against a live unit:

| Tick | Scenario | Result |
|---|---|---|
| 1 | cold start, resolve fails | **no `51-` file written** — empty-set lockout guard holds live |
| 2 | resolves to A (203.0.113.10) | `51-` written; systemd effective `IPAddressAllow` includes A |
| 3 | FQDN rotates to B (203.0.113.20) | within grace: **both A and B** present (in-flight survives) |
| 4 | +15 min, past 10-min grace, still B | **A shrunk out**, only B remains |
| all | — | **MainPID 3078821 unchanged** — no restart at any point |

## Conclusion
The SP-1b.2b.2 wiring (resolve → grace tracker → live applier → 51- drop-in →
daemon-reload → systemd effective config) is sound on systemd 255 / kernel 6.8.
Combined with the mechanism spike (kernel enforcement of the same drop-ins), the
live enforcement path is fully validated.

**Promotion guidance unchanged:** `hardening.egress_refresh_enforce` is now
safe to enable on a **vetted single-app host** — but only after the operator
reviews that host's shadow `51-` allow-sets (LogApplier logs them) and confirms
every legitimate destination is covered. Stage the rollout: one host, watch for
blocked-egress alerts, then widen. The gated test
(`cmd/xhelix/egress_live_validate_test.go`) should be re-run on any new host
class before promoting it.

**Still deferred (benign, tracked):** `liveEgressApplier.Forget` is not yet wired
to refresher-side eviction — on opt-out a `51-` file orphans (stale-permissive,
never a lockout).

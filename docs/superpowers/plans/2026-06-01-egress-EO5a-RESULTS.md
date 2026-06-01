# Phase EO.5a — L7 protocol from existing signals — RESULTS

**Date:** 2026-06-01 · **Branch:** `verdict-foundation`

## Headline
Every egress flow now carries an `l7_protocol` label derived from already-captured
signals (no new instrumentation): TLS SNI, dst port, the SSL-uprobe HTTP request-line,
the HTTP/2 preface (decoded from `payload_b64`), and L4. Descriptive enrichment stored
alongside the FlowKey (no migration). ALPN/QUIC/raw remain EO.5b/EO.5c.

## Commits
| Commit | What |
|---|---|
| `3b6ccae` | `pkg/l7proto` pure classifier (https/http/http2/grpc/ssh/dns/quic/tls-other/raw) |
| `0fa369b` | `l7_protocol` enrichment through Event/FlowMetrics/ProcEvent/cold-parquet/warm-merge |
| `b902488` | classify + stamp at the egress observe site (HTTP/2 preface decoded from payload_b64) |
| `11c56b5` | `FlowFilter.L7Protocol` query filter + UI "Proto" column |

## Verification
- `pkg/l7proto`, `pkg/egressledger`, `pkg/pipeline`, `ui/web` `-race` green; `make vet`/`static-check`/`build` green.
- **Replay regression vs the .11 trace: 364 emitted / 88,875 suppressed — UNCHANGED.** l7 is descriptive; it does not affect alert emission.
- warm `mergeRecord` carries L7Protocol (the EO.3 bug was NOT repeated; covered by test).

## Accuracy ceilings (honest, per the EO.5 investigation)
| Proto | Signal | Confidence |
|---|---|---|
| https | port 443 + SNI present | ~99% |
| ssh / dns | port (22 / 53) | ~95-98% |
| http | port 80/8080 or decrypted request-line | ~85% (SSL-uprobe captures only first 256B) |
| http2 | decrypted preface in payload_b64 | ~90% when payload captured |
| quic | UDP/443 | port-only guess until EO.5c wire capture |
| tls-other | 443, no SNI, no HTTP | low — could be QUIC-over-TCP-rare/custom |
| raw | unknown port | fallback |

## Not yet done (rest of EO.5)
- **EO.5b** — ALPN (switch dpi sniffer to pkg/ja3 which already parses ALPN → real grpc/h2). Userspace, no eBPF.
- **EO.5c** — NEW eBPF: QUIC initial capture + raw first-payload. HIGH risk, perf-gated, default-off until soak-validated.
- **EO.5d** — fold b/c protocols in; consolidated RESULTS with measured accuracy + hot-path overhead.

## Status
Built + tested + replay-clean, NOT deployed (batched with EO.3/EO.4/EO.6 for the next redeploy).

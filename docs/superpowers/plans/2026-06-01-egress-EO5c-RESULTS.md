# Phase EO.5c — QUIC eBPF capture — RESULTS (T1-T3; T4 deploy-gated)

**Date:** 2026-06-01 · **Branch:** `verdict-foundation`

## What shipped (compile-verified; runtime validation pending a deploy)
| Commit | Task | What |
|---|---|---|
| (T1) | EO5c-T1 | `quic` made honest: UDP/443 → `udp-other` unless confirmed; `EBPF.DeepCapture` flag (default off). Pure Go, fully tested, ZERO kernel risk. |
| (T2) | EO5c-T2 | eBPF QUIC long-header peek in `udp_sendmsg` (walks `msg_iter` ITER_UBUF/ITER_IOVEC, reads 5 bytes, checks long-header + known version), gated by `xh_deepcapture` map, flag in net-event `_pad[0]`; decoder emits `quic_confirmed`. **`make ebpf` compiles clean.** |
| (T3) | EO5c-T3 | backend sets `xh_deepcapture` map from `cfg.Sensors.EBPF.DeepCapture`; pipeline sets `Signals.QUICConfirmed` from the tag → classifier returns `quic` only when confirmed. |

## Verification done
- `make ebpf` compiles `all.bpf.c` → valid eBPF object (toolchain: clang-18, libbpf 1.3).
- `make vet`, `make static-check`, `go build ./...` green.
- Unit tests: l7proto (confirmed vs udp-other), config (flag), pipeline, decoder quic-flag decode.
- **Default OFF** → `xh_deepcapture=0` → the in-kernel peek early-returns; byte-for-byte prior behavior. T1's honest-quic improvement applies even with the flag off.

## NOT done — EO5c-T4 (deploy-gated, REQUIRES explicit consent)
The kernel **verifier acceptance** and **hot-path perf** of the `msg_iter` peek are NOT
proven — a compile is not a load. T4 must, on the dev box with `DeepCapture=true`:
1. Confirm the program LOADS (runtime verifier passes) — the `msg_iter`/`iov_iter`
   walk is the version-sensitive risk; may need iteration against the verifier log.
2. Generate QUIC (curl --http3 / browser) → confirm `quic_confirmed` flows; generate
   non-QUIC UDP/443 → confirm it does not.
3. Measure hot-path overhead + EO.2 drop counters under load; must not regress.
Only then is `DeepCapture` a recommended setting. Prod stays off until separately approved.

## EO5c-T5 (deferred)
Raw TCP first-payload capture for unknown-port cleartext — separate, same risk profile,
only after QUIC (T1-T4) validates.

## Honest bottom line
The QUIC path is **written and compile-verified end-to-end, off by default**. It is
**not runtime-proven**; that is one dev-box load test away (T4) and is the genuinely
risky step. T1's honest-quic relabel is the part that delivers value immediately.

---

## EO5c-T4 — LIVE validation on dev box (2026-06-01, executed)

Deployed new binary + new `xhelix-progs.o` to dev box; staged: loaded with
DeepCapture OFF first (verifier test), then ON for functional test.

**Results:**
- ✅ **Kernel verifier ACCEPTS the QUIC peek** — the new `.o` (with the msg_iter
  walk compiled in) loads clean; daemon active, eBPF sensor + uprobes attached,
  net events flowing, 0 restarts. The #1 risk is cleared.
- ✅ **Stable with DeepCapture ON** — 0 restarts, no eBPF errors, no perf collapse.
- ✅ **End-to-end QUIC confirmed** — connected UDP/443 datagrams with a QUIC v1
  long-header classified as `l7_protocol: "quic"` in the recent ring (`python3 →
  quic`). Non-QUIC and TCP traffic unaffected.
- ✅ **Bug found + fixed by this live test:** `l7proto.Classify` checked
  `QUICConfirmed` *inside* the `L4=="udp"` branch, but `net_bytes` events carry no
  L4 tag, so it never ran. Moved the check to the top (a confirmed long-header is
  authoritative regardless of L4). Committed.

**Honest caveats / limits found live:**
1. The peek's port gate reads dst port from the **socket** (`skc_dport`), so it
   only fires for **connected** UDP sockets (real QUIC clients connect; an
   unconnected `sendto()` QUIC sender is missed). Acceptable for browser/curl QUIC.
2. **connstate is TCP-only** — the live "Connections" view shows UDP flows masked
   onto TCP tuples; UDP/QUIC visibility is via the ledger recent ring, not the
   connections endpoint. Noted for EO.7 UI work.
3. **Sustained perf/overhead soak NOT done** — only a brief stability check.
   DeepCapture restored to **OFF** after the test pending a proper overhead soak.

**Disposition:** QUIC eBPF is functionally validated (loads, stable, classifies
correctly). DeepCapture is OFF by default; re-enable for a measured overhead soak
before recommending it generally. Prod untouched.

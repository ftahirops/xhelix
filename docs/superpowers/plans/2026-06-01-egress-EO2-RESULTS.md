# Phase EO.2 — Capture-Loss Honesty — RESULTS

**Date:** 2026-06-01
**Branch:** `verdict-foundation`
**Plan:** `docs/superpowers/plans/2026-06-01-egress-EO2-capture-loss.md`

## Headline

eBPF event loss is no longer a single silent number. The one `drops` counter is
split into three causes, carried through `sensors.Health`, exposed in `/api/sensors`,
and surfaced as an honest **capture-loss banner** on the egress dashboard. An
operator can now see *that* traffic is being missed and *why* (kernel ringbuf
overflow vs. consumer too slow vs. decode error) instead of being silently blind.

## What shipped (commits, in order)

| Commit | Task | Change |
|---|---|---|
| `73b66b4` | EO2-T1 | Split `drops` into `dropRingbuf` / `dropConsumerFull` / `dropDecode`; `Drops()` now the sum; 3 cause-specific accessors; stub parity |
| `6592363` | EO2-T2 | `sensors.Health` gains `DropRingbuf`/`DropConsumerFull`/`DropDecode`; eBPF `Health()` populates them; `Backend` interface widened |
| `59d347f` | EO2-T3 | `/api/sensors` emits the 3 keys; egress dashboard banner warns on live capture loss |

## The three drop causes (where each fires, verified in code)

In `sensors/ebpf/backend_linux.go` `readLoop`:
- **`dropRingbuf`** — `b.events.Read()` returned an error (includes kernel ringbuf overflow / lost samples). This is the dangerous one: events the kernel produced that userspace never saw.
- **`dropDecode`** — `Decode(rec.RawSample)` failed (malformed/short event). Softer: a produced event we couldn't parse.
- **`dropConsumerFull`** — the `select { case b.out <- ev: ... default: }` default branch: the downstream pipeline channel was full, so we dropped rather than block. Means the consumer is too slow.

## Banner behavior

The egress page polls `/api/sensors` (5s, honoring pause/hidden), finds the `ebpf`
sensor, and shows a visible amber banner when `drop_ringbuf > 0 || drop_consumer_full > 0`:

`⚠ Capture loss: ringbuf overflow R, consumer-full C — some egress traffic may be missing from this view. (+D decode errors)`

Hidden when all three are zero. Copy is deliberately honest — "may be missing," not
"blocked."

## Acceptance gates

| Gate | Result |
|---|---|
| Counters increment by correct cause | **PASS** (mapping code-verified + accessor unit test) |
| `Health()` reports the split, `DropCount` still combined | **PASS** (`TestSensorHealth_DropBreakdown`) |
| `/api/sensors` exposes the breakdown | **PASS** (`TestHandleSensorsIncludesDropBreakdown`) |
| Banner shows on loss / hides when zero | **PASS** (JS logic; `node --check` clean) |
| `make vet`, `make static-check`, `-race` on touched pkgs | **PASS** |
| `make build` | **PASS** |
| Backward compat (`Drops()`, `DropCount`) | **PASS** (both remain, = sum) |

## Honest limits

1. **Makes loss visible; does not prevent it.** EO.2 is observability, not a fix.
   Reducing the loss (bigger ringbuf, faster consumer, backpressure) is separate
   future work — the banner tells you *when* that work is needed.
2. **Plumbing unit-tested; in-kernel overflow path code-verified, not integration-tested.**
   Triggering a real ringbuf overflow needs a live daemon under load; the three
   increment sites are one-line cause-specific swaps verified by reading the code.
3. **Banner verified at the JSON + JS-syntax layer**, not in a live browser against
   real drops.

## Status / next

Built, tested, committed — **ready to deploy, NOT yet deployed.** Per the working
agreement, redeploy is operator-gated. The `pkg/cgroupclass` daemon-misclassification
fix (commit after EO.1) and EO.2 will ride the same next redeploy. EO.3 (service-role
classification — the wire-format/schema-bump phase) is next in the roadmap.

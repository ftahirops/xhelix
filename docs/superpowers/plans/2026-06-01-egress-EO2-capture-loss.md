# Phase EO.2 — Capture-Loss Honesty Implementation Plan

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Checkbox steps.

**Goal:** Make eBPF event loss VISIBLE and ATTRIBUTABLE instead of a single silent counter, so an operator can never be unknowingly blind to traffic. Split the one `drops` counter into three causes (ringbuf overflow, consumer-too-slow, decode error), expose them through sensor `Health`, and show a "data loss" banner in the egress UI when loss is occurring.

**Architecture:** `sensors/ebpf/backend_linux.go` already counts every drop into one `drops atomic.Uint64` at three distinct sites. Split into three atomics with cause-specific accessors; keep a combined `Drops()` for backward compatibility. Carry the breakdown up through the shared `sensors.Health` struct (new optional fields, other sensors leave them zero), which `ui/web/server.go` already serializes per sensor. The egress UI renders a dismissable-but-recurring banner when ringbuf-overflow or consumer-full is nonzero in the current window. Honest framing baked into the banner copy: this does not PREVENT loss, it makes loss observable.

**Tech Stack:** Go 1.22 CGO=0, `sensors/ebpf` (Linux build-tagged), `sensors/sensor.go` (Health struct), `ui/web` (server-rendered + static JS).

**Honest scope note:** the actual increment sites live in `readLoop`, which requires a live ringbuf to exercise end-to-end; unit tests cover the counter/accessor/Health plumbing directly, and the three increment lines are verified by code inspection (one-line cause-specific `.Add(1)` swaps). No false claim of a kernel-overflow integration test.

---

## Task EO2-T1: split the drop counter by cause in the eBPF backend

**Files:**
- Modify: `sensors/ebpf/backend_linux.go` (struct field `drops` ~line 36; `Drops()` ~line 103; increment sites ~264/269/277)
- Modify: `sensors/ebpf/backend_stub.go` (non-Linux stub — add matching no-op accessors so the package builds everywhere)
- Test: `sensors/ebpf/backend_drops_test.go` (new; `//go:build linux`)

- [ ] **Step 1 — failing test (accessor plumbing).** Create `sensors/ebpf/backend_drops_test.go`:
```go
//go:build linux

package ebpf

import "testing"

func TestDropCounters_Breakdown(t *testing.T) {
	b := &linuxBackend{}
	b.dropRingbuf.Add(2)
	b.dropConsumerFull.Add(5)
	b.dropDecode.Add(1)
	if got := b.DropRingbuf(); got != 2 {
		t.Fatalf("DropRingbuf=%d want 2", got)
	}
	if got := b.DropConsumerFull(); got != 5 {
		t.Fatalf("DropConsumerFull=%d want 5", got)
	}
	if got := b.DropDecode(); got != 1 {
		t.Fatalf("DropDecode=%d want 1", got)
	}
	if got := b.Drops(); got != 8 {
		t.Fatalf("Drops (combined)=%d want 8", got)
	}
}
```

- [ ] **Step 2 — run, expect FAIL.** `go test ./sensors/ebpf/ -run TestDropCounters_Breakdown` → fails (fields/methods undefined).

- [ ] **Step 3 — implement.** In `backend_linux.go`:
  - Replace `drops   atomic.Uint64` with:
```go
	dropRingbuf      atomic.Uint64 // ringbuf read error (incl. overflow/lost samples)
	dropConsumerFull atomic.Uint64 // downstream channel full — consumer too slow
	dropDecode       atomic.Uint64 // event decode failure
```
  - Replace the `Drops()` method body with the sum and add three accessors:
```go
func (b *linuxBackend) Drops() uint64 {
	return b.dropRingbuf.Load() + b.dropConsumerFull.Load() + b.dropDecode.Load()
}
func (b *linuxBackend) DropRingbuf() uint64      { return b.dropRingbuf.Load() }
func (b *linuxBackend) DropConsumerFull() uint64 { return b.dropConsumerFull.Load() }
func (b *linuxBackend) DropDecode() uint64       { return b.dropDecode.Load() }
```
  - At the three increment sites in `readLoop`, swap `b.drops.Add(1)` for the cause-specific counter: the `b.events.Read()` error path → `b.dropRingbuf.Add(1)`; the decode-error path → `b.dropDecode.Add(1)`; the `default:` (channel full) path → `b.dropConsumerFull.Add(1)`. (Confirm which line is which by reading the surrounding code; do not guess — the read-error is right after `b.events.Read()`, decode is right after `Decode(...)`, consumer-full is the `select { case b.out <- ev: ... default: }`.)

- [ ] **Step 4 — stub parity.** In `backend_stub.go`, add no-op methods so non-Linux builds compile and any caller of the accessors is satisfied:
```go
func (s *stubBackend) Drops() uint64            { return 0 }
func (s *stubBackend) DropRingbuf() uint64      { return 0 }
func (s *stubBackend) DropConsumerFull() uint64 { return 0 }
func (s *stubBackend) DropDecode() uint64       { return 0 }
```
(Only add the ones that don't already exist — check first.)

- [ ] **Step 5 — run, expect PASS + build.** `go test ./sensors/ebpf/ -run TestDropCounters_Breakdown` PASS; `go build ./...` OK.

- [ ] **Step 6 — commit.**
```bash
git add sensors/ebpf/backend_linux.go sensors/ebpf/backend_stub.go sensors/ebpf/backend_drops_test.go
git commit -m "feat(ebpf): split silent drop counter into ringbuf/consumer-full/decode causes"
```

## Task EO2-T2: carry the breakdown through sensors.Health

**Files:**
- Modify: `sensors/sensor.go` (the `Health` struct ~line 28)
- Modify: `sensors/ebpf/sensor.go` (`Sensor.Health()` ~line 61 — populate the new fields from the backend)
- Test: `sensors/ebpf/sensor_health_test.go` (new; `//go:build linux`) OR extend an existing sensor test

- [ ] **Step 1 — failing test.** Create `sensors/ebpf/sensor_health_test.go`:
```go
//go:build linux

package ebpf

import "testing"

func TestSensorHealth_DropBreakdown(t *testing.T) {
	b := &linuxBackend{}
	b.dropRingbuf.Add(3)
	b.dropConsumerFull.Add(4)
	s := &Sensor{backend: b} // adjust to the actual field name wiring backend into Sensor
	h := s.Health()
	if h.DropRingbuf != 3 || h.DropConsumerFull != 4 {
		t.Fatalf("health breakdown wrong: %+v", h)
	}
	if h.DropCount != 7 {
		t.Fatalf("DropCount=%d want 7 (combined)", h.DropCount)
	}
}
```
FIRST read `sensors/ebpf/sensor.go` to confirm how `Sensor` holds its backend (field name/type) and how `Health()` currently sets `DropCount`; match reality (the literal `&Sensor{backend: b}` may need a different field name).

- [ ] **Step 2 — run, expect FAIL.** `go test ./sensors/ebpf/ -run TestSensorHealth_DropBreakdown`.

- [ ] **Step 3 — implement.** In `sensors/sensor.go`, add to the `Health` struct (after `DropCount`):
```go
	// Drop breakdown by cause (eBPF sensor; other sensors leave these 0).
	// DropCount remains the combined total for backward compatibility.
	DropRingbuf      uint64
	DropConsumerFull uint64
	DropDecode       uint64
```
In `sensors/ebpf/sensor.go` `Health()`, set the three new fields from the backend accessors, and keep `DropCount` = `backend.Drops()` (combined). Use whatever interface/type the backend is referenced as; if the backend is referenced through an interface that lists `Drops()`, add the three accessors to that interface too (check `backend_stub.go` satisfies it — T1 added the stub methods).

- [ ] **Step 4 — run, expect PASS + `go build ./...`.**

- [ ] **Step 5 — commit.**
```bash
git add sensors/sensor.go sensors/ebpf/sensor.go sensors/ebpf/sensor_health_test.go
git commit -m "feat(sensors): expose eBPF drop-cause breakdown via Health"
```

## Task EO2-T3: surface drop breakdown in the web API + egress data-loss banner

**Files:**
- Modify: `ui/web/server.go` (the per-sensor health serialization ~line 294-299, where `"drop_count": h.DropCount` is emitted)
- Modify: the egress page handler/template + `ui/web/static/egress/egress.js` (banner render)
- Test: extend an existing `ui/web` test or add a minimal JSON-shape assertion

- [ ] **Step 1 — API: add the breakdown to the sensor health JSON.** Where `server.go` builds the per-sensor map (currently `"drop_count": h.DropCount`), add:
```go
			"drop_ringbuf":       h.DropRingbuf,
			"drop_consumer_full": h.DropConsumerFull,
			"drop_decode":        h.DropDecode,
```

- [ ] **Step 2 — egress banner.** In the egress dashboard (find where the egress page is served / its JS bootstraps), add a banner element that polls the existing sensor-health JSON and, when `drop_ringbuf > 0` OR `drop_consumer_full > 0` for the ebpf sensor, shows a fixed, visible warning:
  `⚠ Capture loss: N events dropped (ringbuf overflow R / consumer-full C). Some egress traffic may be missing from this view.`
  Decode-only drops (`drop_decode`) are a softer note (malformed events, not necessarily missed traffic) — include in the count but phrase as "decode errors D". Match the existing egress.js fetch/render style; do not add a framework. Keep the banner readable on narrow widths (the full responsive reorg is EO.7 — here just don't make it overflow).

- [ ] **Step 3 — test.** Add/extend a `ui/web` test asserting the sensor-health JSON for an ebpf-like sensor includes `drop_ringbuf`/`drop_consumer_full`/`drop_decode`. If the health serialization isn't easily unit-testable, add a tiny test on the map-building helper; otherwise assert via a constructed `sensors.Health`.

- [ ] **Step 4 — run + build.** `go test ./ui/web/...` PASS; `go build ./...` OK.

- [ ] **Step 5 — commit.**
```bash
git add ui/web/
git commit -m "feat(egress-ui): expose drop-cause breakdown + capture-loss banner"
```

## Task EO2-T4: full sweep + RESULTS + redeploy gate

**Files:** Create `docs/superpowers/plans/2026-06-01-egress-EO2-RESULTS.md`

- [ ] **Step 1 — sweep.** `make vet && make static-check && go test -race -count=1 ./sensors/ebpf/ ./sensors/ ./ui/web/`. (Note the known pre-existing egressledger time-boundary flake is in a different package and not in scope.)
- [ ] **Step 2 — `make build`.**
- [ ] **Step 3 — RESULTS doc:** what shipped, the three drop causes + how each is triggered in the code, the banner behavior, and the honest limit (makes loss visible, does not prevent it; the accessor plumbing is unit-tested, the in-kernel overflow path is code-verified not integration-tested).
- [ ] **Step 4 — PAUSE: redeploy is operator-gated.** Do NOT `sudo install`/restart. Report ready-to-deploy and stop; the operator decides when to redeploy (the cgroupclass daemon fix + EO.2 will ride the same redeploy).
- [ ] **Step 5 — commit RESULTS** (`git add -f`).

## Self-review notes
- Spec coverage: T1 splits causes, T2 carries them through Health, T3 surfaces API+banner, T4 verifies+documents. Matches EO.2 in the roadmap.
- Backward compat: `Drops()` and `Health.DropCount` remain (sum), so existing consumers (server.go:299) keep working.
- Cross-platform: stub gets matching accessors (T1 Step 4); new fields on the shared Health struct are zero for non-ebpf sensors.
- Type consistency: `DropRingbuf`/`DropConsumerFull`/`DropDecode` used identically in backend accessors (T1), Health struct + populate (T2), and JSON keys `drop_ringbuf`/`drop_consumer_full`/`drop_decode` (T3).

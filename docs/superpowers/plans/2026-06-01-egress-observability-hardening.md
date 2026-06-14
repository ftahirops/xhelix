# Egress Observability Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the six observability/correlation weak points in the xhelix egress controller (container naming, capture-loss honesty, service-role grouping, IP intelligence depth, deep L7/DPI protocol classification, reverse-DNS use) and reorganize the egress web UI into responsive, per-case observability views.

**Architecture:** Each weak point is an independent phase that produces working, testable software on its own and is measured against live egress data before the next phase starts. Phases reuse existing packages where they exist (`pkg/cgroupclass` for container identity, `pkg/destclass` for classification, `pkg/threatintel` for feeds, `sensors/dnsresolver` for forward DNS). Two cross-cutting constraints: (1) any change to `egressledger.FlowKey` is a storage-schema change under `/var/lib/xhelix/` and is handled by a **store-version bump that ages old data out** (no destructive migration); (2) all development happens off the running daemon — the dev-box shadow soak is NOT interrupted until the operator explicitly approves a redeploy.

**Tech Stack:** Go 1.22 (CGO_ENABLED=0, static), `pkg/egressledger` (Badger warm + Parquet cold + in-memory hot), `pkg/cgroupclass`, `pkg/destclass`, `pkg/geoip`, `pkg/threatintel`, `sensors/ebpf`, `sensors/dnsresolver`, `pkg/pipeline`, `ui/web` (server-rendered + JSON APIs).

**Decisions locked (from operator):**
- IP intel: offline-first + **optional** online reputation (VirusTotal/AbuseIPDB) **default OFF**, behind config flag. Enabling it sends destination IPs to a third party — documented as an explicit egress-of-data action.
- Sequencing: **phased, measured per phase.** Each phase ends with a RESULTS doc citing live numbers + green tests.
- L7: **deep DPI-style** classification (its own large phase, EO.5).

---

## Phase map and acceptance gates

| Phase | Weak point | Deliverable | Acceptance gate |
|---|---|---|---|
| **EO.1** | Container unnamed | Wire `cgroupclass` into egress; container id/class on every flow + recent ring + UI | New unit tests green; live: ≥1 docker container's egress shows its container id in `/api/egress` recent feed; race clean; static-check passes |
| **EO.2** | Silent capture loss | Split eBPF drop counters (ringbuf-overflow vs consumer-full vs decode-error); surface in `Health()` + UI banner | Counters increment in a forced-overflow test; `Health()` reports them; UI shows a loss banner when nonzero |
| **EO.3** | No service role | `parent_comm` + a service-role classifier (`web`/`db`/`cache`/`mail`/`ssh`/`other`) into FlowKey (store-version bump) | Classifier unit tests for nginx/mysql/redis/postfix/sshd; live: egress groupable by role; old store data ages out cleanly |
| **EO.4** | Shallow IP intel | Bundled IP→ASN dataset + richer org/CDN attribution; optional online reputation (default OFF) | ASN resolves offline for known ranges; online path gated by flag + unit-tested with a mock; no external calls when flag off (asserted in test) |
| **EO.5** | L4-only protocol | Deep L7/DPI classifier (own sub-plan) | Separate detailed plan `2026-..-egress-dpi.md`; per-protocol identification accuracy measured on live + corpus |
| **EO.6** | rDNS unused | PTR cache + rDNS-suffix-driven CDN/company detection feeding `destclass` | Cache hit-rate measured; rDNS suffix match contributes to org/CDN class in unit tests |
| **EO.7** | UI not organized | Reorganize egress UI into responsive observability tabs (Processes / Services / Users / Containers / Protocols / Destinations / Timeline / Intel) | Manual responsive check at 360px / 768px / 1280px; every Phase EO.1–EO.6 field has a home; no dead links |

Phases EO.2–EO.7 each get their own fully-detailed plan document at the start of that phase (the design will be informed by the prior phase's live measurements). **This document fully details Phase EO.1 only**, which is the next executable work.

---

## Phase EO.1 — Container / pod naming (detailed)

**Why first:** highest operator value (on a container host you currently cannot name which container is sending traffic), lowest risk (the resolver already exists), and no storage-schema change (container id rides in the recent-events ring + as an optional `Event` field, not in `FlowKey`).

**Approach:** `pkg/cgroupclass.Classifier.Classify(pid)` already returns `Info{Class, Unit, ContainerID, UserID}` from a single cached `/proc/<pid>/cgroup` read. We add a `*cgroupclass.Classifier` to the pipeline, call it at the egress observe site, carry `ContainerID` + `ContainerClass` + `Unit` on `egressledger.Event` and the recent-ring `ProcEvent`, and surface them in the `/api/egress` recent feed and IP-info drilldown. Container **id** (offline, from cgroup path) is the deliverable; friendly container **name** via the docker socket is explicitly out of scope for EO.1 (optional online follow-up, like the EO.4 reputation flag).

### File structure for EO.1

- Modify `pkg/egressledger/types.go` — add `ContainerID`, `ContainerClass`, `Unit` to `Event` (input only; NOT added to `FlowKey`).
- Modify `pkg/egressledger/recent.go` — add `ContainerID`, `ContainerClass`, `Unit` to `ProcEvent`; populate in the append path.
- Modify `pkg/pipeline/pipeline.go` — add `ContainerClassifier *cgroupclass.Classifier` field; at the egress observe site (~line 400) call `Classify(ev.PID)` and stamp the three fields onto `le`.
- Modify `cmd/xhelix/run.go` — construct one `cgroupclass.New(0)` and assign to `pipeline.ContainerClassifier`; wire `Forget` to the proctree exit hook if one exists (best-effort).
- Modify `ui/web/egress.go` (or the handler that renders the recent feed / `/api/egress`) — include the new fields in the JSON and a "Container" column.
- Tests: `pkg/egressledger/recent_test.go`, `pkg/pipeline/pipeline_test.go` (observe-site stamping).

### Task 1: Add container fields to `egressledger.Event`

**Files:**
- Modify: `pkg/egressledger/types.go:50-83`
- Test: `pkg/egressledger/types_test.go` (create if absent)

- [ ] **Step 1: Write the failing test**

Create/append `pkg/egressledger/types_test.go`:

```go
package egressledger

import "testing"

func TestEvent_ContainerFields(t *testing.T) {
	e := Event{ContainerID: "9f8e7d6c", ContainerClass: "container", Unit: "docker-9f8e7d6c.scope"}
	if e.ContainerID != "9f8e7d6c" || e.ContainerClass != "container" || e.Unit != "docker-9f8e7d6c.scope" {
		t.Fatalf("container fields not retained: %+v", e)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/egressledger/ -run TestEvent_ContainerFields`
Expected: FAIL — `unknown field ContainerID in struct literal`.

- [ ] **Step 3: Add the fields**

In `pkg/egressledger/types.go`, inside `type Event struct`, after the `Comm string` block (line ~79), add:

```go
	// ContainerID / ContainerClass / Unit describe the cgroup origin of
	// the process. ContainerClass is "container"|"user"|"system"|
	// "kernel"|"unknown" (cgroupclass.Class.String()); ContainerID is the
	// docker/containerd/cri-o id when ContainerClass=="container"; Unit is
	// the systemd unit. Recorded in the recent-events ring (NOT the FlowKey
	// — would explode cardinality and force a store-schema change).
	ContainerID    string
	ContainerClass string
	Unit           string
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/egressledger/ -run TestEvent_ContainerFields`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/egressledger/types.go pkg/egressledger/types_test.go
git commit -m "feat(egress): add container id/class/unit to ledger Event input"
```

### Task 2: Carry container fields through the recent-events ring

**Files:**
- Modify: `pkg/egressledger/recent.go:16-30` (ProcEvent struct) and the append site
- Test: `pkg/egressledger/recent_test.go`

- [ ] **Step 1: Write the failing test**

Append to `pkg/egressledger/recent_test.go`:

```go
func TestRecentRing_RetainsContainer(t *testing.T) {
	r := newRecentRing(8)
	r.append(ProcEvent{PID: 42, Comm: "curl", ContainerID: "abc123", ContainerClass: "container"})
	got := r.snapshot()
	if len(got) != 1 || got[0].ContainerID != "abc123" || got[0].ContainerClass != "container" {
		t.Fatalf("container fields lost through ring: %+v", got)
	}
}
```

NOTE: confirm the actual constructor/append/snapshot names in `recent.go` before running (they may be `newRecentRing`/`append`/`snapshot` or similar). Match the existing names exactly; do not rename.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/egressledger/ -run TestRecentRing_RetainsContainer`
Expected: FAIL — unknown fields on `ProcEvent`.

- [ ] **Step 3: Add fields to ProcEvent**

In `pkg/egressledger/recent.go`, add to `type ProcEvent struct` (after `SNI`):

```go
	ContainerID    string
	ContainerClass string
	Unit           string
```

No change needed to append/snapshot if they copy the whole struct by value (verify — if they copy field-by-field, add the three assignments).

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./pkg/egressledger/ -run TestRecentRing_RetainsContainer`
Expected: PASS.

- [ ] **Step 5: Wire Event→ProcEvent copy**

Find where `Observe` builds a `ProcEvent` from the incoming `Event` (grep `ProcEvent{` in `ledger.go`/`recent.go`). Add the three field copies:

```go
		ContainerID:    ev.ContainerID,
		ContainerClass: ev.ContainerClass,
		Unit:           ev.Unit,
```

- [ ] **Step 6: Run package tests + commit**

Run: `go test ./pkg/egressledger/`
Expected: PASS.

```bash
git add pkg/egressledger/recent.go pkg/egressledger/recent_test.go pkg/egressledger/ledger.go
git commit -m "feat(egress): retain container id/class/unit in recent-events ring"
```

### Task 3: Classify the process at the egress observe site

**Files:**
- Modify: `pkg/pipeline/pipeline.go` (struct field near other observer fields; observe site ~400-449)
- Test: `pkg/pipeline/pipeline_test.go`

- [ ] **Step 1: Add the classifier field**

In `pkg/pipeline/pipeline.go`, in the `Pipeline` struct, near `EgressLedger`/`DestClassifier`, add:

```go
	// ContainerClassifier resolves a pid's cgroup origin (container id /
	// systemd unit / class). Optional; nil = container fields left empty.
	ContainerClassifier *cgroupclass.Classifier
```

Add the import `"github.com/xhelix/xhelix/pkg/cgroupclass"` if not present.

- [ ] **Step 2: Write the failing test**

Append to `pkg/pipeline/pipeline_test.go` a test that builds a `Pipeline` with a stubbed `EgressLedger` capturing the last `Event`, sets `ContainerClassifier` to a classifier whose injected reader returns a docker cgroup line for the test pid, feeds an `ebpf.net` `net_connect` event, and asserts the captured `Event.ContainerID`/`ContainerClass` are set.

```go
func TestPipeline_StampsContainerOnEgress(t *testing.T) {
	cap := &captureLedger{} // implements the EgressLedger interface; stores last Observe arg
	cc := cgroupclass.NewWithReader(0, func(path string) ([]byte, error) {
		return []byte("0::/system.slice/docker-9f8e7d6c5b4a3210fedcba9876543210fedcba9876543210fedcba9876543210.scope\n"), nil
	})
	p := &Pipeline{EgressLedger: cap, ContainerClassifier: cc}
	p.Handle(model.Event{
		Sensor: "ebpf.net", PID: 1234, Comm: "curl",
		Tags: map[string]string{"kind": "net_connect", "dst_ip": "1.2.3.4", "dst_port": "443"},
	})
	if cap.last.ContainerClass != "container" || cap.last.ContainerID == "" {
		t.Fatalf("container not stamped: %+v", cap.last)
	}
}
```

NOTE: `cgroupclass.New` currently hardcodes `os.ReadFile`. This test needs an injectable reader. If `NewWithReader` does not exist, add it in Task 3a (below) before this test. Also confirm the ledger interface/`captureLedger` shape against existing pipeline tests and reuse any existing fake.

- [ ] **Step 2a (only if needed): expose an injectable-reader constructor**

In `pkg/cgroupclass/cgroupclass.go`, add (the `read` field already exists):

```go
// NewWithReader is New with an injectable file reader (for tests).
func NewWithReader(cap int, read func(string) ([]byte, error)) *Classifier {
	c := New(cap)
	if read != nil {
		c.read = read
	}
	return c
}
```

Commit this separately:
```bash
git add pkg/cgroupclass/cgroupclass.go
git commit -m "test(cgroupclass): add NewWithReader for injectable reads"
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./pkg/pipeline/ -run TestPipeline_StampsContainerOnEgress`
Expected: FAIL — container fields empty (not yet stamped).

- [ ] **Step 4: Stamp at the observe site**

In `pkg/pipeline/pipeline.go`, immediately before `p.EgressLedger.Observe(le)` (line ~449), add:

```go
				if p.ContainerClassifier != nil && ev.PID != 0 {
					ci := p.ContainerClassifier.Classify(ev.PID)
					le.ContainerID = ci.ContainerID
					le.ContainerClass = ci.Class.String()
					le.Unit = ci.Unit
				}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./pkg/pipeline/ -run TestPipeline_StampsContainerOnEgress`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/pipeline/pipeline.go pkg/pipeline/pipeline_test.go
git commit -m "feat(egress): classify container at egress observe site"
```

### Task 4: Construct + wire the classifier in the daemon

**Files:**
- Modify: `cmd/xhelix/run.go` (where the `Pipeline` is constructed and `EgressLedger`/`DestClassifier` are assigned)

- [ ] **Step 1: Construct and assign**

Find where the pipeline's egress fields are set in `cmd/xhelix/run.go` (grep `DestClassifier`). Add nearby:

```go
	containerClassifier := cgroupclass.New(0)
	pipe.ContainerClassifier = containerClassifier
```

(use the actual pipeline variable name). Add the import if missing.

- [ ] **Step 2: Best-effort cache eviction on process exit**

If the daemon has a proctree exit hook (grep `OnExit`/`OnProcExit` in `run.go`/`pkg/proctree`), add `containerClassifier.Forget(pid)` in that callback. If there is no such hook, SKIP — the LRU cap bounds memory; do not invent a new hook for this.

- [ ] **Step 3: Build**

Run: `make build`
Expected: builds `./xhelix` with no errors.

- [ ] **Step 4: Commit**

```bash
git add cmd/xhelix/run.go
git commit -m "feat(egress): wire container classifier into daemon pipeline"
```

### Task 5: Surface container in the egress UI / API

**Files:**
- Modify: the handler that renders the recent-events feed and `/api/egress` JSON (grep `ProcEvent`/`recent` in `ui/web/`)
- Test: existing UI handler test if present; otherwise a JSON-shape assertion

- [ ] **Step 1: Add fields to the JSON response struct**

In the UI handler that marshals recent events, add `ContainerID`, `ContainerClass`, `Unit` (json tags `container_id`, `container_class`, `unit`) to the response row struct and copy them from `ProcEvent`.

- [ ] **Step 2: Add a "Container" column / field to the rendered view**

In the recent-events table (and the IP-info drilldown's per-PID list), add a Container column that shows `ContainerID` (short, first 12 chars) when `ContainerClass=="container"`, else the `ContainerClass` token (`user`/`system`). Keep it responsive — see EO.7; for now a plain `<td>` that collapses on narrow screens is fine.

- [ ] **Step 3: Verify the JSON includes the fields**

Run (after a local non-root build; this exercises only the marshaling, not eBPF):
`go test ./ui/web/ -run Egress` (run whatever egress UI tests exist; if none assert JSON shape, add a minimal one).
Expected: PASS, JSON contains `container_class`.

- [ ] **Step 4: Commit**

```bash
git add ui/web/
git commit -m "feat(egress-ui): show container id/class in recent feed + drilldown"
```

### Task 6: Phase EO.1 RESULTS + live verification (PAUSE for consent)

**Files:**
- Create: `docs/superpowers/plans/2026-06-01-egress-observability-EO1-RESULTS.md`

- [ ] **Step 1: Full sweep**

Run: `make test && make vet && make static-check`
Expected: all green, binary statically linked.

- [ ] **Step 2: PAUSE — request explicit operator consent before any redeploy**

Live verification requires installing the new binary, which interrupts the running shadow soak (a hard-stop item). Do NOT `sudo install`/restart. Stop here and report: tests green, build static, and ask whether to (a) redeploy to dev box now to confirm a real docker container's egress shows its id, or (b) defer live check and continue to Phase EO.2 development off-box.

- [ ] **Step 3: After consent only — live check**

If approved: start a throwaway container (`docker run --rm -d alpine sh -c "while true; do wget -q -O- https://example.com; sleep 5; done"`), then confirm `/api/egress` recent feed shows that container's id on the example.com flows. Record the observed id + flow in the RESULTS doc. Then stop the throwaway container.

- [ ] **Step 4: Write RESULTS doc**

Document: fields added, files touched, tests added, the live observation (or that it was deferred), and the honest limit — **container id, not friendly name**; k8s pod name / docker name resolution is a separate optional online follow-up.

- [ ] **Step 5: Commit**

```bash
git add -f docs/superpowers/plans/2026-06-01-egress-observability-EO1-RESULTS.md
git commit -m "docs(egress): Phase EO.1 results — container naming wired"
```

---

## Phase EO.2–EO.7 specifications (detailed plans authored at phase start)

### EO.2 — Capture-loss honesty
Split `sensors/ebpf/backend_linux.go` `drops` counter into `ringbufOverflow`, `consumerFull`, `decodeError` (separate `atomic.Uint64`s); expose via the sensor `Health()` and a new `/api/egress/health` field; render a persistent UI banner when any nonzero in the last interval. Acceptance: a forced-overflow unit/integration test increments `ringbufOverflow`; banner shows; `Health()` reports the split. Honest framing: this does not prevent loss, it makes loss visible.

### EO.3 — Service-role / process-group classification
Add `service_role` (`web`/`db`/`cache`/`mail`/`ssh`/`proxy`/`other`) derived from listening ports + binary name + `parent_comm`; add `parent_comm` and `service_role` to `FlowKey`. **Store-schema change:** bump an egressledger store version constant; on version mismatch, start a fresh warm/cold generation and let the old data age out under existing retention (no in-place migration, no data destruction — old generation is read-only until it expires). Acceptance: classifier unit tests (nginx/apache→web, mysql/postgres→db, redis→cache, postfix→mail, sshd→ssh); live grouping works; old store data still queryable until retention expires, new data carries roles.

### EO.4 — IP intelligence depth
Bundle a static IP→ASN dataset (e.g. iptoasn.com TSV, ~a few MB) into the deb at `/usr/share/xhelix/ip2asn.tsv`; add `pkg/asnlookup` (sorted-range binary search, v4+v6) feeding org/ASN into `destclass` and the IP-info UI. Improve org/CDN attribution using ASN-org + existing CIDR/SNI. Add **optional** online reputation in `pkg/threatintel` (or a new `pkg/ipreputation`): config `Detection.OnlineReputation{Enabled bool (default false), Provider, APIKeyEnv}`; when disabled, **zero** external calls (assert in a test that the HTTP client is never invoked). When enabled, documented as sending dest IPs to a third party. Acceptance: ASN resolves offline for known ranges; flag-off no-call test passes; flag-on path tested against a mock server.

### EO.5 — Deep L7 / DPI protocol classification
Own detailed plan `docs/superpowers/plans/<date>-egress-dpi.md`. Scope: protocol identification beyond L4 — TLS (with ALPN/JA3-style fingerprint), HTTP/1.1, HTTP/2, QUIC, SSH, DNS, and a "tunnel/unknown-on-known-port" flag (e.g. non-TLS bytes on 443). Source bytes from the existing eBPF sendmsg/recvmsg payload capture + SSL uprobes; classifier runs at the observe site, result stored as `l7_protocol` on the flow. Honest framing up front: DPI on partial/encrypted payloads is heuristic; expect a measured FP/misclassification rate, reported on the corpus + live. This is the multi-week phase.

### EO.6 — Reverse-DNS use + cache
Add a bounded TTL PTR cache (replace the per-page-load `LookupAddr`); feed rDNS suffixes (e.g. `*.1e100.net`→Google, `*.cloudfront.net`→AWS CDN) into `destclass` as an additional org/CDN signal alongside CIDR/SNI/ASN. Acceptance: cache hit-rate measured; rDNS-suffix→org/CDN unit tests; no unbounded growth (LRU/TTL test).

### EO.7 — UI/UX reorganization + responsiveness
Reorganize the egress UI into clearly-labeled observability tabs, each answering one question: **Processes** (per-PID/binary), **Services** (by service_role, EO.3), **Users** (by UID), **Containers** (by container id/class, EO.1), **Protocols** (by l7_protocol, EO.5), **Destinations** (by IP/domain/org/ASN/CDN, EO.4/EO.6), **Timeline** (time-series), **Intel** (threat-intel + reputation hits). Fully responsive: verify usable layout at 360px (mobile), 768px (tablet), 1280px (desktop) — tables collapse to cards on narrow widths; no horizontal scroll traps; the capture-loss banner (EO.2) is visible on all widths. Acceptance: every field introduced in EO.1–EO.6 has a home in exactly one tab; manual responsive check at the three widths; no dead links/columns.

---

## Self-review notes
- **Spec coverage:** all six weak points map to EO.1–EO.6; UI requirement maps to EO.7. Capture-loss (EO.2) and the wire-format risk (EO.3) are explicitly handled.
- **Schema risk:** only EO.3 touches `FlowKey`; handled by version-bump + age-out, called out as a hard-stop requiring consent before redeploy.
- **Soak safety:** EO.1 Task 6 Step 2 is an explicit PAUSE before any redeploy; same gate applies to every phase.
- **No silent online calls:** EO.4 default-OFF asserted by test.
- **Type consistency:** `ContainerID`/`ContainerClass`/`Unit` used identically in Event (Task 1), ProcEvent (Task 2), observe-site stamping (Task 3), and UI (Task 5).

# Phase EO.1 — Container / Pod Naming — RESULTS

**Date:** 2026-06-01
**Branch:** `verdict-foundation`
**Plan:** `docs/superpowers/plans/2026-06-01-egress-observability-hardening.md`

## Headline

Egress flows now carry their **container origin**. Every outbound connection
observed by the eBPF net sensor is classified by `pkg/cgroupclass` at the
pipeline observe site and stamped with `ContainerID` / `ContainerClass` / `Unit`,
which survive into the recent-events ring and are surfaced in the egress web UI
(JSON + the historical-PID tables). This closes the "can't name which container
is sending traffic" gap — with one honest limit: it is the container **id**
(from the cgroup path), not the friendly docker/k8s **name** (that needs an
optional online resolver, deferred).

## What shipped (commits, in order)

| Commit | Task | Change |
|---|---|---|
| `4ea3892` | 1 | `ContainerID`/`ContainerClass`/`Unit` added to `egressledger.Event` (input only, NOT in FlowKey) |
| `327aa6d` | 2 | Same three fields retained through the recent-events ring (`ProcEvent` + `observeRecent` copy) |
| `50f2d31` | 3a | `cgroupclass.NewWithReader` injectable-reader constructor (for tests) |
| `ee78c08` | 3 | Pipeline stamps container origin at the egress observe site (reuses existing `CGroupClassifier`) |
| `4b06509` | 5 | Egress UI/JSON shows a "Container" column in the historical-PID tables (country + binary drilldowns) |

Task 4 (daemon wiring) required **no code**: the pipeline already had a
`CGroupClassifier` field constructed (`cgroupclass.New(0)`, run.go:1454),
assigned non-nil in the same struct literal as `EgressLedger` (run.go:3747/3784),
with a `Forget(pid)` exit hook already present (pipeline.go:785). Because Task 3
reused that field, container stamping is **live, not inert** — verified by
reading run.go.

## Acceptance gates

| Gate | Result |
|---|---|
| New unit tests green (egressledger, cgroupclass, pipeline, ui/web) | **PASS** — `go test -race` green on all four touched packages |
| `make vet` | **PASS** |
| `make static-check` | **PASS** — all binaries statically linked |
| `make build` | **PASS** |
| Container id appears on a real container's egress (live) | **DEFERRED** — requires redeploy, which interrupts the running soak; pending operator consent |

## Design notes / deviations

- **Reused `CGroupClassifier` instead of adding `ContainerClassifier`.** The plan
  proposed a new pipeline field; the implementer found an existing field of the
  exact type already used downstream for tag-stamping and reused it (DRY, single
  cache per pipeline). Approved.
- **Container fields are NOT in `FlowKey`.** They ride in the recent-events ring
  only. This was deliberate: adding them to the aggregation key would explode
  cardinality and force a storage-schema change. No schema change in EO.1.
- **Per-IP `/api/egress/ipinfo` page not updated.** It builds per-process activity
  from aggregated `FlowRecord` rows, which carry no container fields. Surfacing
  container there would need a new ledger query — out of EO.1 scope.

## Honest limits

1. **Container id, not friendly name.** We resolve the docker/containerd/cri-o id
   and the k8s cgroup path, not the human container/pod name. Name resolution
   (docker socket / k8s API) is an optional online follow-up, intentionally not
   built here.
2. **Live confirmation pending.** All evidence so far is unit-test + code-read
   level. The live "start a container, see its id on the example.com flows" check
   is deferred to avoid interrupting the verdict-engine shadow soak.

## Pre-existing issue found (NOT caused by EO.1) — follow-up

`pkg/egressledger` has flaky time-boundary tests: `TestHotRingObserveMerges` and
`TestLedgerObserveQueryLive` use `time.Now()` with second offsets that occasionally
straddle a minute/bucket edge, producing 2 rows where 1 is expected. Confirmed
flaky on the clean parent `ac179f6` (independent of EO.1): the failing test passed
5/5 on the EO.1 tree and 3/3 on the parent across repeated runs. Recommend a
follow-up that injects a fixed clock into these tests. Logged here, not fixed
(out of EO.1 scope).

## Next

- **Decision pending:** redeploy to dev box for the live container check now (interrupts soak), or defer and proceed to Phase EO.2 (capture-loss honesty) development off-box.

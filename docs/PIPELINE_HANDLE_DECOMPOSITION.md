# Decomposing Pipeline.Handle() — P-RF.8

`pkg/pipeline/pipeline.go`'s `Handle()` is ~2000 lines in a single method
(line 393+). It is the per-event dispatcher: every `model.Event` flows
through it. The size makes it impossible to unit-test a phase in isolation
and hard to reason about locally — a bug anywhere needs a full-pipeline
E2E test to catch.

P-RF.8 decomposes it **incrementally, behaviour-preserving**, one phase at
a time, each extraction landing with its own unit test. This is the
deliberate "highest-risk-first" approach chosen over a single big-bang
rewrite (which would need a golden-corpus replay harness before it could
be trusted).

## The pattern (template for each extraction)

1. Pick a phase of `Handle()` with a **clean seam**: it reads `ev` (and a
   small, explicit set of `p.*` collaborators) and produces a side effect
   or an enrichment, with no control-flow entanglement with later phases.
2. Move the block verbatim into `func (p *Pipeline) <phaseName>(ev model.Event, …)`.
   Keep the nil-guards; convert the outer `if cond { … }` wrapper into an
   early `return` at the top of the method so the call site is a bare
   `p.<phaseName>(ev)`.
3. Replace the inline block with the method call + a one-line comment
   pointing here.
4. Add a unit test (`pipeline_phases_test.go`) that pins the block's prior
   behaviour: the happy path, every nil/short-circuit guard, and each
   drop/skip branch. Construct a minimal `&Pipeline{<onlyTheNeededField>: …}`.
5. `go test -race ./pkg/pipeline/` stays green. No behaviour change.

## Done

| Phase | Method | Test | Notes |
|---|---|---|---|
| TLS-L2 plaintext capture | `observeTLSPlaintext` | `pipeline_phases_test.go` | First extraction. Self-contained, nil-safe, depends only on `p.TLSPlaintext`. Chosen first because it's a high-risk feature (captures plaintext) and had the cleanest seam. |

## Candidate next phases (seam quality, easiest → hardest)

Ordered by coupling — lower coupling extracts more safely:

1. **Egress-ledger enrichment** (`ev.Sensor == "ebpf.net"`, ~line 423+).
   Larger, but a single `if` block. Depends on `EgressLedger`,
   `DestClassifier`, `CGroupClassifier`, `ProcTree`, `ConnTable`. Each is
   nil-safe; extract as `recordEgressFlow(ev)` and test with real
   classifiers (cheap to construct) or nil ones for the drop paths.
2. **Phase H.1 rolling byte counter** (line ~980) and **Phase H.2
   long-window recorder** (line ~1287) — already factored as helpers with
   "Nil-safe" contracts; promoting their call sites into named phases is
   low-risk.
3. **Rule-evaluation + correlation dispatch** — the core; extract only
   after the surrounding enrichment phases are out, so its inputs are
   explicit. Highest coupling; do last and consider the golden-corpus
   replay harness before touching it.

## Guardrails

- **No behaviour change per extraction.** If a phase needs to *also* be
  reordered or fixed, do that in a *separate* commit after the pure move,
  so a regression is bisectable to the behaviour change, not the move.
- **One phase per commit.** Keeps each diff reviewable and each extraction
  independently revertible.
- Do **not** attempt the full rewrite in one pass — that path needs a
  replay harness that does not exist yet.

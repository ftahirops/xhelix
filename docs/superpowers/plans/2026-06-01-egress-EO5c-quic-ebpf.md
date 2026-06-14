# Phase EO.5c — QUIC + Raw-Payload eBPF Capture Implementation Plan

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development (FULL review). This phase adds NEW in-kernel eBPF on the hot path — highest risk in the egress work.

**Goal:** Confirm QUIC (vs other UDP/443) and capture the first bytes of raw TCP payloads on unknown ports, so `l7_protocol` reflects wire reality instead of port guesses — behind a config flag, default OFF, validated on the soak before it ever counts.

**Feasibility (verified 2026-06-01):** the build toolchain is present and works — `make vmlinux` regenerated `vmlinux.h` (150,631 lines from `/sys/kernel/btf/vmlinux`) and `make ebpf` compiled `all.bpf.c` to a valid eBPF object. So eBPF changes can be COMPILE-verified here. Runtime verifier acceptance + perf, however, require LOADING the program (a daemon run) — that is the deploy-gated validation, not something a compile proves.

**Hard honesty (the cost you accepted):**
- Reading the UDP payload in `kprobe/udp_sendmsg` means walking `struct msghdr` → `msg_iter` → user iov base. The `iov_iter` layout is **kernel-version-sensitive**; this is the fiddly, verifier-sensitive crux and may take several compile→load→verify iterations.
- New hot-path code touches every UDP send. It MUST be measured (overhead + the EO.2 drop counters) and ships **default-off** until the soak shows it's safe.
- This delivers **nothing observable** until enabled + validated. It is real multi-session kernel work.

**Architecture:** Extend `kprobe/udp_sendmsg` to peek the first 5 payload bytes for dst-port-443 UDP only, set a `quic_confirmed` bit (long-header high bit 0x80 + a known QUIC version word) on the existing net event. A new config flag `Sensors.DPI.DeepCapture` (default false) gates whether the loader attaches the peek variant. `l7proto.Classify` already returns `quic` for UDP/443; EO.5c upgrades that from a port guess to a confirmed signal and lets us distinguish `quic` from `udp-other`. The raw-TCP-payload capture (unknown-port cleartext) is a SECOND, separately-gated step after QUIC lands.

**Tech:** eBPF C (GPL-2.0, `sensors/ebpf/progs/all.bpf.c`), `make ebpf`, `sensors/ebpf/decoder.go`, `sensors/ebpf/backend_linux.go` (program attach), `pkg/config`, `pkg/l7proto`, `pkg/pipeline`.

---

## EO5c-T1: config flag + classifier readiness (NO eBPF yet — safe, fully testable)

**Files:** `pkg/config/config.go`, `pkg/l7proto/l7proto.go` (+ tests)

- Add `Sensors.DPI.DeepCapture bool` (default false) — gates the eBPF payload peek. (Confirm the DPI sensor config struct location; add the field + default + any normalize.)
- Add a `ProtoUDPOther Proto = "udp-other"` and split the classifier: today UDP/443 → `quic` (port guess). Change `Classify` so UDP/443 returns `quic` ONLY when a new `Signals.QUICConfirmed bool` is set; otherwise `udp-other`. UDP/53 stays `dns`. This makes the label honest: `quic` means confirmed, not guessed.
- Update `l7proto_test.go`: `quic-udp443-confirmed` (QUICConfirmed=true → quic), `udp443-unconfirmed` (false → udp-other).
- Build + test. Commit: `feat(l7proto): gate quic on confirmed signal; add DeepCapture flag (default off)`
- **Zero eBPF risk** — this is pure Go + config, safe to ship immediately.

## EO5c-T2: eBPF UDP payload peek (COMPILE-verified here; runtime gated)

**Files:** `sensors/ebpf/progs/all.bpf.c`, `sensors/ebpf/decoder.go`, tests

- In `kprobe/udp_sendmsg` (PARM2 = `struct msghdr *msg`): when the dst port is 443, read the first 5 payload bytes from `msg->msg_iter` user iov base via `BPF_CORE_READ` + `bpf_probe_read_user`. Guard everything (null checks, `iter_type`, count) for the verifier. Set a `quic` bit in the net event when `head[0] & 0x80` (long header) AND the 4-byte version at head[1..4] is a known QUIC version (`0x00000001` v1, `0x6b3343cf` v2, or draft/`0xff0000xx`). Reuse the `xh_emit_net_bytes` event; add a `quic` flag field in a reserved/_pad byte (no wire-format break — use an existing pad).
- Decoder: read the new flag; set `ev.Tags["quic_confirmed"]="1"` when set.
- `make ebpf` MUST compile clean. Add a Go decoder unit test for the new flag byte.
- Commit: `feat(ebpf): peek QUIC long-header on udp/443 send, emit quic_confirmed (gated)`
- **Stop point:** this compiles but is NOT proven to pass the kernel verifier or to be perf-safe — that is EO5c-T4.

## EO5c-T3: attach gating + wire quic_confirmed into l7proto

**Files:** `sensors/ebpf/backend_linux.go`, `pkg/pipeline/pipeline.go`

- The loader attaches the udp peek only when `DeepCapture` is true (otherwise the existing byte-only udp_sendmsg path). If splitting the program is impractical, compile the peek in but make it a no-op early-return unless a BPF map flag set from userspace by config — pick the simpler verifier-friendly option and document it.
- Pipeline observe: set `Signals.QUICConfirmed = ev.Tags["quic_confirmed"]=="1"`.
- Build + pipeline test (quic_confirmed tag → l7_protocol "quic"; absent → "udp-other"). Commit.

## EO5c-T4: load + verifier + perf validation (DEPLOY-GATED — explicit consent)

- On the dev box, with `DeepCapture=true`: confirm the program LOADS (runtime verifier passes), generate QUIC traffic (curl --http3 / a browser) and confirm `quic_confirmed` flows; generate non-QUIC UDP/443 and confirm it does NOT.
- Measure: hot-path overhead (before/after) and the EO.2 drop counters under load — must not regress.
- Only after this passes does `DeepCapture` become a recommended setting; prod stays off until separately approved.
- RESULTS doc with measured accuracy + overhead. This step REQUIRES the operator to approve a redeploy.

## EO5c-T5 (optional, separate): raw TCP first-payload for unknown-port cleartext
Deferred sub-step: peek first bytes of `tcp_sendmsg` for connections NOT on a known port and NOT TLS, to label cleartext protocols / `raw-tunnel`. Same risk profile; only after QUIC (T1-T4) is validated and if still wanted.

## Self-review / guardrails
- Default OFF (`DeepCapture=false`) → byte-for-byte current behavior; T1 makes `quic` honest (confirmed-only) even with the flag off (UDP/443 becomes `udp-other` rather than a false `quic`).
- eBPF compiles here; runtime verifier + perf are explicitly deploy-gated (T4), not claimed by compilation.
- No wire-format break — the quic flag rides an existing pad byte.
- This is the high-risk phase; every eBPF step is `make ebpf`-verified and the load/perf step needs consent.

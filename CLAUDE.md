# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

See [AGENTS.md](AGENTS.md) for the canonical contributor guide — it covers build commands, project layout, architecture notes, and what's wired vs. only present in code. Read it before making non-trivial changes. The notes below are a Claude-Code-specific addendum.

## Host context (durable)

- **This machine IS the dev box `135.181.79.27`.** Local commands operate directly on it — do NOT use ssh / scp to reach the dev box. `sudo systemctl …`, `sudo cp … /usr/local/bin/`, deb installs all run locally here.
- **Production is `65.108.246.67` — never touched** unless the user explicitly says "deploy to prod" in the current message. The dev/prod split is by IP, not by hostname.
- Daemon binaries live at `/usr/local/bin/{xhelix,xhelixctl,xhelix-verify}`; state at `/var/lib/xhelix/`; logs at `/var/log/xhelix/`; config at `/etc/xhelix/xhelix.yaml`; service unit `xhelix.service`.

## Common commands

```bash
make build          # CGO_ENABLED=0, produces ./xhelix, ./xhelixctl, ./xhelix-verify
make test           # go test -race -count=1 ./...
make vet            # go vet ./...
make static-check   # asserts ./xhelix and ./xhelix-verify are statically linked
make deb            # build dist/xhelix_*.deb (and xhub deb)
make ebpf           # compile sensors/ebpf/progs/all.bpf.c → xhelix-progs.o (needs clang + libbpf-dev)
make vmlinux        # regenerate vmlinux.h from running kernel BTF (rerun after kernel upgrades)
```

Single test: `go test -race -run TestName ./pkg/<dir>/`. There is no golangci-lint or pre-commit; CI is just `vet → test -race → build → static-check`.

Local runs that need no root: `./xhelix version`, `./xhelix tui`, `./xhelixctl rules lint`, `./xhelixctl posture lsm`, `./xhelix-verify --chain DIR --pub KEY`. The full agent (`sudo ./xhelix run --config examples/...yaml`) needs `/var/lib/xhelix`, `/var/log/xhelix`, `/run/xhelix` to exist.

## Architecture (big picture)

Single static Go binary EDR. No agent/manager split — one daemon (`xhelix`), one operator CLI (`xhelixctl`), one standalone chain verifier (`xhelix-verify`), plus an optional fleet baseline hub (`xhub`, under `cmd/xhub/`). The daemon composes three layers:

1. **Sensors** (`sensors/`) — each implements `sensors.Sensor` (Name/Start/Stop/Health) and emits `model.Event` over a channel. Started/wired in `cmd/xhelix/run.go`. eBPF, FIM, decoy, netids, identity, memory, lsmaudit are all instantiated. Linux-specific code is split via build tags (`backend_linux.go` vs `backend_stub.go`; same pattern in `sensors/decoy/atime_*.go` and `pkg/enforce/signals_*.go`) — preserve this when touching those packages, or non-Linux builds break.

2. **Pipeline** (in `cmd/xhelix/run.go`'s dispatch loop) — every event flows through ProcTree ancestry enrichment (`pkg/proctree/`), ImageCache SHA-256 enrichment (`pkg/imagecache/`), the CEL rule engine (`pkg/rules/engine.go`, rules in `ruleset/core/*.yaml`), and the correlator (`pkg/correlator/engine.go`, **deterministic single-goroutine for replayability** — don't parallelize). Matches become alerts on the alert bus (`pkg/alert/`).

3. **Response / persistence** — alerts can trigger `pkg/response/`, `pkg/enforce/` (Soak gate, PanicSwitch, Quarantine), `pkg/remediate/`, `pkg/netban/`. Events are batched, Ed25519-signed, and hash-chained by `pkg/chain/`; `cmd/xhelix-verify` re-walks the chain offline and names the exact tampered batch. Hot store is SQLite via `modernc.org/sqlite` (CGO-free — required, see constraint below).

Baseline subsystem (`pkg/baseline/` + `pkg/baselinehub/` + `cmd/xhub/`): per-binary hourly feature aggregates (syscalls, children, endpoints, file_writes) with set-diff + EWMA scoring; agents optionally upload to `xhub` for cross-host rare-endpoint detection.

Config (`pkg/config/config.go`): single YAML merged over `Default()`. Missing file is **not** an error. Presets (desktop/server/container-host) applied post-load via `ApplyPreset()`.

Version (`pkg/version/version.go`): `Version`/`Commit` are injected via Makefile ldflags — editing source values won't stick.

## Hard constraints (don't break these)

- **CGO_ENABLED=0** always. Binary must stay statically linked (`make static-check` enforces). No C deps — that's why SQLite is `modernc.org/sqlite`, not `mattn/go-sqlite3`.
- **Linux-only runtime.** Non-Linux code paths exist only to keep `go build` green on dev machines; gate Linux-specific code with `//go:build linux` and provide a stub.
- **Module path** `github.com/xhelix/xhelix`. go.mod is Go 1.23; CI builds on Go 1.22 — avoid 1.23-only stdlib APIs.
- **Apache-2.0** for Go code; **eBPF C programs under `sensors/ebpf/progs/` are GPL-2.0** (kernel ABI requirement) — don't relicense.
- Kernel ≥ 5.15 at runtime for eBPF; BPF LSM needs `lsm=...,bpf` on kernel cmdline.

## eBPF specifics

The 8 eBPF C programs in `sensors/ebpf/progs/` are **not** built by `make build`. Use `make ebpf` (clang + libbpf-dev) to produce `xhelix-progs.o`; the deb ships it to `/usr/lib/xhelix/xhelix-progs.o` and the loader (`sensors/ebpf/backend_linux.go`) loads it at runtime via `cilium/ebpf`.

## Working agreement

These four rules apply to every interaction in this repo. They override default helpfulness instincts where they conflict.

### 1. The four discipline rules (Karpathy)

1. **Ask, don't assume.** If something is unclear — intent, architecture, the right place to put code — ask before writing a single line. Never make silent assumptions.
2. **Simplest solution first.** Implement the simplest thing that could work. Do not add abstractions, flexibility, configuration, or layers that were not explicitly requested.
3. **Don't touch unrelated code.** If a file or function is not directly part of the current task, do not modify it, rename it, reorder it, or "improve" it. If you notice something worth fixing, mention it in a closing note. Do not act on it.
4. **Flag uncertainty explicitly.** If you are not sure about a fact, an API surface, a performance number, a behavior of the runtime, say so before stating it. Confidence without certainty has cost real time in this project (see ERRORS.md).

### 2. Hard stops — these actions require explicit "yes" in the current message

Stop, list what will be affected, and wait for confirmation before:

- `sudo systemctl stop/start/restart xhelix` or any other service unit
- `sudo cp` into `/usr/local/bin/`, `/usr/local/sbin/`, `/usr/share/`, `/etc/xhelix/`
- `git push`, `git push --force`, `git reset --hard`, branch deletion
- `sudo apt`, `dpkg -i`, package install/remove
- Schema or data migrations (sqlite, etc.) on `/var/lib/xhelix/*.db`
- Editing `/etc/systemd/system/xhelix.service*` or its drop-ins
- Truncating, rotating, or deleting files under `/var/log/xhelix/`
- Anything that touches state outside the repo working tree

User confirmation in a *previous* message is not sufficient — re-confirm in the current turn.

### 3. Options before significant work

Before any task that:

- Introduces a new package, dependency, or sub-binary
- Affects more than three files
- Changes a public API or wire format
- Touches the dispatch loop in `cmd/xhelix/run.go`
- Adds a new sensor or response action

…present 2-3 approaches with honest tradeoffs (cost, FP risk, perf impact, maintenance burden), wait for a choice, and only then implement.

This does not apply to small follow-ons inside an already-chosen plan.

### 4. ERRORS.md — record bugs that cost time

There is an `ERRORS.md` at repo root. When an approach takes more than 2 attempts to work, or when a "should have been obvious" detail bites, log an entry:

- What didn't work
- What worked instead
- Note for next time

Check ERRORS.md before suggesting approaches in adjacent areas.

### Behavior I should default to

- **Show what changed at end of every coding turn**: files touched (one line each), files intentionally not touched, follow-ups.
- **Verify before claiming success**: actual test output, actual live API response, actual git log, not just "it should work".
- **Honest non-promises**: when a design has a known limit (false positives, scale ceiling, edge case), say so up front, not after operators trip on it.

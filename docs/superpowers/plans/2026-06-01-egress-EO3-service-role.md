# Phase EO.3 — Service-Role Classification Implementation Plan

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Checkbox steps.

**Goal:** Let an operator group/filter egress by what a process IS (web / database / cache / broker / proxy / mail / dns / ssh / other), and record each flow's parent process name — closing the "no service role, can't tell web from DB, can't tell sshd-spawned shell from standalone curl" gap.

**Architecture (per operator decisions):**
- **Rich roles, seeded from appident.** A new pure `pkg/servicerole` classifier maps a process to a role using a known-binary table (primary), with `appident.Kind` (web/service/cli/background/container) and listening-port as weaker fallbacks. Unknown → `other` (honest).
- **Enrichment ALONGSIDE the key, not IN it.** `ServiceRole` and `ParentComm` are added to `egressledger.Event` (input), to `FlowMetrics` (descriptive, last-observed — written into the gob value and parquet, so historical aggregates can group by role), and to the recent-ring `ProcEvent` (per-event fidelity). They are **NOT** added to `FlowKey` — so the fixed 46-byte warm key encoder is untouched, gob values stay backward-decodable, and parquet just gains nullable columns. **No destructive migration; old data ages out / reads zero-filled.**

**Tech Stack:** Go 1.22 CGO=0; new `pkg/servicerole`; `pkg/egressledger` (types/warm gob/cold parquet/recent/query); `pkg/pipeline` (observe site + parent_comm derivation ordering); `pkg/appident` (Kind hint); `ui/web`.

**Honest scope notes:**
- Service role is a heuristic over known binaries; unknown binaries are `other`, not guessed. The known-binary table is the accuracy ceiling and is explicitly enumerated.
- `FlowMetrics.ServiceRole`/`ParentComm` are "last observed for this key." Because the key already pins (binary, uid, cgroup), role is stable; parent_comm is usually stable but documented as last-observed.
- parent_comm at the egress observe site is derived from proctree at write time (today it is only derived later in the LOTL block); EO3-T4 makes it available before Observe.

---

## Task EO3-T1: pkg/servicerole pure classifier

**Files:**
- Create: `pkg/servicerole/servicerole.go`
- Test: `pkg/servicerole/servicerole_test.go`

- [ ] **Step 1 — failing test.** Create `pkg/servicerole/servicerole_test.go`:
```go
package servicerole

import "testing"

func TestClassify_KnownBinaries(t *testing.T) {
	cases := []struct {
		bin, comm, appKind string
		listenPort         uint16
		want               Role
	}{
		{"/usr/sbin/nginx", "nginx", "", 0, RoleWeb},
		{"/usr/sbin/apache2", "apache2", "", 0, RoleWeb},
		{"/usr/bin/caddy", "caddy", "", 0, RoleWeb},
		{"/usr/sbin/mysqld", "mysqld", "", 0, RoleDatabase},
		{"/usr/lib/postgresql/16/bin/postgres", "postgres", "", 0, RoleDatabase},
		{"/usr/bin/mongod", "mongod", "", 0, RoleDatabase},
		{"/usr/bin/redis-server", "redis-server", "", 0, RoleCache},
		{"/usr/bin/memcached", "memcached", "", 0, RoleCache},
		{"/usr/sbin/rabbitmq-server", "beam.smp", "", 0, RoleBroker},
		{"/usr/sbin/haproxy", "haproxy", "", 0, RoleProxy},
		{"/usr/sbin/sshd", "sshd", "", 0, RoleSSH},
		{"/usr/lib/postfix/sbin/master", "master", "", 0, RoleMail},
		{"/usr/sbin/named", "named", "", 0, RoleDNS},
		{"/opt/app/server", "server", "web", 0, RoleWeb},        // appKind fallback
		{"/usr/bin/python3", "python3", "service", 0, RoleOther}, // unknown + service kind -> other
		{"/usr/bin/curl", "curl", "", 0, RoleOther},
	}
	for _, c := range cases {
		if got := Classify(c.bin, c.comm, c.appKind, c.listenPort); got != c.want {
			t.Errorf("Classify(%q,%q,%q,%d)=%q want %q", c.bin, c.comm, c.appKind, c.listenPort, got, c.want)
		}
	}
}

func TestClassify_PortFallback(t *testing.T) {
	// unknown binary, but listening on a well-known service port
	if got := Classify("/opt/x/db", "db", "", 3306); got != RoleDatabase {
		t.Errorf("port 3306 fallback = %q want database", got)
	}
	if got := Classify("/opt/x/srv", "srv", "", 6379); got != RoleCache {
		t.Errorf("port 6379 fallback = %q want cache", got)
	}
}
```

- [ ] **Step 2 — run, expect FAIL** (package/symbols undefined): `go test ./pkg/servicerole/`.

- [ ] **Step 3 — implement** `pkg/servicerole/servicerole.go`:
```go
// Package servicerole classifies a process into a coarse service role
// (web/database/cache/...) for grouping egress traffic. It is a pure,
// table-driven heuristic: a known-binary basename map is the primary
// signal, with the appident Kind hint and the process's listening port
// as weaker fallbacks. Unknown processes are RoleOther — never guessed.
package servicerole

import (
	"path/filepath"
	"strings"
)

type Role string

const (
	RoleWeb      Role = "web"
	RoleDatabase Role = "database"
	RoleCache    Role = "cache"
	RoleBroker   Role = "broker"
	RoleProxy    Role = "proxy"
	RoleMail     Role = "mail"
	RoleDNS      Role = "dns"
	RoleSSH      Role = "ssh"
	RoleOther    Role = "other"
)

// byBinary maps a known process/binary basename to a role. This table is
// the accuracy ceiling; extend it as new services are encountered.
var byBinary = map[string]Role{
	"nginx": RoleWeb, "apache2": RoleWeb, "httpd": RoleWeb, "caddy": RoleWeb,
	"lighttpd": RoleWeb, "traefik": RoleWeb, "node": RoleWeb, "gunicorn": RoleWeb, "uwsgi": RoleWeb,
	"mysqld": RoleDatabase, "mariadbd": RoleDatabase, "postgres": RoleDatabase,
	"mongod": RoleDatabase, "clickhouse-serv": RoleDatabase, "influxd": RoleDatabase,
	"redis-server": RoleCache, "memcached": RoleCache,
	"beam.smp": RoleBroker, "rabbitmq-server": RoleBroker, "kafka": RoleBroker, "nats-server": RoleBroker,
	"haproxy": RoleProxy, "envoy": RoleProxy, "squid": RoleProxy,
	"master": RoleMail, "smtpd": RoleMail, "dovecot": RoleMail, "exim4": RoleMail,
	"named": RoleDNS, "unbound": RoleDNS, "dnsmasq": RoleDNS, "coredns": RoleDNS,
	"sshd": RoleSSH,
}

// byPort is the weak fallback when the binary is unknown.
var byPort = map[uint16]Role{
	80: RoleWeb, 443: RoleWeb, 8080: RoleWeb, 8443: RoleWeb,
	3306: RoleDatabase, 5432: RoleDatabase, 27017: RoleDatabase,
	6379: RoleCache, 11211: RoleCache,
	5672: RoleBroker, 9092: RoleBroker,
	25: RoleMail, 587: RoleMail, 993: RoleMail,
	53: RoleDNS, 22: RoleSSH,
}

// Classify returns the service role for a process. binaryPath/comm identify
// the binary; appKind is the appident Kind hint ("web"/"service"/...);
// listenPort is the process's listening port (0 if unknown / not a server).
func Classify(binaryPath, comm, appKind string, listenPort uint16) Role {
	base := comm
	if binaryPath != "" {
		base = filepath.Base(binaryPath)
	}
	if r, ok := byBinary[base]; ok {
		return r
	}
	if comm != "" {
		if r, ok := byBinary[comm]; ok {
			return r
		}
	}
	// appident Kind hint: only "web"/"container" map cleanly to a role here;
	// "service"/"cli"/"background" are too coarse to call database vs cache.
	if strings.EqualFold(appKind, "web") {
		return RoleWeb
	}
	if listenPort != 0 {
		if r, ok := byPort[listenPort]; ok {
			return r
		}
	}
	return RoleOther
}
```

- [ ] **Step 4 — run, expect PASS:** `go test ./pkg/servicerole/`.
- [ ] **Step 5 — commit.**
```bash
git add pkg/servicerole/
git commit -m "feat(servicerole): pure binary/port/appkind service-role classifier"
```

## Task EO3-T2: add ServiceRole + ParentComm to Event, FlowMetrics, ProcEvent (NOT FlowKey)

**Files:**
- Modify: `pkg/egressledger/types.go` (Event struct; FlowMetrics struct — NOT FlowKey)
- Modify: `pkg/egressledger/recent.go` (ProcEvent struct + observeRecent copy)
- Modify: `pkg/egressledger/hot.go` (where FlowMetrics is updated on Observe — set the descriptive fields)
- Test: `pkg/egressledger/types_test.go` + `recent_test.go`

- [ ] **Step 1 — failing test** (append to `pkg/egressledger/types_test.go`):
```go
func TestEvent_ServiceRoleParentComm(t *testing.T) {
	e := Event{ServiceRole: "database", ParentComm: "systemd"}
	if e.ServiceRole != "database" || e.ParentComm != "systemd" {
		t.Fatalf("fields not retained: %+v", e)
	}
	var m FlowMetrics
	m.ServiceRole = "web"
	m.ParentComm = "sshd"
	if m.ServiceRole != "web" || m.ParentComm != "sshd" {
		t.Fatalf("metrics fields not retained: %+v", m)
	}
}
```

- [ ] **Step 2 — run, expect FAIL.**

- [ ] **Step 3 — implement.**
  - In `types.go`, add to `Event` (after `Comm`/container fields): `ServiceRole string` and `ParentComm string` with a comment that they are descriptive enrichment, NOT part of FlowKey.
  - In `types.go`, add to `FlowMetrics`: `ServiceRole string` and `ParentComm string` with a comment "last observed for this key (descriptive; key already pins binary/uid/cgroup)".
  - **Do NOT touch `FlowKey`.**
  - In `hot.go`, where the per-bucket `FlowMetrics` is updated from the incoming `Event` (the merge site that does `m.BytesOut += ...`), set `m.ServiceRole = ev.ServiceRole` and `m.ParentComm = ev.ParentComm` (last-observed wins; only overwrite when the incoming value is non-empty so a later blank doesn't erase a known value).

- [ ] **Step 4 — recent ring** (`recent.go`): add `ServiceRole string` and `ParentComm string` to `ProcEvent` (after the container fields from EO.1) and copy them in `observeRecent`'s `push(ProcEvent{...})` from `ev.ServiceRole`/`ev.ParentComm`. Append a recent_test.go case asserting they survive a push→snapshot round-trip.

- [ ] **Step 5 — run all:** `go test ./pkg/egressledger/`. PASS.

- [ ] **Step 6 — commit.**
```bash
git add pkg/egressledger/types.go pkg/egressledger/hot.go pkg/egressledger/recent.go pkg/egressledger/types_test.go pkg/egressledger/recent_test.go
git commit -m "feat(egress): carry service_role + parent_comm as flow enrichment (not in key)"
```

## Task EO3-T3: persist service_role + parent_comm in warm (gob) + cold (parquet)

**Files:**
- Modify: `pkg/egressledger/cold.go` (parquetRow struct + recordToRow + rowToRecord)
- (warm.go needs NO change for the value: `encodeValue` gob-encodes the whole `FlowRecord` incl. `Metrics`, so the new Metrics fields ride automatically — VERIFY and add a round-trip test rather than editing the encoder)
- Test: `pkg/egressledger/cold_test.go` (or existing) + a warm round-trip test

- [ ] **Step 1 — failing test (cold round-trip).** Add a test that builds a `FlowRecord` with `Metrics.ServiceRole="database"`, `Metrics.ParentComm="sshd"`, writes it via the cold-store write path, reads it back, and asserts both survive. Model on existing cold-store tests. Also add a warm round-trip test (encodeValue→decodeValue) asserting the two Metrics fields survive.

- [ ] **Step 2 — run, expect FAIL** (parquet has no such columns yet; warm test should actually PASS already — if so, keep it as a regression guard and note that warm needed no change).

- [ ] **Step 3 — implement cold.** In `cold.go`:
  - Add to `parquetRow`: `ServiceRole string `parquet:"service_role,zstd"`` and `ParentComm string `parquet:"parent_comm,zstd"``.
  - In `recordToRow` (Record→parquetRow), set them from `r.Metrics.ServiceRole`/`r.Metrics.ParentComm`.
  - In `rowToRecord` (parquetRow→Record), set `Metrics.ServiceRole`/`Metrics.ParentComm` from the row (old files lacking the columns zero-fill to "", which is correct).

- [ ] **Step 4 — run all:** `go test ./pkg/egressledger/`. PASS. Confirm the old-file tolerance by a test that reads a parquetRow with the fields empty.

- [ ] **Step 5 — commit.**
```bash
git add pkg/egressledger/cold.go pkg/egressledger/cold_test.go pkg/egressledger/warm_test.go
git commit -m "feat(egress): persist service_role + parent_comm in cold parquet (warm gob auto-carries)"
```

## Task EO3-T4: classify + stamp at the egress observe site

**Files:**
- Modify: `pkg/pipeline/pipeline.go` (egress observe block ~397-459; ensure parent_comm derived before it)
- Modify: `cmd/xhelix/run.go` (construct/wire the servicerole classifier + listening-port source if needed — reuse the existing listen-port cache if accessible)
- Test: `pkg/pipeline/egress_servicerole_test.go`

- [ ] **Step 1 — read** the observe block and the existing parent_comm derivation (LOTL block ~737-756) and the listening-port cache in `recent.go` (`inferRole`/listen cache). Decide the minimal way to (a) have `parent_comm` available before Observe and (b) get a listening port for the pid (optional — pass 0 if not readily available; the binary table is the primary signal).

- [ ] **Step 2 — failing test.** In `pkg/pipeline/egress_servicerole_test.go`, build a Pipeline with a real ledger (as in `egress_container_test.go`), feed an `ebpf.net` net_connect event for a process whose `Image` is `/usr/sbin/mysqld` (comm `mysqld`), and assert the recorded flow (via `QueryRecent`) has `ServiceRole=="database"`. Also assert `ParentComm` is populated when the event carries a parent (set `ev.Tags["parent_comm"]` or a ParentPID with a stubbed proctree, matching how the container test stubs deps).

- [ ] **Step 3 — run, expect FAIL.**

- [ ] **Step 4 — implement.** In the egress observe block, before `p.EgressLedger.Observe(le)`:
  - Ensure `parentComm` is available: reuse `ev.Tags["parent_comm"]` if set, else derive via the same `proctree.Ancestors(ev.ParentPID, 1)` call the LOTL block uses (guard nil proctree). Set `le.ParentComm`.
  - Compute role: `le.ServiceRole = string(servicerole.Classify(le.Binary, le.Comm, ev.Tags["app_id_kind"], 0))` — use whatever appident-kind tag exists (confirm the exact tag key during step 1; if none is readily available at this point, pass "" — the binary table still classifies known services). Listening port may be 0 unless cheaply available.
  - Use a `p.ServiceRoleClassifier`-style hook only if construction needs config; since `servicerole.Classify` is a pure func, prefer calling it directly (no new pipeline field) unless the team prefers a field for testability — keep it simplest.
- In `run.go`, no wiring needed if `Classify` is called directly. If a listening-port lookup is wired, reuse the existing cache; do not build a new one.

- [ ] **Step 5 — run:** `go test ./pkg/pipeline/`; `go build ./...`. PASS.

- [ ] **Step 6 — commit.**
```bash
git add pkg/pipeline/pipeline.go cmd/xhelix/run.go pkg/pipeline/egress_servicerole_test.go
git commit -m "feat(egress): classify service_role + stamp parent_comm at observe site"
```

## Task EO3-T5: query filter + UI surfacing

**Files:**
- Modify: `pkg/egressledger/query.go` + `types.go` `FlowFilter` (add a `ServiceRole string` filter; empty = any)
- Modify: `ui/web` egress handlers/JS (show ServiceRole + ParentComm columns; allow grouping/filtering by role in the existing views — NOT a new tab, that's EO.7)
- Test: a query-filter test + a UI JSON-shape test

- [ ] **Step 1 — query filter.** Add `ServiceRole string` to `FlowFilter`; in the query matchers (hot/warm/cold scan), skip records whose `Metrics.ServiceRole` != filter when the filter is non-empty. Add a unit test over the hot tier.
- [ ] **Step 2 — UI.** Surface `service_role` and `parent_comm` in the egress JSON rows that already carry container fields (the HistoricalPID path from EO.1) and add columns to those tables. Add a role filter control reusing existing UI patterns. Keep responsive-safe (full reorg is EO.7).
- [ ] **Step 3 — tests + build:** `go test ./pkg/egressledger/ ./ui/web/...`; `go build ./...`.
- [ ] **Step 4 — commit.**
```bash
git add pkg/egressledger/query.go pkg/egressledger/types.go ui/web/
git commit -m "feat(egress): query+UI grouping by service_role and parent_comm"
```

## Task EO3-T6: full sweep + RESULTS + redeploy gate

- [ ] **Step 1 — sweep:** `make vet && make static-check && go test -race -count=1 ./pkg/servicerole/ ./pkg/egressledger/ ./pkg/pipeline/ ./ui/web/`.
- [ ] **Step 2 — `make build`.**
- [ ] **Step 3 — RESULTS doc** `docs/superpowers/plans/2026-06-01-egress-EO3-RESULTS.md`: known-binary table = accuracy ceiling; enrichment-not-in-key = no destructive migration (gob/parquet additive, verified by round-trip tests); honest limits (unknown→other; last-observed semantics).
- [ ] **Step 4 — PAUSE: operator-gated redeploy.** Do NOT install/restart. Note that because fields ride alongside the key (not in it), existing warm/cold data stays readable on the new binary — no migration step. Report ready-to-deploy.
- [ ] **Step 5 — commit RESULTS** (`git add -f`).

## Self-review notes
- Decisions honored: rich roles seeded from appident (T1); enrichment alongside key, FlowKey untouched (T2/T3) → no fragile warm-key migration, no destructive schema change.
- Type consistency: `ServiceRole`/`ParentComm` (both `string`) used identically across Event, FlowMetrics, ProcEvent (T2), parquetRow columns `service_role`/`parent_comm` (T3), observe-site stamping (T4), FlowFilter + UI keys `service_role`/`parent_comm` (T5).
- Backward compat: FlowKey unchanged → warm keys unchanged; gob values additive (old decode fine); parquet columns additive (old files zero-fill). No migration; verified by round-trip + old-file tests.
- Honest ceilings stated: known-binary table, unknown→other, last-observed metrics.

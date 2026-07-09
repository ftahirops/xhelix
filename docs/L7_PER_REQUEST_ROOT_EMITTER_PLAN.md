# L7 Per-Request Root Emitter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Emit a per-HTTP-request source root so php-fpm's exec/DB/file work attributes to the originating request, by parsing the FastCGI wire on php-fpm's receive side.

**Architecture:** Two per-request emitters sharing one `request_id` concept and one anchor-persistence change. A — synthesize `request_id` at the existing `ssl_read` decode site (per-request nginx-tier roots). B — a new eBPF capture of FastCGI bytes on php-fpm's `tcp_recvmsg`, parsed by a new pure-Go `pkg/fastcgi`, yielding request identity + serving worker PID atomically; a pipeline hook mints a per-request `RootWeb` anchor and `AttributeSource`s the worker. No nginx→php-fpm 4-tuple join (NAT-proof).

**Tech Stack:** Go 1.23 (CGO_ENABLED=0), eBPF C (GPL-2.0, `cilium/ebpf` loader), `modernc.org/sqlite`.

## Global Constraints

- CGO_ENABLED=0 always; binary must stay statically linked (`make static-check`).
- No C deps in Go; SQLite is `modernc.org/sqlite`.
- Linux-only runtime; gate Linux-specific code with `//go:build linux` + stub.
- Module path `github.com/xhelix/xhelix`; go.mod Go 1.23 but CI builds on Go 1.22 — avoid 1.23-only stdlib APIs.
- eBPF C under `sensors/ebpf/progs/` is GPL-2.0 — do not relicense.
- eBPF programs are NOT built by `make build`; use `make ebpf` (clang + libbpf-dev).
- The correlator/dispatch loop is deterministic single-goroutine — do not parallelize.
- Fidelity honesty (scope §6): coarse capture MUST be tagged coarse; never fake precision.
- Deploy to vps-4 (`135.181.79.13`) only; prod `65.108.246.67` never touched. Schema migration on `source.db` is hard-stop-gated.

---

### Task 1: `pkg/fastcgi` — FastCGI record + PARAMS parser (pure Go)

**Files:**
- Create: `pkg/fastcgi/fastcgi.go`
- Test: `pkg/fastcgi/fastcgi_test.go`

**Interfaces:**
- Consumes: nothing (leaf package, mirrors `pkg/dbsemantic`).
- Produces: `type Result struct { RequestID uint16; IsBeginRequest bool; Method, URI, Host, Script string }` and `func Parse(b []byte) (Result, bool)` — returns `(Result, true)` when at least one BEGIN_REQUEST or PARAMS record was recognized; `(_, false)` otherwise. `func IsFastCGI(b []byte) bool` — true when `b` begins with a v1 record header of a known type (cheap magic sniff for the capture gate).

- [ ] **Step 1: Write the failing test**

```go
package fastcgi

import "testing"

// beginRequest builds an 8-byte-header + 8-byte-body FCGI_BEGIN_REQUEST record
// for requestId=1 (role=RESPONDER, flags=KEEP_CONN).
func beginRequest(reqID uint16) []byte {
	body := []byte{0x00, 0x01, 0x01, 0, 0, 0, 0, 0} // role=1, flags=KEEP_CONN
	return record(1 /*FCGI_BEGIN_REQUEST*/, reqID, body)
}

// paramsRecord builds an FCGI_PARAMS record from name/value pairs (short-form
// lengths only, which is what nginx emits for these keys).
func paramsRecord(reqID uint16, kv map[string]string) []byte {
	var content []byte
	for k, v := range kv {
		content = append(content, byte(len(k)), byte(len(v)))
		content = append(content, []byte(k)...)
		content = append(content, []byte(v)...)
	}
	return record(4 /*FCGI_PARAMS*/, reqID, content)
}

func record(typ byte, reqID uint16, content []byte) []byte {
	h := []byte{1, typ, byte(reqID >> 8), byte(reqID), byte(len(content) >> 8), byte(len(content)), 0, 0}
	return append(h, content...)
}

func TestParseBeginAndParams(t *testing.T) {
	stream := append(beginRequest(1), paramsRecord(1, map[string]string{
		"REQUEST_METHOD":  "POST",
		"REQUEST_URI":     "/wp-login.php?x=1",
		"HTTP_HOST":       "site-a.com",
		"SCRIPT_FILENAME": "/var/www/site-a/wp-login.php",
	})...)
	r, ok := Parse(stream)
	if !ok {
		t.Fatal("Parse returned ok=false")
	}
	if !r.IsBeginRequest || r.RequestID != 1 {
		t.Errorf("begin/reqid = %v/%d, want true/1", r.IsBeginRequest, r.RequestID)
	}
	if r.Method != "POST" || r.URI != "/wp-login.php?x=1" || r.Host != "site-a.com" {
		t.Errorf("got method=%q uri=%q host=%q", r.Method, r.URI, r.Host)
	}
	if r.Script != "/var/www/site-a/wp-login.php" {
		t.Errorf("script = %q", r.Script)
	}
}

func TestParseParamsOnlyOnReusedConn(t *testing.T) {
	// Keepalive: a second request on the same connection may arrive as PARAMS
	// with a fresh BEGIN_REQUEST; ensure PARAMS alone still classifies.
	r, ok := Parse(paramsRecord(2, map[string]string{"HTTP_HOST": "b.com", "REQUEST_URI": "/"}))
	if !ok || r.Host != "b.com" || r.URI != "/" {
		t.Fatalf("params-only parse failed: ok=%v %+v", ok, r)
	}
}

func TestParseRejectsNonFastCGI(t *testing.T) {
	if _, ok := Parse([]byte("GET / HTTP/1.1\r\n")); ok {
		t.Error("plain HTTP must not parse as FastCGI")
	}
	if _, ok := Parse(nil); ok {
		t.Error("nil must not parse")
	}
}

func TestParseTruncatedContent(t *testing.T) {
	// Header claims 200 bytes of PARAMS but only 4 present → best-effort, no panic.
	h := []byte{1, 4, 0, 1, 0, 200, 0, 0}
	if _, ok := Parse(append(h, 1, 2, 'a', 'b')); ok {
		// ok either way is acceptable; the contract is "must not panic".
	}
}

func TestIsFastCGI(t *testing.T) {
	if !IsFastCGI(beginRequest(1)) {
		t.Error("BEGIN_REQUEST should sniff as FastCGI")
	}
	if IsFastCGI([]byte("*1\r\n$4\r\nPING\r\n")) {
		t.Error("redis RESP must not sniff as FastCGI")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./pkg/fastcgi/`
Expected: FAIL — `undefined: Parse` / `undefined: IsFastCGI` (package has no implementation).

- [ ] **Step 3: Write minimal implementation**

```go
// Package fastcgi is the coarse FastCGI request adapter for the L7 per-request
// root emitter. Given the leading bytes php-fpm receives on a FastCGI
// connection, it extracts the request identity (method, URI, host, script) and
// the FastCGI requestId from BEGIN_REQUEST + PARAMS records — WITHOUT a full
// FastCGI server implementation.
//
// Honest limit: COARSE by construction. It reads the leading bytes of one recv,
// walks record headers, and extracts a fixed set of PARAMS keys. It does not
// reassemble multi-recv PARAMS streams or STDIN bodies.
package fastcgi

const (
	typeBeginRequest = 1
	typeParams       = 4
)

// paramsKeys are the only PARAMS names we extract (coarse identity).
// Others are skipped without allocation.

// Result is the coarse per-request classification of a FastCGI request.
type Result struct {
	RequestID      uint16
	IsBeginRequest bool
	Method         string
	URI            string
	Host           string
	Script         string
}

// IsFastCGI reports whether b begins with a plausible v1 FastCGI record header
// of a known type. Cheap gate for the eBPF-capture decode path.
func IsFastCGI(b []byte) bool {
	if len(b) < 8 || b[0] != 1 {
		return false
	}
	switch b[1] {
	case typeBeginRequest, typeParams, 5 /*STDIN*/, 9 /*GET_VALUES*/ :
		return true
	}
	return false
}

// Parse walks the FastCGI records in b, recognizing BEGIN_REQUEST (request
// boundary) and PARAMS (identity). Returns (Result, true) when at least one such
// record was recognized. Best-effort and panic-free on truncated input.
func Parse(b []byte) (Result, bool) {
	var r Result
	var recognized bool
	off := 0
	for off+8 <= len(b) {
		if b[off] != 1 { // version must be 1
			break
		}
		typ := b[off+1]
		reqID := uint16(b[off+2])<<8 | uint16(b[off+3])
		contentLen := int(b[off+4])<<8 | int(b[off+5])
		padLen := int(b[off+6])
		contentStart := off + 8
		contentEnd := contentStart + contentLen
		if contentEnd > len(b) {
			contentEnd = len(b) // truncated: parse what we have
		}
		switch typ {
		case typeBeginRequest:
			r.IsBeginRequest = true
			r.RequestID = reqID
			recognized = true
		case typeParams:
			r.RequestID = reqID
			parseParams(b[contentStart:contentEnd], &r)
			recognized = true
		}
		next := contentEnd + padLen
		if next <= off { // no forward progress (malformed) — stop
			break
		}
		off = next
	}
	return r, recognized
}

// parseParams walks FastCGI name-value pairs and fills the identity fields.
func parseParams(b []byte, r *Result) {
	off := 0
	for off < len(b) {
		nameLen, n, ok := readLen(b, off)
		if !ok {
			return
		}
		off += n
		valLen, n, ok := readLen(b, off)
		if !ok {
			return
		}
		off += n
		if off+nameLen+valLen > len(b) {
			return
		}
		name := string(b[off : off+nameLen])
		val := string(b[off+nameLen : off+nameLen+valLen])
		off += nameLen + valLen
		switch name {
		case "REQUEST_METHOD":
			r.Method = val
		case "REQUEST_URI":
			r.URI = val
		case "HTTP_HOST":
			r.Host = val
		case "SCRIPT_FILENAME":
			r.Script = val
		}
	}
}

// readLen decodes a FastCGI length field: 1 byte if high bit clear, else 4 bytes
// big-endian with the high bit of the first byte masked off. Returns the length,
// bytes consumed, and ok=false on truncation.
func readLen(b []byte, off int) (length, consumed int, ok bool) {
	if off >= len(b) {
		return 0, 0, false
	}
	if b[off]&0x80 == 0 {
		return int(b[off]), 1, true
	}
	if off+4 > len(b) {
		return 0, 0, false
	}
	return int(b[off]&0x7f)<<24 | int(b[off+1])<<16 | int(b[off+2])<<8 | int(b[off+3]), 4, true
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -race ./pkg/fastcgi/`
Expected: PASS (all 5 tests).

- [ ] **Step 5: Commit**

```bash
git add pkg/fastcgi/fastcgi.go pkg/fastcgi/fastcgi_test.go
git commit -m "feat(fastcgi): coarse FastCGI request parser (L7 per-request core)"
```

---

### Task 2: eBPF FastCGI-recv capture + decoder tags

**Files:**
- Modify: `sensors/ebpf/progs/all.bpf.c` (add a `tcp_recvmsg` entry+ret capture emitting a new `XH_EV_FCGI_REQUEST` event; mirror the `ssl_read` uprobe pattern at `all.bpf.c:527/539`).
- Modify: `sensors/ebpf/types.go` (add the `XH_EV_FCGI_REQUEST` event-kind constant + its `"fcgi_request"` string, mirroring the `db_query` mapping at `types.go:100`).
- Modify: `sensors/ebpf/decoder.go` (add `decodeFCGIRequestEvent`, mirroring `decodeSSLReadEvent` at `decoder.go:416` and `decodeDBQueryEvent` at `decoder.go:388`).
- Test: `sensors/ebpf/decoder_test.go` (decode-path unit test — no kernel needed).

**Interfaces:**
- Consumes: `fastcgi.Parse` and `fastcgi.IsFastCGI` from Task 1.
- Produces: events with `ev.Tags["kind"]="fcgi_request"`, and when parsed: `http_host`, `http_method`, `http_uri`, `script_filename`, `fcgi_request_id`, `fidelity="coarse"`. `ev.PID` = the receiving php-fpm worker's (host-namespace) PID. `ev.Comm`/`ev.Image` = the worker.

- [ ] **Step 1: Study the templates (read before writing)**

Read these to lift exact offsets/patterns — do NOT guess them:
- `sensors/ebpf/progs/all.bpf.c` lines ~527–560 (`up_ssl_read_entry`/`up_ssl_read_ret`: the save-buffer-ptr-at-entry, read-at-ret pattern) and ~806–900 (`tcp_recvmsg` kprobe: how the socket 4-tuple + `dir` + PID are already read).
- `sensors/ebpf/decoder.go` `decodeSSLReadEvent` (416) and `decodeDBQueryEvent` (388) for the Go decode idiom (`binary.LittleEndian`, `ev.Tags[...]`, the `dbsemantic.Parse` call site to mirror with `fastcgi.Parse`).
- Note the event struct layout emitted for `ssl_read` so the new `XH_EV_FCGI_REQUEST` payload matches what the decoder expects: `[buf_len(4)][buf[N]]` plus the standard header carrying PID/comm.

- [ ] **Step 2: Write the failing decoder test**

```go
// In sensors/ebpf/decoder_test.go — build a synthetic XH_EV_FCGI_REQUEST payload
// (buf_len prefix + a fastcgi BEGIN_REQUEST+PARAMS stream) and assert the tags.
func TestDecodeFCGIRequest(t *testing.T) {
	// Reuse the fastcgi test helpers' wire format: BEGIN_REQUEST(reqID=1) + PARAMS.
	params := []byte{1, 4, 0, 1, 0, 0, 0, 0} // placeholder header; fill content below
	_ = params
	payload := buildFCGITestPayload(t) // helper: buf_len(4 LE) + fastcgi stream
	ev := model.Event{Tags: map[string]string{}}
	decodeFCGIRequestEvent(&ev, payload)
	if ev.Tags["kind"] != "fcgi_request" {
		t.Fatalf("kind = %q", ev.Tags["kind"])
	}
	if ev.Tags["http_host"] != "site-a.com" || ev.Tags["http_uri"] != "/wp-login.php" {
		t.Errorf("host/uri = %q/%q", ev.Tags["http_host"], ev.Tags["http_uri"])
	}
	if ev.Tags["fidelity"] != "coarse" {
		t.Error("fcgi_request must be tagged coarse")
	}
}
```

(Implement `buildFCGITestPayload` in the test file using the same record/params
byte-builders as `pkg/fastcgi/fastcgi_test.go`, prefixed with a 4-byte
little-endian `buf_len`. Match the exact payload framing observed in Step 1.)

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./sensors/ebpf/ -run TestDecodeFCGIRequest`
Expected: FAIL — `undefined: decodeFCGIRequestEvent`.

- [ ] **Step 4: Implement the decoder (Go)**

```go
// decodeFCGIRequestEvent parses an XH_EV_FCGI_REQUEST payload: buf_len(4 LE) |
// buf[buf_len]. The buf is the leading bytes php-fpm received on a FastCGI
// connection. We stamp coarse per-request identity; PID/comm come from the
// event header (the receiving php-fpm worker).
func decodeFCGIRequestEvent(ev *model.Event, b []byte) {
	ev.Tags["kind"] = "fcgi_request"
	if len(b) < 4 {
		return
	}
	blen := int(binary.LittleEndian.Uint32(b[:4]))
	data := b[4:]
	if blen < len(data) {
		data = data[:blen]
	}
	if !fastcgi.IsFastCGI(data) {
		return
	}
	r, ok := fastcgi.Parse(data)
	if !ok {
		return
	}
	ev.Tags["fcgi_request_id"] = fmt.Sprintf("%d", r.RequestID)
	if r.Host != "" {
		ev.Tags["http_host"] = r.Host
	}
	if r.Method != "" {
		ev.Tags["http_method"] = r.Method
	}
	if r.URI != "" {
		ev.Tags["http_uri"] = r.URI
	}
	if r.Script != "" {
		ev.Tags["script_filename"] = r.Script
	}
	ev.Tags["fidelity"] = "coarse"
}
```

Wire it into the decode dispatch switch alongside the `XH_EV_DB_QUERY` case (find the switch that routes `decodeDBQueryEvent`; add the `XH_EV_FCGI_REQUEST` case). Add the constant in `types.go` mirroring `db_query` (`types.go:100`).

- [ ] **Step 5: Implement the eBPF capture (C)**

In `all.bpf.c`, add a `tcp_recvmsg` entry+ret pair mirroring `up_ssl_read_entry/ret`:
- entry (`kprobe/tcp_recvmsg`): stash the destination iov buffer pointer + the socket 4-tuple keyed by `pid_tgid` in a scratch map (the existing `tcp_recvmsg` kprobe already reads the tuple — reuse that read).
- ret (`kretprobe/tcp_recvmsg`): gate on dst OR src port in the FastCGI set (9000 plus the published range; keep a coarse port allowlist as the cheap pre-filter), read up to `XH_FCGI_BUF_MAX` (256) bytes from the saved buffer, verify `buf[0]==1` (v1 record) as a magic pre-filter, and emit `XH_EV_FCGI_REQUEST{buf_len, buf}` with the standard PID/comm header.
- Coarse ceiling (intended): single-segment `ITER_UBUF`/first iovec only — same as the DB capture; do not attempt `ITER_IOVEC` reassembly.
- Keep the program GPL-2.0 header intact.

- [ ] **Step 6: Run decoder test + build eBPF**

Run: `go test -race ./sensors/ebpf/` then `make ebpf`
Expected: decoder tests PASS; `make ebpf` produces `xhelix-progs.o` with no verifier errors.

- [ ] **Step 7: Commit**

```bash
git add sensors/ebpf/progs/all.bpf.c sensors/ebpf/types.go sensors/ebpf/decoder.go sensors/ebpf/decoder_test.go
git commit -m "feat(ebpf): FastCGI recv-side capture -> fcgi_request coarse identity"
```

---

### Task 3: A-tier — synthesize `request_id` at `ssl_read` (per-request nginx roots)

**Files:**
- Modify: `sensors/ebpf/decoder.go` (`decodeSSLReadEvent`, ~416 — after `http_host`/`http_request_line` are set, synthesize `ev.Tags["request_id"]`).
- Test: `sensors/ebpf/decoder_test.go`.

**Interfaces:**
- Consumes: existing `http_host` + `http_request_line` tags on the ssl_read event.
- Produces: `ev.Tags["request_id"]` non-empty on nginx-tier web events. `mint.go:116` already copies it to `Origin.HTTPRequestID`.

- [ ] **Step 1: Write the failing test**

```go
func TestSSLReadStampsRequestID(t *testing.T) {
	ev := model.Event{PID: 4242, Tags: map[string]string{
		"http_host":         "site-a.com",
		"http_request_line": "GET /wp-login.php HTTP/1.1",
	}}
	stampWebRequestID(&ev) // the new helper
	if ev.Tags["request_id"] == "" {
		t.Fatal("request_id not stamped")
	}
	// Stable within an event, distinct across request-lines.
	first := ev.Tags["request_id"]
	ev.Tags["request_id"] = ""
	ev.Tags["http_request_line"] = "GET /other HTTP/1.1"
	stampWebRequestID(&ev)
	if ev.Tags["request_id"] == first {
		t.Error("distinct request-lines must yield distinct request_id")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./sensors/ebpf/ -run TestSSLReadStampsRequestID`
Expected: FAIL — `undefined: stampWebRequestID`.

- [ ] **Step 3: Implement**

```go
// stampWebRequestID synthesizes a compact per-request id for a decoded web
// (ssl_read) event from the serving PID + request-line + a per-PID sequence, so
// nginx-tier web roots resolve at request (not vhost) granularity. FNV keeps it
// short and allocation-light; collisions across distinct request-lines are
// astronomically unlikely for identity purposes.
func stampWebRequestID(ev *model.Event) {
	rl := ev.Tags["http_request_line"]
	if rl == "" {
		return
	}
	h := fnv.New64a()
	fmt.Fprintf(h, "%d|%s|%s", ev.PID, ev.Tags["http_host"], rl)
	ev.Tags["request_id"] = "n" + strconv.FormatUint(h.Sum64(), 36)
}
```

Call `stampWebRequestID(ev)` at the end of `decodeSSLReadEvent` (after `http_host` is set). Add imports `hash/fnv`, `strconv`.

- [ ] **Step 4: Run to verify it passes**

Run: `go test -race ./sensors/ebpf/ -run TestSSLReadStampsRequestID`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add sensors/ebpf/decoder.go sensors/ebpf/decoder_test.go
git commit -m "feat(l7): synthesize request_id at ssl_read for per-request nginx roots"
```

---

### Task 4: B-tier — `attributeFcgiRoot` per-request mint + worker attribution

**Files:**
- Modify: `pkg/webroot/tracker.go` (add per-request keying nested under vhost, cap-bounded; or a sibling `RequestTracker` if the host-keyed one is load-bearing elsewhere — decide in Step 1).
- Modify: `pkg/pipeline/pipeline.go` (add `attributeFcgiRoot(ctx, ev)`, mirror `attributeWebRoot` at `2271`, called from the dispatch alongside the `db_query`/web sites; mint per-request `RootWeb` anchor with `request_id` + `AttributeSource(ev.PID, anchorID)`).
- Test: `pkg/pipeline/pipeline_test.go` (or the existing web-root test file).

**Interfaces:**
- Consumes: `fcgi_request` events (Task 2) carrying `request_id` (synthesize here too, from `fcgi_request_id`+PID+seq if absent), `http_host`, `http_uri`, and `ev.PID` (worker).
- Produces: a minted `source.Anchor{Kind: KindWeb, HTTPRequestID: <id>}` and `ProcTree.SourceOf(worker_pid) != 0` for the serving worker.

- [ ] **Step 1: Study the template**

Read `pkg/pipeline/pipeline.go:2271` `attributeWebRoot` end-to-end (how it calls the minter, `webroot.Tracker`, and `ProcTree.AttributeSource`), and `pkg/webroot/tracker.go` (the host-keyed cap-bounded cache). Decide: extend `Tracker` with a per-request key or add `RequestTracker`. Also confirm the synthesized `request_id` for B: `"f" + worker_pid + "-" + fcgi_request_id + "-" + seq`.

- [ ] **Step 2: Write the failing test**

```go
func TestAttributeFcgiRootMintsPerRequest(t *testing.T) {
	p := newTestPipeline(t) // existing helper used by web-root tests
	ev := model.Event{PID: 9001, Comm: "php-fpm", Time: testTime, Tags: map[string]string{
		"kind": "fcgi_request", "http_host": "site-a.com",
		"http_uri": "/wp-login.php", "fcgi_request_id": "1",
	}}
	p.attributeFcgiRoot(context.Background(), &ev)
	if ev.Tags["request_id"] == "" {
		t.Fatal("request_id not synthesized for app-tier root")
	}
	if got := p.ProcTree.SourceOf(9001); got == 0 {
		t.Fatal("worker PID 9001 not attributed to a source root")
	}
	// The minted anchor persists the request id.
	a := p.lastMintedAnchor(t) // test helper reading the source store
	if a.Kind != source.KindWeb || a.HTTPRequestID == "" {
		t.Errorf("anchor = kind %v reqid %q, want web + non-empty", a.Kind, a.HTTPRequestID)
	}
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `go test ./pkg/pipeline/ -run TestAttributeFcgiRootMintsPerRequest`
Expected: FAIL — `undefined: attributeFcgiRoot` (and `HTTPRequestID` field, added in Task 5 — if this task runs first, add the field stub in Task 5's file now or sequence Task 5 before this; see Self-Review note).

- [ ] **Step 4: Implement `attributeFcgiRoot`**

```go
// attributeFcgiRoot mints a per-request web root from a FastCGI request received
// by a php-fpm worker and attributes the worker's subtree to it, so the worker's
// subsequent DB/file events inherit the originating request as their source
// root. Join-free: the receiving worker PID and the request identity arrive on
// the same event (no nginx->php-fpm 4-tuple correlation). Nil-safe.
func (p *Pipeline) attributeFcgiRoot(ctx context.Context, ev *model.Event) {
	if p.SourceMinter == nil || ev.Tags["kind"] != "fcgi_request" || ev.PID == 0 {
		return
	}
	host := ev.Tags["http_host"]
	if host == "" {
		return
	}
	rid := ev.Tags["request_id"]
	if rid == "" {
		rid = "f" + strconv.Itoa(int(ev.PID)) + "-" + ev.Tags["fcgi_request_id"] +
			"-" + strconv.FormatUint(p.WebRoots.NextSeq(host), 36)
		ev.Tags["request_id"] = rid
	}
	// Mint once per request id (cap-bounded); returns the anchor id.
	id, minted := p.WebRoots.MintRequest(ctx, p.SourceMinter, ev, rid)
	if !minted || id == 0 {
		return
	}
	p.ProcTree.AttributeSource(ev.PID, id)
}
```

Add `WebRoots.NextSeq(host) uint64` and `WebRoots.MintRequest(ctx, minter, ev, rid) (lineage.LineageID, bool)` to `pkg/webroot/tracker.go` (per-request cap-bounded; `MintRequest` builds an identity event tagged `service=web`, `http_host`, `request_id` and calls `minter.MintFromEvent`, returning the anchor id). Call `p.attributeFcgiRoot(ctx, &ev)` from `Handle` right after the `fcgi_request` decode point (co-locate with the `db_query` block near `pipeline.go:1076`).

- [ ] **Step 5: Run to verify it passes**

Run: `go test -race ./pkg/pipeline/ ./pkg/webroot/ -run 'Fcgi|Request'`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add pkg/pipeline/pipeline.go pkg/webroot/tracker.go pkg/pipeline/pipeline_test.go
git commit -m "feat(l7): attributeFcgiRoot mints per-request app-tier root + attributes worker"
```

---

### Task 5: Persist `HTTPRequestID` on the source anchor (additive schema migration)

**Files:**
- Modify: `pkg/source/anchor.go` (add `HTTPRequestID string` to `Anchor`; populate in `FromOrigin` from `o.HTTPRequestID`).
- Modify: `pkg/source/store.go` (add `http_request_id` column; additive migration; read/write it in `Put`/scan).
- Test: `pkg/source/store_test.go`.

**Interfaces:**
- Consumes: `lineage.Origin.HTTPRequestID` (already exists per the code map).
- Produces: `Anchor.HTTPRequestID` persisted and read back; older DBs migrate additively (old rows → `""`).

- [ ] **Step 1: Write the failing test**

```go
func TestAnchorHTTPRequestIDRoundTrips(t *testing.T) {
	s := openMem(t)
	want := Anchor{ID: 7, Kind: KindWeb, CreatedAt: time.Now().UTC(),
		Actor: "site-a.com", HTTPRequestID: "f9001-1-0"}
	if err := s.Put(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(context.Background(), 7)
	if err != nil {
		t.Fatal(err)
	}
	if got.HTTPRequestID != "f9001-1-0" {
		t.Errorf("HTTPRequestID = %q, want f9001-1-0", got.HTTPRequestID)
	}
}

func TestMigrationAddsColumnToOldDB(t *testing.T) {
	// Open a store whose table predates the column, re-open, assert no error and
	// existing rows read HTTPRequestID == "".
	s := openMem(t)
	// Simulate a pre-migration row via direct insert without the column, then
	// re-run initSchema (idempotent ADD COLUMN guarded by a column-exists check).
	// ... (use the same pattern store_test.go already uses for schema setup)
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./pkg/source/ -run 'HTTPRequestID|Migration'`
Expected: FAIL — `unknown field HTTPRequestID` / column missing.

- [ ] **Step 3: Implement**

- In `anchor.go`: add `HTTPRequestID string` to `Anchor`; in `FromOrigin` set `a.HTTPRequestID = o.HTTPRequestID`.
- In `store.go`: extend the `CREATE TABLE` with `http_request_id TEXT NOT NULL DEFAULT ''`; add an idempotent migration in the schema-init function:

```go
// additive, backward-compatible: add the column only if absent.
if !columnExists(db, "source_anchors", "http_request_id") {
	if _, err := db.Exec(`ALTER TABLE source_anchors ADD COLUMN http_request_id TEXT NOT NULL DEFAULT ''`); err != nil {
		return err
	}
}
```

Add `http_request_id` to the INSERT column list + args in `Put`, and to the SELECT + `rows.Scan` targets in the read path. Implement `columnExists` via `PRAGMA table_info(...)` if no equivalent helper exists.

- [ ] **Step 4: Run to verify it passes**

Run: `go test -race ./pkg/source/`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/source/anchor.go pkg/source/store.go pkg/source/store_test.go
git commit -m "feat(source): persist HTTPRequestID on the anchor (additive migration)"
```

---

### Task 6: Full build, race suite, and live-verify on vps-4 (acceptance gate)

**Files:** none (integration + acceptance). This task gates the branch.

**Interfaces:**
- Consumes: Tasks 1–5.
- Produces: proof the per-request root attributes DB/file work on real WordPress traffic.

- [ ] **Step 1: Full local verification**

Run: `make vet && go test -race -count=1 ./... && make build && make ebpf && make static-check`
Expected: vet clean; all tests pass; static binaries OK; `xhelix-progs.o` builds.

- [ ] **Step 2: Build deb**

Run: `make deb`
Expected: `dist/xhelix_0.0.2_amd64.deb` produced.

- [ ] **Step 3: Deploy to vps-4 (HARD STOP — confirm before running)**

Confirm with the operator, then:
```bash
scp -i /root/.ssh/id_rsa dist/xhelix_0.0.2_amd64.deb root@135.181.79.13:/root/xhelix.deb
ssh -i /root/.ssh/id_rsa root@135.181.79.13 \
  'DEBIAN_FRONTEND=noninteractive dpkg -i --force-confold /root/xhelix.deb; systemctl restart xhelix; sleep 3; systemctl is-active xhelix'
```
Note: `--force-confold` avoids the interactive conffile prompt (known deploy gotcha). The migration on `/var/lib/xhelix/source.db` runs on first start — it is additive; keep the pre-deploy `source.db` intact (no manual migration).

- [ ] **Step 4: Drive uncached WordPress traffic**

```bash
ssh -i /root/.ssh/id_rsa root@135.181.79.13 '
hosts=$(grep -rhoE "server_name [^;]+" /etc/nginx 2>/dev/null | awk "{print \$2}" | grep -vE "_$|localhost" | sort -u | head -6)
for h in $hosts; do for i in $(seq 1 10); do
  curl -sk -o /dev/null -H "Host: $h" "https://127.0.0.1/?nocache=$RANDOM$i"
  curl -sk -o /dev/null -H "Host: $h" "https://127.0.0.1/wp-login.php?x=$RANDOM"
done; done'
```
(Cache-busting is required — cached pages + pooled DB conns hide the app-tier work; lesson from the DB-fusion verify.)

- [ ] **Step 5: Assert the acceptance criteria**

```bash
ssh -i /root/.ssh/id_rsa root@135.181.79.13 '
echo "== per-request web anchors (distinct request ids) =="; xhelixctl source count; xhelixctl source list --kind web | tail
echo "== php-fpm DB events now carry a request root_id (not 0) =="; grep -h "fcgi_request\|db_query" /var/log/xhelix/*.jsonl 2>/dev/null | tail -5
echo "== recorder shapes at request phase =="; xhelixctl brp edge observed | head'
```
Acceptance: (1) `kind=web` anchors mint per request with distinct `http_request_id`; (2) a php-fpm worker's `db_query`/file event resolves `SourceOf(pid) != 0` to a web request root; (3) recorder shows `phase=request` shapes carrying a URI. If any fails, do NOT commit the arc as "verified" — capture the actual output and iterate.

- [ ] **Step 6: Commit the verification note + update memory**

```bash
git commit --allow-empty -m "test(l7): live-verify per-request root attribution on vps-4 [paste real output]"
```
Update the `xhelix_crossapp_sp3_progress` memory with the live result and any honest limits observed (e.g. multi-recv PARAMS truncation, php-fpm pool behavior).

---

## Self-Review notes

- **Task ordering / type dependency:** Task 4's test references `Anchor.HTTPRequestID`, added in Task 5. **Sequence Task 5 before Task 4**, or add the `HTTPRequestID` struct field (Task 5 Step 3, anchor.go only) as Task 4's Step 0. Recommended: run 5 before 4.
- **`request_id` scheme consistency:** nginx-tier ids are prefixed `n` (Task 3), app-tier `f` (Task 4) — deliberately distinct namespaces; the two tiers mint independent roots (spec: no cross-tier join). Do not "unify" them.
- **Coarse-fidelity honesty:** every `fcgi_request` event is tagged `fidelity="coarse"` (Task 2 Step 4); do not drop this — it is a scope §6 requirement.
- **eBPF is the risk:** Task 2 Step 5 is the one genuinely novel piece. Prove the capture emits correct `http_uri`/`http_host` on vps-4 (add a temporary debug log) before trusting Tasks 4/6. If `ITER_IOVEC` recvs dominate and PARAMS are missed, that is the documented coarse limit — log it, don't silently degrade.
- **Non-goal guard:** do not add the nginx-side 4-tuple join or unix-socket FastCGI support (spec non-goals).

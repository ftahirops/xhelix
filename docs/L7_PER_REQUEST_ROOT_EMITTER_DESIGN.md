# L7 Per-Request Root Emitter — Design

Date: 2026-07-03
Branch: `verdict-foundation`
Status: approved design, pre-implementation
Live test host: vps-4 (`135.181.79.13`, Dockerised WordPress)

## Problem

xhelix's source-attribution layer mints web roots at **per-vhost** granularity
only (`KindWeb`/`RootWeb`, driven by the eBPF `ssl_read` signal — commit
`22d2d83`). Its stated honest limit: *"roots land on the TLS terminator (nginx),
not the php-fpm app tier; per-request app attribution needs socket correlation."*

Consequently `request_id` — already plumbed through every layer
(`ev.Tags["request_id"]` → `Origin.HTTPRequestID` → `workflowchain` phase/fidelity
gate at `chain.go:24,126`) — is **never populated**. Downstream consumers already
treat it as authoritative; the missing piece is *production of the value* and
*app-tier attribution* of the originating HTTP request.

This design produces a per-request root at both the nginx tier (A) and the
php-fpm app tier (B), so that a php-fpm worker's `SELECT wp_posts` / `GET wp:` /
file-write events attribute to the specific HTTP request that caused them.

## Key decisions (locked with the user 2026-07-03)

1. **Scope: A + B (full cross-tier).** Per-request identity at nginx ingress
   *and* propagation to the php-fpm app tier.
2. **Join fidelity: deterministic — parse the FastCGI wire.** Not a time-window
   heuristic. Correct under keepalive connection reuse and concurrency.
3. **Parse side: php-fpm RECEIVE side (B-recv), not nginx send side.** The
   nginx→php-fpm connection crosses a Docker port-publish boundary
   (`127.0.0.1:910x → container:9000`); DNAT/docker-proxy rewrites the 4-tuple,
   so a nginx-side→php-fpm-side 4-tuple join is broken on exactly the
   containerized hosts we target. Parsing on php-fpm's `tcp_recvmsg` yields the
   **request identity and the serving worker PID atomically** (like the DB-query
   capture yields engine+PID together) — no cross-tier join, no NAT problem, no
   time-window race.

## Architecture

Two per-request emitters sharing one `request_id` concept and one anchor
persistence change:

- **A — nginx-tier** (`ssl_read`): synthesize a `request_id` where the HTTP
  request-line is already decoded (`sensors/ebpf/decoder.go:416`
  `decodeSSLReadEvent`), upgrading the existing per-vhost web root to
  **per-request**. Covers static / non-PHP requests that never reach php-fpm.
- **B — app-tier** (php-fpm `tcp_recvmsg`): a new eBPF FastCGI-recv capture
  parses `FCGI_BEGIN_REQUEST` + `FCGI_PARAMS` as the worker receives them,
  yielding request identity + serving worker PID atomically, then
  `ProcTree.AttributeSource(worker_pid, request_root)`. This is the authoritative
  per-request root; the worker's subsequent DB/file events inherit it.

Everything downstream already consumes `request_id`; this design produces it.

**A and B produce independent per-request roots**, not one shared `request_id`.
The nginx-tier root (A) identifies the request at the TLS terminator; the
app-tier root (B) identifies it at php-fpm. Joining "nginx root X == app root Y
for the same logical request" is precisely the nginx→php-fpm NAT-crossing
correlation we rejected in decision 3 — so the two tiers stay deliberately
separate. Each is per-request and self-consistent within its own tier; that is
the honest consequence of the join-free B-recv choice, and it is sufficient
because the app-tier root (B) is the one that attributes DB/file work.

## Components (each independently testable)

### C1. `pkg/fastcgi` (new — pure parser, mirrors `pkg/dbsemantic`)
- Input: raw bytes received by php-fpm on a FastCGI connection.
- Output: `Result{Method, URI, Host, Script, FCGIRequestID uint16, IsBeginRequest bool, OK bool}`.
- Deterministic FastCGI record framing: 8-byte record header (version, type,
  requestId(2), contentLength(2), paddingLength, reserved), then content.
  Recognize `FCGI_BEGIN_REQUEST` (type 1 → new request boundary) and
  `FCGI_PARAMS` (type 4 → name/value pairs; extract `REQUEST_METHOD`,
  `REQUEST_URI`, `HTTP_HOST`, `SCRIPT_FILENAME`).
- No I/O, no allocation beyond the parsed strings. Unit-tested against real
  record fixtures.

### C2. eBPF FastCGI-recv capture (new event `XH_EV_FCGI_REQUEST`)
- Capture the received bytes on `tcp_recvmsg` using the **entry+ret buffer-read
  pattern** already used by the `ssl_read` uprobe (`all.bpf.c:527/539`): save the
  destination buffer pointer at entry, read it at return after the kernel has
  copied data in.
- Gate to FastCGI transport: local/dst port `9000` plus published `910x`, or an
  FCGI magic-byte sniff (first record header version==1 && type in {1,4}). Prefer
  the magic-byte sniff so it's port-config-independent; keep a port allowlist as
  a cheap pre-filter.
- Decoder (`sensors/ebpf/decoder.go`) stamps: `kind=fcgi_request`, `http_host`,
  `http_method`, `http_uri`, `script_filename`, `fcgi_request_id`.
- Coarse capture ceiling (accepted, see Limits): single-segment `ITER_UBUF` /
  first iovec only.

### C3. `request_id` synthesis
- Compact, stable, unique-per-request token. Scheme:
  `fcgi_request_id` (u16 on the connection) is unique among in-flight requests on
  one connection; combine with the serving worker PID and a per-worker monotonic
  sequence to get host-unique: e.g. `r<worker_pid>-<seq>`. The `fcgi_request_id`
  disambiguates if a worker ever multiplexes.
- Stamped as `ev.Tags["request_id"]`; `mint.go:116` already copies it to
  `Origin.HTTPRequestID`.
- A-tier (nginx): synthesize from the `ssl_read` request-line + host + nginx
  worker PID + per-worker seq at the decode site.

### C4. Minting / attribution
- Extend `webroot.Tracker` (`pkg/webroot/tracker.go`, currently host-keyed) to
  key per-request (nested under vhost), cap-bounded (reuse the existing 4096 cap
  discipline).
- New pipeline hook `attributeFcgiRoot(ctx, ev)` parallel to `attributeWebRoot`
  (`pipeline.go:2271`, called from `:1479`): on an `fcgi_request` event, mint a
  per-request `RootWeb` anchor carrying `HTTPRequestID` and
  `AttributeSource(worker_pid, anchor_id)`.
- A-tier: `attributeWebRoot` upgraded from per-vhost to per-request via the
  synthesized `request_id`.

### C5. Persistence
- Add `HTTPRequestID string` to the `source.Anchor` struct (`anchor.go`) and
  populate it in `FromOrigin` (`anchor.go:117`).
- Add a `http_request_id` column to the `source_anchors` table in
  `pkg/source/store.go` with an additive, backward-compatible migration
  (`ALTER TABLE ... ADD COLUMN` guarded by a column-exists check; older rows get
  `""`). **This is the hard-stop-class change** — schema migration on
  `/var/lib/xhelix/source.db`; gated and reviewed before deploy.

## Data flow (one request, end to end)

```
client ──TLS──> nginx
   │  ssl_read decode → synthesize request_id → per-request NGINX root (A)
   ▼
nginx ──FastCGI/TCP──> [Docker NAT: 127.0.0.1:910x → container:9000]  (join-free)
   ▼
php-fpm worker  tcp_recvmsg  (XH_EV_FCGI_REQUEST)
   │  pkg/fastcgi parse: BEGIN_REQUEST + PARAMS(METHOD,URI,HOST,SCRIPT)
   │  synthesize request_id → mint per-request APP root (B)
   │  AttributeSource(worker_pid, request_root)
   ▼
worker's SELECT wp_posts / GET wp: / file-write events
   │  ProcTree.SourceOf(worker_pid) = request_root  → root_id != 0
   ▼
workflowchain stamps phase=request, full fidelity
```

## Honest limits (stated up front)

- **Coarse recv capture**: single-segment `ITER_UBUF` / first-iovec only;
  multi-segment `ITER_IOVEC` recvs skipped — same ceiling already accepted for DB
  capture (doc §5.4). `FCGI_BEGIN_REQUEST`+`FCGI_PARAMS` are small and normally
  arrive in one recv, so low-risk in practice; stated, not hidden.
- **TCP FastCGI only**: unix-socket FastCGI transport (`/run/php-fpm.sock`) is not
  captured by `tcp_recvmsg`. Out of scope; flagged. vps-4 uses TCP:9000.
- **Keepalive reuse**: re-attribution fires on each `BEGIN_REQUEST`. The window
  between a worker's `BEGIN_REQUEST` and its first downstream syscall is bounded
  and stamped synchronously in the single-goroutine dispatch, so no cross-request
  bleed in the common one-request-per-worker model.
- **Mint volume**: one root mint per HTTP request. Add a per-worker throttle if
  volume bites (mirrors the DB per-conn throttle note). Cap-bounded tracker
  prevents unbounded growth.
- **Pre-existing workers**: fills as php-fpm workers (re)spawn/serve under the
  running daemon; workers idle at attach time attribute on their next request.

## Testing

1. `pkg/fastcgi` unit tests against real `FCGI_BEGIN_REQUEST`/`FCGI_PARAMS` byte
   fixtures (including a keepalive second-request-on-connection fixture and a
   truncated/partial record → `OK=false`).
2. Per-request mint test: `request_id` populated → distinct anchors →
   `HTTPRequestID` persisted and read back from `source.Store`.
3. Migration test: open a pre-migration `source.db`, run open, assert the column
   is added and old rows read `""`.
4. **Live-verify on vps-4** (the acceptance gate): drive WP traffic (cache-busting
   `?nocache=$RANDOM` per the fusion-verify lesson), then confirm:
   - per-request web anchors mint (`xhelixctl source` shows `kind=web` count rising
     per request, distinct `http_request_id`);
   - php-fpm mysql/redis events carry a per-request `root_id != 0`
     (`learnable-diag` / source graph);
   - recorder shows `phase=request` shapes carrying the URI.

## Build sequence (phased, each shippable + testable)

1. **`pkg/fastcgi` parser + tests** — pure Go, zero runtime risk.
2. **eBPF FastCGI-recv capture + decoder tags** — the main technical risk
   (recv-side buffer read via entry+ret). Prove the capture emits correct
   `http_uri/http_host` on vps-4 before wiring attribution.
3. **A: `request_id` synthesis at `ssl_read`** → per-request nginx roots.
4. **B: `attributeFcgiRoot` per-request mint + worker attribution.**
5. **`Anchor.HTTPRequestID` persistence** (additive schema migration; hard-stop
   gated).
6. **Live-verify + honesty pass** on vps-4.

## Effort

Comparable to the SP-3 DB-semantics arc but larger: a new eBPF capture path
*plus* a schema migration. Realistically multi-day. Phase 2 (recv-side payload
capture) is the one genuinely novel/risky piece; everything else mirrors existing
patterns (`dbsemantic` parser, `ssl_read` capture, `attributeWebRoot` hook,
`webroot.Tracker`).

## Non-goals

- No nginx-side 4-tuple join / docker-proxy tracing (obviated by B-recv).
- No unix-socket FastCGI transport support.
- No change to the deterministic single-goroutine correlator/dispatch ordering.
- No arming of enforcement based on these roots (separate calibration item).

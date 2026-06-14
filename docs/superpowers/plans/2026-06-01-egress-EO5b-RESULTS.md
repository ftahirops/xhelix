# Phase EO.5b — ALPN-based L7 classification — RESULTS

**Date:** 2026-06-01 · **Branch:** `verdict-foundation` · commit `88acf8a`

## What shipped (no new eBPF — userspace only)
- The dpi AF_PACKET sniffer now parses the ClientHello via `pkg/ja3.Parse` (which yields
  SNI **and** ALPN) instead of SNI-only. SNI is preserved (falls back to the old
  `dpi.ParseClientHelloSNI` if ja3 yields nothing — never regresses).
- `connstate.Conn.ALPN` + `AttachALPN` (mirrors AttachSNI). The sniffer attaches a coarse
  hint token: grpc > h2 (http/1.1 deliberately not labeled).
- The egress observe site surfaces ALPN (connstate, with a tag override for tests) into
  `l7proto.Signals.ALPN`, so flows negotiating gRPC/HTTP-2 now classify as `grpc`/`http2`.

## Verified
- `connstate`, `pipeline`, `sensors/dpi`, `l7proto` tests green (36); `go build ./...` ok.
- Live path confirmed: observe block calls `lookupALPNFromConnstate(p.ConnTable, …)`.

## Honest limit
ClientHello ALPN is the client's **offered** list, not the **negotiated** protocol — a
strong hint, not proof. Acceptable for a descriptive label; l7proto still falls through to
HTTP/2-preface, request-line, and port heuristics when ALPN is absent.

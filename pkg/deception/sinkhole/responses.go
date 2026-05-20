package sinkhole

import (
	"bufio"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// fakeHTTPResponse builds a plausible HTTP/1.1 response for the
// given request. Looks like nginx serving a small page. Matches the
// kinds of beacons attacker malware expects from typical C2 paths.
//
// Returns the wire-format bytes ready to write to the socket plus
// the status string for forensic logging.
func fakeHTTPResponse(req *http.Request) (wire []byte, status string) {
	// Pick a content based on path heuristics so common C2 endpoints
	// get distinct realistic-looking bodies. Attackers using a
	// custom protocol over HTTP only care about Status + a body
	// that parses; this is enough.
	body, contentType := pickFakeBody(req)

	status = "200 OK"
	header := strings.Builder{}
	fmt.Fprintf(&header, "HTTP/1.1 %s\r\n", status)
	fmt.Fprintf(&header, "Server: nginx/1.18.0 (Ubuntu)\r\n")
	fmt.Fprintf(&header, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123))
	fmt.Fprintf(&header, "Content-Type: %s\r\n", contentType)
	fmt.Fprintf(&header, "Content-Length: %d\r\n", len(body))
	fmt.Fprintf(&header, "Connection: keep-alive\r\n")
	// Some realistic-looking headers many sites send.
	fmt.Fprintf(&header, "X-Frame-Options: SAMEORIGIN\r\n")
	fmt.Fprintf(&header, "X-Content-Type-Options: nosniff\r\n")
	fmt.Fprintf(&header, "Cache-Control: no-store, no-cache, must-revalidate\r\n")
	header.WriteString("\r\n")

	wire = append([]byte(header.String()), body...)
	return wire, status
}

func pickFakeBody(req *http.Request) (body []byte, contentType string) {
	if req == nil || req.URL == nil {
		return []byte(loremIpsum), "text/html; charset=utf-8"
	}
	path := strings.ToLower(req.URL.Path)
	switch {
	case strings.Contains(path, ".json"), strings.HasSuffix(path, "/api"),
		strings.Contains(path, "/api/"):
		return []byte(`{"status":"ok","data":[]}`), "application/json"
	case strings.Contains(path, ".xml"), strings.Contains(path, "/rss"):
		return []byte(`<?xml version="1.0"?><response><status>ok</status></response>`),
			"application/xml"
	case strings.Contains(path, ".png"), strings.Contains(path, ".jpg"),
		strings.Contains(path, ".gif"), strings.Contains(path, ".ico"):
		// Tiny but plausible image: 1x1 transparent PNG.
		return tinyPNG, "image/png"
	case strings.Contains(path, ".js"):
		return []byte(`(function(){var _0=window;_0.ts=Date.now()})();`), "application/javascript"
	case strings.Contains(path, ".css"):
		return []byte(`body{font-family:sans-serif}`), "text/css"
	case strings.Contains(path, "robots.txt"):
		return []byte("User-agent: *\nAllow: /\n"), "text/plain"
	case strings.HasSuffix(path, "/"), path == "":
		return []byte(loremIndexHTML), "text/html; charset=utf-8"
	}
	return []byte(loremIpsum), "text/html; charset=utf-8"
}

// tinyPNG is a 1×1 transparent PNG (smallest valid PNG payload).
var tinyPNG = []byte{
	0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
	0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
	0x89, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x44, 0x41,
	0x54, 0x78, 0x9C, 0x62, 0x00, 0x01, 0x00, 0x00,
	0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
	0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
	0x42, 0x60, 0x82,
}

const loremIpsum = `Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.`

const loremIndexHTML = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Index</title></head>
<body><h1>Welcome</h1><p>Service running.</p></body>
</html>
`

// parseHTTPRequest reads an HTTP request from a bufio.Reader. The
// returned byte slice is a best-effort raw-bytes snapshot for the
// forensic log (request-line + headers). http.ReadRequest consumes
// the body lazily; callers MUST drain it before next iteration.
func parseHTTPRequest(br *bufio.Reader) (*http.Request, []byte, error) {
	// Peek what's already buffered — non-blocking. http.ReadRequest
	// will read more from the underlying connection as needed.
	startBuf, _ := br.Peek(br.Buffered())
	snapshot := append([]byte(nil), startBuf...)
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, snapshot, err
	}
	// If we got nothing in the pre-peek (e.g. ReadRequest blocked on
	// the underlying conn), synthesize a snapshot from the parsed
	// request so the forensic log isn't empty.
	if len(snapshot) == 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "%s %s %s\r\n", req.Method, req.URL.RequestURI(), req.Proto)
		_ = req.Header.Write(&b)
		b.WriteString("\r\n")
		snapshot = []byte(b.String())
	}
	return req, snapshot, nil
}

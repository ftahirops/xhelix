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

// paramsContent builds a raw FastCGI PARAMS name-value block (no record header),
// which is what the recv-side capture emits.
func paramsContent(kv [][2]string) []byte {
	var b []byte
	for _, p := range kv {
		b = append(b, byte(len(p[0])), byte(len(p[1])))
		b = append(b, []byte(p[0])...)
		b = append(b, []byte(p[1])...)
	}
	return b
}

func TestParseParamsExtractsIdentity(t *testing.T) {
	content := paramsContent([][2]string{
		{"SCRIPT_FILENAME", "/var/www/a/index.php"},
		{"REQUEST_METHOD", "GET"},
		{"REQUEST_URI", "/wp-admin/"},
		{"SERVER_NAME", "a.com"},
		{"HTTP_HOST", "a.com"},
	})
	r, ok := ParseParams(content)
	if !ok {
		t.Fatal("ParseParams ok=false")
	}
	if r.Host != "a.com" || r.URI != "/wp-admin/" || r.Method != "GET" {
		t.Errorf("got host=%q uri=%q method=%q", r.Host, r.URI, r.Method)
	}
	if r.ServerName != "a.com" || r.Script != "/var/www/a/index.php" {
		t.Errorf("got server_name=%q script=%q", r.ServerName, r.Script)
	}
}

func TestParseParamsServerNameOnly(t *testing.T) {
	r, ok := ParseParams(paramsContent([][2]string{{"SERVER_NAME", "b.com"}, {"REQUEST_URI", "/"}}))
	if !ok || r.ServerName != "b.com" {
		t.Fatalf("server_name = %q ok=%v", r.ServerName, ok)
	}
}

func TestParseParamsRejectsGarbage(t *testing.T) {
	// Padding / non-nv bytes → no identity fields → ok=false.
	if _, ok := ParseParams([]byte{0, 0, 0, 0}); ok {
		t.Error("all-zero padding must not classify")
	}
	if _, ok := ParseParams(nil); ok {
		t.Error("nil must not classify")
	}
}

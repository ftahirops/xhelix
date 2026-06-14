package tlsledger

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type captureAuditor struct {
	mu      sync.Mutex
	entries []string
}

func (c *captureAuditor) LogAccess(remoteIP, action, recordID, binary string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, action+":"+remoteIP+":"+recordID+":"+binary)
}
func (c *captureAuditor) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func TestDisabledByDefault_DropsEverything(t *testing.T) {
	l := New(Options{}) // empty AllowedBinaries
	l.Observe(Event{
		Time:    time.Now(),
		Binary:  "/usr/bin/curl",
		Payload: []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
	})
	if got := l.Stats().Stored; got != 0 {
		t.Fatalf("dormant ledger stored %d records, want 0", got)
	}
	if got := l.Stats().DroppedNotAllowed; got != 1 {
		t.Fatalf("dropped_not_allowed=%d want 1", got)
	}
}

func TestPerBinaryOptIn(t *testing.T) {
	l := New(Options{AllowedBinaries: []string{"/usr/bin/curl"}})
	l.Observe(Event{Time: time.Now(), Binary: "/usr/bin/wget",
		Payload: []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")})
	l.Observe(Event{Time: time.Now(), Binary: "/usr/bin/curl",
		Payload: []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")})
	recs := l.List(10, ListFilter{}, "127.0.0.1")
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if recs[0].Binary != "/usr/bin/curl" {
		t.Fatalf("wrong binary stored: %s", recs[0].Binary)
	}
}

func TestAuthorizationHeaderRedacted(t *testing.T) {
	l := New(Options{AllowedBinaries: []string{"/usr/bin/curl"}})
	payload := "POST /api/x HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"Authorization: Bearer sk_live_supersecret\r\n" +
		"Content-Type: application/json\r\n\r\n" +
		`{"hello":"world"}`
	l.Observe(Event{Time: time.Now(), Binary: "/usr/bin/curl",
		Payload: []byte(payload)})
	r := l.List(1, ListFilter{}, "127.0.0.1")[0]
	if r.Headers["Authorization"] != "[REDACTED]" {
		t.Fatalf("Authorization not redacted: %q", r.Headers["Authorization"])
	}
	if strings.Contains(r.Headers["Authorization"], "supersecret") {
		t.Fatalf("secret leaked into stored header")
	}
}

func TestCookieHeaderRedacted(t *testing.T) {
	l := New(Options{AllowedBinaries: []string{"app"}})
	payload := "GET / HTTP/1.1\r\nHost: x\r\nCookie: SESSIONID=abc123\r\n\r\n"
	l.Observe(Event{Time: time.Now(), Binary: "app", Payload: []byte(payload)})
	r := l.List(1, ListFilter{}, "127.0.0.1")[0]
	if r.Headers["Cookie"] != "[REDACTED]" {
		t.Fatalf("Cookie not redacted: %q", r.Headers["Cookie"])
	}
}

func TestJSONFieldsRedacted(t *testing.T) {
	body := `{"username":"alice","password":"hunter2","token":"abc","nested":{"api_key":"xyz"}}`
	red := redactJSONFields(body)
	for _, k := range []string{"hunter2", "abc", "xyz"} {
		if strings.Contains(red, k) {
			t.Fatalf("secret %q leaked: %s", k, red)
		}
	}
	if !strings.Contains(red, `"username":"alice"`) {
		t.Fatalf("non-secret field stripped: %s", red)
	}
}

func TestBodyTruncated(t *testing.T) {
	l := New(Options{
		AllowedBinaries: []string{"app"},
		MaxBodyKB:       1, // 1 KB cap
	})
	big := strings.Repeat("x", 4096)
	payload := "POST / HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\n\r\n" + big
	l.Observe(Event{Time: time.Now(), Binary: "app", Payload: []byte(payload)})
	r := l.List(1, ListFilter{}, "127.0.0.1")[0]
	if !r.Truncated {
		t.Fatalf("expected Truncated=true")
	}
	if !strings.Contains(r.BodyText, "[...truncated") {
		t.Fatalf("missing truncation marker: %q", r.BodyText[len(r.BodyText)-80:])
	}
}

func TestRingBufferEvictsOldest(t *testing.T) {
	l := New(Options{
		AllowedBinaries: []string{"app"},
		RingSize:        3,
	})
	for i := 0; i < 5; i++ {
		l.Observe(Event{
			Time:    time.Unix(int64(i), 0),
			Binary:  "app",
			Payload: []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		})
	}
	recs := l.List(10, ListFilter{}, "127.0.0.1")
	if len(recs) != 3 {
		t.Fatalf("got %d records, want 3", len(recs))
	}
	// Newest first; we wrote times 0..4; expect 4, 3, 2
	if got := recs[0].Time.Unix(); got != 4 {
		t.Fatalf("newest record time=%d want 4", got)
	}
	if got := recs[2].Time.Unix(); got != 2 {
		t.Fatalf("oldest surviving record time=%d want 2", got)
	}
}

func TestAuditLoggerCalled(t *testing.T) {
	ca := &captureAuditor{}
	l := New(Options{
		AllowedBinaries: []string{"app"},
		AuditLogger:     ca,
	})
	l.Observe(Event{Time: time.Now(), Binary: "app",
		Payload: []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")})
	l.List(10, ListFilter{}, "1.2.3.4")
	r := l.List(10, ListFilter{}, "1.2.3.4")
	if len(r) == 0 {
		t.Fatalf("no records")
	}
	if _, ok := l.Get(r[0].ID, "5.6.7.8"); !ok {
		t.Fatalf("Get returned !ok for known id")
	}
	if _, ok := l.Get("nope", "5.6.7.8"); ok {
		t.Fatalf("Get on missing id reported ok")
	}
	if ca.count() < 3 {
		t.Fatalf("expected ≥ 3 audit entries, got %d", ca.count())
	}
}

func TestConcurrentObserveAndList(t *testing.T) {
	l := New(Options{
		AllowedBinaries: []string{"app"},
		RingSize:        100,
	})
	var wg sync.WaitGroup
	var stop atomic.Bool
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				l.Observe(Event{
					Time:    time.Now(),
					Binary:  "app",
					Payload: []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
				})
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				_ = l.List(50, ListFilter{}, "127.0.0.1")
				_ = l.Stats()
			}
		}()
	}
	time.Sleep(100 * time.Millisecond)
	stop.Store(true)
	wg.Wait()
}

func TestAddRemoveAllowAtRuntime(t *testing.T) {
	l := New(Options{})
	l.AddAllow("foo")
	if !contains(l.AllowList(), "foo") {
		t.Fatalf("AddAllow did not persist")
	}
	l.RemoveAllow("foo")
	if contains(l.AllowList(), "foo") {
		t.Fatalf("RemoveAllow did not clear")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

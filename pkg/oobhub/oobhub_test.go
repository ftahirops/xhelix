package oobhub

import (
	"context"
	"errors"
	"net"
	"testing"
)

// fakeTransport returns programmed dial results.
type fakeTransport struct {
	name      string
	priority  int
	available bool
	dialErr   error
	dialed    int
}

func (f *fakeTransport) Name() string    { return f.name }
func (f *fakeTransport) Priority() int   { return f.priority }
func (f *fakeTransport) Available() bool { return f.available }
func (f *fakeTransport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	f.dialed++
	if f.dialErr != nil {
		return nil, f.dialErr
	}
	// Return a closed conn pair just to satisfy the interface.
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return c1, nil
}

func TestRegisterAndOrder(t *testing.T) {
	m := New()
	m.Register(&fakeTransport{name: "c", priority: 3, available: true})
	m.Register(&fakeTransport{name: "a", priority: 1, available: true})
	m.Register(&fakeTransport{name: "b", priority: 2, available: true})
	got := m.Names()
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("priority order wrong: %v", got)
	}
}

func TestRegisterReplacesByName(t *testing.T) {
	m := New()
	m.Register(&fakeTransport{name: "x", priority: 1})
	m.Register(&fakeTransport{name: "x", priority: 9})
	if len(m.transports) != 1 {
		t.Fatalf("register-by-name should replace; got %d", len(m.transports))
	}
	if m.transports[0].Priority() != 9 {
		t.Fatalf("priority not updated; got %d", m.transports[0].Priority())
	}
}

func TestUnregister(t *testing.T) {
	m := New()
	m.Register(&fakeTransport{name: "x", priority: 1})
	m.Register(&fakeTransport{name: "y", priority: 2})
	m.Unregister("x")
	if got := m.Names(); len(got) != 1 || got[0] != "y" {
		t.Fatalf("Unregister failed; got %v", got)
	}
}

func TestDialEmptyManagerErrors(t *testing.T) {
	m := New()
	if _, err := m.Dial(context.Background(), "hub:9443"); err == nil {
		t.Fatal("dial with no transports should error")
	}
}

func TestDialFirstAvailable(t *testing.T) {
	m := New()
	t1 := &fakeTransport{name: "primary", priority: 1, available: true}
	t2 := &fakeTransport{name: "fallback", priority: 2, available: true}
	m.Register(t1)
	m.Register(t2)
	res, err := m.Dial(context.Background(), "hub:9443")
	if err != nil {
		t.Fatal(err)
	}
	if res.TransportName != "primary" {
		t.Fatalf("primary should have been used; got %s", res.TransportName)
	}
	_ = res.Conn.Close()
	if t1.dialed != 1 || t2.dialed != 0 {
		t.Fatalf("primary should have been dialed once and fallback not at all; %d/%d", t1.dialed, t2.dialed)
	}
}

func TestFallbackOnPrimaryError(t *testing.T) {
	m := New()
	t1 := &fakeTransport{name: "primary", priority: 1, available: true, dialErr: errors.New("nope")}
	t2 := &fakeTransport{name: "fallback", priority: 2, available: true}
	m.Register(t1)
	m.Register(t2)
	res, err := m.Dial(context.Background(), "hub:9443")
	if err != nil {
		t.Fatal(err)
	}
	if res.TransportName != "fallback" {
		t.Fatalf("expected fallback; got %s", res.TransportName)
	}
	_ = res.Conn.Close()
}

func TestSkipsUnavailable(t *testing.T) {
	m := New()
	t1 := &fakeTransport{name: "primary", priority: 1, available: false}
	t2 := &fakeTransport{name: "fallback", priority: 2, available: true}
	m.Register(t1)
	m.Register(t2)
	res, _ := m.Dial(context.Background(), "hub:9443")
	if res.TransportName != "fallback" {
		t.Fatalf("expected fallback when primary unavailable; got %s", res.TransportName)
	}
	_ = res.Conn.Close()
	if t1.dialed != 0 {
		t.Errorf("primary should never have been dialed")
	}
}

func TestErrorWhenAllFail(t *testing.T) {
	m := New()
	m.Register(&fakeTransport{name: "a", priority: 1, available: true, dialErr: errors.New("a-down")})
	m.Register(&fakeTransport{name: "b", priority: 2, available: true, dialErr: errors.New("b-down")})
	if _, err := m.Dial(context.Background(), "hub:9443"); err == nil {
		t.Fatal("expected error when every transport fails")
	}
}

func TestErrorWhenNoneAvailable(t *testing.T) {
	m := New()
	m.Register(&fakeTransport{name: "x", priority: 1, available: false})
	if _, err := m.Dial(context.Background(), "hub:9443"); err == nil {
		t.Fatal("expected error when no transport Available")
	}
}

func TestStatsRecordCounters(t *testing.T) {
	m := New()
	t1 := &fakeTransport{name: "primary", priority: 1, available: true}
	t2 := &fakeTransport{name: "secondary", priority: 2, available: true, dialErr: errors.New("oops")}
	m.Register(t1)
	m.Register(t2)
	for i := 0; i < 3; i++ {
		res, _ := m.Dial(context.Background(), "hub:9443")
		_ = res.Conn.Close()
	}
	snap := m.Stats()
	if len(snap) != 2 {
		t.Fatalf("snap len = %d", len(snap))
	}
	var primary StatSnapshot
	for _, s := range snap {
		if s.Name == "primary" {
			primary = s
		}
	}
	if primary.Successes != 3 {
		t.Errorf("primary successes = %d, want 3", primary.Successes)
	}
}

func TestRegisterNilIgnored(t *testing.T) {
	m := New()
	m.Register(nil)
	if len(m.Names()) != 0 {
		t.Fatal("nil transport should not register")
	}
}

package idlehint

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeSource returns programmed sums in sequence.
type fakeSource struct {
	values []uint64
	idx    int
	err    error
}

func (f *fakeSource) CounterSum() (uint64, error) {
	if f.err != nil {
		return 0, f.err
	}
	if f.idx >= len(f.values) {
		return f.values[len(f.values)-1], nil
	}
	v := f.values[f.idx]
	f.idx++
	return v, nil
}

func TestFirstPollIsActive(t *testing.T) {
	d := New(&fakeSource{values: []uint64{1000}}, time.Second)
	active, err := d.Poll()
	if err != nil {
		t.Fatal(err)
	}
	if !active {
		t.Fatal("first poll should be active (optimistic bootstrap)")
	}
}

func TestActivityDetected(t *testing.T) {
	d := New(&fakeSource{values: []uint64{100, 200, 250}}, time.Second)
	t0 := time.Unix(1000, 0)
	d.now = func() time.Time { return t0 }
	_, _ = d.Poll() // bootstrap at t0
	active, _ := d.Poll()
	if !active {
		t.Fatal("counter delta should mean active")
	}
	if d.SinceLastActivity() != 0 {
		t.Errorf("SinceLastActivity = %v, want 0", d.SinceLastActivity())
	}
}

func TestIdleAfterThreshold(t *testing.T) {
	d := New(&fakeSource{values: []uint64{100, 100, 100, 100}}, 2*time.Second)
	t0 := time.Unix(1000, 0)
	d.now = func() time.Time { return t0 }
	_, _ = d.Poll() // bootstrap, lastChange = t0
	d.now = func() time.Time { return t0.Add(time.Second) }
	active, _ := d.Poll()
	if !active {
		t.Fatal("within threshold (1s < 2s) should still be active")
	}
	d.now = func() time.Time { return t0.Add(3 * time.Second) }
	active, _ = d.Poll()
	if active {
		t.Fatal("past threshold should be idle")
	}
}

func TestIdleBreaksOnNewActivity(t *testing.T) {
	d := New(&fakeSource{values: []uint64{100, 100, 200}}, time.Second)
	t0 := time.Unix(1000, 0)
	d.now = func() time.Time { return t0 }
	_, _ = d.Poll() // bootstrap
	d.now = func() time.Time { return t0.Add(5 * time.Second) }
	if active, _ := d.Poll(); active {
		t.Fatal("should be idle before activity returns")
	}
	d.now = func() time.Time { return t0.Add(6 * time.Second) }
	if active, _ := d.Poll(); !active {
		t.Fatal("delta should re-activate")
	}
	if d.IsIdle() {
		t.Fatal("IsIdle should return false after fresh activity")
	}
}

func TestSourceErrorSurfaced(t *testing.T) {
	d := New(&fakeSource{err: errors.New("boom")}, time.Second)
	if _, err := d.Poll(); err == nil {
		t.Fatal("expected error from source")
	}
}

func TestIsIdleBeforeBootstrap(t *testing.T) {
	d := New(&fakeSource{values: []uint64{1}}, time.Second)
	if d.IsIdle() {
		t.Fatal("IsIdle before any Poll should be false")
	}
	if d.SinceLastActivity() != 0 {
		t.Fatal("SinceLastActivity before Poll should be 0")
	}
}

func TestProcInterruptsParserSums(t *testing.T) {
	s := NewProcInterruptsSource("/dev/null")
	// Synthetic /proc/interrupts content with i8042 + USB HID.
	content := `           CPU0       CPU1
  1:    1234567       42  IO-APIC    1-edge      i8042
 12:       8888      111  IO-APIC   12-edge      i8042
 16:        100        0  IO-APIC   16-fasteoi   ehci_hcd:usb1
 18:         42       17  PCI-MSI    524288-edge USB HID keyboard
TLB:          0        0   TLB shootdowns
`
	got, err := s.sumReader(strings.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	// Expected: 1234567+42 + 8888+111 + 42+17 = 1243667
	want := uint64(1234567 + 42 + 8888 + 111 + 42 + 17)
	if got != want {
		t.Fatalf("sum = %d, want %d", got, want)
	}
}

func TestProcInterruptsIgnoresUnmatched(t *testing.T) {
	s := NewProcInterruptsSource("/dev/null")
	// No keyboard / mouse lines.
	content := `           CPU0
  1:        123     TLB shootdowns
 16:        100     ehci_hcd:usb1
`
	// usb1 alone isn't in our pattern set — should not match.
	got, _ := s.sumReader(strings.NewReader(content))
	if got != 0 {
		t.Fatalf("unmatched lines summed to %d, want 0", got)
	}
}

func TestProcInterruptsPatternsConfigurable(t *testing.T) {
	s := &ProcInterruptsSource{Patterns: []string{"foo"}}
	content := `  1: 99 IO-APIC 1-edge FOO device
  2: 50 IO-APIC 2-edge bar`
	got, _ := s.sumReader(strings.NewReader(content))
	if got != 99 {
		t.Fatalf("pattern match summed to %d, want 99", got)
	}
}

func TestProcInterruptsMissingFile(t *testing.T) {
	s := NewProcInterruptsSource("/tmp/does-not-exist-9999-xhelix")
	if _, err := s.CounterSum(); err == nil {
		t.Fatal("expected error from missing file")
	}
}

func TestDefaultThreshold(t *testing.T) {
	d := New(nil, 0)
	if d.IdleThreshold != 60*time.Second {
		t.Fatalf("default threshold = %v", d.IdleThreshold)
	}
}

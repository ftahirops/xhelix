//go:build linux

package ebpf

import "testing"

func TestSensorHealth_DropBreakdown(t *testing.T) {
	b := &linuxBackend{}
	b.dropRingbuf.Add(3)
	b.dropConsumerFull.Add(4)
	s := &Sensor{backend: b}
	h := s.Health()
	if h.DropRingbuf != 3 || h.DropConsumerFull != 4 {
		t.Fatalf("breakdown wrong: %+v", h)
	}
	if h.DropCount != 7 {
		t.Fatalf("DropCount=%d want 7 (combined)", h.DropCount)
	}
}

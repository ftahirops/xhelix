//go:build linux

package ebpf

import "testing"

func TestDropCounters_Breakdown(t *testing.T) {
	b := &linuxBackend{}
	b.dropRingbuf.Add(2)
	b.dropConsumerFull.Add(5)
	b.dropDecode.Add(1)
	if got := b.DropRingbuf(); got != 2 {
		t.Fatalf("DropRingbuf=%d want 2", got)
	}
	if got := b.DropConsumerFull(); got != 5 {
		t.Fatalf("DropConsumerFull=%d want 5", got)
	}
	if got := b.DropDecode(); got != 1 {
		t.Fatalf("DropDecode=%d want 1", got)
	}
	if got := b.Drops(); got != 8 {
		t.Fatalf("Drops combined=%d want 8", got)
	}
}

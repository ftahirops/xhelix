package verdictcount

import (
	"sync"
	"testing"
)

func TestCounter_RecordAndDrain(t *testing.T) {
	c := New()
	c.Record("critical")
	c.Record("high")
	c.Record("high")
	c.Record("watch")
	cr, h, tot := c.Drain()
	if cr != 1 || h != 2 || tot != 4 {
		t.Fatalf("got %d/%d/%d want 1/2/4", cr, h, tot)
	}
	cr, h, tot = c.Drain()
	if cr != 0 || h != 0 || tot != 0 {
		t.Fatal("drain must reset")
	}
}

func TestCounter_Concurrent(t *testing.T) {
	c := New()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c.Record("critical") }()
	}
	wg.Wait()
	if cr, _, tot := c.Drain(); cr != 100 || tot != 100 {
		t.Fatalf("got %d/%d want 100/100", cr, tot)
	}
}

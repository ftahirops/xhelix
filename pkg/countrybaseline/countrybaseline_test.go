package countrybaseline

import (
	"testing"
	"time"
)

func TestFirstObservationIsNovel(t *testing.T) {
	d := New(0)
	a := d.Observe("firefox-sha", "US")
	if !a.IsNovel {
		t.Fatal("first observation should be novel")
	}
	if a.HitCount != 1 {
		t.Fatalf("hit_count = %d, want 1", a.HitCount)
	}
}

func TestSecondObservationSameCountryNotNovel(t *testing.T) {
	d := New(0)
	d.Observe("firefox-sha", "US")
	a := d.Observe("firefox-sha", "US")
	if a.IsNovel {
		t.Fatal("second observation of same country should not be novel")
	}
	if a.HitCount != 2 {
		t.Fatalf("hit_count = %d, want 2", a.HitCount)
	}
}

func TestNovelPerBinary(t *testing.T) {
	d := New(0)
	d.Observe("firefox-sha", "US")
	a := d.Observe("snapd-sha", "US") // different binary, first US contact
	if !a.IsNovel {
		t.Fatal("US is novel to snapd-sha")
	}
}

func TestConfidenceGate(t *testing.T) {
	d := New(7 * 24 * time.Hour)
	t0 := time.Unix(1000, 0)
	d.now = func() time.Time { return t0 }
	d.Observe("firefox", "US")
	if d.IsConfident("firefox") {
		t.Fatal("immediate IsConfident should be false")
	}
	d.now = func() time.Time { return t0.Add(8 * 24 * time.Hour) }
	if !d.IsConfident("firefox") {
		t.Fatal("after window IsConfident should be true")
	}
}

func TestIsConfidentUnknownBinaryFalse(t *testing.T) {
	d := New(time.Hour)
	if d.IsConfident("unknown") {
		t.Fatal("unknown binary should not be confident")
	}
}

func TestKnownCountriesSorted(t *testing.T) {
	d := New(0)
	d.Observe("ff", "US")
	d.Observe("ff", "CA")
	d.Observe("ff", "DE")
	got := d.KnownCountries("ff")
	if len(got) != 3 || got[0] != "CA" || got[1] != "DE" || got[2] != "US" {
		t.Fatalf("got %v", got)
	}
}

func TestStats(t *testing.T) {
	d := New(0)
	d.Observe("a", "US")
	d.Observe("a", "CA")
	d.Observe("b", "US")
	s := d.Stats()
	if s.Binaries != 2 {
		t.Errorf("binaries = %d", s.Binaries)
	}
	if s.Countries != 2 {
		t.Errorf("countries = %d", s.Countries)
	}
}

func TestSnapshotAndLoadRoundTrip(t *testing.T) {
	d := New(0)
	d.Observe("ff", "US")
	d.Observe("ff", "CA")
	d.Observe("snapd", "NL")

	snap := d.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("snap len = %d", len(snap))
	}

	d2 := New(0)
	d2.Load(snap)
	if !equalKnown(d2.KnownCountries("ff"), []string{"CA", "US"}) {
		t.Fatalf("ff countries after Load = %v", d2.KnownCountries("ff"))
	}
}

func TestForget(t *testing.T) {
	d := New(0)
	d.Observe("ff", "US")
	d.Forget("ff")
	if len(d.KnownCountries("ff")) != 0 {
		t.Fatal("Forget did not clear baseline")
	}
}

func TestEmptyKeyOrCountryIgnored(t *testing.T) {
	d := New(0)
	a := d.Observe("", "US")
	if a.IsNovel || a.HitCount != 0 {
		t.Fatal("empty key should be ignored")
	}
	a = d.Observe("ff", "")
	if a.IsNovel || a.HitCount != 0 {
		t.Fatal("empty country should be ignored")
	}
}

func equalKnown(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

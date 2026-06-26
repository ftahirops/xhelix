package synth

import (
	"reflect"
	"testing"
)

func TestGeneralizeWriteRoots_GlobsAboveThreshold(t *testing.T) {
	o := Observed{WriteDirs: map[string][]string{
		"/u/up": {"/u/up/a.jpg", "/u/up/b.jpg", "/u/up/c.jpg"}, // 3 leaves
	}}
	got := GeneralizeWriteRoots(o, 3) // >=3 → glob
	if !reflect.DeepEqual(got, []string{"/u/up/**"}) {
		t.Errorf("got %v, want [/u/up/**]", got)
	}
}

func TestGeneralizeWriteRoots_ExactBelowThreshold(t *testing.T) {
	o := Observed{WriteDirs: map[string][]string{
		"/u/up": {"/u/up/a.jpg", "/u/up/b.jpg"}, // 2 leaves, threshold 3
	}}
	got := GeneralizeWriteRoots(o, 3)
	want := []string{"/u/up/a.jpg", "/u/up/b.jpg"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestGeneralizeWriteRoots_MixedDirsSortedDistinct(t *testing.T) {
	o := Observed{WriteDirs: map[string][]string{
		"/u/up":   {"/u/up/a", "/u/up/b", "/u/up/c"}, // glob
		"/u/logs": {"/u/logs/x.log"},                 // exact
	}}
	got := GeneralizeWriteRoots(o, 3)
	want := []string{"/u/logs/x.log", "/u/up/**"} // sorted
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestGeneralizeWriteRoots_ThresholdOneAlwaysGlobs(t *testing.T) {
	o := Observed{WriteDirs: map[string][]string{"/d": {"/d/one"}}}
	if got := GeneralizeWriteRoots(o, 1); !reflect.DeepEqual(got, []string{"/d/**"}) {
		t.Errorf("threshold 1 should glob a single leaf, got %v", got)
	}
}

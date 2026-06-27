package synth

import (
	"reflect"
	"testing"
)

func TestGeneralizeExecPaths_GoBuildCollapses(t *testing.T) {
	in := []string{
		"/tmp/go-build2191397473/b001/exe/codemap_gen",
		"/tmp/go-build701149590/b001/exe/routeextract",
	}
	got := GeneralizeExecPaths(in)
	if !reflect.DeepEqual(got, []string{"/tmp/go-build*/**"}) {
		t.Errorf("got %v, want [/tmp/go-build*/**] (both ephemeral build exes collapse + dedup)", got)
	}
}

func TestGeneralizeExecPaths_VersionSegmentNormalized(t *testing.T) {
	in := []string{
		"/root/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.11.linux-amd64/pkg/tool/linux_amd64/cgo",
	}
	got := GeneralizeExecPaths(in)
	want := []string{"/root/go/pkg/mod/golang.org/toolchain@*/pkg/tool/linux_amd64/cgo"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (@version collapsed, structure kept)", got, want)
	}
}

func TestGeneralizeExecPaths_StablePathsVerbatim(t *testing.T) {
	in := []string{"/usr/bin/gcc", "/usr/bin/bash", "/usr/bin/date"}
	got := GeneralizeExecPaths(in)
	want := []string{"/usr/bin/bash", "/usr/bin/date", "/usr/bin/gcc"} // sorted, unchanged
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v (stable paths pass through verbatim)", got, want)
	}
}

func TestGeneralizeExecPaths_DedupAfterGeneralization(t *testing.T) {
	// Two distinct versioned paths of the same module collapse to one.
	in := []string{
		"/r/mod/x@v1.2.3/cmd/tool",
		"/r/mod/x@v4.5.6/cmd/tool",
		"/usr/bin/bash",
	}
	got := GeneralizeExecPaths(in)
	want := []string{"/r/mod/x@*/cmd/tool", "/usr/bin/bash"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

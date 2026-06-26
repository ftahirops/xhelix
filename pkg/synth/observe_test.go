package synth

import (
	"sort"
	"testing"

	"github.com/xhelix/xhelix/pkg/recorder"
)

type fakeReader struct {
	shapes   []recorder.ShapeRow
	byKey    map[string]map[recorder.EdgeKind]map[string][]string // shapeHash -> kind -> key -> raws
}

func (f fakeReader) Shapes(_ string) ([]recorder.ShapeRow, error) { return f.shapes, nil }
func (f fakeReader) ExemplarsByKey(_ , shapeHash string, kind recorder.EdgeKind) (map[string][]string, error) {
	if m, ok := f.byKey[shapeHash]; ok {
		return m[kind], nil
	}
	return map[string][]string{}, nil
}

func TestGather_UnionsAcrossShapes(t *testing.T) {
	r := fakeReader{
		shapes: []recorder.ShapeRow{
			{AppID: "shop", ShapeHash: "s1", Count: 10},
			{AppID: "shop", ShapeHash: "s2", Count: 5},
		},
		byKey: map[string]map[recorder.EdgeKind]map[string][]string{
			"s1": {
				recorder.EdgeExec:   {"curl": {"/usr/bin/curl"}},
				recorder.EdgeEgress: {"api.stripe.com:443": {"api.stripe.com:443"}},
				recorder.EdgeWrite:  {"/u/up": {"/u/up/a.jpg", "/u/up/b.jpg"}},
			},
			"s2": {
				recorder.EdgeExec:  {"curl": {"/usr/bin/curl"}}, // dup across shapes
				recorder.EdgeWrite: {"/u/up": {"/u/up/c.jpg"}, "/u/logs": {"/u/logs/x.log"}},
			},
		},
	}
	got, err := Gather(r, "shop")
	if err != nil {
		t.Fatal(err)
	}
	if got.SampleCount != 15 {
		t.Errorf("SampleCount = %d, want 15", got.SampleCount)
	}
	if len(got.ExecRaws) != 1 || got.ExecRaws[0] != "/usr/bin/curl" {
		t.Errorf("ExecRaws = %v, want [/usr/bin/curl] (deduped)", got.ExecRaws)
	}
	if len(got.EgressKeys) != 1 || got.EgressKeys[0] != "api.stripe.com:443" {
		t.Errorf("EgressKeys = %v", got.EgressKeys)
	}
	up := got.WriteDirs["/u/up"]
	sort.Strings(up)
	if len(up) != 3 { // a,b from s1 + c from s2
		t.Errorf("WriteDirs[/u/up] = %v, want 3 leaves", up)
	}
	if len(got.WriteDirs["/u/logs"]) != 1 {
		t.Errorf("WriteDirs[/u/logs] = %v, want 1", got.WriteDirs["/u/logs"])
	}
}

package vendorcatalog

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultContainsPlesk(t *testing.T) {
	c := Default()
	found := false
	for _, v := range c.Vendors {
		if v.Name == "plesk" {
			found = true
			if len(v.Detect) == 0 || len(v.Binaries) == 0 {
				t.Fatal("plesk entry must have Detect and Binaries")
			}
		}
	}
	if !found {
		t.Fatal("default catalog missing plesk")
	}
}

func TestAutoDetectFindsExistingPath(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "version")
	if err := os.WriteFile(marker, []byte("1.0"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &Catalog{Vendors: []Vendor{{
		Name:     "synthetic",
		Detect:   []string{marker},
		Binaries: []string{"/opt/synthetic/*"},
	}}}
	dets := c.AutoDetect()
	if len(dets) != 1 || dets[0].Vendor != "synthetic" {
		t.Fatalf("autodetect failed: %+v", dets)
	}
	if dets[0].Reason != marker {
		t.Fatalf("reason: %s", dets[0].Reason)
	}
}

func TestAutoDetectSkipsMissing(t *testing.T) {
	c := &Catalog{Vendors: []Vendor{{
		Name:   "ghost",
		Detect: []string{"/no/such/path/anywhere"},
	}}}
	if got := c.AutoDetect(); len(got) != 0 {
		t.Fatalf("expected empty, got %+v", got)
	}
}

func TestLoadDirOverlays(t *testing.T) {
	dir := t.TempDir()
	yml := `name: customstack
detect: ["` + dir + `/marker"]
binaries: ["/usr/bin/customstack-*"]
`
	if err := os.WriteFile(filepath.Join(dir, "custom.yaml"), []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, v := range c.Vendors {
		if v.Name == "customstack" {
			found = true
		}
	}
	if !found {
		t.Fatal("custom vendor not loaded")
	}
}

func TestLoadDirMissingIsOK(t *testing.T) {
	c, err := LoadDir("/nonexistent/path/xhelix-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Vendors) == 0 {
		t.Fatal("expected default vendors")
	}
}

func TestAllBinariesConcatenates(t *testing.T) {
	dets := []Detection{
		{Vendor: "a", Binaries: []string{"/a/*"}},
		{Vendor: "b", Binaries: []string{"/b/*", "/b2/*"}},
	}
	all := AllBinaries(dets)
	if len(all) != 3 {
		t.Fatalf("expected 3 globs, got %v", all)
	}
}

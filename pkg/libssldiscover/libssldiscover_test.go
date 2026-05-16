package libssldiscover

import (
	"os/exec"
	"testing"
)

func TestDiscoverFindsHostLibssl(t *testing.T) {
	// This is an integration test that depends on the host
	// having libssl installed. Skip if absent.
	targets := Discover(nil)
	if len(targets) == 0 {
		t.Skip("no libssl-class library found on this host")
	}
	for _, tgt := range targets {
		if tgt.LibPath == "" || tgt.Symbol == "" {
			t.Errorf("malformed target: %+v", tgt)
		}
		if tgt.Offset == 0 {
			t.Errorf("zero offset for %+v", tgt)
		}
		if tgt.Family == FamilyUnknown {
			t.Errorf("unclassified family for %+v", tgt)
		}
	}
	t.Logf("discovered %d targets", len(targets))
	for _, tgt := range targets {
		t.Logf("  %s :: %s at 0x%x (%s)", tgt.LibPath, tgt.Symbol, tgt.Offset, tgt.Family)
	}
}

func TestDiscoverSingleOpenSSL(t *testing.T) {
	tgt, ok := DiscoverSingle("libssl.so", nil)
	if !ok {
		t.Skip("no libssl.so on host")
	}
	if tgt.Family != FamilyOpenSSL {
		t.Errorf("family = %s, want openssl", tgt.Family)
	}
	if tgt.Symbol != "SSL_read" && tgt.Symbol != "SSL_read_ex" {
		t.Errorf("symbol = %s", tgt.Symbol)
	}
}

func TestResolveSymbolUnknownLib(t *testing.T) {
	if _, err := ResolveSymbol("/nonexistent.so", "x"); err == nil {
		t.Fatal("missing file should error")
	}
}

func TestResolveSymbolMissingSymbol(t *testing.T) {
	tgt, ok := DiscoverSingle("libssl.so", nil)
	if !ok {
		t.Skip("no libssl.so")
	}
	if _, err := ResolveSymbol(tgt.LibPath, "totally_made_up_symbol_xyz"); err == nil {
		t.Fatal("missing symbol must error")
	}
}

func TestIsLikelyStaticBinary(t *testing.T) {
	// /usr/bin/ls is dynamically linked on every distro I've
	// touched — should report false.
	lsPath, err := exec.LookPath("ls")
	if err != nil {
		t.Skip("ls not in PATH")
	}
	if IsLikelyStaticBinary(lsPath) {
		t.Errorf("%s reported static; almost certainly wrong", lsPath)
	}
}

func TestDiscoverWithEmptyPathsUsesDefaults(t *testing.T) {
	a := Discover(nil)
	b := Discover(DefaultSearchPaths)
	if len(a) != len(b) {
		t.Errorf("default-path resolution diverged: %d vs %d", len(a), len(b))
	}
}

func TestLibCatalogShape(t *testing.T) {
	// Compile-time-ish check that every entry has both prefix
	// and symbol populated.
	for _, e := range libCatalog {
		if e.prefix == "" || e.symbol == "" {
			t.Errorf("malformed libCatalog entry: %+v", e)
		}
	}
}

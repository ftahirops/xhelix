package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xhelix/xhelix/pkg/contractarm"
)

func newTestApplier(t *testing.T) (*liveEgressApplier, *[]string, string) {
	t.Helper()
	dir := t.TempDir()
	var ran []string
	arm := &contractarm.Armorer{SystemdDir: dir, Runner: func(a ...string) error { ran = append(ran, strings.Join(a, " ")); return nil }}
	return newLiveEgressApplier(arm), &ran, dir
}

func TestLiveApplierWritesDropInAndReloadsOnce(t *testing.T) {
	a, ran, dir := newTestApplier(t)
	if err := a.Apply("nginx.service", []string{"1.1.1.1/32", "10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Commit(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "nginx.service.d", "51-xhelix-egress-dynamic.conf"))
	if err != nil {
		t.Fatalf("drop-in not written: %v", err)
	}
	if !strings.Contains(string(b), "IPAddressAllow=1.1.1.1/32 10.0.0.0/8") {
		t.Errorf("bad drop-in content:\n%s", string(b))
	}
	if strings.Contains(string(b), "IPAddressDeny") || strings.Contains(string(b), "localhost") {
		t.Errorf("dynamic file must not carry deny/localhost (floor owns them):\n%s", string(b))
	}
	if len(*ran) != 1 || (*ran)[0] != "daemon-reload" {
		t.Errorf("expected exactly one daemon-reload, got %v", *ran)
	}
}

func TestLiveApplierEmptySetGuardColdStart(t *testing.T) {
	a, ran, dir := newTestApplier(t)
	// First-ever apply with an empty set must NOT write a lockout file.
	if err := a.Apply("nginx.service", nil); err != nil {
		t.Fatal(err)
	}
	a.Commit()
	if _, err := os.Stat(filepath.Join(dir, "nginx.service.d", "51-xhelix-egress-dynamic.conf")); !os.IsNotExist(err) {
		t.Error("empty set on cold start must NOT create a lockout drop-in")
	}
	if len(*ran) != 0 {
		t.Errorf("no change -> no reload; got %v", *ran)
	}
}

func TestLiveApplierEmptyAfterNonEmptyIsLockdown(t *testing.T) {
	a, _, dir := newTestApplier(t)
	a.Apply("nginx.service", []string{"1.1.1.1/32"}) // non-empty first
	a.Commit()
	a.Apply("nginx.service", nil) // now empty -> intentional lockdown allowed
	a.Commit()
	b, _ := os.ReadFile(filepath.Join(dir, "nginx.service.d", "51-xhelix-egress-dynamic.conf"))
	if !strings.Contains(string(b), "IPAddressAllow=\n") && !strings.HasSuffix(strings.TrimRight(string(b), "\n"), "IPAddressAllow=") {
		t.Errorf("empty set after a non-empty set should write an empty allow (lockdown):\n%s", string(b))
	}
}

func TestLiveApplierForgetRemovesDropIn(t *testing.T) {
	a, _, dir := newTestApplier(t)
	a.Apply("nginx.service", []string{"1.1.1.1/32"}); a.Commit()
	p := filepath.Join(dir, "nginx.service.d", "51-xhelix-egress-dynamic.conf")
	if _, err := os.Stat(p); err != nil {
		t.Fatal("setup: drop-in missing")
	}
	a.Forget("nginx.service"); a.Commit()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("Forget should delete the unit's dynamic drop-in")
	}
}

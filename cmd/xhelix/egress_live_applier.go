package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/xhelix/xhelix/pkg/contractarm"
)

const liveEgressDropIn = "51-xhelix-egress-dynamic.conf"

// liveEgressApplier implements egressrefresh.Applier (SP-1b.2b.2). It writes
// each live unit's dynamic allow-set to its own 51- drop-in and batches a
// single `systemctl daemon-reload` per Commit. The drop-in carries ONLY the
// IPAddressAllow list; the deny floor + localhost/link-local live in the
// arm-time floor drop-in, so removing an IP here genuinely shrinks the
// running filter (proven by the SP-1b.2b.2 spike). Mechanism: drop-in
// rewrite + daemon-reload (NOT set-property).
type liveEgressApplier struct {
	arm *contractarm.Armorer

	mu          sync.Mutex
	hadNonEmpty map[string]bool // unit -> has ever had a non-empty set applied
	dirty       bool            // a file changed this cycle -> reload on Commit
}

func newLiveEgressApplier(arm *contractarm.Armorer) *liveEgressApplier {
	return &liveEgressApplier{arm: arm, hadNonEmpty: map[string]bool{}}
}

func (a *liveEgressApplier) dropInPath(unit string) string {
	return filepath.Join(a.arm.SystemdDir, unit+".d", liveEgressDropIn)
}

func (a *liveEgressApplier) Apply(unit string, allowCIDRs []string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Empty-set guard: a cold-start empty set (no IP has ever resolved) must
	// NOT write a lockout. An empty set AFTER a non-empty one is an
	// intentional lockdown and is honoured.
	if len(allowCIDRs) == 0 && !a.hadNonEmpty[unit] {
		return nil
	}
	dir := filepath.Join(a.arm.SystemdDir, unit+".d")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("live egress: mkdir %s: %w", dir, err)
	}
	content := "# Managed by xhelix egressrefresh (SP-1b.2b.2). Do not edit by hand.\n" +
		"[Service]\nIPAddressAllow=" + strings.Join(allowCIDRs, " ") + "\n"
	if err := os.WriteFile(a.dropInPath(unit), []byte(content), 0o644); err != nil {
		return fmt.Errorf("live egress: write %s: %w", a.dropInPath(unit), err)
	}
	if len(allowCIDRs) > 0 {
		a.hadNonEmpty[unit] = true
	}
	a.dirty = true
	return nil
}

// Forget removes a unit's dynamic drop-in and its history (called when a unit
// stops being live). Carry-forward from the SP-1b.2b.1 review.
func (a *liveEgressApplier) Forget(unit string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := os.Remove(a.dropInPath(unit)); err == nil {
		a.dirty = true
	}
	delete(a.hadNonEmpty, unit)
}

func (a *liveEgressApplier) Commit() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.dirty {
		return nil
	}
	a.dirty = false
	return a.arm.Runner("daemon-reload")
}

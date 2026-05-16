// Package sbom implements software bill of materials baseline and
// drift detection for supply-chain security.
//
// It tracks installed packages, versions, and hashes to detect
// unauthorized changes such as the XZ backdoor (CVE-2024-3094).
package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

// Baseline tracks the expected state of system packages and critical
// binaries.
type Baseline struct {
	mu       sync.RWMutex
	path     string
	packages map[string]Package
	binaries map[string]Binary
}

// Package describes one installed system package.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Manager string `json:"manager"` // apt, rpm, apk, etc.
	Hash    string `json:"hash"`    // sha256 of package metadata
}

// Binary describes one critical binary on disk.
type Binary struct {
	Path string `json:"path"`
	Hash string `json:"hash"` // sha256 of file content
}

// NewBaseline loads or creates a baseline at path.
func NewBaseline(path string) (*Baseline, error) {
	b := &Baseline{
		path:     path,
		packages: map[string]Package{},
		binaries: map[string]Binary{},
	}
	if _, err := os.Stat(path); err == nil {
		_ = b.load()
	}
	return b, nil
}

// Scan populates the baseline from the current system state.
func (b *Baseline) Scan() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Detect package manager and scan
	pkgs, err := scanPackages()
	if err != nil {
		return fmt.Errorf("scan packages: %w", err)
	}
	b.packages = pkgs

	// Scan critical binaries
	bins, err := scanCriticalBinaries()
	if err != nil {
		return fmt.Errorf("scan binaries: %w", err)
	}
	b.binaries = bins

	return b.save()
}

// Diff compares the current system state against the baseline and
// returns any drift (new, removed, or modified packages/binaries).
func (b *Baseline) Diff() (*DiffResult, error) {
	b.mu.RLock()
	baselinePkgs := make(map[string]Package, len(b.packages))
	for k, v := range b.packages {
		baselinePkgs[k] = v
	}
	baselineBins := make(map[string]Binary, len(b.binaries))
	for k, v := range b.binaries {
		baselineBins[k] = v
	}
	b.mu.RUnlock()

	currentPkgs, err := scanPackages()
	if err != nil {
		return nil, fmt.Errorf("scan packages: %w", err)
	}
	currentBins, err := scanCriticalBinaries()
	if err != nil {
		return nil, fmt.Errorf("scan binaries: %w", err)
	}

	var result DiffResult

	// Check for new or modified packages
	for name, cp := range currentPkgs {
		bp, ok := baselinePkgs[name]
		if !ok {
			result.NewPackages = append(result.NewPackages, cp)
		} else if bp.Hash != cp.Hash || bp.Version != cp.Version {
			result.ModifiedPackages = append(result.ModifiedPackages, PackageChange{
				Name:     name,
				Expected: bp,
				Actual:   cp,
			})
		}
		delete(baselinePkgs, name)
	}
	// Remaining baseline packages were removed
	for _, bp := range baselinePkgs {
		result.RemovedPackages = append(result.RemovedPackages, bp)
	}

	// Check for new or modified binaries
	for path, cb := range currentBins {
		bb, ok := baselineBins[path]
		if !ok {
			result.NewBinaries = append(result.NewBinaries, cb)
		} else if bb.Hash != cb.Hash {
			result.ModifiedBinaries = append(result.ModifiedBinaries, BinaryChange{
				Path:     path,
				Expected: bb.Hash,
				Actual:   cb.Hash,
			})
		}
		delete(baselineBins, path)
	}
	for _, bb := range baselineBins {
		result.RemovedBinaries = append(result.RemovedBinaries, bb)
	}

	return &result, nil
}

// ToEvents converts a DiffResult into security events.
func (d *DiffResult) ToEvents(host string) []model.Event {
	var events []model.Event
	now := time.Now().UTC()

	for _, p := range d.NewPackages {
		ev := model.NewEvent("sbom.drift", model.SeverityWarn)
		ev.Time = now
		ev.Host = host
		ev.Tags["type"] = "new_package"
		ev.Tags["name"] = p.Name
		ev.Tags["version"] = p.Version
		ev.Tags["manager"] = p.Manager
		ev.Tags["reason"] = fmt.Sprintf("New package installed: %s %s", p.Name, p.Version)
		events = append(events, ev)
	}

	for _, c := range d.ModifiedPackages {
		ev := model.NewEvent("sbom.drift", model.SeverityHigh)
		ev.Time = now
		ev.Host = host
		ev.Tags["type"] = "modified_package"
		ev.Tags["name"] = c.Name
		ev.Tags["expected_version"] = c.Expected.Version
		ev.Tags["actual_version"] = c.Actual.Version
		ev.Tags["reason"] = fmt.Sprintf("Package modified: %s (expected %s, got %s)",
			c.Name, c.Expected.Version, c.Actual.Version)
		events = append(events, ev)
	}

	for _, c := range d.ModifiedBinaries {
		ev := model.NewEvent("sbom.drift", model.SeverityCritical)
		ev.Time = now
		ev.Host = host
		ev.Tags["type"] = "modified_binary"
		ev.Tags["path"] = c.Path
		ev.Tags["expected_hash"] = c.Expected
		ev.Tags["actual_hash"] = c.Actual
		ev.Tags["reason"] = fmt.Sprintf("Binary hash mismatch: %s", c.Path)
		events = append(events, ev)
	}

	return events
}

// DiffResult captures all drift detected between baseline and current state.
type DiffResult struct {
	NewPackages      []Package
	RemovedPackages  []Package
	ModifiedPackages []PackageChange
	NewBinaries      []Binary
	RemovedBinaries  []Binary
	ModifiedBinaries []BinaryChange
}

// PackageChange records a version/hash mismatch.
type PackageChange struct {
	Name     string
	Expected Package
	Actual   Package
}

// BinaryChange records a hash mismatch.
type BinaryChange struct {
	Path     string
	Expected string
	Actual   string
}

func (b *Baseline) save() error {
	data, err := json.MarshalIndent(map[string]interface{}{
		"packages": b.packages,
		"binaries": b.binaries,
		"scanned":  time.Now().UTC(),
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(b.path, data, 0o600)
}

func (b *Baseline) load() error {
	data, err := os.ReadFile(b.path)
	if err != nil {
		return err
	}
	var v struct {
		Packages map[string]Package `json:"packages"`
		Binaries map[string]Binary  `json:"binaries"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	b.packages = v.Packages
	b.binaries = v.Binaries
	return nil
}

func scanPackages() (map[string]Package, error) {
	pkgs := map[string]Package{}

	// Try dpkg
	if _, err := exec.LookPath("dpkg"); err == nil {
		out, err := exec.Command("dpkg-query", "-W", "-f=${Package}\t${Version}\n").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				parts := strings.Split(line, "\t")
				if len(parts) == 2 {
					name := strings.TrimSpace(parts[0])
					ver := strings.TrimSpace(parts[1])
					if name != "" {
						h := sha256.Sum256([]byte(name + ver))
						pkgs[name] = Package{
							Name:    name,
							Version: ver,
							Manager: "dpkg",
							Hash:    hex.EncodeToString(h[:]),
						}
					}
				}
			}
		}
		return pkgs, nil
	}

	// Try rpm
	if _, err := exec.LookPath("rpm"); err == nil {
		out, err := exec.Command("rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				parts := strings.Split(line, "\t")
				if len(parts) == 2 {
					name := strings.TrimSpace(parts[0])
					ver := strings.TrimSpace(parts[1])
					if name != "" {
						h := sha256.Sum256([]byte(name + ver))
						pkgs[name] = Package{
							Name:    name,
							Version: ver,
							Manager: "rpm",
							Hash:    hex.EncodeToString(h[:]),
						}
					}
				}
			}
		}
		return pkgs, nil
	}

	return pkgs, nil
}

func scanCriticalBinaries() (map[string]Binary, error) {
	bins := map[string]Binary{}
	paths := []string{
		"/usr/bin/ssh", "/usr/sbin/sshd",
		"/usr/bin/sudo", "/bin/su",
		"/usr/bin/bash", "/bin/sh",
		"/usr/bin/curl", "/usr/bin/wget",
		"/usr/lib/x86_64-linux-gnu/liblzma.so.5",
		"/lib/x86_64-linux-gnu/liblzma.so.5",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		hash, err := hashFile(p)
		if err != nil {
			continue
		}
		bins[p] = Binary{Path: p, Hash: hash}
	}
	return bins, nil
}

func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

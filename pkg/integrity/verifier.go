package integrity

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Verifier implements execguard.IntegrityVerifier on top of a
// Baseline + optional authentic-upgrade Tester. It is the runtime
// adapter that fuses B1 (baseline) and B2 (authentic-upgrade
// detection) for the B3 (execve-time check) hook.
//
// Decision flow per Verify call:
//  1. Look up Path in Baseline. If absent: TOFU policy — record the
//     row, return allow. (First-time-seen binaries that exist on disk
//     before xhelix observed them are accepted; the alternative is to
//     deny every binary in /usr/local until baselined, which is
//     hostile to operators.)
//  2. Hash the file on disk. If hash matches baseline: allow.
//  3. Hash differs. Consult the Tester (if any) to ask "was the most
//     recent writer of this path an authentic package-manager upgrade
//     lineage?" If yes: refresh the baseline row, allow, source=pkg-mgr.
//  4. Otherwise: deny + reason. Caller (execguard) honors the mode
//     (detect / enforce) to decide whether to actually deny the exec.
//
// Performance: hashing happens once per (path, mtime). A small
// per-(path, mtime) cache eliminates repeated work for re-execs of
// the same binary.
type Verifier struct {
	baseline *Baseline
	tester   *Tester // may be nil — TOFU+hash-match still works
	log      *slog.Logger
	// AcceptTOFU controls policy for paths not in the baseline.
	// True (default) records the first-seen hash and allows.
	// False denies — used in strict mode after baseline is locked.
	AcceptTOFU bool

	// (path|mtime_unix) → matched/cached verdict to avoid rehashing
	// hot binaries on every execve.
	cacheMu sync.RWMutex
	cache   map[string]cacheEntry

	stats struct {
		baselineMatched atomic.Uint64
		hashMismatched  atomic.Uint64
		tofuAccepted    atomic.Uint64
		upgradeRecovers atomic.Uint64
		errors          atomic.Uint64
	}
}

type cacheEntry struct {
	verdict bool
	reason  string
}

// NewVerifier wires a baseline + (optional) authentic-upgrade tester.
func NewVerifier(b *Baseline, t *Tester, log *slog.Logger) *Verifier {
	if log == nil {
		log = slog.Default()
	}
	return &Verifier{
		baseline:   b,
		tester:     t,
		log:        log,
		AcceptTOFU: true,
		cache:      map[string]cacheEntry{},
	}
}

// Verify implements execguard.IntegrityVerifier.
func (v *Verifier) Verify(path string, pid uint32) (bool, string) {
	if v == nil || v.baseline == nil || path == "" {
		return true, ""
	}
	st, err := os.Stat(path)
	if err != nil {
		v.stats.errors.Add(1)
		// Can't stat — exec will probably fail anyway; allow and audit.
		return true, fmt.Sprintf("integrity: stat %s failed: %v", path, err)
	}
	cacheKey := fmt.Sprintf("%s|%d", path, st.ModTime().Unix())
	v.cacheMu.RLock()
	if e, ok := v.cache[cacheKey]; ok {
		v.cacheMu.RUnlock()
		return e.verdict, e.reason
	}
	v.cacheMu.RUnlock()

	verdict, reason := v.verifyUncached(path, pid, st)

	v.cacheMu.Lock()
	v.cache[cacheKey] = cacheEntry{verdict: verdict, reason: reason}
	v.cacheMu.Unlock()
	return verdict, reason
}

func (v *Verifier) verifyUncached(path string, pid uint32, st os.FileInfo) (bool, string) {
	row, found, err := v.baseline.Lookup(path)
	if err != nil {
		v.stats.errors.Add(1)
		return true, fmt.Sprintf("integrity: baseline lookup error: %v", err)
	}

	hash, size, mt, err := HashFile(path, DefaultMaxFileSize)
	if err != nil {
		v.stats.errors.Add(1)
		return true, fmt.Sprintf("integrity: hash failed: %v", err)
	}

	if !found {
		if !v.AcceptTOFU {
			return false, fmt.Sprintf("integrity: %s not in baseline (TOFU disabled)", path)
		}
		_ = v.baseline.Upsert(Row{
			Path:      path,
			SHA256:    hash,
			Size:      size,
			MtimeUnix: mt.Unix(),
			Source:    SourceTOFU,
			AddedAt:   time.Now().UTC(),
		})
		v.stats.tofuAccepted.Add(1)
		return true, fmt.Sprintf("integrity: %s TOFU baselined", path)
	}

	if row.SHA256 == hash {
		v.stats.baselineMatched.Add(1)
		return true, "" // hot path — silent
	}

	// Hash mismatch. Consult B2 if available.
	v.stats.hashMismatched.Add(1)
	if v.tester != nil && pid != 0 {
		verdict := v.tester.Verify(pid, path, hash)
		if verdict.Authentic {
			// Refresh baseline with the new authentic hash.
			_ = v.baseline.Upsert(Row{
				Path:      path,
				SHA256:    hash,
				Size:      size,
				MtimeUnix: mt.Unix(),
				Source:    SourcePkgMgr,
				Package:   verdict.Package,
				AddedAt:   row.AddedAt,
			})
			v.stats.upgradeRecovers.Add(1)
			return true, fmt.Sprintf("integrity: authentic %s upgrade (writer=%s)",
				verdict.Manager, verdict.Reason)
		}
	}
	return false, fmt.Sprintf("integrity: SHA mismatch for %s — expected %s, got %s (writer not authentic)",
		path, row.SHA256[:12], hash[:12])
}

// Stats are observable counters for the integrity dashboard.
type VerifierStats struct {
	BaselineMatched uint64
	HashMismatched  uint64
	TOFUAccepted    uint64
	UpgradeRecovers uint64
	Errors          uint64
}

// Stats returns counter snapshot.
func (v *Verifier) Stats() VerifierStats {
	return VerifierStats{
		BaselineMatched: v.stats.baselineMatched.Load(),
		HashMismatched:  v.stats.hashMismatched.Load(),
		TOFUAccepted:    v.stats.tofuAccepted.Load(),
		UpgradeRecovers: v.stats.upgradeRecovers.Load(),
		Errors:          v.stats.errors.Load(),
	}
}

// InvalidateCache clears the per-(path, mtime) verdict cache. Call
// after a baseline rebuild or manual policy change.
func (v *Verifier) InvalidateCache() {
	v.cacheMu.Lock()
	v.cache = map[string]cacheEntry{}
	v.cacheMu.Unlock()
}

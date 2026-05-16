// Package baseline implements per-image LOLBin profiling for xhelix.
//
// Living-off-the-land binaries (curl, wget, bash, python, …) are
// tools attackers reuse instead of dropping new binaries. The
// challenge: many of these are also legitimate. Detection works by
// learning, per parent image, which LOLBins it normally invokes and
// alerting on first-time-unusual ones.
package baseline

import (
	"sync"
	"time"
)

// LOLBins is the set of binaries we treat as living-off-the-land
// candidates. Curated from the Falco LOLBins ruleset and operator
// experience.
var LOLBins = map[string]struct{}{
	"bash": {}, "sh": {}, "dash": {}, "zsh": {}, "ksh": {}, "ash": {},
	"curl": {}, "wget": {}, "fetch": {}, "scp": {}, "rsync": {},
	"nc": {}, "ncat": {}, "socat": {},
	"python": {}, "python3": {}, "perl": {}, "ruby": {}, "lua": {},
	"awk": {}, "sed": {}, "tee": {}, "xxd": {}, "base64": {},
	"gcc": {}, "cc": {}, "as": {}, "ld": {},
	"strace": {}, "ltrace": {}, "gdb": {},
	"iptables": {}, "nft": {}, "ip": {}, "ss": {},
	"openssl": {}, "ssh": {}, "sshpass": {},
	"find": {}, "xargs": {},
	"systemctl": {}, "service": {},
}

// IsLOLBin reports whether comm is a known LOLBin.
func IsLOLBin(comm string) bool {
	_, ok := LOLBins[comm]
	return ok
}

// LOLBin tracks per-parent-image profiles of which LOLBins are
// invoked, with frequency.
type LOLBin struct {
	WarmupDays uint  // default 7
	startedAt  time.Time

	mu       sync.RWMutex
	profiles map[string]*Profile
}

// Profile is one parent image's LOLBin invocation history.
type Profile struct {
	Image       string
	Invocations map[string]uint64 // child comm -> count
	UniqueChild map[string]uint64 // child arg0 -> count
	FirstSeen   time.Time
	LastSeen    time.Time
}

// New returns a LOLBin tracker.
func New(warmupDays uint) *LOLBin {
	if warmupDays == 0 {
		warmupDays = 7
	}
	return &LOLBin{
		WarmupDays: warmupDays,
		startedAt:  time.Now(),
		profiles:   map[string]*Profile{},
	}
}

// Observe records that parentImage invoked childComm. Returns true
// if this is anomalous — i.e., warmup is over and childComm has
// never been observed under this parentImage.
func (l *LOLBin) Observe(parentImage, childComm string, t time.Time) bool {
	if !IsLOLBin(childComm) {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	p, ok := l.profiles[parentImage]
	if !ok {
		p = &Profile{
			Image:       parentImage,
			Invocations: map[string]uint64{},
			UniqueChild: map[string]uint64{},
			FirstSeen:   t,
		}
		l.profiles[parentImage] = p
	}
	p.LastSeen = t

	_, seen := p.Invocations[childComm]
	p.Invocations[childComm]++

	// During warmup, never alert; just learn.
	if time.Since(l.startedAt) < time.Duration(l.WarmupDays)*24*time.Hour {
		return false
	}
	// After warmup, first-time invocation is anomalous.
	return !seen
}

// IsUnusual asks whether parentImage invoking childComm would be
// flagged as anomalous (without recording the invocation). Used by
// the CEL helper baseline.is_lolbin_unusual.
func (l *LOLBin) IsUnusual(parentImage, childComm string) bool {
	if !IsLOLBin(childComm) {
		return false
	}
	if time.Since(l.startedAt) < time.Duration(l.WarmupDays)*24*time.Hour {
		return false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	p, ok := l.profiles[parentImage]
	if !ok {
		return true // never seen this parent
	}
	_, seen := p.Invocations[childComm]
	return !seen
}

// Snapshot returns a copy of every profile. Useful for the TUI.
func (l *LOLBin) Snapshot() []Profile {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]Profile, 0, len(l.profiles))
	for _, p := range l.profiles {
		cp := *p
		out = append(out, cp)
	}
	return out
}

// SetWarmupComplete forces warmup to be considered done. Used by
// tests to exercise the alerting path without 7 days of clock
// advancement.
func (l *LOLBin) SetWarmupComplete() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.startedAt = time.Now().Add(-time.Duration(l.WarmupDays+1) * 24 * time.Hour)
}

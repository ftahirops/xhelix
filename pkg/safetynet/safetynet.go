// Package safetynet provides a global never-block allow-list and a
// block-with-observation list. Other xhelix subsystems consult
// safetynet before installing any deny rule — this is the single
// source of truth for "is this IP allowed/blocked".
//
// Design notes:
//
//   - always_allow is a hard veto: any IP that matches a prefix here
//     MUST NOT be blocked by netban, egressguard, containment, or any
//     future enforcement mechanism. Operator's own management IP lives
//     here so a buggy auto-block can't lock them out of the box.
//
//   - block_observe is a parallel drop-and-log set: traffic from/to
//     these IPs is dropped at the nftables layer AND every attempt is
//     captured (src/dst/port/proto) so the operator can see what those
//     IPs are trying to do.
//
//   - All methods are nil-safe so callers can pass a nil *SafetyNet
//     when the feature is disabled or not yet wired.
//
//   - CIDRs are linear-walked on every check. The lists are tiny (<100
//     entries in practice). If that ever changes, swap to a trie.
//
// IPv6 status: parse/store works for v6 prefixes in the allow list
// (AllowAlways handles v6 correctly). The block_observe nftables
// install is v4-only in this cut — see nftables.go header for the
// honest non-promise.
package safetynet

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// SafetyNet is the runtime store of allow/block CIDRs + recent
// blocked-attempt log.
type SafetyNet struct {
	mu       sync.RWMutex
	allow    []netip.Prefix // never-block, vetoes other blocks
	block    []netip.Prefix // drop + log
	attempts ring           // last N blocked attempts

	// Counters
	allowChecks uint64
	allowHits   uint64
	blockChecks uint64
	blockHits   uint64
}

// Attempt is one blocked-traffic record observed in nftables logs.
type Attempt struct {
	Time    time.Time `json:"time"`
	SrcIP   string    `json:"src_ip"`
	DstIP   string    `json:"dst_ip"`
	DstPort uint16    `json:"dst_port"`
	Proto   string    `json:"proto"`
	Bytes   uint64    `json:"bytes"`
}

// ring is a fixed-size circular buffer of Attempt.
type ring struct {
	buf  []Attempt
	pos  int
	full bool
}

// Stats reports counters + current list sizes.
type Stats struct {
	AllowChecks uint64 `json:"allow_checks"`
	AllowHits   uint64 `json:"allow_hits"`
	BlockChecks uint64 `json:"block_checks"`
	BlockHits   uint64 `json:"block_hits"`
	AllowCount  int    `json:"allow_count"`
	BlockCount  int    `json:"block_count"`
	AttemptsLog int    `json:"attempts_log"`
}

// New constructs a SafetyNet with the given allow/block CIDRs.
// Returns parse errors with which CIDR was bad. attemptHistory <= 0
// selects the 1000-entry default.
func New(allowCIDRs, blockCIDRs []string, attemptHistory int) (*SafetyNet, error) {
	if attemptHistory <= 0 {
		attemptHistory = 1000
	}
	s := &SafetyNet{
		attempts: ring{buf: make([]Attempt, attemptHistory)},
	}
	for _, c := range allowCIDRs {
		p, err := parsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("safetynet: bad always_allow %q: %w", c, err)
		}
		s.allow = append(s.allow, p)
	}
	for _, c := range blockCIDRs {
		p, err := parsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("safetynet: bad block_observe %q: %w", c, err)
		}
		// block_observe is v4-only in this cut.
		if !p.Addr().Is4() && !p.Addr().Is4In6() {
			return nil, fmt.Errorf("safetynet: block_observe %q is IPv6; v6 blocklist deferred (Phase 2)", c)
		}
		s.block = append(s.block, p)
	}
	return s, nil
}

// parsePrefix accepts "1.2.3.4", "1.2.3.4/32", "fe80::/10", etc.
// Bare addresses are upgraded to /32 (v4) or /128 (v6).
func parsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	bits := 32
	if addr.Is6() && !addr.Is4In6() {
		bits = 128
	}
	return netip.PrefixFrom(addr, bits), nil
}

func ipToAddr(ip net.IP) (netip.Addr, bool) {
	if ip == nil {
		return netip.Addr{}, false
	}
	if v4 := ip.To4(); v4 != nil {
		return netip.AddrFrom4([4]byte{v4[0], v4[1], v4[2], v4[3]}), true
	}
	a, ok := netip.AddrFromSlice(ip)
	return a, ok
}

// AllowAlways returns true if the IP should be vetoed from any block
// decision. Nil-safe.
func (s *SafetyNet) AllowAlways(ip net.IP) bool {
	if s == nil {
		return false
	}
	atomic.AddUint64(&s.allowChecks, 1)
	addr, ok := ipToAddr(ip)
	if !ok {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.allow {
		if p.Contains(addr) {
			atomic.AddUint64(&s.allowHits, 1)
			return true
		}
	}
	return false
}

// IsBlocked returns true if this IP is on the block-observe list.
// Nil-safe.
func (s *SafetyNet) IsBlocked(ip net.IP) bool {
	if s == nil {
		return false
	}
	atomic.AddUint64(&s.blockChecks, 1)
	addr, ok := ipToAddr(ip)
	if !ok {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.block {
		if p.Contains(addr) {
			atomic.AddUint64(&s.blockHits, 1)
			return true
		}
	}
	return false
}

// RecordAttempt appends a blocked-traffic observation. Nil-safe.
func (s *SafetyNet) RecordAttempt(a Attempt) {
	if s == nil {
		return
	}
	if a.Time.IsZero() {
		a.Time = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.attempts.buf) == 0 {
		return
	}
	s.attempts.buf[s.attempts.pos] = a
	s.attempts.pos++
	if s.attempts.pos >= len(s.attempts.buf) {
		s.attempts.pos = 0
		s.attempts.full = true
	}
}

// RecentAttempts returns up to n most-recent blocked attempts,
// newest first. Nil-safe (returns nil).
func (s *SafetyNet) RecentAttempts(n int) []Attempt {
	if s == nil || n <= 0 {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	size := len(s.attempts.buf)
	if size == 0 {
		return nil
	}
	count := s.attempts.pos
	if s.attempts.full {
		count = size
	}
	if n > count {
		n = count
	}
	out := make([]Attempt, 0, n)
	// Walk backwards from the most recently written slot.
	idx := s.attempts.pos - 1
	for i := 0; i < n; i++ {
		if idx < 0 {
			idx = size - 1
		}
		out = append(out, s.attempts.buf[idx])
		idx--
	}
	return out
}

// AddAllow adds a CIDR (or bare IP) to the allow list. Nil-safe.
func (s *SafetyNet) AddAllow(cidr string) error {
	if s == nil {
		return fmt.Errorf("safetynet: not enabled")
	}
	p, err := parsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("safetynet: bad CIDR %q: %w", cidr, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.allow {
		if existing == p {
			return nil // idempotent
		}
	}
	s.allow = append(s.allow, p)
	return nil
}

// RemoveAllow removes a CIDR from the allow list. Returns nil if
// absent (idempotent). Nil-safe.
func (s *SafetyNet) RemoveAllow(cidr string) error {
	if s == nil {
		return fmt.Errorf("safetynet: not enabled")
	}
	p, err := parsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("safetynet: bad CIDR %q: %w", cidr, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.allow[:0]
	for _, existing := range s.allow {
		if existing != p {
			out = append(out, existing)
		}
	}
	s.allow = out
	return nil
}

// AddBlock adds a CIDR to the block-observe list. v4-only in this cut.
// Nil-safe.
func (s *SafetyNet) AddBlock(cidr string) error {
	if s == nil {
		return fmt.Errorf("safetynet: not enabled")
	}
	p, err := parsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("safetynet: bad CIDR %q: %w", cidr, err)
	}
	if !p.Addr().Is4() && !p.Addr().Is4In6() {
		return fmt.Errorf("safetynet: block_observe %q is IPv6; v6 blocklist deferred (Phase 2)", cidr)
	}
	// Refuse to block any IP that's in always_allow — the allow list
	// is a hard veto. Operator must remove from allow first if they
	// really want to block. This prevents accidental lockout via UI.
	s.mu.RLock()
	for _, allowed := range s.allow {
		if allowed.Overlaps(p) || p.Overlaps(allowed) {
			s.mu.RUnlock()
			return fmt.Errorf("safetynet: refusing to block %q — it overlaps always_allow entry %q", cidr, allowed.String())
		}
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.block {
		if existing == p {
			return nil
		}
	}
	s.block = append(s.block, p)
	return nil
}

// RemoveBlock removes a CIDR from the block-observe list. Nil-safe.
func (s *SafetyNet) RemoveBlock(cidr string) error {
	if s == nil {
		return fmt.Errorf("safetynet: not enabled")
	}
	p, err := parsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("safetynet: bad CIDR %q: %w", cidr, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.block[:0]
	for _, existing := range s.block {
		if existing != p {
			out = append(out, existing)
		}
	}
	s.block = out
	return nil
}

// AllowList returns a snapshot of allow CIDRs. Nil-safe (returns nil).
func (s *SafetyNet) AllowList() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.allow))
	for i, p := range s.allow {
		out[i] = p.String()
	}
	return out
}

// BlockList returns a snapshot of block CIDRs. Nil-safe (returns nil).
func (s *SafetyNet) BlockList() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.block))
	for i, p := range s.block {
		out[i] = p.String()
	}
	return out
}

// Stats returns hit/check counters and current sizes. Nil-safe.
func (s *SafetyNet) Stats() Stats {
	if s == nil {
		return Stats{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	logged := s.attempts.pos
	if s.attempts.full {
		logged = len(s.attempts.buf)
	}
	return Stats{
		AllowChecks: atomic.LoadUint64(&s.allowChecks),
		AllowHits:   atomic.LoadUint64(&s.allowHits),
		BlockChecks: atomic.LoadUint64(&s.blockChecks),
		BlockHits:   atomic.LoadUint64(&s.blockHits),
		AllowCount:  len(s.allow),
		BlockCount:  len(s.block),
		AttemptsLog: logged,
	}
}

// Package nrd is a pure-Go Bloom filter for Newly-Registered-
// Domain tracking. Domains registered in the last N days are a
// disproportionate fraction of phishing / C2 infrastructure
// (one-shot phishing kits, freshly-rotated DGA seeds).
//
// Operators load a daily feed (whoisds.com, Cisco Umbrella's NRD
// feed, etc.) into a Filter via Load(reader); xhelix's intel
// provider chain consults Contains(domain) on every resolved
// hostname. Bloom-filter false positives mean "this might be NRD";
// negatives are authoritative.
//
// The filter is pure-Go, uses xxhash-style double-hashing for
// k independent hash functions over a single bit array, and is
// safe for concurrent reads. Writes (Load, Add) take a write lock.
package nrd

import (
	"bufio"
	"encoding/binary"
	"hash/fnv"
	"io"
	"math"
	"strings"
	"sync"
)

// Filter is the Bloom filter.
type Filter struct {
	mu      sync.RWMutex
	bits    []uint64
	m       uint64 // number of bits (size of bit array)
	k       uint64 // number of hash functions
	count   uint64 // number of Add calls (informational)
	loadAt  string // optional human-readable timestamp from the feed
}

// New returns a Filter sized for `expectedItems` with a target
// `fpRate` (e.g. 0.001 for 0.1%). Both must be > 0.
//
// Sizing formulas (Bloom standard):
//
//	m = -n * ln(p) / (ln(2))^2
//	k = m / n * ln(2)
func New(expectedItems uint64, fpRate float64) *Filter {
	if expectedItems == 0 {
		expectedItems = 1
	}
	if fpRate <= 0 || fpRate >= 1 {
		fpRate = 0.001
	}
	m := uint64(math.Ceil(-float64(expectedItems) * math.Log(fpRate) / (math.Ln2 * math.Ln2)))
	if m < 64 {
		m = 64
	}
	k := uint64(math.Round(float64(m) / float64(expectedItems) * math.Ln2))
	if k < 1 {
		k = 1
	}
	if k > 16 {
		k = 16
	}
	return &Filter{
		bits: make([]uint64, (m+63)/64),
		m:    m,
		k:    k,
	}
}

// Add inserts a domain. Domain is normalised (lowercase, trim
// trailing dot, drop "www." prefix).
func (f *Filter) Add(domain string) {
	d := normalize(domain)
	if d == "" {
		return
	}
	h1, h2 := hash64(d)
	f.mu.Lock()
	for i := uint64(0); i < f.k; i++ {
		bit := (h1 + i*h2) % f.m
		f.bits[bit/64] |= 1 << (bit % 64)
	}
	f.count++
	f.mu.Unlock()
}

// Contains reports whether domain *might* be in the filter. A true
// return is a probabilistic positive (bounded by the configured
// false-positive rate); a false return is authoritative.
func (f *Filter) Contains(domain string) bool {
	d := normalize(domain)
	if d == "" {
		return false
	}
	h1, h2 := hash64(d)
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.m == 0 {
		return false
	}
	for i := uint64(0); i < f.k; i++ {
		bit := (h1 + i*h2) % f.m
		if f.bits[bit/64]&(1<<(bit%64)) == 0 {
			return false
		}
	}
	return true
}

// Load reads one domain per line from r and Adds each. Lines
// starting with '#' are treated as comments. Returns the number
// of domains added.
func (f *Filter) Load(r io.Reader) (int, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f.Add(line)
		n++
	}
	return n, sc.Err()
}

// SetLoadStamp records an operator-supplied timestamp for the
// most recent Load. Free-form string; consulted by status output.
func (f *Filter) SetLoadStamp(s string) {
	f.mu.Lock()
	f.loadAt = s
	f.mu.Unlock()
}

// LoadStamp returns the timestamp set by SetLoadStamp.
func (f *Filter) LoadStamp() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.loadAt
}

// Stats returns operational counters.
type Stats struct {
	Bits         uint64
	Hashes       uint64
	Items        uint64
	BitsSetEst   float64 // estimated bit-set count from items (informational)
	FillRatio    float64 // BitsSetEst / Bits — feeds the FP rate
}

// Stats returns a snapshot. BitsSet is estimated rather than
// counted (cheaper); a precise count would walk the whole bit
// array.
func (f *Filter) Stats() Stats {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.m == 0 {
		return Stats{}
	}
	// Approximation: each Add hits k bits, but collisions reduce
	// the effective set count. Using the standard Bloom-fill
	// formula:  set ≈ m * (1 - (1 - 1/m)^(k*items))
	expSet := float64(f.m) * (1 - math.Pow(1-1/float64(f.m), float64(f.k*f.count)))
	return Stats{
		Bits: f.m, Hashes: f.k, Items: f.count,
		BitsSetEst: expSet, FillRatio: expSet / float64(f.m),
	}
}

// EstimatedFPRate returns the current expected false-positive rate
// given Items already inserted.
func (f *Filter) EstimatedFPRate() float64 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.m == 0 || f.count == 0 {
		return 0
	}
	// FP ≈ (1 - e^(-k*n/m))^k
	exponent := -float64(f.k*f.count) / float64(f.m)
	return math.Pow(1-math.Exp(exponent), float64(f.k))
}

// Reset clears the bit array.
func (f *Filter) Reset() {
	f.mu.Lock()
	for i := range f.bits {
		f.bits[i] = 0
	}
	f.count = 0
	f.mu.Unlock()
}

// ── helpers ───────────────────────────────────────────────────

// normalize lowercases, strips trailing dot, drops "www." prefix
// (operators sometimes feed the bloom with or without).
func normalize(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimSuffix(d, ".")
	d = strings.TrimPrefix(d, "www.")
	return d
}

// hash64 returns two independent 64-bit hashes used for Bloom
// double-hashing. We use fnv-1a and a byte-rotated variant —
// cheap, dependency-free, sufficient for filter use.
func hash64(s string) (uint64, uint64) {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	h1 := h.Sum64()

	// Second hash: same FNV state seeded with a different prefix.
	h.Reset()
	var seed [8]byte
	binary.LittleEndian.PutUint64(seed[:], 0x9E3779B97F4A7C15) // golden ratio
	_, _ = h.Write(seed[:])
	_, _ = h.Write([]byte(s))
	h2 := h.Sum64()
	if h2 == 0 {
		h2 = 1 // avoid degenerate step
	}
	return h1, h2
}

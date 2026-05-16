// Package dnsexfil detects DNS-based command-and-control and data
// exfiltration.
//
// Why DNS: even paranoid networks let outbound DNS through, and
// recursive resolvers happily forward arbitrary subdomain queries to
// the attacker's authoritative server. So:
//
//   data exfiltration: encode payload as base32/64 in subdomain labels
//                      e.g. ZGF0YQ.attacker.example.com
//   C2 over DNS:        TXT record responses carry commands
//   tunneling:          high query rate to a single domain, often
//                      with TXT record responses
//
// We catch this without DPI by watching the rhythm and shape of DNS
// queries, per registered domain (effective TLD + 1):
//
//   query rate          legitimate domains: 1-100/min spread.
//                       DNS tunnel: 1000+/min concentrated on one.
//   label entropy       legitimate labels: low entropy (real words).
//                       encoded payload: high entropy (≈4.5 bits/byte).
//   label length        legitimate: 5-25 chars typically.
//                       payload: 20+ chars, often max-length 63.
//   TXT response %      legitimate: rare for most users.
//                       C2: TXT-heavy.
//
// The shape signal alone is enough to flag the most common DNS
// tunnels (dnscat2, iodine, custom Go implants). Operators tune
// thresholds for their environment.
package dnsexfil

import (
	"math"
	"strings"
	"sync"
	"time"
)

// Event is one DNS query we observed.
type Event struct {
	Domain    string // the FULL queried name, e.g. "AAAABBBB.evil.com"
	QType     string // "A", "AAAA", "TXT", ...
	At        time.Time
}

// Verdict is what the detector returns when a domain crosses thresholds.
type Verdict struct {
	RegDomain   string        // the registered domain, e.g. "evil.com"
	Reasons     []string      // human-readable signals
	Queries     int
	WindowSpan  time.Duration
	AvgLabelLen float64
	AvgEntropy  float64
	TxtFraction float64
}

// Config tunes the detector.
type Config struct {
	// Window is the rolling-window length. Older events drop out.
	// Default: 5 minutes.
	Window time.Duration
	// MinQueriesPerWindow before we even consider firing.
	// Default: 30.
	MinQueriesPerWindow int
	// MaxLabelLen — average label length above which we suspect
	// encoding. Default: 25.
	MaxLabelLen float64
	// MaxEntropy — Shannon entropy of label characters above which
	// labels look like base32/64 payload. Range 0..log2(N) where N
	// is alphabet size. ASCII-letters labels typically come in around
	// 3.5 bits; base32 is ≈4.0; base64 ≈4.5; random hex ≈4.0.
	// Default: 3.8.
	MaxEntropy float64
	// MaxTxtFraction — fraction of queries that are TXT. Default 0.4.
	MaxTxtFraction float64
	// MinReasonsToFire — N of (rate, label-len, entropy, txt-frac)
	// that must trigger before we emit. Default 2.
	MinReasonsToFire int
}

// Detector keeps per-registered-domain rolling stats.
type Detector struct {
	cfg Config
	mu  sync.Mutex
	by  map[string]*window
	verdicts map[string]time.Time
}

type window struct {
	events []Event
	totalLabelLen int
	totalEntropySum float64
	txtCount      int
}

func New(cfg Config) *Detector {
	if cfg.Window == 0 {
		cfg.Window = 5 * time.Minute
	}
	if cfg.MinQueriesPerWindow == 0 {
		cfg.MinQueriesPerWindow = 30
	}
	if cfg.MaxLabelLen == 0 {
		cfg.MaxLabelLen = 25
	}
	if cfg.MaxEntropy == 0 {
		cfg.MaxEntropy = 3.8
	}
	if cfg.MaxTxtFraction == 0 {
		cfg.MaxTxtFraction = 0.4
	}
	if cfg.MinReasonsToFire == 0 {
		cfg.MinReasonsToFire = 2
	}
	return &Detector{cfg: cfg, by: map[string]*window{}, verdicts: map[string]time.Time{}}
}

// Observe records a DNS query and may return a Verdict.
func (d *Detector) Observe(e Event) *Verdict {
	if e.Domain == "" {
		return nil
	}
	reg := registeredDomain(e.Domain)
	if reg == "" {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	w, ok := d.by[reg]
	if !ok {
		w = &window{}
		d.by[reg] = w
	}
	// Trim old events outside the window.
	cutoff := e.At.Add(-d.cfg.Window)
	for len(w.events) > 0 && w.events[0].At.Before(cutoff) {
		old := w.events[0]
		w.events = w.events[1:]
		w.totalLabelLen -= maxLabelLen(old.Domain)
		w.totalEntropySum -= maxLabelEntropy(old.Domain)
		if old.QType == "TXT" {
			w.txtCount--
		}
	}
	w.events = append(w.events, e)
	w.totalLabelLen += maxLabelLen(e.Domain)
	w.totalEntropySum += maxLabelEntropy(e.Domain)
	if e.QType == "TXT" {
		w.txtCount++
	}

	if len(w.events) < d.cfg.MinQueriesPerWindow {
		return nil
	}

	avgLen := float64(w.totalLabelLen) / float64(len(w.events))
	avgEnt := w.totalEntropySum / float64(len(w.events))
	txtFrac := float64(w.txtCount) / float64(len(w.events))
	span := w.events[len(w.events)-1].At.Sub(w.events[0].At)
	// Guard against same-timestamp bursts (common in tests, also seen
	// when an event source delivers batches with identical .At). A
	// zero span used to divide to +Inf, spuriously contributing the
	// "rate" reason. Treat zero-span as rate=0 — if the burst pattern
	// itself is suspicious, the other features (entropy/label-len)
	// will catch it on their own merits.
	rate := 0.0
	if span > 0 {
		rate = float64(len(w.events)) / span.Minutes()
	}

	var reasons []string
	if rate >= 60 {
		reasons = append(reasons, "rate")
	}
	if avgLen >= d.cfg.MaxLabelLen {
		reasons = append(reasons, "label_len")
	}
	if avgEnt >= d.cfg.MaxEntropy {
		reasons = append(reasons, "entropy")
	}
	if txtFrac >= d.cfg.MaxTxtFraction {
		reasons = append(reasons, "txt")
	}
	if len(reasons) < d.cfg.MinReasonsToFire {
		return nil
	}
	if last, ok := d.verdicts[reg]; ok && e.At.Sub(last) < d.cfg.Window {
		return nil
	}
	d.verdicts[reg] = e.At
	return &Verdict{
		RegDomain:   reg,
		Reasons:     reasons,
		Queries:     len(w.events),
		WindowSpan:  span,
		AvgLabelLen: avgLen,
		AvgEntropy:  avgEnt,
		TxtFraction: txtFrac,
	}
}

// Sweep purges idle windows.
func (d *Detector) Sweep(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, w := range d.by {
		if len(w.events) == 0 || now.Sub(w.events[len(w.events)-1].At) > 2*d.cfg.Window {
			delete(d.by, k)
		}
	}
	for k, t := range d.verdicts {
		if now.Sub(t) > 24*time.Hour {
			delete(d.verdicts, k)
		}
	}
}

// registeredDomain returns the eTLD+1 for a query. We use a tiny
// built-in suffix list — this is intentionally simplistic. Operators
// who need real public-suffix-list support can wrap with a richer
// resolver; for detection purposes the simple "last two labels"
// heuristic catches the vast majority of cases.
//
// Special cases: foo.co.uk → co.uk + foo? We handle a small set of
// known double-suffix TLDs.
func registeredDomain(name string) string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return ""
	}
	// Heuristic: if the last two labels are a known double-suffix,
	// take the last three. Otherwise last two.
	doubleTLDs := map[string]bool{
		"co.uk": true, "ac.uk": true, "gov.uk": true, "org.uk": true,
		"com.au": true, "net.au": true, "org.au": true,
		"co.jp": true, "ne.jp": true, "or.jp": true,
		"com.br": true, "com.cn": true, "com.hk": true,
		"co.za": true, "co.in": true,
	}
	if len(parts) >= 3 {
		tail := parts[len(parts)-2] + "." + parts[len(parts)-1]
		if doubleTLDs[tail] {
			return parts[len(parts)-3] + "." + tail
		}
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

// maxLabelLen returns the longest label in the qname (registered
// domain stripped). This focuses the metric on the dynamic part —
// payload-bearing labels — rather than the static "evil.com".
func maxLabelLen(name string) int {
	name = strings.TrimSuffix(name, ".")
	max := 0
	for _, l := range strings.Split(name, ".") {
		if len(l) > max {
			max = len(l)
		}
	}
	return max
}

// maxLabelEntropy returns the highest Shannon entropy across labels.
func maxLabelEntropy(name string) float64 {
	name = strings.TrimSuffix(name, ".")
	max := 0.0
	for _, l := range strings.Split(name, ".") {
		if len(l) < 8 {
			continue // short labels aren't meaningful
		}
		e := shannon(l)
		if e > max {
			max = e
		}
	}
	return max
}

func shannon(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

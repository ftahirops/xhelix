// Package brandcheck detects phishing-shaped domains by
// comparing a queried name against a registry of legitimate
// brand domains. Four detection families:
//
//   - Typosquat   — within Levenshtein distance ≤ MaxEditDistance
//                   of a brand root, e.g. paypa1.com → paypal.com
//   - Homograph   — Unicode lookalikes (Cyrillic 'а', Greek 'ο',
//                   Punycode 'xn--' encoding of the same)
//   - Combosquat  — brand label appears as a token alongside
//                   security-themed words: paypal-secure-login.com
//   - Bitsquat    — 1-bit-flip neighbour of a brand label,
//                   e.g. pagpal.com (p[1]: 0x61 → 0x67)
//
// Pure-Go. Caller provides the brand seed list; we ship a small
// curated example (50 high-value brands).
package brandcheck

import (
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

// Family classifies which detector fired.
type Family string

const (
	FamilyNone       Family = ""
	FamilyTyposquat  Family = "typosquat"
	FamilyHomograph  Family = "homograph"
	FamilyCombosquat Family = "combosquat"
	FamilyBitsquat   Family = "bitsquat"
)

// Severity grades a hit.
type Severity uint8

const (
	SeverityNone     Severity = 0
	SeverityNotice   Severity = 2
	SeverityWarn     Severity = 3
	SeverityHigh     Severity = 4
	SeverityCritical Severity = 5
)

// Match is the output of one classification.
type Match struct {
	Family       Family
	Brand        string   // canonical brand root that matched
	Distance     int      // edit distance (typosquat) or 0
	Reason       string
	Severity     Severity
	NormalizedQ  string   // unicode-normalised, lowercase, IDNA-decoded
}

// Config controls Classify.
type Config struct {
	// MaxEditDistance is the typosquat threshold. Default 2.
	MaxEditDistance int
	// MinLabelLen — labels shorter than this are skipped to avoid
	// "ab" matching every two-letter label. Default 4.
	MinLabelLen int
}

// Detector holds the brand registry + config.
type Detector struct {
	cfg    Config
	brands []string // canonical root labels (no TLD), lowercase ASCII

	// Two map indexes for cheap lookups.
	brandSet      map[string]struct{} // exact root labels
	brandRootDom  map[string]string   // root label → original brand root domain
}

// NewDetector returns a Detector loaded with the given brand
// registrable-roots (e.g. "paypal.com", "google.com"). Empty list
// uses DefaultBrands().
func NewDetector(cfg Config, brands []string) *Detector {
	if cfg.MaxEditDistance <= 0 {
		cfg.MaxEditDistance = 2
	}
	if cfg.MinLabelLen <= 0 {
		cfg.MinLabelLen = 4
	}
	if len(brands) == 0 {
		brands = DefaultBrands()
	}
	d := &Detector{
		cfg:           cfg,
		brandSet:      map[string]struct{}{},
		brandRootDom:  map[string]string{},
	}
	for _, b := range brands {
		b = strings.ToLower(strings.TrimSuffix(b, "."))
		root := rootLabel(b)
		if root == "" {
			continue
		}
		d.brands = append(d.brands, root)
		d.brandSet[root] = struct{}{}
		d.brandRootDom[root] = b
	}
	return d
}

// Classify checks domain against every brand for the four
// detection families. Returns the *worst* match (highest severity)
// or FamilyNone Match if nothing fires.
func (d *Detector) Classify(domain string) Match {
	q := normalize(domain)
	if q == "" {
		return Match{}
	}
	root := rootLabel(q)

	// Skip exact-match: it's the legitimate brand.
	if _, ok := d.brandSet[root]; ok {
		return Match{NormalizedQ: q}
	}

	best := Match{NormalizedQ: q}

	// 1. Typosquat — edit distance ≤ MaxEditDistance against any
	//    brand root.
	for _, b := range d.brands {
		if len(root) < d.cfg.MinLabelLen {
			break
		}
		dist := levenshteinAtMost(root, b, d.cfg.MaxEditDistance+1)
		if dist > 0 && dist <= d.cfg.MaxEditDistance {
			sev := SeverityHigh
			if dist == 1 {
				sev = SeverityCritical
			}
			if sev > best.Severity {
				best = Match{
					Family: FamilyTyposquat,
					Brand:  d.brandRootDom[b], Distance: dist,
					Severity:    sev,
					Reason:      "edit-distance " + itoa(dist) + " from " + b,
					NormalizedQ: q,
				}
			}
		}
	}

	// 2. Homograph — IDN/punycode decode changed the visible name.
	//    If the punycode-decoded form looks like a brand but the
	//    original ASCII didn't equal it, flag.
	if domain != q && q != "" {
		// q is the unicode form; check if it ASCII-folds to a brand.
		asciiFold := asciiSimulation(q)
		root2 := rootLabel(asciiFold)
		if _, ok := d.brandSet[root2]; ok {
			if best.Severity < SeverityCritical {
				best = Match{
					Family: FamilyHomograph, Brand: d.brandRootDom[root2],
					Severity:    SeverityCritical,
					Reason:      "Unicode lookalike of " + root2,
					NormalizedQ: q,
				}
			}
		}
	}

	// 3. Combosquat — brand appears as a token among security-
	//    themed words.
	if best.Family == FamilyNone {
		if m := combosquatMatch(q, d.brandSet); m.Family != FamilyNone {
			if m.Severity > best.Severity {
				m.NormalizedQ = q
				m.Brand = d.brandRootDom[m.Brand]
				best = m
			}
		}
	}

	// 4. Bitsquat — single-bit-flip neighbour of a brand.
	if best.Family == FamilyNone {
		for _, b := range d.brands {
			if isBitflipNeighbour(root, b) {
				if best.Severity < SeverityHigh {
					best = Match{
						Family: FamilyBitsquat, Brand: d.brandRootDom[b],
						Severity:    SeverityHigh,
						Reason:      "1-bit-flip of " + b,
						NormalizedQ: q,
					}
				}
				break
			}
		}
	}
	return best
}

// ── normalisation ─────────────────────────────────────────────

// normalize lowercases, strips trailing dot, IDNA-decodes Punycode.
func normalize(d string) string {
	d = strings.ToLower(strings.TrimSuffix(d, "."))
	if d == "" {
		return ""
	}
	if u, err := idna.ToUnicode(d); err == nil {
		return u
	}
	return d
}

// asciiSimulation collapses Unicode lookalikes to their ASCII
// equivalents (Cyrillic а→a, Greek ο→o, fullwidth ＡP→ap, etc.).
// This is intentionally lossy — it's the "what a human would
// mistake this for" mapping.
func asciiSimulation(s string) string {
	var b strings.Builder
	for _, r := range s {
		// Cyrillic and Greek lookalikes
		switch r {
		case 'а': r = 'a'
		case 'е': r = 'e'
		case 'о': r = 'o'
		case 'р': r = 'p'
		case 'с': r = 'c'
		case 'у': r = 'y'
		case 'х': r = 'x'
		case 'ο': r = 'o'
		case 'ρ': r = 'p'
		case 'α': r = 'a'
		case 'ι': r = 'i'
		case '0': r = 'o'
		case '1': r = 'l'
		}
		// Fullwidth → halfwidth
		if r >= 0xFF21 && r <= 0xFF3A {
			r = r - 0xFF21 + 'a'
		}
		if r >= 0xFF41 && r <= 0xFF5A {
			r = r - 0xFF41 + 'a'
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// rootLabel returns the registrable root label of d
// ("www.paypal.com" → "paypal", "fonts.gstatic.com" → "gstatic").
// Coarse approximation; doesn't consult the public-suffix list.
func rootLabel(d string) string {
	parts := strings.Split(d, ".")
	if len(parts) < 2 {
		return d
	}
	return parts[len(parts)-2]
}

// ── helpers ───────────────────────────────────────────────────

// levenshteinAtMost computes the Levenshtein distance up to
// maxPlus1. Returns maxPlus1 when actual distance ≥ maxPlus1.
// Significantly faster than full DP for the small-max common case.
func levenshteinAtMost(a, b string, maxPlus1 int) int {
	if a == b {
		return 0
	}
	la, lb := len(a), len(b)
	if abs(la-lb) >= maxPlus1 {
		return maxPlus1
	}
	if la == 0 {
		if lb < maxPlus1 {
			return lb
		}
		return maxPlus1
	}
	if lb == 0 {
		if la < maxPlus1 {
			return la
		}
		return maxPlus1
	}

	prev := make([]int, lb+1)
	cur := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		cur[0] = i
		minInRow := cur[0]
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = minOf(
				prev[j]+1,    // deletion
				cur[j-1]+1,   // insertion
				prev[j-1]+cost, // substitution
			)
			if cur[j] < minInRow {
				minInRow = cur[j]
			}
		}
		if minInRow >= maxPlus1 {
			return maxPlus1
		}
		prev, cur = cur, prev
	}
	return prev[lb]
}

func combosquatMatch(q string, brands map[string]struct{}) Match {
	// Combosquat #1: a brand label and a suspicious keyword
	// appear as hyphen-separated tokens of the same registrable
	// root, e.g. "paypal-secure-login.com".
	root := rootLabel(q)
	tokens := strings.Split(root, "-")
	if len(tokens) >= 2 {
		for _, tok := range tokens {
			if _, ok := brands[tok]; !ok {
				continue
			}
			for _, sib := range tokens {
				if sib != tok && suspiciousToken(sib) {
					return Match{
						Family: FamilyCombosquat, Brand: tok,
						Severity: SeverityHigh,
						Reason:   "brand " + tok + " combined with '" + sib + "'",
					}
				}
			}
		}
	}

	// Combosquat #2: a brand label appears as a subdomain
	// alongside another label that is (or contains) a suspicious
	// keyword — e.g. "paypal.secure-attacker.example".
	labels := strings.Split(q, ".")
	for i := 0; i < len(labels)-1; i++ {
		if _, ok := brands[labels[i]]; !ok {
			continue
		}
		if hasSuspiciousNeighbour(labels) {
			return Match{
				Family: FamilyCombosquat, Brand: labels[i],
				Severity: SeverityHigh,
				Reason:   "brand " + labels[i] + " used as subdomain alongside suspicious labels",
			}
		}
	}
	return Match{}
}

var suspiciousTokens = map[string]struct{}{
	"login": {}, "secure": {}, "account": {}, "verify": {}, "support": {},
	"signin": {}, "auth": {}, "update": {}, "wallet": {}, "billing": {},
	"confirm": {}, "alert": {}, "recover": {}, "reset": {}, "session": {},
	"reissue": {}, "reactivate": {}, "kyc": {}, "id": {}, "online": {},
}

func suspiciousToken(s string) bool {
	_, ok := suspiciousTokens[s]
	return ok
}

func hasSuspiciousNeighbour(labels []string) bool {
	for _, l := range labels {
		// Check the whole label.
		if suspiciousToken(l) {
			return true
		}
		// And each hyphen-separated token within it.
		for _, tok := range strings.Split(l, "-") {
			if suspiciousToken(tok) {
				return true
			}
		}
	}
	return false
}

// isBitflipNeighbour returns true if a and b differ at exactly one
// character position by a power-of-two XOR within the same length.
func isBitflipNeighbour(a, b string) bool {
	if len(a) != len(b) || a == b {
		return false
	}
	diffPos := -1
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			if diffPos >= 0 {
				return false
			}
			diffPos = i
		}
	}
	if diffPos < 0 {
		return false
	}
	xor := a[diffPos] ^ b[diffPos]
	return xor != 0 && (xor&(xor-1)) == 0
}

// DefaultBrands is a 50-brand seed list covering high-value
// phishing targets. Operators extend via config.
func DefaultBrands() []string {
	return []string{
		"paypal.com", "google.com", "gmail.com", "microsoft.com",
		"office.com", "outlook.com", "apple.com", "icloud.com",
		"amazon.com", "facebook.com", "instagram.com", "whatsapp.com",
		"netflix.com", "linkedin.com", "twitter.com", "x.com",
		"github.com", "gitlab.com", "bitbucket.org",
		"chase.com", "wellsfargo.com", "bankofamerica.com",
		"citibank.com", "hsbc.com", "barclays.co.uk",
		"binance.com", "coinbase.com", "kraken.com", "metamask.io",
		"trezor.io", "ledger.com",
		"dropbox.com", "box.com", "onedrive.live.com",
		"adobe.com", "docusign.com",
		"salesforce.com", "slack.com", "zoom.us", "teams.microsoft.com",
		"discord.com", "telegram.org", "signal.org",
		"cloudflare.com", "cloudflareclient.com",
		"stripe.com", "shopify.com", "ebay.com",
		"steamcommunity.com", "epicgames.com", "ubisoft.com",
	}
}

// ── tiny utils ────────────────────────────────────────────────

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
func minOf(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

package forensic

import (
	"net"
	"regexp"
	"strings"
	"time"
)

// ExtractFromText scans a free-form byte stream for IOCs and
// returns observations. Used by every record-specific extractor as
// the shared workhorse.
//
// origin + source are attached to every observation; at sets the
// timestamp.
func ExtractFromText(s, origin, source string, at time.Time) []Observation {
	if s == "" {
		return nil
	}
	var out []Observation
	add := func(k Kind, v string, conf Confidence) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		out = append(out, Observation{
			Kind: k, Value: v, At: at,
			Confidence: conf, Origin: origin, Source: source,
		})
	}

	for _, m := range reURL.FindAllString(s, -1) {
		add(KindURL, m, ConfidenceDeterministic)
		// Parse host out so it lands as a separate Domain IOC.
		if host := hostFromURL(m); host != "" {
			if net.ParseIP(host) != nil {
				if isIPv6(host) {
					add(KindIPv6, host, ConfidenceDeterministic)
				} else {
					add(KindIPv4, host, ConfidenceDeterministic)
				}
			} else {
				add(KindDomain, host, ConfidenceDeterministic)
			}
		}
	}
	for _, m := range reIPv4.FindAllString(s, -1) {
		// Filter out the more common local/test addresses to avoid
		// flooding the IOC store with 127.0.0.1, 0.0.0.0, etc.
		if !shouldKeepIP(m) {
			continue
		}
		add(KindIPv4, m, ConfidenceHigh)
	}
	for _, m := range reIPv6.FindAllString(s, -1) {
		if !shouldKeepIP(m) {
			continue
		}
		add(KindIPv6, m, ConfidenceHigh)
	}
	for _, m := range reEmail.FindAllString(s, -1) {
		add(KindEmail, m, ConfidenceHigh)
	}
	for _, m := range reDomain.FindAllString(s, -1) {
		if !plausibleDomain(m) {
			continue
		}
		add(KindDomain, m, ConfidenceMedium)
	}
	for _, m := range reSHA256.FindAllString(s, -1) {
		add(KindSHA256, m, ConfidenceHigh)
	}
	for _, m := range reMD5.FindAllString(s, -1) {
		add(KindMD5, m, ConfidenceHigh)
	}
	for _, m := range reAKIA.FindAllString(s, -1) {
		add(KindAWSKey, m, ConfidenceDeterministic)
	}
	for _, m := range reHex.FindAllString(s, -1) {
		// Already-extracted SHA-256 / MD5 will get re-flagged as
		// hex; that's fine — Store dedupes.
		if len(m) >= 32 {
			add(KindHexPayload, m, ConfidenceLow)
		}
	}
	for _, m := range reBase64.FindAllString(s, -1) {
		if len(m) >= 24 && looksLikeRealBase64(m) {
			add(KindBase64, m, ConfidenceLow)
		}
	}
	return out
}

// --- canned regexes ---
var (
	reURL    = regexp.MustCompile(`https?://[^\s'"<>{}|\\^` + "`" + `]+`)
	reIPv4   = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
	reIPv6   = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`)
	reEmail  = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)
	reDomain = regexp.MustCompile(`\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b`)
	reSHA256 = regexp.MustCompile(`\b[A-Fa-f0-9]{64}\b`)
	reMD5    = regexp.MustCompile(`\b[A-Fa-f0-9]{32}\b`)
	reAKIA   = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	reHex    = regexp.MustCompile(`\b[A-Fa-f0-9]{32,}\b`)
	reBase64 = regexp.MustCompile(`\b[A-Za-z0-9+/]{24,}={0,2}\b`)
)

func hostFromURL(u string) string {
	// Cheap parser — avoids importing net/url for one field.
	if i := strings.Index(u, "//"); i >= 0 {
		u = u[i+2:]
	}
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	if i := strings.Index(u, "@"); i >= 0 {
		u = u[i+1:]
	}
	// Strip port.
	if strings.HasPrefix(u, "[") {
		if j := strings.Index(u, "]"); j > 0 {
			return u[1:j]
		}
	}
	if i := strings.LastIndex(u, ":"); i >= 0 && !strings.Contains(u[i+1:], ":") {
		return u[:i]
	}
	return u
}

func isIPv6(s string) bool { return strings.Contains(s, ":") && net.ParseIP(s) != nil }

func shouldKeepIP(ip string) bool {
	switch ip {
	case "", "0.0.0.0", "127.0.0.1", "255.255.255.255", "::1", "::", "1.1.1.1":
		return false
	}
	// 169.254.x.x (link-local), 10.0.0.1, 192.168.0.1 are noisy on
	// dev/CI hosts. Keep them — operators can filter by tag.
	return true
}

// plausibleDomain filters out fragments that match reDomain but
// aren't real (e.g. "/x.so/y", "libfoo.so.6", "main.css"). The
// regex is generous; this is the second-stage sanity check.
func plausibleDomain(d string) bool {
	if net.ParseIP(d) != nil {
		return false
	}
	low := strings.ToLower(d)
	// Common library / asset / script suffixes attackers reference
	// in commands ("payload.sh", "exploit.py") but that are NOT
	// domain names.
	for _, bad := range []string{
		".so", ".o", ".a", ".js", ".css", ".html", ".htm", ".png",
		".jpg", ".jpeg", ".gif", ".ico", ".svg", ".pdf", ".zip",
		".tar", ".gz", ".xz", ".bz2", ".rpm", ".deb",
		".conf", ".txt", ".log", ".bak", ".tmp", ".lock",
		".sh", ".py", ".pl", ".rb", ".php", ".lua", ".ps1", ".bat",
		".exe", ".dll", ".bin", ".elf",
	} {
		if strings.HasSuffix(low, bad) {
			return false
		}
	}
	// Single-label domains (no dots in the SLD position) are
	// usually just filenames captured by the regex.
	labels := strings.Split(low, ".")
	if len(labels) < 2 {
		return false
	}
	// TLD heuristic — keep [a-z]+ that's 2-24 chars. Things like
	// "tar.gz" → tld="gz" is allowed but already filtered above.
	tld := labels[len(labels)-1]
	if len(tld) < 2 || len(tld) > 24 {
		return false
	}
	for _, r := range tld {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}

// looksLikeRealBase64 filters out repeated-character runs (e.g.
// "AAAAAAAAAAAAAA") and obvious all-hex strings (those got KindHex
// already).
func looksLikeRealBase64(s string) bool {
	if len(s) < 24 {
		return false
	}
	uniq := map[byte]struct{}{}
	for i := 0; i < len(s); i++ {
		uniq[s[i]] = struct{}{}
		if len(uniq) >= 8 {
			return true
		}
	}
	return false
}

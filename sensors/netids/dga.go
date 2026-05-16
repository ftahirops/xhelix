// Package netids implements xhelix's network-inspection plane.
//
// Phase 4 ships:
//
//   - DGAScore — entropy + n-gram heuristic on DNS qnames
//   - NXDOMAIN burst detector
//   - JA3/JA4 reputation gate
//   - C2 beacon detector (autocorrelation on connection intervals)
//   - Suricata subprocess supervisor
//
// AF_PACKET capture and the XDP drop hook live in Linux-only files.
package netids

import (
	"math"
	"strings"
	"unicode"
)

// DGAScore returns a domain-generation-algorithm score in [0,1].
// 0 = looks like a real word; 1 = looks random.
//
// The score combines:
//   - normalised Shannon entropy
//   - vowel/consonant ratio deviation
//   - digit density
//   - length pressure (long random strings are the DGA hallmark)
//
// We score the most suspicious label, not just the registered SLD,
// since DGA-style C2 often uses the leftmost subdomain.
//
// Values >= 0.7 emit Notice; >= 0.85 Warn; >= 0.95 High.
func DGAScore(qname string) float64 {
	if onCommonAllowlist(qname) {
		return 0
	}
	labels := candidateLabels(qname)
	var best float64
	for _, lab := range labels {
		if len(lab) < 4 {
			continue
		}
		s := scoreLabel(lab)
		if s > best {
			best = s
		}
	}
	return best
}

func scoreLabel(lab string) float64 {
	entScore := normalisedEntropy(lab)
	vcScore := vowelConsonantDeviation(lab)
	digScore := digitDensity(lab)
	lenScore := lengthPressure(lab)

	score := 0.40*entScore + 0.20*vcScore + 0.15*digScore + 0.25*lenScore
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	return score
}

// candidateLabels returns labels worth scoring: everything except the
// public-suffix-style trailing labels (".com", ".co.uk").
func candidateLabels(name string) []string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return parts
	}
	// Drop the rightmost 1 (single-label TLD: com, net, org, io)
	// or 2 (compound: co.uk, com.au) labels.
	drop := 1
	last := parts[len(parts)-1]
	if len(last) == 2 && len(parts) >= 3 {
		// crude two-label public-suffix heuristic
		secondLast := parts[len(parts)-2]
		if len(secondLast) <= 3 {
			drop = 2
		}
	}
	if drop >= len(parts) {
		return parts
	}
	return parts[:len(parts)-drop]
}

func lengthPressure(s string) float64 {
	// 0 below 8 chars; 1 at 16+ chars.
	if len(s) < 8 {
		return 0
	}
	if len(s) >= 16 {
		return 1
	}
	return float64(len(s)-8) / 8.0
}

func normalisedEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := make(map[rune]int, 32)
	for _, r := range s {
		counts[r]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	// log2(36) ≈ 5.17 — a-z + 0-9
	return clamp(h / 5.17)
}

func vowelConsonantDeviation(s string) float64 {
	vowels := "aeiouy"
	var v, c int
	for _, r := range s {
		if !unicode.IsLetter(r) {
			continue
		}
		if strings.ContainsRune(vowels, r) {
			v++
		} else {
			c++
		}
	}
	tot := v + c
	if tot == 0 {
		return 0
	}
	ratio := float64(v) / float64(tot)
	// Healthy English: ~0.35-0.45 vowels.
	dev := math.Abs(ratio - 0.4) / 0.4
	return clamp(dev)
}

func digitDensity(s string) float64 {
	if s == "" {
		return 0
	}
	d := 0
	for _, r := range s {
		if unicode.IsDigit(r) {
			d++
		}
	}
	// > 30% digits is suspicious.
	density := float64(d) / float64(len(s))
	if density > 0.3 {
		return 1
	}
	return density / 0.3
}

func clamp(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

// onCommonAllowlist suppresses obvious legitimate hostnames so they
// never count against an operator's noise budget.
func onCommonAllowlist(qname string) bool {
	q := strings.ToLower(qname)
	for _, suffix := range []string{
		".internal", ".local", ".lan", ".cluster.local",
		".amazonaws.com", ".google.com", ".googleapis.com",
		".github.com", ".githubusercontent.com",
		".cloudflare.com", ".cdn.cloudflare.net",
	} {
		if strings.HasSuffix(q, suffix) {
			return true
		}
	}
	return false
}

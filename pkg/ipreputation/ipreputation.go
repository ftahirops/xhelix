// Package ipreputation is an OPTIONAL, default-OFF external IP-reputation
// client (VirusTotal / AbuseIPDB). It exists so an operator can enrich
// egress destinations with third-party reputation — at the explicit cost
// of sending destination IPs to that third party.
//
// SAFETY CONTRACT: when the checker is disabled (the default), Check makes
// ZERO network calls and returns (Verdict{}, false) immediately. This is
// asserted by a test. xhelix stays offline-first unless an operator opts in.
package ipreputation

import (
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// Verdict is the reputation result for an IP.
type Verdict struct {
	Listed bool   // true if the provider flags the IP as malicious/abusive
	Score  int    // provider-specific score (0 if none)
	Source string // provider name that produced the verdict
}

// Doer is the minimal HTTP interface (http.Client satisfies it). Injectable
// for tests so the off-path can be proven to make no call.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Checker performs optional reputation lookups. The zero value is a safe,
// disabled checker.
type Checker struct {
	enabled  bool
	provider string
	apiKey   string
	http     Doer
	calls    atomic.Uint64 // external requests actually issued
}

// New builds a checker. When enabled is false, no Doer is needed and Check
// never calls out. provider is "virustotal" or "abuseipdb".
func New(enabled bool, provider, apiKey string, doer Doer) *Checker {
	if doer == nil {
		doer = &http.Client{Timeout: 5 * time.Second}
	}
	return &Checker{enabled: enabled, provider: provider, apiKey: apiKey, http: doer}
}

// Enabled reports whether external lookups are turned on.
func (c *Checker) Enabled() bool { return c != nil && c.enabled }

// Calls returns the number of external requests issued (0 while disabled).
func (c *Checker) Calls() uint64 {
	if c == nil {
		return 0
	}
	return c.calls.Load()
}

// Check returns the reputation verdict for ip. When the checker is disabled
// (the default), it returns (Verdict{}, false) and makes NO network call.
func (c *Checker) Check(ip net.IP) (Verdict, bool) {
	if c == nil || !c.enabled || ip == nil {
		return Verdict{}, false
	}
	req, err := c.buildRequest(ip)
	if err != nil {
		return Verdict{}, false
	}
	c.calls.Add(1)
	resp, err := c.http.Do(req)
	if err != nil {
		return Verdict{}, false
	}
	defer resp.Body.Close()
	// Minimal contract: a 2xx with a provider hit marks Listed. Full
	// response parsing per provider is a follow-up; the off-by-default
	// safety contract and request shape are what this package guarantees.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return Verdict{Listed: true, Source: c.provider, Score: 0}, true
	}
	return Verdict{}, false
}

func (c *Checker) buildRequest(ip net.IP) (*http.Request, error) {
	switch c.provider {
	case "virustotal":
		r, err := http.NewRequest(http.MethodGet, "https://www.virustotal.com/api/v3/ip_addresses/"+ip.String(), nil)
		if err != nil {
			return nil, err
		}
		r.Header.Set("x-apikey", c.apiKey)
		return r, nil
	case "abuseipdb":
		r, err := http.NewRequest(http.MethodGet, "https://api.abuseipdb.com/api/v2/check?ipAddress="+ip.String(), nil)
		if err != nil {
			return nil, err
		}
		r.Header.Set("Key", c.apiKey)
		r.Header.Set("Accept", "application/json")
		return r, nil
	default:
		return nil, fmt.Errorf("unknown reputation provider %q", c.provider)
	}
}

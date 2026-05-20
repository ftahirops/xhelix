package forensicingest

import (
	"encoding/json"

	"github.com/xhelix/xhelix/pkg/forensic"
)

// extractObservations re-derives the (kind, value, source) tuples
// for the CoEngine from a JSON-lines envelope. forensic.ProcessLine
// already pushed full Observations into the Store; this is the
// thin variant the CoEngine needs.
//
// We re-implement here rather than threading it through ProcessLine
// to keep the forensic package's API surface stable and small.
func extractObservations(line []byte) []forensic.Observation {
	var env forensic.Envelope
	if err := json.Unmarshal(line, &env); err != nil {
		return nil
	}
	switch env.Type {
	case "command":
		return obsFromHoneyShCommand(env.Body)
	case "beacon_start":
		return obsFromSinkholeStart(env.Body)
	case "beacon_data":
		return obsFromSinkholeData(env.Body)
	case "dns_poison":
		return obsFromDNSPoison(env.Body)
	}
	return nil
}

type miniCmd struct {
	SessionID string   `json:"session_id"`
	Command   string   `json:"command"`
	URLs      []string `json:"urls"`
	IPs       []string `json:"ips"`
	Domains   []string `json:"domains"`
}

func obsFromHoneyShCommand(body json.RawMessage) []forensic.Observation {
	var m miniCmd
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	var out []forensic.Observation
	add := func(k forensic.Kind, v string) {
		if v != "" {
			out = append(out, forensic.Observation{
				Kind: k, Value: v, Source: m.SessionID,
				Confidence: forensic.ConfidenceHigh, Origin: forensic.OriginHoneySh,
			})
		}
	}
	if m.Command != "" {
		add(forensic.KindCommand, m.Command)
	}
	for _, u := range m.URLs {
		add(forensic.KindURL, u)
	}
	for _, ip := range m.IPs {
		add(forensic.KindIPv4, ip)
	}
	for _, d := range m.Domains {
		add(forensic.KindDomain, d)
	}
	return out
}

type miniSinkStart struct {
	BeaconID string `json:"beacon_id"`
	PeerAddr string `json:"peer_addr"`
	SNI      string `json:"sni"`
	JA3Hash  string `json:"ja3_hash"`
}

func obsFromSinkholeStart(body json.RawMessage) []forensic.Observation {
	var m miniSinkStart
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	var out []forensic.Observation
	add := func(k forensic.Kind, v string) {
		if v != "" {
			out = append(out, forensic.Observation{
				Kind: k, Value: v, Source: m.BeaconID,
				Confidence: forensic.ConfidenceDeterministic, Origin: forensic.OriginSinkhole,
			})
		}
	}
	if m.SNI != "" {
		add(forensic.KindDomain, m.SNI)
	}
	if m.JA3Hash != "" {
		add(forensic.KindJA3, m.JA3Hash)
	}
	// Peer IP: take everything before the last ":".
	if m.PeerAddr != "" {
		add(forensic.KindIPv4, stripPort(m.PeerAddr))
	}
	return out
}

type miniSinkData struct {
	BeaconID  string `json:"beacon_id"`
	HTTPHost  string `json:"http_host"`
	UserAgent string `json:"user_agent"`
	Sha256    string `json:"sha256"`
}

func obsFromSinkholeData(body json.RawMessage) []forensic.Observation {
	var m miniSinkData
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	var out []forensic.Observation
	add := func(k forensic.Kind, v string) {
		if v != "" {
			out = append(out, forensic.Observation{
				Kind: k, Value: v, Source: m.BeaconID,
				Confidence: forensic.ConfidenceDeterministic, Origin: forensic.OriginSinkhole,
			})
		}
	}
	if m.HTTPHost != "" {
		add(forensic.KindBeaconHost, stripPort(m.HTTPHost))
	}
	if m.UserAgent != "" {
		add(forensic.KindUserAgent, m.UserAgent)
	}
	if m.Sha256 != "" {
		add(forensic.KindSHA256, m.Sha256)
	}
	return out
}

type miniDNS struct {
	Peer string `json:"peer"`
	Name string `json:"name"`
}

func obsFromDNSPoison(body json.RawMessage) []forensic.Observation {
	var m miniDNS
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	if m.Name == "" {
		return nil
	}
	return []forensic.Observation{{
		Kind: forensic.KindDomain, Value: m.Name, Source: m.Peer,
		Confidence: forensic.ConfidenceDeterministic, Origin: forensic.OriginDNSPoison,
	}}
}

// stripPort returns "host" from "host:port" (or the input if no port).
func stripPort(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return s[:i]
		}
		if s[i] < '0' || s[i] > '9' {
			break
		}
	}
	return s
}

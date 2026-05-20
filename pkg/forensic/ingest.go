package forensic

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
	"time"
)

// Each deception package writes JSON-lines with a `{"type":"...","body":{...}}`
// envelope. The ingest path reads one line at a time, parses the
// envelope, dispatches to the type-specific extractor, and pushes
// resulting Observations into the Store.
//
// We intentionally don't import the deception packages here —
// instead we accept the wire JSON shapes directly. Keeps the
// dependency direction clean: forensic depends on no deception
// package, and any deception package can write to a forensic-
// compatible JSON-lines log.

// Origin labels match the producing package's package name.
const (
	OriginHoneySh   = "honeysh"
	OriginSinkhole  = "sinkhole"
	OriginDNSPoison = "dnspoison"
	OriginDecoyFS   = "decoyfs"
	OriginCrashLoop = "crashloop"
)

// Envelope is the shared wire shape.
type Envelope struct {
	Type string          `json:"type"`
	Body json.RawMessage `json:"body"`
}

// ProcessLine parses a single JSON-lines envelope and emits the
// resulting Observations to the store. Returns the count of new
// IOCs created (for stats). Unknown envelope types are silently
// ignored — forward-compat for new deception layers.
func ProcessLine(s *Store, line []byte) (int, error) {
	if len(line) == 0 {
		return 0, nil
	}
	var env Envelope
	if err := json.Unmarshal(line, &env); err != nil {
		return 0, err
	}
	obs := extractByType(env)
	added := 0
	for _, o := range obs {
		if ioc := s.Add(o); ioc != nil && ioc.Count == 1 {
			added++
		}
	}
	return added, nil
}

// ProcessReader reads JSON lines until EOF. Per-line errors are
// returned via the optional callback (nil = ignore). Returns total
// new-IOC count.
func ProcessReader(s *Store, r io.Reader, onError func(line []byte, err error)) int {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	added := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		n, err := ProcessLine(s, line)
		if err != nil && onError != nil {
			lineCopy := make([]byte, len(line))
			copy(lineCopy, line)
			onError(lineCopy, err)
			continue
		}
		added += n
	}
	return added
}

// extractByType routes the envelope by Type to the right extractor.
func extractByType(env Envelope) []Observation {
	switch env.Type {
	// honey-sh
	case "session_start":
		return extractHoneyShStart(env.Body)
	case "command":
		return extractHoneyShCommand(env.Body)
	case "session_end":
		return nil // no IOCs — just session bookkeeping

	// sinkhole
	case "beacon_start":
		return extractSinkholeStart(env.Body)
	case "beacon_data":
		return extractSinkholeData(env.Body)
	case "beacon_response":
		return nil
	case "beacon_end":
		return nil

	// dnspoison
	case "dns_poison":
		return extractDNSPoison(env.Body)
	case "dns_passthrough":
		return nil // unflagged queries don't auto-IOC
	}
	return nil
}

// --- honey-sh extractors ---

type honeyShStart struct {
	SessionID   string    `json:"session_id"`
	StartedAt   time.Time `json:"started_at"`
	RemoteIP    string    `json:"remote_ip"`
	ServiceName string    `json:"service_name"`
}

func extractHoneyShStart(body json.RawMessage) []Observation {
	var m honeyShStart
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	if m.RemoteIP == "" {
		return nil
	}
	return []Observation{{
		Kind: KindIPv4, Value: m.RemoteIP, At: m.StartedAt,
		Confidence: ConfidenceDeterministic,
		Origin:     OriginHoneySh, Source: m.SessionID,
	}}
}

type honeyShCommand struct {
	SessionID string    `json:"session_id"`
	At        time.Time `json:"at"`
	Raw       string    `json:"raw"`
	Command   string    `json:"command"`
	URLs      []string  `json:"urls,omitempty"`
	IPs       []string  `json:"ips,omitempty"`
	Domains   []string  `json:"domains,omitempty"`
}

func extractHoneyShCommand(body json.RawMessage) []Observation {
	var m honeyShCommand
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	out := make([]Observation, 0, 8)
	add := func(k Kind, v string, conf Confidence) {
		out = append(out, Observation{
			Kind: k, Value: v, At: m.At,
			Confidence: conf, Origin: OriginHoneySh, Source: m.SessionID,
		})
	}
	if m.Command != "" {
		add(KindCommand, m.Command, ConfidenceHigh)
	}
	if m.Raw != "" {
		// Full command line — a strong indicator for fleet pivots.
		add(KindCommandLine, truncate(m.Raw, 1024), ConfidenceHigh)
		// And run text extraction over it (catches URLs honeysh
		// missed — e.g. inside quoted blobs).
		out = append(out, ExtractFromText(m.Raw, OriginHoneySh, m.SessionID, m.At)...)
	}
	for _, u := range m.URLs {
		add(KindURL, u, ConfidenceDeterministic)
	}
	for _, ip := range m.IPs {
		if shouldKeepIP(ip) {
			add(KindIPv4, ip, ConfidenceDeterministic)
		}
	}
	for _, d := range m.Domains {
		add(KindDomain, d, ConfidenceDeterministic)
	}
	return out
}

// --- sinkhole extractors ---

type sinkholeStart struct {
	BeaconID  string    `json:"beacon_id"`
	StartedAt time.Time `json:"started_at"`
	PeerAddr  string    `json:"peer_addr"`
	SNI       string    `json:"sni"`
	ALPN      string    `json:"alpn"`
	JA3       string    `json:"ja3"`
	JA3Hash   string    `json:"ja3_hash"`
}

func extractSinkholeStart(body json.RawMessage) []Observation {
	var m sinkholeStart
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	out := make([]Observation, 0, 4)
	if ip := hostFromPeer(m.PeerAddr); ip != "" && shouldKeepIP(ip) {
		out = append(out, Observation{
			Kind: KindIPv4, Value: ip, At: m.StartedAt,
			Confidence: ConfidenceDeterministic,
			Origin:     OriginSinkhole, Source: m.BeaconID,
		})
	}
	if m.SNI != "" {
		out = append(out, Observation{
			Kind: KindDomain, Value: m.SNI, At: m.StartedAt,
			Confidence: ConfidenceDeterministic,
			Origin:     OriginSinkhole, Source: m.BeaconID,
		})
	}
	if m.JA3Hash != "" {
		out = append(out, Observation{
			Kind: KindJA3, Value: m.JA3Hash, At: m.StartedAt,
			Confidence: ConfidenceDeterministic,
			Origin:     OriginSinkhole, Source: m.BeaconID,
		})
	}
	return out
}

type sinkholeData struct {
	BeaconID   string    `json:"beacon_id"`
	At         time.Time `json:"at"`
	Payload    string    `json:"payload"`
	IsText     bool      `json:"is_text"`
	Sha256     string    `json:"sha256"`
	HTTPHost   string    `json:"http_host"`
	HTTPPath   string    `json:"http_path"`
	UserAgent  string    `json:"user_agent"`
}

func extractSinkholeData(body json.RawMessage) []Observation {
	var m sinkholeData
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	out := make([]Observation, 0, 8)
	add := func(k Kind, v string, conf Confidence) {
		if v == "" {
			return
		}
		out = append(out, Observation{
			Kind: k, Value: v, At: m.At,
			Confidence: conf, Origin: OriginSinkhole, Source: m.BeaconID,
		})
	}
	if m.HTTPHost != "" {
		// HTTP Host: header — a beacon target. Strong indicator.
		if host := stripPort(m.HTTPHost); host != "" {
			add(KindBeaconHost, host, ConfidenceDeterministic)
			if isPlausibleHost(host) {
				add(KindDomain, host, ConfidenceDeterministic)
			}
		}
	}
	if m.UserAgent != "" {
		add(KindUserAgent, m.UserAgent, ConfidenceDeterministic)
	}
	if m.Sha256 != "" {
		add(KindSHA256, m.Sha256, ConfidenceDeterministic)
	}
	if m.IsText && m.Payload != "" {
		out = append(out, ExtractFromText(m.Payload, OriginSinkhole, m.BeaconID, m.At)...)
	}
	return out
}

// --- dnspoison extractor ---

type dnsPoisonEvent struct {
	At    time.Time `json:"at"`
	Peer  string    `json:"peer"`
	Name  string    `json:"name"`
	QType uint16    `json:"qtype"`
	Match string    `json:"match"`
}

func extractDNSPoison(body json.RawMessage) []Observation {
	var m dnsPoisonEvent
	if err := json.Unmarshal(body, &m); err != nil {
		return nil
	}
	if m.Name == "" {
		return nil
	}
	conf := ConfidenceDeterministic
	if m.Match == "dga_heuristic" {
		conf = ConfidenceMedium // heuristic — could be a real DGA-shaped legitimate name
	}
	return []Observation{{
		Kind: KindDomain, Value: m.Name, At: m.At,
		Confidence: conf, Origin: OriginDNSPoison, Source: m.Peer,
	}}
}

// --- helpers ---

func hostFromPeer(p string) string {
	// "127.0.0.1:45500" → "127.0.0.1"; "[::1]:443" → "::1".
	if strings.HasPrefix(p, "[") {
		if i := strings.Index(p, "]"); i > 0 {
			return p[1:i]
		}
	}
	if i := strings.LastIndex(p, ":"); i > 0 {
		return p[:i]
	}
	return p
}

func stripPort(host string) string {
	if strings.HasPrefix(host, "[") {
		if i := strings.Index(host, "]"); i > 0 {
			return host[1:i]
		}
	}
	if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i+1:], ":") {
		return host[:i]
	}
	return host
}

func isPlausibleHost(h string) bool {
	// Reject IPs and bare hostnames here — those land in their own kinds.
	if i := strings.IndexByte(h, ':'); i >= 0 {
		return false
	}
	if !strings.Contains(h, ".") {
		return false
	}
	return plausibleDomain(h)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}

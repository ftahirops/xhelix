package forensicingest

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/forensic"
)

func writeLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			t.Fatal(err)
		}
	}
	_ = f.Sync()
}

func TestIngestor_ConsumesNewFiles(t *testing.T) {
	dir := t.TempDir()
	store := forensic.NewStore()
	ing := New(Config{
		Dir:          dir,
		ScanInterval: 30 * time.Millisecond,
		PollInterval: 30 * time.Millisecond,
	}, store, nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	go ing.Run(ctx)

	writeLines(t, filepath.Join(dir, "honeysh.jsonl"),
		`{"type":"command","body":{"session_id":"s1","at":"2026-05-20T10:00:00Z","raw":"id","command":"id"}}`,
		`{"type":"command","body":{"session_id":"s1","at":"2026-05-20T10:00:01Z","raw":"curl http://attacker.io","command":"curl","urls":["http://attacker.io"],"domains":["attacker.io"]}}`,
	)

	// Wait up to 1s for the lines to be ingested.
	waitFor(t, 1*time.Second, func() bool {
		return store.Len() > 0
	}, "ingest")

	if store.Get(forensic.KindURL, "http://attacker.io") == nil {
		t.Fatal("URL not in store after ingest")
	}
	if store.Get(forensic.KindCommand, "id") == nil {
		t.Fatal("Command 'id' not in store after ingest")
	}
}

func TestIngestor_PicksUpFilesAddedLater(t *testing.T) {
	dir := t.TempDir()
	store := forensic.NewStore()
	ing := New(Config{
		Dir:          dir,
		ScanInterval: 30 * time.Millisecond,
		PollInterval: 30 * time.Millisecond,
	}, store, nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	go ing.Run(ctx)

	// Sleep past one scan tick, then drop a new file.
	time.Sleep(60 * time.Millisecond)
	writeLines(t, filepath.Join(dir, "dnspoison.jsonl"),
		`{"type":"dns_poison","body":{"at":"2026-05-20T10:00:00Z","peer":"127.0.0.1:1","name":"evil.example.com","qtype":1,"match":"known_bad"}}`,
	)

	waitFor(t, 1*time.Second, func() bool {
		return store.Get(forensic.KindDomain, "evil.example.com") != nil
	}, "late-arriving file")
}

func TestIngestor_AppendedLinesPickedUp(t *testing.T) {
	dir := t.TempDir()
	store := forensic.NewStore()
	path := filepath.Join(dir, "sinkhole.jsonl")

	writeLines(t, path,
		`{"type":"beacon_start","body":{"beacon_id":"b1","peer_addr":"203.0.113.7:5","sni":"first.attacker.com","ja3_hash":"deadbeef"}}`,
	)
	ing := New(Config{Dir: dir, ScanInterval: 30 * time.Millisecond, PollInterval: 30 * time.Millisecond},
		store, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	go ing.Run(ctx)

	waitFor(t, 500*time.Millisecond, func() bool {
		return store.Get(forensic.KindDomain, "first.attacker.com") != nil
	}, "initial line")

	// Append a fresh line — follower goroutine should pick it up.
	writeLines(t, path,
		`{"type":"beacon_start","body":{"beacon_id":"b2","peer_addr":"203.0.113.8:5","sni":"second.attacker.com","ja3_hash":"cafef00d"}}`,
	)
	waitFor(t, 1*time.Second, func() bool {
		return store.Get(forensic.KindDomain, "second.attacker.com") != nil
	}, "appended line")
}

func TestIngestor_FiresCoOccurrence(t *testing.T) {
	dir := t.TempDir()
	store := forensic.NewStore()
	co := forensic.NewCoEngine(forensic.DefaultCoRules())

	var (
		mu   sync.Mutex
		hits []forensic.Hit
	)
	ing := New(Config{Dir: dir, ScanInterval: 30 * time.Millisecond, PollInterval: 30 * time.Millisecond},
		store, co, func(h forensic.Hit) {
			mu.Lock()
			defer mu.Unlock()
			hits = append(hits, h)
		})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	go ing.Run(ctx)

	// Two observations from the same session_id within window:
	// URL + Command — should fire cooccur.download_and_execute.
	writeLines(t, filepath.Join(dir, "honeysh.jsonl"),
		`{"type":"command","body":{"session_id":"sess1","at":"2026-05-20T10:00:00Z","raw":"a","command":"curl","urls":["http://attacker.io/x"]}}`,
		`{"type":"command","body":{"session_id":"sess1","at":"2026-05-20T10:00:01Z","raw":"b","command":"sh"}}`,
	)

	waitFor(t, 1*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, h := range hits {
			if h.RuleID == "cooccur.download_and_execute" {
				return true
			}
		}
		return false
	}, "co-occurrence fire")
}

func TestIngestor_IgnoresNonJsonl(t *testing.T) {
	dir := t.TempDir()
	store := forensic.NewStore()
	ing := New(Config{Dir: dir, ScanInterval: 30 * time.Millisecond, PollInterval: 30 * time.Millisecond},
		store, nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	go ing.Run(ctx)

	writeLines(t, filepath.Join(dir, "noise.txt"),
		`{"type":"command","body":{"session_id":"x","at":"2026-05-20T10:00:00Z","raw":"y","command":"id"}}`,
	)
	time.Sleep(200 * time.Millisecond)

	if store.Len() != 0 {
		t.Fatalf("non-.jsonl file should be ignored; store has %d", store.Len())
	}
}

func TestIngestor_MalformedLineRecordedAsParseError(t *testing.T) {
	dir := t.TempDir()
	store := forensic.NewStore()
	var (
		mu      sync.Mutex
		gotErrs int
	)
	ing := New(Config{
		Dir: dir, ScanInterval: 30 * time.Millisecond, PollInterval: 30 * time.Millisecond,
		OnError: func(string, error) {
			mu.Lock()
			gotErrs++
			mu.Unlock()
		},
	}, store, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	go ing.Run(ctx)

	writeLines(t, filepath.Join(dir, "broken.jsonl"),
		`not json at all`,
		`{"type":"command","body":{"session_id":"x","at":"2026-05-20T10:00:00Z","raw":"y","command":"id"}}`,
	)

	waitFor(t, 500*time.Millisecond, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return gotErrs >= 1 && store.Len() > 0
	}, "parse error + good line both observed")

	st := ing.Stats()
	if st.ParseErrors == 0 {
		t.Fatal("ParseErrors should be > 0")
	}
	if st.LinesRead == 0 {
		t.Fatal("good line should still be counted")
	}
}

func TestStats_FilesActive(t *testing.T) {
	dir := t.TempDir()
	store := forensic.NewStore()
	ing := New(Config{Dir: dir, ScanInterval: 30 * time.Millisecond, PollInterval: 30 * time.Millisecond},
		store, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	go ing.Run(ctx)

	writeLines(t, filepath.Join(dir, "one.jsonl"), `{"type":"command","body":{"session_id":"x","at":"2026-05-20T10:00:00Z","raw":"y","command":"id"}}`)
	writeLines(t, filepath.Join(dir, "two.jsonl"), `{"type":"command","body":{"session_id":"x","at":"2026-05-20T10:00:00Z","raw":"y","command":"id"}}`)

	waitFor(t, 500*time.Millisecond, func() bool { return ing.Stats().FilesActive == 2 },
		"both files actively tailed")
}

// --- helpers ---

func waitFor(t *testing.T, max time.Duration, cond func() bool, label string) {
	t.Helper()
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s: never satisfied within %s", label, max)
}

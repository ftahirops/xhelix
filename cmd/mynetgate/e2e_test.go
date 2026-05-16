package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/localapi"
)

// TestE2EHistoryFlow stands up a real localapi.Server on a temp Unix
// socket, points a mynetgate server at it, and verifies the HTTP
// /api/v1/history path forwards correctly and the cache is populated.
func TestE2EHistoryFlow(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "xhelix.sock")

	api := localapi.NewServer(sock, localapi.OptionAllowUIDs(uint32(os.Getuid())))
	api.RegisterHandler("history.list", func(ctx context.Context, _ json.RawMessage) (any, error) {
		return map[string]any{
			"activities": []map[string]any{
				{"id": 1, "exe": "/usr/bin/curl", "primary_host": "example.com", "verdict": "amber"},
			},
		}, nil
	})
	api.RegisterHandler("alerts.list", func(ctx context.Context, _ json.RawMessage) (any, error) {
		return map[string]any{"alerts": []any{}}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := api.Start(ctx); err != nil {
		t.Fatal(err)
	}
	// Brief wait for the socket file to appear.
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	cache, err := OpenCache(":memory:", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	srv := &server{
		socketPath: sock,
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		cache:      cache,
	}

	r := httptest.NewRequest("GET", "/api/v1/history?since=1h", nil)
	w := httptest.NewRecorder()
	srv.history(w, r)
	if w.Code != 200 {
		t.Fatalf("history: code=%d body=%s", w.Code, w.Body.String())
	}
	var parsed map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid json: %v body=%s", err, w.Body.String())
	}
	acts, _ := parsed["activities"].([]any)
	if len(acts) != 1 {
		t.Fatalf("want 1 activity, got %d (body=%s)", len(acts), w.Body.String())
	}

	// Cache must now hold the response.
	if cached := cache.LoadActivities(); cached == nil {
		t.Fatal("cache not populated after fresh fetch")
	}
}

func TestE2EPingReportsSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "xhelix.sock")
	api := localapi.NewServer(sock, localapi.OptionAllowUIDs(uint32(os.Getuid())))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := api.Start(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	srv := &server{
		socketPath: sock,
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	r := httptest.NewRequest("GET", "/api/v1/ping", nil)
	w := httptest.NewRecorder()
	srv.ping(w, r)
	if w.Code != 200 {
		t.Fatalf("ping failed: %d %s", w.Code, w.Body.String())
	}
	if !contains(w.Body.String(), sock) {
		t.Errorf("ping body should mention socket; got %s", w.Body.String())
	}
}

func TestE2EHistoryServesCacheWhenSocketDown(t *testing.T) {
	cache, err := OpenCache(":memory:", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	stale := []byte(`{"activities":[{"id":99,"exe":"/cached/bin"}]}`)
	if err := cache.StoreActivities(stale); err != nil {
		t.Fatal(err)
	}
	srv := &server{
		socketPath: "/nonexistent.sock",
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		cache:      cache,
	}
	r := httptest.NewRequest("GET", "/api/v1/history", nil)
	w := httptest.NewRecorder()
	srv.history(w, r)
	if w.Code != 200 {
		t.Fatalf("expected stale fallback to return 200; got %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Xhelix-Stale") != "true" {
		t.Errorf("stale fallback should set X-Xhelix-Stale; headers=%v", w.Header())
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func _avoidUnused() *http.Server { return nil }

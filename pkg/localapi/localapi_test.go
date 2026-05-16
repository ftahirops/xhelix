package localapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func tempSocket(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "test.sock")
}

func TestUnaryHandlerRoundTrip(t *testing.T) {
	sock := tempSocket(t)
	srv := NewServer(sock, OptionAllowUIDs(uint32(os.Geteuid())))
	srv.RegisterHandler("echo", func(ctx context.Context, req json.RawMessage) (any, error) {
		var s string
		_ = json.Unmarshal(req, &s)
		return "you said: " + s, nil
	})
	if err := srv.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	c, err := Dial(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var out string
	if err := c.Call("echo", "hello", &out); err != nil {
		t.Fatal(err)
	}
	if out != "you said: hello" {
		t.Fatalf("got %q", out)
	}
}

func TestUnknownMethodErrors(t *testing.T) {
	sock := tempSocket(t)
	srv := NewServer(sock, OptionAllowUIDs(uint32(os.Geteuid())))
	if err := srv.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	c, _ := Dial(sock)
	defer c.Close()
	var out any
	err := c.Call("missing.method", nil, &out)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestStreamerHandlerEmitsAndEnds(t *testing.T) {
	sock := tempSocket(t)
	srv := NewServer(sock, OptionAllowUIDs(uint32(os.Geteuid())))
	srv.RegisterStreamer("count", func(ctx context.Context, req json.RawMessage, out chan<- any) error {
		var n int
		_ = json.Unmarshal(req, &n)
		for i := 0; i < n; i++ {
			out <- i
		}
		return nil
	})
	if err := srv.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	c, _ := Dial(sock)
	defer c.Close()
	got := []int{}
	err := c.Stream(context.Background(), "count", 5, func(raw json.RawMessage) error {
		var v int
		_ = json.Unmarshal(raw, &v)
		got = append(got, v)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 || got[0] != 0 || got[4] != 4 {
		t.Fatalf("got %v", got)
	}
}

func TestStreamerErrorPropagated(t *testing.T) {
	sock := tempSocket(t)
	srv := NewServer(sock, OptionAllowUIDs(uint32(os.Geteuid())))
	srv.RegisterStreamer("broken", func(ctx context.Context, req json.RawMessage, out chan<- any) error {
		return errFake
	})
	if err := srv.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	c, _ := Dial(sock)
	defer c.Close()
	err := c.Stream(context.Background(), "broken", nil, nil)
	if err == nil || err.Error() != "fake" {
		t.Fatalf("err = %v", err)
	}
}

func TestServerStopIdempotent(t *testing.T) {
	sock := tempSocket(t)
	srv := NewServer(sock, OptionAllowUIDs(uint32(os.Geteuid())))
	_ = srv.Start(context.Background())
	_ = srv.Stop()
	_ = srv.Stop()
}

func TestConcurrentCalls(t *testing.T) {
	sock := tempSocket(t)
	srv := NewServer(sock, OptionAllowUIDs(uint32(os.Geteuid())))
	srv.RegisterHandler("add", func(ctx context.Context, req json.RawMessage) (any, error) {
		var in struct{ A, B int }
		_ = json.Unmarshal(req, &in)
		return in.A + in.B, nil
	})
	if err := srv.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := Dial(sock)
			if err != nil {
				t.Errorf("dial %d: %v", i, err)
				return
			}
			defer c.Close()
			var out int
			for j := 0; j < 25; j++ {
				if err := c.Call("add", map[string]int{"A": j, "B": i}, &out); err != nil {
					t.Errorf("call: %v", err)
					return
				}
				if out != i+j {
					t.Errorf("got %d", out)
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestUnauthorizedUIDRejected(t *testing.T) {
	sock := tempSocket(t)
	// Allow only a UID that's not us. The peer-cred check should
	// refuse the local-uid client.
	srv := NewServer(sock, OptionAllowUIDs(uint32(os.Geteuid()+1)))
	if err := srv.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	c, err := Dial(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var out any
	err = c.Call("anything", nil, &out)
	if err == nil {
		t.Fatal("expected unauthorized rejection")
	}
}

func TestSocketChmodApplied(t *testing.T) {
	sock := tempSocket(t)
	srv := NewServer(sock)
	if err := srv.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	st, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o660 {
		t.Errorf("socket mode = %o, want 0660", st.Mode().Perm())
	}
}

func TestStreamContextCancel(t *testing.T) {
	sock := tempSocket(t)
	srv := NewServer(sock, OptionAllowUIDs(uint32(os.Geteuid())))
	srv.RegisterStreamer("forever", func(ctx context.Context, req json.RawMessage, out chan<- any) error {
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case out <- 1:
				time.Sleep(time.Millisecond)
			}
		}
	})
	if err := srv.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	c, _ := Dial(sock)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	count := 0
	_ = c.Stream(ctx, "forever", nil, func(json.RawMessage) error {
		count++
		return nil
	})
	if count == 0 {
		t.Fatal("should have received at least one frame before cancel")
	}
}

type sentinel string

func (s sentinel) Error() string { return string(s) }

var errFake = sentinel("fake")

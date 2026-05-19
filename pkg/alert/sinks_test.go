package alert

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

func makeAlert(rule string) model.Alert {
	return model.Alert{
		RuleID: rule,
		Reason: "test reason for " + rule,
		Mode:   model.ModeDetect,
		Event: model.Event{
			Time:     time.Now(),
			Severity: model.SeverityNotice,
			PID:      1234,
			Comm:     "tester",
			Sensor:   "test",
		},
	}
}

func TestFileSink_NoRotationWhenDisabled(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "alerts.jsonl")
	fs, err := NewFileSink(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	for i := 0; i < 100; i++ {
		if err := fs.Send(context.Background(), makeAlert("rule_x")); err != nil {
			t.Fatal(err)
		}
	}
	// No rotation requested → no .1 / .2 files.
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Errorf("unexpected rotated file with rotation disabled")
	}
}

func TestFileSink_RotatesAtSizeBound(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "alerts.jsonl")
	fs, err := NewFileSinkWithOptions(path, FileSinkOptions{
		MaxSizeBytes: 200, // tiny — easy to overflow
		Keep:         2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	// Each alert serialises to ~200+ bytes, so every Send triggers
	// rotation. Send several to exercise the .N shift.
	for i := 0; i < 6; i++ {
		if err := fs.Send(context.Background(), makeAlert("rule_x")); err != nil {
			t.Fatal(err)
		}
	}

	// Expected state: active file exists, .1 + .2 exist, .3 must NOT
	// (would exceed Keep=2).
	for _, suffix := range []string{"", ".1", ".2"} {
		if _, err := os.Stat(path + suffix); err != nil {
			t.Errorf("expected file %q to exist: %v", path+suffix, err)
		}
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Errorf("file %s should not exist (keep=2)", path+".3")
	}
}

func TestFileSink_ActiveFileNeverExceedsCap(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "alerts.jsonl")
	const cap = 512
	fs, err := NewFileSinkWithOptions(path, FileSinkOptions{
		MaxSizeBytes: cap,
		Keep:         3,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	for i := 0; i < 200; i++ {
		if err := fs.Send(context.Background(), makeAlert("rule_x")); err != nil {
			t.Fatal(err)
		}
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Active file may briefly exceed cap by ONE alert (the alert that
	// triggered rotation is then written to the freshly opened file),
	// so allow some slack — but it must be in the same order of magnitude.
	if st.Size() > cap*2 {
		t.Errorf("active file size %d > 2x cap %d (rotation broken)",
			st.Size(), cap)
	}
}

func TestFileSink_PreservesContentJSONOneLinePerEntry(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "alerts.jsonl")
	fs, err := NewFileSink(path)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		if err := fs.Send(context.Background(), makeAlert("rule_y")); err != nil {
			t.Fatal(err)
		}
	}
	fs.Close()

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	lines := 0
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "{") || !strings.HasSuffix(line, "}") {
			t.Errorf("line %d not JSON-shaped: %q", lines, line)
		}
		if !strings.Contains(line, "rule_y") {
			t.Errorf("line %d missing rule id: %q", lines, line)
		}
		lines++
	}
	if lines != 3 {
		t.Errorf("got %d lines, want 3", lines)
	}
}

func TestFileSink_SeedsCounterFromExistingFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "alerts.jsonl")

	// Pre-create a file that's already over cap.
	pre := strings.Repeat("a", 1024) + "\n"
	if err := os.WriteFile(path, []byte(pre), 0o640); err != nil {
		t.Fatal(err)
	}

	fs, err := NewFileSinkWithOptions(path, FileSinkOptions{
		MaxSizeBytes: 256,
		Keep:         2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	// First Send should immediately rotate because the existing file
	// is already past the cap.
	if err := fs.Send(context.Background(), makeAlert("rule_z")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("first Send on pre-overflow file should rotate: %v", err)
	}
}

func TestFileSink_KeepDefault(t *testing.T) {
	// When MaxSizeBytes > 0 but Keep == 0, the sink should default
	// to a sensible Keep value (we picked 7).
	tmp := t.TempDir()
	path := filepath.Join(tmp, "alerts.jsonl")
	fs, err := NewFileSinkWithOptions(path, FileSinkOptions{
		MaxSizeBytes: 200,
		Keep:         0,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	if fs.keep != 7 {
		t.Errorf("default Keep = %d, want 7", fs.keep)
	}
}

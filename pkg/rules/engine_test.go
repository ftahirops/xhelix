package rules

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

func TestEngineSimpleMatch(t *testing.T) {
	var fires atomic.Uint64
	var captured atomic.Pointer[model.Alert]

	eng, err := NewEngine(func(a model.Alert) {
		fires.Add(1)
		c := a
		captured.Store(&c)
	})
	if err != nil {
		t.Fatal(err)
	}

	rules := []model.Rule{
		{
			ID:          "test_match",
			Desc:        "match anything from heartbeat sensor",
			SeverityRaw: "warn",
			Match:       `event.sensor == "heartbeat"`,
		},
		{
			ID:          "test_nomatch",
			SeverityRaw: "info",
			Match:       `event.sensor == "ebpf.proc"`,
		},
	}
	for i := range rules {
		if err := rules[i].Normalize(); err != nil {
			t.Fatalf("normalize: %v", err)
		}
	}
	if err := eng.Load(rules); err != nil {
		t.Fatalf("load: %v", err)
	}
	if eng.Count() != 2 {
		t.Errorf("loaded %d, want 2", eng.Count())
	}

	ev := model.NewEvent("heartbeat", model.SeverityInfo)
	ev.Comm = "xhelix"
	eng.Eval(context.Background(), ev)

	if got := fires.Load(); got != 1 {
		t.Errorf("fired %d, want 1", got)
	}
	if a := captured.Load(); a == nil || a.RuleID != "test_match" {
		t.Errorf("rule id = %v, want test_match", a)
	}
}

func TestEngineRateLimit(t *testing.T) {
	var fires atomic.Uint64
	eng, err := NewEngine(func(a model.Alert) { fires.Add(1) })
	if err != nil {
		t.Fatal(err)
	}

	r := model.Rule{
		ID:          "rl",
		SeverityRaw: "warn",
		Match:       `event.sensor == "test"`,
		RateLimit: &model.RuleRateLimit{
			PerMinute: 2,
			PerKey:    "rule",
		},
	}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	if err := eng.Load([]model.Rule{r}); err != nil {
		t.Fatal(err)
	}

	ev := model.NewEvent("test", model.SeverityInfo)
	for i := 0; i < 5; i++ {
		eng.Eval(context.Background(), ev)
	}
	if got := fires.Load(); got != 2 {
		t.Errorf("fires = %d, want 2 (rate-limited)", got)
	}
}

func TestEngineLoadInvalidRule(t *testing.T) {
	eng, _ := NewEngine(func(model.Alert) {})

	r := model.Rule{
		ID:          "bad",
		SeverityRaw: "warn",
		Match:       "this isn't valid CEL syntax @@@",
	}
	_ = r.Normalize()
	err := eng.Load([]model.Rule{r})
	if err == nil {
		t.Fatal("expected compile error on invalid CEL")
	}
}

func TestLimiterStopIsIdempotent(t *testing.T) {
	l := NewLimiter()
	l.Stop()
	l.Stop() // must not panic
}

func TestEngineTagsAndTreeAccessible(t *testing.T) {
	var fires atomic.Uint64
	eng, _ := NewEngine(func(model.Alert) { fires.Add(1) })

	r := model.Rule{
		ID:          "tags_tree",
		SeverityRaw: "high",
		Match: `event.tags["foo"] == "bar" &&` +
			` size(tree) > 0 && tree[0].comm == "shell"`,
	}
	_ = r.Normalize()
	if err := eng.Load([]model.Rule{r}); err != nil {
		t.Fatal(err)
	}

	ev := model.NewEvent("ebpf.proc", model.SeverityHigh)
	ev.Tags["foo"] = "bar"
	ev.ProcTree = []model.ProcNode{{PID: 1234, Comm: "shell"}}
	eng.Eval(context.Background(), ev)
	time.Sleep(10 * time.Millisecond)

	if got := fires.Load(); got != 1 {
		t.Errorf("fires = %d, want 1", got)
	}
}

// TestKernelModuleAndModprobeRulesMatch guards the 2026-06-13 detection
// fixes: kernel_module_dropped must match drift-scanner events (sensor
// "fim.drift", not just "fim") via sensor.startsWith, and the new
// modprobe_persistence rule must match a /etc/modprobe.d write. Tags are
// the exact shapes observed live on the dev box. These rules are
// category:incident, so live they feed the verdict scorer rather than
// emitting a named alert — this test asserts the raw MATCH that the
// scorer depends on.
func TestKernelModuleAndModprobeRulesMatch(t *testing.T) {
	cases := []struct {
		name, match, sensor string
		tags                map[string]string
		want                bool
	}{
		{
			name:   "kernel_module_dropped via drift scanner",
			match:  `event.sensor.startsWith("fim") && (path.startsWith("/lib/modules/") || path.startsWith("/usr/lib/modules/")) && path.endsWith(".ko") && event.tags["create"] == "true" && (!("package_managed" in event.tags) || event.tags["package_managed"] != "true")`,
			sensor: "fim.drift",
			tags:   map[string]string{"create": "true", "path": "/usr/lib/modules/evil.ko"},
			want:   true,
		},
		{
			name:   "kernel_module_dropped skips package-managed",
			match:  `event.sensor.startsWith("fim") && (path.startsWith("/lib/modules/") || path.startsWith("/usr/lib/modules/")) && path.endsWith(".ko") && event.tags["create"] == "true" && (!("package_managed" in event.tags) || event.tags["package_managed"] != "true")`,
			sensor: "fim.drift",
			tags:   map[string]string{"create": "true", "path": "/usr/lib/modules/legit.ko", "package_managed": "true"},
			want:   false,
		},
		{
			name:   "modprobe_persistence on modprobe.d write",
			match:  `event.sensor.startsWith("fim") && (path.startsWith("/etc/modprobe.d/") || path.startsWith("/etc/modules-load.d/") || path == "/etc/modules") && (event.tags["create"] == "true" || event.tags["write"] == "true") && (!("package_managed" in event.tags) || event.tags["package_managed"] != "true")`,
			sensor: "fim",
			tags:   map[string]string{"create": "true", "path": "/etc/modprobe.d/backdoor.conf"},
			want:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var fires atomic.Uint64
			eng, err := NewEngine(func(model.Alert) { fires.Add(1) })
			if err != nil {
				t.Fatal(err)
			}
			r := model.Rule{ID: "t", SeverityRaw: "high", Match: tc.match}
			if err := r.Normalize(); err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if err := eng.Load([]model.Rule{r}); err != nil {
				t.Fatalf("compile: %v", err)
			}
			ev := model.NewEvent(tc.sensor, model.SeverityHigh)
			ev.Tags = tc.tags
			eng.Eval(context.Background(), ev)
			if got := fires.Load() == 1; got != tc.want {
				t.Errorf("fired=%v want=%v", got, tc.want)
			}
		})
	}
}

// TestMemfdRunPatternExcludesCoreInfra guards the 2026-06-15 FP fix:
// systemd-executor and `runc init` re-exec via /proc/self/fd by design
// and must NOT score as fileless malware, while a real /proc/self/fd
// payload still fires.
func TestMemfdRunPatternExcludesCoreInfra(t *testing.T) {
	const match = `event.sensor == "ebpf.proc" &&
  (event.image.startsWith("/proc/self/fd/") || event.tags["from_memfd"] == "true") &&
  !(("argv" in event.tags) && (
    event.tags["argv"].startsWith("/usr/lib/systemd/systemd-executor") ||
    event.tags["argv"].startsWith("runc")
  ))`
	cases := []struct {
		name, image, argv string
		want              bool
	}{
		{"systemd-executor", "/proc/self/fd/9", "/usr/lib/systemd/systemd-executor --deserialize 136", false},
		{"runc init", "/proc/self/fd/6", "runc init", false},
		{"real fileless payload", "/proc/self/fd/3", "/tmp/x", true},
		{"fileless no argv tag", "/proc/self/fd/3", "", true}, // missing argv must not break the guard
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var fired atomic.Uint64
			eng, _ := NewEngine(func(model.Alert) { fired.Add(1) })
			r := model.Rule{ID: "memfd", SeverityRaw: "high", Match: match}
			if err := r.Normalize(); err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if err := eng.Load([]model.Rule{r}); err != nil {
				t.Fatalf("compile: %v", err)
			}
			ev := model.NewEvent("ebpf.proc", model.SeverityHigh)
			ev.Image = tc.image
			ev.Tags = map[string]string{}
			if tc.argv != "" {
				ev.Tags["argv"] = tc.argv
			}
			eng.Eval(context.Background(), ev)
			if got := fired.Load() == 1; got != tc.want {
				t.Errorf("fired=%v want=%v", got, tc.want)
			}
		})
	}
}

// TestBinaryRunsFromTmpExcludesGoBuild guards the 2026-06-15 FP fix:
// Go toolchain binaries under /tmp/go-build* are excluded; a real
// dropper in /tmp still fires.
func TestBinaryRunsFromTmpExcludesGoBuild(t *testing.T) {
	const match = `event.sensor == "ebpf.proc" &&
  (event.image.startsWith("/tmp/") || event.image.startsWith("/var/tmp/") || event.image.startsWith("/dev/shm/")) &&
  !event.image.contains("/go-build")`
	cases := []struct {
		image string
		want  bool
	}{
		{"/tmp/go-build3203061905/b001/exe/codemap_gen", false},
		{"/tmp/go-build2565644184/b001/router.test", false},
		{"/tmp/evil.sh", true},
		{"/dev/shm/payload", true},
		{"/tmp/xgs-waf-proxy", true}, // dev binary in /tmp is still flagged (intended)
	}
	for _, tc := range cases {
		var fired atomic.Uint64
		eng, _ := NewEngine(func(model.Alert) { fired.Add(1) })
		r := model.Rule{ID: "tmp", SeverityRaw: "warn", Match: match}
		if err := r.Normalize(); err != nil {
			t.Fatalf("normalize: %v", err)
		}
		if err := eng.Load([]model.Rule{r}); err != nil {
			t.Fatalf("compile: %v", err)
		}
		ev := model.NewEvent("ebpf.proc", model.SeverityWarn)
		ev.Image = tc.image
		eng.Eval(context.Background(), ev)
		if got := fired.Load() == 1; got != tc.want {
			t.Errorf("image=%s fired=%v want=%v", tc.image, got, tc.want)
		}
	}
}

package memory

import (
	"testing"
	"time"
)

func TestClassifyKnownMessages(t *testing.T) {
	cases := map[string]string{
		"general protection fault: 0000 [#1] SMP":          "gpf",
		"kernel BUG at fs/inode.c:1234!":                   "bug",
		"BUG: KASAN: out-of-bounds in foo":                 "kasan",
		"Code: Bad RIP value":                              "bad_rip",
		"WARNING: CPU: 0 PID: 1 at kernel/sched/core.c":    "warn",
		"[lkrg] cred validation failed":                    "lkrg_cred",
		"[lkrg] kASLR leak detected":                       "lkrg_kaslr",
		"some unrelated dmesg line":                        "",
	}
	for msg, want := range cases {
		got := Classify(msg)
		if got != want {
			t.Errorf("Classify(%q) = %q, want %q", msg, got, want)
		}
	}
}

func TestSegfaultBurstThreshold(t *testing.T) {
	b := NewSegfaultBurst()
	now := time.Now()
	for i := 0; i < 9; i++ {
		if b.Observe(123, now.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("tripped at i=%d, want at 10", i)
		}
	}
	if !b.Observe(123, now.Add(9*time.Second)) {
		t.Fatal("threshold of 10 not tripped")
	}
}

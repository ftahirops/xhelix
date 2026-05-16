package ebpf

import (
	"context"
	"testing"
	"time"

	"github.com/xhelix/xhelix/pkg/model"
)

func TestSensorLifecycleStub(t *testing.T) {
	// Stub backend is used on non-Linux; on Linux the live backend
	// preflights the kernel and may refuse. The lifecycle contract
	// (no panic, idempotent Stop) is the same.
	s := New(Config{})

	out := make(chan model.Event, 1)
	ctx := context.Background()
	if err := s.Start(ctx, out); err != nil {
		// Linux without BPF LSM enabled returns this; that's fine
		// for an environment-dependent CI runner.
		t.Logf("Start preflight result: %v", err)
		return
	}

	stopCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := s.Stop(stopCtx); err != nil {
		t.Errorf("Stop: %v", err)
	}
	// Idempotent
	if err := s.Stop(stopCtx); err != nil {
		t.Errorf("second Stop: %v", err)
	}
}

func TestEventKindString(t *testing.T) {
	cases := []struct {
		k    EventKind
		want string
	}{
		{KindProcSpawn, "proc_spawn"},
		{KindFileOpen, "file_open"},
		{KindNetConnect, "net_connect"},
		{KindBPFSyscall, "bpf_syscall"},
		{KindMprotectRWX, "mprotect_rwx"},
	}
	for _, c := range cases {
		if got := c.k.String(); got != c.want {
			t.Errorf("kind %d -> %q, want %q", c.k, got, c.want)
		}
	}
}

// Package ebpf is xhelix's kernel-eBPF sensor plane.
//
// The package compiles on every platform; eBPF programs are loaded
// and attached only on Linux. Non-Linux builds use a stub backend
// that emits no events, so cross-builds (e.g., for developer Macs)
// stay clean.
package ebpf

import (
	"context"

	"github.com/xhelix/xhelix/pkg/model"
)

// EventKind mirrors the kernel-side enum.
//
// Wire format with the kernel programs is stable across releases:
// new event types add new kind values; existing kinds never change
// layout.
type EventKind uint32

// These constants MUST match enum xh_event_kind in
// sensors/ebpf/progs/all.bpf.c. Drift between the two ends
// silently corrupts event decoding — the verifier won't catch it.
const (
	KindProcSpawn    EventKind = 1
	KindProcExit     EventKind = 2
	KindProcCred     EventKind = 3
	KindFileOpen     EventKind = 4
	KindNetConnect   EventKind = 5
	KindNetBind      EventKind = 6
	KindModLoad      EventKind = 7
	KindBPFSyscall   EventKind = 8
	KindPtrace       EventKind = 9
	KindMount        EventKind = 10
	KindMprotectRWX  EventKind = 11
	// reserved for future expansion (must stay aligned with C)
	KindCanaryFail   EventKind = 12
	KindInodePerm    EventKind = 13
	KindSetxattr     EventKind = 14
	KindNetICMP      EventKind = 15
	KindNetRawSock   EventKind = 16
	KindCapSet       EventKind = 17
	KindPivotRoot    EventKind = 18
	KindUnshare      EventKind = 19
	KindSSLRead      EventKind = 20
	KindNetBytes     EventKind = 22
	KindProcScrape   EventKind = 23
)

// String returns a stable, lowercase token for the kind.
func (k EventKind) String() string {
	switch k {
	case KindProcSpawn:
		return "proc_spawn"
	case KindProcExit:
		return "proc_exit"
	case KindProcCred:
		return "proc_cred"
	case KindFileOpen:
		return "file_open"
	case KindNetConnect:
		return "net_connect"
	case KindNetBind:
		return "net_bind"
	case KindModLoad:
		return "mod_load"
	case KindBPFSyscall:
		return "bpf_syscall"
	case KindPtrace:
		return "ptrace"
	case KindMount:
		return "mount"
	case KindMprotectRWX:
		return "mprotect_rwx"
	case KindCanaryFail:
		return "canary_fail"
	case KindInodePerm:
		return "inode_perm"
	case KindSetxattr:
		return "setxattr"
	case KindNetICMP:
		return "net_icmp"
	case KindNetRawSock:
		return "net_raw_sock"
	case KindCapSet:
		return "cap_set"
	case KindPivotRoot:
		return "pivot_root"
	case KindUnshare:
		return "unshare"
	case KindSSLRead:
		return "ssl_read"
	case KindNetBytes:
		return "net_bytes"
	case KindProcScrape:
		return "proc_scrape"
	}
	return "unknown"
}

// Backend is the platform-specific implementation surface.
//
// On Linux it loads, attaches, and reads eBPF programs. On other
// OSes it is a no-op stub. Decoded events are pushed onto out.
type Backend interface {
	Start(ctx context.Context, out chan<- model.Event) error
	Stop(ctx context.Context) error
	Healthy() bool
	Drops() uint64
}

// Config carries operator-tunable knobs.
type Config struct {
	RingbufSizeMB uint
	WatchPaths    []string
	BadIPs        []string
	SelfPID       uint32
}

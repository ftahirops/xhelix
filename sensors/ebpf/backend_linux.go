//go:build linux

package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/xhelix/xhelix/pkg/libssldiscover"

	"github.com/xhelix/xhelix/pkg/model"
)

// linuxBackend is the production backend.
//
// It loads eBPF programs from an ELF object file at runtime. The C
// source lives in sensors/ebpf/progs/ and must be compiled separately
// (clang + llvm-objcopy into a .o). If the ELF is missing the backend
// degrades to preflight-only.
type linuxBackend struct {
	cfg Config

	mu      sync.Mutex
	started atomic.Bool
	healthy atomic.Bool
	drops   atomic.Uint64
	cancel  context.CancelFunc
	out     chan<- model.Event

	// eBPF objects (nil when ELF not loaded)
	coll   *ebpf.Collection
	events *ringbuf.Reader
	links  []link.Link
}

func newPlatformBackend(cfg Config) Backend {
	return &linuxBackend{cfg: cfg}
}

func (b *linuxBackend) Start(ctx context.Context, out chan<- model.Event) error {
	if !b.started.CompareAndSwap(false, true) {
		return errors.New("ebpf: backend already started")
	}
	b.out = out
	if err := preflight(); err != nil {
		b.started.Store(false)
		return err
	}
	// Remove memlock limit for eBPF maps
	if err := rlimit.RemoveMemlock(); err != nil {
		b.started.Store(false)
		return fmt.Errorf("ebpf rlimit: %w", err)
	}

	// Attempt to load from ELF object. Paths are searched in order.
	elfPaths := []string{
		"/usr/lib/xhelix/xhelix-progs.o",
		"/var/lib/xhelix/xhelix-progs.o",
		"sensors/ebpf/progs/xhelix-progs.o",
	}
	for _, p := range elfPaths {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if err := b.loadELF(ctx, p); err != nil {
			return fmt.Errorf("ebpf load %s: %w", p, err)
		}
		break
	}
	b.healthy.Store(true)
	return nil
}

func (b *linuxBackend) Stop(ctx context.Context) error {
	b.healthy.Store(false)
	if b.cancel != nil {
		b.cancel()
	}
	if b.events != nil {
		_ = b.events.Close()
	}
	for _, l := range b.links {
		_ = l.Close()
	}
	b.links = nil
	if b.coll != nil {
		b.coll.Close()
	}
	return nil
}

func (b *linuxBackend) Healthy() bool { return b.healthy.Load() }
func (b *linuxBackend) Drops() uint64 { return b.drops.Load() }

// loadELF loads a compiled eBPF object and attaches programs.
func (b *linuxBackend) loadELF(parent context.Context, path string) error {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return fmt.Errorf("load spec: %w", err)
	}

	// Override map sizes from config
	if b.cfg.RingbufSizeMB > 0 {
		if m := spec.Maps["xh_events"]; m != nil {
			m.MaxEntries = uint32(b.cfg.RingbufSizeMB) * 1024 * 1024
		}
	}

	// Detect BPF LSM availability; strip LSM programs if unavailable
	lsmAvailable := false
	if lsmData, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		lsmAvailable = contains(string(lsmData), "bpf")
	}
	if !lsmAvailable {
		for name, p := range spec.Programs {
			if strings.HasPrefix(p.SectionName, "lsm/") {
				delete(spec.Programs, name)
			}
		}
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("new collection: %w", err)
	}
	b.coll = coll

	// Populate self-pid map so probes suppress their own activity
	if m := coll.Maps["xh_self_pid"]; m != nil {
		pid := uint32(os.Getpid())
		_ = m.Update(uint32(0), pid, ebpf.UpdateAny)
	}

	// Populate bad-ips map from config
	if m := coll.Maps["xh_bad_ips"]; m != nil && len(b.cfg.BadIPs) > 0 {
		for _, ipStr := range b.cfg.BadIPs {
			key := ipToU64(ipStr)
			if key != 0 {
				_ = m.Update(key, uint8(1), ebpf.UpdateAny)
			}
		}
	}

	// Attach tracepoint and kprobe programs by name pattern
	for name, prog := range coll.Programs {
		ps := spec.Programs[name]
		if ps == nil {
			fmt.Fprintf(os.Stderr, "ebpf: program %q has no spec; skipping\n", name)
			continue
		}
		sec := ps.SectionName
		var lnk link.Link
		var err error
		switch {
		case sec == "tp/sched/sched_process_exec":
			lnk, err = link.Tracepoint("sched", "sched_process_exec", prog, nil)
		case sec == "tp/sched/sched_process_exit":
			lnk, err = link.Tracepoint("sched", "sched_process_exit", prog, nil)
		case sec == "tp/syscalls/sys_enter_connect":
			lnk, err = link.Tracepoint("syscalls", "sys_enter_connect", prog, nil)
		case sec == "tp/syscalls/sys_enter_bind":
			lnk, err = link.Tracepoint("syscalls", "sys_enter_bind", prog, nil)
		case sec == "tp/syscalls/sys_enter_mprotect":
			lnk, err = link.Tracepoint("syscalls", "sys_enter_mprotect", prog, nil)
		// case sec == "tp/syscalls/sys_enter_openat":
		// 	lnk, err = link.Tracepoint("syscalls", "sys_enter_openat", prog, nil)
		// — re-enable when the procscrape BPF program is rewritten
		// in a verifier-safe form (see sensors/ebpf/progs/all.bpf.c
		// for the failed attempts and the path forward).
		case sec == "kprobe/security_kernel_module_from_file":
			lnk, err = link.Kprobe("security_kernel_module_from_file", prog, nil)
		case sec == "kprobe/__x64_sys_finit_module":
			lnk, err = link.Kprobe("__x64_sys_finit_module", prog, nil)
		case sec == "kprobe/__x64_sys_init_module":
			lnk, err = link.Kprobe("__x64_sys_init_module", prog, nil)
		case sec == "kprobe/__x64_sys_bpf":
			lnk, err = link.Kprobe("__x64_sys_bpf", prog, nil)
		case sec == "kprobe/__x64_sys_ptrace":
			lnk, err = link.Kprobe("__x64_sys_ptrace", prog, nil)
		case sec == "kprobe/do_mount":
			lnk, err = link.Kprobe("do_mount", prog, nil)
		case sec == "kprobe/mprotect_fixup":
			lnk, err = link.Kprobe("mprotect_fixup", prog, nil)
		case sec == "kprobe/tcp_connect":
			lnk, err = link.Kprobe("tcp_connect", prog, nil)
		case sec == "kprobe/tcp_sendmsg":
			lnk, err = link.Kprobe("tcp_sendmsg", prog, nil)
		case sec == "kprobe/tcp_recvmsg":
			lnk, err = link.Kprobe("tcp_recvmsg", prog, nil)
		case sec == "kprobe/udp_sendmsg":
			lnk, err = link.Kprobe("udp_sendmsg", prog, nil)
		case sec == "kprobe/udp_recvmsg":
			lnk, err = link.Kprobe("udp_recvmsg", prog, nil)
		case sec == "tp/syscalls/sys_enter_socket":
			lnk, err = link.Tracepoint("syscalls", "sys_enter_socket", prog, nil)
		case sec == "tp/syscalls/sys_enter_capset":
			lnk, err = link.Tracepoint("syscalls", "sys_enter_capset", prog, nil)
		case sec == "tp/syscalls/sys_enter_pivot_root":
			lnk, err = link.Tracepoint("syscalls", "sys_enter_pivot_root", prog, nil)
		case sec == "tp/syscalls/sys_enter_unshare":
			lnk, err = link.Tracepoint("syscalls", "sys_enter_unshare", prog, nil)
		case sec == "uprobe/SSL_read":
			// uprobe attach happens after the for-loop so we can
			// iterate the libssldiscover.Discover() results, which
			// may yield zero, one, or many targets.
			continue
		case sec == "uretprobe/SSL_read":
			continue
		default:
			continue
		}
		if err != nil {
			// Per-kernel symbols can be absent (e.g.,
			// security_kernel_module_from_file was renamed).
			// Skip the program and keep going — the rest of the
			// agent should not die over one missing kprobe.
			fmt.Fprintf(os.Stderr, "ebpf: skip %s (%s): %v\n", name, sec, err)
			continue
		}
		if lnk != nil {
			b.links = append(b.links, lnk)
		}
	}

	// libssl uprobe attachment — best-effort across every
	// discovered TLS library on the host. Failures are logged
	// and skipped; xhelix never refuses to start because one
	// libssl is missing or unreadable.
	b.attachLibsslUprobes(coll, spec)

	// Start ringbuf reader
	eventsMap := coll.Maps["xh_events"]
	if eventsMap == nil {
		coll.Close()
		return errors.New("ebpf: xh_events map not found")
	}
	reader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		coll.Close()
		return fmt.Errorf("ringbuf reader: %w", err)
	}
	b.events = reader

	ctx, cancel := context.WithCancel(parent)
	b.cancel = cancel
	go b.readLoop(ctx)
	return nil
}

func (b *linuxBackend) readLoop(ctx context.Context) {
	for ctx.Err() == nil {
		rec, err := b.events.Read()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			b.drops.Add(1)
			continue
		}
		ev, err := Decode(rec.RawSample)
		if err != nil {
			b.drops.Add(1)
			continue
		}
		select {
		case b.out <- ev:
		case <-ctx.Done():
			return
		default:
			b.drops.Add(1)
		}
	}
}

func ipToU64(s string) uint64 {
	// Simple IPv4 parser: pack into upper 4 bytes of uint64
	var ip [4]byte
	n, _ := fmt.Sscanf(s, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3])
	if n != 4 {
		return 0
	}
	return binary.BigEndian.Uint64([]byte{0, 0, 0, 0, ip[0], ip[1], ip[2], ip[3]})
}

// preflight verifies the kernel exposes BTF. BPF LSM is optional
// — tracepoints and kprobes work without it.
func preflight() error {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return fmt.Errorf("ebpf preflight: BTF missing (/sys/kernel/btf/vmlinux): %w", err)
	}
	body, err := os.ReadFile("/sys/kernel/security/lsm")
	if err == nil && !contains(string(body), "bpf") {
		// warn only — LSM hooks will be skipped at attach time
		// tracepoints/kprobes still work
	}
	return nil
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// attachLibsslUprobes discovers libssl-class libraries on the
// host and attaches the up_ssl_read_entry / up_ssl_read_ret
// programs at the resolved symbol offsets. Failures are non-fatal.
func (b *linuxBackend) attachLibsslUprobes(coll *ebpf.Collection, spec *ebpf.CollectionSpec) {
	entry := coll.Programs["up_ssl_read_entry"]
	ret := coll.Programs["up_ssl_read_ret"]
	if entry == nil || ret == nil {
		return
	}
	targets := libssldiscover.Discover(nil)
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "ebpf: no libssl-class library found; SSL_read uprobe disabled")
		return
	}
	for _, tgt := range targets {
		exe, err := link.OpenExecutable(tgt.LibPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ebpf: open %s: %v\n", tgt.LibPath, err)
			continue
		}
		// Entry uprobe — captures buf+num at call time.
		l1, err := exe.Uprobe(tgt.Symbol, entry, &link.UprobeOptions{Address: tgt.Offset})
		if err != nil {
			fmt.Fprintf(os.Stderr, "ebpf: uprobe %s @ %s: %v\n", tgt.Symbol, tgt.LibPath, err)
			continue
		}
		b.links = append(b.links, l1)
		// Return uprobe — reads bytes back when SSL_read returns.
		l2, err := exe.Uretprobe(tgt.Symbol, ret, &link.UprobeOptions{Address: tgt.Offset})
		if err != nil {
			fmt.Fprintf(os.Stderr, "ebpf: uretprobe %s @ %s: %v\n", tgt.Symbol, tgt.LibPath, err)
			continue
		}
		b.links = append(b.links, l2)
		fmt.Fprintf(os.Stderr, "ebpf: attached %s @ %s +0x%x (%s)\n",
			tgt.Symbol, tgt.LibPath, tgt.Offset, tgt.Family)
	}
}

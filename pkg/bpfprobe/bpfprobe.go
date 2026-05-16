// Package bpfprobe enumerates the currently-loaded eBPF programs
// on a Linux host and diffs the inventory against a baseline.
//
// Why it exists: an attacker who loads their own eBPF program can
// observe and modify everything xhelix does — eBPF rootkits are
// the emerging form of hostile kernel residence. xhelix's own
// programs (loaded by sensors/ebpf) have known tags and names;
// anything else is, by default, worth surfacing.
//
// Mechanism: bpf(BPF_PROG_GET_NEXT_ID) → BPF_PROG_GET_FD_BY_ID →
// BPF_OBJ_GET_INFO_BY_FD. Pure-Go syscall (no cilium/ebpf
// dependency for the enum path — we use it elsewhere; this stays
// self-contained so the detector keeps working even if the loader
// breaks).
//
// Build-tag-split: Linux only. Non-Linux callers get an empty
// snapshot.
package bpfprobe

import "sort"

// ProgInfo describes one loaded eBPF program.
type ProgInfo struct {
	ID            uint32
	Type          uint32  // bpf_prog_type enum
	TypeName      string  // human-readable
	Name          string  // CO-RE program name (up to 16 chars)
	Tag           string  // 8-byte deterministic content hash, hex
	LoadTime      uint64  // jiffies since boot when loaded (or 0)
	CreatedByUID  uint32
	GPLCompatible bool
}

// Snapshot is the current set of loaded programs.
type Snapshot struct {
	Progs []ProgInfo
}

// Diff describes how a current Snapshot differs from a baseline.
type Diff struct {
	Added   []ProgInfo
	Removed []ProgInfo
}

// IsEmpty returns true when neither side changed.
func (d Diff) IsEmpty() bool { return len(d.Added) == 0 && len(d.Removed) == 0 }

// Compare returns the change set keyed by program Tag (a
// deterministic content hash). Programs with no tag are keyed by
// (Name, Type) as a fallback.
func Compare(base, cur Snapshot) Diff {
	bm := indexByKey(base)
	cm := indexByKey(cur)
	var d Diff
	for k, p := range cm {
		if _, ok := bm[k]; !ok {
			d.Added = append(d.Added, p)
		}
	}
	for k, p := range bm {
		if _, ok := cm[k]; !ok {
			d.Removed = append(d.Removed, p)
		}
	}
	sort.Slice(d.Added, func(i, j int) bool { return d.Added[i].ID < d.Added[j].ID })
	sort.Slice(d.Removed, func(i, j int) bool { return d.Removed[i].ID < d.Removed[j].ID })
	return d
}

// IsWhitelisted reports whether p's identity matches any entry in
// the whitelist. Names compared case-insensitively; tags exact.
func IsWhitelisted(p ProgInfo, whitelist []Whitelist) bool {
	for _, w := range whitelist {
		if w.Tag != "" && w.Tag == p.Tag {
			return true
		}
		if w.Name != "" && equalFold(w.Name, p.Name) {
			return true
		}
	}
	return false
}

// FilterUnknown removes whitelisted programs from a Snapshot,
// leaving only the surprising ones for alerting.
func FilterUnknown(s Snapshot, whitelist []Whitelist) []ProgInfo {
	out := make([]ProgInfo, 0)
	for _, p := range s.Progs {
		if IsWhitelisted(p, whitelist) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// Whitelist is one acceptable program identity.
type Whitelist struct {
	Name string // CO-RE program name match
	Tag  string // exact tag match
	Note string // operator-facing reason
}

// XhelixWhitelist returns the bundled whitelist of programs xhelix
// itself loads via sensors/ebpf. Operators extend via config.
func XhelixWhitelist() []Whitelist {
	return []Whitelist{
		{Name: "tp_sys_enter_execve", Note: "xhelix proc-spawn tracepoint"},
		{Name: "tp_sched_process_exit", Note: "xhelix proc-exit tracepoint"},
		{Name: "tp_sys_enter_connect", Note: "xhelix net-connect tracepoint"},
		{Name: "tp_sys_enter_bind", Note: "xhelix net-bind tracepoint"},
		{Name: "kprobe_tcp_connect", Note: "xhelix tcp_connect kprobe (sport)"},
		{Name: "tp_sys_enter_socket", Note: "xhelix raw-socket tracepoint"},
		{Name: "tp_sys_enter_capset", Note: "xhelix capset tracepoint"},
		{Name: "tp_sys_enter_ptrace", Note: "xhelix ptrace tracepoint"},
		{Name: "tp_sys_enter_mprotect", Note: "xhelix mprotect tracepoint"},
		{Name: "kprobe_do_mount", Note: "xhelix mount kprobe"},
		{Name: "kprobe_init_module", Note: "xhelix module-load kprobe"},
		{Name: "kprobe_finit_module", Note: "xhelix module-load kprobe"},
		{Name: "kprobe_sys_bpf", Note: "xhelix bpf-syscall kprobe"},
	}
}

// ProgTypeName maps a bpf_prog_type enum value to its kernel name.
// Limited to types we expect to see; unknown values render as
// "TYPE<n>".
func ProgTypeName(t uint32) string {
	switch t {
	case 0:
		return "BPF_PROG_TYPE_UNSPEC"
	case 1:
		return "BPF_PROG_TYPE_SOCKET_FILTER"
	case 2:
		return "BPF_PROG_TYPE_KPROBE"
	case 3:
		return "BPF_PROG_TYPE_SCHED_CLS"
	case 4:
		return "BPF_PROG_TYPE_SCHED_ACT"
	case 5:
		return "BPF_PROG_TYPE_TRACEPOINT"
	case 6:
		return "BPF_PROG_TYPE_XDP"
	case 7:
		return "BPF_PROG_TYPE_PERF_EVENT"
	case 8:
		return "BPF_PROG_TYPE_CGROUP_SKB"
	case 9:
		return "BPF_PROG_TYPE_CGROUP_SOCK"
	case 10:
		return "BPF_PROG_TYPE_LWT_IN"
	case 11:
		return "BPF_PROG_TYPE_LWT_OUT"
	case 12:
		return "BPF_PROG_TYPE_LWT_XMIT"
	case 13:
		return "BPF_PROG_TYPE_SOCK_OPS"
	case 14:
		return "BPF_PROG_TYPE_SK_SKB"
	case 15:
		return "BPF_PROG_TYPE_CGROUP_DEVICE"
	case 16:
		return "BPF_PROG_TYPE_SK_MSG"
	case 17:
		return "BPF_PROG_TYPE_RAW_TRACEPOINT"
	case 18:
		return "BPF_PROG_TYPE_CGROUP_SOCK_ADDR"
	case 19:
		return "BPF_PROG_TYPE_LWT_SEG6LOCAL"
	case 20:
		return "BPF_PROG_TYPE_LIRC_MODE2"
	case 21:
		return "BPF_PROG_TYPE_SK_REUSEPORT"
	case 22:
		return "BPF_PROG_TYPE_FLOW_DISSECTOR"
	case 23:
		return "BPF_PROG_TYPE_CGROUP_SYSCTL"
	case 24:
		return "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE"
	case 25:
		return "BPF_PROG_TYPE_CGROUP_SOCKOPT"
	case 26:
		return "BPF_PROG_TYPE_TRACING"
	case 27:
		return "BPF_PROG_TYPE_STRUCT_OPS"
	case 28:
		return "BPF_PROG_TYPE_EXT"
	case 29:
		return "BPF_PROG_TYPE_LSM"
	case 30:
		return "BPF_PROG_TYPE_SK_LOOKUP"
	case 31:
		return "BPF_PROG_TYPE_SYSCALL"
	}
	return progTypeFallback(t)
}

func progTypeFallback(t uint32) string {
	return "BPF_PROG_TYPE_" + itoa(int(t))
}

// ── helpers ───────────────────────────────────────────────────

func indexByKey(s Snapshot) map[string]ProgInfo {
	out := make(map[string]ProgInfo, len(s.Progs))
	for _, p := range s.Progs {
		key := p.Tag
		if key == "" {
			key = "name:" + p.Name + "|type:" + itoa(int(p.Type))
		}
		out[key] = p
	}
	return out
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca := a[i]
		cb := b[i]
		if ca == cb {
			continue
		}
		if ca|0x20 != cb|0x20 {
			return false
		}
	}
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
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

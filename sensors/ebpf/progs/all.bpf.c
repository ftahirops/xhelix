// SPDX-License-Identifier: GPL-2.0
//
// Unified xhelix eBPF object. All programs share a single ringbuf
// and a small set of pinned maps so the userspace loader does one
// LoadCollectionSpec call.
//
// Build:  make ebpf
// Output: sensors/ebpf/progs/xhelix-progs.o
//
// Loader: sensors/ebpf/backend_linux.go attaches each program by
// the SEC() string declared on its function.

#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

// ---------------------------------------------------------------- types

#define XH_TASK_COMM_LEN 16
#define XH_PATH_MAX      256

enum xh_event_kind {
    XH_EV_PROC_SPAWN     = 1,
    XH_EV_PROC_EXIT      = 2,
    XH_EV_PROC_CRED      = 3,
    XH_EV_FILE_OPEN      = 4,
    XH_EV_NET_CONNECT    = 5,
    XH_EV_NET_BIND       = 6,
    XH_EV_MOD_LOAD       = 7,
    XH_EV_BPF_SYSCALL    = 8,
    XH_EV_PTRACE         = 9,
    XH_EV_MOUNT          = 10,
    XH_EV_MPROTECT_RWX   = 11,
    XH_EV_NET_ICMP       = 15,
    XH_EV_NET_RAW_SOCK   = 16,
    XH_EV_CAP_SET        = 17,
    XH_EV_PIVOT_ROOT     = 18,
    XH_EV_UNSHARE        = 19,
    XH_EV_SSL_READ       = 20,
    XH_EV_NET_BYTES      = 22,
    XH_EV_PROC_SCRAPE    = 23,
};

struct xh_event_hdr {
    __u64 ts_ns;
    __u32 kind;
    __u32 pid;
    __u32 tid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    char  comm[XH_TASK_COMM_LEN];
};

struct xh_proc_spawn {
    struct xh_event_hdr hdr;
    char  filename[XH_PATH_MAX];
    __u32 from_memfd;
    __u32 stdin_is_socket;
    __u32 stdout_is_socket;
};

struct xh_proc_exit_evt {
    struct xh_event_hdr hdr;
    __u32 exit_code;
};

struct xh_net_evt {
    struct xh_event_hdr hdr;
    __u32 family;
    __u8  daddr[16];
    __u16 dport;
    __u16 sport;   // local source port; 0 when emitter doesn't know
};

struct xh_bpf_syscall_evt {
    struct xh_event_hdr hdr;
    __u32 cmd;
};

/* Per-socket data-path byte counters. dir = 0 (out, tcp_sendmsg)
   or 1 (in, tcp_recvmsg). bytes is the size argument from the call;
   entry probes approximate (return-probes would give exact bytes
   transferred). Coarse aggregation lives in userspace. */
struct xh_net_bytes_evt {
    struct xh_event_hdr hdr;
    __u32 family;
    __u8  daddr[16];
    __u16 dport;
    __u16 sport;
    __u32 bytes;
    __u8  dir;
    __u8  _pad[3];
};

struct xh_ptrace_evt {
    struct xh_event_hdr hdr;
    __u32 request;
    __u32 target_pid;
};

struct xh_rawsock_evt {
    struct xh_event_hdr hdr;
    __u32 family;       // AF_INET=2, AF_INET6=10, AF_PACKET=17
    __u32 type;         // SOCK_RAW=3, SOCK_DGRAM=2, etc.
    __u32 protocol;     // IPPROTO_ICMP=1, IPPROTO_RAW=255, ETH_P_ALL=0x0003 etc.
};

struct xh_capset_evt {
    struct xh_event_hdr hdr;
    __u64 effective;     // CAP_* bitset that becomes effective
    __u64 permitted;
    __u64 inheritable;
};

struct xh_unshare_evt {
    struct xh_event_hdr hdr;
    __u64 flags;         // CLONE_NEW* bit mask passed to unshare(2)
};

#define XH_SSL_BUF_MAX 256
struct xh_sslread_evt {
    struct xh_event_hdr hdr;
    __u32 buf_len;          // bytes read (kernel-side capped at XH_SSL_BUF_MAX)
    __u8  buf[XH_SSL_BUF_MAX];
};

struct xh_mprotect_evt {
    struct xh_event_hdr hdr;
    __u64 addr;
    __u32 prot;
};

/* Procfs-scrape event. Fires when a process calls openat() with a
   path matching /proc/<pid>/{environ,maps,mem,status,cmdline,auxv,task/<tid>/{environ,maps,mem}}.
   target_pid is the inspected PID (parsed userspace-side from path
   for simplicity — BPF carries the raw path only). target_kind is
   one of XH_PROC_SCRAPE_{ENVIRON,MAPS,MEM,STATUS,CMDLINE,AUXV}. */
enum {
    XH_PROC_SCRAPE_ENVIRON = 1,
    XH_PROC_SCRAPE_MAPS    = 2,
    XH_PROC_SCRAPE_MEM     = 3,
    XH_PROC_SCRAPE_STATUS  = 4,
    XH_PROC_SCRAPE_CMDLINE = 5,
    XH_PROC_SCRAPE_AUXV    = 6,
};

struct xh_proc_scrape_evt {
    struct xh_event_hdr hdr;
    __u32 target_kind;   // XH_PROC_SCRAPE_*
    __u32 _pad;
    char  path[XH_PATH_MAX];
};

// ---------------------------------------------------------------- maps

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);
} xh_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} xh_self_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 20);
    __type(key, __u32);
    __type(value, __u8);
} xh_bad_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} xh_panic SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 18);
    __type(key, __u32);
    __type(value, __u8);
} xh_drop_set SEC(".maps");

// ---------------------------------------------------------------- helpers

static __always_inline int xh_is_self(void) {
    __u32 zero = 0;
    __u32 *self = bpf_map_lookup_elem(&xh_self_pid, &zero);
    if (!self) return 0;
    return *self == (__u32)(bpf_get_current_pid_tgid() >> 32);
}

static __always_inline int xh_is_panic(void) {
    __u32 zero = 0;
    __u8 *p = bpf_map_lookup_elem(&xh_panic, &zero);
    return p && *p;
}

static __always_inline void xh_fill_hdr(struct xh_event_hdr *h, __u32 kind) {
    h->ts_ns = bpf_ktime_get_ns();
    h->kind  = kind;
    __u64 id = bpf_get_current_pid_tgid();
    h->pid = id >> 32;
    h->tid = (__u32)id;
    __u64 ug = bpf_get_current_uid_gid();
    h->uid = (__u32)ug;
    h->gid = ug >> 32;
    h->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(h->comm, sizeof(h->comm));
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = BPF_CORE_READ(task, real_parent);
        if (parent) {
            h->ppid = BPF_CORE_READ(parent, tgid);
        }
    }
}

// ---------------------------------------------------------------- programs

char LICENSE[] SEC("license") = "GPL";

// fd_is_socket walks task->files->fdt->fd[fd_index] and reports
// whether the resulting struct file's inode is a socket.
//
// The verifier accepts this because every dereference is guarded
// and we never index past fdt->max_fds.
static __always_inline int fd_is_socket(struct task_struct *task, int fd_index) {
    if (!task) return 0;
    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files) return 0;
    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt) return 0;
    unsigned int max_fds = BPF_CORE_READ(fdt, max_fds);
    if ((unsigned int)fd_index >= max_fds) return 0;
    struct file **fda = BPF_CORE_READ(fdt, fd);
    if (!fda) return 0;
    struct file *f = NULL;
    bpf_probe_read_kernel(&f, sizeof(f), &fda[fd_index]);
    if (!f) return 0;
    struct inode *ino = BPF_CORE_READ(f, f_inode);
    if (!ino) return 0;
    umode_t mode = BPF_CORE_READ(ino, i_mode);
    // S_IFMT = 0170000, S_IFSOCK = 0140000
    return ((mode & 0170000) == 0140000) ? 1 : 0;
}

SEC("tp/sched/sched_process_exec")
int tp_proc_spawn(struct trace_event_raw_sched_process_exec *ctx) {
    if (xh_is_self()) return 0;
    struct xh_proc_spawn *e = bpf_ringbuf_reserve(&xh_events, sizeof(*e), 0);
    if (!e) return 0;
    xh_fill_hdr(&e->hdr, XH_EV_PROC_SPAWN);

    // The tracepoint's filename is __data_loc storage in kernel
    // memory; bpf_probe_read_kernel_str reads from kernel addr space.
    // Userspace decoder falls back to /proc/<pid>/exe on failure.
    unsigned int loc = ctx->__data_loc_filename;
    const char *fn = (const char *)((void *)ctx + (loc & 0xFFFF));
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), fn);

    e->from_memfd = 0;
    if (e->filename[0] == '/' && e->filename[1] == 'm' &&
        e->filename[2] == 'e' && e->filename[3] == 'm' &&
        e->filename[4] == 'f' && e->filename[5] == 'd') {
        e->from_memfd = 1;
    }

    // Walk the fd table at the exact moment of exec — captures the
    // reverse-shell pattern (bash with stdin/stdout = TCP socket fd)
    // with zero post-decode race.
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->stdin_is_socket  = fd_is_socket(task, 0);
    e->stdout_is_socket = fd_is_socket(task, 1);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int tp_proc_exit(struct trace_event_raw_sched_process_template *ctx) {
    if (xh_is_self()) return 0;
    struct xh_proc_exit_evt *e = bpf_ringbuf_reserve(&xh_events, sizeof(*e), 0);
    if (!e) return 0;
    xh_fill_hdr(&e->hdr, XH_EV_PROC_EXIT);
    e->exit_code = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_connect")
int tp_sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    if (xh_is_self()) return 0;
    struct sockaddr *uaddr = (struct sockaddr *)ctx->args[1];
    if (!uaddr) return 0;
    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &uaddr->sa_family);
    if (family != 2 && family != 10) return 0;

    struct xh_net_evt *e = bpf_ringbuf_reserve(&xh_events, sizeof(*e), 0);
    if (!e) return 0;
    xh_fill_hdr(&e->hdr, XH_EV_NET_CONNECT);
    e->family = family;

    if (family == 2) {
        struct sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), uaddr);
        __u32 ip = sin.sin_addr.s_addr;
        __builtin_memset(e->daddr, 0, 16);
        __builtin_memcpy(e->daddr + 12, &ip, 4);
        e->dport = bpf_ntohs(sin.sin_port);
    } else {
        struct sockaddr_in6 sin6 = {};
        bpf_probe_read_user(&sin6, sizeof(sin6), uaddr);
        __builtin_memcpy(e->daddr, &sin6.sin6_addr, 16);
        e->dport = bpf_ntohs(sin6.sin6_port);
    }
    e->sport = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// kprobe on tcp_connect — fires *after* the kernel has bound a
// local port to the socket, so we can read sk->__sk_common.skc_num
// (host byte order) and emit a full 4-tuple. This complements the
// sys_enter_connect tracepoint above; both events carry kind=
// NET_CONNECT but downstream dedupes by (pid, dst_ip, dst_port)
// using arrival time. The kprobe variant has sport > 0; the
// tracepoint variant has sport == 0.
SEC("kprobe/tcp_connect")
int kprobe_tcp_connect(struct pt_regs *ctx) {
    if (xh_is_self()) return 0;
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    __u16 family = 0;
    BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
    if (family != 2 && family != 10) return 0;

    struct xh_net_evt *e = bpf_ringbuf_reserve(&xh_events, sizeof(*e), 0);
    if (!e) return 0;
    xh_fill_hdr(&e->hdr, XH_EV_NET_CONNECT);
    e->family = family;
    __builtin_memset(e->daddr, 0, 16);

    if (family == 2) {
        __u32 daddr = 0;
        __u16 dport = 0;
        BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
        BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
        __builtin_memcpy(e->daddr + 12, &daddr, 4);
        e->dport = bpf_ntohs(dport);
    } else {
        BPF_CORE_READ_INTO(&e->daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
        __u16 dport = 0;
        BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
        e->dport = bpf_ntohs(dport);
    }

    __u16 sport_host = 0;
    BPF_CORE_READ_INTO(&sport_host, sk, __sk_common.skc_num);
    e->sport = sport_host; // already in host byte order

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_bind")
int tp_sys_enter_bind(struct trace_event_raw_sys_enter *ctx) {
    if (xh_is_self()) return 0;
    struct xh_net_evt *e = bpf_ringbuf_reserve(&xh_events, sizeof(*e), 0);
    if (!e) return 0;
    xh_fill_hdr(&e->hdr, XH_EV_NET_BIND);
    e->family = 0;
    e->dport  = 0;
    e->sport  = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// sys_enter_capset: capset(cap_user_header_t hdrp, cap_user_data_t datap).
// datap is an array of two cap_user_data structs for version 3
// headers. Each struct is { __u32 effective, permitted, inheritable }.
// We OR the two halves into u64 masks (CAP_LAST_CAP < 64 on modern
// kernels) so userspace classifiers can match by bit position.
SEC("tp/syscalls/sys_enter_capset")
int tp_sys_enter_capset(struct trace_event_raw_sys_enter *ctx) {
    if (xh_is_self()) return 0;
    void *datap = (void *)ctx->args[1];
    if (!datap) return 0;

    // Read two cap_user_data_t entries (12 bytes each).
    __u32 raw[6] = {0};
    bpf_probe_read_user(raw, sizeof(raw), datap);

    struct xh_capset_evt *e = bpf_ringbuf_reserve(&xh_events, sizeof(*e), 0);
    if (!e) return 0;
    xh_fill_hdr(&e->hdr, XH_EV_CAP_SET);
    e->effective   = ((__u64)raw[3] << 32) | (__u64)raw[0];
    e->permitted   = ((__u64)raw[4] << 32) | (__u64)raw[1];
    e->inheritable = ((__u64)raw[5] << 32) | (__u64)raw[2];
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// uretprobe on libssl SSL_read. Captures the first
// XH_SSL_BUF_MAX bytes of decrypted payload — typically the HTTP
// request line + a few headers, enough for the userspace URL
// extractor.
//
// SSL_read(ssl, buf, num) returns the byte count. We rely on the
// uretprobe being attached via the userspace loader with the
// per-call buf pointer captured into a BPF map keyed by tid. To
// keep this self-contained we stash the buf+num at entry via a
// uprobe (below) and read at return.
//
// Attachment is the loader's job: open
// /usr/lib/x86_64-linux-gnu/libssl.so.3, resolve `SSL_read`
// symbol offset, attach uprobe (entry) + uretprobe (return) to
// that offset. Multi-libc handling (BoringSSL, NSS) lives
// upstream in the loader; this program only needs the offset.
struct xh_ssl_ctx {
    __u64 buf_addr;
    __u64 num;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);          // tid
    __type(value, struct xh_ssl_ctx);
} xh_ssl_ctx_map SEC(".maps");

SEC("uprobe/SSL_read")
int up_ssl_read_entry(struct pt_regs *ctx) {
    if (xh_is_self()) return 0;
    __u64 tid = bpf_get_current_pid_tgid();
    struct xh_ssl_ctx c = {
        .buf_addr = (__u64)PT_REGS_PARM2(ctx),
        .num      = (__u64)PT_REGS_PARM3(ctx),
    };
    bpf_map_update_elem(&xh_ssl_ctx_map, &tid, &c, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int up_ssl_read_ret(struct pt_regs *ctx) {
    if (xh_is_self()) return 0;
    __u64 tid = bpf_get_current_pid_tgid();
    struct xh_ssl_ctx *c = bpf_map_lookup_elem(&xh_ssl_ctx_map, &tid);
    if (!c) return 0;
    bpf_map_delete_elem(&xh_ssl_ctx_map, &tid);

    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0) return 0;

    __u32 cap = (__u32)ret;
    if (cap > XH_SSL_BUF_MAX) cap = XH_SSL_BUF_MAX;

    struct xh_sslread_evt *e = bpf_ringbuf_reserve(&xh_events, sizeof(*e), 0);
    if (!e) return 0;
    xh_fill_hdr(&e->hdr, XH_EV_SSL_READ);
    e->buf_len = cap;
    __builtin_memset(e->buf, 0, sizeof(e->buf));
    bpf_probe_read_user(e->buf, cap, (void *)c->buf_addr);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// sys_enter_pivot_root(new_root, put_old). Almost never legitimate
// outside the once-per-container-start invocation by the runtime.
// We emit a bare header event; the userspace classifier scores by
// (cgroup_class, parent_exe) — if the calling pid is inside a
// container and its parent isn't a known runtime, that's escape.
SEC("tp/syscalls/sys_enter_pivot_root")
int tp_sys_enter_pivot_root(struct trace_event_raw_sys_enter *ctx) {
    if (xh_is_self()) return 0;
    struct xh_event_hdr *e = bpf_ringbuf_reserve(&xh_events, sizeof(*e), 0);
    if (!e) return 0;
    xh_fill_hdr(e, XH_EV_PIVOT_ROOT);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// sys_enter_unshare(flags). CLONE_NEWUSER, CLONE_NEWNS,
// CLONE_NEWPID flag bits are the high-signal subset — they're the
// building blocks every container-escape PoC uses. We capture all
// invocations and let userspace filter; this is cheap.
SEC("tp/syscalls/sys_enter_unshare")
int tp_sys_enter_unshare(struct trace_event_raw_sys_enter *ctx) {
    if (xh_is_self()) return 0;
    __u64 flags = (__u64)ctx->args[0];
    struct xh_unshare_evt *e = bpf_ringbuf_reserve(&xh_events, sizeof(*e), 0);
    if (!e) return 0;
    xh_fill_hdr(&e->hdr, XH_EV_UNSHARE);
    e->flags = flags;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// sys_enter_socket(family, type, protocol). We only care about
// raw / packet sockets — those are overwhelmingly used by
// scanners, custom protocol clients, and tooling that legitimate
// desktop / server software rarely touches. AF_PACKET is the
// strongest signal (sniffers, hping3, custom). SOCK_RAW (3) is
// next.
SEC("tp/syscalls/sys_enter_socket")
int tp_sys_enter_socket(struct trace_event_raw_sys_enter *ctx) {
    if (xh_is_self()) return 0;
    __u32 family   = (__u32)ctx->args[0];
    __u32 type     = (__u32)ctx->args[1] & 0xFF; // SOCK_TYPE_MASK
    __u32 protocol = (__u32)ctx->args[2];

    // Filter: only emit for AF_PACKET, or any SOCK_RAW.
    if (family != 17 /* AF_PACKET */ && type != 3 /* SOCK_RAW */) {
        return 0;
    }

    struct xh_rawsock_evt *e = bpf_ringbuf_reserve(&xh_events, sizeof(*e), 0);
    if (!e) return 0;
    xh_fill_hdr(&e->hdr, XH_EV_NET_RAW_SOCK);
    e->family   = family;
    e->type     = type;
    e->protocol = protocol;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/__x64_sys_finit_module")
int kp_module_load(struct pt_regs *ctx) {
    if (xh_is_self()) return 0;
    struct xh_event_hdr *e = bpf_ringbuf_reserve(&xh_events, sizeof(*e), 0);
    if (!e) return 0;
    xh_fill_hdr(e, XH_EV_MOD_LOAD);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/__x64_sys_init_module")
int kp_init_module(struct pt_regs *ctx) {
    if (xh_is_self()) return 0;
    struct xh_event_hdr *e = bpf_ringbuf_reserve(&xh_events, sizeof(*e), 0);
    if (!e) return 0;
    xh_fill_hdr(e, XH_EV_MOD_LOAD);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/__x64_sys_bpf")
int kp_sys_bpf(struct pt_regs *ctx) {
    if (xh_is_self()) return 0;
    struct xh_bpf_syscall_evt *e = bpf_ringbuf_reserve(&xh_events, sizeof(*e), 0);
    if (!e) return 0;
    xh_fill_hdr(&e->hdr, XH_EV_BPF_SYSCALL);
    e->cmd = (__u32)PT_REGS_PARM1(ctx);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/__x64_sys_ptrace")
int kp_sys_ptrace(struct pt_regs *ctx) {
    if (xh_is_self()) return 0;
    struct xh_ptrace_evt *e = bpf_ringbuf_reserve(&xh_events, sizeof(*e), 0);
    if (!e) return 0;
    xh_fill_hdr(&e->hdr, XH_EV_PTRACE);
    e->request    = (__u32)PT_REGS_PARM1(ctx);
    e->target_pid = (__u32)PT_REGS_PARM2(ctx);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/do_mount")
int kp_do_mount(struct pt_regs *ctx) {
    if (xh_is_self()) return 0;
    struct xh_event_hdr *e = bpf_ringbuf_reserve(&xh_events, sizeof(*e), 0);
    if (!e) return 0;
    xh_fill_hdr(e, XH_EV_MOUNT);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// mprotect syscall tracepoint — args[0]=addr, args[1]=len, args[2]=prot.
// PROT_EXEC = 0x4, PROT_WRITE = 0x2 — fire only when both are set.
// We use the syscall tracepoint not the kprobe because mprotect_fixup's
// signature varies across kernels; the syscall tracepoint is stable.
/* sys_enter_openat — fires on every openat(2). We only emit an
   event when the filename starts with "/proc/" AND a recognised
   credential-bearing suffix (/environ, /maps, /mem, /status,
   /cmdline, /auxv) appears in the path. PID parsing + reader
   allowlisting happen userspace-side; the BPF program's job is to
   keep the noise low without false negatives.

   args layout for sys_enter_openat:
     args[0] = int dfd
     args[1] = const char __user *filename
     args[2] = int flags
     args[3] = umode_t mode
*/
// NOTE: the XH_EV_PROC_SCRAPE / tp_sys_enter_openat_procscrape
// program is intentionally absent. Two earlier implementations
// failed the 6.8 verifier:
//
//   1. 256-byte stack-allocated path + probe_read_user_str:
//      "value -2147483648 makes fp pointer be out of bounds"
//   2. Read directly into the ringbuf event + variable-index
//      tail-byte compare:
//      "R1 unbounded memory access, make sure to bounds check"
//
// The userspace sensors/procscrape package + ruleset/core/
// procscrape.yaml stay in place as no-ops; once the kernel-side
// program is rewritten in a verifier-safe form (likely using a
// per-CPU map-backed scratch buffer instead of stack/ringbuf
// direct read, plus a bpf_strncmp-style fixed-length compare),
// it can be added back here without changing the userspace surface.

SEC("tp/syscalls/sys_enter_mprotect")
int tp_sys_enter_mprotect(struct trace_event_raw_sys_enter *ctx) {
    if (xh_is_self()) return 0;
    unsigned long prot = (unsigned long)ctx->args[2];
    if (!(prot & 0x4) || !(prot & 0x2)) return 0;
    struct xh_mprotect_evt *e = bpf_ringbuf_reserve(&xh_events, sizeof(*e), 0);
    if (!e) return 0;
    xh_fill_hdr(&e->hdr, XH_EV_MPROTECT_RWX);
    e->addr = (__u64)ctx->args[0];
    e->prot = (__u32)prot;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* tcp_sendmsg / tcp_recvmsg kprobes — emit a short event per call
   carrying the requested byte count, dst tuple, and direction. The
   threshold filter (size >= 64) skips keepalives + tiny ACKs that
   would otherwise drown the ringbuf on busy hosts. */
static __always_inline void xh_emit_net_bytes(struct sock *sk,
                                              __u32 size, __u8 dir) {
    if (xh_is_self()) return;
    if (size < 64) return;
    if (!sk) return;

    __u16 family = 0;
    BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
    if (family != 2 && family != 10) return;

    struct xh_net_bytes_evt *e =
        bpf_ringbuf_reserve(&xh_events, sizeof(*e), 0);
    if (!e) return;
    xh_fill_hdr(&e->hdr, XH_EV_NET_BYTES);
    e->family = family;
    __builtin_memset(e->daddr, 0, 16);

    if (family == 2) {
        __u32 daddr = 0;
        __u16 dport = 0;
        BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
        BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
        __builtin_memcpy(e->daddr + 12, &daddr, 4);
        e->dport = bpf_ntohs(dport);
    } else {
        BPF_CORE_READ_INTO(&e->daddr, sk,
                           __sk_common.skc_v6_daddr.in6_u.u6_addr8);
        __u16 dport = 0;
        BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
        e->dport = bpf_ntohs(dport);
    }
    __u16 sport_host = 0;
    BPF_CORE_READ_INTO(&sport_host, sk, __sk_common.skc_num);
    e->sport = sport_host;
    e->bytes = size;
    e->dir = dir;
    e->_pad[0] = e->_pad[1] = e->_pad[2] = 0;
    bpf_ringbuf_submit(e, 0);
}

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    __u32 size = (__u32)PT_REGS_PARM3(ctx);
    xh_emit_net_bytes(sk, size, 0 /* out */);
    return 0;
}

SEC("kprobe/tcp_recvmsg")
int kprobe_tcp_recvmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    __u32 size = (__u32)PT_REGS_PARM3(ctx);
    xh_emit_net_bytes(sk, size, 1 /* in */);
    return 0;
}

/* UDP byte accounting — same wire format, different L4. Useful for
   DNS, QUIC, and other UDP-based services. udp_sendmsg/recvmsg have
   the same (sk, msg, size) prefix in kernel versions xhelix supports. */
SEC("kprobe/udp_sendmsg")
int kprobe_udp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    __u32 size = (__u32)PT_REGS_PARM3(ctx);
    xh_emit_net_bytes(sk, size, 0);
    return 0;
}

SEC("kprobe/udp_recvmsg")
int kprobe_udp_recvmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    __u32 size = (__u32)PT_REGS_PARM3(ctx);
    xh_emit_net_bytes(sk, size, 1);
    return 0;
}

SEC("xdp")
int xdp_drop(struct xdp_md *ctx) {
    if (xh_is_panic()) return XDP_PASS;
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(0x0800)) return XDP_PASS;
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    __u32 src = ip->saddr;
    if (bpf_map_lookup_elem(&xh_drop_set, &src)) {
        return XDP_DROP;
    }
    return XDP_PASS;
}

/* SPDX-License-Identifier: Apache-2.0 */
#ifndef XH_COMMON_H
#define XH_COMMON_H

/*
 * xhelix shared kernel/userspace event format.
 *
 * Wire-format stability rules:
 *   - existing kinds never change layout
 *   - new event types add new kind values to xh_event_kind
 *   - userspace decodes by inspecting xh_event_hdr.kind
 *
 * All payloads must begin with xh_event_hdr.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef XH_TASK_COMM_LEN
#define XH_TASK_COMM_LEN 16
#endif

#ifndef XH_PATH_MAX
#define XH_PATH_MAX 256
#endif

#ifndef XH_ARGV_MAX
#define XH_ARGV_MAX 8
#endif

#ifndef XH_ARG_LEN
#define XH_ARG_LEN 128
#endif

enum xh_event_kind {
    XH_EV_PROC_SPAWN     = 1,
    XH_EV_PROC_CRED      = 2,
    XH_EV_FILE_OPEN      = 3,
    XH_EV_INODE_PERM     = 4,
    XH_EV_NET_CONNECT    = 5,
    XH_EV_NET_BIND       = 6,
    XH_EV_MOD_LOAD       = 7,
    XH_EV_BPF_SYSCALL    = 8,
    XH_EV_PTRACE         = 9,
    XH_EV_MOUNT          = 10,
    XH_EV_SETXATTR       = 11,
    XH_EV_MPROTECT_RWX   = 12,
    XH_EV_NET_BYTES      = 22,
    XH_EV_CANARY_FAIL    = 13,
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
    char  cwd[XH_PATH_MAX];
    __u32 argc;
    char  argv[XH_ARGV_MAX][XH_ARG_LEN];
    __u32 stdin_is_socket;
    __u32 stdout_is_socket;
    __u32 from_memfd;
};

struct xh_proc_cred {
    struct xh_event_hdr hdr;
    __u32 old_uid;
    __u32 new_uid;
};

struct xh_file_open_evt {
    struct xh_event_hdr hdr;
    char  path[XH_PATH_MAX];
    __u32 flags;
    __u32 mode;
};

struct xh_net_connect_evt {
    struct xh_event_hdr hdr;
    __u32 family;
    __u32 protocol;
    __u8  daddr[16];
    __u16 dport;
    __u8  saddr[16];
    __u16 sport;
};

struct xh_bpf_syscall_evt {
    struct xh_event_hdr hdr;
    __u32 cmd;
};

/* xh_net_bytes_evt — per-socket data-path byte counters emitted by
   kprobes on tcp_sendmsg / tcp_recvmsg. dir: 0=out, 1=in. bytes is
   the size argument from the call (kretprobes would give actual
   transferred bytes; entry probes approximate). */
struct xh_net_bytes_evt {
    struct xh_event_hdr hdr;
    __u32 family;     /* AF_INET / AF_INET6 */
    __u8  daddr[16];
    __u16 dport;
    __u16 sport;
    __u32 bytes;
    __u8  dir;        /* 0 out, 1 in */
    __u8  _pad[3];
};

#endif /* XH_COMMON_H */

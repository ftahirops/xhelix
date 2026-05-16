/* SPDX-License-Identifier: Apache-2.0 */
#ifndef XH_MAPS_H
#define XH_MAPS_H

#include "xh_common.h"

/* Single ring buffer for all event kinds. 8 MB by default. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);
} xh_events SEC(".maps");

/* Self pid so probes suppress their own activity. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} xh_self_pid SEC(".maps");

/* Watch-list of path hashes (FNV-1a on full d_path) for the file
 * sensor. Userspace populates from config.sensors.fim.watch_paths. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} xh_watch_paths SEC(".maps");

/* Threat-intel set of bad IPs (v4 packed into upper 4 bytes; v6 keys
 * are full 16-byte hashes). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 20);
    __type(key, __u64);
    __type(value, __u8);
} xh_bad_ips SEC(".maps");

/* Panic flag for the v1.0 enforcement kill switch. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} xh_panic SEC(".maps");

static __always_inline int xh_is_self(struct task_struct *task) {
    __u32 zero = 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 *self = bpf_map_lookup_elem(&xh_self_pid, &zero);
    return self && *self == pid;
}

static __always_inline int xh_is_panic(void) {
    __u32 zero = 0;
    __u8 *p = bpf_map_lookup_elem(&xh_panic, &zero);
    return p && *p;
}

static __always_inline void xh_fill_hdr(struct xh_event_hdr *h,
                                        __u32 kind,
                                        struct task_struct *task) {
    h->ts_ns = bpf_ktime_get_ns();
    h->kind  = kind;
    __u64 id = bpf_get_current_pid_tgid();
    h->pid   = id >> 32;
    h->tid   = (__u32)id;
    h->uid   = (__u32)bpf_get_current_uid_gid();
    h->gid   = bpf_get_current_uid_gid() >> 32;
    h->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(h->comm, XH_TASK_COMM_LEN);
    if (task) {
        h->ppid = BPF_CORE_READ(task, real_parent, tgid);
    }
}

#endif /* XH_MAPS_H */

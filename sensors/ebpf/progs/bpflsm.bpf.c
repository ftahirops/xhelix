// SPDX-License-Identifier: GPL-2.0
//
// xhelix BPF-LSM program — Phase I synchronous deny path.
//
// Hooks: security_bprm_check (execve entry point)
// Action: returns -EPERM if the binary path matches a deny-prefix in
// the operator-managed `xh_bpflsm_deny_paths` hash map. Otherwise 0
// (allow).
//
// REQUIREMENTS:
//   - kernel ≥ 5.7 (BPF LSM)
//   - kernel cmdline `lsm=...,bpf` (xhelix probes for this; refuses
//     to load if absent)
//   - userspace populates xh_bpflsm_deny_paths via cilium/ebpf
//
// Build alongside the main all.bpf.c into the same object file via
// the `make ebpf` target. The userspace loader (pkg/bpflsm) loads
// + attaches this program separately from the sensors loader.
//
// SAFETY:
//   - per-CPU array reserved scratch (no kmalloc)
//   - bounded path-copy via bpf_probe_read_kernel_str
//   - verifier-safe loops (constant bound)
//   - return value is signed int (LSM convention): 0 = allow, <0 = deny
//
// THIS FILE IS GPL-2.0 — same as all.bpf.c, kernel ABI requirement.

#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define XH_LSM_PATH_MAX   256
#define XH_LSM_MAX_PREFIX 64

// xh_bpflsm_deny_paths — hash map keyed by path prefix (up to 256
// bytes, NUL-terminated). Value is a u32 flags byte (currently
// just 1 = "deny", reserved for future per-rule policy).
//
// Userspace adds entries via bpf_map_update_elem(BPF_ANY).
// Entries are exact-prefix matches: deny if argv[0] (or interp arg)
// starts with the prefix.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[XH_LSM_PATH_MAX]);
    __type(value, __u32);
} xh_bpflsm_deny_paths SEC(".maps");

// xh_bpflsm_stats — per-CPU counter of (allowed, denied) for
// operator metrics via `xhelixctl bpflsm stats`.
struct xh_bpflsm_stat {
    __u64 allowed;
    __u64 denied;
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xh_bpflsm_stat);
} xh_bpflsm_stats SEC(".maps");

// Scratch buffer for the path string (per-CPU to stay under stack
// limits; verifier rejects 256-byte stack allocation).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[XH_LSM_PATH_MAX]);
} xh_bpflsm_scratch SEC(".maps");

// security_bprm_check: called BEFORE execve completes the new image.
// Return 0 to allow, -EPERM (1) to deny with errno=EPERM.
SEC("lsm/bprm_check_security")
int BPF_PROG(xh_lsm_bprm_check, struct linux_binprm *bprm, int ret)
{
    __u32 zero = 0;
    struct xh_bpflsm_stat *stat = bpf_map_lookup_elem(&xh_bpflsm_stats, &zero);

    // If a previous LSM in the chain already denied, propagate without
    // overriding. This is the BPF-LSM convention.
    if (ret != 0) {
        return ret;
    }

    // Get the filename being execve'd.
    char *path_buf = bpf_map_lookup_elem(&xh_bpflsm_scratch, &zero);
    if (!path_buf) {
        return 0;
    }

    // bprm->filename is a kernel-side string pointer.
    const char *filename = BPF_CORE_READ(bprm, filename);
    if (!filename) {
        if (stat) {
            stat->allowed++;
        }
        return 0;
    }

    long n = bpf_probe_read_kernel_str(path_buf, XH_LSM_PATH_MAX, filename);
    if (n <= 0) {
        if (stat) {
            stat->allowed++;
        }
        return 0;
    }

    // Exact-prefix match against the deny map. Hash lookup keyed by
    // the full path is O(1); for prefix matching we use a strategy
    // of "operator inserts the canonical denied path (e.g.
    // /tmp/.cache/payload), exact match denies."
    //
    // True prefix matching needs an LPM trie; left as a follow-on.
    // For v1, exact-path matching covers the common dropper case.
    __u32 *val = bpf_map_lookup_elem(&xh_bpflsm_deny_paths, path_buf);
    if (val && *val) {
        if (stat) {
            stat->denied++;
        }
        return -1; // -EPERM
    }

    if (stat) {
        stat->allowed++;
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

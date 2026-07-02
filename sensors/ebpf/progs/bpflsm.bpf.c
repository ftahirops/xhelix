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

// xh_bpflsm_deny_prefix — LPM trie for PATH-PREFIX denies. Key is
// {prefixlen_bits, path[256]}; the kernel matches the longest stored prefix
// that is a prefix of the execve'd path. Lets an operator deny a whole
// directory (e.g. a container's writable /var/www/.../uploads, or /tmp)
// with one entry instead of enumerating every binary. BPF_F_NO_PREALLOC is
// mandatory for LPM_TRIE.
struct xh_lpm_key {
    __u32 prefixlen;
    unsigned char data[XH_LSM_PATH_MAX];
};
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct xh_lpm_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} xh_bpflsm_deny_prefix SEC(".maps");

// Per-CPU scratch for the LPM lookup key (too big for the BPF stack).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xh_lpm_key);
} xh_bpflsm_lpm_scratch SEC(".maps");

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

    // Zero the whole scratch buffer before reading. The deny map is a HASH
    // keyed by the full 256-byte buffer, and userspace inserts zero-padded
    // keys. bpf_probe_read_kernel_str only writes up to the NUL and leaves the
    // tail as stale bytes from a previous (longer) path on this per-CPU slot,
    // so without this memset the kernel's key never equals userspace's padded
    // key and NOTHING is ever denied (verified live on vps-4, 2026-07-02).
    __builtin_memset(path_buf, 0, XH_LSM_PATH_MAX);

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

    // 1) Exact-path match against the hash deny map (O(1)).
    __u32 *val = bpf_map_lookup_elem(&xh_bpflsm_deny_paths, path_buf);
    if (val && *val) {
        if (stat) {
            stat->denied++;
        }
        return -1; // -EPERM
    }

    // 2) Longest-prefix match against the LPM deny trie — denies whole
    // directory subtrees with one entry (e.g. an upload dir). Build the
    // lookup key in per-CPU scratch: prefixlen = full path length in bits so
    // the trie returns the longest stored prefix that matches.
    struct xh_lpm_key *lk = bpf_map_lookup_elem(&xh_bpflsm_lpm_scratch, &zero);
    if (lk) {
        __builtin_memset(lk, 0, sizeof(*lk));
        long m = bpf_probe_read_kernel_str(lk->data, XH_LSM_PATH_MAX, filename);
        if (m > 0) {
            // exclude the NUL terminator from the match length
            lk->prefixlen = (__u32)(m - 1) * 8;
            __u32 *pval = bpf_map_lookup_elem(&xh_bpflsm_deny_prefix, lk);
            if (pval && *pval) {
                if (stat) {
                    stat->denied++;
                }
                return -1; // -EPERM
            }
        }
    }

    if (stat) {
        stat->allowed++;
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

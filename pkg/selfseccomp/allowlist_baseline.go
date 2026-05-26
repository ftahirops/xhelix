package selfseccomp

import "runtime"

// BaselineAllowList returns the audit-mode-safe starting allowlist
// for xhelix. It includes the syscalls a Go runtime uses on any
// modern Linux + the syscalls xhelix's primary subsystems use
// (eBPF, file I/O, signals, networking, threading, /proc).
//
// This is NOT meant to be the final enforce-mode list. It's the
// audit-mode starting point: install with ModeAudit, soak 24-48h
// against normal traffic + attack-sim corpus, harvest denied-but-
// logged syscalls from /var/log/audit/audit.log SECCOMP entries,
// add them here, repeat until empty for sustained period.
//
// The list is curated by syscall FAMILY:
//   - Go runtime: futex, sched_yield, rt_sigaction, rt_sigprocmask,
//     clone, clone3, exit, exit_group, mmap, munmap, mprotect,
//     madvise, rseq, getpid, gettid, tgkill, set_tid_address, ...
//   - File I/O: read, write, openat, openat2, close, fstat, statx,
//     lseek, getdents64, fcntl, dup, dup2, dup3, pipe2, ...
//   - Signals: signalfd4, sigaltstack, rt_sigreturn, rt_sigsuspend,
//     rt_sigtimedwait, kill, tkill, tgkill, ...
//   - Networking: socket, socketpair, bind, listen, accept4, connect,
//     getsockname, getpeername, getsockopt, setsockopt, sendto,
//     sendmsg, sendmmsg, recvfrom, recvmsg, recvmmsg, shutdown, ...
//   - eBPF / bpf(2): bpf, perf_event_open, ...
//   - inotify / fanotify: inotify_init1, inotify_add_watch,
//     inotify_rm_watch, fanotify_init, fanotify_mark, ...
//   - epoll: epoll_create1, epoll_ctl, epoll_wait, epoll_pwait, ...
//   - Timers: clock_gettime, clock_nanosleep, nanosleep,
//     timerfd_create, timerfd_settime, timerfd_gettime, ...
//   - Process introspection: prctl, getrandom, sysinfo, uname,
//     getrlimit, setrlimit, prlimit64, getcpu, ...
//   - Capabilities + identity: getuid, geteuid, getgid, getegid,
//     getgroups, capset, capget, ...
//
// Numbers come from BaselineSyscallNumbers for the host arch.
func BaselineAllowList() AllowList {
	wanted := baselineSyscallNames()
	resolved, numbers := resolveSyscalls(runtime.GOARCH, wanted)
	// Drop duplicates by NR so the same syscall doesn't bloat the
	// filter (e.g. arm64 aliases `open`→openat and `openat`→openat
	// both resolve to NR 56).
	seen := make(map[uint32]bool, len(numbers))
	uName := resolved[:0]
	uNum := numbers[:0]
	for i, nr := range numbers {
		if seen[nr] {
			continue
		}
		seen[nr] = true
		uName = append(uName, resolved[i])
		uNum = append(uNum, nr)
	}
	return AllowList{
		Names:   uName,
		Numbers: uNum,
		Mode:    ModeOff, // safety: caller must explicitly bump to audit/enforce
	}
}

// resolveSyscalls returns the subset of `wanted` that has an NR on
// the given arch, in matching order. Unknown names are silently
// dropped — they couldn't be enforced anyway.
func resolveSyscalls(arch string, wanted []string) (names []string, numbers []uint32) {
	tbl := numberTableForArch(arch)
	if tbl == nil {
		return nil, nil
	}
	for _, n := range wanted {
		if nr, ok := tbl[n]; ok {
			names = append(names, n)
			numbers = append(numbers, nr)
		}
	}
	return names, numbers
}

// baselineSyscallNames lists every syscall the xhelix audit-mode
// baseline allows. Adding a syscall here makes it allowed. Removing
// one makes it denied (LOG in audit mode; EPERM in enforce mode).
//
// Sources: Go runtime source (runtime/sys_linux_*.s), xhelix sensors
// (sensors/ebpf, sensors/fim, sensors/identity), known eBPF program
// loader requirements (cilium/ebpf), and modernc.org/sqlite syscall
// usage.
func baselineSyscallNames() []string {
	return []string{
		// Go runtime + threading
		"futex", "futex_waitv",
		"sched_yield", "sched_getaffinity", "sched_setaffinity",
		"clone", "clone3", "execve", "execveat",
		"exit", "exit_group",
		"set_tid_address", "set_robust_list", "get_robust_list",
		"rseq",
		"gettid", "getpid", "getppid", "getsid", "getpgid", "setpgid", "setsid",
		"arch_prctl",
		"prctl",

		// Memory
		"mmap", "mmap2", "munmap", "mprotect", "madvise", "mremap",
		"mlock", "mlock2", "mlockall", "munlock", "munlockall",
		"brk",

		// Signals
		"rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
		"rt_sigsuspend", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo",
		"sigaltstack", "signalfd4",
		"kill", "tkill", "tgkill",
		"pause",

		// File I/O
		"read", "write", "pread64", "pwrite64", "readv", "writev",
		"preadv", "pwritev", "preadv2", "pwritev2",
		"open", "openat", "openat2", "close", "close_range",
		"lseek", "ftruncate", "truncate",
		"fsync", "fdatasync", "sync", "syncfs",
		"fstat", "newfstatat", "statx", "lstat", "stat",
		"fcntl", "flock", "ioctl",
		"dup", "dup2", "dup3",
		"pipe2",
		"getdents64",
		"readlink", "readlinkat",
		"access", "faccessat", "faccessat2",
		"chdir", "fchdir", "getcwd",
		"mkdir", "mkdirat", "rmdir",
		"rename", "renameat", "renameat2",
		"unlink", "unlinkat",
		"chmod", "fchmod", "fchmodat",
		"chown", "fchown", "fchownat", "lchown",
		"utimensat", "futimesat",
		"link", "linkat", "symlink", "symlinkat",
		"copy_file_range", "sendfile",
		"memfd_create",

		// Networking
		"socket", "socketpair",
		"bind", "listen", "accept", "accept4",
		"connect",
		"getsockname", "getpeername",
		"getsockopt", "setsockopt",
		"sendto", "sendmsg", "sendmmsg",
		"recvfrom", "recvmsg", "recvmmsg",
		"shutdown",

		// epoll / event notification
		"epoll_create", "epoll_create1",
		"epoll_ctl", "epoll_wait", "epoll_pwait", "epoll_pwait2",
		"eventfd", "eventfd2",
		"poll", "ppoll", "select", "pselect6",

		// inotify / fanotify (FIM sensors)
		"inotify_init1", "inotify_add_watch", "inotify_rm_watch",
		"fanotify_init", "fanotify_mark",

		// eBPF + perf (sensors/ebpf)
		"bpf", "perf_event_open",

		// Timers
		"clock_gettime", "clock_getres", "clock_nanosleep", "nanosleep",
		"timerfd_create", "timerfd_settime", "timerfd_gettime",
		"timer_create", "timer_delete", "timer_gettime", "timer_settime",
		"gettimeofday", "time",

		// Process introspection
		"getrandom", "sysinfo", "uname",
		"getrlimit", "setrlimit", "prlimit64", "getcpu",

		// Identity / capabilities
		"getuid", "geteuid", "getgid", "getegid",
		"setuid", "setgid", "setreuid", "setregid",
		"getgroups", "setgroups",
		"capget", "capset",

		// systemd / cgroup helpers
		"setns", "unshare",

		// xattrs (used by integrity helpers, container ID checks)
		"getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr",

		// Wait / process lifecycle (xhelix spawns helpers like nft)
		"wait4", "waitid",

		// Misc utility used by stdlib
		"umask", "getpriority", "setpriority",
		"membarrier",

		// Allowed for restart / immutable / state-dir ops
		"chroot",
	}
}

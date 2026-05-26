// SPDX-License-Identifier: Apache-2.0

//go:build linux

// fanotify-backed sensor — SCAFFOLD ONLY (intentionally not yet wired).
//
// Status (2026-05-24):
//
//	This file lays out the fanotify migration path that closes the
//	writer-attribution gap structurally. The inotify-based sensor in
//	inotify_linux.go cannot identify the writer (kernel doesn't carry
//	that information for inotify). fanotify with FAN_REPORT_PIDFD or
//	FAN_REPORT_TID provides the writer's PID with each event.
//
//	What's here:
//	  - Constants for the syscalls + flags we need
//	  - A no-op Start() that documents the implementation steps
//
//	What's NOT here (deferred to a focused sensor-rewrite session):
//	  - fanotify_init / fanotify_mark syscall wrappers
//	  - event-loop reading from the fanotify fd
//	  - parsing struct fanotify_event_metadata + the PIDFD info record
//	  - permission-event vs notification-event handling
//	  - graceful degradation when CAP_SYS_ADMIN is unavailable
//	  - tests against a real kernel fanotify fd
//
//	Honest scope: 1-2 focused days to ship a working sensor that emits
//	model.Event with ev.PID populated. Multi-day if we want permission
//	events (block-on-write) too.
//
// Until this lands, the writerattr.Cache (pkg/brp/writerattr) provides
// a 5-second correlation window between eBPF write events and FIM
// notifications — adequate for typical attacker patterns but not the
// structural fix.
package fim

import (
	"errors"
)

// fanotify flag values from linux/fanotify.h (manually transcribed
// because golang.org/x/sys may not expose them on older Go toolchains).
const (
	fanClassNotif      = 0x00000000
	fanReportFID       = 0x00000200
	fanReportPIDFD     = 0x00000080
	fanReportTID       = 0x00000100
	fanMarkAdd         = 0x00000001
	fanMarkFilesystem  = 0x00000100
	fanModify          = 0x00000002
	fanCreate          = 0x00000100
	fanCloseWrite      = 0x00000008
)

// FanotifyAvailable reports whether the running kernel + permissions
// would support the planned fanotify configuration. Real implementation
// will probe via fanotify_init + close. For now returns ErrNotImplemented
// so callers can fall back to inotify_linux.go cleanly.
func FanotifyAvailable() error {
	return errors.New("fanotify sensor not yet implemented; use inotify path")
}

// Implementation checklist for the follow-on session:
//
//   1. Wrap fanotify_init via syscall.Syscall with fanClassNotif |
//      fanReportPIDFD. Bail if errno is EPERM (no CAP_SYS_ADMIN).
//
//   2. fanotify_mark on each watch root with fanMarkAdd | fanMarkFilesystem
//      and the event mask (fanModify | fanCreate | fanCloseWrite).
//
//   3. Read loop: read(fd) returns one or more struct fanotify_event_metadata
//      records. Each carries fd or fhandle (file identifier) plus an
//      info record carrying the PIDFD (FAN_EVENT_INFO_TYPE_PIDFD).
//
//   4. For each event: resolve path via /proc/self/fd/<info.fd>, resolve
//      PID via pidfd_getpid(info.pidfd), emit model.Event with PID +
//      Comm populated by reading /proc/<pid>/comm.
//
//   5. Close all FDs after emission to avoid leaking kernel resources.
//
// Once shipped, the writerattr.Cache becomes a redundant safety net
// rather than the primary attribution path.

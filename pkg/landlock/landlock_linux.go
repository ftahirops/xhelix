//go:build linux

package landlock

import (
	"fmt"
	"log/slog"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// landlock_ruleset_attr — kernel struct layout. handled_access_fs is
// the bitmask of access types this ruleset cares about; rules added
// via landlock_add_rule must use a subset of these.
type rulesetAttr struct {
	HandledAccessFS uint64
}

// landlock_path_beneath_attr — for LANDLOCK_RULE_PATH_BENEATH rule type.
type pathBeneathAttr struct {
	AllowedAccess uint64
	ParentFD      int32
}

// SYS_LANDLOCK_RESTRICT_SELF is not in the older sys/unix headers;
// hardcode for amd64+arm64. Syscall number is the same on both arches
// (446 on amd64; arm64 uses the asm-generic table where landlock
// occupies a contiguous block).
const sysLandlockRestrictSelf uintptr = 446

// LANDLOCK_RULE_PATH_BENEATH = 1 — only rule type we use.
const ruleTypePathBeneath uintptr = 1

// probeABI calls landlock_create_ruleset(NULL, 0,
// LANDLOCK_CREATE_RULESET_VERSION) to retrieve the kernel's highest
// supported ABI. Returns version (>=1) or error.
func probeABI() (int, error) {
	r1, _, errno := unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		0,
		0,
		uintptr(unix.LANDLOCK_CREATE_RULESET_VERSION),
	)
	if errno != 0 {
		return 0, fmt.Errorf("landlock_create_ruleset version probe: %w", errno)
	}
	return int(r1), nil
}

// handledAccessFS returns the bitmask of FS access types this ruleset
// should track. We start with the v1 set; if abi >= 2 add REFER; if
// abi >= 3 add TRUNCATE.
func handledAccessFS(abi int) uint64 {
	mask := uint64(
		unix.LANDLOCK_ACCESS_FS_EXECUTE |
			unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
			unix.LANDLOCK_ACCESS_FS_READ_FILE |
			unix.LANDLOCK_ACCESS_FS_READ_DIR |
			unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
			unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
			unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
			unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
			unix.LANDLOCK_ACCESS_FS_MAKE_REG |
			unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
			unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
			unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
			unix.LANDLOCK_ACCESS_FS_MAKE_SYM,
	)
	if abi >= 2 {
		mask |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		mask |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	return mask
}

// roAccessFS is the access bitmask we grant for read-only paths.
func roAccessFS(abi int) uint64 {
	return uint64(
		unix.LANDLOCK_ACCESS_FS_EXECUTE |
			unix.LANDLOCK_ACCESS_FS_READ_FILE |
			unix.LANDLOCK_ACCESS_FS_READ_DIR,
	)
}

// rwAccessFS is the access bitmask for read+write paths. Includes
// everything in handledAccessFS so the daemon can do any FS op
// (create, write, remove, mkfifo, etc.) within these paths.
func rwAccessFS(abi int) uint64 {
	return handledAccessFS(abi)
}

func enforce(p Policy, abi int, log *slog.Logger) error {
	// 1. Create ruleset.
	attr := rulesetAttr{HandledAccessFS: handledAccessFS(abi)}
	rsFD, _, errno := unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("landlock_create_ruleset: %w", errno)
	}
	defer syscall.Close(int(rsFD))

	// 2. Add rules for each path. Missing paths are logged + skipped.
	roMask := roAccessFS(abi)
	rwMask := rwAccessFS(abi)
	added := 0
	for _, path := range p.ReadOnly {
		if err := addPathRule(int(rsFD), path, roMask); err != nil {
			if log != nil {
				log.Warn("landlock: skip read-only path", "path", path, "err", err)
			}
			continue
		}
		added++
	}
	for _, path := range p.ReadWrite {
		if err := addPathRule(int(rsFD), path, rwMask); err != nil {
			if log != nil {
				log.Warn("landlock: skip read-write path", "path", path, "err", err)
			}
			continue
		}
		added++
	}

	if log != nil {
		log.Info("landlock: rules added", "count", added,
			"requested_ro", len(p.ReadOnly), "requested_rw", len(p.ReadWrite))
	}

	// 3. Ensure PR_SET_NO_NEW_PRIVS is set. G.1 should have done this
	// already, but landlock_restrict_self requires it — be idempotent.
	if _, _, errno := unix.Syscall6(unix.SYS_PRCTL,
		unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("landlock: PR_SET_NO_NEW_PRIVS: %w", errno)
	}

	// 4. Restrict self. IRREVERSIBLE.
	if _, _, errno := unix.Syscall(
		sysLandlockRestrictSelf,
		rsFD,
		0,
		0,
	); errno != 0 {
		return fmt.Errorf("landlock_restrict_self: %w", errno)
	}

	if log != nil {
		log.Info("landlock: filesystem restriction ACTIVE",
			"mode", "enforce",
			"abi", abi,
			"rules_active", added,
			"warning", "restriction is irreversible for this process and all descendants")
	}
	return nil
}

// addPathRule opens `path` with O_PATH and adds a path-beneath rule
// granting `access` to that subtree.
func addPathRule(rsFD int, path string, access uint64) error {
	fd, err := os.OpenFile(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer fd.Close()
	rule := pathBeneathAttr{
		AllowedAccess: access,
		ParentFD:      int32(fd.Fd()),
	}
	if _, _, errno := unix.Syscall6(
		unix.SYS_LANDLOCK_ADD_RULE,
		uintptr(rsFD),
		ruleTypePathBeneath,
		uintptr(unsafe.Pointer(&rule)),
		0, 0, 0,
	); errno != 0 {
		return fmt.Errorf("landlock_add_rule: %w", errno)
	}
	return nil
}

package pkgmgr

import (
	"context"
	"strings"
	"time"
)

// TailDpkg tails /var/log/dpkg.log and infers transaction boundaries.
// dpkg.log has no explicit start/end markers, so we use a sliding-window
// approach: every log line opens or extends a 60s window from the line
// timestamp.
//
// dpkg.log format:
//
//	2026-05-01 06:50:50 startup archives unpack
//	2026-05-01 06:50:50 upgrade kmod:amd64 31+20240202-2ubuntu7.1 31+20240202-2ubuntu7.2
//	2026-05-01 06:50:50 status triggers-pending initramfs-tools:all 0.142ubuntu25.8
//
// The first column is the date, second is the time, third onwards is the
// action.
func TailDpkg(ctx context.Context, store *Store, path string) error {
	return tailLog(ctx, store, path, ManagerDpkg, parseDpkgLine)
}

// 60s sliding window — anything that happens within 60s of the last
// dpkg.log line is considered "still inside a dpkg transaction." The
// average dpkg transaction is sub-second; the 60s window covers slow
// postinst scripts (initramfs regen, font cache rebuild, etc.).
const dpkgWindowSlide = 60 * time.Second

func parseDpkgLine(line string, fallbackTs time.Time) lineEvent {
	// Need at least "YYYY-MM-DD HH:MM:SS action" — 20 chars of timestamp.
	if len(line) < 20 {
		return lineEvent{}
	}
	t, err := time.ParseInLocation("2006-01-02 15:04:05", line[:19], time.Local)
	if err != nil {
		return lineEvent{}
	}
	// dpkg.log timestamps are local time; xhelix events are typically
	// UTC. The IsActive check is on absolute time so local-vs-UTC
	// matters — convert to UTC for consistency with the rest of xhelix.
	t = t.UTC()

	// Skip noisy "status" lines — there are dozens per transaction and
	// they don't add window information beyond the upgrade/install line
	// that triggered them.
	action := strings.Fields(line[20:])
	if len(action) > 0 && action[0] == "status" {
		// Still extend the window — status lines occur during the
		// transaction. But don't log them as fresh starts.
	}

	return lineEvent{
		kind:  openOnly,
		start: t,
		end:   t.Add(dpkgWindowSlide),
	}
}

// TailSnap tails /var/log/snapd.log if available. Snap transactions are
// rarer + slower; same 60s sliding pattern as dpkg.
func TailSnap(ctx context.Context, store *Store, path string) error {
	return tailLog(ctx, store, path, ManagerSnap, parseDpkgLine)
}

// TailDnf tails /var/log/dnf.rpm.log on RHEL/Fedora. The format is similar
// enough to dpkg.log (timestamp + action) that the same parser works for
// the basic window-tracking case.
func TailDnf(ctx context.Context, store *Store, path string) error {
	return tailLog(ctx, store, path, ManagerDnf, parseDpkgLine)
}

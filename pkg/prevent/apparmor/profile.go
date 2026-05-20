// Package apparmor generates per-service AppArmor profiles from a
// ServiceContract and (on Linux) installs them via apparmor_parser.
//
// Pure Go renderer + thin Linux-only install path. CGO_ENABLED=0
// compatible. See PROTECTED_SERVICES_TRAP.md §5 (Ring 1) and §12
// (prevention order: cap drop → MAC → seccomp → ...).
//
// AppArmor is the file-and-exec layer of Ring 1. Where seccomp
// blocks syscalls by number, AppArmor blocks paths by name —
// catching things seccomp can't see (e.g. /bin/sh via different
// path, /etc/cron.d writes).
//
// We pick AppArmor over SELinux for v1 per
// PROTECTED_SERVICES_TRAP.md §15 milestone P-PS.4: one MAC,
// well-supported on Debian/Ubuntu (the SMB target audience).
package apparmor

import (
	"fmt"
	"sort"
	"strings"

	"github.com/xhelix/xhelix/pkg/profiles/contracts"
	"github.com/xhelix/xhelix/pkg/protectedsvc"
)

// Profile is a rendered AppArmor policy ready for apparmor_parser.
type Profile struct {
	// Name is the AppArmor profile name (e.g. "xhelix.nginx-main").
	Name string
	// Path is where Install() writes the file (typically under
	// /etc/apparmor.d/). Empty until Install() is called.
	Path string
	// Body is the rendered profile text.
	Body string
}

// ProfileNamePrefix is the namespace under which xhelix-generated
// profiles live. Operators can grep /etc/apparmor.d/ for xhelix.*
// to see everything we install.
const ProfileNamePrefix = "xhelix"

// Render builds the AppArmor profile text for a ProtectedService.
// Pure function — does not touch the filesystem. The result is
// human-readable, deterministic (same input → identical bytes), and
// loadable by apparmor_parser as-is.
func Render(svc *protectedsvc.ProtectedService) (Profile, error) {
	if svc == nil {
		return Profile{}, fmt.Errorf("apparmor: nil service")
	}
	if svc.Name == "" {
		return Profile{}, fmt.Errorf("apparmor: service has no name")
	}
	if svc.ExecPath == "" {
		return Profile{}, fmt.Errorf("apparmor %q: exec_path required", svc.Name)
	}

	name := ProfileName(svc.Name)
	var b strings.Builder

	// Header — pulled-in tunables are how AppArmor handles paths.
	fmt.Fprintln(&b, "#include <tunables/global>")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "# xhelix Protected Services profile — DO NOT EDIT BY HAND.\n")
	fmt.Fprintf(&b, "# Generated for service %q (kind=%s role=%s).\n",
		svc.Name, svc.Kind, svc.Role)
	fmt.Fprintf(&b, "# See PROTECTED_SERVICES_TRAP.md §5 for the policy model.\n")
	fmt.Fprintln(&b)

	fmt.Fprintf(&b, "profile %s %s {\n", name, svc.ExecPath)
	fmt.Fprintln(&b, `  #include <abstractions/base>`)
	fmt.Fprintln(&b, `  #include <abstractions/nameservice>`)
	fmt.Fprintln(&b)

	// Allow the binary itself to be mmap-read and exec'd by the kernel.
	fmt.Fprintf(&b, "  # Self\n")
	fmt.Fprintf(&b, "  %s mr,\n", svc.ExecPath)
	fmt.Fprintf(&b, "  %s ix,\n", svc.ExecPath)
	fmt.Fprintln(&b)

	// Config — services typically need to read /etc/<service> at
	// startup. Conservative: a single read-only include for the
	// service's own config dir.
	configDir := defaultConfigDir(svc.Kind)
	if configDir != "" {
		fmt.Fprintf(&b, "  # Config\n")
		fmt.Fprintf(&b, "  %s/ r,\n", configDir)
		fmt.Fprintf(&b, "  %s/** r,\n", configDir)
		fmt.Fprintln(&b)
	}

	// Writes.
	if len(svc.Contract.WriteRoots) > 0 {
		fmt.Fprintf(&b, "  # Allowed writes (WriteRoots)\n")
		for _, w := range sortedCopy(svc.Contract.WriteRoots) {
			fmt.Fprintf(&b, "  %s/ rw,\n", w)
			fmt.Fprintf(&b, "  %s/** rwk,\n", w) // k = lock
		}
		fmt.Fprintln(&b)
	}

	// Reads — explicit reads beyond config (typical: /var/www/**).
	// AppArmor "@{HOME}" tunables are too broad; ask the operator
	// to declare via abstractions/include in their own profile if
	// they need it. Built-ins don't add anything here.

	// UNIX sockets.
	if len(svc.Contract.UnixSockets) > 0 {
		fmt.Fprintf(&b, "  # UNIX sockets\n")
		for _, s := range sortedCopy(svc.Contract.UnixSockets) {
			fmt.Fprintf(&b, "  %s rw,\n", s)
		}
		fmt.Fprintln(&b)
	}

	// Network. Web services need TCP + UDP (for DNS). UDP allows
	// resolver queries; restricting it further requires AppArmor
	// extended network rules + a recent kernel.
	fmt.Fprintf(&b, "  # Network\n")
	fmt.Fprintln(&b, `  network inet tcp,`)
	fmt.Fprintln(&b, `  network inet6 tcp,`)
	fmt.Fprintln(&b, `  network inet udp,`)
	fmt.Fprintln(&b, `  network inet6 udp,`)
	fmt.Fprintln(&b)

	// Capabilities — minimal set. setuid/setgid for worker drop;
	// net_bind_service for ports < 1024; kill for worker reload;
	// dac_override + chown for log/cache management.
	fmt.Fprintf(&b, "  # Capabilities\n")
	for _, c := range defaultCapabilities() {
		fmt.Fprintf(&b, "  capability %s,\n", c)
	}
	fmt.Fprintln(&b)

	// Denies — the heart of Ring 1. If deception.fake_exec is on,
	// the redirected exec paths (shell/interp/downloader/recon/priv)
	// are NOT denied here — bind-mounts route them to honey-sh and
	// AppArmor needs to allow the resolved path. See execroute pkg.
	if svc.Response.Deception.Enabled && svc.Response.Deception.FakeExec {
		fmt.Fprintf(&b, "  # Ring 2 redirect target (honey-sh) — profile transition\n")
		fmt.Fprintln(&b, "  /usr/lib/xhelix/honey-sh rPx -> xhelix.honeysh,")
		fmt.Fprintln(&b)
		// Allow exec on the bind-mounted targets so the redirect can
		// complete. The bind-mount makes /bin/sh literally be the
		// honey-sh inode; AppArmor matches on the requested path
		// string, so we need each redirected path to be ix or Px.
		fmt.Fprintf(&b, "  # Ring 2 redirected paths (bind-mount → honey-sh)\n")
		for _, p := range redirectedPaths() {
			fmt.Fprintf(&b, "  %s rPx -> xhelix.honeysh,\n", p)
		}
		fmt.Fprintln(&b)
	}

	denies := buildDenies(svc)
	if len(denies) > 0 {
		fmt.Fprintf(&b, "  # Ring 1 denials (PROTECTED_SERVICES_TRAP.md §5.4)\n")
		for _, line := range denies {
			fmt.Fprintf(&b, "  %s\n", line)
		}
		fmt.Fprintln(&b)
	}

	// Deny memory primitives via /proc and /sys paths the kernel
	// exposes. AppArmor doesn't have a syscall-level "deny ptrace"
	// (that's seccomp), but we CAN block the read/write surfaces
	// attackers use to read memory or escalate.
	fmt.Fprintf(&b, "  # Memory & EDR surfaces\n")
	for _, line := range memorySurfaceDenies() {
		fmt.Fprintf(&b, "  %s\n", line)
	}
	fmt.Fprintln(&b)

	// AllowExecPaths — operator declared helpers (legitimate).
	if len(svc.Contract.AllowExecPaths) > 0 {
		fmt.Fprintf(&b, "  # Operator-declared legitimate execs\n")
		for _, p := range sortedCopy(svc.Contract.AllowExecPaths) {
			fmt.Fprintf(&b, "  %s ix,\n", p)
		}
		fmt.Fprintln(&b)
	}

	// ReadSensitiveRoots — operator-declared no-read zones.
	if len(svc.Contract.ReadSensitiveRoots) > 0 {
		fmt.Fprintf(&b, "  # Operator-declared no-read zones\n")
		for _, r := range sortedCopy(svc.Contract.ReadSensitiveRoots) {
			fmt.Fprintf(&b, "  deny %s/** r,\n", r)
		}
		fmt.Fprintln(&b)
	}

	fmt.Fprintln(&b, "}")

	return Profile{
		Name: name,
		Body: b.String(),
	}, nil
}

// ProfileName returns the canonical AppArmor profile name for a
// service. Exported so callers can compute names without rendering.
func ProfileName(svc string) string {
	return ProfileNamePrefix + "." + sanitize(svc)
}

// --- internals ---

// redirectedPaths returns NeverLearnableExec entries that get
// bind-mounted to honey-sh under deception mode. Same paths the
// execroute package generates BindReadOnlyPaths for. Keep the two
// in sync.
func redirectedPaths() []string {
	out := make([]string, 0, len(contracts.NeverLearnableExec))
	for _, p := range contracts.NeverLearnableExec {
		switch contracts.ClassifyExecAttempt(p) {
		case "shell_attempt", "interp_attempt", "downloader",
			"recon_tool", "priv_tool":
			out = append(out, p)
		}
	}
	return out
}

// buildDenies returns the deny lines: NeverLearnable execs + any
// operator-supplied DenyExecPaths (already unioned by contracts.Merge).
//
// When deception.fake_exec is enabled, the redirected exec
// categories (shell/interp/downloader/recon/priv) are EXCLUDED —
// the bind-mount + Px transition handles them. The deny list still
// catches operator-declared customs + the non-redirected staging
// tools (base64/xxd/openssl).
func buildDenies(svc *protectedsvc.ProtectedService) []string {
	redirected := map[string]struct{}{}
	if svc.Response.Deception.Enabled && svc.Response.Deception.FakeExec {
		for _, p := range redirectedPaths() {
			redirected[p] = struct{}{}
		}
	}

	// Use a set to absorb duplicates between built-in + override.
	set := map[string]struct{}{}
	for _, p := range contracts.NeverLearnableExec {
		if _, skip := redirected[p]; skip {
			continue
		}
		set[p] = struct{}{}
	}
	for _, p := range svc.Contract.DenyExecPaths {
		if _, skip := redirected[p]; skip {
			continue
		}
		set[p] = struct{}{}
	}

	paths := make([]string, 0, len(set))
	for p := range set {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	out := make([]string, 0, len(paths)+5)
	for _, p := range paths {
		// "x" denies exec; "m" denies mmap'd exec (loader path).
		out = append(out, fmt.Sprintf("deny %s xm,", p))
	}

	// StrictReadOnly: deny writes outside WriteRoots. AppArmor handles
	// this by simply NOT granting write — we don't need an explicit
	// deny since AppArmor is default-deny. Keep this comment for
	// operators reading the profile.
	if svc.Contract.StrictReadOnly {
		out = append(out, "# strict_read_only: AppArmor is default-deny — writes are limited to WriteRoots above.")
	}

	return out
}

// memorySurfaceDenies blocks the kernel surfaces attackers use to
// read process memory, tamper with EDR, or escalate. Complements
// the seccomp deny on ptrace/userfaultfd/bpf/perf_event_open.
func memorySurfaceDenies() []string {
	return []string{
		"deny /proc/*/mem rw,",          // /proc/PID/mem — direct memory access
		"deny /proc/*/maps w,",          // can't tamper with own mapping
		"deny /proc/sys/kernel/** w,",   // sysctl writes
		"deny /sys/kernel/security/** rw,", // LSM tampering
		"deny /sys/module/** rw,",       // module surface
		"deny /sys/fs/cgroup/** w,",     // cgroup escape
		"deny mount,",                   // explicit (seccomp also blocks)
		"deny umount,",
		"deny remount,",
		"deny pivot_root,",
	}
}

// defaultCapabilities returns the minimal cap set web services need.
// AppArmor "capability X," allows the named capability; absence is
// implicit deny.
//
// We deliberately DO NOT grant: sys_admin, sys_ptrace, sys_module,
// sys_rawio, net_admin, sys_chroot — these are the escape-hatch
// caps used by exploit chains.
func defaultCapabilities() []string {
	return []string{
		"setuid",
		"setgid",
		"net_bind_service",
		"kill",
		"dac_override",
		"dac_read_search",
		"chown",
		"fsetid",
		"fowner",
		"sys_resource",
	}
}

func defaultConfigDir(kind protectedsvc.ServiceKind) string {
	switch kind {
	case protectedsvc.KindNginx:
		return "/etc/nginx"
	case protectedsvc.KindApache:
		return "/etc/apache2" // Debian/Ubuntu; RHEL is /etc/httpd
	}
	return ""
}

func sortedCopy(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	return out
}

// sanitize keeps the profile name safe for the AppArmor parser.
// Replaces anything outside [A-Za-z0-9._-] with '_'.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// Package execroute installs the "exec → honey-sh" redirect for
// protected services. Despite the design sketch in
// PROTECTED_SERVICES_TRAP.md §4.1 saying "bpf_override_return", the
// actual kernel facility for replacing the binary an execve resolves
// to is simpler: a bind-mount inside the service's private mount
// namespace.
//
// systemd's BindReadOnlyPaths= directive sets up the bind-mount
// when the unit starts, scoped to that unit's mount namespace
// (PrivateMounts=yes). The host's /bin/sh stays untouched; only
// processes inside nginx.service see honey-sh when they execve
// /bin/sh. This is robust, kernel-version-independent, and doesn't
// need CONFIG_BPF_KPROBE_OVERRIDE.
//
// bpf_override_return remains useful for other Ring-2 features
// (sinkhole socket via socket_connect, fake-success on writes via
// inode_permission) where the verb is "make this syscall appear to
// succeed". Exec redirect doesn't need it — bind-mount is the
// right tool.
//
// See PROTECTED_SERVICES_TRAP.md §4.1.
package execroute

import (
	"fmt"
	"sort"
	"strings"

	"github.com/xhelix/xhelix/pkg/profiles/contracts"
	"github.com/xhelix/xhelix/pkg/protectedsvc"
)

// DefaultHoneyShPath is where the deb/rpm packaging installs the
// xhelix-honeysh binary. The bind-mount source.
const DefaultHoneyShPath = "/usr/lib/xhelix/honey-sh"

// SystemdDropIn is the body of a systemd unit drop-in file
// (typically /etc/systemd/system/<unit>.d/xhelix-deception.conf).
// Operators install it, then `systemctl daemon-reload && systemctl
// restart <unit>` activates the redirect.
type SystemdDropIn struct {
	// UnitName is the unit this drop-in applies to (e.g. "nginx.service").
	UnitName string
	// Path is the on-disk location once installed (typically under
	// /etc/systemd/system/<unit>.d/).
	Path string
	// Body is the full file contents — ready to write.
	Body string
	// Mounts is the parsed list of bind-mounts the drop-in declares.
	Mounts []BindMount
}

// BindMount is one source→target pair.
type BindMount struct {
	Source string // existing path on host (e.g. /usr/lib/xhelix/honey-sh)
	Target string // path inside the unit's mount namespace (e.g. /bin/sh)
}

// Options tune which paths get redirected. Zero value means
// "redirect everything in contracts.NeverLearnableExec to honey-sh".
type Options struct {
	// HoneyShPath overrides DefaultHoneyShPath.
	HoneyShPath string
	// RedirectShells, RedirectInterpreters, RedirectDownloaders,
	// RedirectReconTools, RedirectPrivTools — toggles per category.
	// All default to true via AllRedirects().
	RedirectShells       bool
	RedirectInterpreters bool
	RedirectDownloaders  bool
	RedirectReconTools   bool
	RedirectPrivTools    bool

	// ExtraTargets are extra paths to bind-mount onto honey-sh.
	// Operator-declared (e.g. /opt/legacy/expect).
	ExtraTargets []string

	// DropInDir is the parent dir for the generated drop-in.
	// Defaults to /etc/systemd/system/<unit>.d.
	DropInDir string
	// FileName for the drop-in (default "xhelix-deception.conf").
	FileName string
}

// AllRedirects returns Options with every category enabled — the
// production default.
func AllRedirects() Options {
	return Options{
		HoneyShPath:          DefaultHoneyShPath,
		RedirectShells:       true,
		RedirectInterpreters: true,
		RedirectDownloaders:  true,
		RedirectReconTools:   true,
		RedirectPrivTools:    true,
	}
}

func (o Options) defaulted() Options {
	d := o
	if d.HoneyShPath == "" {
		d.HoneyShPath = DefaultHoneyShPath
	}
	if d.FileName == "" {
		d.FileName = "xhelix-deception.conf"
	}
	return d
}

// GenerateDropIn builds the systemd drop-in for the given service.
// Returns ErrNoDeception if the service's contract has
// Response.Deception.FakeExec=false (deception disabled — refuse-
// only mode, no redirect needed).
func GenerateDropIn(svc *protectedsvc.ProtectedService, opts Options) (SystemdDropIn, error) {
	if svc == nil {
		return SystemdDropIn{}, fmt.Errorf("execroute: nil service")
	}
	if svc.Unit == "" {
		return SystemdDropIn{}, fmt.Errorf("execroute %q: service has no Unit", svc.Name)
	}
	if !svc.Response.Deception.Enabled || !svc.Response.Deception.FakeExec {
		return SystemdDropIn{}, ErrNoDeception
	}

	opts = opts.defaulted()
	mounts := computeMounts(opts)
	if len(mounts) == 0 {
		return SystemdDropIn{}, fmt.Errorf("execroute %q: no paths to redirect", svc.Name)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# xhelix Protected Services — exec redirect (P-PS.6b)\n")
	fmt.Fprintf(&b, "# Service: %s (kind=%s role=%s)\n", svc.Name, svc.Kind, svc.Role)
	fmt.Fprintf(&b, "# Generated. DO NOT EDIT — re-run xhelixctl protect install.\n\n")
	fmt.Fprintln(&b, "[Service]")
	// PrivateMounts=yes scopes the BindReadOnlyPaths to this unit's
	// mount namespace — host /bin/sh is untouched.
	fmt.Fprintln(&b, "PrivateMounts=yes")
	for _, m := range mounts {
		// BindReadOnlyPaths=<source>:<target>:<options>
		// "norbind" — no recursive bind (we're mounting a single file).
		fmt.Fprintf(&b, "BindReadOnlyPaths=%s:%s:norbind\n", m.Source, m.Target)
	}

	dir := opts.DropInDir
	if dir == "" {
		dir = "/etc/systemd/system/" + svc.Unit + ".d"
	}

	return SystemdDropIn{
		UnitName: svc.Unit,
		Path:     dir + "/" + opts.FileName,
		Body:     b.String(),
		Mounts:   mounts,
	}, nil
}

// ErrNoDeception is returned when the service has deception disabled.
var ErrNoDeception = fmt.Errorf("execroute: deception is disabled for this service")

// computeMounts walks NeverLearnableExec + ExtraTargets and decides
// which to redirect based on opts. Returns sorted, deduped mounts.
func computeMounts(opts Options) []BindMount {
	seen := map[string]struct{}{}
	var out []BindMount
	add := func(target string) {
		if _, dup := seen[target]; dup {
			return
		}
		seen[target] = struct{}{}
		out = append(out, BindMount{Source: opts.HoneyShPath, Target: target})
	}

	for _, p := range contracts.NeverLearnableExec {
		switch category(p) {
		case "shell":
			if opts.RedirectShells {
				add(p)
			}
		case "interp":
			if opts.RedirectInterpreters {
				add(p)
			}
		case "downloader":
			if opts.RedirectDownloaders {
				add(p)
			}
		case "recon":
			if opts.RedirectReconTools {
				add(p)
			}
		case "priv":
			if opts.RedirectPrivTools {
				add(p)
			}
		}
	}
	for _, p := range opts.ExtraTargets {
		add(p)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out
}

// category classifies a NeverLearnableExec path by basename so we
// can toggle each group independently.
func category(path string) string {
	base := path
	if i := strings.LastIndex(path, "/"); i >= 0 {
		base = path[i+1:]
	}
	switch contracts.ClassifyExecAttempt(path) {
	case "shell_attempt":
		return "shell"
	case "interp_attempt":
		return "interp"
	case "downloader":
		return "downloader"
	case "recon_tool":
		return "recon"
	case "priv_tool":
		return "priv"
	}
	// base64/xxd/openssl etc — staging tools. Treat as "downloader"
	// category so they're redirected with the same toggle.
	switch base {
	case "base64", "xxd", "openssl":
		return "downloader"
	}
	return ""
}

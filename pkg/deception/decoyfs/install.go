package decoyfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/xhelix/xhelix/pkg/deception/execroute"
	"github.com/xhelix/xhelix/pkg/protectedsvc"
)

// DefaultDecoyDir is where decoy files live on disk. Bind-mounts
// point into here from each protected service's namespace.
const DefaultDecoyDir = "/var/lib/xhelix/decoys"

// File is one decoy file on disk: source path (where bytes live) +
// target path (where it'll be bind-mounted in the service mount ns).
type File struct {
	Source string // /var/lib/xhelix/decoys/shadow
	Target string // /etc/shadow
	Mode   os.FileMode
}

// InstallOpts tunes Install().
type InstallOpts struct {
	Dir string // override DefaultDecoyDir
}

// Install writes the Set's files to disk and returns the list of
// (Source, Target) pairs the systemd drop-in should bind-mount.
// Idempotent: re-writing a decoy with identical content is a no-op.
func Install(s Set, opts InstallOpts) ([]File, error) {
	dir := opts.Dir
	if dir == "" {
		dir = DefaultDecoyDir
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("decoyfs: mkdir %s: %w", dir, err)
	}

	files := layout(s, dir)
	for _, f := range files {
		if f.Source == "" {
			continue
		}
		if err := writeIfChanged(f.Source, []byte(contentFor(f.Target, s)), f.Mode); err != nil {
			return nil, err
		}
	}

	// Drop entries with no source content.
	out := make([]File, 0, len(files))
	for _, f := range files {
		if f.Source != "" {
			out = append(out, f)
		}
	}
	return out, nil
}

// layout returns the canonical (source, target) mapping. Source
// paths include the per-user honey username so we don't have to
// re-render content per protected service — the same file backs
// every service's bind-mount.
func layout(s Set, dir string) []File {
	homeDir := "/home/" + s.HoneyUser
	return []File{
		{Source: filepath.Join(dir, "shadow"), Target: "/etc/shadow", Mode: 0o640},
		{Source: filepath.Join(dir, "passwd"), Target: "/etc/passwd", Mode: 0o644},
		{Source: filepath.Join(dir, "sudoers"), Target: "/etc/sudoers", Mode: 0o440},
		{Source: filepath.Join(dir, "ssh-id_rsa"), Target: homeDir + "/.ssh/id_rsa", Mode: 0o600},
		{Source: filepath.Join(dir, "ssh-id_rsa.pub"), Target: homeDir + "/.ssh/id_rsa.pub", Mode: 0o644},
		{Source: filepath.Join(dir, "aws-credentials"), Target: homeDir + "/.aws/credentials", Mode: 0o600},
		{Source: filepath.Join(dir, "gcp-application_default_credentials.json"), Target: homeDir + "/.config/gcloud/application_default_credentials.json", Mode: 0o600},
		{Source: filepath.Join(dir, "kube-config"), Target: homeDir + "/.kube/config", Mode: 0o600},
		{Source: filepath.Join(dir, "docker-config.json"), Target: homeDir + "/.docker/config.json", Mode: 0o600},
		// P-PS.19 borrows from IDE Shepherd's cred-path catalog:
		{Source: filepath.Join(dir, "netrc"), Target: homeDir + "/.netrc", Mode: 0o600},
		{Source: filepath.Join(dir, "git-credentials"), Target: homeDir + "/.git-credentials", Mode: 0o600},
		{Source: filepath.Join(dir, "bash_history"), Target: homeDir + "/.bash_history", Mode: 0o600},
		{Source: filepath.Join(dir, "zsh_history"), Target: homeDir + "/.zsh_history", Mode: 0o600},
		{Source: filepath.Join(dir, "gnupg-secring.gpg"), Target: homeDir + "/.gnupg/secring.gpg", Mode: 0o600},
	}
}

func contentFor(target string, s Set) string {
	switch {
	case target == "/etc/shadow":
		return s.Shadow
	case target == "/etc/passwd":
		return s.Passwd
	case target == "/etc/sudoers":
		return s.Sudoers
	case strings.HasSuffix(target, "/.ssh/id_rsa"):
		return s.SSHKey
	case strings.HasSuffix(target, "/.ssh/id_rsa.pub"):
		return s.SSHPubKey
	case strings.HasSuffix(target, "/.aws/credentials"):
		return s.AWSCreds
	case strings.HasSuffix(target, "/application_default_credentials.json"):
		return s.GCPCreds
	case strings.HasSuffix(target, "/.kube/config"):
		return s.KubeConfig
	case strings.HasSuffix(target, "/.docker/config.json"):
		return s.DockerCfg
	case strings.HasSuffix(target, "/.netrc"):
		return s.Netrc
	case strings.HasSuffix(target, "/.git-credentials"):
		return s.GitCreds
	case strings.HasSuffix(target, "/.bash_history"):
		return s.BashHistory
	case strings.HasSuffix(target, "/.zsh_history"):
		return s.ZshHistory
	case strings.HasSuffix(target, "/secring.gpg"):
		return s.GPGSecKey
	}
	return ""
}

func writeIfChanged(path string, body []byte, mode os.FileMode) error {
	if existing, err := os.ReadFile(path); err == nil {
		if len(existing) == len(body) && string(existing) == string(body) {
			return nil // idempotent — no change
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, mode); err != nil {
		return fmt.Errorf("decoyfs: write %s: %w", tmp, err)
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("decoyfs: chmod %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("decoyfs: rename %s → %s: %w", tmp, path, err)
	}
	return nil
}

// MountSpec converts the installed File list into execroute.BindMount
// records that the systemd drop-in generator consumes. Use this to
// extend the per-service drop-in with decoy bind-mounts on top of
// the honey-sh redirects.
func MountSpec(files []File) []execroute.BindMount {
	mounts := make([]execroute.BindMount, 0, len(files))
	for _, f := range files {
		mounts = append(mounts, execroute.BindMount{
			Source: f.Source,
			Target: f.Target,
		})
	}
	sort.Slice(mounts, func(i, j int) bool { return mounts[i].Target < mounts[j].Target })
	return mounts
}

// MergeIntoDropIn appends decoy bind-mounts to the body of an
// existing execroute.SystemdDropIn. Idempotent: if a target is
// already mounted, it's not added again. Returns the updated copy.
func MergeIntoDropIn(d execroute.SystemdDropIn, files []File) (execroute.SystemdDropIn, error) {
	if d.UnitName == "" {
		return d, errors.New("decoyfs: drop-in has no UnitName")
	}
	seen := map[string]struct{}{}
	for _, m := range d.Mounts {
		seen[m.Target] = struct{}{}
	}

	var add []execroute.BindMount
	for _, m := range MountSpec(files) {
		if _, dup := seen[m.Target]; dup {
			continue
		}
		add = append(add, m)
		d.Mounts = append(d.Mounts, m)
	}
	if len(add) == 0 {
		return d, nil
	}

	// Append fresh bind-mount lines to the body. The drop-in already
	// has PrivateMounts=yes in the [Service] section from execroute.
	var b strings.Builder
	b.WriteString(d.Body)
	if !strings.HasSuffix(d.Body, "\n") {
		b.WriteString("\n")
	}
	b.WriteString("# decoyfs bind-mounts (PROTECTED_SERVICES_TRAP.md §4.3)\n")
	for _, m := range add {
		fmt.Fprintf(&b, "BindReadOnlyPaths=%s:%s:norbind\n", m.Source, m.Target)
	}
	d.Body = b.String()
	return d, nil
}

// AttachToService is the all-in-one helper: ensure decoys are
// installed, then extend a service's existing execroute drop-in
// with the decoy bind-mounts. Operator wrapper around
// Install + MergeIntoDropIn.
func AttachToService(svc *protectedsvc.ProtectedService, set Set, dropIn execroute.SystemdDropIn, opts InstallOpts) (execroute.SystemdDropIn, []File, error) {
	if svc == nil {
		return dropIn, nil, errors.New("decoyfs: nil service")
	}
	if !svc.Response.Deception.Enabled || !svc.Response.Deception.DecoyFS {
		return dropIn, nil, nil // deception off — no-op
	}
	files, err := Install(set, opts)
	if err != nil {
		return dropIn, nil, err
	}
	merged, err := MergeIntoDropIn(dropIn, files)
	if err != nil {
		return dropIn, files, err
	}
	return merged, files, nil
}

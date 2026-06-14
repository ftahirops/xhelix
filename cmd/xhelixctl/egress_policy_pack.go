// Pre-built per-app policy pack — Week 6.
//
// Ten hand-crafted policy templates bundled into the binary via
// //go:embed. The `pack list` command shows what's available; the
// `pack install` command signs the embedded YAML with the operator's
// key, optionally lets the operator edit it first, and writes the
// SignedPolicy to /etc/xhelix/policies/.
//
// Every bundled profile ships in mode: observe so installing it
// can never break the host's egress. Operator opts into enforcement
// explicitly with `xhelixctl egress policy enforce <binary>`.
package main

import (
	"embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/xhelix/xhelix/pkg/egresspolicy"
)

// execEditor runs the editor command (which may be "vi", "/usr/bin/nano",
// or a shell-style "code --wait") against the given file. Stdin/out/err
// are inherited so interactive TUIs work.
func execEditor(editor, path string) error {
	parts := strings.Fields(editor)
	if len(parts) == 0 {
		return fmt.Errorf("empty editor command")
	}
	cmd := exec.Command(parts[0], append(parts[1:], path)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

//go:embed policy_pack/*.yaml
var policyPackFS embed.FS

// packEntry is one item in the bundled profile list.
type packEntry struct {
	Name        string // file basename without .yaml (e.g. "nginx-reverse-proxy")
	Binary      string // sanitised binary identifier (e.g. "nginx")
	Mode        string
	Description string
	YAML        string // raw embedded YAML
}

// loadPackEntries reads + parses every embedded YAML once.
func loadPackEntries() ([]packEntry, error) {
	files, err := policyPackFS.ReadDir("policy_pack")
	if err != nil {
		return nil, err
	}
	out := make([]packEntry, 0, len(files))
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".yaml") {
			continue
		}
		body, err := policyPackFS.ReadFile("policy_pack/" + f.Name())
		if err != nil {
			return nil, err
		}
		var pol egresspolicy.Policy
		if err := yaml.Unmarshal(body, &pol); err != nil {
			return nil, fmt.Errorf("parse embedded %s: %w", f.Name(), err)
		}
		out = append(out, packEntry{
			Name:        strings.TrimSuffix(f.Name(), ".yaml"),
			Binary:      pol.Binary,
			Mode:        string(pol.Mode),
			Description: pol.Comment,
			YAML:        string(body),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// findPackEntry returns the entry matching either the profile name
// (e.g. "nginx-reverse-proxy") or the binary it targets (e.g.
// "nginx"). Returns nil if no match.
func findPackEntry(entries []packEntry, key string) *packEntry {
	key = strings.ToLower(strings.TrimSpace(key))
	for i := range entries {
		if strings.ToLower(entries[i].Name) == key || strings.ToLower(entries[i].Binary) == key {
			return &entries[i]
		}
	}
	return nil
}

func init() {
	prev := extendEgressCmd
	extendEgressCmd = chainExtenders(prev, func(cmd *cobra.Command) {
		// Reach into the already-attached `policy` subtree (added by
		// egress_policy.go via the same extender chain) and append our
		// `pack` group. The policy command was added via cmd.AddCommand
		// in the previous extender; find it back so we can attach to it.
		for _, c := range cmd.Commands() {
			if c.Name() == "policy" {
				c.AddCommand(newEgressPolicyPackCmd())
				return
			}
		}
		// Fallback: attach at the top of `egress` so the feature is
		// reachable even if the ordering ever flips.
		cmd.AddCommand(newEgressPolicyPackCmd())
	})
}

func newEgressPolicyPackCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pack",
		Short: "Pre-built per-app policy templates (signed + installed locally)",
		Long: `The policy pack bundles hand-crafted templates for the common
application shapes: nginx, mysql, postgres, redis, php-fpm, postfix,
tor, sshd, node, apt. Every template ships in mode: observe so
installing one cannot break the host. Bump to deny_default later
with 'xhelixctl egress policy enforce <binary>'.`,
	}
	cmd.AddCommand(newPolicyPackListCmd())
	cmd.AddCommand(newPolicyPackShowCmd())
	cmd.AddCommand(newPolicyPackInstallCmd())
	return cmd
}

func newPolicyPackListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List bundled per-app policy templates",
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := loadPackEntries()
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tBINARY\tMODE\tDESCRIPTION")
			for _, e := range entries {
				desc := e.Description
				if len(desc) > 64 {
					desc = desc[:61] + "…"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.Name, e.Binary, e.Mode, desc)
			}
			tw.Flush()
			fmt.Println()
			fmt.Println("Install with: xhelixctl egress policy pack install <name> --signer X --key /path/to/operator.key")
			return nil
		},
	}
}

func newPolicyPackShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name-or-binary>",
		Short: "Print one bundled template's raw YAML",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := loadPackEntries()
			if err != nil {
				return err
			}
			e := findPackEntry(entries, args[0])
			if e == nil {
				return fmt.Errorf("no bundled template matches %q (run `pack list`)", args[0])
			}
			_, _ = os.Stdout.WriteString(e.YAML)
			return nil
		},
	}
}

func newPolicyPackInstallCmd() *cobra.Command {
	var keyPath, signer, outDir, editor string
	var edit bool
	cmd := &cobra.Command{
		Use:   "install <name-or-binary>",
		Short: "Sign + install a bundled per-app template",
		Long: `Reads the bundled YAML for <name-or-binary>, optionally lets you
edit it before signing (with --edit), signs with --key, and writes
the SignedPolicy under --out-dir. The daemon polls the policy
directory every 30s and will pick it up automatically.

Default --out-dir is the same /etc/xhelix/policies directory the
daemon loads from. The installed template ships in mode: observe;
use 'xhelixctl egress policy enforce <binary>' to bump it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if signer == "" {
				return fmt.Errorf("--signer is required")
			}
			if keyPath == "" {
				return fmt.Errorf("--key is required")
			}
			entries, err := loadPackEntries()
			if err != nil {
				return err
			}
			e := findPackEntry(entries, args[0])
			if e == nil {
				return fmt.Errorf("no bundled template matches %q (run `pack list`)", args[0])
			}
			yamlBody := e.YAML
			if edit {
				edited, err := launchEditor(editor, e.Name+"-*.yaml", []byte(yamlBody))
				if err != nil {
					return fmt.Errorf("edit: %w", err)
				}
				yamlBody = string(edited)
			}
			var pol egresspolicy.Policy
			if err := yaml.Unmarshal([]byte(yamlBody), &pol); err != nil {
				return fmt.Errorf("parse policy: %w", err)
			}
			// Note: full Policy.Validate() requires Signer, which Sign()
			// sets for us. We do basic sanity here.
			if pol.Binary == "" {
				return fmt.Errorf("template missing binary field")
			}
			priv, err := readPrivKey(keyPath)
			if err != nil {
				return fmt.Errorf("read private key: %w", err)
			}
			sp, err := egresspolicy.Sign(pol, signer, priv)
			if err != nil {
				return fmt.Errorf("sign: %w", err)
			}
			signed, err := yaml.Marshal(sp)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return fmt.Errorf("mkdir %s: %w", outDir, err)
			}
			outPath := filepath.Join(outDir, sanitizeBinary(pol.Binary)+".yaml")
			if err := os.WriteFile(outPath, signed, 0o644); err != nil {
				return fmt.Errorf("write %s: %w", outPath, err)
			}
			fmt.Printf("installed %s (mode=%s) → %s\n", e.Name, pol.Mode, outPath)
			fmt.Println("daemon will pick this up within 30s. To enforce: xhelixctl egress policy enforce", pol.Binary, "--signer", signer, "--key", keyPath)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "path to ed25519 private key (required)")
	cmd.Flags().StringVar(&signer, "signer", "", "signer identity (required)")
	cmd.Flags().StringVar(&outDir, "out-dir", defaultPolicyDir, "policy directory to write into")
	cmd.Flags().BoolVar(&edit, "edit", false, "open the template in $EDITOR before signing")
	cmd.Flags().StringVar(&editor, "editor", "", "editor to invoke when --edit is set (default $EDITOR or vi)")
	return cmd
}

// sanitizeBinary mirrors the daemon's file-naming for policy YAMLs:
// lowercase + only [a-z0-9_-], replacing everything else with '_'.
// Matches what the daemon's store globs for at load time.
func sanitizeBinary(b string) string {
	b = strings.ToLower(b)
	var out strings.Builder
	for _, r := range b {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			out.WriteRune(r)
		default:
			out.WriteRune('_')
		}
	}
	if out.Len() == 0 {
		return "binary"
	}
	return out.String()
}

// launchEditor writes body to a tempfile, exec's the editor, and
// returns the file's content after the editor exits. Falls back to
// $EDITOR / vi when --editor isn't set. If the editor can't be
// found or exits non-zero, returns the original body so the install
// path keeps moving forward (operator can re-run with --edit later).
func launchEditor(prefer, namePattern string, body []byte) ([]byte, error) {
	tmp, err := os.CreateTemp("", namePattern)
	if err != nil {
		return body, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return body, err
	}
	tmp.Close()
	cmd := pickEditor(prefer)
	if cmd == "" {
		return body, fmt.Errorf("no editor available (set --editor or $EDITOR)")
	}
	if err := execEditor(cmd, tmp.Name()); err != nil {
		return body, err
	}
	return os.ReadFile(tmp.Name())
}

func pickEditor(prefer string) string {
	if prefer != "" {
		return prefer
	}
	if e := os.Getenv("EDITOR"); e != "" {
		return e
	}
	return "vi"
}

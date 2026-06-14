// Egress policy operator surface — Week 3.
//
// Read-only commands plus keygen. The observe → sign workflow (turning
// a binary's observed-flow history into a draft Policy that the
// operator then reviews + signs) is a Week 4 deliverable; that command
// will live next to these.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/xhelix/xhelix/pkg/egresspolicy"
	"github.com/xhelix/xhelix/pkg/localapi"
)

// decodeKey accepts an ed25519 key as hex or base64. Whitespace and a
// trailing newline are tolerated; an "ed25519:" prefix is stripped.
// Returns nil on no successful decode.
func decodeKey(raw []byte) []byte {
	s := strings.TrimSpace(string(raw))
	s = strings.TrimPrefix(s, "ed25519:")
	if b, err := hex.DecodeString(s); err == nil {
		return b
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b
	}
	return nil
}

const defaultPolicyDir = "/etc/xhelix/policies"

func init() {
	prev := extendEgressCmd
	extendEgressCmd = chainExtenders(prev, func(cmd *cobra.Command) {
		cmd.AddCommand(newEgressPolicyCmd())
	})
}

func newEgressPolicyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Per-binary signed egress policies (read + keygen)",
		Long: `Inspect signed Ed25519-protected egress policies loaded by the
daemon from ` + defaultPolicyDir + `/. Each binary may have one
<sanitized-binary>.yaml file; the daemon loads them at startup and
rescans every 30s.

Default mode is OBSERVE for any binary without a signed policy: every
connect is recorded, no action is taken. Operators sign stricter
policies (allow_any, deny_default, tor_only) once they're confident
the binary's observed traffic is the intended traffic. The
observe → sign workflow ships in Week 4; this command set is
intentionally read-only + keygen for now.`,
	}
	cmd.AddCommand(newEgressPolicyListCmd())
	cmd.AddCommand(newEgressPolicyShowCmd())
	cmd.AddCommand(newEgressPolicyReloadCmd())
	cmd.AddCommand(newEgressPolicyKeygenCmd())
	cmd.AddCommand(newEgressPolicyProposeCmd())
	cmd.AddCommand(newEgressPolicySignCmd())
	cmd.AddCommand(newEgressPolicyInstallCmd())
	cmd.AddCommand(newEgressPolicyEnforceCmd())
	cmd.AddCommand(newEgressPolicyObserveCmd())
	cmd.AddCommand(newEgressPolicyRevertCmd())
	return cmd
}

func newEgressPolicyListCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List signed policies loaded from the policy directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			pubPath := filepath.Join(dir, "operator.pub")
			pub, err := readPubKey(pubPath)
			if err != nil {
				return fmt.Errorf("read public key %s: %w", pubPath, err)
			}
			store, err := egresspolicy.NewStore(dir, pub)
			if err != nil {
				return fmt.Errorf("open store: %w", err)
			}
			n, rerr := store.Reload()
			if rerr != nil {
				fmt.Fprintf(os.Stderr, "warning: %v\n", rerr)
			}
			policies := store.All()
			if len(policies) == 0 {
				fmt.Printf("(no signed policies loaded from %s; %d files attempted)\n", dir, n)
				return nil
			}
			sort.Slice(policies, func(i, j int) bool {
				return policies[i].Policy.Binary < policies[j].Policy.Binary
			})
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "BINARY\tMODE\tALLOW\tDENY\tSIGNER\tSIGNED_AT")
			for _, sp := range policies {
				p := sp.Policy
				fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\t%s\n",
					p.Binary, p.Mode, len(p.Allow), len(p.Deny),
					p.Signer, p.SignedAt.Format("2006-01-02T15:04:05Z"))
			}
			tw.Flush()
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", defaultPolicyDir, "policy directory")
	return cmd
}

func newEgressPolicyShowCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "show <binary>",
		Short: "Show one signed policy as YAML",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pubPath := filepath.Join(dir, "operator.pub")
			pub, err := readPubKey(pubPath)
			if err != nil {
				return fmt.Errorf("read public key %s: %w", pubPath, err)
			}
			store, err := egresspolicy.NewStore(dir, pub)
			if err != nil {
				return err
			}
			if _, rerr := store.Reload(); rerr != nil {
				fmt.Fprintf(os.Stderr, "warning: %v\n", rerr)
			}
			sp := store.Get(args[0])
			if sp == nil {
				return fmt.Errorf("no signed policy for %q in %s", args[0], dir)
			}
			data, err := yaml.Marshal(sp)
			if err != nil {
				return err
			}
			_, _ = os.Stdout.Write(data)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", defaultPolicyDir, "policy directory")
	return cmd
}

func newEgressPolicyReloadCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "reload",
		Short: "Force re-scan of the policy directory (local validation)",
		Long: `Re-loads every <binary>.yaml file in the policy directory and
re-verifies its Ed25519 signature against operator.pub. Reports the
count loaded + the first parse / verify error encountered, if any.

NOTE: this command performs a local re-scan only — it does NOT signal
the running daemon. The daemon polls the same directory every 30s
and will pick up changes automatically. A future Week-4 command will
add a daemon-side "reload now" RPC.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			pubPath := filepath.Join(dir, "operator.pub")
			pub, err := readPubKey(pubPath)
			if err != nil {
				return fmt.Errorf("read public key %s: %w", pubPath, err)
			}
			store, err := egresspolicy.NewStore(dir, pub)
			if err != nil {
				return err
			}
			n, rerr := store.Reload()
			fmt.Printf("loaded %d signed polic(ies) from %s\n", n, dir)
			if rerr != nil {
				return rerr
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", defaultPolicyDir, "policy directory")
	return cmd
}

func newEgressPolicyKeygenCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "keygen <out-dir>",
		Short: "Generate an Ed25519 operator keypair for signing policies",
		Args:  cobra.ExactArgs(1),
		Long: `Generates a fresh Ed25519 keypair and writes:

  <out-dir>/operator.pub  — public key (hex), 0644
  <out-dir>/operator.key  — private key (hex), 0600

The daemon expects operator.pub to exist at ` + defaultPolicyDir + `
to enable the policy engine. Keep operator.key off the production
host once policies have been signed — the daemon never reads it.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			outDir := args[0]
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return fmt.Errorf("mkdir %s: %w", outDir, err)
			}
			pubPath := filepath.Join(outDir, "operator.pub")
			keyPath := filepath.Join(outDir, "operator.key")
			if !force {
				for _, p := range []string{pubPath, keyPath} {
					if _, err := os.Stat(p); err == nil {
						return fmt.Errorf("%s already exists (use --force to overwrite)", p)
					}
				}
			}
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return fmt.Errorf("generate: %w", err)
			}
			if err := os.WriteFile(pubPath, []byte(hex.EncodeToString(pub)+"\n"), 0o644); err != nil {
				return fmt.Errorf("write %s: %w", pubPath, err)
			}
			if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(priv)+"\n"), 0o600); err != nil {
				return fmt.Errorf("write %s: %w", keyPath, err)
			}
			fmt.Printf("wrote %s (public) and %s (private)\n", pubPath, keyPath)
			fmt.Printf("public key (hex): %s\n", hex.EncodeToString(pub))
			fmt.Println()
			fmt.Println("Next steps:")
			fmt.Printf("  sudo install -m 0644 %s %s/operator.pub\n", pubPath, defaultPolicyDir)
			fmt.Println("  # then sign policies with operator.key on an offline workstation")
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing files")
	return cmd
}

// readPubKey reads an Ed25519 public key from disk, accepting hex or
// base64. Mirrors the daemon's tryDecodeKey loader so what the CLI
// can verify, the daemon can verify.
func readPubKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := decodeKey(raw)
	if len(dec) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("not a valid ed25519 public key (decoded len=%d, want %d)", len(dec), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(dec), nil
}

// readPrivKey reads an Ed25519 private key from disk. Accepts hex or
// base64; trims an "ed25519:" prefix. Length-checked to PrivateKeySize.
func readPrivKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := decodeKey(raw)
	if len(dec) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("not a valid ed25519 private key (decoded len=%d, want %d)", len(dec), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(dec), nil
}

// ─────────────────────────────────────────────────────────────────
// Week 4: observe → sign → enforce workflow commands
// ─────────────────────────────────────────────────────────────────

func newEgressPolicyProposeCmd() *cobra.Command {
	var sock, out string
	var days int
	cmd := &cobra.Command{
		Use:   "propose <binary>",
		Short: "Draft a policy proposal from observed ledger flows (Week 4)",
		Long: `Asks the running daemon to query the egress ledger for the named
binary over the last --days days and return a draft Policy proposal:
distinct destinations, suggested mode, per-rule confidence scores.

The proposal is printed as YAML and (optionally) written to --out.
Operator then reviews + edits + signs with 'egress policy sign'.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return fmt.Errorf("dial daemon: %w", err)
			}
			defer c.Close()
			req := map[string]any{"binary": args[0], "days": days}
			var prop egresspolicy.Proposal
			if err := c.Call("egress.policy.propose", req, &prop); err != nil {
				return fmt.Errorf("egress.policy.propose: %w", err)
			}
			data, err := yaml.Marshal(prop)
			if err != nil {
				return err
			}
			if out != "" {
				if err := os.WriteFile(out, data, 0o644); err != nil {
					return fmt.Errorf("write %s: %w", out, err)
				}
				fmt.Fprintf(os.Stderr, "wrote proposal to %s (%d rules, suggested_mode=%s)\n",
					out, len(prop.Allow), prop.SuggestedMode)
				return nil
			}
			_, _ = os.Stdout.Write(data)
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", "/run/xhelix/api.sock", "daemon socket")
	cmd.Flags().IntVar(&days, "days", 14, "observation window in days")
	cmd.Flags().StringVar(&out, "out", "", "write proposal to this file (default: stdout)")
	return cmd
}

func newEgressPolicySignCmd() *cobra.Command {
	var keyPath, signer, mode, out string
	cmd := &cobra.Command{
		Use:   "sign <proposal.yaml>",
		Short: "Sign a reviewed proposal into a SignedPolicy",
		Long: `Reads a Proposal YAML, converts it to a Policy, applies the optional
--mode override, signs with --key, and writes the SignedPolicy to
--out (default: <proposal>.signed.yaml). Use 'install' to push the
result to the daemon.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if signer == "" {
				return fmt.Errorf("--signer is required")
			}
			if keyPath == "" {
				return fmt.Errorf("--key is required")
			}
			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("read %s: %w", args[0], err)
			}
			var prop egresspolicy.Proposal
			if err := yaml.Unmarshal(data, &prop); err != nil {
				return fmt.Errorf("parse proposal: %w", err)
			}
			if mode != "" {
				prop.SuggestedMode = egresspolicy.Mode(mode)
			}
			priv, err := readPrivKey(keyPath)
			if err != nil {
				return fmt.Errorf("read private key: %w", err)
			}
			sp, err := egresspolicy.ProposalToSignedPolicy(prop, signer, priv)
			if err != nil {
				return fmt.Errorf("sign: %w", err)
			}
			signed, err := yaml.Marshal(sp)
			if err != nil {
				return err
			}
			if out == "" {
				out = strings.TrimSuffix(args[0], ".yaml") + ".signed.yaml"
			}
			if err := os.WriteFile(out, signed, 0o644); err != nil {
				return fmt.Errorf("write %s: %w", out, err)
			}
			fmt.Printf("signed policy for %q (mode=%s) → %s\n", sp.Policy.Binary, sp.Policy.Mode, out)
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "path to ed25519 private key")
	cmd.Flags().StringVar(&signer, "signer", "", "signer identity (required)")
	cmd.Flags().StringVar(&mode, "mode", "", "override policy mode: observe|deny_default|allow_any|tor_only")
	cmd.Flags().StringVar(&out, "out", "", "output path (default: <proposal>.signed.yaml)")
	return cmd
}

func newEgressPolicyInstallCmd() *cobra.Command {
	var sock string
	cmd := &cobra.Command{
		Use:   "install <signed.yaml>",
		Short: "Push a SignedPolicy to the running daemon",
		Long: `POSTs a SignedPolicy to the daemon's egress.policy.install RPC. The
daemon re-verifies the signature against operator.pub before saving
to the policy directory. The next 30s store re-scan picks it up;
this command also triggers an immediate re-scan.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("read %s: %w", args[0], err)
			}
			var sp egresspolicy.SignedPolicy
			if err := yaml.Unmarshal(data, &sp); err != nil {
				return fmt.Errorf("parse signed policy: %w", err)
			}
			c, err := localapi.Dial(sock)
			if err != nil {
				return fmt.Errorf("dial daemon: %w", err)
			}
			defer c.Close()
			var resp map[string]any
			if err := c.Call("egress.policy.install", sp, &resp); err != nil {
				return fmt.Errorf("egress.policy.install: %w", err)
			}
			fmt.Printf("installed %v (total loaded: %v)\n", resp["installed"], resp["loaded_total"])
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", "/run/xhelix/api.sock", "daemon socket")
	return cmd
}

// reSignWithMode is the shared core of enforce/observe: fetch the
// current signed policy from the daemon, swap Mode, re-sign, install.
func reSignWithMode(sock, binary, mode, keyPath, signer string) error {
	if signer == "" {
		return fmt.Errorf("--signer is required")
	}
	if keyPath == "" {
		return fmt.Errorf("--key is required")
	}
	priv, err := readPrivKey(keyPath)
	if err != nil {
		return fmt.Errorf("read private key: %w", err)
	}
	c, err := localapi.Dial(sock)
	if err != nil {
		return fmt.Errorf("dial daemon: %w", err)
	}
	defer c.Close()
	var current []egresspolicy.SignedPolicy
	if err := c.Call("egress.policy.list", nil, &current); err != nil {
		return fmt.Errorf("list: %w", err)
	}
	var existing *egresspolicy.SignedPolicy
	for i := range current {
		if current[i].Policy.Binary == binary {
			existing = &current[i]
			break
		}
	}
	if existing == nil {
		return fmt.Errorf("no signed policy installed for %q — propose+sign+install first", binary)
	}
	p := existing.Policy
	p.Mode = egresspolicy.Mode(mode)
	p.SignedAt = time.Time{} // re-stamp on Sign
	sp, err := egresspolicy.Sign(p, signer, priv)
	if err != nil {
		return fmt.Errorf("re-sign: %w", err)
	}
	var resp map[string]any
	if err := c.Call("egress.policy.install", sp, &resp); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	fmt.Printf("mode for %q → %s (installed; total loaded: %v)\n", binary, mode, resp["loaded_total"])
	return nil
}

func newEgressPolicyEnforceCmd() *cobra.Command {
	var sock, keyPath, signer string
	cmd := &cobra.Command{
		Use:   "enforce <binary>",
		Short: "Bump an installed policy to deny_default mode and re-sign",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return reSignWithMode(sock, args[0], string(egresspolicy.ModeDenyDefault), keyPath, signer)
		},
	}
	cmd.Flags().StringVar(&sock, "sock", "/run/xhelix/api.sock", "daemon socket")
	cmd.Flags().StringVar(&keyPath, "key", "", "path to ed25519 private key")
	cmd.Flags().StringVar(&signer, "signer", "", "signer identity")
	return cmd
}

func newEgressPolicyObserveCmd() *cobra.Command {
	var sock, keyPath, signer string
	cmd := &cobra.Command{
		Use:   "observe <binary>",
		Short: "Bump an installed policy to observe mode and re-sign",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return reSignWithMode(sock, args[0], string(egresspolicy.ModeObserve), keyPath, signer)
		},
	}
	cmd.Flags().StringVar(&sock, "sock", "/run/xhelix/api.sock", "daemon socket")
	cmd.Flags().StringVar(&keyPath, "key", "", "path to ed25519 private key")
	cmd.Flags().StringVar(&signer, "signer", "", "signer identity")
	return cmd
}

func newEgressPolicyRevertCmd() *cobra.Command {
	var sock string
	cmd := &cobra.Command{
		Use:   "revert <binary>",
		Short: "Delete the signed policy for a binary (returns to default observe)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := localapi.Dial(sock)
			if err != nil {
				return fmt.Errorf("dial daemon: %w", err)
			}
			defer c.Close()
			req := map[string]any{"binary": args[0]}
			var resp map[string]any
			if err := c.Call("egress.policy.delete", req, &resp); err != nil {
				return fmt.Errorf("egress.policy.delete: %w", err)
			}
			fmt.Printf("reverted %v (total loaded: %v)\n", resp["deleted"], resp["loaded_total"])
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", "/run/xhelix/api.sock", "daemon socket")
	return cmd
}

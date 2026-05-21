package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/credbroker"
)

// Default paths. The master key lives under /var/lib/xhelix so the
// daemon and the CLI both find it. CLI use of seal/unseal here is
// for v1 migration; in USG.2+ the kernel hook does this transparently.
const (
	defaultMasterKey = "/var/lib/xhelix/credbroker.key"
)

func newCredbrokerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "credbroker",
		Short: "Credential broker — seal/unseal/inspect managed secrets",
		Long: `xhelix credential broker (P-USG.1, see docs/UNIVERSAL_SECRET_GATE_ARCHITECTURE_2026-05-21.md).

Sealed files replace plaintext credential files on disk. Each
sealed file is AES-256-GCM-encrypted with a master key held under
/var/lib/xhelix/credbroker.key (mode 0600).

Commands:
  seal      Encrypt a plaintext file → write .sealed companion
  unseal    Decrypt a sealed file → print plaintext (use --force ack)
  status    Show metadata of a sealed file without unsealing
  history   Print the broker's recent decision audit log (daemon-only)

USG.1a scope: file-level seal/unseal works. Real policy gate (lineage
match, passport, 2FA, honey-on-deny) is being built in USG.1b-1d.
Until then, unseal returns plaintext on operator command without
remote-attestation checks. Use --force to acknowledge this.`,
	}
	cmd.AddCommand(newCredbrokerSealCmd())
	cmd.AddCommand(newCredbrokerUnsealCmd())
	cmd.AddCommand(newCredbrokerStatusCmd())
	cmd.AddCommand(newCredbrokerHistoryCmd())
	return cmd
}

// ─── seal ──────────────────────────────────────────────────────────

func newCredbrokerSealCmd() *cobra.Command {
	var (
		keyPath string
		class   string
		purpose string
		issuer  string
		outPath string
		keepOrig bool
	)
	cmd := &cobra.Command{
		Use:   "seal <input-file>",
		Short: "Encrypt a plaintext file into a sealed companion",
		Long: `Reads <input-file>, AES-256-GCM-encrypts it, writes the
result to <input-file>.sealed (or --out if supplied). The original
file is NOT removed unless you confirm with --remove-plaintext (a
sane default: keep it so you can verify before deleting).

Examples:
  xhelixctl credbroker seal /root/.aws/credentials \
     --class=api_key --purpose="prod aws creds"

After verifying the sealed file unseals back to the original, run:
  xhelixctl credbroker seal /root/.aws/credentials \
     --class=api_key --remove-plaintext --force`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			input := args[0]
			plaintext, err := os.ReadFile(input)
			if err != nil {
				return fmt.Errorf("read input: %w", err)
			}
			key, err := credbroker.LoadOrCreateMasterKey(keyPath)
			if err != nil {
				return fmt.Errorf("master key: %w", err)
			}
			sealer, err := credbroker.NewAESGCMSealer(key, "default")
			if err != nil {
				return fmt.Errorf("sealer: %w", err)
			}
			b := credbroker.NewBroker(sealer, 0)
			meta := credbroker.Meta{
				Class:    credbroker.Class(class),
				Purpose:  purpose,
				Issuer:   issuer,
				OrigPath: input,
			}
			if meta.Issuer == "" {
				meta.Issuer = "operator:" + currentUser()
			}
			sf, err := b.Seal(plaintext, meta)
			if err != nil {
				return fmt.Errorf("seal: %w", err)
			}
			out := outPath
			if out == "" {
				out = input + ".sealed"
			}
			if err := sf.Write(out); err != nil {
				return fmt.Errorf("write sealed: %w", err)
			}
			fmt.Printf("sealed %s -> %s (class=%s purpose=%q)\n",
				input, out, meta.Class, meta.Purpose)
			if !keepOrig {
				fmt.Printf("plaintext %s is preserved. Verify the sealed file unseals correctly, then remove it manually or re-run with --remove-plaintext.\n", input)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&keyPath, "master-key", defaultMasterKey, "path to master key file")
	cmd.Flags().StringVar(&class, "class", string(credbroker.ClassCredentials),
		"data class (credentials|api_key|payment_token|backup|source_code|canary)")
	cmd.Flags().StringVar(&purpose, "purpose", "", "human-readable purpose for audit")
	cmd.Flags().StringVar(&issuer, "issuer", "", "issuer identifier (default: operator:<user>)")
	cmd.Flags().StringVar(&outPath, "out", "", "output path (default: <input>.sealed)")
	cmd.Flags().BoolVar(&keepOrig, "remove-plaintext", false, "remove the plaintext input after sealing")
	return cmd
}

// ─── unseal ────────────────────────────────────────────────────────

func newCredbrokerUnsealCmd() *cobra.Command {
	var (
		keyPath string
		force   bool
		outPath string
	)
	cmd := &cobra.Command{
		Use:   "unseal <sealed-file>",
		Short: "Decrypt a sealed file (operator override; bypasses broker policy)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !force {
				return fmt.Errorf("unseal bypasses the broker policy gate. Pass --force to confirm.")
			}
			sf, err := credbroker.ReadSealed(args[0])
			if err != nil {
				return err
			}
			key, err := credbroker.LoadOrCreateMasterKey(keyPath)
			if err != nil {
				return fmt.Errorf("master key: %w", err)
			}
			sealer, err := credbroker.NewAESGCMSealer(key, sf.Meta.KeyID)
			if err != nil {
				return fmt.Errorf("sealer: %w", err)
			}
			b := credbroker.NewBroker(sealer, 0)
			pt, err := b.Unseal(sf)
			if err != nil {
				return err
			}
			if outPath == "" || outPath == "-" {
				_, _ = io.Copy(os.Stdout, strings.NewReader(string(pt)))
				return nil
			}
			return os.WriteFile(outPath, pt, 0o600)
		},
	}
	cmd.Flags().StringVar(&keyPath, "master-key", defaultMasterKey, "path to master key file")
	cmd.Flags().BoolVar(&force, "force", false, "acknowledge that this bypasses the broker policy")
	cmd.Flags().StringVar(&outPath, "out", "-", "output path (default stdout)")
	return cmd
}

// ─── status ────────────────────────────────────────────────────────

func newCredbrokerStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status <sealed-file>",
		Short: "Show metadata of a sealed file without unsealing",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sf, err := credbroker.ReadSealed(args[0])
			if err != nil {
				return err
			}
			b, _ := json.MarshalIndent(sf.Meta, "", "  ")
			fmt.Println(string(b))
			fmt.Printf("ciphertext: %d bytes\n", len(sf.Ciphertext))
			return nil
		},
	}
	return cmd
}

// ─── history ───────────────────────────────────────────────────────

func newCredbrokerHistoryCmd() *cobra.Command {
	var sock string
	cmd := &cobra.Command{
		Use:   "history",
		Short: "Show recent broker decisions from the daemon's audit log",
		Long: `Reads the daemon's in-memory audit log via LocalAPI. Each
record covers one credential-release decision: allow/deny/honey,
which lineage requested, what class was requested, and the reason
the broker decided as it did.

USG.1a: the daemon doesn't have a broker wired yet, so this command
returns an empty list. Will be populated by USG.1b when the broker
is integrated into pipeline.Pipeline.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("USG.1a: daemon-side broker not yet wired.")
			fmt.Println("This commits the package + tooling so seal/unseal work today;")
			fmt.Println("the LocalAPI handler lands in USG.1b alongside the policy gate.")
			_ = sock
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "TIME\tCLASS\tOUTCOME\tPID\tCOMM\tREASON")
			tw.Flush()
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "sock", defaultSock, "path to xhelix LocalAPI socket")
	return cmd
}

// currentUser returns the running OS user for issuer attribution.
// Falls back to "unknown" — we don't want to fail seal because we
// couldn't read /etc/passwd.
func currentUser() string {
	for _, env := range []string{"SUDO_USER", "USER", "LOGNAME"} {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	return "unknown"
}

// silence unused-import warning when time isn't otherwise needed
var _ = time.Time{}

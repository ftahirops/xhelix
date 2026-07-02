// xhelixctl synth — propose / list / export candidate behavioral profiles.
//
//	xhelixctl synth propose <app>       synthesize a candidate profile from recorder data
//	xhelixctl synth list <app>          list existing proposals for an app
//	xhelixctl synth export <app> <id>   print a proposal's DeclarationJSON to stdout
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/brp"
	"github.com/xhelix/xhelix/pkg/contractpropose"
	"github.com/xhelix/xhelix/pkg/localapi"
	"github.com/xhelix/xhelix/pkg/synth"

	_ "modernc.org/sqlite"
)

func newSynthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "synth",
		Short: "Manage synthesized behavioral profile proposals (SP-4)",
	}
	cmd.AddCommand(newSynthProposeCmd())
	cmd.AddCommand(newSynthListCmd())
	cmd.AddCommand(newSynthExportCmd())
	cmd.AddCommand(newSynthApproveCmd())
	return cmd
}

// newSynthApproveCmd is the auto-promote step: it takes a pending proposal,
// signs its profile with the operator's key file, installs the signed profile
// into the BRP library directory, marks the proposal approved, and (by default)
// hot-reloads the running daemon so the profile goes live without a restart.
//
// This closes the previously-manual middle of the learn→lock loop
// (export → hand-sign → copy → restart) into a single command.
//
//	xhelixctl synth approve <app> <id> --key /etc/xhelix/brp/ops.key --signer ops-local
func newSynthApproveCmd() *cobra.Command {
	var stateDir, keyPath, signer, outDir, sock string
	var reload, force bool
	cmd := &cobra.Command{
		Use:   "approve <app> <id>",
		Short: "Sign, install, and activate a pending proposal (operator-key-file model)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			appID, id := args[0], args[1]
			if keyPath == "" {
				return errors.New("--key is required (operator Ed25519 private key file; make one with 'xhelixctl brp keygen')")
			}
			if signer == "" {
				return errors.New("--signer is required (must match a public key in the daemon's trusted-keys.d)")
			}

			priv, err := loadPrivateKey(keyPath)
			if err != nil {
				return fmt.Errorf("load operator key: %w", err)
			}
			propPath := filepath.Join(stateDir, "contract-propose.db")
			store, err := contractpropose.Open(propPath)
			if err != nil {
				return fmt.Errorf("open proposal store: %w", err)
			}
			defer store.Close()

			dst, err := promoteProposal(store, appID, id, priv, signer, outDir, force)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "approved %s → signed profile %s\n", id, dst)

			// 5. Hot-reload the running daemon (best-effort).
			if reload {
				c, derr := localapi.Dial(sock)
				if derr != nil {
					fmt.Fprintf(os.Stderr, "profile installed but daemon not reachable (%v) — it will load on next start, or run 'xhelixctl brp reload'\n", derr)
					return nil
				}
				defer c.Close()
				var resp struct {
					Loaded int `json:"loaded"`
					Size   int `json:"size"`
				}
				if err := c.Call("brp.reload", nil, &resp); err != nil {
					fmt.Fprintf(os.Stderr, "profile installed but hot-reload failed (%v) — run 'xhelixctl brp reload'\n", err)
					return nil
				}
				fmt.Fprintf(os.Stdout, "hot-reloaded: %d profiles now live\n", resp.Size)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", "/var/lib/xhelix", "xhelix state directory (contains contract-propose.db)")
	cmd.Flags().StringVar(&keyPath, "key", "", "operator Ed25519 private key file (base64)")
	cmd.Flags().StringVar(&signer, "signer", "", "signer name (must match a trusted public key on the daemon)")
	cmd.Flags().StringVar(&outDir, "out-dir", "/etc/xhelix/brp", "BRP profile library directory to install into")
	cmd.Flags().StringVar(&sock, "sock", "/run/xhelix/xhelix.sock", "daemon socket (for hot-reload)")
	cmd.Flags().BoolVar(&reload, "reload", true, "hot-reload the running daemon after install")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing signed profile")
	return cmd
}

func newSynthProposeCmd() *cobra.Command {
	var dbPath, stateDir string
	var globThreshold, minSamples int
	cmd := &cobra.Command{
		Use:   "propose <app>",
		Short: "Synthesize a candidate profile from recorder data and file it for review",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			appID := args[0]

			// Open recorder DB read-only (mirrors recorder.go pattern).
			if _, err := os.Stat(dbPath); err != nil {
				return fmt.Errorf("recorder db not found at %s — has the recorder ever run?", dbPath)
			}
			rec, err := openRecorderReadOnly(dbPath)
			if err != nil {
				return err
			}
			defer rec.Close()

			// Open proposal store.
			propPath := filepath.Join(stateDir, "contract-propose.db")
			store, err := contractpropose.Open(propPath)
			if err != nil {
				return fmt.Errorf("open proposal store: %w", err)
			}
			defer store.Close()

			prop, err := synth.Propose(rec, store, appID, globThreshold, minSamples)
			if err != nil {
				if errors.Is(err, synth.ErrNoData) {
					fmt.Fprintf(os.Stderr, "no recorded data for %s — run the recorder first\n", appID)
					return nil
				}
				if errors.Is(err, synth.ErrInsufficientSamples) {
					fmt.Fprintf(os.Stderr, "%s: too few observations (need >= %d) — wait for the behavior to recur, or lower --min-samples\n", appID, minSamples)
					return nil
				}
				return fmt.Errorf("synth propose: %w", err)
			}
			fmt.Printf("proposal filed: id=%s app=%s\n%s\n", prop.ID, prop.App, prop.Reason)
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "/var/lib/xhelix/recorder.db", "path to recorder.db")
	cmd.Flags().StringVar(&stateDir, "state-dir", "/var/lib/xhelix", "xhelix state directory (contains contract-propose.db)")
	cmd.Flags().IntVar(&globThreshold, "glob-threshold", 3, "minimum path count to trigger glob generalization")
	cmd.Flags().IntVar(&minSamples, "min-samples", 5, "minimum total observations before an app is worth proposing (<=1 disables the gate)")
	return cmd
}

func newSynthListCmd() *cobra.Command {
	var stateDir string
	cmd := &cobra.Command{
		Use:   "list <app>",
		Short: "List existing proposals for an app",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			appID := args[0]
			propPath := filepath.Join(stateDir, "contract-propose.db")
			if _, err := os.Stat(propPath); err != nil {
				return fmt.Errorf("proposal store not found at %s — run 'synth propose' first", propPath)
			}
			store, err := contractpropose.Open(propPath)
			if err != nil {
				return fmt.Errorf("open proposal store: %w", err)
			}
			defer store.Close()

			proposals, err := store.ListForApp(appID, 100)
			if err != nil {
				return fmt.Errorf("list proposals: %w", err)
			}
			fmt.Print(renderProposalList(proposals))
			return nil
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", "/var/lib/xhelix", "xhelix state directory (contains contract-propose.db)")
	return cmd
}

func newSynthExportCmd() *cobra.Command {
	var stateDir string
	cmd := &cobra.Command{
		Use:   "export <app> <id>",
		Short: "Print a proposal's DeclarationJSON to stdout (pipe into signing pipeline)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			appID, id := args[0], args[1]
			propPath := filepath.Join(stateDir, "contract-propose.db")
			if _, err := os.Stat(propPath); err != nil {
				return fmt.Errorf("proposal store not found at %s — run 'synth propose' first", propPath)
			}
			store, err := contractpropose.Open(propPath)
			if err != nil {
				return fmt.Errorf("open proposal store: %w", err)
			}
			defer store.Close()

			prop, ok := store.Get(appID, id)
			if !ok {
				return fmt.Errorf("proposal %s not found for app %s", id, appID)
			}
			_, err = os.Stdout.Write(prop.DeclarationJSON)
			return err
		},
	}
	cmd.Flags().StringVar(&stateDir, "state-dir", "/var/lib/xhelix", "xhelix state directory (contains contract-propose.db)")
	return cmd
}

// promoteProposal signs a pending proposal's profile with the operator key,
// installs it into outDir as <profile_id>.signed.json, and marks the proposal
// approved. Returns the installed path. Extracted from the CLI closure so the
// sign→install→approve core is unit-testable without a daemon. Reload is the
// caller's responsibility (it needs a live socket).
func promoteProposal(store *contractpropose.Store, appID, id string, priv ed25519.PrivateKey, signer, outDir string, force bool) (string, error) {
	prop, ok := store.Get(appID, id)
	if !ok {
		return "", fmt.Errorf("proposal %s not found for app %s", id, appID)
	}
	var prof brp.Profile
	if err := json.Unmarshal(prop.DeclarationJSON, &prof); err != nil {
		return "", fmt.Errorf("proposal declaration is not a valid profile: %w", err)
	}
	if prof.ProfileID == "" {
		return "", errors.New("proposal profile has no profile_id — cannot name the output file")
	}
	signed, err := brp.Sign(prof, signer, priv)
	if err != nil {
		return "", fmt.Errorf("sign profile: %w", err)
	}
	dst := filepath.Join(outDir, prof.ProfileID+".signed.json")
	if !force {
		if _, err := os.Stat(dst); err == nil {
			return "", fmt.Errorf("%s already exists (pass --force to overwrite)", dst)
		}
	}
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return "", fmt.Errorf("create %s: %w", outDir, err)
	}
	if err := brp.WriteSigned(dst, signed); err != nil {
		return "", fmt.Errorf("write signed profile: %w", err)
	}
	if prop.Status != contractpropose.StatusApproved {
		if err := store.Decide(appID, id, contractpropose.StatusApproved, signer); err != nil {
			return "", fmt.Errorf("mark approved: %w", err)
		}
	}
	return dst, nil
}

// renderProposalList formats a slice of proposals for terminal display. Pure — tested.
func renderProposalList(ps []contractpropose.Proposal) string {
	var b strings.Builder
	for _, p := range ps {
		fmt.Fprintf(&b, "%s  app=%s  status=%s  %s  %s\n",
			p.ID, p.App, p.Status, p.CreatedAt.Format("2006-01-02T15:04:05Z07:00"), p.Reason)
	}
	if b.Len() == 0 {
		return "(no proposals)\n"
	}
	return b.String()
}

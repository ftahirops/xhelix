package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/credbroker"
)

// newCredbrokerDecoyCmd adds `xhelixctl credbroker decoy` for the
// honey-decoy workflow. A decoy is a peer `.honey` file dropped
// next to a sealed credential. It is world-readable and carries a
// unique marker embedded in realistic-looking credential content.
// The fangate marks every .honey file as adversarial-by-construction:
// any open triggers a Tier-1 alert and lights up the takeover scorer.
func newCredbrokerDecoyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "decoy",
		Short: "Manage honey decoy files (peers to sealed credentials)",
	}
	cmd.AddCommand(newDecoyDropCmd())
	return cmd
}

func newDecoyDropCmd() *cobra.Command {
	var class string
	var outPath string
	cmd := &cobra.Command{
		Use:   "drop <sealed-file>",
		Short: "Generate a .honey decoy peer for a sealed credential file",
		Long: `Creates a peer <sealed-file with .sealed replaced by .honey>
containing realistic-looking honey credentials with an embedded
marker. The marker is unique per drop so any later observation of it
(in network traffic, logs, env vars) can be attributed back to this
sealed file.

The daemon's fangate marks honey files; any open triggers an alert.
Set the file world-readable (default 0o644) so attackers grep and
find it before finding the .sealed file.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sealedPath := args[0]
			if outPath == "" {
				outPath = strings.TrimSuffix(sealedPath, ".sealed") + ".honey"
			}
			h := credbroker.NewHoneyFactory()
			content, origin := h.Generate(
				credbroker.Class(class),
				sealedPath,
				credbroker.Request{Reason: "operator decoy drop"},
			)
			if err := os.WriteFile(outPath, content, 0o644); err != nil {
				return fmt.Errorf("write honey: %w", err)
			}
			fmt.Printf("decoy honey written to %s\n", outPath)
			fmt.Printf("  marker:      %s\n", origin.Marker)
			fmt.Printf("  marker-hex:  %s\n", hex.EncodeToString([]byte(origin.Marker)[:8]))
			fmt.Printf("\nRecord the marker — any future observation of it in network\n")
			fmt.Printf("traffic, logs, or env vars indicates this decoy was exfiltrated.\n")
			fmt.Printf("(Marker is also embedded in the honey content body.)\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&class, "class", string(credbroker.ClassCredentials),
		"honey class (credentials|api_key) — controls content shape")
	cmd.Flags().StringVar(&outPath, "out", "",
		"output path (default: replace .sealed suffix with .honey)")
	return cmd
}

// sha256OfFile is a small helper used by contract scaffold --pin.
func sha256OfFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

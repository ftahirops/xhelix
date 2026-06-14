package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/brp"
	"github.com/xhelix/xhelix/pkg/xhubfleet"
)

// newXhubCmd is the operator entrypoint for reviewing fleet candidates,
// signing them, and inspecting the published BRP feed served by xhub.
func newXhubCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "xhub",
		Short: "Operate against an xhub fleet baseline hub",
	}
	cmd.AddCommand(newXhubCandidatesCmd())
	cmd.AddCommand(newXhubCohortsCmd())
	cmd.AddCommand(newXhubTrustCmd())
	cmd.AddCommand(newXhubFeedCmd())
	cmd.AddCommand(newXhubReviewCmd())
	cmd.AddCommand(newXhubSignCmd())
	return cmd
}

type xhubFlags struct {
	hub       string
	tokenFile string
}

func (f *xhubFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.hub, "hub", "http://127.0.0.1:18444", "xhub base URL")
	cmd.Flags().StringVar(&f.tokenFile, "token-file", "", "Path to bearer-token file (matches xhub --token-file)")
}

func (f *xhubFlags) token() (string, error) {
	if f.tokenFile == "" {
		return "", nil
	}
	body, err := os.ReadFile(f.tokenFile)
	if err != nil {
		return "", fmt.Errorf("read token file: %w", err)
	}
	return strings.TrimSpace(string(body)), nil
}

// httpGet performs an authenticated GET and decodes the JSON body into out.
func (f *xhubFlags) httpGet(path string, out interface{}) error {
	tok, err := f.token()
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodGet, f.hub+path, nil)
	if err != nil {
		return err
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GET %s: %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// httpPostJSON performs an authenticated POST with a JSON body.
func (f *xhubFlags) httpPostJSON(path string, payload interface{}, out interface{}) error {
	tok, err := f.token()
	if err != nil {
		return err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, f.hub+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		rb, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("POST %s: %s: %s", path, resp.Status, strings.TrimSpace(string(rb)))
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func newXhubCandidatesCmd() *cobra.Command {
	f := &xhubFlags{}
	var rebuild bool
	cmd := &cobra.Command{
		Use:   "candidates",
		Short: "List fleet BRP candidates pending operator review",
		RunE: func(cmd *cobra.Command, _ []string) error {
			path := "/api/fleet/candidates"
			var cands []xhubfleet.Candidate
			if rebuild {
				if err := f.httpPostJSON(path+"?rebuild=1", struct{}{}, &cands); err != nil {
					// Hub returns the list on POST too; if POST not allowed, fall through.
					if err := f.httpGet(path, &cands); err != nil {
						return err
					}
				}
			} else {
				if err := f.httpGet(path, &cands); err != nil {
					return err
				}
			}
			if len(cands) == 0 {
				fmt.Println("No candidates pending.")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "PROFILE_ID\tCOHORT\tBINARY\tHOSTS_AGREED\tTOTAL\tGENERATED_AT")
			for _, c := range cands {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%s\n",
					c.Profile.ProfileID, c.Cohort.String(), c.Binary,
					c.HostsAgreed, c.TotalHosts,
					c.GeneratedAt.Format(time.RFC3339))
			}
			return tw.Flush()
		},
	}
	f.bind(cmd)
	cmd.Flags().BoolVar(&rebuild, "rebuild", false, "Force the hub to recompute candidates before returning")
	return cmd
}

func newXhubCohortsCmd() *cobra.Command {
	f := &xhubFlags{}
	cmd := &cobra.Command{
		Use:   "cohorts",
		Short: "List cohorts the hub has observed",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var ks []xhubfleet.CohortKey
			if err := f.httpGet("/api/fleet/cohorts", &ks); err != nil {
				return err
			}
			if len(ks) == 0 {
				fmt.Println("No cohorts indexed yet.")
				return nil
			}
			for _, k := range ks {
				fmt.Println(k.String())
			}
			return nil
		},
	}
	f.bind(cmd)
	return cmd
}

func newXhubTrustCmd() *cobra.Command {
	f := &xhubFlags{}
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Print per-host trust levels",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var rs []xhubfleet.HostRecord
			if err := f.httpGet("/api/fleet/trust", &rs); err != nil {
				return err
			}
			if len(rs) == 0 {
				fmt.Println("No host records.")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "HOST_TAG\tTRUST\tALERTS_24H\tCRITICAL\tFIRST_SEEN\tLAST_SEEN\tREASON")
			for _, r := range rs {
				fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\t%s\t%s\n",
					r.HostTag, r.Trust, r.AlertCount24h, r.CriticalAlerts,
					r.FirstSeen.Format(time.RFC3339),
					r.LastSeen.Format(time.RFC3339),
					r.Reason)
			}
			return tw.Flush()
		},
	}
	f.bind(cmd)
	return cmd
}

func newXhubFeedCmd() *cobra.Command {
	f := &xhubFlags{}
	cmd := &cobra.Command{
		Use:   "feed",
		Short: "Show the currently-published signed BRP feed",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var feed []brp.SignedProfile
			if err := f.httpGet("/api/brp/feed", &feed); err != nil {
				return err
			}
			if len(feed) == 0 {
				fmt.Println("Feed empty.")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "PROFILE_ID\tAPP\tSIGNER\tCONFIDENCE\tSIGNED_AT")
			for _, sp := range feed {
				t := time.Unix(0, sp.Profile.SigningEpoch).UTC().Format(time.RFC3339)
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
					sp.Profile.ProfileID, sp.Profile.Key.App,
					sp.Signer, sp.Profile.Confidence.String(), t)
			}
			return tw.Flush()
		},
	}
	f.bind(cmd)
	return cmd
}

func newXhubReviewCmd() *cobra.Command {
	f := &xhubFlags{}
	var candidateID string
	cmd := &cobra.Command{
		Use:   "review",
		Short: "Show full candidate detail as JSON",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if candidateID == "" {
				return fmt.Errorf("--candidate-id is required")
			}
			cand, err := fetchCandidate(f, candidateID)
			if err != nil {
				return err
			}
			out, err := json.MarshalIndent(cand, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(out))
			return nil
		},
	}
	f.bind(cmd)
	cmd.Flags().StringVar(&candidateID, "candidate-id", "", "Profile ID of the candidate to inspect")
	return cmd
}

func newXhubSignCmd() *cobra.Command {
	f := &xhubFlags{}
	var (
		candidateID string
		keyPath     string
		signer      string
	)
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a fleet candidate locally and publish it back to the hub",
		Long: `Workflow:
  1. Fetches the named candidate from the hub
  2. Loads the operator's ed25519 private key from --key
  3. Signs the candidate's Profile locally
  4. POSTs the SignedProfile to /api/fleet/publish on the hub

The private key never leaves the operator's host.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if candidateID == "" {
				return fmt.Errorf("--candidate-id is required")
			}
			if keyPath == "" {
				return fmt.Errorf("--key is required")
			}
			if signer == "" {
				return fmt.Errorf("--signer is required")
			}
			cand, err := fetchCandidate(f, candidateID)
			if err != nil {
				return err
			}
			if err := xhubfleet.ValidateForSigning(*cand); err != nil {
				return fmt.Errorf("candidate not signable: %w", err)
			}
			priv, err := loadEd25519PrivateKey(keyPath)
			if err != nil {
				return fmt.Errorf("load private key: %w", err)
			}
			sp, err := brp.Sign(cand.Profile, signer, priv)
			if err != nil {
				return fmt.Errorf("sign: %w", err)
			}
			var resp map[string]string
			if err := f.httpPostJSON("/api/fleet/publish", sp, &resp); err != nil {
				return fmt.Errorf("publish: %w", err)
			}
			fmt.Printf("Published %s (signer=%s)\n", sp.Profile.ProfileID, sp.Signer)
			return nil
		},
	}
	f.bind(cmd)
	cmd.Flags().StringVar(&candidateID, "candidate-id", "", "Profile ID of the candidate to sign")
	cmd.Flags().StringVar(&keyPath, "key", "", "Path to operator ed25519 private key (PEM or raw 64 bytes)")
	cmd.Flags().StringVar(&signer, "signer", "", "Signer identity recorded in the SignedProfile (e.g. operator-acme)")
	return cmd
}

// fetchCandidate retrieves the full Candidate list and returns the matching one.
func fetchCandidate(f *xhubFlags, profileID string) (*xhubfleet.Candidate, error) {
	var cands []xhubfleet.Candidate
	if err := f.httpGet("/api/fleet/candidates", &cands); err != nil {
		return nil, err
	}
	for i := range cands {
		if cands[i].Profile.ProfileID == profileID {
			return &cands[i], nil
		}
	}
	return nil, fmt.Errorf("candidate %q not found", profileID)
}

// loadEd25519PrivateKey accepts either a PEM-encoded PKCS8 key or raw
// 64-byte ed25519 seed bytes.
func loadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Raw 64-byte key (ed25519 private key size).
	if len(data) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(data), nil
	}
	// 32-byte seed → expand.
	if len(data) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(data), nil
	}
	// PEM-encoded.
	block, _ := pem.Decode(data)
	if block != nil {
		if len(block.Bytes) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(block.Bytes), nil
		}
		if len(block.Bytes) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(block.Bytes), nil
		}
		return nil, fmt.Errorf("PEM block payload is %d bytes; want %d or %d", len(block.Bytes), ed25519.PrivateKeySize, ed25519.SeedSize)
	}
	return nil, fmt.Errorf("unsupported key format (file is %d bytes; expected %d or %d raw, or PEM-encoded)", len(data), ed25519.SeedSize, ed25519.PrivateKeySize)
}

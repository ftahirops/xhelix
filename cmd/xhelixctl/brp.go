package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/brp"
	parser "github.com/xhelix/xhelix/pkg/brp/parser"
)

const (
	defaultBRPProfileDir = "/etc/xhelix/brp"
	defaultBRPKeysDir    = "/etc/xhelix/brp/trusted-keys.d"
)

// newBRPCmd is the operator surface for v2 Behavioral Reference Profiles.
//
// Like `xhelixctl source`, this talks to the on-disk profile library
// directly (no daemon round-trip) so it works whether the daemon is
// running or stopped.
func newBRPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "brp",
		Short: "Inspect Behavioral Reference Profiles (signed JSON envelopes for each app)",
		Long: `BRP commands inspect signed *.signed.json profiles, parse local
config files into their derived ProfileKey, and explain runtime decisions.

  list                 - list loaded signed profiles
  show <id>            - full detail for one profile
  verify <path>        - load + cryptographically verify a profile
  parse <config-path>  - parse a live config; show derived ProfileKey + behavior
  why <profile-id> <event...> - explain what the runtime would decide
  keygen               - generate an operator Ed25519 keypair
  generate             - parse a config + sign + write a *.signed.json profile`,
	}
	cmd.AddCommand(newBRPListCmd())
	cmd.AddCommand(newBRPShowCmd())
	cmd.AddCommand(newBRPVerifyCmd())
	cmd.AddCommand(newBRPParseCmd())
	cmd.AddCommand(newBRPWhyCmd())
	cmd.AddCommand(newBRPKeygenCmd())
	cmd.AddCommand(newBRPGenerateCmd())
	cmd.AddCommand(newBRPEdgeCmd())
	return cmd
}

// ─────────────────────────────────────────────────────────────────────
// brp edge — operator-curated inter-app interaction allowlist
// ─────────────────────────────────────────────────────────────────────
func newBRPEdgeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edge",
		Short: "Inspect / sign inter-app BRP edges (nginx → php-fpm, app → mysql, …)",
		Long: `BRP edges declare allowed inter-app interactions. They are loaded
from /etc/xhelix/brp/edges.d/*.edge.json at daemon startup, signed with the
same operator keys used for BRP profiles. The verifier's CrossApp domain
attenuates score for signed edges.

  list   - list loaded edges
  sign   - produce a signed *.edge.json from CLI arguments`,
	}
	cmd.AddCommand(newBRPEdgeListCmd())
	cmd.AddCommand(newBRPEdgeSignCmd())
	return cmd
}

func newBRPEdgeListCmd() *cobra.Command {
	var (
		dir     string
		keysDir string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List loaded signed BRP edges",
		RunE: func(cmd *cobra.Command, args []string) error {
			keys, err := loadTrustedKeys(keysDir)
			if err != nil {
				return err
			}
			s := brp.NewEdgeSet(keys)
			loaded, rejected, err := s.LoadDir(dir)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "loaded=%d rejected=%d\n", loaded, rejected)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "/etc/xhelix/brp/edges.d", "directory containing *.edge.json")
	cmd.Flags().StringVar(&keysDir, "keys", defaultBRPKeysDir, "directory of trusted public keys")
	return cmd
}

func newBRPEdgeSignCmd() *cobra.Command {
	var (
		fromApp        string
		toApp          string
		signer         string
		keyPath        string
		outDir         string
		outPath        string
		actions        []string
		destinations   []string
		note           string
		force          bool
	)
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Produce a signed *.edge.json envelope from CLI arguments",
		Long: `Example:
  xhelixctl brp edge sign \
      --from nginx --to php-fpm \
      --signer ops-local \
      --key /etc/xhelix/brp/ops-local.key \
      --action net_connect \
      --dest unix:/run/php/php-fpm.sock`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if fromApp == "" || toApp == "" {
				return errors.New("--from and --to are required")
			}
			if signer == "" {
				return errors.New("--signer is required")
			}
			if keyPath == "" {
				return errors.New("--key is required")
			}
			priv, err := loadPrivateKey(keyPath)
			if err != nil {
				return fmt.Errorf("load key: %w", err)
			}
			e := brp.Edge{
				SchemaVersion:  1,
				FromApp:        fromApp,
				ToApp:          toApp,
				AllowedActions: actions,
				Destinations:   destinations,
				Note:           note,
			}
			signed, err := brp.SignEdge(e, signer, priv)
			if err != nil {
				return err
			}
			dst := outPath
			if dst == "" {
				dst = filepath.Join(outDir, fmt.Sprintf("%s-to-%s.edge.json", fromApp, toApp))
			}
			if !force {
				if _, err := os.Stat(dst); err == nil {
					return fmt.Errorf("%s already exists (pass --force)", dst)
				}
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return err
			}
			buf, err := json.MarshalIndent(signed, "", "  ")
			if err != nil {
				return err
			}
			if err := os.WriteFile(dst, append(buf, '\n'), 0o644); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "wrote %s\n", dst)
			fmt.Fprintf(os.Stdout, "  edge:   %s → %s\n", fromApp, toApp)
			fmt.Fprintf(os.Stdout, "  signer: %s\n", signer)
			if len(actions) > 0 {
				fmt.Fprintf(os.Stdout, "  actions: %v\n", actions)
			}
			if len(destinations) > 0 {
				fmt.Fprintf(os.Stdout, "  dests:   %v\n", destinations)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&fromApp, "from", "", "source app (e.g. nginx)")
	cmd.Flags().StringVar(&toApp, "to", "", "destination app (e.g. php-fpm)")
	cmd.Flags().StringVar(&signer, "signer", "", "signer name (must match a *.pub in trust root)")
	cmd.Flags().StringVar(&keyPath, "key", "", "path to the Ed25519 private key")
	cmd.Flags().StringSliceVar(&actions, "action", nil, "allowed action (repeatable). Default: any")
	cmd.Flags().StringSliceVar(&destinations, "dest", nil, "allowed destination (repeatable)")
	cmd.Flags().StringVar(&note, "note", "", "human-readable note")
	cmd.Flags().StringVar(&outDir, "out-dir", "/etc/xhelix/brp/edges.d", "output directory")
	cmd.Flags().StringVar(&outPath, "out", "", "explicit output path (overrides --out-dir)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing")
	return cmd
}

// ─────────────────────────────────────────────────────────────────────
// brp keygen --signer NAME [--out-dir /etc/xhelix/brp]
// ─────────────────────────────────────────────────────────────────────
//
// Produces two files in <out-dir>:
//   <signer>.key       — Ed25519 private key (base64, mode 0600)
//   trusted-keys.d/<signer>.pub  — public key (base64, mode 0644)
//
// The .pub goes into the daemon's trust root automatically (any *.pub
// under /etc/xhelix/brp/trusted-keys.d/ is loaded at startup). The .key
// stays with the operator and is only needed when running `brp generate`.
func newBRPKeygenCmd() *cobra.Command {
	var (
		outDir string
		signer string
		force  bool
	)
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an Ed25519 operator signing keypair for BRP profiles",
		Long: `Produces a private key (<out-dir>/<signer>.key, mode 0600) and a
public key (<out-dir>/trusted-keys.d/<signer>.pub, mode 0644). After running
this once, ` + "`xhelixctl brp generate`" + ` can sign profiles with the
private key and the running xhelix daemon will trust them on next restart.

The signer name is the identity stamped into every profile signed with this
key — pick something memorable like "ops-alice" or "site-prod-2026".`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if signer == "" {
				return errors.New("--signer is required")
			}
			if !validSigner(signer) {
				return fmt.Errorf("signer must match [a-zA-Z0-9_.-]+, got %q", signer)
			}
			pub, priv, err := ed25519.GenerateKey(nil)
			if err != nil {
				return fmt.Errorf("generate key: %w", err)
			}
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return fmt.Errorf("mkdir %s: %w", outDir, err)
			}
			keysDir := filepath.Join(outDir, "trusted-keys.d")
			if err := os.MkdirAll(keysDir, 0o755); err != nil {
				return fmt.Errorf("mkdir %s: %w", keysDir, err)
			}
			privPath := filepath.Join(outDir, signer+".key")
			pubPath := filepath.Join(keysDir, signer+".pub")
			if !force {
				if _, err := os.Stat(privPath); err == nil {
					return fmt.Errorf("%s already exists (pass --force to overwrite)", privPath)
				}
				if _, err := os.Stat(pubPath); err == nil {
					return fmt.Errorf("%s already exists (pass --force to overwrite)", pubPath)
				}
			}
			privB64 := base64.StdEncoding.EncodeToString(priv)
			pubB64 := base64.StdEncoding.EncodeToString(pub)
			if err := os.WriteFile(privPath, []byte(privB64+"\n"), 0o600); err != nil {
				return fmt.Errorf("write %s: %w", privPath, err)
			}
			if err := os.WriteFile(pubPath, []byte(pubB64+"\n"), 0o644); err != nil {
				return fmt.Errorf("write %s: %w", pubPath, err)
			}
			fmt.Fprintf(os.Stdout, "wrote %s (private, 0600)\n", privPath)
			fmt.Fprintf(os.Stdout, "wrote %s (public,  0644)\n", pubPath)
			fmt.Fprintf(os.Stdout, "\nKeep %s safe — anyone with this file can sign BRP profiles.\n", privPath)
			fmt.Fprintf(os.Stdout, "Restart xhelix to load the new trust root.\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&outDir, "out-dir", defaultBRPProfileDir, "directory to write the key files into")
	cmd.Flags().StringVar(&signer, "signer", "", "signer name (stamped into every signed profile)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing key files")
	return cmd
}

// ─────────────────────────────────────────────────────────────────────
// brp generate --config PATH --signer NAME --key PATH [...]
// ─────────────────────────────────────────────────────────────────────
//
// One-shot path from "operator has a real nginx.conf on this host" to
// "signed BRP profile sitting in /etc/xhelix/brp/ ready for the daemon
// to enforce."
func newBRPGenerateCmd() *cobra.Command {
	var (
		configPath  string
		appHint     string
		signer      string
		keyPath     string
		outPath     string
		outDir      string
		profileID   string
		versionRange string
		osFamily    string
		confidence  string
		force       bool
	)
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Parse a config file + sign + write a *.signed.json profile",
		Long: `Reads --config, runs the appropriate parser, fills in a Profile, and
writes a *.signed.json envelope signed with --key.

Example:
  xhelixctl brp generate \
      --config /etc/nginx/nginx.conf \
      --signer ops-alice \
      --key /etc/xhelix/brp/ops-alice.key \
      --version-range 1.24.0 \
      --os-family debian12

The output path defaults to /etc/xhelix/brp/<profile-id>.signed.json. Restart
xhelix (or wait for the next library reload) to enforce the new profile.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				return errors.New("--config is required")
			}
			if signer == "" {
				return errors.New("--signer is required")
			}
			if keyPath == "" {
				return errors.New("--key is required")
			}
			app := appHint
			if app == "" {
				app = autodetectApp(configPath)
			}
			behavior, key, perr := parseByApp(app, configPath)
			if perr != nil {
				return fmt.Errorf("parse: %w", perr)
			}
			conf, err := parseConfidence(confidence)
			if err != nil {
				return err
			}
			if versionRange == "" {
				versionRange = "unspecified"
			}
			if osFamily != "" {
				key.OSFamily = osFamily
			}
			id := profileID
			if id == "" {
				id = fmt.Sprintf("brp-%s-%s-%s-%s-local",
					key.App, versionRange,
					nonEmptyDefault(key.OSFamily, "anyos"),
					nonEmptyDefault(key.Role, "default"))
			}
			profile := brp.Profile{
				SchemaVersion: brp.SchemaVersion,
				ProfileID:     id,
				Confidence:    conf,
				SampleCount:   1,
				FleetCount:    1,
				SigningEpoch:  time.Now().UTC().UnixNano(),
				VersionRange:  versionRange,
				Key:           key,
				Behavior:      behavior,
				SourceFiles:   []string{configPath},
			}
			if err := profile.Validate(); err != nil {
				return fmt.Errorf("validate: %w (protect-our-own backstop)", err)
			}
			// Non-fatal quality warnings — operators see these so they
			// can tighten the profile before it ships. Daemon does NOT
			// reject profiles for these.
			if warns := profile.QualityWarnings(); len(warns) > 0 {
				fmt.Fprintf(os.Stderr, "\nProfile quality warnings (non-fatal):\n")
				for _, w := range warns {
					fmt.Fprintf(os.Stderr, "  ! %s\n", w)
				}
				fmt.Fprintln(os.Stderr)
			}
			priv, err := loadPrivateKey(keyPath)
			if err != nil {
				return fmt.Errorf("load key: %w", err)
			}
			signed, err := brp.Sign(profile, signer, priv)
			if err != nil {
				return fmt.Errorf("sign: %w", err)
			}
			dst := outPath
			if dst == "" {
				dst = filepath.Join(outDir, id+".signed.json")
			}
			if !force {
				if _, err := os.Stat(dst); err == nil {
					return fmt.Errorf("%s already exists (pass --force to overwrite)", dst)
				}
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return fmt.Errorf("mkdir: %w", err)
			}
			if err := brp.WriteSigned(dst, signed); err != nil {
				return fmt.Errorf("write %s: %w", dst, err)
			}
			fmt.Fprintf(os.Stdout, "wrote %s\n", dst)
			fmt.Fprintf(os.Stdout, "  profile_id  = %s\n", id)
			fmt.Fprintf(os.Stdout, "  app/role    = %s / %s\n", key.App, key.Role)
			fmt.Fprintf(os.Stdout, "  signer      = %s\n", signer)
			fmt.Fprintf(os.Stdout, "  confidence  = %s\n", conf)
			fmt.Fprintf(os.Stdout, "\nRestart xhelix or `kill -SIGHUP $(pidof xhelix)` to enforce.\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to the live config file to parse")
	cmd.Flags().StringVar(&appHint, "app", "", "override app autodetection (nginx|apache|sshd|mysql|phpfpm)")
	cmd.Flags().StringVar(&signer, "signer", "", "signer name (must match a *.pub in trust root)")
	cmd.Flags().StringVar(&keyPath, "key", "", "path to the Ed25519 private key (from `brp keygen`)")
	cmd.Flags().StringVar(&outPath, "out", "", "output *.signed.json path (default: <out-dir>/<profile-id>.signed.json)")
	cmd.Flags().StringVar(&outDir, "out-dir", defaultBRPProfileDir, "output directory when --out is not set")
	cmd.Flags().StringVar(&profileID, "profile-id", "", "profile id (default derived from key)")
	cmd.Flags().StringVar(&versionRange, "version-range", "", "version range e.g. \"1.24.0\" (strict) or \"1.24.x\" (family)")
	cmd.Flags().StringVar(&osFamily, "os-family", "", "OS family e.g. debian12, ubuntu24")
	cmd.Flags().StringVar(&confidence, "confidence", "strict",
		"confidence class (strict|stable_fallback|constrained_adaptation)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite existing output file")
	return cmd
}

// validSigner restricts signer names so they can be used as filename
// components without escaping headaches.
func validSigner(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '_', r == '-', r == '.':
		default:
			return false
		}
	}
	return true
}

func parseConfidence(s string) (brp.ConfidenceClass, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "strict", "":
		return brp.ConfidenceStrict, nil
	case "stable_fallback":
		return brp.ConfidenceStableFallback, nil
	case "constrained_adaptation":
		return brp.ConfidenceConstrainedAdaptation, nil
	}
	return brp.ConfidenceUnknown,
		fmt.Errorf("unknown confidence %q (want strict|stable_fallback|constrained_adaptation)", s)
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("base64: %w", err)
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("decoded key length %d != %d", len(decoded), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(decoded), nil
}

func nonEmptyDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// ─────────────────────────────────────────────────────────────────────
// brp list
// ─────────────────────────────────────────────────────────────────────
func newBRPListCmd() *cobra.Command {
	var (
		dir     string
		appFlag string
		keysDir string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List loaded signed BRP profiles",
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := loadBRPMatcher(dir, keysDir)
			if err != nil {
				return err
			}
			ps := allProfiles(m)
			if appFlag != "" {
				filtered := ps[:0]
				for _, p := range ps {
					if p.Key.App == appFlag {
						filtered = append(filtered, p)
					}
				}
				ps = filtered
			}
			if len(ps) == 0 {
				fmt.Fprintf(os.Stdout, "(no profiles in %s)\n", dir)
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tAPP\tVERSION\tOS\tROLE\tCONFIDENCE\tSIGNED")
			for _, p := range ps {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					p.ProfileID,
					nonEmpty(p.Key.App),
					nonEmpty(p.VersionRange),
					nonEmpty(p.Key.OSFamily),
					nonEmpty(p.Key.Role),
					p.Confidence,
					time.Unix(0, p.SigningEpoch).UTC().Format(time.RFC3339),
				)
			}
			tw.Flush()
			fmt.Fprintf(os.Stdout, "\n%d profile(s) in %s\n", len(ps), dir)
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", defaultBRPProfileDir, "directory containing *.signed.json profiles")
	cmd.Flags().StringVar(&keysDir, "keys", defaultBRPKeysDir, "directory of trusted public keys (*.pub)")
	cmd.Flags().StringVar(&appFlag, "app", "", "filter by app (nginx|apache|sshd|mysql|phpfpm)")
	return cmd
}

// ─────────────────────────────────────────────────────────────────────
// brp show <profile-id>
// ─────────────────────────────────────────────────────────────────────
func newBRPShowCmd() *cobra.Command {
	var (
		dir     string
		keysDir string
	)
	cmd := &cobra.Command{
		Use:   "show <profile-id>",
		Short: "Show full detail for one BRP profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := loadBRPMatcher(dir, keysDir)
			if err != nil {
				return err
			}
			for _, p := range allProfiles(m) {
				if p.ProfileID == args[0] {
					printBRPDetail(os.Stdout, p)
					return nil
				}
			}
			return fmt.Errorf("no profile with id %q in %s", args[0], dir)
		},
	}
	cmd.Flags().StringVar(&dir, "dir", defaultBRPProfileDir, "directory containing *.signed.json profiles")
	cmd.Flags().StringVar(&keysDir, "keys", defaultBRPKeysDir, "directory of trusted public keys")
	return cmd
}

// ─────────────────────────────────────────────────────────────────────
// brp verify <path>
// ─────────────────────────────────────────────────────────────────────
func newBRPVerifyCmd() *cobra.Command {
	var keysDir string
	cmd := &cobra.Command{
		Use:   "verify <path-to-signed.json>",
		Short: "Cryptographically verify a signed BRP profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sp, err := brp.LoadSigned(args[0])
			if err != nil {
				return fmt.Errorf("load: %w", err)
			}
			pub, err := loadTrustedKeys(keysDir)
			if err != nil {
				return fmt.Errorf("load trust root: %w", err)
			}
			signerKey, ok := pub[sp.Signer]
			if !ok {
				fmt.Fprintf(os.Stderr,
					"REJECT: signer %q not in trust root %s (known: %v)\n",
					sp.Signer, keysDir, sortedKeys(pub))
				return errors.New("untrusted signer")
			}
			if err := brp.Verify(sp, signerKey); err != nil {
				fmt.Fprintf(os.Stderr, "REJECT: %v\n", err)
				return err
			}
			fmt.Fprintf(os.Stdout, "OK\n")
			fmt.Fprintf(os.Stdout, "  profile_id   = %s\n", sp.Profile.ProfileID)
			fmt.Fprintf(os.Stdout, "  signer       = %s\n", sp.Signer)
			fmt.Fprintf(os.Stdout, "  algorithm    = %s\n", sp.Algorithm)
			fmt.Fprintf(os.Stdout, "  signing_time = %s\n",
				time.Unix(0, sp.Profile.SigningEpoch).UTC().Format(time.RFC3339))
			return nil
		},
	}
	cmd.Flags().StringVar(&keysDir, "keys", defaultBRPKeysDir, "directory of trusted public keys")
	return cmd
}

// ─────────────────────────────────────────────────────────────────────
// brp parse <config-path>
// ─────────────────────────────────────────────────────────────────────
func newBRPParseCmd() *cobra.Command {
	var appHint string
	cmd := &cobra.Command{
		Use:   "parse <config-path>",
		Short: "Parse a live config file and show derived ProfileKey + behavior",
		Long: `Helps an operator see what BRP profile their actual config maps to.
The app type is auto-detected from filename when possible; use --app to override:
  nginx | apache | sshd | mysql | phpfpm`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]
			app := appHint
			if app == "" {
				app = autodetectApp(path)
			}
			behavior, key, err := parseByApp(app, path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: %v\n", err)
			}
			printParseResult(os.Stdout, app, path, behavior, key)
			return nil
		},
	}
	cmd.Flags().StringVar(&appHint, "app", "",
		"override autodetection: nginx | apache | sshd | mysql | phpfpm")
	return cmd
}

// ─────────────────────────────────────────────────────────────────────
// brp why <profile-id> action=...
// ─────────────────────────────────────────────────────────────────────
func newBRPWhyCmd() *cobra.Command {
	var (
		dir     string
		keysDir string
	)
	cmd := &cobra.Command{
		Use:   "why <profile-id> action=KIND [path=...] [target=...] [host=...] [port=N]",
		Short: "Explain what the runtime would decide for a hypothetical event",
		Long: `Replays a single hypothetical event through the BRP runtime against
the named profile. Useful for "why was this event flagged?" investigations.

Example:
  xhelixctl brp why brp-nginx-1.24.0-debian12-reverse-proxy-v1 \
      action=exec target=/bin/sh role=nginx-reverse-proxy

Returns one of: hard_deny / verify / allow / unknown — with the reason.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			m, err := loadBRPMatcher(dir, keysDir)
			if err != nil {
				return err
			}
			var match brp.MatchResult
			match.Confidence = brp.ConfidenceUnprofiled
			for _, p := range allProfiles(m) {
				if p.ProfileID == args[0] {
					pp := p
					match.Profile = &pp
					match.Confidence = p.Confidence
					match.Reason = "manual lookup"
					break
				}
			}
			if match.Profile == nil {
				fmt.Fprintf(os.Stderr,
					"warning: profile %q not found in %s — treating as Unprofiled\n",
					args[0], dir)
			}
			facts, ferr := parseWhyFacts(args[1:])
			if ferr != nil {
				return ferr
			}
			rt := brp.NewRuntime(brp.DefaultInvariants())
			decision, reason := rt.Evaluate(match, facts)
			fmt.Fprintf(os.Stdout, "decision: %s\n", decision)
			fmt.Fprintf(os.Stdout, "reason:   %s\n", reason)
			fmt.Fprintf(os.Stdout, "profile:  %s\n", args[0])
			if match.Profile != nil {
				fmt.Fprintf(os.Stdout, "confidence: %s\n", match.Confidence)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", defaultBRPProfileDir, "directory containing *.signed.json profiles")
	cmd.Flags().StringVar(&keysDir, "keys", defaultBRPKeysDir, "directory of trusted public keys")
	return cmd
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

func loadBRPMatcher(dir, keysDir string) (*brp.Matcher, error) {
	keys, err := loadTrustedKeys(keysDir)
	if err != nil {
		// Empty trust root is allowed — matcher loads nothing but
		// `parse` / `why` paths still work for hypothetical scenarios.
		keys = map[string]ed25519.PublicKey{}
	}
	m := brp.NewMatcher(keys)
	if _, err := os.Stat(dir); err == nil {
		loaded, rejected, lerr := m.LoadDir(dir)
		if lerr != nil {
			return nil, fmt.Errorf("load profiles: %w", lerr)
		}
		if rejected > 0 {
			fmt.Fprintf(os.Stderr,
				"warning: %d profile(s) rejected (signature or trust-root failure) — see daemon log\n",
				rejected)
		}
		_ = loaded
	}
	return m, nil
}

// loadTrustedKeys reads every *.pub file in dir as a base64-encoded
// Ed25519 public key. Filename (without extension) is the signer name.
// Files containing a json map "{\"signer_name\": \"base64key\"}" are also
// accepted, for operators who keep one keyring file.
//
// Empty/missing dir returns an empty map without error — the operator
// hasn't configured trust yet, which is the safe default for fresh
// installs.
func loadTrustedKeys(dir string) (map[string]ed25519.PublicKey, error) {
	out := map[string]ed25519.PublicKey{}
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("trust-root path %s is not a directory", dir)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		path := filepath.Join(dir, name)
		// Only consider files the daemon would also load.
		// The daemon (cmd/xhelix/foundation.go loadBRPTrustRoot) accepts
		// *.pub files only. The CLI additionally accepts *.json keyrings
		// for operators who keep one shared file — but never any other
		// extension, otherwise CLI and daemon disagree on the trust root.
		isPub := strings.HasSuffix(name, ".pub")
		isJSON := strings.HasSuffix(name, ".json")
		if !isPub && !isJSON {
			continue
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			continue
		}
		if isJSON {
			var keyring map[string]string
			if err := json.Unmarshal(data, &keyring); err == nil && len(keyring) > 0 {
				for signer, b64 := range keyring {
					if pub, perr := decodePub(b64); perr == nil {
						out[signer] = pub
					}
				}
			}
			continue
		}
		// Bare base64 .pub file — signer = filename stem.
		signer := strings.TrimSuffix(name, ".pub")
		pub, perr := decodePub(strings.TrimSpace(string(data)))
		if perr != nil {
			continue
		}
		out[signer] = pub
	}
	return out, nil
}

func decodePub(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("decoded key size %d != %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// allProfiles enumerates the Matcher's verified library.
func allProfiles(m *brp.Matcher) []brp.Profile {
	return m.Profiles()
}

func autodetectApp(path string) string {
	base := strings.ToLower(filepath.Base(path))
	switch {
	case strings.Contains(base, "nginx"):
		return "nginx"
	case strings.Contains(base, "httpd") || strings.Contains(base, "apache"):
		return "apache"
	case strings.HasPrefix(base, "sshd_") || base == "sshd_config":
		return "sshd"
	case strings.Contains(base, "my.cnf") || strings.HasSuffix(base, ".cnf"):
		return "mysql"
	case strings.Contains(base, "fpm") || strings.HasSuffix(base, ".conf") && strings.Contains(path, "fpm"):
		return "phpfpm"
	}
	return ""
}

func parseByApp(app, path string) (parser.ConfigDerivedBehavior, parser.ProfileKey, error) {
	switch app {
	case "nginx":
		return parser.ParseNginx(path)
	case "apache":
		return parser.ParseApache(path)
	case "sshd":
		return parser.ParseSSHD(path)
	case "mysql":
		return parser.ParseMySQL(path)
	case "phpfpm":
		return parser.ParsePHPFPM(path)
	}
	return parser.ConfigDerivedBehavior{}, parser.ProfileKey{},
		fmt.Errorf("unknown or undetectable app %q (use --app to override)", app)
}

func printParseResult(w *os.File, app, path string, b parser.ConfigDerivedBehavior, k parser.ProfileKey) {
	fmt.Fprintf(w, "Parsed: %s (%s)\n", path, app)
	fmt.Fprintf(w, "ProfileKey: %s\n", k.String())
	fmt.Fprintf(w, "  app                = %s\n", nonEmpty(k.App))
	fmt.Fprintf(w, "  role               = %s\n", nonEmpty(k.Role))
	fmt.Fprintf(w, "  feature_fingerprint= %s\n", nonEmpty(k.FeatureFingerprint))
	fmt.Fprintln(w)
	if len(b.Features) > 0 {
		fmt.Fprintf(w, "Features:        %s\n", strings.Join(b.Features, " "))
	}
	if len(b.ListenPorts) > 0 {
		fmt.Fprintf(w, "ListenPorts:     %v\n", b.ListenPorts)
	}
	if len(b.ListenSockets) > 0 {
		fmt.Fprintf(w, "ListenSockets:   %v\n", b.ListenSockets)
	}
	if len(b.ReadRoots) > 0 {
		fmt.Fprintf(w, "ReadRoots:       %s\n", strings.Join(b.ReadRoots, ", "))
	}
	if len(b.WriteRoots) > 0 {
		fmt.Fprintf(w, "WriteRoots:      %s\n", strings.Join(b.WriteRoots, ", "))
	}
	if len(b.ExecAllowed) > 0 {
		fmt.Fprintf(w, "ExecAllowed:     %s\n", strings.Join(b.ExecAllowed, ", "))
	}
	if len(b.UpstreamHosts) > 0 {
		fmt.Fprintf(w, "UpstreamHosts:   %s\n", strings.Join(b.UpstreamHosts, ", "))
	}
	if len(b.UpstreamSockets) > 0 {
		fmt.Fprintf(w, "UpstreamSockets: %s\n", strings.Join(b.UpstreamSockets, ", "))
	}
	if len(b.Modules) > 0 {
		fmt.Fprintf(w, "Modules:         %s\n", strings.Join(b.Modules, ", "))
	}
	if len(b.ParseWarnings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "ParseWarnings (%d):\n", len(b.ParseWarnings))
		for i, p := range b.ParseWarnings {
			if i >= 10 {
				fmt.Fprintf(w, "  ... (%d more)\n", len(b.ParseWarnings)-10)
				break
			}
			fmt.Fprintf(w, "  - %s\n", p)
		}
	}
}

func printBRPDetail(w *os.File, p brp.Profile) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "ProfileID:\t%s\n", p.ProfileID)
	fmt.Fprintf(tw, "SchemaVersion:\t%d\n", p.SchemaVersion)
	fmt.Fprintf(tw, "Confidence:\t%s\n", p.Confidence)
	fmt.Fprintf(tw, "VersionRange:\t%s\n", p.VersionRange)
	fmt.Fprintf(tw, "SampleCount:\t%d\n", p.SampleCount)
	fmt.Fprintf(tw, "FleetCount:\t%d\n", p.FleetCount)
	fmt.Fprintf(tw, "SigningEpoch:\t%s\n", time.Unix(0, p.SigningEpoch).UTC().Format(time.RFC3339))
	fmt.Fprintf(tw, "Key.App:\t%s\n", p.Key.App)
	fmt.Fprintf(tw, "Key.VersionFamily:\t%s\n", p.Key.VersionFamily)
	fmt.Fprintf(tw, "Key.OSFamily:\t%s\n", p.Key.OSFamily)
	fmt.Fprintf(tw, "Key.PackageOrigin:\t%s\n", p.Key.PackageOrigin)
	fmt.Fprintf(tw, "Key.Role:\t%s\n", p.Key.Role)
	fmt.Fprintf(tw, "Key.FeatureFingerprint:\t%s\n", p.Key.FeatureFingerprint)
	tw.Flush()
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Behavior:")
	fmt.Fprintf(w, "  Role:            %s\n", p.Behavior.Role)
	fmt.Fprintf(w, "  Features:        %v\n", p.Behavior.Features)
	fmt.Fprintf(w, "  ListenPorts:     %v\n", p.Behavior.ListenPorts)
	fmt.Fprintf(w, "  ListenSockets:   %v\n", p.Behavior.ListenSockets)
	fmt.Fprintf(w, "  ReadRoots:       %v\n", p.Behavior.ReadRoots)
	fmt.Fprintf(w, "  WriteRoots:      %v\n", p.Behavior.WriteRoots)
	fmt.Fprintf(w, "  ExecAllowed:     %v\n", p.Behavior.ExecAllowed)
	fmt.Fprintf(w, "  UpstreamHosts:   %v\n", p.Behavior.UpstreamHosts)
	fmt.Fprintf(w, "  UpstreamSockets: %v\n", p.Behavior.UpstreamSockets)
	fmt.Fprintf(w, "  Modules:         %v\n", p.Behavior.Modules)
}

func parseWhyFacts(kvs []string) (brp.EventFacts, error) {
	f := brp.EventFacts{}
	for _, kv := range kvs {
		idx := strings.IndexByte(kv, '=')
		if idx <= 0 {
			return f, fmt.Errorf("expected key=value, got %q", kv)
		}
		k, v := kv[:idx], kv[idx+1:]
		switch k {
		case "action":
			f.Action = v
		case "path":
			f.Path = v
		case "mode":
			f.Mode = v
		case "target", "target_image":
			f.TargetImage = v
		case "host", "dest_host":
			f.DestHost = v
		case "port", "dest_port":
			n, err := strconv.ParseUint(v, 10, 16)
			if err != nil {
				return f, fmt.Errorf("invalid port %q: %w", v, err)
			}
			f.DestPort = uint16(n)
		case "socket", "dest_socket":
			f.DestSocket = v
		case "role":
			f.Role = v
		case "pid":
			n, err := strconv.ParseUint(v, 10, 32)
			if err != nil {
				return f, fmt.Errorf("invalid pid %q: %w", v, err)
			}
			f.PID = uint32(n)
		default:
			return f, fmt.Errorf("unknown fact key %q", k)
		}
	}
	if f.Action == "" {
		return f, errors.New("action= is required")
	}
	return f, nil
}

func nonEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func sortedKeys(m map[string]ed25519.PublicKey) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

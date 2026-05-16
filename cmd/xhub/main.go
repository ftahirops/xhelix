// Command xhub is the fleet-baseline hub. Agents (xhelix) ship
// per-binary feature aggregates here on a schedule; xhub serves them
// back as cross-fleet "rare endpoint" lists agents use to elevate
// detection severity.
//
// Usage:
//
//	xhub run --bind :18444 --data /var/lib/xhub --token-file /etc/xhub/token
//
// xhub is intentionally separate from xhelix: a single hub serves
// many agents, and operators may want to run it on dedicated
// hardware behind their own TLS termination.
package main

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/xhelix/xhelix/pkg/baselinehub"
	"github.com/xhelix/xhelix/pkg/version"
)

func main() {
	root := &cobra.Command{
		Use:   "xhub",
		Short: "xhelix fleet-baseline hub",
	}
	root.AddCommand(newRunCmd())
	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Printf("xhub %s (commit %s)\n", version.Version, version.Commit)
		},
	})
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRunCmd() *cobra.Command {
	var (
		bind      string
		dataDir   string
		tokenFile string
		certFile  string
		keyFile   string
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the xhub HTTP(S) server",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runHub(bind, dataDir, tokenFile, certFile, keyFile)
		},
	}
	cmd.Flags().StringVar(&bind, "bind", "127.0.0.1:18444", "HTTP(S) listen address")
	cmd.Flags().StringVar(&dataDir, "data", "/var/lib/xhub", "Directory for ingested feed data")
	cmd.Flags().StringVar(&tokenFile, "token-file", "",
		"Path to file containing the bearer token agents use (empty = auth disabled, dev only)")
	cmd.Flags().StringVar(&certFile, "tls-cert", "", "TLS cert path (omit for plain HTTP)")
	cmd.Flags().StringVar(&keyFile, "tls-key", "", "TLS key path")
	return cmd
}

func runHub(bind, dataDir, tokenFile, certFile, keyFile string) error {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	log.Info("xhub starting", "version", version.Version,
		"commit", version.Commit, "bind", bind, "data", dataDir)

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("mkdir data dir: %w", err)
	}
	store, err := baselinehub.NewStore(dataDir)
	if err != nil {
		return fmt.Errorf("hub store: %w", err)
	}
	defer store.Close()

	token := ""
	if tokenFile != "" {
		body, err := os.ReadFile(tokenFile)
		if err != nil {
			return fmt.Errorf("read token file: %w", err)
		}
		token = strings.TrimSpace(string(body))
		if token == "" {
			return fmt.Errorf("token file is empty")
		}
		log.Info("auth enabled", "token_file", tokenFile)
	} else {
		log.Warn("auth DISABLED — token-file empty (dev mode)")
	}

	srv := baselinehub.NewServer(baselinehub.ServerConfig{
		Store:     store,
		AuthToken: token,
		Logger:    log,
	})

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)

	httpsSrv := &http.Server{
		Addr:              bind,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, cancel := signal.NotifyContext(cmd_ctx_root(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		if certFile != "" && keyFile != "" {
			httpsSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			log.Info("listening (HTTPS)", "addr", bind)
			errCh <- httpsSrv.ListenAndServeTLS(certFile, keyFile)
		} else {
			log.Info("listening (HTTP — token over the wire is sniffable; production should set tls)", "addr", bind)
			errCh <- httpsSrv.ListenAndServe()
		}
	}()

	notifyReady()

	select {
	case <-ctx.Done():
		log.Info("xhub stopping")
	case err := <-errCh:
		if err != http.ErrServerClosed {
			log.Error("server error", "err", err)
			return err
		}
	}
	stopCtx, stopCancel := contextWithTimeout(time.Minute)
	defer stopCancel()
	_ = httpsSrv.Shutdown(stopCtx)
	log.Info("xhub stopped")
	_ = filepath.Join // keep filepath import live for future config-discovery code
	return nil
}

// secureui — demonstrates the protection layer.
//
// Binds 0.0.0.0:18443 (HTTPS) and 0.0.0.0:18080 (HTTP redirect) and
// requires:
//   1. Source IP in the allow-list (auto-detected SSH IP + explicit list)
//   2. Bearer token (printed once at startup)
//   3. CSRF token on POST/PUT/DELETE
//   4. Rate limit 10/sec/source
//
// Then it runs the same attack-population flow as uidemo so the
// dashboard has live data, and prints test commands you can use to
// probe it.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/xhelix/xhelix/ui/web"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Self-signed cert in /tmp
	certDir := "/tmp/xhelix-tls"
	os.MkdirAll(certDir, 0o755)
	certPath := filepath.Join(certDir, "ui.crt")
	keyPath := filepath.Join(certDir, "ui.key")

	allowedExtra := []string{}
	if v := os.Getenv("XHELIX_ALLOW_IP"); v != "" {
		for _, p := range strings.Split(v, ",") {
			allowedExtra = append(allowedExtra, strings.TrimSpace(p))
		}
	}

	if err := web.EnsureSelfSignedCert(certPath, keyPath, allowedExtra); err != nil {
		fmt.Printf("cert: %v\n", err)
		os.Exit(1)
	}
	fp, _ := web.CertFingerprint(certPath)
	fmt.Printf("[secureui] self-signed cert: %s\n", certPath)
	fmt.Printf("[secureui] fingerprint:       %s\n", fp)

	// Configure auth
	guard, err := web.NewAuthGuard(web.AuthConfig{
		AllowIPs:      allowedExtra,
		AutoDetectSSH: true, // pulls $SSH_CONNECTION
		TokenFile:     filepath.Join(certDir, "ui-token"),
		AuditLogPath:  filepath.Join(certDir, "ui-audit.log"),
	})
	if err != nil {
		fmt.Printf("auth: %v\n", err)
		os.Exit(1)
	}
	defer guard.Stop()

	// Build the actual app (re-uses uidemo's logic).
	srv := buildApp(ctx)

	// Compose the protected mux: every request goes through guard.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui", http.StatusFound)
	})
	srv.attachUI(mux)
	protected := guard.Wrap(mux)

	// HTTP redirect to HTTPS
	go func() {
		err := http.ListenAndServe("0.0.0.0:18080",
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				host := r.Host
				if i := strings.Index(host, ":"); i > 0 {
					host = host[:i]
				}
				http.Redirect(w, r, "https://"+host+":18443"+r.URL.Path,
					http.StatusMovedPermanently)
			}))
		if err != nil {
			fmt.Printf("[secureui] http: %v\n", err)
		}
	}()

	// HTTPS server
	httpsSrv := &http.Server{
		Addr:    "0.0.0.0:18443",
		Handler: protected,
	}

	fmt.Printf("[secureui] listening on https://0.0.0.0:18443\n")
	fmt.Printf("[secureui] http redirect on  http://0.0.0.0:18080  -> https\n")
	fmt.Printf("[secureui] audit log:         %s\n", filepath.Join(certDir, "ui-audit.log"))
	fmt.Printf("\n")
	fmt.Printf("[secureui] try these from your shell:\n")
	fmt.Printf("\n")
	tok, _ := os.ReadFile(filepath.Join(certDir, "ui-token"))
	tokenStr := strings.TrimSpace(string(tok))
	fmt.Printf("    # No token, no IP allow ->  401 / 403\n")
	fmt.Printf("    curl -ksI https://127.0.0.1:18443/ui\n")
	fmt.Printf("\n")
	fmt.Printf("    # With token (loopback already allowed) ->  200\n")
	fmt.Printf("    curl -ksI -H 'Authorization: Bearer %s' https://127.0.0.1:18443/ui\n", tokenStr)
	fmt.Printf("\n")
	fmt.Printf("    # Pretending to come from a non-allow-listed IP via XFF -> 403\n")
	fmt.Printf("    curl -ksI -H 'Authorization: Bearer %s' \\\n", tokenStr)
	fmt.Printf("         -H 'X-Forwarded-For: 198.51.100.99' \\\n")
	fmt.Printf("         https://127.0.0.1:18443/ui  # XFF only honoured if TrustForwardedFor=true\n")
	fmt.Printf("\n")

	go populate(ctx, srv)

	go func() { _ = httpsSrv.ListenAndServeTLS(certPath, keyPath) }()

	<-ctx.Done()
}

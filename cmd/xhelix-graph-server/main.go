// Command xhelix-graph-server serves the source-graph HTTP API.
//
// Reads the same SQLite file the xhelix daemon writes
// (/var/lib/xhelix/source.db by default). SQLite WAL mode permits
// multiple concurrent readers alongside the daemon's writer.
//
// Mount this behind nginx with a location block proxying
// /api/v1/source/ to localhost:9082. It serves NO content of its own
// besides the API — the correlation-graph UI is shipped from the
// dashboard's docs/dashboard/ static directory.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/xhelix/xhelix/pkg/source"
)

func main() {
	var (
		addr   = flag.String("addr", "127.0.0.1:9082", "listen address")
		dbPath = flag.String("db", "/var/lib/xhelix/source.db", "path to source.db (written by xhelix daemon)")
	)
	flag.Parse()

	st, err := source.Open(*dbPath)
	if err != nil {
		log.Fatalf("open %s: %v", *dbPath, err)
	}
	defer st.Close()
	fmt.Fprintf(os.Stderr, "[graph-server] opened %s\n", *dbPath)

	mux := http.NewServeMux()
	mux.Handle("/api/v1/source/", source.NewHTTPHandler(st))
	mux.HandleFunc("/api/v1/source", listAnchorsHandler(st))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           withCORS(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		fmt.Fprintf(os.Stderr, "[graph-server] shutting down\n")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	fmt.Fprintf(os.Stderr, "[graph-server] listening on http://%s\n", *addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}
}

// listAnchorsHandler returns the list of source anchors so the UI can
// present a selector / sidebar of available sessions.
func listAnchorsHandler(st *source.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		anchors, err := st.List(ctx, 200)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `[`)
		for i, a := range anchors {
			if i > 0 {
				fmt.Fprint(w, `,`)
			}
			// Build event count per anchor for the picker.
			cnt, _ := st.EventCount(ctx, a.ID, source.TimeWindow{})
			parent := uint64(0)
			if a.ParentAnchorID != 0 {
				parent = uint64(a.ParentAnchorID)
			}
			// IDs serialised as strings — they're uint64 (Unix nanos)
			// which JavaScript Numbers can't represent precisely
			// beyond 2^53. Treat as opaque tokens on the wire.
			fmt.Fprintf(w,
				`{"id":"%d","kind":%q,"actor":%q,"source_ip":%q,"unit":%q,"created":%q,"parent_anchor_id":"%d","event_count":%d}`,
				uint64(a.ID), a.Kind.String(), jsonEsc(a.Actor), a.SourceIP,
				jsonEsc(a.Unit), a.CreatedAt.UTC().Format(time.RFC3339), parent, cnt)
		}
		fmt.Fprint(w, `]`)
	}
}

// withCORS allows the dashboard origin to call the API even when the
// proxy doesn't strip CORS headers. Tightened by nginx in production.
func withCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(204)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// jsonEsc minimal JSON-escape for actor / unit fields. Avoids pulling
// encoding/json for this hot list endpoint; only handles the cases
// realistic operator inputs produce.
func jsonEsc(s string) string {
	r := ""
	for _, c := range s {
		switch c {
		case '"', '\\':
			r += "\\" + string(c)
		case '\n':
			r += "\\n"
		case '\t':
			r += "\\t"
		default:
			if c < 0x20 {
				r += " "
			} else {
				r += string(c)
			}
		}
	}
	return r
}

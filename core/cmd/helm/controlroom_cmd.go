package main

import (
	"embed"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
)

//go:embed controlroom_assets
var controlRoomAssets embed.FS

// runControlRoom starts the HELM control-room web UI.
//
// Usage:
//
//	helm control-room --port 8090
//
// This serves a minimal dashboard for:
//   - Viewing live proxy receipts
//   - Inspecting ProofGraph DAG
//   - Browsing conformance reports
//   - Monitoring budget utilization
//
// Exit codes:
//
//	0 = clean shutdown
//	2 = config error
func runControlRoom(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("control-room", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		port        int
		receiptsDir string
	)

	cmd.IntVar(&port, "port", 8090, "Control-room UI port")
	cmd.StringVar(&receiptsDir, "receipts-dir", "./helm-receipts", "Directory with proxy receipts")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	mux := http.NewServeMux()

	// Serve embedded SPA assets
	mux.Handle("/", http.FileServer(http.FS(controlRoomAssets)))

	// API endpoints
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","component":"control-room"}`))
	})

	mux.HandleFunc("/api/receipts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Placeholder: in production, read from receipts-dir JSONL
		_, _ = w.Write([]byte(`{"receipts":[],"message":"wire to receipt store"}`))
	})

	mux.HandleFunc("/api/proofgraph", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Placeholder: in production, serve proofgraph.json from receipts-dir
		_, _ = w.Write([]byte(`{"nodes":[],"message":"wire to proofgraph store"}`))
	})

	mux.HandleFunc("/api/budget", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"daily_used":0,"daily_limit":0,"monthly_used":0,"monthly_limit":0}`))
	})

	addr := fmt.Sprintf(":%d", port)
	_, _ = fmt.Fprintf(stdout, "HELM Control Room\n")
	_, _ = fmt.Fprintf(stdout, "  UI:       http://localhost:%d\n", port)
	_, _ = fmt.Fprintf(stdout, "  Receipts: %s\n", receiptsDir)
	_, _ = fmt.Fprintf(stdout, "\nOpen your browser to start monitoring.\n")

	log.Printf("control-room listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	return 0
}

func init() {
	Register(Subcommand{Name: "control-room", Aliases: []string{}, Usage: "Launch the Control Room UI", RunFn: runControlRoom})
}

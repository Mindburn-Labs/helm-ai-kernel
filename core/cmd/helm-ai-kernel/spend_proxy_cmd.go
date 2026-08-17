// quantum_posture: spend-proxy signs BudgetVerdict receipts with a classical
// Ed25519 issuer key (seeded via HELM_SPEND_PROXY_SIGNING_SEED or --sign) and
// hashes receipt payloads with SHA-256; no post-quantum primitives are used in
// this file.

// spend_proxy_cmd.go — `helm-ai-kernel spend-proxy` runs the governed spend
// path end-to-end as a local OpenAI-compatible proxy (HELM-615):
//
//	SPEND3 RouteQuote engine + GovernedGateway routes
//	+ real cloud ProviderDispatch (OpenRouter-style base URL, key from env)
//	+ in-process signed BudgetVerdict issuance (trusted-key registry on disk)
//	+ durable JSONL RouteQuote/BudgetVerdict/Usage/Settlement receipts
//
// There is no unreceipted dispatch path: the authorized quote is fsynced to
// the receipt log before any provider call, and a store failure refuses
// dispatch. `helm-ai-kernel spend-proxy export` renders the captured receipts
// into offline-verifiable spend EvidencePacks.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/spendproxy"
)

// runSpendProxyCmd dispatches `spend-proxy` and its `export` subaction.
//
// Exit codes: 0 = clean shutdown / successful export, 2 = config error,
// 1 = runtime failure.
func runSpendProxyCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "export" {
		return runSpendProxyExport(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "up" {
		args = args[1:]
	}

	cmd := flag.NewFlagSet("spend-proxy", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var (
		configPath  string
		addr        string
		port        int
		receiptsDir string
		upstream    string
		apiKey      string
		signSecret  string
	)
	cmd.StringVar(&configPath, "config", "", "Path to the spend-proxy JSON config (required; prices, envelopes, defaults)")
	cmd.StringVar(&addr, "addr", "127.0.0.1", "Listen address (loopback by default; the proxy holds a live provider key)")
	cmd.IntVar(&port, "port", 9095, "Listen port")
	cmd.StringVar(&receiptsDir, "receipts-dir", "./helm-spend-receipts", "Directory for the durable receipt log and trusted-key registry")
	cmd.StringVar(&upstream, "upstream", "https://openrouter.ai/api/v1", "Upstream OpenAI-compatible base URL (includes /v1)")
	cmd.StringVar(&apiKey, "api-key", "", "Upstream API key (or set OPENROUTER_API_KEY)")
	cmd.StringVar(&signSecret, "sign", "", "Ed25519 signing seed for BudgetVerdict receipts (or set HELM_SPEND_PROXY_SIGNING_SEED; empty generates a per-run key)")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if configPath == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --config is required")
		_, _ = fmt.Fprintln(stderr, "Run `helm-ai-kernel spend-proxy --help` for usage.")
		return 2
	}
	if apiKey == "" {
		apiKey = os.Getenv("OPENROUTER_API_KEY")
	}
	if apiKey == "" {
		_, _ = fmt.Fprintln(stderr, "Error: upstream API key is required (--api-key or OPENROUTER_API_KEY)")
		return 2
	}
	if signSecret == "" {
		signSecret = os.Getenv("HELM_SPEND_PROXY_SIGNING_SEED")
	}

	cfg, sourceHash, err := spendproxy.LoadConfig(configPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	server, err := spendproxy.NewServer(spendproxy.ServerOptions{
		Config:          cfg,
		SourceHash:      sourceHash,
		ReceiptsDir:     receiptsDir,
		UpstreamBaseURL: upstream,
		UpstreamAPIKey:  apiKey,
		SigningSecret:   signSecret,
		Logf: func(format string, a ...any) {
			_, _ = fmt.Fprintf(stderr, format+"\n", a...)
		},
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	defer server.Close()

	replay := server.ReplaySummary()
	_, _ = fmt.Fprintf(stdout, "spend-proxy: governed OpenAI-compatible proxy\n")
	_, _ = fmt.Fprintf(stdout, "  listen:        http://%s\n", net.JoinHostPort(addr, strconv.Itoa(port)))
	_, _ = fmt.Fprintf(stdout, "  upstream:      %s\n", upstream)
	_, _ = fmt.Fprintf(stdout, "  config:        %s (source hash %s)\n", configPath, sourceHash)
	_, _ = fmt.Fprintf(stdout, "  receipts:      %s\n", server.ReceiptLogPath())
	_, _ = fmt.Fprintf(stdout, "  signing key:   %s (registered in trusted-key registry)\n", server.SigningKeyID())
	_, _ = fmt.Fprintf(stdout, "  balance:       %d cents available\n", server.BalanceCents())
	if replay.RestoredSettlements > 0 || replay.DebitedCents > 0 {
		_, _ = fmt.Fprintf(stdout, "  replayed:      %d settlements, %d cents already debited\n",
			replay.RestoredSettlements, replay.DebitedCents)
	}

	httpServer := &http.Server{
		Addr:              net.JoinHostPort(addr, strconv.Itoa(port)),
		Handler:           server.Handler(),
		ReadHeaderTimeout: 30 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- httpServer.ListenAndServe() }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		_, _ = fmt.Fprintf(stdout, "spend-proxy: received %s, shutting down\n", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
		return 0
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
		return 0
	}
}

// runSpendProxyExport renders captured receipts into offline-verifiable spend
// EvidencePacks under --out.
func runSpendProxyExport(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("spend-proxy export", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	var (
		receiptsDir string
		outDir      string
		intent      string
		jsonOut     bool
	)
	cmd.StringVar(&receiptsDir, "receipts-dir", "./helm-spend-receipts", "Directory holding the receipt log and trusted-key registry")
	cmd.StringVar(&outDir, "out", "./helm-spend-evidence", "Output directory for spend EvidencePacks")
	cmd.StringVar(&intent, "intent", "", "Export only this spend intent id (default: all)")
	cmd.BoolVar(&jsonOut, "json", false, "Print the export summary as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}

	results, err := spendproxy.ExportEvidencePacks(receiptsDir, outDir, intent)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
		return 0
	}
	for _, res := range results {
		status := "offline-verified"
		if !res.OfflineVerified {
			status = "VERIFICATION FAILED"
		}
		sig := "unsigned"
		if res.SignatureVerified {
			sig = "signature verified (" + res.SignatureKeyID + ")"
		}
		_, _ = fmt.Fprintf(stdout, "%s: %s, %s -> %s\n", res.SpendIntentID, status, sig, res.OutputDir)
	}
	_, _ = fmt.Fprintf(stdout, "%d spend EvidencePack(s) exported to %s\n", len(results), outDir)
	return 0
}

func init() {
	Register(Subcommand{
		Name:    "spend-proxy",
		Aliases: []string{},
		Usage:   "Governed OpenAI-compatible spend proxy (SPEND3 quotes, signed verdicts, durable receipts)",
		RunFn:   runSpendProxyCmd,
	})
}

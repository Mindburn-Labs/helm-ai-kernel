package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/registry"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/store"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/store/ledger"

	_ "github.com/lib/pq" // Postgres Driver
)

// Dispatcher
func main() {
	os.Exit(Run(os.Args, os.Stdout, os.Stderr))
}

// startServer is a variable to allow mocking in tests
var startServer = runServer

// Run is the entrypoint for testing
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		// Default to server
		startServer()
		return 0
	}

	// Attempt to dispatch from registry
	if code, ok := Dispatch(args[1], args[2:], stdout, stderr); ok {
		return code
	}

	// Handle specific global commands that don't fit the registry pattern
	switch args[1] {
	case "server", "serve":
		startServer()
		return 0

	case "trust":
		if len(args) < 3 {
			_, _ = fmt.Fprintln(stderr, "Usage: helm trust <add-key|revoke-key|list-keys>")
			return 2
		}
		return runTrustCmd(args[2:], stdout, stderr)
	case "threat":
		if len(args) < 3 {
			_, _ = fmt.Fprintln(stderr, "Usage: helm threat <scan|test> [flags]")
			return 2
		}
		return runThreatCmd(args[2:], stdout, stderr)
	case "run":
		if len(args) > 2 && args[2] == "maintenance" {
			return runMaintenanceCmd(args[3:], stdout, stderr)
		}
		fmt.Fprintln(stderr, "Usage: helm run maintenance [--once|--schedule]")
		return 2
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "%sHELM%s %s (%s)\n", ColorBold, ColorReset, displayVersion(), displayCommit())
		fmt.Fprintf(stdout, "  Report Schema:          %s\n", reportSchemaVersion)
		fmt.Fprintf(stdout, "  EvidencePack Schema:    1\n")
		fmt.Fprintf(stdout, "  Compatibility Schema:   1\n")
		fmt.Fprintf(stdout, "  MCP Bundle Schema:      1\n")
		fmt.Fprintf(stdout, "  Build Time:             %s\n", displayBuildTime())
		return 0
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	default:
		if args[1][0] == '-' {
			startServer() // Default backward compat behavior for flags passed without 'server'
			return 0
		}
		_, _ = fmt.Fprintf(stderr, "Unknown command: %s\n", args[1])
		printUsage(stderr)
		return 2
	}
}

// ANSI Colors
const (
	ColorReset  = "\033[0m"
	ColorBold   = "\033[1m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorGray   = "\033[37m"
)

//nolint:gocognit,gocyclo
func runServer() {
	fmt.Fprintf(os.Stdout, "%sHELM Kernel starting...%s\n", ColorBold+ColorBlue, ColorReset)
	ctx := context.Background()
	logger := slog.Default()

	var (
		db  *sql.DB
		err error
	)

	// 0.2 Connect to Database (Infrastructure)
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		fmt.Fprintf(os.Stdout, "ℹ️  DATABASE_URL not set. Falling back to %sLite Mode%s (SQLite).\n", ColorBold+ColorCyan, ColorReset)
		db, _, _, err = setupLiteMode(ctx)
		if err != nil {
			log.Fatalf("Failed to setup Lite Mode: %v", err)
		}
	} else {
		db, err = sql.Open("postgres", dbURL)
		if err != nil {
			log.Fatalf("Failed to connect to DB: %v", err)
		}
		if err := db.PingContext(ctx); err != nil {
			log.Fatalf("DB Ping failed: %v", err)
		}
		log.Println("[helm] postgres: connected")

		// Initialize Postgres stores (used by Services layer)
		pl := ledger.NewPostgresLedger(db)
		if err := pl.Init(ctx); err != nil {
			log.Fatalf("Failed to init ledger: %v", err)
		}
		_ = pl // Ledger is managed via Services layer
		ps := store.NewPostgresReceiptStore(db)
		if err := ps.Init(ctx); err != nil {
			log.Fatalf("Failed to init receipt store: %v", err)
		}
		_ = ps // Receipt store is managed via Services layer
	}

	// 1. Initialize Kernel Layers

	// Signing Authority
	signer, err := loadOrGenerateSigner()
	if err != nil {
		log.Fatalf("Failed to init signer: %v", err)
	}
	verifier, _ := crypto.NewEd25519Verifier(signer.PublicKeyBytes())
	fmt.Fprintf(os.Stdout, "🔑 Trust Root: %s%s%s\n", ColorBold+ColorGreen, signer.PublicKey(), ColorReset)

	// 2. Registry
	reg := registry.NewPostgresRegistry(db)
	if err := reg.Init(ctx); err != nil {
		log.Fatalf("Failed to init registry: %v", err)
	}
	log.Println("[helm] registry: ready")

	// Pack verification is handled via the CLI subcommands (pack verify, etc.)

	// Artifact Store
	artStore, _ := artifacts.NewFileStore("data/artifacts")
	artRegistry := artifacts.NewRegistry(artStore, verifier)

	// === SUBSYSTEM WIRING ===
	services, svcErr := NewServices(ctx, db, artStore, logger)
	if svcErr != nil {
		log.Printf("Services init (non-fatal, degraded mode): %v", svcErr)
	}

	// 2.5 PRG & Guardian
	ruleGraph := prg.NewGraph()
	// Bootstrap a minimal allow rule so governed chat inference is usable out of the box.
	// Production deployments should replace this with a loaded policy bundle.
	if err := ruleGraph.AddRule("LLM_INFERENCE", prg.RequirementSet{
		ID:    "bootstrap-llm-inference",
		Logic: prg.AND,
	}); err != nil {
		log.Fatalf("Failed to add bootstrap PRG rule: %v", err)
	}

	// Guardian
	guard := guardian.NewGuardian(signer, ruleGraph, artRegistry)

	// Executor and MCP catalog are managed via the Services layer
	// (see services.go and subsystems.go for route wiring)

	// Register Subsystem Routes
	var extraRoutes func(*http.ServeMux)
	if services != nil {
		services.Guardian = guard
		extraRoutes = func(mux *http.ServeMux) {
			RegisterSubsystemRoutes(mux, services)
		}
	}

	// Start API Server
	port := 8080
	if envPort := os.Getenv("HELM_PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil {
			port = p
		}
	}
	mux := http.NewServeMux()
	if extraRoutes != nil {
		extraRoutes(mux)
	}
	server := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		log.Printf("[helm] API server: :%d", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("API server failed", "error", err)
		}
	}()

	// Health Server
	healthPort := 8081
	if envHP := os.Getenv("HELM_HEALTH_PORT"); envHP != "" {
		if p, err := strconv.Atoi(envHP); err == nil {
			healthPort = p
		}
	}
	healthMux := http.NewServeMux()
	healthHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}
	healthMux.HandleFunc("/health", healthHandler)
	healthMux.HandleFunc("/healthz", healthHandler)
	healthServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", healthPort),
		Handler:           healthMux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		log.Printf("[helm] health server: :%d", healthPort)
		if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[helm] health server error: %v", err)
		}
	}()

	log.Printf("[helm] ready: http://localhost:%d", port)
	log.Println("[helm] press ctrl+c to stop")

	// Graceful Shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Println("[helm] shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("[helm] API server shutdown error: %v", err)
	}
	if err := healthServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("[helm] health server shutdown error: %v", err)
	}
	log.Println("[helm] shutdown complete")
}

func init() {
	Register(Subcommand{
		Name:    "health",
		Aliases: []string{},
		Usage:   "Check local HELM server health",
		RunFn:   func(args []string, stdout, stderr io.Writer) int { return runHealthCmd(stdout, stderr) },
	})
}

func runHealthCmd(out, errOut io.Writer) int {
	resp, err := http.Get("http://localhost:8081/healthz")
	if err != nil {
		fmt.Fprintf(errOut, "Health check failed: %v\n", err)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(errOut, "Health check failed: status %d\n", resp.StatusCode)
		return 1
	}

	fmt.Fprintln(out, "OK")
	return 0
}

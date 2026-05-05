package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	helmapi "github.com/Mindburn-Labs/helm-oss/core/pkg/api"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/artifacts"
	helmauth "github.com/Mindburn-Labs/helm-oss/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/pdp"
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

type serverOptions struct {
	Mode       string
	BindAddr   string
	Port       int
	DataDir    string
	SQLitePath string
	PolicyPath string
	Console    bool
	ConsoleDir string
	JSON       bool
	Stdout     io.Writer
	Stderr     io.Writer
}

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
		return runServerCommand(args[1], args[2:], stdout, stderr)

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
	runServerWithOptions(serverOptions{Mode: "server", Stdout: os.Stdout, Stderr: os.Stderr})
}

//nolint:gocognit,gocyclo
func runServerWithOptions(opts serverOptions) {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	fmt.Fprintf(opts.Stdout, "%sHELM Kernel starting...%s\n", ColorBold+ColorBlue, ColorReset)
	ctx := context.Background()
	logger := slog.Default()
	dataDir := opts.DataDir
	if dataDir == "" {
		dataDir = "data"
	}

	var (
		db           *sql.DB
		receiptStore store.ReceiptStore
		err          error
	)

	// 0.2 Connect to Database (Infrastructure)
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		fmt.Fprintf(opts.Stdout, "ℹ️  DATABASE_URL not set. Falling back to %sLite Mode%s (SQLite).\n", ColorBold+ColorCyan, ColorReset)
		if opts.SQLitePath != "" {
			db, _, receiptStore, err = setupLiteModeWithDBPath(ctx, opts.SQLitePath)
			dataDir = filepath.Dir(opts.SQLitePath)
		} else {
			db, _, receiptStore, err = setupLiteModeWithDataDir(ctx, dataDir)
		}
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
		receiptStore = ps
	}

	// 1. Initialize Kernel Layers

	// Signing Authority
	signer, err := loadOrGenerateSignerWithDataDir(dataDir)
	if err != nil {
		log.Fatalf("Failed to init signer: %v", err)
	}
	verifier, _ := crypto.NewEd25519Verifier(signer.PublicKeyBytes())
	fmt.Fprintf(opts.Stdout, "🔑 Trust Root: %s%s%s\n", ColorBold+ColorGreen, signer.PublicKey(), ColorReset)

	// 2. Registry
	reg := registry.NewPostgresRegistry(db)
	if err := reg.Init(ctx); err != nil {
		log.Fatalf("Failed to init registry: %v", err)
	}
	log.Println("[helm] registry: ready")

	// Pack verification is handled via the CLI subcommands (pack verify, etc.)

	// Artifact Store
	artStore, _ := artifacts.NewFileStore(filepath.Join(dataDir, "artifacts"))
	artRegistry := artifacts.NewRegistry(artStore, verifier)

	// === SUBSYSTEM WIRING ===
	services, svcErr := NewServices(ctx, db, artStore, logger)
	if svcErr != nil {
		log.Printf("Services init (non-fatal, degraded mode): %v", svcErr)
	}

	// 2.5 PRG & Guardian. The serve policy is authoritative when provided.
	// No implicit allow rule is installed; an empty or action-less policy graph
	// fails closed at evaluation time with NO_POLICY_DEFINED.
	ruleGraph := prg.NewGraph()
	var runtimePolicy *servePolicyRuntime
	if opts.PolicyPath != "" {
		runtimePolicy, err = loadServePolicyRuntime(opts.PolicyPath)
		if err != nil {
			log.Fatalf("Failed to load serve policy runtime: %v", err)
		}
		ruleGraph = runtimePolicy.Graph
		log.Printf("[helm] policy: loaded %s reference_pack=%s actions=%d", runtimePolicy.Policy.Name, runtimePolicy.ReferencePack.PackID, len(ruleGraph.Rules))
	} else {
		log.Printf("[helm] policy: no serve policy provided; kernel starts with an empty fail-closed rule graph")
	}

	// Guardian
	guardianOpts := []guardian.GuardianOption{}
	if runtimePolicy != nil {
		guardianOpts = append(guardianOpts, guardian.WithPDP(pdp.NewHelmPDP(runtimePolicy.Policy.Name, runtimePolicy.AllowMap())))
	}
	guard := guardian.NewGuardian(signer, ruleGraph, artRegistry, guardianOpts...)

	// Executor and MCP catalog are managed via the Services layer
	// (see services.go and subsystems.go for route wiring)

	// Register Subsystem Routes
	var extraRoutes func(*http.ServeMux)
	if services != nil {
		services.Guardian = guard
		services.ReceiptStore = receiptStore
		services.ReceiptSigner = signer
		extraRoutes = func(mux *http.ServeMux) {
			RegisterSubsystemRoutes(mux, services)
			RegisterConsoleRoutes(mux, services, opts)
		}
	}

	// Start API Server
	// SEC: Default to localhost to prevent accidental network exposure (OpenClaw vector).
	// Set HELM_BIND_ADDR=0.0.0.0 to listen on all interfaces when intentionally exposing.
	bindAddr := opts.BindAddr
	if bindAddr == "" {
		bindAddr = "127.0.0.1"
	}
	if envBind := os.Getenv("HELM_BIND_ADDR"); envBind != "" && opts.BindAddr == "" {
		bindAddr = envBind
	}
	port := opts.Port
	if port == 0 {
		port = 8080
	}
	if envPort := os.Getenv("HELM_PORT"); envPort != "" && opts.Port == 0 {
		if p, err := strconv.Atoi(envPort); err == nil {
			port = p
		}
	}
	mux := http.NewServeMux()
	if extraRoutes != nil {
		extraRoutes(mux)
	}
	RegisterConsoleStaticRoutes(mux, opts)
	rateLimiter := helmapi.NewGlobalRateLimiter(60, 120)
	if envBool("HELM_TRUST_PROXY_HEADERS") {
		rateLimiter = rateLimiter.WithTrustProxy(true)
	}
	server := &http.Server{
		Addr: fmt.Sprintf("%s:%d", bindAddr, port),
		Handler: helmauth.SecurityHeaders(
			helmauth.CORSMiddleware(nil)(
				helmauth.RequestIDMiddleware(
					rateLimiter.Middleware(mux),
				),
			),
		),
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if bindAddr == "0.0.0.0" {
		log.Printf("[helm] WARNING: API server binding to all interfaces (0.0.0.0:%d) — ensure firewall rules are in place", port)
	}
	go func() {
		log.Printf("[helm] API server: %s:%d", bindAddr, port)
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
		Addr:              fmt.Sprintf("%s:%d", bindAddr, healthPort),
		Handler:           healthMux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		log.Printf("[helm] health server: %s:%d", bindAddr, healthPort)
		if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[helm] health server error: %v", err)
		}
	}()

	if opts.JSON {
		_ = json.NewEncoder(opts.Stdout).Encode(map[string]any{
			"name":   "helm-edge-local",
			"addr":   bindAddr,
			"port":   port,
			"ready":  true,
			"policy": opts.PolicyPath,
		})
	} else if opts.Mode == "serve" {
		fmt.Fprintf(opts.Stdout, "helm-edge-local · listening :%d · ready\n", port)
	} else {
		log.Printf("[helm] ready: http://%s:%d", bindAddr, port)
	}
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

func envBool(key string) bool {
	value := os.Getenv(key)
	return value == "1" || value == "true" || value == "TRUE" || value == "yes" || value == "YES"
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
	healthPort := 8081
	if envHP := os.Getenv("HELM_HEALTH_PORT"); envHP != "" {
		if p, parseErr := strconv.Atoi(envHP); parseErr == nil {
			healthPort = p
		}
	}

	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/healthz", healthPort))
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

package main

// quantum_posture: CLI dispatch/front-door wiring only; cryptographic controls
// live in core/pkg/crypto and related verifier packages.

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	helmapi "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	policyreconcile "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policy/reconcile"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/registry"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/sandbox"
	dockersandbox "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/sandbox/docker"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store/ledger"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/translog"

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
	Quickstart *quickstartRuntime
	OnReady    func(bindAddr string, port int)
	JSON       bool
	Stdout     io.Writer
	Stderr     io.Writer
}

// Run is the entrypoint for testing
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		printFrontDoor(stdout)
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
			_, _ = fmt.Fprintln(stderr, "Usage: helm-ai-kernel trust <add-key|revoke-key|list-keys>")
			return 2
		}
		return runTrustCmd(args[2:], stdout, stderr)
	case "threat":
		if len(args) < 3 {
			_, _ = fmt.Fprintln(stderr, "Usage: helm-ai-kernel threat <scan|test> [flags]")
			return 2
		}
		return runThreatCmd(args[2:], stdout, stderr)
	case "run":
		if len(args) > 2 && args[2] == "maintenance" {
			return runMaintenanceCmd(args[3:], stdout, stderr)
		}
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel run maintenance [--once|--schedule]")
		return 2
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "%sHELM AI Kernel%s %s (%s)\n", ColorBold, ColorReset, displayVersion(), displayCommit())
		fmt.Fprintf(stdout, "  Report Schema:          %s\n", reportSchemaVersion)
		fmt.Fprintf(stdout, "  EvidencePack Schema:    1\n")
		fmt.Fprintf(stdout, "  Compatibility Schema:   1\n")
		fmt.Fprintf(stdout, "  MCP Bundle Schema:      1\n")
		fmt.Fprintf(stdout, "  Build Time:             %s\n", displayBuildTime())
		return 0
	case "help":
		if len(args) > 2 && args[2] == "--all" {
			printUsageAll(stdout)
			return 0
		}
		printFrontDoor(stdout)
		return 0
	case "--help", "-h":
		printFrontDoor(stdout)
		return 0
	default:
		if args[1][0] == '-' {
			if err := startServer(); err != nil { // Default backward compat behavior for flags passed without 'server'.
				_, _ = fmt.Fprintf(stderr, "Error: start server: %v\n", err)
				return 1
			}
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
func runServer() error {
	return runServerWithOptions(serverOptions{Mode: "server", Stdout: os.Stdout, Stderr: os.Stderr})
}

//nolint:gocognit,gocyclo
func runServerWithOptions(opts serverOptions) error {
	// Consume the Desktop launch secret before any optional runtime setup can
	// spawn a subprocess. The route retains only the in-memory copy below.
	desktopReadyToken := takeDesktopReadyToken()
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	// SEC: Default to localhost to prevent accidental network exposure.
	// HELM_BIND_ADDR=0.0.0.0 remains an explicit opt-in for server mode.
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
	apiAddr := net.JoinHostPort(bindAddr, strconv.Itoa(port))
	apiListener, listenErr := net.Listen("tcp", apiAddr)
	if listenErr != nil {
		return fmt.Errorf("bind API server at %s: %w", apiAddr, listenErr)
	}
	defer func() { _ = apiListener.Close() }()

	fmt.Fprintf(opts.Stdout, "%sHELM AI Kernel starting...%s\n", ColorBold+ColorBlue, ColorReset)
	ctx, runtimeCancel := context.WithCancel(context.Background())
	defer runtimeCancel()
	logger := slog.Default()
	dataDir := opts.DataDir
	if dataDir == "" {
		dataDir = "data"
	}

	var (
		db                    *sql.DB
		receiptStore          store.ReceiptStore
		principalBindingStore store.PrincipalBindingStore
		err                   error
		databaseMode          = "sqlite"
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
		principalBindingStore, err = store.NewSQLitePrincipalBindingStore(db)
		if err != nil {
			log.Fatalf("Failed to init sqlite principal binding store: %v", err)
		}
	} else {
		databaseMode = "postgres"
		if envBool("HELM_PRODUCTION") {
			if err := validateProductionDatabaseURL(dbURL); err != nil {
				log.Fatalf("Invalid production DATABASE_URL: %v", err)
			}
		}
		db, err = sql.Open("postgres", dbURL)
		if err != nil {
			log.Fatalf("Failed to connect to DB: %v", err)
		}
		configurePostgresPool(db)
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
		pbs, pbErr := store.NewPostgresPrincipalBindingStore(db)
		if pbErr != nil {
			log.Fatalf("Failed to init postgres principal binding store: %v", pbErr)
		}
		principalBindingStore = pbs
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
	services, svcErr := NewServices(ctx, db, artStore, logger, dataDir)
	if svcErr != nil {
		// In production we refuse to start in a degraded state. Subsystems are
		// allowed to fail in dev (e.g. observability without an OTLP endpoint),
		// but the boundary enforcer and other safety-critical components must
		// be present whenever HELM_PRODUCTION=1. A configured emergency-stop
		// fence is also safety-critical in every mode: continuing with an empty
		// service graph would make readiness ambiguous and hide a bad authority
		// or durable-store configuration.
		if servicesInitFailureIsFatal() {
			log.Fatalf("Services init failed while a fail-closed runtime boundary is enabled: %v", svcErr)
		}
		log.Printf("Services init (non-fatal, degraded mode): %v", svcErr)
	}
	if services != nil {
		services.DatabaseMode = databaseMode
		services.DatabaseStatus = "ready"
		if opts.SQLitePath != "" && databaseMode == "sqlite" {
			services.SQLitePath = opts.SQLitePath
		}
	}

	// 2.5 PRG & Guardian. --policy remains bootstrap/source configuration;
	// runtime policy authority is installed only through the reconciler.
	ruleGraph := prg.NewGraph()
	policyScope := policyreconcile.DefaultScope
	var (
		policyStore      policyreconcile.PolicySnapshotStore
		policyReconciler *policyreconcile.Reconciler
	)
	if opts.PolicyPath != "" {
		policySource, policySourceKind, sourceErr := policySourceFromEnv(opts.PolicyPath, policyScope)
		if sourceErr != nil {
			log.Fatalf("Failed to configure policy source: %v", sourceErr)
		}
		policyVerifier, requirePolicySignature, verifierErr := policySignatureVerifierFromEnv(policySourceKind)
		if verifierErr != nil {
			log.Fatalf("Failed to configure policy signature verifier: %v", verifierErr)
		}
		policyStore = policyreconcile.NewAtomicSnapshotStore()
		policyReconciler, err = policyreconcile.NewReconciler(policyreconcile.ReconcilerConfig{
			Source:            policySource,
			Store:             policyStore,
			Compiler:          compileServePolicySnapshot,
			Verifier:          policyVerifier,
			RequireSignature:  requirePolicySignature,
			KeepLastKnownGood: true,
		})
		if err != nil {
			log.Fatalf("Failed to initialize policy reconciler: %v", err)
		}
		reconcileCtx := ctx
		if timeout := policyInitialReconcileTimeoutFromEnv(); timeout > 0 {
			var cancel context.CancelFunc
			reconcileCtx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		status, recErr := policyReconciler.Reconcile(reconcileCtx, policyScope)
		if recErr != nil {
			log.Fatalf("Failed to reconcile initial policy snapshot: %v", recErr)
		}
		snapshot, ok := policyStore.Get(policyScope)
		if !ok || snapshot == nil {
			log.Fatalf("Failed to install initial policy snapshot: %s", status.ReconcileStatus)
		}
		if snapshot.Graph != nil {
			ruleGraph = snapshot.Graph
		}
		policyReconciler.Start(ctx, policyPollIntervalFromEnv())
		log.Printf("[helm] policy: source=%s reconciled snapshot hash=%s epoch=%d actions=%d", policySourceKind, snapshot.PolicyHash, snapshot.PolicyEpoch, len(ruleGraph.Rules))
	} else {
		log.Printf("[helm] policy: no serve policy provided; kernel starts with an empty fail-closed rule graph")
	}

	// Guardian
	guardianOpts := []guardian.GuardianOption{}
	if policyStore != nil {
		guardianOpts = append(guardianOpts, guardian.WithPolicySnapshots(policyStore, policyScope))
	}
	if services != nil && services.EmergencyStops != nil {
		guardianOpts = append(guardianOpts, guardian.WithScopedStopReader(services.EmergencyStops))
	}

	if envBool("HELM_ENABLE_WARM_POOL") {
		poolSize := 4
		if sizeStr := os.Getenv("HELM_WARM_POOL_SIZE"); sizeStr != "" {
			if s, err := strconv.Atoi(sizeStr); err == nil && s > 0 {
				poolSize = s
			}
		}
		imageDigest := os.Getenv("HELM_WARM_POOL_IMAGE_DIGEST")
		if imageDigest == "" {
			imageDigest = "sha256:test-digest"
		}
		fallbackMock := envBool("HELM_WARM_POOL_FALLBACK_MOCK")
		if !fallbackMock {
			cmd := exec.Command("docker", "info")
			if err := cmd.Run(); err != nil {
				log.Println("[helm] Docker daemon not reachable, falling back to mock warm sandboxes")
				fallbackMock = true
			}
		}
		log.Printf("[helm] Initializing Warm Sandbox Lease Pool: size=%d image=%s mock=%t", poolSize, imageDigest, fallbackMock)
		factory := func(id string) sandbox.Runner {
			return dockersandbox.NewDockerRunner()
		}
		warmMgr := sandbox.NewWarmLeaseManager(poolSize, imageDigest, fallbackMock, factory)
		guardianOpts = append(guardianOpts, guardian.WithWarmLeaseManager(warmMgr))
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
		services.PrincipalBindings = principalBindingStore
		SetPrincipalBindingStore(principalBindingStore)
		services.PolicyReconciler = policyReconciler
		services.PolicySnapshotStore = policyStore
		services.PolicyScope = policyScope

		// Receipt transparency log: anchor decision-record receipt hashes at
		// issuance (see persistDecisionReceipt -> anchorReceiptTransparency). The
		// anchor (LogID/LeafIndex/Transparency) is persisted with the receipt.
		// Sharing the signer's public key as the log identity matches
		// `helm-ai-kernel log` (see translog_cmd.go). Fail-closed by default;
		// degrade only when HELM_TRANSPARENCY_DEGRADE is explicitly set.
		transpLog, transpErr := translog.Open(filepath.Join(dataDir, "translog"))
		if transpErr != nil {
			if envBool("HELM_PRODUCTION") {
				log.Fatalf("Failed to open receipt transparency log: %v", transpErr)
			}
			log.Printf("[helm] receipt transparency log disabled (dev): %v", transpErr)
		} else {
			services.TranspLog = transpLog
			services.TranspLogID = translog.LogIDFromPublicKey(signer.PublicKeyBytes())
			services.TranspLogDegrade = envBool("HELM_TRANSPARENCY_DEGRADE")
		}
		extraRoutes = func(mux *http.ServeMux) {
			RegisterSubsystemRoutes(mux, services)
			RegisterConsoleRoutes(mux, services, opts)
			RegisterLocalFirstRunRoutes(mux, services, opts)
			RegisterPrincipalBindingRoutes(mux, services, opts)
		}
	}

	// Start API Server. The listener is bound synchronously above so OnReady
	// cannot advertise a Kernel endpoint that failed to claim its port.
	mux := http.NewServeMux()
	registerDesktopReadyRoute(mux, desktopReadyToken)
	if extraRoutes != nil {
		extraRoutes(mux)
	}
	rateLimiter := buildRuntimeRateLimiter()
	server := &http.Server{
		Addr: apiAddr,
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
		if err := server.Serve(apiListener); err != nil && err != http.ErrServerClosed {
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
	metricsPort := envInt("HELM_METRICS_PORT", healthPort)
	metricsEnabled := envBool("HELM_METRICS_ENABLED")
	if metricsEnabled && metricsPort == healthPort {
		healthMux.HandleFunc("/metrics", verificationMetrics.PrometheusHandler())
	}
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
	var metricsServer *http.Server
	if metricsEnabled && metricsPort != healthPort {
		metricsMux := http.NewServeMux()
		metricsMux.HandleFunc("/metrics", verificationMetrics.PrometheusHandler())
		metricsServer = &http.Server{
			Addr:              fmt.Sprintf("%s:%d", bindAddr, metricsPort),
			Handler:           metricsMux,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      5 * time.Second,
			IdleTimeout:       30 * time.Second,
		}
		go func() {
			log.Printf("[helm] metrics server: %s:%d", bindAddr, metricsPort)
			if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("[helm] metrics server error: %v", err)
			}
		}()
	}

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
	if opts.OnReady != nil {
		opts.OnReady(bindAddr, port)
	}
	log.Println("[helm] press ctrl+c to stop")

	// Graceful Shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Println("[helm] shutting down...")
	runtimeCancel()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("[helm] API server shutdown error: %v", err)
	}
	if err := healthServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("[helm] health server shutdown error: %v", err)
	}
	if metricsServer != nil {
		if err := metricsServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("[helm] metrics server shutdown error: %v", err)
		}
	}
	log.Println("[helm] shutdown complete")
	return nil
}

func servicesInitFailureIsFatal() bool {
	return envBool("HELM_PRODUCTION") || emergencyStopFenceEnabled()
}

func envBool(key string) bool {
	value := os.Getenv(key)
	return value == "1" || value == "true" || value == "TRUE" || value == "yes" || value == "YES"
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return fallback
	}
	return parsed
}

func buildRuntimeRateLimiter() *helmapi.GlobalRateLimiter {
	rateLimiter := helmapi.NewGlobalRateLimiter(
		envInt("HELM_LIMIT_GLOBAL_RPS", envInt("HELM_LIMIT_RPS", 60)),
		envInt("HELM_LIMIT_GLOBAL_BURST", envInt("HELM_LIMIT_BURST", 120)),
	)
	rateLimiter = rateLimiter.WithEndpointLimits(runtimeRateClassForRequest, map[string]helmapi.RateLimitProfile{
		string(RouteRatePublic):   endpointRateProfile(RouteRatePublic, 120, 240),
		string(RouteRateKernel):   endpointRateProfile(RouteRateKernel, 60, 120),
		string(RouteRateEvidence): endpointRateProfile(RouteRateEvidence, 40, 80),
		string(RouteRateAdmin):    endpointRateProfile(RouteRateAdmin, 20, 40),
		string(RouteRateStream):   endpointRateProfile(RouteRateStream, 20, 40),
	})
	rateLimiter = rateLimiter.WithActorLimit(helmapi.RateLimitProfile{
		RPS:   envInt("HELM_LIMIT_ACTOR_RPS", 60),
		Burst: envInt("HELM_LIMIT_ACTOR_BURST", 120),
	})
	rateLimiter = rateLimiter.WithConcurrencyLimit(envInt("HELM_CONCURRENCY_MAX", 0))
	if envBool("HELM_LOAD_SHED_ENABLED") {
		rateLimiter = rateLimiter.WithLowPriorityLoadShed(envInt("HELM_LOAD_SHED_LOW_PRIORITY_MAX", 0))
	}
	if envBool("HELM_TRUST_PROXY_HEADERS") {
		rateLimiter = rateLimiter.WithTrustProxy(true)
	}
	return rateLimiter
}

func configurePostgresPool(db *sql.DB) {
	maxOpen := envInt("HELM_DB_MAX_OPEN_CONNS", 25)
	maxIdle := envInt("HELM_DB_MAX_IDLE_CONNS", 10)
	if maxIdle > maxOpen && maxOpen > 0 {
		maxIdle = maxOpen
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(durationFromEnv("HELM_DB_CONN_MAX_LIFETIME", 30*time.Minute))
}

func endpointRateProfile(class RouteRateLimit, defaultRPS, defaultBurst int) helmapi.RateLimitProfile {
	name := strings.ToUpper(string(class))
	return helmapi.RateLimitProfile{
		RPS:   envInt("HELM_LIMIT_"+name+"_RPS", envInt("HELM_LIMIT_ENDPOINT_RPS", defaultRPS)),
		Burst: envInt("HELM_LIMIT_"+name+"_BURST", envInt("HELM_LIMIT_ENDPOINT_BURST", defaultBurst)),
	}
}

func runtimeRateClassForRequest(r *http.Request) string {
	path := r.URL.EscapedPath()
	bestClass := string(RouteRatePublic)
	bestLen := -1
	for _, spec := range RuntimeRouteSpecs() {
		if spec.Method != "" && spec.Method != r.Method {
			continue
		}
		if !runtimeRouteMatches(spec.MuxPattern, path) {
			continue
		}
		if len(spec.MuxPattern) > bestLen {
			bestLen = len(spec.MuxPattern)
			bestClass = string(spec.RateLimit)
		}
	}
	return bestClass
}

func runtimeRouteMatches(pattern string, path string) bool {
	if pattern == "" {
		return false
	}
	if pattern == path {
		return true
	}
	return strings.HasSuffix(pattern, "/") && strings.HasPrefix(path, pattern)
}

func policyPollIntervalFromEnv() time.Duration {
	return durationFromEnv("HELM_POLICY_POLL_INTERVAL", 10*time.Second)
}

func policyInitialReconcileTimeoutFromEnv() time.Duration {
	return durationFromEnv("HELM_POLICY_INITIAL_RECONCILE_TIMEOUT", 30*time.Second)
}

func policySourceFromEnv(policyPath string, scope policyreconcile.PolicyScope) (policyreconcile.PolicySource, string, error) {
	kind := strings.TrimSpace(os.Getenv("HELM_POLICY_SOURCE_KIND"))
	if kind == "" {
		kind = "mountedFile"
	}
	switch strings.ToLower(kind) {
	case "mountedfile", "mounted-file", "mounted_file":
		return policyreconcile.NewMountedFileSource(policyPath, scope), "mountedFile", nil
	case "controlplane", "control-plane", "control_plane":
		baseURL := strings.TrimSpace(os.Getenv("HELM_POLICY_CONTROLPLANE_URL"))
		if baseURL == "" {
			return nil, "controlplane", fmt.Errorf("HELM_POLICY_CONTROLPLANE_URL is required when HELM_POLICY_SOURCE_KIND=controlplane")
		}
		if err := policyreconcile.ValidateControlPlaneURL(baseURL); err != nil {
			return nil, "controlplane", err
		}
		source := policyreconcile.NewControlPlaneSource(baseURL, scope)
		source.BearerToken = os.Getenv("HELM_POLICY_BEARER_TOKEN")
		return source, "controlplane", nil
	case "crd":
		return nil, "crd", fmt.Errorf("HELM_POLICY_SOURCE_KIND=crd requires a CRD source implementation in the runtime build; this OSS binary only ships the chart CRD/RBAC contract")
	default:
		return nil, kind, fmt.Errorf("unsupported HELM_POLICY_SOURCE_KIND %q", kind)
	}
}

func policySignatureVerifierFromEnv(sourceKind string) (policyreconcile.SignatureVerifier, bool, error) {
	requireSignature := envBool("HELM_POLICY_SIGNATURE_REQUIRED")
	publicKey := strings.TrimSpace(os.Getenv("HELM_POLICY_TRUST_PUBLIC_KEY"))
	if strings.EqualFold(sourceKind, "controlplane") && !requireSignature {
		return nil, false, fmt.Errorf("HELM_POLICY_SIGNATURE_REQUIRED=true is required when HELM_POLICY_SOURCE_KIND=controlplane")
	}
	if publicKey == "" {
		if requireSignature {
			return nil, true, fmt.Errorf("HELM_POLICY_TRUST_PUBLIC_KEY is required when HELM_POLICY_SIGNATURE_REQUIRED=true")
		}
		return nil, false, nil
	}
	keyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return nil, requireSignature, fmt.Errorf("HELM_POLICY_TRUST_PUBLIC_KEY must be hex encoded: %w", err)
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, requireSignature, fmt.Errorf("HELM_POLICY_TRUST_PUBLIC_KEY must be a %d-byte Ed25519 public key encoded as hex", ed25519.PublicKeySize)
	}
	return policyreconcile.NewEd25519PolicyVerifier(publicKey), requireSignature, nil
}

func durationFromEnv(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration < 0 {
		return fallback
	}
	return duration
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

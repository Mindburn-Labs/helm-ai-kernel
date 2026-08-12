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
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tracing"
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
	Mode               string
	BindAddr           string
	Port               int
	DataDir            string
	SQLitePath         string
	PolicyPath         string
	DesktopTransportV1 bool
	Quickstart         *quickstartRuntime
	ConsoleMode        bool
	ConsolePeerProof   *localConsolePeerProof
	OnReady            func(bindAddr string, port int) error
	OnShutdown         func()
	RuntimeExit        <-chan struct{}
	JSON               bool
	Stdout             io.Writer
	Stderr             io.Writer
}

// utcRuntimeClock is the shared runtime clock for reconciliation and Guardian.
type utcRuntimeClock struct{}

func (utcRuntimeClock) Now() time.Time { return time.Now().UTC() }

// Run is the entrypoint for testing
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		printFrontDoor(stdout)
		return 0
	}
	if args[1] == "help" {
		return runHelpCommand(args[2:], stdout, stderr)
	}
	if len(args) == 3 && isHelpRequest(args[2:]) {
		if code, ok := Dispatch(args[1], []string{"--help"}, stdout, stderr); ok {
			return code
		}
		printGlobalCommandHelp(args[1], stdout)
		return 0
	}

	// Attempt to dispatch from registry
	if code, ok := Dispatch(args[1], args[2:], stdout, stderr); ok {
		return code
	}

	// Handle specific global commands that don't fit the registry pattern
	switch args[1] {
	case "completion":
		return runCompletionCommand(args[2:], stdout, stderr)
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
	case "version":
		return runVersionCommand(args[2:], stdout, stderr)
	case "--version", "-v":
		return runVersionFlag(args[2:], stdout, stderr)
	case "--help", "-h":
		printFrontDoor(stdout)
		return 0
	default:
		if args[1][0] == '-' {
			// An unrecognized flag used to start the server, as a convenience for
			// `helm-ai-kernel --port …` without the subcommand. Nothing in the
			// estate invokes it that way — every image, chart and unit names
			// `serve`, `server` or a subcommand explicitly — and the convenience
			// meant a mistyped flag silently launched a listener and minted a
			// trust root in the working directory. A boundary that starts by
			// accident is not a boundary.
			_, _ = fmt.Fprintf(stderr, "Unknown flag: %s\n", args[1])
			_, _ = fmt.Fprintf(stderr, "To start the server, name it: helm-ai-kernel serve %s\n", args[1])
			printUsage(stderr)
			return 2
		}
		printUnknownCommand(stderr, args[1])
		return 2
	}
}

func runHelpCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "--json" {
		return writeCommandCatalogJSON(stdout)
	}
	if len(args) > 0 && args[0] == "--all" {
		printUsageAll(stdout)
		return 0
	}
	if len(args) > 0 {
		path := append([]string(nil), args[1:]...)
		if !isHelpRequest(path) {
			path = append(path, "--help")
		}
		if code, ok := Dispatch(args[0], path, stdout, stderr); ok {
			return code
		}
		printGlobalCommandHelp(args[0], stdout)
		return 0
	}
	printFrontDoor(stdout)
	return 0
}

func printGlobalCommandHelp(name string, stdout io.Writer) {
	switch name {
	case "console":
		fmt.Fprintln(stdout, "The local browser Console is launched by Quickstart, not as a standalone server.")
		printLocalConsoleJourney(stdout)
		return
	case "completion":
		fmt.Fprintln(stdout, "Usage: helm-ai-kernel completion <bash|zsh|fish|powershell>")
	case "help":
		fmt.Fprintln(stdout, "Usage: helm-ai-kernel help [--all|--json|<command>]")
	case "server":
		fmt.Fprintln(stdout, "Usage: helm-ai-kernel server [--policy PATH] [--addr ADDR] [--port PORT] [--data-dir DIR] [--json]")
		fmt.Fprintln(stdout, "Logs default to JSON; set HELM_LOG_FORMAT=text for local human-readable output.")
	case "serve":
		fmt.Fprintln(stdout, "Usage: helm-ai-kernel serve --policy PATH [--addr ADDR] [--port PORT] [--data-dir DIR] [--json]")
		fmt.Fprintln(stdout, "Logs default to JSON; set HELM_LOG_FORMAT=text for local human-readable output.")
	case "threat":
		fmt.Fprintln(stdout, "Usage: helm-ai-kernel threat <scan|test> [flags]")
	case "version":
		fmt.Fprintln(stdout, "Usage: helm-ai-kernel version [--json]")
	default:
		fmt.Fprintf(stdout, "Usage: helm-ai-kernel %s [options]\n", name)
	}
	fmt.Fprintln(stdout, "Run `helm-ai-kernel help --all` to list commands.")
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

func resolveServerLogFormat(mode string) (string, error) {
	format := strings.ToLower(strings.TrimSpace(os.Getenv("HELM_LOG_FORMAT")))
	if format == "" {
		if mode == "quickstart" {
			return "text", nil
		}
		return "json", nil
	}
	if format != "json" && format != "text" {
		return "", fmt.Errorf("invalid HELM_LOG_FORMAT %q: expected json or text", format)
	}
	return format, nil
}

func newServerLogHandler(w io.Writer, format string) slog.Handler {
	var handler slog.Handler
	switch format {
	case "json":
		handler = slog.NewJSONHandler(w, &slog.HandlerOptions{ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
			if len(groups) == 0 && attr.Key == slog.TimeKey && attr.Value.Kind() == slog.KindTime {
				return slog.String("timestamp", attr.Value.Time().UTC().Format("2006-01-02T15:04:05.000Z07:00"))
			}
			return attr
		}})
	case "text":
		handler = slog.NewTextHandler(w, nil)
	}
	return tracing.NewSlogHandler(handler)
}

func configureServerLogger(w io.Writer, mode string) (*slog.Logger, string, error) {
	format, err := resolveServerLogFormat(mode)
	if err != nil {
		return nil, "", err
	}
	logger := slog.New(newServerLogHandler(w, format))
	slog.SetDefault(logger)
	return logger, format, nil
}

func writeServerNarration(logger *slog.Logger, format string, human io.Writer, humanText, message string, attrs ...any) {
	if format == "json" {
		logger.Info(message, attrs...)
		return
	}
	_, _ = fmt.Fprintln(human, humanText)
}

//nolint:gocognit,gocyclo
func runServerWithOptions(opts serverOptions) error {
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	logger, logFormat, logConfigErr := configureServerLogger(opts.Stderr, opts.Mode)
	if logConfigErr != nil {
		return logConfigErr
	}
	// Consume the Desktop launch secret before any optional runtime setup can
	// spawn a subprocess. The route retains only the in-memory copy below.
	desktopReadyToken := takeDesktopReadyToken()
	desktopTransport, transportErr := desktopTransportV1ForOptions(opts)
	if transportErr != nil {
		return fmt.Errorf("desktop transport v1 configuration: %w", transportErr)
	}
	narration := opts.Stdout
	if opts.JSON {
		narration = opts.Stderr
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
	healthPort := 8081
	if envHP := os.Getenv("HELM_HEALTH_PORT"); envHP != "" {
		if p, err := strconv.Atoi(envHP); err == nil {
			healthPort = p
		}
	}
	metricsPort := envInt("HELM_METRICS_PORT", healthPort)
	metricsEnabled := envBool("HELM_METRICS_ENABLED")
	suppressAuxiliaryHealth, healthConfigErr := desktopTransportV1SuppressesAuxiliaryHealth(desktopTransport, healthPort, metricsEnabled)
	if healthConfigErr != nil {
		return fmt.Errorf("desktop transport v1 configuration: %w", healthConfigErr)
	}
	apiAddr := net.JoinHostPort(bindAddr, strconv.Itoa(port))
	var (
		apiListener net.Listener
		apiOrigin   string
	)
	if desktopTransport != nil {
		apiListener, apiOrigin, transportErr = desktopTransport.bind()
		if transportErr != nil {
			return transportErr
		}
		bindAddr = "127.0.0.1"
		port = apiListener.Addr().(*net.TCPAddr).Port
		apiAddr = net.JoinHostPort(bindAddr, strconv.Itoa(port))
	} else {
		var listenErr error
		apiListener, listenErr = net.Listen("tcp", apiAddr)
		if listenErr != nil {
			return fmt.Errorf("bind API server at %s: %w", apiAddr, listenErr)
		}
	}
	defer func() { _ = apiListener.Close() }()

	writeServerNarration(logger, logFormat, narration,
		ColorBold+ColorBlue+"HELM AI Kernel starting..."+ColorReset,
		"HELM AI Kernel starting")
	ctx, runtimeCancel := context.WithCancel(context.Background())
	defer runtimeCancel()
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
		writeServerNarration(logger, logFormat, narration,
			"ℹ️  DATABASE_URL not set. Falling back to "+ColorBold+ColorCyan+"Lite Mode"+ColorReset+" (SQLite).",
			"DATABASE_URL not set; using Lite Mode", "database", "sqlite")
		if opts.SQLitePath != "" {
			db, _, receiptStore, err = setupLiteModeWithDBPath(ctx, opts.SQLitePath)
			dataDir = filepath.Dir(opts.SQLitePath)
		} else {
			db, _, receiptStore, err = setupLiteModeWithDataDir(ctx, dataDir)
		}
		if err != nil {
			return fmt.Errorf("setup Lite Mode: %w", err)
		}
		principalBindingStore, err = store.NewSQLitePrincipalBindingStore(db)
		if err != nil {
			return fmt.Errorf("init sqlite principal binding store: %w", err)
		}
	} else {
		databaseMode = "postgres"
		if envBool("HELM_PRODUCTION") {
			if err := validateProductionDatabaseURL(dbURL); err != nil {
				return fmt.Errorf("invalid production DATABASE_URL: %w", err)
			}
		}
		db, err = sql.Open("postgres", dbURL)
		if err != nil {
			return fmt.Errorf("connect to DB: %w", err)
		}
		configurePostgresPool(db)
		if err := db.PingContext(ctx); err != nil {
			return fmt.Errorf("ping DB: %w", err)
		}
		log.Println("[helm] postgres: connected")

		// Initialize Postgres stores (used by Services layer)
		pl := ledger.NewPostgresLedger(db)
		if err := pl.Init(ctx); err != nil {
			return fmt.Errorf("init ledger: %w", err)
		}
		_ = pl // Ledger is managed via Services layer
		ps := store.NewPostgresReceiptStore(db)
		if err := ps.Init(ctx); err != nil {
			return fmt.Errorf("init receipt store: %w", err)
		}
		receiptStore = ps
		pbs, pbErr := store.NewPostgresPrincipalBindingStore(db)
		if pbErr != nil {
			return fmt.Errorf("init postgres principal binding store: %w", pbErr)
		}
		principalBindingStore = pbs
	}

	// 1. Initialize Kernel Layers

	// Signing Authority
	signer, err := loadOrGenerateSignerWithDataDir(dataDir)
	if err != nil {
		return fmt.Errorf("init signer: %w", err)
	}
	verifier, _ := crypto.NewEd25519Verifier(signer.PublicKeyBytes())
	writeServerNarration(logger, logFormat, narration,
		"🔑 Trust Root: "+ColorBold+ColorGreen+signer.PublicKey()+ColorReset,
		"trust root ready", "public_key", signer.PublicKey())

	// 2. Registry
	reg := registry.NewPostgresRegistry(db)
	if err := reg.Init(ctx); err != nil {
		return fmt.Errorf("init registry: %w", err)
	}
	log.Println("[helm] registry: ready")

	// Pack verification is handled via the CLI subcommands (pack verify, etc.)

	// Artifact Store
	artStore, _ := artifacts.NewFileStore(filepath.Join(dataDir, "artifacts"))
	artRegistry := artifacts.NewRegistry(artStore, verifier)

	// === SUBSYSTEM WIRING ===
	services, svcErr := NewServices(ctx, db, artStore, logger, dataDir, databaseMode)
	if svcErr != nil {
		// In production we refuse to start in a degraded state. Subsystems are
		// allowed to fail in dev (e.g. observability without an OTLP endpoint),
		// but the boundary enforcer and other safety-critical components must
		// be present whenever HELM_PRODUCTION=1. A configured emergency-stop
		// fence is also safety-critical in every mode: continuing with an empty
		// service graph would make readiness ambiguous and hide a bad authority
		// or durable-store configuration.
		if servicesInitFailureIsFatal() {
			return fmt.Errorf("services init failed while a fail-closed runtime boundary is enabled: %w", svcErr)
		}
		logger.Warn("services init failed; continuing in degraded mode", "error", svcErr)
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
	policyScope := policyreconcile.PolicyScope{
		TenantID:    configuredRuntimeTenantID(),
		WorkspaceID: configuredRuntimeWorkspaceID(),
	}.Normalize()
	runtimeClock := utcRuntimeClock{}
	var (
		policyStore      policyreconcile.PolicySnapshotStore
		policyReconciler *policyreconcile.Reconciler
	)
	if opts.PolicyPath != "" {
		policySource, policySourceKind, sourceErr := policySourceFromEnv(opts.PolicyPath, policyScope)
		if sourceErr != nil {
			return fmt.Errorf("configure policy source: %w", sourceErr)
		}
		policyVerifier, requirePolicySignature, verifierErr := policySignatureVerifierFromEnv(policySourceKind)
		if verifierErr != nil {
			return fmt.Errorf("configure policy signature verifier: %w", verifierErr)
		}
		keepLastKnownGood, lkgMaxAge, lkgConfigErr := policyLastKnownGoodConfigFromEnv()
		if lkgConfigErr != nil {
			return fmt.Errorf("configure last-known-good policy retention: %w", lkgConfigErr)
		}
		policyStore = policyreconcile.NewAtomicSnapshotStore()
		policyReconciler, err = policyreconcile.NewReconciler(policyreconcile.ReconcilerConfig{
			Source:              policySource,
			Store:               policyStore,
			Compiler:            compileServePolicySnapshot,
			Verifier:            policyVerifier,
			RequireSignature:    requirePolicySignature,
			KeepLastKnownGood:   keepLastKnownGood,
			LastKnownGoodMaxAge: lkgMaxAge,
			Clock:               runtimeClock.Now,
		})
		if err != nil {
			return fmt.Errorf("initialize policy reconciler: %w", err)
		}
		reconcileCtx := ctx
		if timeout := policyInitialReconcileTimeoutFromEnv(); timeout > 0 {
			var cancel context.CancelFunc
			reconcileCtx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		status, recErr := policyReconciler.Reconcile(reconcileCtx, policyScope)
		if recErr != nil {
			return fmt.Errorf("reconcile initial policy snapshot: %w", recErr)
		}
		snapshot, ok := policyStore.Get(policyScope)
		if !ok || snapshot == nil {
			return fmt.Errorf("install initial policy snapshot: %s", status.ReconcileStatus)
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
	guardianOpts := []guardian.GuardianOption{guardian.WithClock(runtimeClock)}
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
				logger.Warn("Docker daemon not reachable; falling back to mock warm sandboxes")
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
		services.ApprovalConsumption, err = newApprovalConsumptionRuntime(ctx, db, databaseMode, signer, services.EmergencyStops)
		if err != nil {
			return fmt.Errorf("initialize approval grant consumption runtime: %w", err)
		}
		services.GeneratedSpecApproval, err = newGeneratedSpecApprovalRuntime(ctx, db, databaseMode, signer, services.EmergencyStops)
		if err != nil {
			return fmt.Errorf("initialize GeneratedSpec approval runtime: %w", err)
		}

		// Receipt transparency log: anchor decision-record receipt hashes at
		// issuance (see persistDecisionReceipt -> anchorReceiptTransparency). The
		// anchor (LogID/LeafIndex/Transparency) is persisted with the receipt.
		// Sharing the signer's public key as the log identity matches
		// `helm-ai-kernel log` (see translog_cmd.go). Fail-closed by default;
		// degrade only when HELM_TRANSPARENCY_DEGRADE is explicitly set.
		transpLog, transpErr := translog.Open(filepath.Join(dataDir, "translog"))
		if transpErr != nil {
			if envBool("HELM_PRODUCTION") {
				return fmt.Errorf("open receipt transparency log: %w", transpErr)
			}
			logger.Warn("receipt transparency log disabled in development", "error", transpErr)
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
	registerDesktopTransportV1ProofRoute(mux, desktopTransport, apiOrigin)
	if extraRoutes != nil {
		extraRoutes(mux)
	}
	rateLimiter := buildRuntimeRateLimiter()
	server := &http.Server{
		Addr:              apiAddr,
		Handler:           buildAPIHandler(mux, rateLimiter),
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if bindAddr == "0.0.0.0" {
		logger.Warn("API server binding to all interfaces; ensure firewall rules are in place", "port", port)
	}
	go func() {
		log.Printf("[helm] API server: %s:%d", bindAddr, port)
		if err := server.Serve(apiListener); err != nil && err != http.ErrServerClosed {
			logger.Error("API server failed", "error", err)
		}
	}()
	if desktopTransport != nil {
		if err := desktopTransport.writeReadinessRecord(opts.Stdout, apiOrigin); err != nil {
			return err
		}
	}

	var healthServer *http.Server
	if !suppressAuxiliaryHealth {
		healthMux := http.NewServeMux()
		healthHandler := func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		}
		healthMux.HandleFunc("/health", healthHandler)
		healthMux.HandleFunc("/healthz", healthHandler)
		if metricsEnabled && metricsPort == healthPort {
			healthMux.HandleFunc("/metrics", verificationMetrics.PrometheusHandler())
		}
		healthServer = &http.Server{
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
				logger.Error("health server failed", "error", err)
			}
		}()
	}
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
				logger.Error("metrics server failed", "error", err)
			}
		}()
	}

	shutdown := func() {
		if opts.OnShutdown != nil {
			opts.OnShutdown()
		}
		runtimeCancel()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("API server shutdown failed", "error", err)
		}
		if healthServer != nil {
			if err := healthServer.Shutdown(shutdownCtx); err != nil {
				logger.Error("health server shutdown failed", "error", err)
			}
		}
		if metricsServer != nil {
			if err := metricsServer.Shutdown(shutdownCtx); err != nil {
				logger.Error("metrics server shutdown failed", "error", err)
			}
		}
		// Flush the OTLP batchers last, after the servers stopped accepting.
		// The span processor batches on a 5s timer (observability.DefaultConfig
		// BatchTimeout), so without this the final batch dies with the process —
		// and in a short-lived pod that batch is most of the trace.
		//
		// flushObservability deliberately does NOT take shutdownCtx: see its doc
		// comment. Reusing the drain's budget makes the flush a no-op in exactly
		// the case it exists for.
		if services != nil && services.Observability != nil {
			if err := flushObservability(services.Observability); err != nil {
				logger.Error("observability shutdown failed", "error", err)
			}
		}
	}
	if err := writeServerReady(opts, logger, logFormat, bindAddr, port); err != nil {
		shutdown()
		return err
	}
	log.Println("[helm] press ctrl+c to stop")

	// Graceful Shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)
	var runtimeErr error
	select {
	case <-sigChan:
		log.Println("[helm] shutting down...")
	case <-opts.RuntimeExit:
		runtimeErr = fmt.Errorf("local Console exited")
		log.Println("[helm] local Console exited; shutting down...")
	}
	shutdown()
	log.Println("[helm] shutdown complete")
	return runtimeErr
}

func writeServerReady(opts serverOptions, logger *slog.Logger, logFormat, bindAddr string, port int) error {
	if opts.OnReady != nil {
		if err := opts.OnReady(bindAddr, port); err != nil {
			return err
		}
	}
	if opts.JSON && (opts.Mode != "quickstart" || opts.OnReady == nil) {
		_ = json.NewEncoder(opts.Stdout).Encode(map[string]any{
			"name":   "helm-edge-local",
			"addr":   bindAddr,
			"port":   port,
			"ready":  true,
			"policy": opts.PolicyPath,
		})
	} else if logFormat == "json" {
		logger.Info("server ready", "name", "helm-edge-local", "addr", bindAddr, "port", port, "policy", opts.PolicyPath)
	} else if opts.Mode == "serve" {
		fmt.Fprintf(opts.Stdout, "helm-edge-local · listening :%d · ready\n", port)
	} else {
		log.Printf("[helm] ready: http://%s:%d", bindAddr, port)
	}
	return nil
}

func servicesInitFailureIsFatal() bool {
	return envBool("HELM_PRODUCTION") || emergencyStopFenceEnabled() || envBool(approvalConsumptionEnabledEnv) || envBool(generatedSpecApprovalEnabledEnv)
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

// buildAPIHandler assembles the daemon's request pipeline.
//
// Layer order is load-bearing and pinned by api_handler_chain_test.go:
//
//	SecurityHeaders -> CORS -> RequestID -> tracing -> rateLimiter -> mux
//
// The tracing wrapper (HELM-333/HELM-495) sits INSIDE RequestIDMiddleware and
// OUTSIDE the rate limiter. Both halves matter:
//
//   - Inside RequestID because that middleware calls next.ServeHTTP with
//     r.WithContext(ctx). http.ServeMux stamps the matched pattern onto the
//     *http.Request it is handed, in place — so whichever request object
//     otelhttp passes downstream is the one that comes back carrying Pattern.
//     From outside RequestID, otelhttp holds the pre-clone request and never
//     sees the pattern, which makes per-route naming structurally impossible.
//   - Outside the rate limiter so a rejected request is still a span: a 429 is
//     exactly the case worth seeing in a trace.
//
// The accepted cost of moving in is the CORS preflight, which CORSMiddleware
// answers before the span starts and which therefore is no longer traced.
//
// Nothing here stamps http.route, and nothing here could. All three
// route-bearing surfaces are supplied inside tracing.WrapEdgeHandler, but NOT
// all three by the same mechanism — the split is what pins them to that
// function rather than to this chain:
//
//   - The span NAME needs an otelhttp OPTION (WithSpanNameFormatter). otelhttp
//     re-runs its formatter after the inner handler returns (handler.go:180-181)
//     and overwrites whatever SetName a middleware performed, so no middleware,
//     here or anywhere, can win that race.
//   - The span ATTRIBUTE needs a MIDDLEWARE (tracing's own withRouteAttribute).
//     There is no option for it: otelhttp freezes the request attributes at span
//     start, before routing, and never revisits them. The middleware has to sit
//     INSIDE otelhttp.NewHandler, because from outside the span has already
//     ended and the write is dropped — which is precisely why it lives in the
//     wrapper and cannot be a layer of this chain.
//   - The metric ATTRIBUTE has TWO post-routing hooks — otelhttp.Labeler and
//     WithMetricAttributesFn — and the wrapper uses the option, because it
//     belongs to the wrapper rather than to any handler and so covers edges we
//     do not own. See tracing.WrapEdgeHandler for why, and use the Labeler for
//     an attribute only one handler knows.
//
// The one requirement this chain owes that machinery is that every layer below
// the wrapper pass the request through unchanged; the rate limiter does.
//
// Everything downstream runs with a span in r.Context(), which is what lets
// *Context slog call sites stamp trace_id/span_id (see tracing.NewSlogHandler).
//
// This is the daemon's only traced entry point: api.NewServer wraps its own
// edge, but the daemon does not use that constructor (it registers its routes
// on its own mux). The tracer is resolved per request from the global
// TracerProvider, so wrapping before observability.New has configured OTel is
// harmless as long as configuration lands before traffic does.
//
// The health (:HELM_HEALTH_PORT) and metrics (:HELM_METRICS_PORT) servers are
// deliberately NOT wrapped: they serve liveness probes and Prometheus scrapes
// on separate ports at a fixed cadence (~1200 probes per idle hour), which
// would bury real request traces in root spans that carry no inbound
// traceparent and no governance decision.
func buildAPIHandler(mux http.Handler, rateLimiter *helmapi.GlobalRateLimiter) http.Handler {
	return helmauth.SecurityHeaders(
		helmauth.CORSMiddleware(nil)(
			helmauth.RequestIDMiddleware(
				tracing.WrapEdgeHandler(
					rateLimiter.Middleware(mux),
					"helm.api",
				),
			),
		),
	)
}

// observabilityFlushTimeout is the budget the OTLP flush gets to itself. It is
// spent only after the HTTP servers have drained, so the pod's
// terminationGracePeriodSeconds must cover the drain budget plus this.
const observabilityFlushTimeout = 5 * time.Second

// observabilityFlusher is the flush seam, narrow enough to fake in a test.
type observabilityFlusher interface {
	Shutdown(context.Context) error
}

// flushObservability drains the OTLP batchers on a budget created here, not on
// the one the server drain was given.
//
// The drain and the flush cannot share a deadline. /api/v1/receipts/tail
// (registered in receipt_routes.go) is an unbounded SSE loop whose only exit is
// <-r.Context().Done(), and http.Server.Shutdown does not cancel in-flight
// request contexts — it waits. One Console tailing receipts therefore burns the
// whole drain budget, and sdktrace.TracerProvider.Shutdown then returns
// ctx.Err() BEFORE it stops the span processor (otel/sdk trace/provider.go), so
// nothing is exported: zero spans in precisely the shutdown the hook was added
// to capture.
func flushObservability(flusher observabilityFlusher) error {
	flushCtx, cancel := context.WithTimeout(context.Background(), observabilityFlushTimeout)
	defer cancel()
	return flusher.Shutdown(flushCtx)
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

func policyLastKnownGoodConfigFromEnv() (bool, time.Duration, error) {
	action := strings.TrimSpace(os.Getenv("HELM_POLICY_ON_INVALID_UPDATE"))
	switch {
	case action == "" || strings.EqualFold(action, "keepLastKnownGood"):
		maxAge := policyreconcile.DefaultLKGMaxAge
		if raw := strings.TrimSpace(os.Getenv("HELM_POLICY_LAST_KNOWN_GOOD_MAX_AGE")); raw != "" {
			parsed, err := time.ParseDuration(raw)
			if err != nil || parsed <= 0 {
				return false, 0, fmt.Errorf("HELM_POLICY_LAST_KNOWN_GOOD_MAX_AGE must be a positive duration")
			}
			maxAge = parsed
		}
		return true, maxAge, nil
	case strings.EqualFold(action, "deny"):
		return false, 0, nil
	default:
		return false, 0, fmt.Errorf("HELM_POLICY_ON_INVALID_UPDATE must be deny or keepLastKnownGood")
	}
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

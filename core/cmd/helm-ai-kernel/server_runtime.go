package main

// quantum_posture: server initialization delegates signing and verification to core/pkg/crypto.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/pgdsn"
	policyreconcile "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policy/reconcile"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/postgresmigration"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/translog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

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

//nolint:gocognit,gocyclo
func runServer() error {
	return runServerWithOptions(serverOptions{Mode: "server", Stdout: os.Stdout, Stderr: os.Stderr})
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
	semanticEscalationBP, semanticConfigErr := semanticThreatEscalationBPFromEnv()
	if semanticConfigErr != nil {
		return semanticConfigErr
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
	metricsToken := os.Getenv(metricsBearerTokenEnv)
	suppressAuxiliaryHealth, healthConfigErr := desktopTransportV1SuppressesAuxiliaryHealth(desktopTransport, healthPort, metricsEnabled)
	if healthConfigErr != nil {
		return fmt.Errorf("desktop transport v1 configuration: %w", healthConfigErr)
	}
	apiTLSConfig, tlsConfigErr := serveTLSConfigFromEnv()
	if tlsConfigErr != nil {
		return fmt.Errorf("API listener TLS configuration: %w", tlsConfigErr)
	}
	if apiTLSConfig != nil && desktopTransport != nil {
		return errors.New("API listener TLS configuration: HELM_TLS_* is not supported with desktop transport v1")
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
	dataDir := translogDataDir(opts.DataDir)

	var (
		db                    *sql.DB
		receiptStore          store.ReceiptStore
		principalBindingStore store.PrincipalBindingStore
		err                   error
		databaseMode          = "sqlite"
	)

	// 0.2 Connect to Database (Infrastructure)
	if strings.TrimSpace(os.Getenv("HELM_MIGRATION_DATABASE_URL")) != "" {
		return errors.New("HELM_MIGRATION_DATABASE_URL must not be present in the Kernel serving process; run `helm-ai-kernel migrate` with that credential")
	}
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
		if err := validateRuntimePostgresURL(dbURL); err != nil {
			return fmt.Errorf("invalid postgres DATABASE_URL: %w", err)
		}
		utcURL, err := pgdsn.WithUTCTimeZone(dbURL)
		if err != nil {
			return fmt.Errorf("invalid postgres DATABASE_URL: %w", err)
		}
		db, err = sql.Open("postgres", utcURL)
		if err != nil {
			return fmt.Errorf("connect to DB: %w", err)
		}
		configurePostgresPool(db)
		if err := db.PingContext(ctx); err != nil {
			return fmt.Errorf("ping DB: %w", err)
		}
		log.Println("[helm] postgres: connected")
		if err := postgresmigration.ValidateRuntime(ctx, db, postgresmigration.RuntimeOptions{
			EmergencyStops:        emergencyStopFenceEnabled(),
			ApprovalConsumption:   envBool(approvalConsumptionEnabledEnv),
			GeneratedSpecApproval: envBool(generatedSpecApprovalEnabledEnv),
			ReleaseAuthority:      envBool(effectDispositionEnabledEnv) || envBool(effectReconciliationCandidatesEnabledEnv),
		}); err != nil {
			return fmt.Errorf("validate postgres runtime schema: %w", err)
		}

		// Construct Postgres stores (the one-shot migration command owns DDL).
		ps := store.NewPostgresReceiptStore(db)
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
		"Trust Root: "+ColorBold+ColorGreen+signer.PublicKey()+ColorReset,
		"trust root ready", "public_key", signer.PublicKey())

	// Pack verification is handled via the CLI subcommands (pack verify, etc.)

	// Artifact Store
	artStore, _ := artifacts.NewFileStore(filepath.Join(dataDir, "artifacts"))
	artRegistry := artifacts.NewRegistry(artStore, verifier)

	// === SUBSYSTEM WIRING ===
	if err := ensureLocalAPIKeys(dataDir, logger); err != nil {
		return err
	}
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
		if envBool("HELM_PRODUCTION") {
			policyStore, err = policyreconcile.NewPersistentSnapshotStore(filepath.Join(dataDir, "policy-replay-watermarks.json"))
			if err != nil {
				return fmt.Errorf("open policy replay watermark store: %w", err)
			}
		} else {
			policyStore = policyreconcile.NewAtomicSnapshotStore()
		}
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
	guardianOpts := []guardian.GuardianOption{}
	if semanticEscalationBP > 0 {
		guardianOpts = append(guardianOpts, guardian.WithSemanticThreatEscalation(semanticEscalationBP))
	}
	if policyStore != nil {
		guardianOpts = append(guardianOpts, guardian.WithPolicySnapshots(policyStore, policyScope))
	}
	if services != nil && services.Observability != nil {
		guardianOpts = append(guardianOpts, guardian.WithOTel())
	}

	guardianState := productionGuardianState{DataDir: dataDir}
	if services != nil && services.EmergencyStops != nil {
		guardianState.Stops = services.EmergencyStops
	}
	guard, err := newProductionGuardian(signer, ruleGraph, artRegistry, runtimeClock, guardianState, guardianOpts...)
	if err != nil {
		return fmt.Errorf("initialize production Guardian: %w", err)
	}

	// Executor and MCP catalog are managed via the Services layer
	// (see services.go and subsystems.go for route wiring)

	// Register Subsystem Routes
	var extraRoutes func(routeMux)
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
		services.ControlPlaneIdentity, err = newControlPlaneIdentityFromEnv()
		if err != nil {
			return fmt.Errorf("initialize Control Plane identity: %w", err)
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
		extraRoutes = func(mux routeMux) {
			registerRuntimeAPIRoutes(mux, services, opts)
		}
	}

	// Start API Server. The listener is bound synchronously above so OnReady
	// cannot advertise a Kernel endpoint that failed to claim its port.
	// Every pattern mounted here must be declared in RuntimeRouteSpecs(); the
	// mux panics on an undeclared one rather than serve it.
	mux := newRuntimeRouteMux()
	registerDesktopReadyRoute(mux, desktopReadyToken)
	registerDesktopTransportV1ProofRoute(mux, desktopTransport, apiOrigin)
	if extraRoutes != nil {
		extraRoutes(mux)
	}
	rateLimiter, err := buildRuntimeRateLimiter()
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              apiAddr,
		Handler:           buildAPIHandler(mux, rateLimiter),
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig:         apiTLSConfig,
	}
	if bindAddr == "0.0.0.0" {
		logger.Warn("API server binding to all interfaces; ensure firewall rules are in place", "port", port)
	}
	go func() {
		var err error
		if apiTLSConfig != nil {
			log.Printf("[helm] API server: %s:%d (TLS, client auth %s)", bindAddr, port, apiTLSConfig.ClientAuth)
			// The certificate comes from TLSConfig.GetCertificate, so no files here.
			err = server.ServeTLS(apiListener, "", "")
		} else {
			log.Printf("[helm] API server: %s:%d", bindAddr, port)
			err = server.Serve(apiListener)
		}
		if err != nil && err != http.ErrServerClosed {
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
		healthMux := newListenerRouteMux(listenerHealth)
		var healthMetrics http.HandlerFunc
		if metricsEnabled && metricsPort == healthPort {
			healthMetrics = protectedMetricsHandler(services, metricsToken)
		}
		registerHealthRoutes(healthMux, healthMetrics)
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
		metricsMux := newListenerRouteMux(listenerMetrics)
		registerMetricsRoutes(metricsMux, protectedMetricsHandler(services, metricsToken))
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

// metricsHandler composes the provider-local OTel scrape surface with the
// bounded governance collector before promhttp encodes the response. A single
// encoder is required because OpenMetrics responses terminate with # EOF.
func metricsHandler(services *Services) http.HandlerFunc {
	gatherers := prometheus.Gatherers{}
	if services != nil && services.Observability != nil {
		if gatherer := services.Observability.PrometheusGatherer(); gatherer != nil {
			gatherers = append(gatherers, gatherer)
		}
	}
	gatherers = append(gatherers, verificationMetrics.PrometheusGatherer(), controlPlaneIdentityMetrics.PrometheusGatherer())
	return promhttp.HandlerFor(gatherers, promhttp.HandlerOpts{EnableOpenMetrics: true}).ServeHTTP
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

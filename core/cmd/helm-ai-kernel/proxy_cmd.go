// quantum_posture: the proxy command configures optional classical Ed25519 receipt signing.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/artifacts"
	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/bridge"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	helmotel "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/otel"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tracing"
)

// proxyCtxKey is a unique context key type to stash per-request governance state
// from Director through to ModifyResponse without collisions with other packages.
type proxyCtxKey struct{ name string }

var (
	ctxKeyCorrelationID = proxyCtxKey{"correlation_id"}
	ctxKeyRequestInfo   = proxyCtxKey{"request_info"}
	ctxKeySessionID     = proxyCtxKey{"session_id"}
	ctxKeyTraceparent   = proxyCtxKey{"traceparent"}
)

// proxyConfig is the proxy's resolved configuration.
type proxyConfig struct {
	upstream      string
	apiKey        string
	jsonOutput    bool
	verbose       bool
	receiptsDir   string
	signKey       string
	tenantID      string
	policyGraph   *prg.Graph // nil: every tool call is denied
	maxIterations int
	maxWallclock  time.Duration
}

// proxyRuntime is a constructed proxy: the governed handler plus the state the
// sidecar's own endpoints and shutdown path read.
type proxyRuntime struct {
	handler     http.Handler
	upstream    string
	receiptPath string
	store       *receiptStore
	pg          *proofgraph.Graph
	signer      *helmcrypto.Ed25519Signer // nil unless --sign
	close       func()
}

// newProxyRuntime wires the receipt store, signer, Guardian bridge and the
// governed reverse proxy. runProxyCmd and the tests both build the proxy here,
// so the tests exercise the shipped wiring rather than a copy of it.
func newProxyRuntime(cfg proxyConfig, stderr io.Writer) (*proxyRuntime, error) {
	upstream := cfg.upstream
	upstreamURL, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}
	tenantID := cfg.tenantID
	receiptsDir := cfg.receiptsDir

	// Initialize receipt store
	receiptPath := filepath.Join(receiptsDir, fmt.Sprintf("receipts-%s.jsonl", time.Now().Format("2006-01-02")))
	store, err := newReceiptStore(receiptPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize receipt store at %s: %w", receiptPath, err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = store.Close()
		}
	}()

	// Ed25519 signer for the Guardian's decision records and, with --sign, for
	// the proxy receipts.
	//
	// --sign is documented as a signing seed. It previously became the signer's
	// key *id* while the actual keypair was generated at random, so receipts
	// were unverifiable after a restart and the seed was published in every
	// receipt's KeyID field (F-01).
	var kernelSigner *helmcrypto.Ed25519Signer
	if cfg.signKey != "" {
		var derivedFromPassphrase bool
		kernelSigner, derivedFromPassphrase, err = helmcrypto.NewEd25519SignerFromSecret(cfg.signKey, "helm-proxy")
		if err != nil {
			return nil, fmt.Errorf("failed to create kernel signer: %w", err)
		}
		if derivedFromPassphrase {
			_, _ = fmt.Fprintln(stderr,
				"Warning: --sign is not a 32-byte hex/base64 seed; deriving one by hashing it. "+
					"Supply a generated seed so receipts stay verifiable and the key is not guessable.")
		}
	} else {
		// No seed supplied: an ephemeral key signs the Guardian's decision
		// records, which cannot be verified once this process exits, and the
		// proxy receipts stay unsigned (signer below is nil). Fails closed under
		// HELM_PRODUCTION.
		kernelSigner, err = helmcrypto.NewEd25519Signer("helm-proxy")
		if err != nil {
			return nil, fmt.Errorf("failed to create kernel signer: %w", err)
		}
	}

	// Receipt signer: the same key, and only with --sign. Without it receipts
	// are hash-chained and carry no signature.
	var signer *helmcrypto.Ed25519Signer
	if cfg.signKey != "" {
		signer = kernelSigner
	}

	// Initialize KernelBridge: Guardian + ProofGraph. The proxy passes no budget
	// enforcer: it cannot price a tool call (see runProxyCmd).
	prgGraph := cfg.policyGraph
	if prgGraph == nil {
		prgGraph = prg.NewGraph()
	}
	artStore, artErr := artifacts.NewFileStore(filepath.Join(receiptsDir, "artifacts"))
	if artErr != nil {
		return nil, fmt.Errorf("failed to create artifact store: %w", artErr)
	}
	artRegistry := artifacts.NewRegistry(artStore, kernelSigner)
	// The proxy reads the same stop state as serve: freeze_state.json and the
	// Lite Mode fence database in HELM_DATA_DIR (default ./data), or the fence
	// in DATABASE_URL.
	fence, err := openStandaloneEmergencyStopFence(context.Background(), "")
	if err != nil {
		return nil, fmt.Errorf("failed to open the emergency-stop fence: %w", err)
	}
	defer func() {
		if !ok {
			_ = fence.Close()
		}
	}()
	var fenceScope emergencyStopScope
	if fence != nil {
		fenceScope = fence.scope
		if tenantID != fenceScope.TenantID {
			return nil, fmt.Errorf("--tenant-id %q must equal %s %q while %s is on, so the fence covers the tenant this proxy governs", tenantID, runtimeTenantIDEnv, fenceScope.TenantID, emergencyStopFenceEnabledEnv)
		}
	}
	g, guardianErr := newProductionGuardian(kernelSigner, prgGraph, artRegistry, utcRuntimeClock{}, fence.guardianState(""))
	if guardianErr != nil {
		return nil, fmt.Errorf("failed to initialize production Guardian: %w", guardianErr)
	}
	pg := proofgraph.NewGraph()
	kb := bridge.NewKernelBridge(g, prgGraph, pg, nil, tenantID)
	limits := newProxySessionLimits(cfg.maxIterations, cfg.maxWallclock, time.Now)
	proofPath := filepath.Join(receiptsDir, "proofgraph.json")

	// Governance tracer — attaches OTel GenAI spans to every request.
	// NoopTracer when no OTLP endpoint is configured; the GovernanceTracer
	// itself decides whether to wire a real exporter.
	otelTracer := helmotel.NoopTracer()
	if endpoint := os.Getenv("HELM_OTLP_ENDPOINT"); endpoint != "" {
		if rt, otelErr := helmotel.NewGovernanceTracer(helmotel.Config{
			ServiceName: "helm-proxy",
			Endpoint:    endpoint,
			Insecure:    os.Getenv("HELM_OTLP_INSECURE") == "1",
		}); otelErr == nil {
			otelTracer = rt
		} else {
			log.Printf("[WARN] OTLP exporter setup failed, falling back to noop: %v", otelErr)
		}
	}

	response := proxyResponseHandler{
		upstream:    upstream,
		tenantID:    tenantID,
		genAISystem: inferGenAISystem(upstreamURL),
		proofPath:   proofPath,
		fenceScope:  fenceScope,
		graph:       pg,
		limits:      limits,
		governance:  kb,
		store:       store,
		signer:      signer,
		tracer:      otelTracer,
		jsonOutput:  cfg.jsonOutput,
		verbose:     cfg.verbose,
	}
	proxy := &httputil.ReverseProxy{
		Director:       proxyRequestDirector(upstreamURL, upstream, cfg.apiKey),
		ModifyResponse: response.modify,
	}
	handler := proxyRequestHandler(proxy)

	ok = true
	return &proxyRuntime{
		handler:     handler,
		upstream:    upstream,
		receiptPath: receiptPath,
		store:       store,
		pg:          pg,
		signer:      signer,
		close: func() {
			_ = otelTracer.Shutdown(context.Background())
			_ = store.Close()
			_ = fence.Close()
		},
	}, nil
}

func proxyRequestHandler(next http.Handler) http.HandlerFunc {
	// The governed entry point reads the request once, refuses a streamed
	// request that offers tools before it reaches the upstream, and records the
	// transport identity the Guardian binds decisions to.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		if r.Body != nil {
			b, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				http.Error(w, "failed to read request body", http.StatusBadRequest)
				return
			}
			body = b
			r.Body = io.NopCloser(bytes.NewReader(b))
			r.ContentLength = int64(len(b))
		}
		info := inspectProxyRequest(body)
		if info.stream && info.toolsDeclared {
			slog.WarnContext(r.Context(), "proxy refused a streamed request that offers tools before the upstream call",
				"reason_code", "PROXY_STREAMING_TOOLS_REFUSED")
			writeStreamingToolsRefusal(w)
			return
		}
		ctx := context.WithValue(r.Context(), ctxKeyRequestInfo, info)
		if _, authenticated := helmauth.AuthenticatedCredentialHash(ctx); !authenticated {
			ctx = helmauth.WithAuthenticatedCredential(ctx, proxyLocalCredential)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// runProxyCmd implements `helm-ai-kernel proxy`.
//
// Usage:
//
//	helm-ai-kernel proxy --upstream https://api.openai.com/v1 --port 9090 --policy ./helm.toml
//
// Then:
//
//	export OPENAI_BASE_URL=http://localhost:9090/v1
//	python your_app.py  # Every tool call now gets a verdict and a receipt.
//
// Features:
//   - Receipt persistence: JSONL audit log at --receipts-dir
//   - PEP validation: tool_call arguments validated as JSON, canonicalized (JCS), and SHA-256 hashed
//   - Policy: tool calls are decided by the Guardian against --policy; without it every tool call is denied
//   - Streaming: a request that offers tools must not stream; the proxy cannot parse a stream
//   - Causal chain: receipts linked via PrevHash (SHA-256 of previous receipt)
//   - Ed25519 signature: receipts are signed only with --sign; without it they are unsigned
//
// Exit codes:
//
//	0 = clean shutdown
//	2 = config error
func runProxyCmd(args []string, stdout, stderr io.Writer) int {
	// Handle `proxy up` alias — strip "up" and pass remaining args
	if len(args) > 0 && args[0] == "up" {
		args = args[1:]
	}

	cmd := flag.NewFlagSet("proxy", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		upstream      string
		port          int
		apiKey        string
		jsonOutput    bool
		verbose       bool
		receiptsDir   string
		signKey       string
		tenantID      string
		policyPath    string
		dailyLimit    int64
		monthlyLimit  int64
		maxIterations int
		maxWallclock  time.Duration
		websocket     bool
	)

	cmd.StringVar(&upstream, "upstream", "https://api.openai.com/v1", "Upstream API base URL")
	cmd.IntVar(&port, "port", 9090, "Local proxy port")
	cmd.StringVar(&apiKey, "api-key", "", "API key to forward to upstream (or use OPENAI_API_KEY env)")
	cmd.BoolVar(&jsonOutput, "json", false, "Log receipts as JSON to stdout")
	cmd.BoolVar(&verbose, "verbose", false, "Verbose logging")
	cmd.StringVar(&receiptsDir, "receipts-dir", "./helm-receipts", "Directory for persistent receipt JSONL logs")
	cmd.StringVar(&signKey, "sign", "", "Ed25519 signing key seed (enables receipt signatures)")
	cmd.StringVar(&tenantID, "tenant-id", "default", "Tenant identifier recorded as the governing principal")
	cmd.StringVar(&policyPath, "policy", "", "Path to a serve policy file; without it every tool call is denied (fail-closed)")
	cmd.Int64Var(&dailyLimit, "daily-limit", 0, "Unsupported: the proxy has no monetary price for a tool call, so a non-zero budget is refused")
	cmd.Int64Var(&monthlyLimit, "monthly-limit", 0, "Unsupported: the proxy has no monetary price for a tool call, so a non-zero budget is refused")
	cmd.IntVar(&maxIterations, "max-iterations", 10, "Max tool calls per session (X-Helm-Session-ID) (0=unlimited)")
	cmd.DurationVar(&maxWallclock, "max-wallclock", 120*time.Second, "Max session duration from its first tool call (0=unlimited)")
	cmd.BoolVar(&websocket, "websocket", false, "Request Responses WebSocket mode (unsupported in OSS runtime)")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if websocket {
		_, _ = fmt.Fprintln(stderr, "Error: --websocket is not supported in the OSS proxy runtime")
		_, _ = fmt.Fprintln(stderr, "Use the HTTP proxy surface at /v1/chat/completions until Responses WebSocket support is implemented.")
		return 2
	}

	// The proxy forwards --api-key and serves the receipt log, so it binds
	// loopback unless HELM_PROXY_BIND_ADDR says otherwise, and a non-loopback
	// bind requires HELM_PROXY_TOKEN (audit S-01).
	proxyBind := listenerBindAddr(proxyBindAddrEnv)
	proxyToken := os.Getenv(proxyTokenEnv)
	if err := requireListenerAuth("proxy", proxyBind, proxyToken != "", "set "+proxyTokenEnv+" and have callers send it as their bearer token"); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	noteIgnoredSharedBind(stderr, "the proxy", proxyBindAddrEnv)

	// The proxy only ever sees token counts, never prices, so it cannot enforce
	// a spend budget (audit 07-01); refuse the flags instead of accepting them.
	if dailyLimit != 0 || monthlyLimit != 0 {
		_, _ = fmt.Fprintln(stderr, "Error: --daily-limit and --monthly-limit are not supported by the proxy: it sees token counts, not prices, so it cannot enforce a spend budget")
		return 2
	}
	if helmcrypto.ProductionMode() {
		_, _ = fmt.Fprintln(stderr, "Error: helm proxy is disabled under HELM_PRODUCTION: request, response, and SSE payloads do not have verified inline personal-data inspection")
		return 2
	}

	// A serve policy compiles to the Guardian rule graph. Absent --policy the
	// graph stays empty, which denies every tool call (fail-closed default).
	var policyGraph *prg.Graph
	if policyPath != "" {
		runtimePolicy, err := loadServePolicyRuntime(policyPath)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: load serve policy %q: %v\n", policyPath, err)
			return 2
		}
		policyGraph = runtimePolicy.Graph
		if authorized := len(runtimePolicy.AllowMap()); authorized == 0 {
			_, _ = fmt.Fprintf(stderr, "Warning: serve policy %q authorizes 0 actions; every tool call will be denied\n", policyPath)
		} else {
			_, _ = fmt.Fprintf(stderr, "Serve policy %q authorizes %d action(s)\n", policyPath, authorized)
		}
	}

	rt, err := newProxyRuntime(proxyConfig{
		upstream:      strings.TrimSuffix(upstream, "/"),
		apiKey:        apiKey,
		jsonOutput:    jsonOutput,
		verbose:       verbose,
		receiptsDir:   receiptsDir,
		signKey:       signKey,
		tenantID:      tenantID,
		policyGraph:   policyGraph,
		maxIterations: maxIterations,
		maxWallclock:  maxWallclock,
	}, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	defer rt.close()
	upstream = rt.upstream
	receiptPath := rt.receiptPath
	pg := rt.pg
	signer := rt.signer

	mux := newListenerRouteMux(listenerProxy)
	registerProxyRoutes(mux, rt)

	addr := net.JoinHostPort(proxyBind, strconv.Itoa(port))

	_, _ = fmt.Fprintf(stdout, "HELM Proxy Sidecar\n")
	_, _ = fmt.Fprintf(stdout, "══════════════════\n")
	_, _ = fmt.Fprintf(stdout, "  Upstream:    %s\n", upstream)
	_, _ = fmt.Fprintf(stdout, "  Listen:      http://%s\n", addr)
	_, _ = fmt.Fprintf(stdout, "  Health:      http://%s/healthz\n", addr)
	_, _ = fmt.Fprintf(stdout, "  Receipts:    %s\n", receiptPath)
	_, _ = fmt.Fprintf(stdout, "  Tenant:      %s\n", tenantID)
	if proxyToken != "" {
		_, _ = fmt.Fprintf(stdout, "  Auth:        bearer token (%s)\n", proxyTokenEnv)
	}
	if policyPath != "" {
		_, _ = fmt.Fprintf(stdout, "  Policy:      %s\n", policyPath)
	} else {
		_, _ = fmt.Fprintf(stdout, "  Policy:      none (every tool call is denied)\n")
	}
	if maxIterations > 0 {
		_, _ = fmt.Fprintf(stdout, "  Max Rounds:  %d\n", maxIterations)
	}
	if maxWallclock > 0 {
		_, _ = fmt.Fprintf(stdout, "  Wallclock:   %s\n", maxWallclock)
	}
	if signer != nil {
		_, _ = fmt.Fprintf(stdout, "  Signing:     Ed25519 (key: %s)\n", signer.KeyID)
	} else {
		_, _ = fmt.Fprintf(stdout, "  Signing:     none (receipts are hash-chained, not signed; pass --sign <seed>)\n")
	}
	_, _ = fmt.Fprintf(stdout, "  ProofGraph: %s\n", filepath.Join(receiptsDir, "proofgraph.json"))
	_, _ = fmt.Fprintf(stdout, "  Governance:  Guardian → ProofGraph\n")
	_, _ = fmt.Fprintf(stdout, "\n")
	_, _ = fmt.Fprintf(stdout, "  Drop-in usage:\n")
	_, _ = fmt.Fprintf(stdout, "    export OPENAI_BASE_URL=http://%s/v1\n", addr)
	_, _ = fmt.Fprintf(stdout, "    python your_app.py\n")
	_, _ = fmt.Fprintf(stdout, "\n")
	_, _ = fmt.Fprintf(stdout, "  Tool calls are governed, hashed, and receipted; a request that offers tools\n")
	_, _ = fmt.Fprintf(stdout, "  must not stream, and a response the proxy cannot parse is withheld. Ctrl+C to stop.\n")

	server := &http.Server{
		Addr: addr,
		// The proxy is an external ingress edge: run every request inside an
		// otelhttp server span so an inbound W3C traceparent is continued
		// (HELM-333) before governance and upstream forwarding run.
		Handler:           tracing.WrapEdgeHandler(wrapProxyAuth(mux, proxyToken), "helm.proxy"),
		ReadHeaderTimeout: 30 * time.Second,
	}

	// Graceful shutdown: persist ProofGraph on exit
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt)
		<-sigChan
		log.Println("[helm-proxy] shutting down, persisting ProofGraph...")
		persistProofGraph(pg, filepath.Join(receiptsDir, "proofgraph.json"))
		server.Close()
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	return 0
}

// registerProxyRoutes mounts the proxy listener's routes.
func registerProxyRoutes(mux routeMux, rt *proxyRuntime) {
	upstream, receiptPath, pg := rt.upstream, rt.receiptPath, rt.pg

	// Health endpoint
	healthHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","mode":"proxy","upstream":"` + upstream + `"}`))
	}
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/healthz", healthHandler)

	// Receipts endpoint — serve the JSONL file
	mux.HandleFunc("/helm/receipts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		data, err := os.ReadFile(receiptPath)
		if err != nil {
			http.Error(w, "no receipts yet", http.StatusNotFound)
			return
		}
		_, _ = w.Write(data)
	})

	// ProofGraph endpoint — serve the DAG as JSON
	mux.HandleFunc("/helm/proofgraph", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		nodes := pg.AllNodes()
		result := map[string]any{
			"nodes":   nodes,
			"heads":   pg.Heads(),
			"lamport": pg.LamportClock(),
			"count":   pg.Len(),
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		_, _ = w.Write(data)
	})

	// Proxy everything else
	mux.Handle("/", rt.handler)
}

func init() {
	Register(Subcommand{Name: "proxy", Aliases: []string{}, Usage: "OpenAI-compatible governance proxy", RunFn: runProxyCmd})
}

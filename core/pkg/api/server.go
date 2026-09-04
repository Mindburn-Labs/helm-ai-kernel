// Package api implements the HELM Governance REST API.
//
// Endpoints:
//
//	POST /api/v1/evaluate       — Evaluate a tool call through governance
//	GET  /api/v1/receipts/:id   — Retrieve a receipt
//	POST /api/v1/receipts/:id/complete — Record execution outcome
//	GET  /api/v1/verify/:session — Verify receipt chain for a session
//	GET  /api/v1/health         — Health check
//
// This server backs Python, TypeScript, and Rust SDKs.
//
// quantum_posture: receipts minted here use the shared receipt signer. Under
// HELM_PRODUCTION a missing signer fails closed; production callers must
// supply a persistent signer. Local-only servers may use an ephemeral signer
// and never claim a durable trust root.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/agentruntime"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/httperr"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/observability"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/pdp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tracing"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// Server is the HELM Governance REST API server.
type Server struct {
	mu              sync.RWMutex
	pdp             pdp.PolicyDecisionPoint
	receiptSigner   helmcrypto.Signer
	receipts        map[string]*contracts.Receipt
	sessions        map[receiptSessionKey][]string // tenant-qualified session → []receiptID
	lamport         uint64                         // highest causal Lamport clock across active sessions
	receiptSequence uint64
	mux             *http.ServeMux
	edge            http.Handler // otelhttp-wrapped entry point (HELM-333)
	allowedOrigins  []string     // CORS allowed origins (nil = no CORS headers)
	authenticator   Authenticator
}

// AuthenticatedPrincipal is the identity the legacy API trusts for protected
// routes. It is intentionally local to package api to avoid an auth->api import
// cycle while still letting callers inject JWT/API-key validation.
type AuthenticatedPrincipal struct {
	ID       string
	TenantID string
	Roles    []string
}

// Authenticator validates a request and returns the caller identity.
type Authenticator func(*http.Request) (AuthenticatedPrincipal, error)

type authenticatedPrincipalContextKey struct{}

// receiptSessionKey keeps caller-controlled session IDs from joining causal
// chains across tenant boundaries. The external session ID remains the signed
// Receipt.SessionID value; this key is internal ordering state only.
type receiptSessionKey struct {
	tenantID  string
	sessionID string
}

// ReceiptDTO stored in-memory / external schema.
type ReceiptDTO struct {
	ReceiptID           string            `json:"receipt_id"`
	DecisionID          string            `json:"decision_id"`
	CorrelationID       string            `json:"correlation_id,omitempty"`
	EffectID            string            `json:"effect_id"`
	ExternalReferenceID string            `json:"external_reference_id"`
	Status              string            `json:"status"`
	OutputHash          string            `json:"output_hash"`
	BlobHash            string            `json:"blob_hash,omitempty"`
	Timestamp           string            `json:"timestamp"`
	ExecutorID          string            `json:"executor_id,omitempty"`
	Signature           string            `json:"signature"`
	SignatureProfile    string            `json:"signature_profile,omitempty"`
	SignatureAlgorithm  string            `json:"signature_algorithm,omitempty"`
	KeyID               string            `json:"key_id,omitempty"`
	PublicKeySet        map[string]string `json:"public_key_set,omitempty"`
	PrevHash            string            `json:"prev_hash"`
	LamportClock        uint64            `json:"lamport_clock"`
	DecisionHash        string            `json:"decision_hash"`
	ArgsHash            string            `json:"args_hash,omitempty"`
	SignatureVersion    string            `json:"signature_version"`
	Verdict             string            `json:"verdict"`
	ReasonCode          string            `json:"reason_code"`
	PolicyHash          string            `json:"policy_hash"`
	SessionID           string            `json:"session_id"`
	Metadata            map[string]any    `json:"metadata,omitempty"`
}

func FromCanonical(r *contracts.Receipt) *ReceiptDTO {
	if r == nil {
		return nil
	}
	// DecisionHash is a canonical semantic field. Older receipts kept the
	// value only in metadata, so retain that compatibility fallback.
	decHash := r.DecisionHash
	if decHash == "" && r.Metadata != nil {
		if val, ok := r.Metadata["decision_hash"].(string); ok {
			decHash = val
		}
	}
	return &ReceiptDTO{
		ReceiptID:           r.ReceiptID,
		DecisionID:          r.DecisionID,
		CorrelationID:       r.CorrelationID,
		EffectID:            r.EffectID,
		ExternalReferenceID: r.ExternalReferenceID,
		Status:              r.Status,
		OutputHash:          r.OutputHash,
		BlobHash:            r.BlobHash,
		Timestamp:           r.Timestamp.UTC().Format(time.RFC3339Nano),
		ExecutorID:          r.ExecutorID,
		Signature:           r.Signature,
		SignatureProfile:    r.SignatureProfile,
		SignatureAlgorithm:  r.SignatureAlgorithm,
		KeyID:               r.KeyID,
		PublicKeySet:        r.PublicKeySet,
		PrevHash:            r.PrevHash,
		LamportClock:        r.LamportClock,
		DecisionHash:        decHash,
		ArgsHash:            r.ArgsHash,
		SignatureVersion:    r.SignatureVersion,
		Verdict:             r.Verdict,
		ReasonCode:          r.ReasonCode,
		PolicyHash:          r.PolicyHash,
		SessionID:           r.SessionID,
		Metadata:            r.Metadata,
	}
}

// EvaluateRequest is the JSON body sent by SDKs.
type EvaluateRequest struct {
	// Principal, Action, and Resource retain the v0.8 direct-daemon request
	// envelope. Authentication always supplies the effective principal.
	Principal   string         `json:"principal,omitempty"`
	Action      string         `json:"action,omitempty"`
	Resource    string         `json:"resource,omitempty"`
	Tool        string         `json:"tool"`
	Args        map[string]any `json:"args"`
	AgentID     string         `json:"agent_id"`
	EffectLevel string         `json:"effect_level"`
	SessionID   string         `json:"session_id"`
	Context     map[string]any `json:"context"`
	// Originator is accepted only by the dedicated OrganizationRuntime route.
	// It is distinct from the authenticated service principal executing the
	// request and replaces caller-controlled context aliases.
	Originator *contracts.OrganizationRuntimeOriginatorAssertion `json:"originator,omitempty"`
}

// NormalizeEvaluateRequest resolves the public V5 and direct-daemon aliases
// into one unambiguous request before any decision or receipt is produced.
func NormalizeEvaluateRequest(req *EvaluateRequest) error {
	req.Tool = strings.TrimSpace(req.Tool)
	legacyTool := strings.TrimSpace(req.Action)
	if req.Tool != "" && legacyTool != "" && req.Tool != legacyTool {
		return fmt.Errorf("tool and action must match when both are provided")
	}
	if req.Tool == "" {
		req.Tool = legacyTool
	}

	req.EffectLevel = strings.TrimSpace(req.EffectLevel)
	legacyEffectLevel := strings.TrimSpace(req.Resource)
	if req.EffectLevel != "" && legacyEffectLevel != "" && req.EffectLevel != legacyEffectLevel {
		return fmt.Errorf("effect_level and resource must match when both are provided")
	}
	if req.EffectLevel == "" {
		req.EffectLevel = legacyEffectLevel
	}
	if req.Tool == "" || req.EffectLevel == "" {
		return fmt.Errorf("tool and effect_level are required")
	}

	req.SessionID = strings.TrimSpace(req.SessionID)
	contextSessionID := ""
	if req.Context != nil {
		contextSessionID, _ = req.Context["session_id"].(string)
		contextSessionID = strings.TrimSpace(contextSessionID)
	}
	if req.SessionID != "" && contextSessionID != "" && req.SessionID != contextSessionID {
		return fmt.Errorf("session_id must match context.session_id when both are provided")
	}
	if req.SessionID == "" {
		req.SessionID = contextSessionID
	}
	if req.SessionID == "" {
		return fmt.Errorf("session_id is required")
	}

	normalizedSessionID, err := NormalizePublicSessionID(req.SessionID)
	if err != nil {
		return fmt.Errorf("session_id may not contain path separators")
	}
	req.SessionID = normalizedSessionID
	return nil
}

// NormalizeOrganizationRuntimeEvaluateRequest keeps the concrete resource
// separate from its effect class while retaining the shared action and session
// normalization used by the public evaluate envelope.
func NormalizeOrganizationRuntimeEvaluateRequest(req *EvaluateRequest) error {
	resource := strings.TrimSpace(req.Resource)
	effectLevel := strings.TrimSpace(req.EffectLevel)
	if resource == "" || effectLevel == "" {
		return fmt.Errorf("resource and effect_level are required for organization-runtime evaluation")
	}

	// NormalizeEvaluateRequest treats resource as the legacy effect-level alias.
	// Temporarily supply the explicit effect class, then restore the independently
	// bound concrete resource.
	req.Resource = effectLevel
	if err := NormalizeEvaluateRequest(req); err != nil {
		req.Resource = resource
		return err
	}
	req.Resource = resource
	return nil
}

// EvaluateResponse is the JSON response sent back to SDKs.
type EvaluateResponse struct {
	Allow                                  bool                                                `json:"allow"`
	Verdict                                string                                              `json:"verdict"`
	ReceiptID                              string                                              `json:"receipt_id"`
	DecisionID                             string                                              `json:"decision_id"`
	DecisionHash                           string                                              `json:"decision_hash"`
	ReasonCode                             string                                              `json:"reason_code"`
	PolicyRef                              string                                              `json:"policy_ref"`
	LamportClock                           uint64                                              `json:"lamport_clock"`
	OrganizationRuntimeDecisionAttestation *contracts.OrganizationRuntimeDecisionAttestationV1 `json:"organization_runtime_decision_attestation,omitempty"`
	// The legacy DecisionRecord-shaped fields remain additive v0.8 response
	// compatibility for direct-daemon callers.
	ID                 string `json:"id,omitempty"`
	Action             string `json:"action,omitempty"`
	Resource           string `json:"resource,omitempty"`
	Reason             string `json:"reason,omitempty"`
	PolicyVersion      string `json:"policy_version,omitempty"`
	PolicyDecisionHash string `json:"policy_decision_hash,omitempty"`
	Signature          string `json:"signature,omitempty"`
}

// ServerConfig configures the API server.
type ServerConfig struct {
	PDP            pdp.PolicyDecisionPoint
	Addr           string   // e.g., ":8443"
	AllowedOrigins []string // CORS allowed origins (nil = no CORS headers emitted)
	Authenticator  Authenticator
	// ReceiptSigner signs V5 evaluation receipts. Production callers must
	// provide a persistent signer; otherwise evaluate fails closed.
	ReceiptSigner helmcrypto.Signer
}

// NewServer creates a new HELM API server.
//
// NOTE: this is NOT the helm-ai-kernel daemon's server. The daemon
// (core/cmd/helm-ai-kernel) registers its own ~111 routes on its own mux and
// builds its handler chain in buildAPIHandler; this constructor serves the six
// routes in registerRoutes below and is used by embedders and tests. Wiring a
// behavior here does not put it on the daemon's request path — HELM-495 was
// exactly that mistake, with tracing wired here and nowhere else.
func NewServer(cfg ServerConfig) *Server {
	receiptSigner := cfg.ReceiptSigner
	if receiptSigner == nil {
		// NewEd25519Signer deliberately refuses HELM_PRODUCTION, leaving this
		// nil so handleEvaluate can fail closed rather than minting a receipt
		// against an unstable trust root.
		if signer, err := helmcrypto.NewEd25519Signer("api-local"); err == nil {
			receiptSigner = signer
		}
	}
	s := &Server{
		pdp:            cfg.PDP,
		receiptSigner:  receiptSigner,
		receipts:       make(map[string]*contracts.Receipt),
		sessions:       make(map[receiptSessionKey][]string),
		mux:            http.NewServeMux(),
		allowedOrigins: cfg.AllowedOrigins,
		authenticator:  cfg.Authenticator,
	}
	s.registerRoutes()
	// The edge participates in W3C trace context (HELM-333): every request
	// runs inside a server span, continuing an inbound traceparent when
	// present. The tracer is resolved per request from the global
	// TracerProvider, so OTel may be configured after this constructor runs —
	// only after traffic starts is it too late (see tracing.WrapEdgeHandler).
	s.edge = tracing.WrapEdgeHandler(http.HandlerFunc(s.serveEdge), "helm.api")
	return s
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/api/v1/evaluate", s.handleEvaluate)
	s.mux.HandleFunc("/api/v1/guardian/evaluate", s.handleEvaluate)
	s.mux.HandleFunc("/api/v1/receipts/", s.handleReceipts)
	s.mux.HandleFunc("/api/v1/verify/", s.handleVerify)
	s.mux.HandleFunc("/api/v1/launchpad/", s.handleLaunchpad)
	s.mux.HandleFunc("/api/v1/health", s.handleHealth)
}

// ServeHTTP implements http.Handler. It delegates through the otelhttp
// wrapper so every request gets a server span before edge handling runs.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.edge == nil {
		// Zero-value Server (struct literals in tests): no traced wrapper —
		// serve the bare edge, matching pre-otelhttp behavior.
		s.serveEdge(w, r)
		return
	}
	s.edge.ServeHTTP(w, r)
}

// serveEdge is the edge handler running inside the server span: CORS,
// correlation adopt-or-mint, and routing.
func (s *Server) serveEdge(w http.ResponseWriter, r *http.Request) {
	// SEC: CORS uses same-origin by default. Callers should wrap with
	// auth.CORSMiddleware for configurable origin allowlisting.
	// Wildcard CORS removed to prevent cross-origin receipt exfiltration.
	origin := r.Header.Get("Origin")
	if origin != "" && s.allowedOrigins != nil {
		for _, ao := range s.allowedOrigins {
			if ao == "*" || ao == origin {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				// The response varies by Origin; without Vary a shared cache
				// could reuse it across origins.
				w.Header().Add("Vary", "Origin")
				break
			}
		}
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Helm-Correlation-ID")
	w.Header().Set("Access-Control-Expose-Headers", "X-Helm-Correlation-ID")
	// Adopt-or-mint the product request identity at this external edge
	// (telemetry contract §2.2): a valid inbound X-Helm-Correlation-ID is
	// adopted, anything else is replaced with a minted ID, and the ID used
	// is always echoed on the response — including OPTIONS preflight.
	corr, _ := tracing.AdoptOrMintFromHeaders(r.Header)
	ctx := tracing.WithCorrelationID(r.Context(), corr)
	tracing.InjectHTTPHeaders(ctx, w.Header())
	// Stamp the product identity onto the server span so OTel traces and
	// receipts join 1:1 (same attribute the governance tracer uses).
	oteltrace.SpanFromContext(ctx).SetAttributes(
		attribute.String(observability.HelmCorrelationID, string(corr)))
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	s.mux.ServeHTTP(w, r.WithContext(ctx))
}

// ListenAndServe starts the API server with production-grade timeouts.
func (s *Server) ListenAndServe(addr string) error {
	log.Printf("HELM API server listening on %s", addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           s,
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return srv.ListenAndServe()
}

func (s *Server) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	principal, ok := s.requireAuthenticated(w, r)
	if !ok {
		return
	}

	var req EvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if err := NormalizeEvaluateRequest(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if s.receiptSigner == nil {
		http.Error(w, "receipt signer unavailable", http.StatusServiceUnavailable)
		return
	}

	req.AgentID = principal.ID
	if req.Context == nil {
		req.Context = make(map[string]any)
	}
	req.Context["principal_id"] = principal.ID
	req.Context["tenant_id"] = principal.TenantID
	req.Context["session_id"] = req.SessionID

	argsRaw, err := json.Marshal(req.Args)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid args"})
		return
	}
	argsHash, err := agentruntime.ComputeArgsHash(argsRaw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid args"})
		return
	}

	// Map to PDP DecisionRequest.
	decReq := &pdp.DecisionRequest{
		Principal: principal.ID,
		Action:    req.Tool,
		Resource:  req.EffectLevel,
		Context:   req.Context,
	}

	decResp, err := s.pdp.Evaluate(r.Context(), decReq)
	if err != nil {
		// Fail-closed: return DENY
		writeJSON(w, http.StatusOK, EvaluateResponse{
			Allow:      false,
			ReasonCode: "API_ERROR",
		})
		return
	}
	policyHash := strings.TrimSpace(s.pdp.PolicyHash())
	if policyHash == "" {
		http.Error(w, "policy hash unavailable", http.StatusServiceUnavailable)
		return
	}

	// Generate a receipt whose causal clock is scoped to the authenticated
	// tenant and signed session identifier.
	chainKey := receiptSessionKey{tenantID: principal.TenantID, sessionID: req.SessionID}
	s.mu.Lock()
	lamport := uint64(1)
	prevHash := ""
	if sessionReceipts, ok := s.sessions[chainKey]; ok && len(sessionReceipts) > 0 {
		lastID := sessionReceipts[len(sessionReceipts)-1]
		lastReceipt, ok := s.receipts[lastID]
		if !ok {
			s.mu.Unlock()
			http.Error(w, "previous receipt unavailable", http.StatusServiceUnavailable)
			return
		}
		var err error
		prevHash, err = contracts.ReceiptChainHash(lastReceipt)
		if err != nil {
			s.mu.Unlock()
			http.Error(w, "previous receipt hash unavailable", http.StatusServiceUnavailable)
			return
		}
		lamport = lastReceipt.LamportClock + 1
	}

	s.receiptSequence++
	receiptID := fmt.Sprintf("rcpt-%s-%d", time.Now().Format("20060102-150405"), s.receiptSequence)
	// Decision IDs are independent of the tenant/session-local Lamport clock.
	// Binding them to the receipt identity also keeps the V5 signed fields
	// unique for the lifetime of that receipt.
	decisionID := "dec-" + receiptID

	status := "DENY"
	if decResp.Allow {
		status = "ALLOW"
	}
	policyRef := decResp.PolicyRef
	if policyRef == "" {
		policyRef = "default"
	}

	correlationID := ""
	if corr, ok := tracing.GetCorrelationID(r.Context()); ok {
		correlationID = string(corr)
	}

	receipt := &contracts.Receipt{
		ReceiptID:     receiptID,
		DecisionID:    decisionID,
		CorrelationID: correlationID,
		EffectID:      req.Tool,
		Status:        status,
		// OutputHash is part of the V5 signed preimage. DecisionHash remains
		// the semantic/exported alias for SDK consumers and legacy receipts.
		OutputHash:   decResp.DecisionHash,
		DecisionHash: decResp.DecisionHash,
		Timestamp:    time.Now().UTC(),
		ExecutorID:   req.AgentID,
		PrevHash:     prevHash,
		LamportClock: lamport,
		ArgsHash:     argsHash,
		Verdict:      status,
		ReasonCode:   decResp.ReasonCode,
		PolicyHash:   policyHash,
		SessionID:    req.SessionID,
		Metadata: map[string]any{
			"decision_hash": decResp.DecisionHash,
			"principal_id":  principal.ID,
			"tenant_id":     principal.TenantID,
		},
	}
	if err := s.receiptSigner.SignReceipt(receipt); err != nil {
		s.mu.Unlock()
		http.Error(w, "receipt signing failed", http.StatusServiceUnavailable)
		return
	}

	if lamport > s.lamport {
		s.lamport = lamport
	}
	s.receipts[receiptID] = receipt
	s.sessions[chainKey] = append(s.sessions[chainKey], receiptID)
	s.mu.Unlock()

	w.Header().Set("X-Helm-Decision-ID", decisionID)
	w.Header().Set("X-Helm-Verdict", status)
	w.Header().Set("X-Helm-Policy-Version", policyRef)
	w.Header().Set("X-Helm-Decision-Hash", decResp.DecisionHash)
	w.Header().Set("X-Helm-Receipt-ID", receiptID)

	writeJSON(w, http.StatusOK, EvaluateResponse{
		Allow:              decResp.Allow,
		Verdict:            status,
		ReceiptID:          receiptID,
		DecisionID:         decisionID,
		DecisionHash:       decResp.DecisionHash,
		ReasonCode:         decResp.ReasonCode,
		PolicyRef:          policyRef,
		LamportClock:       lamport,
		ID:                 decisionID,
		Action:             req.Tool,
		Resource:           req.EffectLevel,
		Reason:             decResp.ReasonCode,
		PolicyVersion:      policyRef,
		PolicyDecisionHash: decResp.DecisionHash,
	})
}

func (s *Server) handleReceipts(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireAuthenticated(w, r)
	if !ok {
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/receipts/")

	// POST /api/v1/receipts/:id/complete
	if strings.HasSuffix(path, "/complete") && r.Method == http.MethodPost {
		receiptID := strings.TrimSuffix(path, "/complete")
		s.mu.RLock()
		receipt, exists := s.receipts[receiptID]
		s.mu.RUnlock()
		if !exists {
			http.Error(w, "receipt not found", http.StatusNotFound)
			return
		}
		if !receiptVisibleToPrincipal(receipt, principal) {
			WriteForbidden(w, "receipt belongs to another tenant")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "recorded"})
		return
	}

	// GET /api/v1/receipts/:id
	if r.Method == http.MethodGet && path != "" {
		s.mu.RLock()
		receipt, exists := s.receipts[path]
		s.mu.RUnlock()
		if !exists {
			http.Error(w, "receipt not found", http.StatusNotFound)
			return
		}
		if !receiptVisibleToPrincipal(receipt, principal) {
			WriteForbidden(w, "receipt belongs to another tenant")
			return
		}
		writeJSON(w, http.StatusOK, FromCanonical(receipt))
		return
	}

	// GET /api/v1/receipts/ — list all
	if r.Method == http.MethodGet {
		s.mu.RLock()
		all := make([]*ReceiptDTO, 0, len(s.receipts))
		for _, r := range s.receipts {
			if !receiptVisibleToPrincipal(r, principal) {
				continue
			}
			all = append(all, FromCanonical(r))
		}
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, all)
		return
	}

	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	principal, ok := s.requireAuthenticated(w, r)
	if !ok {
		return
	}

	sessionID := strings.TrimPrefix(r.URL.Path, "/api/v1/verify/")
	chainKey := receiptSessionKey{tenantID: principal.TenantID, sessionID: sessionID}
	s.mu.RLock()
	receiptIDs, exists := s.sessions[chainKey]
	if !exists {
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"valid":   false,
			"error":   "session not found",
			"session": sessionID,
		})
		return
	}

	var receipts []*contracts.Receipt
	for _, id := range receiptIDs {
		if r, ok := s.receipts[id]; ok {
			if !receiptVisibleToPrincipal(r, principal) {
				continue
			}
			receipts = append(receipts, r)
		}
	}
	s.mu.RUnlock()

	if len(receipts) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"valid":    true,
			"session":  sessionID,
			"receipts": 0,
			"chain":    map[string]any{},
		})
		return
	}

	// Verify the shared receipt-chain contract: genesis has an empty prev_hash,
	// each successor carries the canonical hash of its predecessor, and Lamport
	// clocks are strictly monotonic in session order.
	valid := true
	for i, receipt := range receipts {
		_, signatureValid, err := helmcrypto.VerifyReceiptProfile(
			receipt.PublicKeySet[helmcrypto.SigPrefixEd25519],
			receipt.PublicKeySet[helmcrypto.SigPrefixMLDSA65],
			receipt,
		)
		if err != nil || !signatureValid {
			valid = false
			break
		}
		if i == 0 {
			if receipt.PrevHash != "" {
				valid = false
			}
			continue
		}
		previous := receipts[i-1]
		if receipt.LamportClock <= previous.LamportClock {
			valid = false
			break
		}
		expectedPrevHash, err := contracts.ReceiptChainHash(previous)
		if err != nil || receipt.PrevHash != expectedPrevHash {
			valid = false
			break
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"valid":    valid,
		"session":  sessionID,
		"receipts": len(receipts),
		"chain": map[string]any{
			"first_lamport": receipts[0].LamportClock,
			"last_lamport":  receipts[len(receipts)-1].LamportClock,
		},
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	receipts := len(s.receipts)
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"backend":  string(s.pdp.Backend()),
		"receipts": receipts,
		"lamport":  s.lamport,
	})
}

func (s *Server) requireAuthenticated(w http.ResponseWriter, r *http.Request) (AuthenticatedPrincipal, bool) {
	if s.authenticator == nil {
		httperr.WriteUnauthorized(w, "Authentication not configured")
		return AuthenticatedPrincipal{}, false
	}
	principal, err := s.authenticator(r)
	if err != nil {
		httperr.WriteUnauthorized(w, err.Error())
		return AuthenticatedPrincipal{}, false
	}
	principal.ID = strings.TrimSpace(principal.ID)
	principal.TenantID = strings.TrimSpace(principal.TenantID)
	if principal.ID == "" || principal.TenantID == "" {
		httperr.WriteUnauthorized(w, "Authenticated principal and tenant are required")
		return AuthenticatedPrincipal{}, false
	}
	return principal, true
}

func WithAuthenticatedPrincipal(ctx context.Context, principal AuthenticatedPrincipal) context.Context {
	return context.WithValue(ctx, authenticatedPrincipalContextKey{}, principal)
}

func AuthenticatedPrincipalFromContext(ctx context.Context) (AuthenticatedPrincipal, bool) {
	principal, ok := ctx.Value(authenticatedPrincipalContextKey{}).(AuthenticatedPrincipal)
	if !ok {
		return AuthenticatedPrincipal{}, false
	}
	principal.ID = strings.TrimSpace(principal.ID)
	principal.TenantID = strings.TrimSpace(principal.TenantID)
	return principal, principal.ID != "" && principal.TenantID != ""
}

func receiptVisibleToPrincipal(receipt *contracts.Receipt, principal AuthenticatedPrincipal) bool {
	if receipt == nil || receipt.Metadata == nil {
		return false
	}
	tenantID, _ := receipt.Metadata["tenant_id"].(string)
	return strings.TrimSpace(tenantID) == principal.TenantID
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

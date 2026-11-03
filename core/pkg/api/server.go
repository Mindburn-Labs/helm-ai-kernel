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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/pdp"
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

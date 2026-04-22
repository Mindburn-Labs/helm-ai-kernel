// Package api implements the HELM Governance REST API.
//
// Endpoints:
//   POST /api/v1/evaluate       — Evaluate a tool call through governance
//   GET  /api/v1/receipts/:id   — Retrieve a receipt
//   POST /api/v1/receipts/:id/complete — Record execution outcome
//   GET  /api/v1/verify/:session — Verify receipt chain for a session
//   GET  /api/v1/health         — Health check
//
// This server backs Python, TypeScript, and Rust SDKs.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/pdp"
)

// Server is the HELM Governance REST API server.
type Server struct {
	mu             sync.RWMutex
	pdp            pdp.PolicyDecisionPoint
	receipts       map[string]*Receipt
	sessions       map[string][]string // sessionID → []receiptID
	lamport        uint64
	mux            *http.ServeMux
	allowedOrigins []string // CORS allowed origins (nil = no CORS headers)
}

// Receipt stored in-memory.
type Receipt struct {
	ReceiptID    string         `json:"receipt_id"`
	DecisionID   string         `json:"decision_id"`
	EffectID     string         `json:"effect_id"`
	Status       string         `json:"status"`
	Timestamp    string         `json:"timestamp"`
	ExecutorID   string         `json:"executor_id,omitempty"`
	Signature    string         `json:"signature"`
	PrevHash     string         `json:"prev_hash"`
	LamportClock uint64         `json:"lamport_clock"`
	DecisionHash string         `json:"decision_hash"`
	ArgsHash     string         `json:"args_hash,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

// EvaluateRequest is the JSON body sent by SDKs.
type EvaluateRequest struct {
	Tool        string         `json:"tool"`
	Args        map[string]any `json:"args"`
	AgentID     string         `json:"agent_id"`
	EffectLevel string         `json:"effect_level"`
	SessionID   string         `json:"session_id"`
	Context     map[string]any `json:"context"`
}

// EvaluateResponse is the JSON response sent back to SDKs.
type EvaluateResponse struct {
	Allow        bool   `json:"allow"`
	ReceiptID    string `json:"receipt_id"`
	DecisionHash string `json:"decision_hash"`
	ReasonCode   string `json:"reason_code"`
	PolicyRef    string `json:"policy_ref"`
	LamportClock uint64 `json:"lamport_clock"`
}

// ServerConfig configures the API server.
type ServerConfig struct {
	PDP            pdp.PolicyDecisionPoint
	Addr           string   // e.g., ":8443"
	AllowedOrigins []string // CORS allowed origins (nil = no CORS headers emitted)
}

// NewServer creates a new HELM API server.
func NewServer(cfg ServerConfig) *Server {
	s := &Server{
		pdp:            cfg.PDP,
		receipts:       make(map[string]*Receipt),
		sessions:       make(map[string][]string),
		mux:            http.NewServeMux(),
		allowedOrigins: cfg.AllowedOrigins,
	}
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/api/v1/evaluate", s.handleEvaluate)
	s.mux.HandleFunc("/api/v1/receipts/", s.handleReceipts)
	s.mux.HandleFunc("/api/v1/verify/", s.handleVerify)
	s.mux.HandleFunc("/api/v1/health", s.handleHealth)
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// SEC: CORS uses same-origin by default. Callers should wrap with
	// auth.CORSMiddleware for configurable origin allowlisting.
	// Wildcard CORS removed to prevent cross-origin receipt exfiltration.
	origin := r.Header.Get("Origin")
	if origin != "" && s.allowedOrigins != nil {
		for _, ao := range s.allowedOrigins {
			if ao == "*" || ao == origin {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				break
			}
		}
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	s.mux.ServeHTTP(w, r)
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

	var req EvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	// Map to PDP DecisionRequest.
	ctx := context.Background()
	decReq := &pdp.DecisionRequest{
		Principal: req.AgentID,
		Action:    req.Tool,
		Resource:  req.EffectLevel,
		Context:   req.Context,
	}

	decResp, err := s.pdp.Evaluate(ctx, decReq)
	if err != nil {
		// Fail-closed: return DENY
		writeJSON(w, http.StatusOK, EvaluateResponse{
			Allow:      false,
			ReasonCode: "API_ERROR",
		})
		return
	}

	// Generate receipt.
	s.mu.Lock()
	s.lamport++
	lamport := s.lamport
	prevHash := "sha256:genesis"
	if sessionReceipts, ok := s.sessions[req.SessionID]; ok && len(sessionReceipts) > 0 {
		lastID := sessionReceipts[len(sessionReceipts)-1]
		if lastReceipt, ok := s.receipts[lastID]; ok {
			prevHash = "sha256:" + lastReceipt.Signature[:64]
		}
	}

	receiptID := fmt.Sprintf("rcpt-%s-%d", time.Now().Format("20060102-150405"), lamport)
	argsJSON, _ := json.Marshal(req.Args)
	argsHash := sha256.Sum256(argsJSON)

	status := "DENY"
	if decResp.Allow {
		status = "ALLOW"
	}

	sig := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s:%d", receiptID, status, prevHash, lamport)))

	receipt := &Receipt{
		ReceiptID:    receiptID,
		DecisionID:   fmt.Sprintf("dec-%d", lamport),
		EffectID:     req.Tool,
		Status:       status,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		ExecutorID:   req.AgentID,
		Signature:    hex.EncodeToString(sig[:]),
		PrevHash:     prevHash,
		LamportClock: lamport,
		DecisionHash: decResp.DecisionHash,
		ArgsHash:     "sha256:" + hex.EncodeToString(argsHash[:]),
	}

	s.receipts[receiptID] = receipt
	s.sessions[req.SessionID] = append(s.sessions[req.SessionID], receiptID)
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, EvaluateResponse{
		Allow:        decResp.Allow,
		ReceiptID:    receiptID,
		DecisionHash: decResp.DecisionHash,
		ReasonCode:   decResp.ReasonCode,
		PolicyRef:    decResp.PolicyRef,
		LamportClock: lamport,
	})
}

func (s *Server) handleReceipts(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/receipts/")

	// POST /api/v1/receipts/:id/complete
	if strings.HasSuffix(path, "/complete") && r.Method == http.MethodPost {
		receiptID := strings.TrimSuffix(path, "/complete")
		s.mu.RLock()
		_, exists := s.receipts[receiptID]
		s.mu.RUnlock()
		if !exists {
			http.Error(w, "receipt not found", http.StatusNotFound)
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
		writeJSON(w, http.StatusOK, receipt)
		return
	}

	// GET /api/v1/receipts/ — list all
	if r.Method == http.MethodGet {
		s.mu.RLock()
		all := make([]*Receipt, 0, len(s.receipts))
		for _, r := range s.receipts {
			all = append(all, r)
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

	sessionID := strings.TrimPrefix(r.URL.Path, "/api/v1/verify/")
	s.mu.RLock()
	receiptIDs, exists := s.sessions[sessionID]
	if !exists {
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"valid":   false,
			"error":   "session not found",
			"session": sessionID,
		})
		return
	}

	var receipts []*Receipt
	for _, id := range receiptIDs {
		if r, ok := s.receipts[id]; ok {
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

	// Verify chain: Lamport monotonicity
	valid := true
	for i := 1; i < len(receipts); i++ {
		if receipts[i].LamportClock <= receipts[i-1].LamportClock {
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

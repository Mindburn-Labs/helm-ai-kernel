package a2a

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWellKnownHandler_MethodNotAllowed(t *testing.T) {
	handler := NewWellKnownHandler(&staticCardProvider{card: &AgentCard{}})
	req := httptest.NewRequest(http.MethodPost, "/.well-known/agent-card.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

func TestWellKnownHandler_NilProvider(t *testing.T) {
	handler := NewWellKnownHandler(&staticCardProvider{card: nil})
	req := httptest.NewRequest(http.MethodGet, "/.well-known/agent-card.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}

func TestEvaluateFederationPolicy_AllowDeny(t *testing.T) {
	policy := &FederationPolicy{
		AllowedOrgs:   []string{"trusted-org", "partner-org"},
		DenyOrgs:      []string{"evil-org"},
		RequireProof:  true,
		MinTrustLevel: "limited",
	}

	tests := []struct {
		name     string
		fc       *FederationContext
		wantOk   bool
		wantCode DenyReason
	}{
		{
			"nil context passes",
			nil, true, "",
		},
		{
			"allowed org with proof",
			&FederationContext{OriginOrg: "trusted-org", TrustLevel: "full", ProofCapsuleRef: "cap:123"},
			true, "",
		},
		{
			"denied org",
			&FederationContext{OriginOrg: "evil-org", TrustLevel: "full", ProofCapsuleRef: "cap:123"},
			false, DenyFederationOrgDenied,
		},
		{
			"unknown org",
			&FederationContext{OriginOrg: "unknown-org", TrustLevel: "full", ProofCapsuleRef: "cap:123"},
			false, DenyFederationOrgDenied,
		},
		{
			"trust too low",
			&FederationContext{OriginOrg: "trusted-org", TrustLevel: "verify_only", ProofCapsuleRef: "cap:123"},
			false, DenyFederationTrustTooLow,
		},
		{
			"no proof when required",
			&FederationContext{OriginOrg: "trusted-org", TrustLevel: "full", ProofCapsuleRef: ""},
			false, DenyFederationProofInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EvaluateFederationPolicy(tt.fc, policy)
			if result.Accepted != tt.wantOk {
				t.Fatalf("Accepted = %v, want %v (deny: %s)", result.Accepted, tt.wantOk, result.DenyReason)
			}
			if !result.Accepted && result.DenyReason != tt.wantCode {
				t.Fatalf("DenyReason = %q, want %q", result.DenyReason, tt.wantCode)
			}
		})
	}
}

// ─── Test helpers ────────────────────────────────────────────────

type staticCardProvider struct {
	card *AgentCard
}

func (p *staticCardProvider) GetCard() *AgentCard {
	return p.card
}

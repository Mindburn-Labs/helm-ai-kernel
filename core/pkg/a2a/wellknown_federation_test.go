package a2a

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWellKnownHandler_ServesCard(t *testing.T) {
	card := &AgentCard{
		AgentID:  "test-agent",
		Name:     "Test Agent",
		Endpoint: "https://test.example.com/a2a",
		Provider: &AgentProvider{
			Organization: "TestOrg",
			URL:          "https://testorg.com",
		},
		SupportedVersions:  []SchemaVersion{CurrentVersion},
		Skills:             []AgentSkill{{ID: "test.skill", Name: "Test Skill"}},
		DefaultInputModes:  []string{"text"},
		DefaultOutputModes: []string{"text"},
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	card.ContentHash = ComputeCardHash(card)

	provider := &staticCardProvider{card: card}
	handler := NewWellKnownHandler(provider)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/agent-card.json", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected application/json, got %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=3600" {
		t.Fatalf("expected cache-control public, got %q", cc)
	}

	var decoded AgentCard
	if err := json.NewDecoder(rec.Body).Decode(&decoded); err != nil {
		t.Fatalf("failed to decode agent card: %v", err)
	}
	if decoded.AgentID != "test-agent" {
		t.Fatalf("expected agent_id 'test-agent', got %q", decoded.AgentID)
	}
	if decoded.Provider == nil || decoded.Provider.Organization != "TestOrg" {
		t.Fatal("expected provider with Organization='TestOrg'")
	}

	// Card must pass validation
	if err := ValidateAgentCard(&decoded); err != nil {
		t.Fatalf("returned card fails validation: %v", err)
	}
}

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

func TestKernelCardProvider_BuildsValidCard(t *testing.T) {
	provider := NewKernelCardProvider(KernelCardConfig{
		AgentID:      "helm-test",
		Name:         "HELM Test",
		EndpointURL:  "https://helm.test.com",
		Organization: "Mindburn Labs",
		OrgURL:       "https://mindburn.org",
		AuthMethods:  []AuthMethod{AuthMethodAPIKey, AuthMethodOAuth2},
	})

	card := provider.GetCard()
	if card == nil {
		t.Fatal("expected non-nil card")
	}
	if err := ValidateAgentCard(card); err != nil {
		t.Fatalf("card fails validation: %v", err)
	}
	if card.AgentID != "helm-test" {
		t.Fatalf("expected agent_id 'helm-test', got %q", card.AgentID)
	}
	if len(card.DefaultInputModes) == 0 {
		t.Fatal("expected defaultInputModes to be set")
	}
	if !card.Capabilities.StateTransitionHistory {
		t.Fatal("expected stateTransitionHistory = true")
	}

	// Verify content hash is stable
	hash1 := card.ContentHash
	hash2 := ComputeCardHash(card)
	if hash1 != hash2 {
		t.Fatalf("content hash not stable: %q != %q", hash1, hash2)
	}
}

func TestFederationContext_Validation(t *testing.T) {
	tests := []struct {
		name    string
		fc      *FederationContext
		wantErr bool
	}{
		{"nil is valid", nil, false},
		{"valid full", &FederationContext{OriginOrg: "org-a", TrustLevel: "full"}, false},
		{"valid limited", &FederationContext{OriginOrg: "org-a", TrustLevel: "limited"}, false},
		{"missing origin", &FederationContext{OriginOrg: "", TrustLevel: "full"}, true},
		{"missing trust", &FederationContext{OriginOrg: "org-a", TrustLevel: ""}, true},
		{"invalid trust", &FederationContext{OriginOrg: "org-a", TrustLevel: "yolo"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFederationContext(tt.fc)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateFederationContext() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
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

func TestProofCapsule_Lifecycle(t *testing.T) {
	capsule := ExportFederationProof(
		"test-org",
		"sha256:abc123",
		[]string{"node:1", "node:2", "node:3"},
		100,
		"v1.0",
		time.Hour,
	)

	if capsule.OriginOrg != "test-org" {
		t.Fatalf("expected origin_org 'test-org', got %q", capsule.OriginOrg)
	}
	if capsule.ContentHash == "" {
		t.Fatal("content hash must be set")
	}

	// Validate fresh capsule
	if err := ValidateProofCapsule(capsule); err != nil {
		t.Fatalf("fresh capsule should be valid: %v", err)
	}

	// Expired capsule
	expired := *capsule
	expired.ExpiresAt = time.Now().Add(-time.Minute)
	if err := ValidateProofCapsule(&expired); err == nil {
		t.Fatal("expired capsule should fail validation")
	}

	// Tampered capsule
	tampered := *capsule
	tampered.ContentHash = "sha256:tampered"
	if err := ValidateProofCapsule(&tampered); err == nil {
		t.Fatal("tampered capsule should fail validation")
	}
}

func TestAgentCard_V1_LF_Fields(t *testing.T) {
	card := &AgentCard{
		AgentID:  "lf-test",
		Name:     "LF Test Agent",
		Endpoint: "https://example.com/a2a",
		Provider: &AgentProvider{
			Organization: "Linux Foundation",
			URL:          "https://linuxfoundation.org",
		},
		SupportedVersions:  []SchemaVersion{CurrentVersion},
		Skills: []AgentSkill{
			{
				ID:          "research",
				Name:        "Research",
				Description: "Conduct research",
				Examples:    []string{"Research the market for X", "Summarize paper Y"},
				InputModes:  []string{"text"},
				OutputModes: []string{"text", "artifact"},
			},
		},
		DefaultInputModes:  []string{"text", "structured"},
		DefaultOutputModes: []string{"text", "structured", "artifact"},
		Capabilities: AgentCapabilities{
			Streaming:              true,
			PushNotifications:      false,
			StateTransitionHistory: true,
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Validate
	if err := ValidateAgentCard(card); err != nil {
		t.Fatalf("LF v1.0 card should be valid: %v", err)
	}

	// Hash stability
	hash1 := ComputeCardHash(card)
	hash2 := ComputeCardHash(card)
	if hash1 != hash2 {
		t.Fatal("card hash not deterministic")
	}

	// Verify new fields appear in JSON
	data, _ := json.Marshal(card)
	var raw map[string]any
	_ = json.Unmarshal(data, &raw)

	if raw["defaultInputModes"] == nil {
		t.Fatal("defaultInputModes missing from JSON")
	}
	if raw["capabilities"] == nil {
		t.Fatal("capabilities missing from JSON")
	}
	if raw["provider"] == nil {
		t.Fatal("provider missing from JSON")
	}

	// Check examples in skills
	skills := raw["skills"].([]any)
	skill0 := skills[0].(map[string]any)
	if skill0["examples"] == nil {
		t.Fatal("skill examples missing from JSON")
	}
}

func TestValidateAgentCard_ProviderOrganizationRequired(t *testing.T) {
	card := &AgentCard{
		AgentID:           "test",
		Endpoint:          "https://test.com",
		SupportedVersions: []SchemaVersion{CurrentVersion},
		Skills:            []AgentSkill{{ID: "s", Name: "S"}},
		Provider:          &AgentProvider{Organization: ""}, // empty org
	}
	if err := ValidateAgentCard(card); err == nil {
		t.Fatal("expected error for empty provider.organization")
	}
}

// ─── Test helpers ────────────────────────────────────────────────

type staticCardProvider struct {
	card *AgentCard
}

func (p *staticCardProvider) GetCard() *AgentCard {
	return p.card
}

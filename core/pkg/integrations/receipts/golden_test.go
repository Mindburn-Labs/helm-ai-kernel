package receipts

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/integrations/capgraph"
)

// TestGoldenReceipt_Allowed verifies the receipt JSON structure for allowed executions.
func TestGoldenReceipt_Allowed(t *testing.T) {
	capRef := CapabilityRef{
		URN:              capgraph.CapabilityURN("cap://github/list-repos@1.0.0"),
		ConnectorVersion: "github-connector-1.2.3",
		ConnectionID:     "conn-abc-123",
	}
	authCtx := AuthContext{
		PrincipalID: "user-42",
		OrgID:       "org-7",
		Roles:       []string{"admin"},
	}

	r := NewAllowed(capRef, authCtx, "sha256:policy123")
	r.Provenance = ZTProvenance{
		TrustLevel:   "VERIFIED",
		TTL:          300,
		Residency:    "eu-west-1",
		ResponseHash: "sha256:abc123def456",
	}
	r.Cost = CostImpact{
		DurationMs:      150,
		RateLimitUnits:  1,
		SpendDeltaCents: 0,
	}
	r.EvidenceRefs = []EvidenceRef{
		{ArtifactID: "ev-001", Hash: "sha256:evidence1"},
	}

	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Round-trip: unmarshal back.
	var decoded IntegrationReceipt
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Validate key fields.
	if decoded.Status != "executed" {
		t.Errorf("expected status 'executed', got %q", decoded.Status)
	}
	if !decoded.PolicyDecision.Allowed {
		t.Error("expected allowed=true")
	}
	if decoded.PolicyDecision.PolicyHash != "sha256:policy123" {
		t.Errorf("unexpected policy hash: %s", decoded.PolicyDecision.PolicyHash)
	}
	if string(decoded.CapabilityRef.URN) != "cap://github/list-repos@1.0.0" {
		t.Errorf("unexpected URN: %s", decoded.CapabilityRef.URN)
	}
	if decoded.CapabilityRef.ConnectionID != "conn-abc-123" {
		t.Errorf("unexpected connection ID: %s", decoded.CapabilityRef.ConnectionID)
	}
	if decoded.AuthContext.PrincipalID != "user-42" {
		t.Errorf("unexpected principal: %s", decoded.AuthContext.PrincipalID)
	}
	if decoded.Provenance.TrustLevel != "VERIFIED" {
		t.Errorf("unexpected trust level: %s", decoded.Provenance.TrustLevel)
	}
	if decoded.Provenance.TTL != 300 {
		t.Errorf("unexpected TTL: %d", decoded.Provenance.TTL)
	}
	if decoded.Provenance.ResponseHash != "sha256:abc123def456" {
		t.Errorf("unexpected response hash: %s", decoded.Provenance.ResponseHash)
	}
	if decoded.Cost.DurationMs != 150 {
		t.Errorf("unexpected duration: %d", decoded.Cost.DurationMs)
	}
	if len(decoded.EvidenceRefs) != 1 || decoded.EvidenceRefs[0].ArtifactID != "ev-001" {
		t.Errorf("unexpected evidence refs: %v", decoded.EvidenceRefs)
	}
}

// TestGoldenReceipt_Denied verifies the receipt JSON structure for denied executions.
func TestGoldenReceipt_Denied(t *testing.T) {
	capRef := CapabilityRef{
		URN: capgraph.CapabilityURN("cap://stripe/charge@2.0.0"),
	}
	authCtx := AuthContext{
		PrincipalID: "user-99",
		OrgID:       "org-3",
		Roles:       []string{"viewer"},
	}

	r := NewDenied(capRef, authCtx, []string{
		"POSTURE_INSUFFICIENT",
		"posture OBSERVE insufficient for risk class E3 (requires SOVEREIGN)",
	})

	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Round-trip.
	var decoded IntegrationReceipt
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Status != "denied" {
		t.Errorf("expected status 'denied', got %q", decoded.Status)
	}
	if decoded.PolicyDecision.Allowed {
		t.Error("expected allowed=false")
	}
	if len(decoded.PolicyDecision.Reasons) != 2 {
		t.Errorf("expected 2 reasons, got %d", len(decoded.PolicyDecision.Reasons))
	}
	if decoded.PolicyDecision.Reasons[0] != "POSTURE_INSUFFICIENT" {
		t.Errorf("unexpected reason: %s", decoded.PolicyDecision.Reasons[0])
	}
}

// TestGoldenReceipt_TimestampPresent verifies timestamps are always set.
func TestGoldenReceipt_TimestampPresent(t *testing.T) {
	r := NewAllowed(CapabilityRef{}, AuthContext{}, "")
	if r.Receipt.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
	if r.Receipt.Timestamp.After(time.Now().Add(time.Second)) {
		t.Error("timestamp in the future")
	}
}

// TestGoldenReceipt_Embeds verifies the contracts.Receipt embed.
func TestGoldenReceipt_Embeds(t *testing.T) {
	r := NewAllowed(CapabilityRef{}, AuthContext{}, "")
	// Verify the embedded receipt is accessible.
	var base contracts.Receipt = r.Receipt
	if base.Status != "executed" {
		t.Errorf("base receipt status: %s", base.Status)
	}
}

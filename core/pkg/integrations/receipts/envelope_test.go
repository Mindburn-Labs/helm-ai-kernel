package receipts

import (
	"encoding/json"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/integrations/capgraph"
)

func TestEnvelopeJSON_RoundTrip(t *testing.T) {
	r := NewAllowed(
		CapabilityRef{
			URN:              capgraph.FormatURN("github", "list-repos", "1.0.0"),
			ConnectorVersion: "1.0.0",
			ConnectionID:     "conn-123",
		},
		AuthContext{
			PrincipalID: "user-456",
			OrgID:       "org-789",
			Roles:       []string{"admin"},
		},
		"sha256:policyhash",
	)
	r.Provenance = ZTProvenance{
		TrustLevel:   "VERIFIED",
		TTL:          300,
		ResponseHash: "sha256:abc",
	}
	r.Cost = CostImpact{
		RateLimitUnits:  1,
		SpendDeltaCents: 0,
	}
	r.EvidenceRefs = []EvidenceRef{
		{ArtifactID: "art-1", Hash: "sha256:ev1"},
	}

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var r2 IntegrationReceipt
	if err := json.Unmarshal(data, &r2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if r2.PolicyDecision.Allowed != true {
		t.Error("expected allowed=true")
	}
	if string(r2.CapabilityRef.URN) != "cap://github/list-repos@1.0.0" {
		t.Errorf("URN mismatch: %s", r2.CapabilityRef.URN)
	}
	if r2.AuthContext.PrincipalID != "user-456" {
		t.Errorf("principal mismatch: %s", r2.AuthContext.PrincipalID)
	}
	if r2.Provenance.TrustLevel != "VERIFIED" {
		t.Errorf("trust level mismatch: %s", r2.Provenance.TrustLevel)
	}
	if r2.Cost.RateLimitUnits != 1 {
		t.Errorf("cost mismatch: %d", r2.Cost.RateLimitUnits)
	}
	if len(r2.EvidenceRefs) != 1 {
		t.Errorf("evidence refs mismatch: %d", len(r2.EvidenceRefs))
	}
	if r2.Status != "executed" {
		t.Errorf("status mismatch: %s", r2.Status)
	}
}

func TestNewDenied(t *testing.T) {
	r := NewDenied(
		CapabilityRef{URN: "cap://github/delete-repo@1.0.0"},
		AuthContext{PrincipalID: "user-1"},
		[]string{"budget_exceeded", "posture_insufficient"},
	)
	if r.PolicyDecision.Allowed {
		t.Error("expected denied")
	}
	if len(r.PolicyDecision.Reasons) != 2 {
		t.Errorf("expected 2 reasons, got %d", len(r.PolicyDecision.Reasons))
	}
	if r.Status != "denied" {
		t.Errorf("expected status=denied, got %s", r.Status)
	}
}

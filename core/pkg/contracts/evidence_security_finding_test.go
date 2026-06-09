package contracts

import (
	"encoding/json"
	"testing"
)

func TestEvidencePackSecurityFindingRefsAreOptionalAndSerializable(t *testing.T) {
	pack := EvidencePack{
		PackID:        "pack-security-loop",
		FormatVersion: "v1",
		SecurityFindings: []SecurityFindingRef{{
			FindingID:          "finding-1",
			State:              "sealed",
			EventHash:          "sha256:event",
			ThreatModelRef:     "threat-model:helm-ai-kernel:v1",
			SandboxReceiptRef:  "sandbox-receipt:verify-1",
			VerifierRef:        "verifier:independent-1",
			PatchRef:           "generated-spec:patch-1",
			RegressionTestRef:  "test:failed-before-passed-after",
			VariantScanRef:     "variant-scan:reattack-1",
			LifecycleEventRefs: []string{"security_event:verified", "security_event:sealed"},
		}},
	}

	raw, err := json.Marshal(pack)
	if err != nil {
		t.Fatalf("marshal pack: %v", err)
	}
	var decoded EvidencePack
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal pack: %v", err)
	}
	if len(decoded.SecurityFindings) != 1 {
		t.Fatalf("decoded SecurityFindings length = %d, want 1", len(decoded.SecurityFindings))
	}
	got := decoded.SecurityFindings[0]
	if got.FindingID != "finding-1" || got.State != "sealed" || got.EventHash == "" {
		t.Fatalf("security finding ref did not round-trip: %#v", got)
	}

	legacy := EvidencePack{PackID: "pack-legacy", FormatVersion: "v1"}
	raw, err = json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy pack: %v", err)
	}
	if string(raw) == "" || containsSecurityFindings(raw) {
		t.Fatalf("legacy pack unexpectedly emitted security_findings: %s", string(raw))
	}
}

func containsSecurityFindings(raw []byte) bool {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(raw, &payload); err != nil {
		return false
	}
	_, ok := payload["security_findings"]
	return ok
}

package contracts_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// The session-risk fields stay on the DecisionRecord wire format after the
// Guardian session-risk gate was removed: records written while it existed
// must still decode with their trajectory evidence intact.
func TestDecisionRecordSessionRiskJSONRoundTrip(t *testing.T) {
	record := contracts.DecisionRecord{
		ID:                     "dec-srm",
		Verdict:                string(contracts.VerdictDeny),
		Reason:                 "session risk",
		TrajectoryRiskScore:    0.42,
		SessionCentroidHash:    "sha256:abc",
		RiskAccumulationWindow: 4,
		Timestamp:              time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC),
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded contracts.DecisionRecord
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.TrajectoryRiskScore != record.TrajectoryRiskScore {
		t.Errorf("TrajectoryRiskScore = %v, want %v", decoded.TrajectoryRiskScore, record.TrajectoryRiskScore)
	}
	if decoded.SessionCentroidHash != record.SessionCentroidHash {
		t.Errorf("SessionCentroidHash = %q, want %q", decoded.SessionCentroidHash, record.SessionCentroidHash)
	}
	if decoded.RiskAccumulationWindow != record.RiskAccumulationWindow {
		t.Errorf("RiskAccumulationWindow = %d, want %d", decoded.RiskAccumulationWindow, record.RiskAccumulationWindow)
	}
}

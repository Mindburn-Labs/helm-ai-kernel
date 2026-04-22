package trust

import (
	"encoding/json"
	"testing"
	"time"
)

func TestCompliancePipeline_IngestMapping(t *testing.T) {
	matrix := NewComplianceMatrix()
	pipeline := NewCompliancePipeline(matrix)

	// Setup: Add a framework and control
	fw := &Framework{
		FrameworkID: "SOC2",
		Name:        "SOC 2 Type II",
	}
	matrix.AddFramework(fw)

	ctrl := &Control{
		ControlID:   "CC1.1",
		FrameworkID: "SOC2",
		Title:       "Access Control",
	}
	_ = matrix.AddControl(ctrl)

	// Create a mapping payload manually
	// Since struct definition in test needs to match
	type MappedControl struct {
		ControlID     string    `json:"control_id"`
		Status        string    `json:"status"`
		Justification string    `json:"justification"`
		EvidenceRefs  []string  `json:"evidence_refs"`
		LastVerified  time.Time `json:"last_verified"`
	}

	payload := map[string]interface{}{
		"mapping_id": "map-001",
		"target_ref": "repo:root/core/pkg/auth",
		"controls": []MappedControl{
			{
				ControlID:    "CC1.1",
				Status:       "compliant",
				EvidenceRefs: []string{"ev-log-001"},
			},
		},
	}

	bytes, _ := json.Marshal(payload)

	// Test Ingestion
	if err := pipeline.IngestMapping(bytes); err != nil {
		t.Fatalf("IngestMapping failed: %v", err)
	}

	// Verify Matrix Update
	updatedCtrl := matrix.Controls["CC1.1"]
	if updatedCtrl.Status != ControlCompliant {
		t.Errorf("expected status compliant, got %s", updatedCtrl.Status)
	}

	if len(updatedCtrl.EvidenceIDs) != 1 || updatedCtrl.EvidenceIDs[0] != "ev-log-001" {
		t.Errorf("evidence not linked correctly")
	}
}

func TestCompliancePipeline_ScanForStaleControls(t *testing.T) {
	matrix := NewComplianceMatrix()
	pipeline := NewCompliancePipeline(matrix)

	fw := &Framework{FrameworkID: "F1"}
	matrix.AddFramework(fw)

	// Add stale control
	staleCtrl := &Control{
		ControlID:   "STALE-1",
		FrameworkID: "F1",
		LastChecked: time.Now().Add(-25 * time.Hour),
	}
	_ = matrix.AddControl(staleCtrl)
	// Force overwrite timestamp since AddControl sets it to Now
	matrix.Controls["STALE-1"].LastChecked = time.Now().Add(-25 * time.Hour)

	// Add fresh control
	freshCtrl := &Control{
		ControlID:   "FRESH-1",
		FrameworkID: "F1",
	}
	_ = matrix.AddControl(freshCtrl)

	stale := pipeline.ScanForStaleControls(24 * time.Hour)
	if len(stale) != 1 || stale[0] != "STALE-1" {
		t.Errorf("expected [STALE-1], got %v", stale)
	}
}

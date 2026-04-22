package trust

import (
	"encoding/json"
	"fmt"
	"time"
)

// CompliancePipeline handles the continuous verification of compliance controls.
type CompliancePipeline struct {
	matrix *ComplianceMatrix
}

// NewCompliancePipeline creates a new compliance pipeline.
func NewCompliancePipeline(matrix *ComplianceMatrix) *CompliancePipeline {
	return &CompliancePipeline{
		matrix: matrix,
	}
}

// ControlMapping represents the mapping between a technical requirement and a control.
// This mirrors the ControlMapping.v1 schema.
type ControlMapping struct {
	MappingID string `json:"mapping_id"`
	TargetRef string `json:"target_ref"` // e.g., "repo:root/core/pkg/auth"
	Controls  []struct {
		ControlID     string    `json:"control_id"`
		Status        string    `json:"status"` // compliant, non_compliant, etc.
		Justification string    `json:"justification"`
		EvidenceRefs  []string  `json:"evidence_refs"`
		LastVerified  time.Time `json:"last_verified"`
	} `json:"controls"`
	MappedBy string    `json:"mapped_by"`
	MappedAt time.Time `json:"mapped_at"`
}

// IngestMapping processes a control mapping and updates the compliance matrix.
// This implements the "Compliance Delta Update" logic.
func (p *CompliancePipeline) IngestMapping(mappingJSON []byte) error {
	var mapping ControlMapping
	if err := json.Unmarshal(mappingJSON, &mapping); err != nil {
		return fmt.Errorf("failed to unmarshal mapping: %w", err)
	}

	p.matrix.mu.Lock()
	defer p.matrix.mu.Unlock()

	for _, mappedCtrl := range mapping.Controls {
		// Find the control in the matrix
		ctrl, exists := p.matrix.Controls[mappedCtrl.ControlID]
		if !exists {
			// In a real system we might log a warning or auto-create, but here we error for safety
			return fmt.Errorf("control %s not found in matrix", mappedCtrl.ControlID)
		}

		// Update status
		ctrl.Status = ControlStatus(mappedCtrl.Status)
		ctrl.LastChecked = time.Now()

		// Link evidence (simple version: just creating placeholder evidence items if needed)
		// In a real implementation, we would look up the actual evidence artifacts.
		for _, ref := range mappedCtrl.EvidenceRefs {
			// Check if evidence already linked
			linked := false
			for _, existingRef := range ctrl.EvidenceIDs {
				if existingRef == ref {
					linked = true
					break
				}
			}

			if !linked {
				// Record that we saw new evidence.
				// The actual evidence object creation usually happens via AddEvidence.
				// Here we just ensure the control knows about it.
				ctrl.EvidenceIDs = append(ctrl.EvidenceIDs, ref)
			}
		}

		// Update timestamp
		p.matrix.UpdatedAt = time.Now()
	}

	return nil
}

// ScanForStaleControls identifies controls that haven't been verified recently.
func (p *CompliancePipeline) ScanForStaleControls(threshold time.Duration) []string {
	p.matrix.mu.RLock()
	defer p.matrix.mu.RUnlock()

	var staleIDs []string
	now := time.Now()

	for id, ctrl := range p.matrix.Controls {
		if now.Sub(ctrl.LastChecked) > threshold {
			staleIDs = append(staleIDs, id)
		}
	}

	return staleIDs
}

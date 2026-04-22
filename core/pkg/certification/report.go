package certification

import (
	"encoding/json"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
)

// ConformanceReport signifies that a specific git revision passed all standard tests.
// The report itself is a verifiable artifact serialized in CSNF.
type ConformanceReport struct {
	ReportID     string            `json:"report_id"`     // UUID
	Timestamp    time.Time         `json:"timestamp"`     // RFC3339
	GitRevision  string            `json:"git_revision"`  // Full SHA
	Platform     string            `json:"platform"`      // e.g. "helm-core-v1"
	Standard     string            `json:"standard"`      // e.g. "CSNF-1.0"
	PassedSuites []string          `json:"passed_suites"` // List of passing suites
	FailedSuites []string          `json:"failed_suites"` // Must be empty for Valid=true
	Metadata     map[string]string `json:"metadata,omitempty"`
	Signature    []byte            `json:"signature"` // Signature of the report content (excluding Signature field)
	SignerID     string            `json:"signer_id"` // Key ID of the certifier
}

// SignReport creates a signed ConformanceReport.
// In production, signer would be an interface to a HSM/Vault.
// Here we accept a signer function for dependency injection.
func SignReport(
	id string,
	revision string,
	passed []string,
	signerID string,
	signFunc func(data []byte) ([]byte, error),
) (*ConformanceReport, error) {
	report := &ConformanceReport{
		ReportID:     id,
		Timestamp:    time.Now().UTC(),
		GitRevision:  revision,
		Platform:     "helm-core-go",
		Standard:     "HELM-STD-2026",
		PassedSuites: passed,
		FailedSuites: []string{},
		SignerID:     signerID,
	}

	// RFC 8785 JCS canonical serialization for deterministic signatures.
	payload, err := canonicalize.JCS(report)
	if err != nil {
		// Fallback to standard JSON if JCS fails (should not happen).
		payload, err = json.Marshal(report)
		if err != nil {
			return nil, err
		}
	}

	sig, err := signFunc(payload)
	if err != nil {
		return nil, err
	}
	report.Signature = sig

	return report, nil
}

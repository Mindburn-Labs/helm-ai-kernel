// Package exportadmin manages enterprise evidence export requests.
// Every export request and completion is recorded as a ProofGraph node
// for cryptographic auditability.
package exportadmin

import "time"

// ExportRequest represents an admin request to export evidence.
type ExportRequest struct {
	RequestID   string    `json:"request_id"`
	TenantID    string    `json:"tenant_id"`
	WorkspaceID string    `json:"workspace_id,omitempty"`
	Format      string    `json:"format"` // "evidence_pack", "audit_log", "compliance_report"
	DateFrom    time.Time `json:"date_from"`
	DateTo      time.Time `json:"date_to"`
	RequestedBy string    `json:"requested_by"`
	Status      string    `json:"status"` // "PENDING", "GENERATING", "READY", "EXPIRED", "FAILED"
	OutputHash  string    `json:"output_hash,omitempty"`
	OutputSize  int64     `json:"output_size,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// ExportManifest describes the contents of a completed export.
type ExportManifest struct {
	RequestID      string   `json:"request_id"`
	TenantID       string   `json:"tenant_id"`
	Format         string   `json:"format"`
	EntryCount     int      `json:"entry_count"`
	ContentHash    string   `json:"content_hash"`
	SignatureHash  string   `json:"signature_hash"`
	ProofGraphNode string   `json:"proofgraph_node"`
	Entries        []string `json:"entries"`
}

// Status constants.
const (
	StatusPending    = "PENDING"
	StatusGenerating = "GENERATING"
	StatusReady      = "READY"
	StatusExpired    = "EXPIRED"
	StatusFailed     = "FAILED"
)

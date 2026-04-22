package contracts

import "time"

// ChangePack represents a proof of authorized change.
type ChangePack struct {
	PackID        string                `json:"pack_id"`
	PackType      string                `json:"pack_type"` // "CHANGE_PACK"
	TargetSystem  string                `json:"target_system"`
	ChangeContext ChangeContext         `json:"change_context"`
	EvidenceRefs  ChangeEvidenceRefs    `json:"evidence_refs"`
	Attestation   ChangePackAttestation `json:"attestation"`
}

type ChangeContext struct {
	Repo      string `json:"repo"`
	CommitSHA string `json:"commit_sha"`
	Branch    string `json:"branch"`
	Tag       string `json:"tag,omitempty"`
	TicketID  string `json:"ticket_id,omitempty"`
}

type ChangeEvidenceRefs struct {
	ApprovalReceiptID     string `json:"approval_receipt_id"`
	BuildReceiptID        string `json:"build_receipt_id"`
	DeploymentReceiptID   string `json:"deployment_receipt_id,omitempty"`
	SecurityScanReceiptID string `json:"security_scan_receipt_id,omitempty"`
}

type ChangePackAttestation struct {
	PackHash    string    `json:"pack_hash"`
	Signature   string    `json:"signature,omitempty"`
	SignerID    string    `json:"signer_id,omitempty"`
	GeneratedAt time.Time `json:"generated_at"`
}

// IncidentPack represents a proof of incident lifecycle.
type IncidentPack struct {
	PackID              string                  `json:"pack_id"`
	PackType            string                  `json:"pack_type"` // "INCIDENT_PACK"
	IncidentID          string                  `json:"incident_id"`
	Severity            string                  `json:"severity,omitempty"`
	Summary             string                  `json:"summary,omitempty"`
	Timeline            []IncidentEvent         `json:"timeline"`
	RootCause           string                  `json:"root_cause,omitempty"`
	RemediationEvidence *IncidentRemediation    `json:"remediation_evidence,omitempty"`
	Attestation         IncidentPackAttestation `json:"attestation"`
}

type IncidentEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	EventType   string    `json:"event_type"` // DETECTED, ACKNOWLEDGED, etc.
	Description string    `json:"description"`
	ReceiptRef  string    `json:"receipt_ref,omitempty"`
	ActorID     string    `json:"actor_id,omitempty"`
}

type IncidentRemediation struct {
	FixCommitSHA    string `json:"fix_commit_sha,omitempty"`
	DeployReceiptID string `json:"deploy_receipt_id,omitempty"`
}

type IncidentPackAttestation struct {
	PackHash    string    `json:"pack_hash"`
	Signature   string    `json:"signature,omitempty"`
	SignerID    string    `json:"signer_id,omitempty"`
	GeneratedAt time.Time `json:"generated_at"`
}

// AccessReviewPack represents a proof of access review.
type AccessReviewPack struct {
	PackID      string                      `json:"pack_id"`
	PackType    string                      `json:"pack_type"` // "ACCESS_REVIEW_PACK"
	Scope       string                      `json:"scope"`
	ReviewedAt  time.Time                   `json:"reviewed_at"`
	ReviewerID  string                      `json:"reviewer_id,omitempty"`
	Reviews     []AccessReviewItem          `json:"reviews"`
	Attestation AccessReviewPackAttestation `json:"attestation"`
}

type AccessReviewItem struct {
	SubjectID     string `json:"subject_id"`
	Resource      string `json:"resource"`
	Permission    string `json:"permission"`
	Decision      string `json:"decision"` // APPROVED, REVOKED, FLAGGED
	Justification string `json:"justification,omitempty"`
	ReceiptRef    string `json:"receipt_ref,omitempty"`
}

type AccessReviewPackAttestation struct {
	PackHash    string    `json:"pack_hash"`
	Signature   string    `json:"signature,omitempty"`
	SignerID    string    `json:"signer_id,omitempty"`
	GeneratedAt time.Time `json:"generated_at"`
}

// VendorDueDiligencePack represents a proof of vendor compliance.
type VendorDueDiligencePack struct {
	PackID           string                            `json:"pack_id"`
	PackType         string                            `json:"pack_type"` // "VENDOR_DUE_DILIGENCE_PACK"
	VendorName       string                            `json:"vendor_name"`
	VendorDomain     string                            `json:"vendor_domain,omitempty"`
	AssessmentDate   time.Time                         `json:"assessment_date"`
	AssessorID       string                            `json:"assessor_id,omitempty"`
	ComplianceChecks []VendorComplianceCheck           `json:"compliance_checks"`
	RiskScore        int                               `json:"risk_score,omitempty"`
	Decision         string                            `json:"decision,omitempty"` // APPROVED, REJECTED, CONDITIONAL
	Attestation      VendorDueDiligencePackAttestation `json:"attestation"`
}

type VendorComplianceCheck struct {
	Standard       string `json:"standard"` // SOC2, ISO27001, etc.
	Status         string `json:"status"`   // COMPLIANT, NON_COMPLIANT, etc.
	EvidenceURL    string `json:"evidence_url,omitempty"`
	ExpirationDate string `json:"expiration_date,omitempty"` // YYYY-MM-DD
	ReceiptRef     string `json:"receipt_ref,omitempty"`
}

type VendorDueDiligencePackAttestation struct {
	PackHash    string    `json:"pack_hash"`
	Signature   string    `json:"signature,omitempty"`
	GeneratedAt time.Time `json:"generated_at"`
}

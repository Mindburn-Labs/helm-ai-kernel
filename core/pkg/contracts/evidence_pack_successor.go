package contracts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	EvidencePackLineageSchemaV1     = "evidence-pack-lineage.v1"
	EvidencePackSuccessorSchemaV1   = "evidence-pack-successor.v1"
	EvidencePackSuccessorContractV1 = "2026-09-04"

	evidencePackSuccessorMaxTokenBytes = 512
)

var (
	ErrEvidencePackSuccessorInvalid   = errors.New("evidence pack successor invalid")
	ErrEvidencePackSuccessorIntegrity = errors.New("evidence pack successor integrity failure")
)

// EvidencePackLineage is sealed into the effect-time EvidencePack before an
// outcome is observed. Every successor repeats this identity and the
// ProofGraph append boundary rejects any drift from the predecessor.
type EvidencePackLineage struct {
	SchemaVersion string `json:"schema_version"`

	TenantID      string `json:"tenant_id"`
	CompanyID     string `json:"company_id"`
	WorkspaceID   string `json:"workspace_id"`
	EnvironmentID string `json:"environment_id"`

	ActivationRecordRef  string `json:"activation_record_ref"`
	ActivationRecordHash string `json:"activation_record_hash"`

	OutcomeContractRef  string `json:"outcome_contract_ref"`
	OutcomeContractHash string `json:"outcome_contract_hash"`

	MeasurementPlanRef  string `json:"measurement_plan_ref"`
	MeasurementPlanHash string `json:"measurement_plan_hash"`
	WindowIdentity      string `json:"window_identity"`
}

func (l EvidencePackLineage) Validate() error {
	if l.SchemaVersion != EvidencePackLineageSchemaV1 {
		return evidencePackSuccessorInvalid("lineage has unsupported schema_version")
	}
	for field, value := range map[string]string{
		"tenant_id": l.TenantID, "company_id": l.CompanyID,
		"workspace_id": l.WorkspaceID, "environment_id": l.EnvironmentID,
		"activation_record_ref": l.ActivationRecordRef,
		"outcome_contract_ref":  l.OutcomeContractRef,
		"measurement_plan_ref":  l.MeasurementPlanRef,
		"window_identity":       l.WindowIdentity,
	} {
		if !isApprovalGrantToken(value) || len(value) > evidencePackSuccessorMaxTokenBytes {
			return evidencePackSuccessorInvalid(field + " is required and must be a bounded token")
		}
	}
	if l.CompanyID != l.TenantID {
		return evidencePackSuccessorInvalid("company_id must match the authenticated tenant domain")
	}
	for field, value := range map[string]string{
		"activation_record_hash": l.ActivationRecordHash,
		"outcome_contract_hash":  l.OutcomeContractHash,
		"measurement_plan_hash":  l.MeasurementPlanHash,
	} {
		if !isApprovalGrantSHA256(value) {
			return evidencePackSuccessorInvalid(field + " must be a lowercase sha256 reference")
		}
	}
	return nil
}

type EvidencePackSuccessorKind string

const (
	EvidencePackSuccessorOperationalEvaluation EvidencePackSuccessorKind = "OPERATIONAL_EVALUATION"
	EvidencePackSuccessorMeasurementProgress   EvidencePackSuccessorKind = "MEASUREMENT_PROGRESS"
	EvidencePackSuccessorMeasurementFinal      EvidencePackSuccessorKind = "MEASUREMENT_FINAL"
	EvidencePackSuccessorMeasurementCensored   EvidencePackSuccessorKind = "MEASUREMENT_CENSORED"
)

// EvidencePackSuccessor is an immutable addendum to a sealed EvidencePack.
// SuccessorID is the idempotency identity. SuccessorHash binds the complete
// observed record, so a retry returns the prior record while different
// evidence under the same identity is detectable as equivocation.
type EvidencePackSuccessor struct {
	SchemaVersion   string `json:"schema_version"`
	ContractVersion string `json:"contract_version"`

	SuccessorID string                    `json:"successor_id"`
	Kind        EvidencePackSuccessorKind `json:"kind"`

	PredecessorRef  string `json:"predecessor_ref"`
	PredecessorHash string `json:"predecessor_hash"`
	SealedPackRef   string `json:"sealed_pack_ref"`
	SealedPackHash  string `json:"sealed_pack_hash"`

	Lineage EvidencePackLineage `json:"lineage"`

	EvidenceRef  string    `json:"evidence_ref"`
	EvidenceHash string    `json:"evidence_hash"`
	RecordedAt   time.Time `json:"recorded_at"`

	SuccessorHash string `json:"successor_hash"`
}

// FinalizesMeasurement is deliberately false for progress evidence. Callers
// must never infer closure merely because a measurement artifact exists.
func (s EvidencePackSuccessor) FinalizesMeasurement() bool {
	return s.Kind == EvidencePackSuccessorMeasurementFinal || s.Kind == EvidencePackSuccessorMeasurementCensored
}

// ContractHash returns the frozen contract that participates in the
// deterministic append identity for this evidence kind.
func (s EvidencePackSuccessor) ContractHash() string {
	if s.Kind == EvidencePackSuccessorOperationalEvaluation {
		return s.Lineage.OutcomeContractHash
	}
	return s.Lineage.MeasurementPlanHash
}

func (s EvidencePackSuccessor) Validate() error {
	if s.SchemaVersion != EvidencePackSuccessorSchemaV1 {
		return evidencePackSuccessorInvalid("unsupported schema_version")
	}
	if s.ContractVersion != EvidencePackSuccessorContractV1 {
		return evidencePackSuccessorInvalid("unsupported contract_version")
	}
	switch s.Kind {
	case EvidencePackSuccessorOperationalEvaluation,
		EvidencePackSuccessorMeasurementProgress,
		EvidencePackSuccessorMeasurementFinal,
		EvidencePackSuccessorMeasurementCensored:
	default:
		return evidencePackSuccessorInvalid("unsupported evidence kind")
	}
	for field, value := range map[string]string{
		"predecessor_ref": s.PredecessorRef,
		"sealed_pack_ref": s.SealedPackRef,
		"evidence_ref":    s.EvidenceRef,
	} {
		if !isApprovalGrantToken(value) || len(value) > evidencePackSuccessorMaxTokenBytes {
			return evidencePackSuccessorInvalid(field + " is required and must be a bounded token")
		}
	}
	for field, value := range map[string]string{
		"predecessor_hash": s.PredecessorHash,
		"sealed_pack_hash": s.SealedPackHash,
		"evidence_hash":    s.EvidenceHash,
	} {
		if !isApprovalGrantSHA256(value) {
			return evidencePackSuccessorInvalid(field + " must be a lowercase sha256 reference")
		}
	}
	if err := s.Lineage.Validate(); err != nil {
		return err
	}
	if s.RecordedAt.IsZero() || !isApprovalGrantUTC(s.RecordedAt) {
		return evidencePackSuccessorInvalid("recorded_at is required and must use UTC")
	}
	if s.SuccessorID != "" && !isApprovalGrantSHA256(s.SuccessorID) {
		return evidencePackSuccessorInvalid("successor_id must be a lowercase sha256 reference")
	}
	if s.SuccessorHash != "" && !isApprovalGrantSHA256(s.SuccessorHash) {
		return evidencePackSuccessorInvalid("successor_hash must be a lowercase sha256 reference")
	}
	return nil
}

// DeriveEvidencePackSuccessorID binds the append position and governing
// contract without binding the newly observed evidence bytes.
func DeriveEvidencePackSuccessorID(s EvidencePackSuccessor) (string, error) {
	if err := s.Validate(); err != nil {
		return "", err
	}
	return hashJCS(struct {
		SchemaVersion   string                    `json:"schema_version"`
		ContractVersion string                    `json:"contract_version"`
		PredecessorHash string                    `json:"predecessor_hash"`
		Kind            EvidencePackSuccessorKind `json:"kind"`
		ContractHash    string                    `json:"contract_hash"`
		WindowIdentity  string                    `json:"window_identity"`
	}{
		SchemaVersion: s.SchemaVersion, ContractVersion: s.ContractVersion,
		PredecessorHash: s.PredecessorHash, Kind: s.Kind,
		ContractHash: s.ContractHash(), WindowIdentity: s.Lineage.WindowIdentity,
	})
}

func (s EvidencePackSuccessor) Seal() (EvidencePackSuccessor, error) {
	s.SuccessorID = ""
	s.SuccessorHash = ""
	if err := s.Validate(); err != nil {
		return EvidencePackSuccessor{}, err
	}
	identity, err := DeriveEvidencePackSuccessorID(s)
	if err != nil {
		return EvidencePackSuccessor{}, err
	}
	s.SuccessorID = identity
	hash, err := hashJCS(s)
	if err != nil {
		return EvidencePackSuccessor{}, evidencePackSuccessorInvalid("seal: " + err.Error())
	}
	s.SuccessorHash = hash
	return s, nil
}

func (s EvidencePackSuccessor) ValidateIntegrity() error {
	if !isApprovalGrantSHA256(s.SuccessorID) || !isApprovalGrantSHA256(s.SuccessorHash) {
		return fmt.Errorf("%w: successor_id and successor_hash are required", ErrEvidencePackSuccessorIntegrity)
	}
	sealed, err := s.Seal()
	if err != nil {
		return err
	}
	if sealed.SuccessorID != s.SuccessorID {
		return fmt.Errorf("%w: successor_id mismatch", ErrEvidencePackSuccessorIntegrity)
	}
	if sealed.SuccessorHash != s.SuccessorHash {
		return fmt.Errorf("%w: successor_hash mismatch", ErrEvidencePackSuccessorIntegrity)
	}
	return nil
}

// DecodeEvidencePackSuccessor rejects unbound extension fields and trailing
// documents before the record reaches lineage validation.
func DecodeEvidencePackSuccessor(data []byte) (EvidencePackSuccessor, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var successor EvidencePackSuccessor
	if err := decoder.Decode(&successor); err != nil {
		return EvidencePackSuccessor{}, evidencePackSuccessorInvalid("decode: " + err.Error())
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return EvidencePackSuccessor{}, evidencePackSuccessorInvalid("decode: trailing JSON")
	}
	if err := successor.ValidateIntegrity(); err != nil {
		return EvidencePackSuccessor{}, err
	}
	return successor, nil
}

func evidencePackSuccessorInvalid(message string) error {
	return fmt.Errorf("%w: %s", ErrEvidencePackSuccessorInvalid, message)
}

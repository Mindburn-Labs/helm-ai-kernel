// Package executor provides EvidencePack production.
// Per Section 6 - EvidencePack Normative Contract
package executor

import (
	"context"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/google/uuid"
)

// EvidencePackProducer creates EvidencePacks for effect executions.
type EvidencePackProducer struct {
	kernelVersion string
}

// NewEvidencePackProducer creates a new evidence pack producer.
func NewEvidencePackProducer(kernelVersion string) *EvidencePackProducer {
	return &EvidencePackProducer{
		kernelVersion: kernelVersion,
	}
}

// EvidencePackInput contains all inputs needed to produce an EvidencePack.
type EvidencePackInput struct {
	// Actor information
	ActorID         string
	ActorType       string
	SessionID       string
	DelegationChain []string

	// Policy decision
	DecisionID          string
	PolicyVersion       string
	RulesFired          []string
	EvaluationGraphHash string

	// Effect details
	EffectID          string
	EffectType        string
	EffectPayloadHash string
	IdempotencyKey    string
	Classification    string

	// Context
	ModeID             string
	LoopID             string
	Jurisdiction       string
	PhenotypeHash      string
	OrchestrationRunID string
	PhaseID            string
	CheckpointRef      string
	CritiqueRef        string
	HeuristicTraceID   string

	// Execution
	ResultHash    string
	Status        string
	RetryCount    int
	StartedAt     time.Time
	CompletedAt   time.Time
	FailureReason string

	// Receipts
	PALReceipts      []contracts.PALReceiptRef
	ExternalReceipts []contracts.ExternalReceiptRef

	// New Receipt Fields support in Input
	ReplayScript     *contracts.ReplayScriptRef
	Provenance       *contracts.ReceiptProvenance
	BundledArtifacts []contracts.ParsedArtifact

	// Reconciliation
	OutboxID       string
	DeniedAttempts []contracts.DeniedAttemptRecord
	FailedAttempts []contracts.FailedAttemptRecord
}

// Produce creates an EvidencePack from the input.
func (p *EvidencePackProducer) Produce(ctx context.Context, input *EvidencePackInput) (*contracts.EvidencePack, error) {
	_ = ctx

	rulesFired := input.RulesFired
	if rulesFired == nil {
		rulesFired = []string{}
	}
	palReceipts := input.PALReceipts
	if palReceipts == nil {
		palReceipts = []contracts.PALReceiptRef{}
	}
	externalReceipts := input.ExternalReceipts
	if externalReceipts == nil {
		externalReceipts = []contracts.ExternalReceiptRef{}
	}
	deniedAttempts := input.DeniedAttempts
	if deniedAttempts == nil {
		deniedAttempts = []contracts.DeniedAttemptRecord{}
	}
	failedAttempts := input.FailedAttempts
	if failedAttempts == nil {
		failedAttempts = []contracts.FailedAttemptRecord{}
	}

	pack := &contracts.EvidencePack{
		PackID:        uuid.New().String(),
		FormatVersion: "1.0.0",
		CreatedAt:     time.Now().UTC(),

		Identity: contracts.EvidencePackIdentity{
			ActorID:         input.ActorID,
			ActorType:       input.ActorType,
			SessionID:       input.SessionID,
			DelegationChain: input.DelegationChain,
		},

		Policy: contracts.EvidencePackPolicy{
			DecisionID:          input.DecisionID,
			PolicyVersion:       input.PolicyVersion,
			RulesFired:          rulesFired,
			EvaluationGraphHash: input.EvaluationGraphHash,
		},

		Effect: contracts.EvidencePackEffect{
			EffectID:          input.EffectID,
			EffectType:        input.EffectType,
			EffectPayloadHash: input.EffectPayloadHash,
			IdempotencyKey:    input.IdempotencyKey,
			Classification:    input.Classification,
		},

		Context: contracts.EvidencePackContext{
			ModeID:             input.ModeID,
			LoopID:             input.LoopID,
			Jurisdiction:       input.Jurisdiction,
			PhenotypeHash:      input.PhenotypeHash,
			OrchestrationRunID: input.OrchestrationRunID,
			PhaseID:            input.PhaseID,
			CheckpointRef:      input.CheckpointRef,
			CritiqueRef:        input.CritiqueRef,
			HeuristicTraceID:   input.HeuristicTraceID,
		},

		Execution: contracts.EvidencePackExecution{
			ExecutionID:   uuid.New().String(),
			Status:        input.Status,
			ResultHash:    input.ResultHash,
			RetryCount:    input.RetryCount,
			StartedAt:     input.StartedAt,
			CompletedAt:   input.CompletedAt,
			FailureReason: input.FailureReason,
		},

		Receipts: contracts.EvidencePackReceipts{
			PALReceipts:      palReceipts,
			ExternalReceipts: externalReceipts,
		},

		Reconciliation: contracts.EvidencePackReconciliation{
			OutboxID:       input.OutboxID,
			DeniedAttempts: deniedAttempts,
			FailedAttempts: failedAttempts,
		},

		ReplayScript:     input.ReplayScript,
		Provenance:       input.Provenance,
		BundledArtifacts: input.BundledArtifacts,

		Attestation: contracts.EvidencePackAttestation{
			KernelVersion: p.kernelVersion,
		},
	}

	// Compute duration if both timestamps present
	if !input.StartedAt.IsZero() && !input.CompletedAt.IsZero() {
		pack.Execution.DurationMs = input.CompletedAt.Sub(input.StartedAt).Milliseconds()
	}

	// Compute pack hash for attestation
	packHash, err := computeEvidencePackHash(pack)
	if err != nil {
		return nil, err
	}
	pack.Attestation.PackHash = packHash

	return pack, nil
}

// computeEvidencePackHash computes SHA-256 of the pack (excluding attestation)
// using JCS (RFC 8785) for deterministic canonicalization.
func computeEvidencePackHash(pack *contracts.EvidencePack) (string, error) {
	// Create copy without attestation for hashing
	hashable := struct {
		PackID           string                               `json:"pack_id"`
		FormatVersion    string                               `json:"format_version"`
		CreatedAt        time.Time                            `json:"created_at"`
		Identity         contracts.EvidencePackIdentity       `json:"identity"`
		Policy           contracts.EvidencePackPolicy         `json:"policy"`
		Effect           contracts.EvidencePackEffect         `json:"effect"`
		Context          contracts.EvidencePackContext        `json:"context"`
		Execution        contracts.EvidencePackExecution      `json:"execution"`
		Receipts         contracts.EvidencePackReceipts       `json:"receipts"`
		Reconciliation   contracts.EvidencePackReconciliation `json:"reconciliation"`
		ReplayScript     *contracts.ReplayScriptRef           `json:"replay_script,omitempty"`
		Provenance       *contracts.ReceiptProvenance         `json:"provenance,omitempty"`
		BundledArtifacts []contracts.ParsedArtifact           `json:"bundled_artifacts,omitempty"`
	}{
		PackID:           pack.PackID,
		FormatVersion:    pack.FormatVersion,
		CreatedAt:        pack.CreatedAt,
		Identity:         pack.Identity,
		Policy:           pack.Policy,
		Effect:           pack.Effect,
		Context:          pack.Context,
		Execution:        pack.Execution,
		Receipts:         pack.Receipts,
		Reconciliation:   pack.Reconciliation,
		ReplayScript:     pack.ReplayScript,
		Provenance:       pack.Provenance,
		BundledArtifacts: pack.BundledArtifacts,
	}

	data, err := canonicalize.JCS(hashable)
	if err != nil {
		return "", fmt.Errorf("failed to canonicalize evidence pack: %w", err)
	}

	return "sha256:" + canonicalize.HashBytes(data), nil
}

// ValidateEvidencePack validates an EvidencePack for completeness.
func ValidateEvidencePack(pack *contracts.EvidencePack) []string {
	issues := []string{}

	// Required fields
	if pack.PackID == "" {
		issues = append(issues, "pack_id is required")
	}
	if pack.Identity.ActorID == "" {
		issues = append(issues, "identity.actor_id is required")
	}
	if pack.Policy.DecisionID == "" {
		issues = append(issues, "policy.decision_id is required")
	}
	if pack.Effect.EffectID == "" {
		issues = append(issues, "effect.effect_id is required")
	}
	if pack.Execution.ExecutionID == "" {
		issues = append(issues, "execution.execution_id is required")
	}
	if pack.Execution.Status == "" {
		issues = append(issues, "execution.status is required")
	}

	// Verify pack hash
	if pack.Attestation.PackHash != "" {
		computed, err := computeEvidencePackHash(pack)
		if err == nil && computed != pack.Attestation.PackHash {
			issues = append(issues, "attestation.pack_hash does not match computed hash")
		}
	}

	return issues
}

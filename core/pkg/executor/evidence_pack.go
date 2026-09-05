// Package executor provides EvidencePack production.
// Per Section 6 - EvidencePack Normative Contract
package executor

import (
	"context"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/correlation"
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

	// Verification and harness-state evidence
	VerificationScopes []contracts.VerificationScope
	HarnessTraceRefs   []contracts.HarnessTraceRef

	// EU AI Act evidence profile
	EUAIActProfile *contracts.EUAIActEvidenceProfile

	// Immutable successor identity, frozen before effect-time pack sealing.
	Lineage *contracts.EvidencePackLineage
}

// Produce creates an EvidencePack from the input.
func (p *EvidencePackProducer) Produce(ctx context.Context, input *EvidencePackInput) (*contracts.EvidencePack, error) {
	_ = ctx
	var lineage *contracts.EvidencePackLineage
	if input.Lineage != nil {
		copy := *input.Lineage
		if err := copy.Validate(); err != nil {
			return nil, fmt.Errorf("invalid evidence pack lineage: %w", err)
		}
		lineage = &copy
	}

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

	correlationID := ""
	if corr, ok := correlation.From(ctx); ok {
		correlationID = string(corr)
	}

	pack := &contracts.EvidencePack{
		PackID:        uuid.New().String(),
		FormatVersion: "1.0.0",
		CreatedAt:     time.Now().UTC(),
		CorrelationID: correlationID,

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

		ReplayScript:       input.ReplayScript,
		Provenance:         input.Provenance,
		BundledArtifacts:   input.BundledArtifacts,
		VerificationScopes: input.VerificationScopes,
		HarnessTraceRefs:   input.HarnessTraceRefs,
		EUAIActProfile:     input.EUAIActProfile,
		Lineage:            lineage,

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
	return contracts.ComputeEvidencePackHash(pack)
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
	issues = append(issues, contracts.ValidateEUAIActEvidenceProfile(pack.EUAIActProfile)...)
	if pack.Lineage != nil {
		if err := pack.Lineage.Validate(); err != nil {
			issues = append(issues, "lineage is invalid: "+err.Error())
		}
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

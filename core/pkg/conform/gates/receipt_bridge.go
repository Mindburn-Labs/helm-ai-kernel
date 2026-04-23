package gates

import (
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// ToContractsReceipt converts a ReceiptEnvelope to a contracts.Receipt,
// enabling runtime receipts to be verified by the conformance engine.
//
// Field mapping preserves all semantics:
//   - ParentReceiptHashes → Provenance.Parents
//   - Actor → Provenance.GeneratedBy
//   - PayloadCommitment → BlobHash
//   - TapeRef → ReplayScript.ScriptID
func (env *ReceiptEnvelope) ToContractsReceipt() *contracts.Receipt {
	r := &contracts.Receipt{
		ReceiptID:  env.ReceiptHash,
		DecisionID: env.DecisionID,
		EffectID:   env.EffectDigestHash,
		Status:     "VERIFIED",
		BlobHash:   env.PayloadCommitment,
		Signature:  env.Signature,
		Metadata: map[string]any{
			"tenant_id":      env.TenantID,
			"envelope_id":    env.EnvelopeID,
			"envelope_hash":  env.EnvelopeHash,
			"jurisdiction":   env.Jurisdiction,
			"effect_class":   env.EffectClass,
			"effect_type":    env.EffectType,
			"action_type":    env.ActionType,
			"intent_id":      env.IntentID,
			"policy_hash":    env.PolicyHash,
			"policy_version": env.PolicyVersion,
			"phenotype_hash": env.PhenotypeHash,
			"run_id":         env.RunID,
			"seq":            env.Seq,
		},
	}

	// Map DAG parents to provenance
	if len(env.ParentReceiptHashes) > 0 || env.Actor != "" {
		r.Provenance = &contracts.ReceiptProvenance{
			GeneratedBy: env.Actor,
			Parents:     env.ParentReceiptHashes,
			Context:     "conformance",
		}
	}

	// Map tape ref to replay script
	if env.TapeRef != "" {
		r.ReplayScript = &contracts.ReplayScriptRef{
			ScriptID: env.TapeRef,
			Engine:   "helm-vcr-v1",
		}
	}

	// Map tool info
	if env.ToolName != "" {
		r.ExecutorID = env.ToolName
		if r.Metadata == nil {
			r.Metadata = make(map[string]any)
		}
		r.Metadata["tool_manifest_hash"] = env.ToolManifestHash
	}

	return r
}

// FromContractsReceipt converts a contracts.Receipt back to a ReceiptEnvelope
// for conformance verification. Fields not present in Receipt are left empty.
func FromContractsReceipt(r *contracts.Receipt) *ReceiptEnvelope {
	env := &ReceiptEnvelope{
		ReceiptHash:       r.ReceiptID,
		DecisionID:        r.DecisionID,
		EffectDigestHash:  r.EffectID,
		PayloadCommitment: r.BlobHash,
		Signature:         r.Signature,
		TimestampVirtual:  r.Timestamp.Format(time.RFC3339Nano),
	}

	// Extract metadata fields
	if r.Metadata != nil {
		if v, ok := r.Metadata["tenant_id"].(string); ok {
			env.TenantID = v
		}
		if v, ok := r.Metadata["envelope_id"].(string); ok {
			env.EnvelopeID = v
		}
		if v, ok := r.Metadata["envelope_hash"].(string); ok {
			env.EnvelopeHash = v
		}
		if v, ok := r.Metadata["jurisdiction"].(string); ok {
			env.Jurisdiction = v
		}
		if v, ok := r.Metadata["effect_class"].(string); ok {
			env.EffectClass = v
		}
		if v, ok := r.Metadata["effect_type"].(string); ok {
			env.EffectType = v
		}
		if v, ok := r.Metadata["action_type"].(string); ok {
			env.ActionType = v
		}
		if v, ok := r.Metadata["intent_id"].(string); ok {
			env.IntentID = v
		}
		if v, ok := r.Metadata["policy_hash"].(string); ok {
			env.PolicyHash = v
		}
		if v, ok := r.Metadata["policy_version"].(string); ok {
			env.PolicyVersion = v
		}
		if v, ok := r.Metadata["phenotype_hash"].(string); ok {
			env.PhenotypeHash = v
		}
		if v, ok := r.Metadata["run_id"].(string); ok {
			env.RunID = v
		}
		if v, ok := r.Metadata["seq"].(uint64); ok {
			env.Seq = v
		}
	}

	// Map provenance to DAG parents + actor
	if r.Provenance != nil {
		env.Actor = r.Provenance.GeneratedBy
		env.ParentReceiptHashes = r.Provenance.Parents
	}

	// Map replay script
	if r.ReplayScript != nil {
		env.TapeRef = r.ReplayScript.ScriptID
	}

	// Map tool info
	if r.ExecutorID != "" {
		env.ToolName = r.ExecutorID
		if r.Metadata != nil {
			if v, ok := r.Metadata["tool_manifest_hash"].(string); ok {
				env.ToolManifestHash = v
			}
		}
	}

	return env
}

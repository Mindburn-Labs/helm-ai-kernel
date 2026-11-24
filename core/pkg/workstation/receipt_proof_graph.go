package workstation

import (
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
)

func buildProofGraph(
	manifest RunManifest,
	artifactHashes map[string]string,
	changedFiles []contracts.AgentChangedFile,
	validation []contracts.AgentValidationResult,
	toolActions []contracts.AgentToolAction,
	memoryEffects []contracts.AgentMemoryEffect,
	recurringEffects []contracts.AgentRecurringLoopEffect,
	deniedEffects []contracts.AgentDeniedEffect,
) ([]*proofgraph.Node, error) {
	graph := proofgraph.NewGraph().WithClock(func() time.Time { return manifestTimestamp(manifest) })
	principal := firstNonEmpty(manifest.ActorID, "agent")
	seq := uint64(1)
	var nodes []*proofgraph.Node
	appendPayload := func(kind proofgraph.NodeType, payload any) error {
		bytes, err := canonicalize.JCS(payload)
		if err != nil {
			return err
		}
		node, err := graph.Append(kind, bytes, principal, seq)
		if err != nil {
			return err
		}
		nodes = append(nodes, node)
		seq++
		return nil
	}
	if err := appendPayload(proofgraph.NodeTypeIntent, map[string]any{
		"run_id":         manifest.RunID,
		"goal":           manifest.Goal,
		"agent_surface":  manifest.AgentSurface,
		"policy_profile": manifest.PolicyProfile,
	}); err != nil {
		return nil, err
	}
	if err := appendPayload(proofgraph.NodeTypeAttestation, map[string]any{
		"artifact_hashes": sortedStringMap(artifactHashes),
	}); err != nil {
		return nil, err
	}
	for _, file := range changedFiles {
		if err := appendPayload(proofgraph.NodeTypeEffect, map[string]any{
			"effect_type": contracts.EffectTypeWorkstationFileDraft,
			"file":        file,
			"verdict":     contracts.WorkstationVerdictAllow,
		}); err != nil {
			return nil, err
		}
	}
	for _, result := range validation {
		if err := appendPayload(proofgraph.NodeTypeEffect, map[string]any{
			"effect_type": contracts.EffectTypeWorkstationValidationRun,
			"validation":  result,
		}); err != nil {
			return nil, err
		}
	}
	for _, action := range toolActions {
		if err := appendPayload(proofgraph.NodeTypeEffect, map[string]any{
			"effect_type": action.EffectType,
			"tool_action": action,
		}); err != nil {
			return nil, err
		}
	}
	for _, effect := range memoryEffects {
		if err := appendPayload(proofgraph.NodeTypeEffect, map[string]any{
			"effect_type":   contracts.EffectTypeWorkstationMemoryWrite,
			"memory_effect": effect,
		}); err != nil {
			return nil, err
		}
	}
	for _, effect := range recurringEffects {
		if err := appendPayload(proofgraph.NodeTypeEffect, map[string]any{
			"effect_type":           contracts.EffectTypeWorkstationRecurringLoop,
			"recurring_loop_effect": effect,
		}); err != nil {
			return nil, err
		}
	}
	for _, effect := range deniedEffects {
		if err := appendPayload(proofgraph.NodeTypeEffect, map[string]any{
			"effect_type":   "WORKSTATION_DENIED_EFFECT",
			"denied_effect": effect,
		}); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

func appendCheckpoint(nodes []*proofgraph.Node, manifest RunManifest, receipt *contracts.AgentRunReceipt) (*proofgraph.Node, error) {
	graph := proofgraph.NewGraph().WithClock(func() time.Time { return manifestTimestamp(manifest) })
	var last *proofgraph.Node
	for _, node := range nodes {
		graphNode, err := graph.Append(node.Kind, node.Payload, node.Principal, node.PrincipalSeq)
		if err != nil {
			return nil, err
		}
		last = graphNode
	}
	_ = last
	payload, err := canonicalize.JCS(map[string]any{
		"receipt_id":         receipt.ReceiptID,
		"receipt_hash":       receipt.ReceiptHash,
		"evidence_pack_refs": receipt.EvidencePackRefs,
	})
	if err != nil {
		return nil, err
	}
	return graph.Append(proofgraph.NodeTypeCheckpoint, payload, firstNonEmpty(manifest.ActorID, "agent"), uint64(len(nodes)+1))
}

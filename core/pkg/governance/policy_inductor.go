package governance

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
)

type PolicyInductor struct {
	ProducerID string
	signer     crypto.Signer
}

func NewPolicyInductor(id string, signer crypto.Signer) *PolicyInductor {
	return &PolicyInductor{ProducerID: id, signer: signer}
}

func (p *PolicyInductor) Name() string {
	return "policy.inductor"
}

func (p *PolicyInductor) Advise(ctx context.Context, intent string, contextData map[string]any) (*artifacts.ArtifactEnvelope, error) {
	// 1. Logic: In a real system, checking historical precedents or OPA rules.
	// For Demo: We assume any "Scale" or "Deploy" intent matches a standard policy.

	policyPayload := map[string]string{
		"policy_id": "pol-generic-allow",
		"intent":    intent,
		"effect":    "ALLOW",
		"reason":    "Standard Operating Procedure",
	}

	bytes, err := json.Marshal(policyPayload)
	if err != nil {
		return nil, fmt.Errorf("policy inductor: marshal failed: %w", err)
	}

	env := &artifacts.ArtifactEnvelope{
		Type:          artifacts.TypePolicyDraft,
		SchemaVersion: "v1",
		Payload:       bytes,
		ProducerID:    p.ProducerID,
		Timestamp:     time.Now().UTC(),
	}
	if err := artifacts.SignEnvelope(env, p.signer); err != nil {
		return nil, err
	}
	return env, nil
}

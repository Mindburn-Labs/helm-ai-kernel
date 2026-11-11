package a2a

import (
	"context"
	"strings"
	"testing"
)

// TestKernelCardEvaluateSkillClaimsOnlyNegotiation pins the helm.evaluate
// skill text the kernel serves at /.well-known/agent-card.json. The skill is
// the helm.evaluate MCP tool, which calls DefaultVerifier.Negotiate; that path
// checks expiry, schema version, policy rules and features, and never the
// envelope signature, so the card must not offer signature verification.
func TestKernelCardEvaluateSkillClaimsOnlyNegotiation(t *testing.T) {
	card := NewKernelCardProvider(KernelCardConfig{}).GetCard()
	if card == nil {
		t.Fatal("kernel card provider returned no card")
	}
	var skill *AgentSkill
	for i := range card.Skills {
		if card.Skills[i].ID == "helm.evaluate" {
			skill = &card.Skills[i]
		}
	}
	if skill == nil {
		t.Fatalf("card has no helm.evaluate skill: %+v", card.Skills)
	}
	const want = "Negotiate A2A protocol features for cross-agent communication: expiry, schema version, policy rules and required features. Envelope signatures are not verified."
	if skill.Description != want {
		t.Fatalf("helm.evaluate description = %q, want %q", skill.Description, want)
	}
	for _, text := range append([]string{skill.Description}, skill.Examples...) {
		lower := strings.ToLower(text)
		if strings.Contains(lower, "verify envelope signatures") || strings.Contains(lower, "verify agent signature") {
			t.Fatalf("helm.evaluate skill offers signature verification: %q", text)
		}
	}
}

// TestNegotiateAcceptsUnsignedEnvelope keeps the card text above true: the
// path behind helm.evaluate accepts an envelope that carries no signature.
func TestNegotiateAcceptsUnsignedEnvelope(t *testing.T) {
	env := &Envelope{
		EnvelopeID:      "env-unsigned",
		SchemaVersion:   CurrentVersion,
		OriginAgentID:   "agent-a",
		TargetAgentID:   "agent-b",
		OfferedFeatures: []Feature{FeatureEvidenceExport},
	}
	result, err := NewDefaultVerifier().Negotiate(context.Background(), env, []Feature{FeatureEvidenceExport})
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	if !result.Accepted {
		t.Fatalf("unsigned envelope was refused (%s: %s); if Negotiate now verifies signatures, update the helm.evaluate card text",
			result.DenyReason, result.DenyDetails)
	}
}

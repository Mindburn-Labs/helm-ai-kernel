package guardian

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/capability"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	kcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
)

type tokenTestRig struct {
	registry  *capability.Registry
	authority *capability.TokenAuthority
	verifier  *capability.TokenVerifier
}

func newTokenTestRig(t *testing.T) tokenTestRig {
	t.Helper()
	reg := loadTestCapabilityRegistry(t)
	signer, err := kcrypto.NewEd25519Signer("guardian-capability-token-test")
	require.NoError(t, err)
	store := capability.NewInMemoryTokenStore()
	authority := capability.NewTokenAuthority(signer, reg, store, nil)
	verifier := capability.NewTokenVerifier(authority.PubKeyHex(), reg, store, nil)
	return tokenTestRig{registry: reg, authority: authority, verifier: verifier}
}

func tokenAsMap(t *testing.T, token *capability.Token) map[string]interface{} {
	t.Helper()
	buf, err := json.Marshal(token)
	require.NoError(t, err)
	var out map[string]interface{}
	require.NoError(t, json.Unmarshal(buf, &out))
	return out
}

func TestCapabilityGate_ValidToken_EnrichesAndConsumes(t *testing.T) {
	rig := newTokenTestRig(t)
	g := NewGuardian(&MockSigner{}, nil, nil,
		WithCapabilityRegistry(rig.registry),
		WithCapabilityTokenVerifier(rig.verifier),
	)
	token, err := rig.authority.Mint(capability.MintRequest{
		TaskID:       "task-1",
		Subject:      capability.TokenSubject{AgentID: "agent-1"},
		CapabilityID: "helm.cap.gui.gelab.tap",
		MaxUses:      2,
	})
	require.NoError(t, err)

	span := noop.NewTracerProvider().Tracer("test")
	_, sp := span.Start(context.Background(), "gate")
	req := &DecisionRequest{
		Principal: "agent-1",
		Action:    "dispatch",
		Context: map[string]interface{}{
			ContextKeyCapabilityID:    "helm.cap.gui.gelab.tap",
			ContextKeyTaskID:          "task-1",
			ContextKeyCapabilityToken: tokenAsMap(t, token),
		},
	}
	decision, handled := g.resolveCapabilityGate(sp, req)
	assert.False(t, handled)
	assert.Nil(t, decision)
	assert.Equal(t, token.TokenID, req.Context["capability_token_id"])

	// One use was consumed.
	_, uses, err := rig.authority.Store().Get(token.TokenID)
	require.NoError(t, err)
	assert.Equal(t, 1, uses)
}

func TestEvaluateDecision_TokenTaskMismatch_Denies(t *testing.T) {
	rig := newTokenTestRig(t)
	g := NewGuardian(&MockSigner{}, nil, nil,
		WithCapabilityRegistry(rig.registry),
		WithCapabilityTokenVerifier(rig.verifier),
	)
	token, err := rig.authority.Mint(capability.MintRequest{
		TaskID:       "task-A",
		Subject:      capability.TokenSubject{AgentID: "agent-1"},
		CapabilityID: "helm.cap.gui.gelab.tap",
	})
	require.NoError(t, err)

	decision, err := g.EvaluateDecision(context.Background(), DecisionRequest{
		Principal: "agent-1",
		Action:    "dispatch",
		Context: map[string]interface{}{
			ContextKeyCapabilityID:    "helm.cap.gui.gelab.tap",
			ContextKeyTaskID:          "task-B",
			ContextKeyCapabilityToken: tokenAsMap(t, token),
		},
	})
	require.NoError(t, err)
	assert.Equal(t, string(contracts.VerdictDeny), decision.Verdict)
	assert.Equal(t, string(contracts.ReasonCapabilityTokenInvalid), decision.ReasonCode)
	assert.Contains(t, decision.Reason, capability.TokenRejectTaskMismatch)
	assert.NotEmpty(t, decision.Signature)
}

func TestEvaluateDecision_RevokedToken_Denies(t *testing.T) {
	rig := newTokenTestRig(t)
	g := NewGuardian(&MockSigner{}, nil, nil,
		WithCapabilityRegistry(rig.registry),
		WithCapabilityTokenVerifier(rig.verifier),
	)
	token, err := rig.authority.Mint(capability.MintRequest{
		TaskID:       "task-1",
		Subject:      capability.TokenSubject{AgentID: "agent-1"},
		CapabilityID: "helm.cap.gui.gelab.tap",
	})
	require.NoError(t, err)
	require.NoError(t, rig.authority.Store().Revoke(token.TokenID, "rcpt_revoke_test"))

	decision, err := g.EvaluateDecision(context.Background(), DecisionRequest{
		Principal: "agent-1",
		Action:    "dispatch",
		Context: map[string]interface{}{
			ContextKeyCapabilityID:    "helm.cap.gui.gelab.tap",
			ContextKeyTaskID:          "task-1",
			ContextKeyCapabilityToken: tokenAsMap(t, token),
		},
	})
	require.NoError(t, err)
	assert.Equal(t, string(contracts.VerdictDeny), decision.Verdict)
	assert.Equal(t, string(contracts.ReasonCapabilityTokenInvalid), decision.ReasonCode)
	assert.Contains(t, decision.Reason, string(capability.TokenStatusRevoked))
}

func TestEvaluateDecision_MalformedToken_Denies(t *testing.T) {
	rig := newTokenTestRig(t)
	g := NewGuardian(&MockSigner{}, nil, nil,
		WithCapabilityRegistry(rig.registry),
		WithCapabilityTokenVerifier(rig.verifier),
	)
	decision, err := g.EvaluateDecision(context.Background(), DecisionRequest{
		Principal: "agent-1",
		Action:    "dispatch",
		Context: map[string]interface{}{
			ContextKeyCapabilityID:    "helm.cap.gui.gelab.tap",
			ContextKeyTaskID:          "task-1",
			ContextKeyCapabilityToken: "not-a-token",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, string(contracts.VerdictDeny), decision.Verdict)
	assert.Equal(t, string(contracts.ReasonCapabilityTokenInvalid), decision.ReasonCode)
}

func TestCapabilityGate_TokenWithoutVerifier_IsIgnored(t *testing.T) {
	// Defense in depth for misconfiguration: a presented token without a
	// verifier must NOT grant anything, but also must not break the gate.
	rig := newTokenTestRig(t)
	g := NewGuardian(&MockSigner{}, nil, nil, WithCapabilityRegistry(rig.registry))
	token, err := rig.authority.Mint(capability.MintRequest{
		TaskID:       "task-1",
		Subject:      capability.TokenSubject{AgentID: "agent-1"},
		CapabilityID: "helm.cap.gui.gelab.tap",
	})
	require.NoError(t, err)

	span := noop.NewTracerProvider().Tracer("test")
	_, sp := span.Start(context.Background(), "gate")
	req := &DecisionRequest{
		Context: map[string]interface{}{
			ContextKeyCapabilityID:    "helm.cap.gui.gelab.tap",
			ContextKeyTaskID:          "task-1",
			ContextKeyCapabilityToken: tokenAsMap(t, token),
		},
	}
	decision, handled := g.resolveCapabilityGate(sp, req)
	assert.False(t, handled)
	assert.Nil(t, decision)
	_, hasTokenID := req.Context["capability_token_id"]
	assert.False(t, hasTokenID, "unverified token must not be bound into context")
	// No use consumed.
	_, uses, err := rig.authority.Store().Get(token.TokenID)
	require.NoError(t, err)
	assert.Equal(t, 0, uses)
}

func TestTokenAuthority_TTLDefault(t *testing.T) {
	rig := newTokenTestRig(t)
	token, err := rig.authority.Mint(capability.MintRequest{
		TaskID:       "task-1",
		Subject:      capability.TokenSubject{AgentID: "agent-1"},
		CapabilityID: "helm.cap.gui.gelab.tap",
	})
	require.NoError(t, err)
	delta := token.Grant.ExpiresAt.Sub(token.Grant.IssuedAt)
	assert.Equal(t, capability.DefaultTokenTTL, delta)
	assert.WithinDuration(t, time.Now().Add(capability.DefaultTokenTTL), token.Grant.ExpiresAt, 5*time.Second)
}

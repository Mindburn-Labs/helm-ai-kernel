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
)

type tokenTestRig struct {
	registry  *capability.Registry
	authority *capability.TokenAuthority
	verifier  *capability.TokenVerifier
}

func newTokenTestRig(t *testing.T) tokenTestRig {
	t.Helper()
	clock := func() time.Time { return time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC) }
	reg := loadTestCapabilityRegistry(t)
	signer, err := kcrypto.NewEd25519Signer("guardian-capability-token-test")
	require.NoError(t, err)
	store := capability.NewInMemoryTokenStore()
	authority := capability.NewTokenAuthority(signer, reg, store, clock)
	verifier := capability.NewTokenVerifier(authority.PubKeyHex(), reg, store, clock)
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

func TestCapabilityGate_ValidTokenEnrichesAndConsumes(t *testing.T) {
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

	req := &DecisionRequest{
		Principal: "agent-1",
		Action:    "dispatch",
		Context: map[string]interface{}{
			ContextKeyCapabilityID:    "helm.cap.gui.gelab.tap",
			ContextKeyTaskID:          "task-1",
			ContextKeyCapabilityToken: tokenAsMap(t, token),
		},
	}
	decision, err := g.resolveCapabilityGate(testCapabilitySpan(t), req, nil, "sha256:policy")
	require.NoError(t, err)
	assert.Nil(t, decision)
	assert.Equal(t, token.TokenID, req.Context["capability_token_id"])
	_, leaked := req.Context[ContextKeyCapabilityToken]
	assert.False(t, leaked, "raw bearer token must not reach the decision context")

	_, uses, err := rig.authority.Store().Get(token.TokenID)
	require.NoError(t, err)
	assert.Equal(t, 1, uses)
}

func TestEvaluateDecision_TokenTaskMismatchDeniesWithoutLeak(t *testing.T) {
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
	_, leaked := decision.InputContext[ContextKeyCapabilityToken]
	assert.False(t, leaked)
}

func TestEvaluateDecision_RevokedAndMalformedTokensDeny(t *testing.T) {
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

	for name, rawToken := range map[string]interface{}{
		"revoked":   tokenAsMap(t, token),
		"malformed": "not-a-token",
	} {
		t.Run(name, func(t *testing.T) {
			decision, err := g.EvaluateDecision(context.Background(), DecisionRequest{
				Action: "dispatch",
				Context: map[string]interface{}{
					ContextKeyCapabilityID:    "helm.cap.gui.gelab.tap",
					ContextKeyTaskID:          "task-1",
					ContextKeyCapabilityToken: rawToken,
				},
			})
			require.NoError(t, err)
			assert.Equal(t, string(contracts.ReasonCapabilityTokenInvalid), decision.ReasonCode)
		})
	}
}

func TestCapabilityGate_PresentedTokenWithoutVerifierDenies(t *testing.T) {
	rig := newTokenTestRig(t)
	token, err := rig.authority.Mint(capability.MintRequest{
		TaskID:       "task-1",
		Subject:      capability.TokenSubject{AgentID: "agent-1"},
		CapabilityID: "helm.cap.gui.gelab.tap",
	})
	require.NoError(t, err)
	g := NewGuardian(&MockSigner{}, nil, nil, WithCapabilityRegistry(rig.registry))

	decision, err := g.EvaluateDecision(context.Background(), DecisionRequest{
		Action: "dispatch",
		Context: map[string]interface{}{
			ContextKeyCapabilityID:    "helm.cap.gui.gelab.tap",
			ContextKeyTaskID:          "task-1",
			ContextKeyCapabilityToken: tokenAsMap(t, token),
		},
	})
	require.NoError(t, err)
	assert.Equal(t, string(contracts.ReasonCapabilityTokenInvalid), decision.ReasonCode)
}

func TestCapabilityTokenRosterAndReasonCode(t *testing.T) {
	rig := newTokenTestRig(t)
	g := NewGuardian(&MockSigner{}, nil, nil, WithCapabilityTokenVerifier(rig.verifier))
	assert.Contains(t, g.GateRoster().Active, GateCapabilityToken)
	assert.True(t, contracts.IsCanonicalReasonCode(string(contracts.ReasonCapabilityTokenInvalid)))
}

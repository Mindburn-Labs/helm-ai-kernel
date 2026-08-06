package mcp

import (
	"context"
	"testing"

	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/runtimeadapters"
)

type permitRecordingConnector struct {
	id     string
	permit *effects.EffectPermit
	calls  int
}

func (c *permitRecordingConnector) ID() string { return c.id }

func (c *permitRecordingConnector) Execute(_ context.Context, permit *effects.EffectPermit, _ string, _ map[string]any) (any, error) {
	c.calls++
	c.permit = permit
	return map[string]any{"ok": true}, nil
}

// Signing is only worth anything if something downstream requires it. This
// asserts the permit that reaches a connector is signed, so the signing path
// cannot silently regress to a no-op.
func TestDispatchedPermitReachesTheConnectorSigned(t *testing.T) {
	connector := &permitRecordingConnector{id: "linear"}
	adapter, _ := newAdapter(t, BridgeConfig{Profile: operateProfile(), Connector: connector, Now: fixedClock()})
	resp, err := adapter.Intercept(context.Background(), &runtimeadapters.AdaptedRequest{
		RuntimeType: "mcp", ToolName: "linear.get_issue",
		Arguments:   map[string]any{"issue_id": "ISS-1"},
		PrincipalID: "ve-assistant",
	})
	if err != nil {
		t.Fatalf("intercept: %v", err)
	}
	if !resp.Allowed {
		t.Fatalf("expected ALLOW, got %+v", resp.DenyReason)
	}
	if connector.calls != 1 || connector.permit == nil {
		t.Fatalf("connector was not dispatched with a permit: calls=%d", connector.calls)
	}
	if connector.permit.Signature == "" {
		t.Fatal("the connector received an unsigned permit from a signing bridge")
	}
}

// The dispatch gate must be reachable. A permit mutated after issuance, or one
// carrying no signature at all, has to be refused before any connector runs —
// this is what keeps signing from being an unobserved side effect while the
// connector-side key is unconfigured.
func TestBridgeDispatchGateRefusesUnsignedAndTamperedPermits(t *testing.T) {
	bridge := NewGovernedBridge(withTestSigningSeed(BridgeConfig{
		Profile: operateProfile(), Connector: &permitRecordingConnector{id: "linear"}, Now: fixedClock(),
	}))
	if bridge.permitSigner == nil {
		t.Fatal("test bridge has no permit signer; the gate would be vacuous")
	}

	if err := bridge.verifyPermitBeforeDispatch(&effects.EffectPermit{ConnectorID: "linear"}); err == nil {
		t.Fatal("an unsigned permit passed the dispatch gate")
	}

	signed := &effects.EffectPermit{
		PermitID:    "permit-gate",
		ConnectorID: "linear",
		Scope:       effects.EffectScope{AllowedAction: "linear.get_issue"},
		Nonce:       "nonce-gate",
	}
	if err := helmcrypto.SignPermit(bridge.permitSigner, signed); err != nil {
		t.Fatalf("sign permit: %v", err)
	}
	if err := bridge.verifyPermitBeforeDispatch(signed); err != nil {
		t.Fatalf("an intact permit was refused: %v", err)
	}
	signed.Scope.AllowedAction = "linear.create_issue"
	if err := bridge.verifyPermitBeforeDispatch(signed); err == nil {
		t.Fatal("a permit whose scope was widened after signing passed the gate")
	}
}

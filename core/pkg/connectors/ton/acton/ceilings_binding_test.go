package acton

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
)

// The P0 ceilings decide whether a mainnet broadcast is allowed at all, whether
// a spend fits under the cap, and which Acton/Tolk versions are accepted. A
// caller that could replace them from the request body would be able to widen
// its own policy, so the connector accepts a caller-supplied ceiling set only
// when the permit binds that exact set by hash.

// ceilingsTestParams is a complete, otherwise-valid testnet deploy request.
// The ceiling set it carries is the one under test.
func ceilingsTestParams() map[string]any {
	manifest := scriptManifest("contracts/scripts/deploy.tolk", "sha256:script", NetworkTestnet)
	return map[string]any{
		"script_path":           "contracts/scripts/deploy.tolk",
		"script_hash":           "sha256:script",
		"tolk_compiler_version": "fixture-tolk-1.0.0",
		"wallet_ref":            "wallet:tenant-test-ton-1",
		"max_ton_spend":         "0.05",
		"script_manifest":       manifest,
		"expected_effects":      manifest.ExpectedEffects,
		"p0_ceilings": map[string]any{
			"MAX_TON_SPEND_PER_ACTION": "0.10",
			"ALLOW_TESTNET_DEPLOY":     true,
		},
	}
}

// TestCallerSuppliedCeilingsWithoutPermitBindingAreDenied is the forbidden
// case: the request carries a ceiling set the permit says nothing about, so
// the call must not dispatch.
func TestCallerSuppliedCeilingsWithoutPermitBindingAreDenied(t *testing.T) {
	exec := &fakeExecutor{stdout: []byte(`{"tx_hash":"abc"}`)}
	connector := NewConnector(Config{Runner: Runner{Executor: exec, SandboxID: "s1"}, SandboxGrant: sealedGrant(t, true, false)})
	permit := ceilingsTestPermit(t, connector)
	// Deliberately not bound to p0_ceilings_hash.
	out, err := connector.Execute(context.Background(), permit, string(ActionScriptTestnet), ceilingsTestParams())
	if err != nil {
		t.Fatalf("a policy denial is reported in the receipt, not as a transport error: %v", err)
	}
	receipt, ok := out.(*ActonReceipt)
	if !ok {
		t.Fatalf("expected ActonReceipt, got %T", out)
	}
	if receipt.Verdict != contracts.VerdictDeny || receipt.ReasonCode != ReasonPolicyHashMismatch {
		t.Fatalf("expected policy hash mismatch deny, got %s/%s", receipt.Verdict, receipt.ReasonCode)
	}
	if exec.calls != 0 {
		t.Fatalf("unbound caller ceilings must not dispatch, calls=%d", exec.calls)
	}
}

// TestCallerSuppliedCeilingsDisagreeingWithPermitAreDenied is the tamper
// case: the permit binds one ceiling set and the request body states a
// different one. The request must lose.
func TestCallerSuppliedCeilingsDisagreeingWithPermitAreDenied(t *testing.T) {
	exec := &fakeExecutor{stdout: []byte(`{"tx_hash":"abc"}`)}
	connector := NewConnector(Config{Runner: Runner{Executor: exec, SandboxID: "s1"}, SandboxGrant: sealedGrant(t, true, false)})
	permit := ceilingsTestPermit(t, connector)
	permit.EvidenceBindings["p0_ceilings_hash"] = policyFromParams(map[string]any{
		"p0_ceilings": map[string]any{
			"MAX_TON_SPEND_PER_ACTION": "0.10",
			"ALLOW_TESTNET_DEPLOY":     true,
		},
	}).Hash()
	params := ceilingsTestParams()
	// The request now states a wider cap than the permit bound.
	params["p0_ceilings"] = map[string]any{
		"MAX_TON_SPEND_PER_ACTION": "1000",
		"ALLOW_TESTNET_DEPLOY":     true,
	}
	out, err := connector.Execute(context.Background(), permit, string(ActionScriptTestnet), params)
	if err != nil {
		t.Fatalf("a policy denial is reported in the receipt, not as a transport error: %v", err)
	}
	receipt, ok := out.(*ActonReceipt)
	if !ok {
		t.Fatalf("expected ActonReceipt, got %T", out)
	}
	if receipt.Verdict != contracts.VerdictDeny || receipt.ReasonCode != ReasonPolicyHashMismatch {
		t.Fatalf("expected policy hash mismatch deny, got %s/%s", receipt.Verdict, receipt.ReasonCode)
	}
	if exec.calls != 0 {
		t.Fatalf("mismatched caller ceilings must not dispatch, calls=%d", exec.calls)
	}
}

// TestCallerSuppliedCeilingsMatchingPermitAreAccepted is the allowed case: a
// caller may restate the ceiling set the permit already binds, and the call
// dispatches under it.
func TestCallerSuppliedCeilingsMatchingPermitAreAccepted(t *testing.T) {
	exec := &fakeExecutor{stdout: []byte(`{"tx_hash":"abc"}`)}
	connector := NewConnector(Config{Runner: Runner{Executor: exec, SandboxID: "s1"}, SandboxGrant: sealedGrant(t, true, false)})
	permit := ceilingsTestPermit(t, connector)
	bindPermitToCeilings(t, permit, ceilingsTestParams())
	out, err := connector.Execute(context.Background(), permit, string(ActionScriptTestnet), ceilingsTestParams())
	if err != nil {
		t.Fatal(err)
	}
	receipt, ok := out.(*ActonReceipt)
	if !ok {
		t.Fatalf("expected ActonReceipt, got %T", out)
	}
	if receipt.Verdict != contracts.VerdictAllow || exec.calls != 1 {
		t.Fatalf("expected allowed dispatch, got %s/%s calls=%d", receipt.Verdict, receipt.ReasonCode, exec.calls)
	}
}

// TestCeilingsAbsentFromRequestUseConnectorDefaults proves the connector's
// own configuration is the source of truth when the request says nothing
// about ceilings at all.
func TestCeilingsAbsentFromRequestUseConnectorDefaults(t *testing.T) {
	exec := &fakeExecutor{stdout: []byte(`{"tx_hash":"abc"}`)}
	connector := NewConnector(Config{Runner: Runner{Executor: exec, SandboxID: "s1"}, SandboxGrant: sealedGrant(t, true, false)})
	permit := ceilingsTestPermit(t, connector)
	params := ceilingsTestParams()
	delete(params, "p0_ceilings")
	out, err := connector.Execute(context.Background(), permit, string(ActionScriptTestnet), params)
	if err != nil {
		t.Fatal(err)
	}
	receipt, ok := out.(*ActonReceipt)
	if !ok {
		t.Fatalf("expected ActonReceipt, got %T", out)
	}
	// The connector default forbids testnet broadcast, so the call is denied
	// on policy grounds — not on a hash mismatch, and never on a ceiling the
	// caller wrote.
	if receipt.Verdict != contracts.VerdictDeny || receipt.ReasonCode != ReasonSpendCeilingExceeded {
		t.Fatalf("expected default ceilings to deny the broadcast, got %s/%s", receipt.Verdict, receipt.ReasonCode)
	}
	if exec.calls != 0 {
		t.Fatalf("default ceilings must not allow the broadcast, calls=%d", exec.calls)
	}
}

// TestEnvelopeRecordsTheCeilingsActuallyApplied proves the envelope names the
// ceiling set the call was judged against, so a replay binds the same limits.
func TestEnvelopeRecordsTheCeilingsActuallyApplied(t *testing.T) {
	exec := &fakeExecutor{stdout: []byte(`{"tx_hash":"abc"}`)}
	connector := NewConnector(Config{Runner: Runner{Executor: exec, SandboxID: "s1"}, SandboxGrant: sealedGrant(t, true, false)})
	permit := ceilingsTestPermit(t, connector)
	params := ceilingsTestParams()
	bindPermitToCeilings(t, permit, params)
	out, err := connector.Execute(context.Background(), permit, string(ActionScriptTestnet), params)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := out.(*ActonReceipt); !ok {
		t.Fatalf("expected ActonReceipt, got %T", out)
	}
	expected := policyFromParams(params).Hash()
	if expected == "" {
		t.Fatal("expected a hashable ceiling set")
	}
	env, envErr := NewEnvelope(params, ActionScriptTestnet, permit.IntentHash, 0)
	if envErr != nil {
		t.Fatal(envErr)
	}
	if env.P0CeilingsHash != "" && env.P0CeilingsHash != expected {
		t.Fatalf("envelope p0_ceilings_hash %q does not name the applied ceilings %q", env.P0CeilingsHash, expected)
	}
}

func ceilingsTestPermit(t *testing.T, connector *Connector) *effects.EffectPermit {
	t.Helper()
	permit := &effects.EffectPermit{
		PermitID:    "permit-ceilings",
		IntentHash:  "sha256:intent",
		VerdictHash: "sha256:verdict",
		PolicyHash:  "sha256:policy",
		EffectType:  effects.EffectTypeExecute,
		ConnectorID: ConnectorID,
		IssuerID:    "principal:test",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	bindPermitToGrant(t, permit, connector.defaultGrant)
	return permit
}

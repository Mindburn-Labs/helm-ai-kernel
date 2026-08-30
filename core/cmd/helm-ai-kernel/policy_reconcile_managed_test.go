package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/pdp"
	policyreconcile "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policy/reconcile"
)

func TestCompileManagedPolicySnapshot(t *testing.T) {
	sourceHash := "sha256:" + strings.Repeat("a", 64)
	bundle := managedPolicyBundleForTest(t, sourceHash)
	head := policyreconcile.PolicyHead{
		Scope:       policyreconcile.PolicyScope{TenantID: "tenant", WorkspaceID: "workspace"},
		PolicyEpoch: 7,
		PolicyHash:  policyreconcile.HashBytes(bundle),
		BundleRef:   "cp-policy-publication:7",
		SourceRefs:  []string{sourceHash},
	}
	snapshot, err := compileServePolicySnapshot(context.Background(), head, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.PDP == nil || snapshot.Graph != nil || snapshot.P0CeilingsHash == "" || snapshot.P1BundleHash == "" || len(snapshot.P2OverlayHashes) != 1 {
		t.Fatalf("managed snapshot is incomplete: %+v", snapshot)
	}
	allow, err := snapshot.PDP.Evaluate(context.Background(), &pdp.DecisionRequest{Action: "READ", Context: map[string]any{"effect_class": "E0"}})
	if err != nil || !allow.Allow {
		t.Fatalf("E0 decision = %+v, err=%v", allow, err)
	}
	escalate, err := snapshot.PDP.Evaluate(context.Background(), &pdp.DecisionRequest{Action: "WRITE", Context: map[string]any{"effect_class": "E3"}})
	if err != nil || escalate.Allow || escalate.ReasonCode != string(contracts.ReasonApprovalRequired) {
		t.Fatalf("E3 decision = %+v, err=%v", escalate, err)
	}

	head.BundleRef = "cp-policy-publication:6"
	if _, err := compileServePolicySnapshot(context.Background(), head, bundle); err == nil || !strings.Contains(err.Error(), "epoch") {
		t.Fatalf("expected bundle_ref epoch rejection, got %v", err)
	}
}

func managedPolicyBundleForTest(t *testing.T, sourceHash string) []byte {
	t.Helper()
	bundle, err := json.Marshal(pdp.ManagedPolicyBundle{
		P0Ceilings:           json.RawMessage(`{"version":"1.0.0"}`),
		P1Bundle:             json.RawMessage(`{"version":"1.0.0"}`),
		P2Overlay:            json.RawMessage(`{"version":"1.0.0"}`),
		ApprovalRoutes:       json.RawMessage(`{"E3_default":{"level":"SINGLE_HUMAN"}}`),
		SourceLanguage:       "cel-dp",
		SourceHash:           sourceHash,
		CompiledArtifactKind: pdp.ManagedPolicyArtifactKind,
		KernelRuntime: pdp.ManagedPolicyRuntime{
			SchemaVersion:  pdp.ManagedPolicySchemaV1,
			DefaultVerdict: contracts.VerdictDeny,
			Rules: []pdp.ManagedPolicyRule{
				{ID: "p0-e4", Layer: pdp.ManagedPolicyLayerP0, EffectClass: "E4", Verdict: contracts.VerdictDeny, Reason: "deny irreversible effects"},
				{ID: "p1-e0", Layer: pdp.ManagedPolicyLayerP1, EffectClass: "E0", Verdict: contracts.VerdictAllow, Reason: "allow reads"},
				{ID: "p1-e3", Layer: pdp.ManagedPolicyLayerP1, EffectClass: "E3", Verdict: contracts.VerdictEscalate, Reason: "require approval"},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

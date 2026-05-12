package guardian

import (
	"context"
	"strings"
	"testing"

	pkg_artifact "github.com/Mindburn-Labs/helm-oss/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/kernel"
	policyreconcile "github.com/Mindburn-Labs/helm-oss/core/pkg/policy/reconcile"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/prg"
)

func allowGraphFor(action string) *prg.Graph {
	graph := prg.NewGraph()
	_ = graph.AddRule(action, prg.RequirementSet{
		ID:    "allow-" + action,
		Logic: prg.AND,
		Requirements: []prg.Requirement{
			{ID: "allow", Expression: "true"},
		},
	})
	return graph
}

func TestGuardianDecisionBindsActivePolicySnapshot(t *testing.T) {
	scope := policyreconcile.DefaultScope
	store := policyreconcile.NewAtomicSnapshotStore()
	hash := "sha256:snapshot-a"
	if err := store.Swap(scope, &policyreconcile.EffectivePolicySnapshot{
		TenantID:    scope.TenantID,
		WorkspaceID: scope.WorkspaceID,
		PolicyEpoch: 42,
		PolicyHash:  hash,
		Validation:  policyreconcile.ValidationStatus{Status: policyreconcile.StatusActive},
		Graph:       allowGraphFor("deploy"),
	}); err != nil {
		t.Fatalf("swap snapshot: %v", err)
	}

	g := NewGuardian(
		&MockSigner{},
		prg.NewGraph(),
		pkg_artifact.NewRegistry(NewMockStore(), nil),
		WithPolicySnapshots(store, scope),
	)
	decision, err := g.EvaluateDecision(context.Background(), DecisionRequest{
		Principal: "agent-1",
		Action:    "EXECUTE_TOOL",
		Resource:  "deploy",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if decision.Verdict != string(contracts.VerdictAllow) {
		t.Fatalf("expected allow, got %+v", decision)
	}
	if decision.PolicyContentHash != hash || decision.PolicyEpoch != "42" || decision.PolicyVersion != hash {
		t.Fatalf("decision did not bind snapshot authority: %+v", decision)
	}
}

func TestGuardianMissingSnapshotDenies(t *testing.T) {
	scope := policyreconcile.DefaultScope
	g := NewGuardian(
		&MockSigner{},
		prg.NewGraph(),
		pkg_artifact.NewRegistry(NewMockStore(), nil),
		WithPolicySnapshots(policyreconcile.NewAtomicSnapshotStore(), scope),
	)

	decision, err := g.EvaluateDecision(context.Background(), DecisionRequest{
		Principal: "agent-1",
		Action:    "EXECUTE_TOOL",
		Resource:  "deploy",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if decision.Verdict != string(contracts.VerdictDeny) || decision.ReasonCode != string(contracts.ReasonPolicyNotReady) {
		t.Fatalf("expected POLICY_NOT_READY deny, got %+v", decision)
	}
}

func TestGuardianEarlyDenyBindsActivePolicySnapshot(t *testing.T) {
	scope := policyreconcile.DefaultScope
	store := policyreconcile.NewAtomicSnapshotStore()
	hash := "sha256:snapshot-freeze"
	if err := store.Swap(scope, &policyreconcile.EffectivePolicySnapshot{
		TenantID:    scope.TenantID,
		WorkspaceID: scope.WorkspaceID,
		PolicyEpoch: 7,
		PolicyHash:  hash,
		Validation:  policyreconcile.ValidationStatus{Status: policyreconcile.StatusActive},
		Graph:       allowGraphFor("deploy"),
	}); err != nil {
		t.Fatalf("swap snapshot: %v", err)
	}
	freeze := kernel.NewFreezeController()
	if _, err := freeze.Freeze("admin"); err != nil {
		t.Fatalf("freeze: %v", err)
	}

	g := NewGuardian(
		&MockSigner{},
		prg.NewGraph(),
		pkg_artifact.NewRegistry(NewMockStore(), nil),
		WithPolicySnapshots(store, scope),
		WithFreezeController(freeze),
	)
	decision, err := g.EvaluateDecision(context.Background(), DecisionRequest{
		Principal: "agent-1",
		Action:    "EXECUTE_TOOL",
		Resource:  "deploy",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if decision.Verdict != string(contracts.VerdictDeny) || decision.ReasonCode != string(contracts.ReasonSystemFrozen) {
		t.Fatalf("expected frozen deny, got %+v", decision)
	}
	if decision.PolicyContentHash != hash || decision.PolicyEpoch != "7" {
		t.Fatalf("early deny did not bind snapshot authority: %+v", decision)
	}
}

func TestGuardianPolicyEpochChangeBeforeIntentDenies(t *testing.T) {
	scope := policyreconcile.DefaultScope
	store := policyreconcile.NewAtomicSnapshotStore()
	if err := store.Swap(scope, &policyreconcile.EffectivePolicySnapshot{
		TenantID:    scope.TenantID,
		WorkspaceID: scope.WorkspaceID,
		PolicyEpoch: 1,
		PolicyHash:  "sha256:snapshot-1",
		Validation:  policyreconcile.ValidationStatus{Status: policyreconcile.StatusActive},
		Graph:       allowGraphFor("deploy"),
	}); err != nil {
		t.Fatalf("swap snapshot: %v", err)
	}
	g := NewGuardian(
		&MockSigner{},
		prg.NewGraph(),
		pkg_artifact.NewRegistry(NewMockStore(), nil),
		WithPolicySnapshots(store, scope),
	)
	decision, err := g.EvaluateDecision(context.Background(), DecisionRequest{
		Principal: "agent-1",
		Action:    "EXECUTE_TOOL",
		Resource:  "deploy",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if decision.Verdict != string(contracts.VerdictAllow) {
		t.Fatalf("expected allow, got %+v", decision)
	}

	if err := store.Swap(scope, &policyreconcile.EffectivePolicySnapshot{
		TenantID:    scope.TenantID,
		WorkspaceID: scope.WorkspaceID,
		PolicyEpoch: 2,
		PolicyHash:  "sha256:snapshot-2",
		Validation:  policyreconcile.ValidationStatus{Status: policyreconcile.StatusActive},
		Graph:       allowGraphFor("deploy"),
	}); err != nil {
		t.Fatalf("swap updated snapshot: %v", err)
	}

	_, err = g.IssueExecutionIntent(context.Background(), decision, &contracts.Effect{
		EffectID:   "effect-1",
		EffectType: "EXECUTE_TOOL",
		Params:     map[string]any{"tool_name": "deploy"},
	})
	if err == nil || !strings.Contains(err.Error(), string(contracts.ReasonPolicyEpochChanged)) {
		t.Fatalf("expected POLICY_EPOCH_CHANGED, got %v", err)
	}
}

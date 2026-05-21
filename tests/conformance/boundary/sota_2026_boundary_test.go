package boundaryconformance

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conformance"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestSOTA2026NegativeBoundaryVectorsAreConformanceGates(t *testing.T) {
	required := []string{
		"policy-not-ready",
		"stale-policy-bundle",
		"stale-rebac-tuples",
		"mcp-tool-list-call-mismatch",
		"direct-upstream-bypass",
		"pdp-outage",
		"missing-credentials",
		"malformed-tool-args",
		"schema-drift",
		"sandbox-overgrant",
		"blocked-egress",
		"deny-receipt-emission",
		"verification-scope-missing-t2",
		"green-tests-without-scope",
		"plan-transaction-missing-for-write",
		"plan-transaction-conflict",
		"stale-assumption-side-effect",
		"unapproved-harness-mutation",
		"harness-change-contract-missing-regression",
		"agent-authored-code-network-attempt",
		"agent-authored-code-unmounted-file-read",
		"wasm-fuel-exhaustion",
		"gui-action-missing-grounding-ref",
		"gui-action-postcondition-unverified",
	}
	vectors := conformance.DefaultNegativeBoundaryVectors()
	seen := map[string]conformance.NegativeBoundaryVector{}
	for _, vector := range vectors {
		seen[vector.ID] = vector
		if vector.ExpectedVerdict != contracts.VerdictDeny && vector.ExpectedVerdict != contracts.VerdictEscalate {
			t.Fatalf("%s expected verdict = %s, want DENY or ESCALATE", vector.ID, vector.ExpectedVerdict)
		}
		if !vector.MustEmitReceipt || !vector.MustNotDispatch {
			t.Fatalf("%s must emit receipt and block dispatch", vector.ID)
		}
		if len(vector.MustBindEvidence) == 0 {
			t.Fatalf("%s must bind evidence fields", vector.ID)
		}
	}
	for _, id := range required {
		if _, ok := seen[id]; !ok {
			t.Fatalf("missing SOTA 2026 negative boundary vector %q", id)
		}
	}
}

func TestSOTA2026BoundaryRegistryPersistsCheckpointedRecords(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "surfaces.json")
	registry, err := boundary.NewFileBackedSurfaceRegistry(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	record, err := registry.PutRecord(contracts.ExecutionBoundaryRecord{
		RecordID:    "conformance-deny-record",
		Verdict:     contracts.VerdictDeny,
		ReasonCode:  contracts.ReasonSchemaViolation,
		PolicyEpoch: "conformance-epoch",
		ToolName:    "mcp.drifted_tool",
		MCPServerID: "mcp-unapproved",
		CreatedAt:   now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.CreateCheckpoint(1); err != nil {
		t.Fatal(err)
	}

	reloaded, err := boundary.NewFileBackedSurfaceRegistry(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	verification := reloaded.VerifyRecord(record.RecordID)
	if !verification.Verified {
		t.Fatalf("expected durable record verification to pass: %+v", verification)
	}
	if verification.CheckpointHash == "" {
		t.Fatal("checkpoint hash must be included in verification")
	}
}

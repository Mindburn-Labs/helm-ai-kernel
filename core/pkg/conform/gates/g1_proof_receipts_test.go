package gates

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
	"github.com/stretchr/testify/require"
)

// makeDAGReceipt creates a receipt with all required fields for DAG model tests.
func makeDAGReceipt(seq uint64, hash string, parentHashes []string, tenantID, envelopeID string) ReceiptEnvelope {
	return ReceiptEnvelope{
		RunID:               "run-1",
		Seq:                 seq,
		TenantID:            tenantID,
		TimestampVirtual:    "2026-01-01T00:00:00Z",
		SchemaVersion:       "1.0",
		EnvelopeID:          envelopeID,
		EnvelopeHash:        "sha256:env001",
		Jurisdiction:        "US",
		PolicyHash:          "sha256:pol001",
		PolicyVersion:       "v1",
		Actor:               "agent-1",
		ActionType:          "policy_decision",
		EffectClass:         "read",
		EffectType:          "data_query",
		DecisionID:          "dec-" + hash,
		IntentID:            "int-" + hash,
		EffectDigestHash:    "sha256:eff001",
		CapabilityRef:       "cap-1",
		BudgetSnapshotRef:   "budget-1",
		PhenotypeHash:       "sha256:pheno001",
		ParentReceiptHashes: parentHashes,
		ReceiptHash:         hash,
		Signature:           "sig-" + hash,
		PayloadCommitment:   "sha256:payload-" + hash,
	}
}

func TestG1_DAGChainIntegrity(t *testing.T) {
	dir := t.TempDir()
	ctx := &conform.RunContext{
		RunID:       "run-1",
		EvidenceDir: dir,
		Clock:       fixedClock,
	}
	receiptsDir := filepath.Join(dir, "02_PROOFGRAPH", "receipts")
	_ = os.MkdirAll(receiptsDir, 0750)

	// Genesis -> r1 -> r2 (linear DAG)
	r1 := makeDAGReceipt(1, "hash-1", []string{"genesis"}, "tenant-1", "env-1")
	r2 := makeDAGReceipt(2, "hash-2", []string{"hash-1"}, "tenant-1", "env-1")

	for i, r := range []ReceiptEnvelope{r1, r2} {
		data, _ := json.MarshalIndent(r, "", "  ")
		_ = os.WriteFile(filepath.Join(receiptsDir, "r"+string(rune('0'+i))+".json"), data, 0600)
	}

	gate := &G1ProofReceipts{}
	result := gate.Run(ctx)
	require.True(t, result.Pass, "valid DAG chain should pass: %v", result.Reasons)
	require.Equal(t, 2, result.Metrics.Counts["receipts_verified"])
}

func TestG1_DAGParallelReceipts(t *testing.T) {
	dir := t.TempDir()
	ctx := &conform.RunContext{
		RunID:       "run-1",
		EvidenceDir: dir,
		Clock:       fixedClock,
	}
	receiptsDir := filepath.Join(dir, "02_PROOFGRAPH", "receipts")
	_ = os.MkdirAll(receiptsDir, 0750)

	// DAG: genesis -> r1, genesis -> r2, r1+r2 -> r3
	r1 := makeDAGReceipt(1, "hash-1", []string{"genesis"}, "tenant-1", "env-1")
	r2 := makeDAGReceipt(2, "hash-2", []string{"genesis"}, "tenant-1", "env-1")
	r3 := makeDAGReceipt(3, "hash-3", []string{"hash-1", "hash-2"}, "tenant-1", "env-1")

	for i, r := range []ReceiptEnvelope{r1, r2, r3} {
		data, _ := json.MarshalIndent(r, "", "  ")
		_ = os.WriteFile(filepath.Join(receiptsDir, fmt.Sprintf("r%d.json", i)), data, 0600)
	}

	gate := &G1ProofReceipts{}
	result := gate.Run(ctx)
	require.True(t, result.Pass, "parallel DAG should pass: %v", result.Reasons)
}

func TestG1_DAGBrokenParent(t *testing.T) {
	dir := t.TempDir()
	ctx := &conform.RunContext{
		RunID:       "run-1",
		EvidenceDir: dir,
		Clock:       fixedClock,
	}
	receiptsDir := filepath.Join(dir, "02_PROOFGRAPH", "receipts")
	_ = os.MkdirAll(receiptsDir, 0750)

	// r1 references nonexistent parent
	r1 := makeDAGReceipt(1, "hash-1", []string{"nonexistent-hash"}, "tenant-1", "env-1")
	data, _ := json.MarshalIndent(r1, "", "  ")
	_ = os.WriteFile(filepath.Join(receiptsDir, "r0.json"), data, 0600)

	gate := &G1ProofReceipts{}
	result := gate.Run(ctx)
	require.False(t, result.Pass, "broken DAG parent should fail")
	require.Contains(t, result.Reasons, conform.ReasonReceiptDAGBroken)
}

func TestG1_MissingTenantID(t *testing.T) {
	dir := t.TempDir()
	ctx := &conform.RunContext{
		RunID:       "run-1",
		EvidenceDir: dir,
		Clock:       fixedClock,
	}
	receiptsDir := filepath.Join(dir, "02_PROOFGRAPH", "receipts")
	_ = os.MkdirAll(receiptsDir, 0750)

	r1 := makeDAGReceipt(1, "hash-1", []string{"genesis"}, "", "env-1") // empty tenant_id
	data, _ := json.MarshalIndent(r1, "", "  ")
	_ = os.WriteFile(filepath.Join(receiptsDir, "r0.json"), data, 0600)

	gate := &G1ProofReceipts{}
	result := gate.Run(ctx)
	require.False(t, result.Pass, "missing tenant_id should fail")
	require.Contains(t, result.Reasons, conform.ReasonTenantIsolationViolation)
}

func TestG1_MissingEnvelopeBinding(t *testing.T) {
	dir := t.TempDir()
	ctx := &conform.RunContext{
		RunID:       "run-1",
		EvidenceDir: dir,
		Clock:       fixedClock,
	}
	receiptsDir := filepath.Join(dir, "02_PROOFGRAPH", "receipts")
	_ = os.MkdirAll(receiptsDir, 0750)

	r1 := makeDAGReceipt(1, "hash-1", []string{"genesis"}, "tenant-1", "") // empty envelope_id
	data, _ := json.MarshalIndent(r1, "", "  ")
	_ = os.WriteFile(filepath.Join(receiptsDir, "r0.json"), data, 0600)

	gate := &G1ProofReceipts{}
	result := gate.Run(ctx)
	require.False(t, result.Pass, "missing envelope binding should fail")
	require.Contains(t, result.Reasons, conform.ReasonEnvelopeNotBound)
}

func TestG1_MeaningfulActionValidation(t *testing.T) {
	dir := t.TempDir()
	ctx := &conform.RunContext{
		RunID:       "run-1",
		EvidenceDir: dir,
		Clock:       fixedClock,
	}
	receiptsDir := filepath.Join(dir, "02_PROOFGRAPH", "receipts")
	_ = os.MkdirAll(receiptsDir, 0750)

	r1 := makeDAGReceipt(1, "hash-1", []string{"genesis"}, "tenant-1", "env-1")
	r1.ActionType = "random_undefined_action"
	data, _ := json.MarshalIndent(r1, "", "  ")
	_ = os.WriteFile(filepath.Join(receiptsDir, "r0.json"), data, 0600)

	gate := &G1ProofReceipts{}
	result := gate.Run(ctx)
	require.False(t, result.Pass, "unknown action type should fail")
}

func TestG1_SignatureValid(t *testing.T) {
	dir := t.TempDir()
	ctx := &conform.RunContext{
		RunID:       "run-1",
		EvidenceDir: dir,
		Clock:       fixedClock,
	}
	receiptsDir := filepath.Join(dir, "02_PROOFGRAPH", "receipts")
	_ = os.MkdirAll(receiptsDir, 0750)

	r1 := makeDAGReceipt(1, "hash-1", []string{"genesis"}, "tenant-1", "env-1")
	data, _ := json.MarshalIndent(r1, "", "  ")
	_ = os.WriteFile(filepath.Join(receiptsDir, "r0.json"), data, 0600)

	gate := &G1ProofReceipts{
		Verifier: func(data []byte, sig string) error { return nil },
	}
	result := gate.Run(ctx)
	require.True(t, result.Pass, "valid signature should pass: %v", result.Reasons)
}

func TestG1_SignatureInvalid(t *testing.T) {
	dir := t.TempDir()
	ctx := &conform.RunContext{
		RunID:       "run-1",
		EvidenceDir: dir,
		Clock:       fixedClock,
	}
	receiptsDir := filepath.Join(dir, "02_PROOFGRAPH", "receipts")
	_ = os.MkdirAll(receiptsDir, 0750)

	r1 := makeDAGReceipt(1, "hash-1", []string{"genesis"}, "tenant-1", "env-1")
	data, _ := json.MarshalIndent(r1, "", "  ")
	_ = os.WriteFile(filepath.Join(receiptsDir, "r0.json"), data, 0600)

	gate := &G1ProofReceipts{
		Verifier: func(data []byte, sig string) error {
			return fmt.Errorf("bad signature")
		},
	}
	result := gate.Run(ctx)
	require.False(t, result.Pass)
	require.Contains(t, result.Reasons, conform.ReasonSignatureInvalid)
}

func TestPayloadCommitment(t *testing.T) {
	salt := []byte("test-salt")
	payload := []byte(`{"action":"deploy"}`)
	commitment := ComputePayloadCommitment(salt, payload)
	require.True(t, VerifyPayloadCommitment(salt, payload, commitment))
	require.False(t, VerifyPayloadCommitment(salt, []byte("tampered"), commitment))
}

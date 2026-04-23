package executor

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/stretchr/testify/require"
)

func TestNewVisualEvidenceVerifier(t *testing.T) {
	verifier := NewVisualEvidenceVerifier(nil)
	require.NotNil(t, verifier)
	require.NotNil(t, verifier.GetMetrics())
}

func TestDefaultVisualEvidenceConfig(t *testing.T) {
	config := DefaultVisualEvidenceConfig()
	require.Equal(t, 10, config.MaxSnapshotsPerPack)
	require.True(t, config.EnableDiffTracking)
	require.True(t, config.VerifyReasoningChain)
	require.Equal(t, 50, config.MaxReasoningSteps)
}

func createTestPack() *contracts.EvidencePack {
	return &contracts.EvidencePack{
		PackID:    "test-pack-1",
		CreatedAt: time.Now(),
		Attestation: contracts.EvidencePackAttestation{
			Signature: "test-signature",
		},
	}
}

func TestCreateVisualEvidence(t *testing.T) {
	verifier := NewVisualEvidenceVerifier(nil)
	pack := createTestPack()

	snapshots := []VisualSnapshot{
		{
			SnapshotID:  "snap-1",
			Timestamp:   time.Now(),
			ContentType: "state",
			ContentHash: computeContentHash(map[string]interface{}{"key": "value1"}),
			Content:     map[string]interface{}{"key": "value1"},
		},
		{
			SnapshotID:  "snap-2",
			Timestamp:   time.Now().Add(time.Second),
			ContentType: "state",
			ContentHash: computeContentHash(map[string]interface{}{"key": "value2"}),
			Content:     map[string]interface{}{"key": "value2"},
		},
	}

	evidence, err := verifier.CreateVisualEvidence(pack, snapshots)
	require.NoError(t, err)
	require.NotNil(t, evidence)
	require.Equal(t, pack.PackID, evidence.Pack.PackID)
	require.Len(t, evidence.Snapshots, 2)
	require.NotEmpty(t, evidence.VisualHash)
}

func TestCreateVisualEvidence_TooManySnapshots(t *testing.T) {
	config := &VisualEvidenceConfig{
		MaxSnapshotsPerPack: 2,
	}
	verifier := NewVisualEvidenceVerifier(config)
	pack := createTestPack()

	snapshots := make([]VisualSnapshot, 5)
	for i := range snapshots {
		snapshots[i] = VisualSnapshot{SnapshotID: "snap-" + string(rune('0'+i))}
	}

	_, err := verifier.CreateVisualEvidence(pack, snapshots)
	require.Error(t, err)
	require.Contains(t, err.Error(), "too many snapshots")
}

func TestCreateVisualEvidence_DiffTracking(t *testing.T) {
	config := DefaultVisualEvidenceConfig()
	config.EnableDiffTracking = true
	verifier := NewVisualEvidenceVerifier(config)
	pack := createTestPack()

	snapshots := []VisualSnapshot{
		{
			SnapshotID:  "snap-1",
			Timestamp:   time.Now(),
			ContentHash: computeContentHash(map[string]interface{}{"key": "value1"}),
			Content:     map[string]interface{}{"key": "value1"},
		},
		{
			SnapshotID:  "snap-2",
			Timestamp:   time.Now().Add(time.Second),
			ContentHash: computeContentHash(map[string]interface{}{"key": "value2", "new": "field"}),
			Content:     map[string]interface{}{"key": "value2", "new": "field"},
		},
	}

	evidence, err := verifier.CreateVisualEvidence(pack, snapshots)
	require.NoError(t, err)

	// Second snapshot should have diff
	require.Nil(t, evidence.Snapshots[0].DiffFromPrev)
	require.NotNil(t, evidence.Snapshots[1].DiffFromPrev)
	require.Equal(t, "snap-1", evidence.Snapshots[1].DiffFromPrev.PreviousSnapshotID)
}

func TestAttachReasoningChain(t *testing.T) {
	verifier := NewVisualEvidenceVerifier(nil)
	pack := createTestPack()

	snapshots := []VisualSnapshot{
		{SnapshotID: "snap-1", Timestamp: time.Now()},
		{SnapshotID: "snap-2", Timestamp: time.Now().Add(time.Second)},
	}

	evidence, _ := verifier.CreateVisualEvidence(pack, snapshots)

	steps := []ReasoningStep{
		{
			StepID:         "step-1",
			Action:         "analyze",
			Rationale:      "reviewing input data",
			SnapshotBefore: "snap-1",
			Timestamp:      time.Now(),
		},
		{
			StepID:        "step-2",
			Action:        "decide",
			Rationale:     "making decision based on analysis",
			SnapshotAfter: "snap-2",
			Timestamp:     time.Now().Add(time.Second),
		},
	}

	chain, err := verifier.AttachReasoningChain(evidence, steps)
	require.NoError(t, err)
	require.NotNil(t, chain)
	require.Equal(t, pack.PackID, chain.PackID)
	require.Len(t, chain.Steps, 2)
	require.Equal(t, "decide", chain.FinalOutcome)
	require.NotEmpty(t, chain.ChainHash)
}

func TestVerify_Success(t *testing.T) {
	verifier := NewVisualEvidenceVerifier(nil)
	pack := createTestPack()

	content1 := map[string]interface{}{"key": "value1"}
	content2 := map[string]interface{}{"key": "value2"}

	snapshots := []VisualSnapshot{
		{
			SnapshotID:  "snap-1",
			Timestamp:   time.Now(),
			ContentHash: computeContentHash(content1),
			Content:     content1,
		},
		{
			SnapshotID:  "snap-2",
			Timestamp:   time.Now().Add(time.Second),
			ContentHash: computeContentHash(content2),
			Content:     content2,
		},
	}

	evidence, _ := verifier.CreateVisualEvidence(pack, snapshots)

	result, err := verifier.Verify(context.Background(), evidence)
	require.NoError(t, err)
	require.True(t, result.Verified)
	require.Contains(t, result.ChecksPassed, "visual_hash_integrity")
	require.Contains(t, result.ChecksPassed, "snapshot_sequence")
	require.Empty(t, result.ChecksFailed)
}

func TestVerify_HashMismatch(t *testing.T) {
	verifier := NewVisualEvidenceVerifier(nil)
	pack := createTestPack()

	snapshots := []VisualSnapshot{
		{SnapshotID: "snap-1", Timestamp: time.Now()},
	}

	evidence, _ := verifier.CreateVisualEvidence(pack, snapshots)

	// Tamper with hash
	evidence.VisualHash = "tampered-hash"

	result, err := verifier.Verify(context.Background(), evidence)
	require.NoError(t, err)
	require.False(t, result.Verified)
	require.Len(t, result.ChecksFailed, 1)
	require.Equal(t, "hash_mismatch", result.ChecksFailed[0].Type)
}

func TestVerify_WithReasoningChain(t *testing.T) {
	verifier := NewVisualEvidenceVerifier(nil)
	pack := createTestPack()

	snapshots := []VisualSnapshot{
		{SnapshotID: "snap-1", Timestamp: time.Now()},
		{SnapshotID: "snap-2", Timestamp: time.Now().Add(time.Second)},
	}

	evidence, _ := verifier.CreateVisualEvidence(pack, snapshots)

	steps := []ReasoningStep{
		{
			StepID:         "step-1",
			Action:         "analyze",
			SnapshotBefore: "snap-1",
			Timestamp:      time.Now(),
		},
	}

	_, _ = verifier.AttachReasoningChain(evidence, steps)

	// Re-compute visual hash after attaching chain
	evidence.VisualHash = computeVisualHash(evidence)

	result, err := verifier.Verify(context.Background(), evidence)
	require.NoError(t, err)
	require.True(t, result.Verified)
	require.True(t, result.CausalIntegrity)
	require.Contains(t, result.ChecksPassed, "reasoning_chain")
}

func TestVerify_InvalidReasoningChainReference(t *testing.T) {
	verifier := NewVisualEvidenceVerifier(nil)
	pack := createTestPack()

	snapshots := []VisualSnapshot{
		{SnapshotID: "snap-1", Timestamp: time.Now()},
	}

	evidence, _ := verifier.CreateVisualEvidence(pack, snapshots)

	// Reference non-existent snapshot
	steps := []ReasoningStep{
		{
			StepID:         "step-1",
			Action:         "analyze",
			SnapshotBefore: "non-existent-snap",
			Timestamp:      time.Now(),
		},
	}

	_, _ = verifier.AttachReasoningChain(evidence, steps)
	evidence.VisualHash = computeVisualHash(evidence)

	result, err := verifier.Verify(context.Background(), evidence)
	require.NoError(t, err)
	// Should have warning for broken chain
	hasChainError := false
	for _, e := range result.ChecksFailed {
		if e.CheckID == "reasoning_chain" {
			hasChainError = true
			break
		}
	}
	require.True(t, hasChainError)
}

func TestMetrics(t *testing.T) {
	verifier := NewVisualEvidenceVerifier(nil)
	pack := createTestPack()

	snapshots := []VisualSnapshot{
		{SnapshotID: "snap-1", Timestamp: time.Now()},
		{SnapshotID: "snap-2", Timestamp: time.Now().Add(time.Second)},
	}

	evidence, _ := verifier.CreateVisualEvidence(pack, snapshots)

	_, _ = verifier.Verify(context.Background(), evidence)
	_, _ = verifier.Verify(context.Background(), evidence)

	metrics := verifier.GetMetrics()
	require.Equal(t, 2, metrics.TotalVerifications)
	require.Equal(t, 4, metrics.TotalSnapshotsProcessed)
	require.Equal(t, 2.0, metrics.AvgSnapshotsPerPack)
}

func TestEncodeDecodeScreenshot(t *testing.T) {
	original := []byte("test screenshot data")
	encoded := EncodeScreenshot(original)
	require.NotEmpty(t, encoded)

	decoded, err := DecodeScreenshot(encoded)
	require.NoError(t, err)
	require.Equal(t, original, decoded)
}

func TestFlattenPaths(t *testing.T) {
	m := map[string]interface{}{
		"a": "value1",
		"b": map[string]interface{}{
			"c": "value2",
			"d": map[string]interface{}{
				"e": "value3",
			},
		},
	}

	result := flattenPaths(m, "")
	require.Equal(t, "value1", result["a"])
	require.Equal(t, "value2", result["b.c"])
	require.Equal(t, "value3", result["b.d.e"])
}

func TestComputeSnapshotDiff(t *testing.T) {
	prev := &VisualSnapshot{
		SnapshotID: "prev",
		Content: map[string]interface{}{
			"existing": "value1",
			"removed":  "old",
		},
	}

	curr := &VisualSnapshot{
		SnapshotID: "curr",
		Content: map[string]interface{}{
			"existing": "value2", // modified
			"added":    "new",
		},
	}

	diff := computeSnapshotDiff(prev, curr)
	require.Equal(t, "prev", diff.PreviousSnapshotID)
	require.Contains(t, diff.AddedPaths, "added")
	require.Contains(t, diff.RemovedPaths, "removed")
	require.Contains(t, diff.ModifiedPaths, "existing")
	require.NotEmpty(t, diff.DiffHash)
}

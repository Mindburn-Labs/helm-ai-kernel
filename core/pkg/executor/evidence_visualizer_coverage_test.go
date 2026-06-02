package executor

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCreateVisualEvidenceAndReasoningErrors(t *testing.T) {
	verifier := NewVisualEvidenceVerifier(&VisualEvidenceConfig{
		MaxSnapshotsPerPack:  2,
		MaxReasoningSteps:    1,
		EnableDiffTracking:   true,
		VerifyReasoningChain: true,
	})

	_, err := verifier.CreateVisualEvidence(nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "evidence pack is required")

	evidence, err := verifier.CreateVisualEvidence(createTestPack(), nil)
	require.NoError(t, err)
	_, err = verifier.AttachReasoningChain(evidence, []ReasoningStep{
		{StepID: "step-1", Timestamp: time.Now()},
		{StepID: "step-2", Timestamp: time.Now().Add(time.Second)},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "too many reasoning steps")
}

func TestVisualEvidenceVerifyFailureBranches(t *testing.T) {
	verifier := NewVisualEvidenceVerifier(DefaultVisualEvidenceConfig())
	pack := createTestPack()
	now := time.Now()
	content := map[string]interface{}{"key": "value"}

	evidence := &VisualEvidence{
		Pack: pack,
		Snapshots: []VisualSnapshot{
			{
				SnapshotID:  "snap-1",
				SequenceNum: 2,
				Timestamp:   now,
				Content:     content,
				ContentHash: "wrong",
			},
			{
				SnapshotID:   "snap-2",
				SequenceNum:  3,
				Timestamp:    now.Add(time.Second),
				Content:      map[string]interface{}{"key": "value2"},
				ContentHash:  computeContentHash(map[string]interface{}{"key": "value2"}),
				DiffFromPrev: &SnapshotDiff{PreviousSnapshotID: "not-snap-1"},
			},
		},
		CreatedAt: now,
	}
	evidence.VisualHash = computeVisualHash(evidence)

	result, err := verifier.Verify(context.Background(), evidence)
	require.NoError(t, err)
	require.False(t, result.Verified)
	require.Contains(t, failureCheckIDs(result), "snapshot_sequence")
	require.Contains(t, failureCheckIDs(result), "snapshot_content_hashes")
	require.Contains(t, failureCheckIDs(result), "diff_chain")
}

func TestVisualEvidenceReasoningVerifierBranches(t *testing.T) {
	verifier := NewVisualEvidenceVerifier(nil)
	snapshots := []VisualSnapshot{{SnapshotID: "snap-1"}}

	require.True(t, verifier.verifyReasoningChain(&ReasoningChain{}, snapshots))

	require.False(t, verifier.verifyReasoningChain(&ReasoningChain{
		Steps: []ReasoningStep{{StepID: "after-missing", SequenceNum: 1, SnapshotAfter: "missing"}},
	}, snapshots))

	require.False(t, verifier.verifyReasoningChain(&ReasoningChain{
		Steps: []ReasoningStep{{StepID: "bad-sequence", SequenceNum: 2}},
	}, snapshots))

	chain := &ReasoningChain{
		ChainID: "chain-1",
		PackID:  "pack-1",
		Steps:   []ReasoningStep{{StepID: "step-1", SequenceNum: 1}},
	}
	chain.ChainHash = "wrong"
	require.False(t, verifier.verifyReasoningChain(chain, snapshots))
}

func TestVisualEvidenceHelperEdges(t *testing.T) {
	verifier := NewVisualEvidenceVerifier(nil)
	require.True(t, verifier.verifyDiffChain([]VisualSnapshot{
		{SnapshotID: "snap-1"},
		{SnapshotID: "snap-2"},
	}))

	diff := computeSnapshotDiff(&VisualSnapshot{SnapshotID: "prev"}, &VisualSnapshot{SnapshotID: "curr"})
	require.Equal(t, "prev", diff.PreviousSnapshotID)
	require.NotEmpty(t, diff.DiffHash)

	require.Equal(t, "marshal-error", computeVisualHash(&VisualEvidence{
		Pack:      createTestPack(),
		Snapshots: []VisualSnapshot{{Content: map[string]interface{}{"bad": math.Inf(1)}}},
	}))
	require.Equal(t, "marshal-error", computeContentHash(map[string]interface{}{"bad": math.Inf(1)}))
}

func failureCheckIDs(result *VerificationResult) []string {
	ids := make([]string, 0, len(result.ChecksFailed))
	for _, failure := range result.ChecksFailed {
		ids = append(ids, failure.CheckID)
	}
	return ids
}

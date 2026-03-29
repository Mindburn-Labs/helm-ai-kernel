package evidence_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/evidence"
)

func TestSeal_ProducesVerifiableReceipt(t *testing.T) {
	pack, receipt, err := evidence.Seal(context.Background(), evidence.SealInput{
		MissionID: "m1",
		Sources: []researchruntime.SourceSnapshot{
			{
				SourceID:         "s1",
				ContentHash:      "abc",
				ProvenanceStatus: researchruntime.ProvenanceVerified,
				CapturedAt:       time.Now(),
			},
		},
		Models: []researchruntime.ModelManifest{
			{
				Stage:         "synthesis",
				RequestedModel: "claude-3-5-sonnet",
				ActualModel:   "claude-3-5-sonnet",
				InvokedAt:     time.Now(),
			},
		},
		ArtifactHash:     "draft-hash-xyz",
		PolicyBundleHash: "policy-hash-abc",
		Score:            0.85,
	})

	require.NoError(t, err)
	assert.NotEmpty(t, pack.PackID)
	assert.Equal(t, "m1", pack.MissionID)
	assert.NotEmpty(t, pack.TraceHash)
	assert.NotEmpty(t, receipt.ReceiptID)
	assert.Equal(t, "m1", receipt.MissionID)
	assert.NotEmpty(t, receipt.ManifestHash)
	assert.NotEmpty(t, receipt.EvidencePackHash)

	// Verify receipt integrity — ManifestHash must survive round-trip.
	err = researchruntime.VerifyPromotionReceipt(*receipt)
	require.NoError(t, err)
}

func TestSeal_EmptySources(t *testing.T) {
	pack, receipt, err := evidence.Seal(context.Background(), evidence.SealInput{
		MissionID:        "m2",
		PolicyBundleHash: "p1",
	})

	require.NoError(t, err)
	assert.NotEmpty(t, pack.PackID)
	assert.Equal(t, "m2", pack.MissionID)
	assert.NotEmpty(t, receipt.ReceiptID)
	assert.NotEmpty(t, receipt.ManifestHash)

	err = researchruntime.VerifyPromotionReceipt(*receipt)
	require.NoError(t, err)
}

func TestSeal_MultipleModels(t *testing.T) {
	pack, receipt, err := evidence.Seal(context.Background(), evidence.SealInput{
		MissionID: "m3",
		Models: []researchruntime.ModelManifest{
			{Stage: "planner", RequestedModel: "claude-3-haiku", ActualModel: "claude-3-haiku", InvokedAt: time.Now()},
			{Stage: "editor", RequestedModel: "claude-3-5-sonnet", ActualModel: "claude-3-5-sonnet", InvokedAt: time.Now()},
			// model with empty stage — falls back to index-based path
			{RequestedModel: "gpt-4o", ActualModel: "gpt-4o", InvokedAt: time.Now()},
		},
		PolicyBundleHash: "p2",
	})

	require.NoError(t, err)
	assert.NotEmpty(t, pack.PackID)
	assert.Len(t, pack.ModelManifest, 3)

	err = researchruntime.VerifyPromotionReceipt(*receipt)
	require.NoError(t, err)
}

func TestSeal_ToolManifests(t *testing.T) {
	pack, receipt, err := evidence.Seal(context.Background(), evidence.SealInput{
		MissionID: "m4",
		Tools: []researchruntime.ToolInvocationManifest{
			{
				InvocationID: "inv-1",
				Stage:        "web-scout",
				ToolName:     "web_search",
				InputHash:    "ihash1",
				OutputHash:   "ohash1",
				Outcome:      "success",
				InvokedAt:    time.Now(),
			},
		},
		PolicyBundleHash: "p3",
	})

	require.NoError(t, err)
	assert.NotEmpty(t, pack.PackID)
	assert.Len(t, pack.ToolManifest, 1)

	err = researchruntime.VerifyPromotionReceipt(*receipt)
	require.NoError(t, err)
}

func TestSeal_DifferentCallsProduceDifferentIDs(t *testing.T) {
	input := evidence.SealInput{
		MissionID:        "m5",
		PolicyBundleHash: "p4",
	}

	_, r1, err := evidence.Seal(context.Background(), input)
	require.NoError(t, err)

	_, r2, err := evidence.Seal(context.Background(), input)
	require.NoError(t, err)

	// Each call mints a fresh receipt UUID.
	assert.NotEqual(t, r1.ReceiptID, r2.ReceiptID)
}

package aigp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testAIGPParentHash = strings.Repeat("1", 64)
	testAIGPReplayHash = "sha256:" + strings.Repeat("2", 64)
)

func TestExporter_FourTestsFailClosedWithoutNodeEvidence(t *testing.T) {
	exporter := NewExporter(ExporterConfig{
		DefaultFourTests: FourTestsCompliance{
			Stoppable:   true,
			Owned:       true,
			Replayable:  true,
			Escalatable: true,
		},
	})
	node := proofgraph.NewNode(
		proofgraph.NodeTypeAttestation,
		nil,
		[]byte(`{"decision":"ALLOW"}`),
		1,
		"",
		0,
	)

	pcd, err := exporter.ExportNode(node)
	require.NoError(t, err)

	assert.False(t, pcd.FourTests.Stoppable)
	assert.False(t, pcd.FourTests.Owned)
	assert.False(t, pcd.FourTests.Replayable)
	assert.False(t, pcd.FourTests.Escalatable)
	assert.Empty(t, pcd.FourTests.OwnerPrincipal)
}

func TestExporter_FourTestsDerivedFromExplicitEvidence(t *testing.T) {
	exporter := NewExporter(ExporterConfig{})
	node := newAIGPCompliantNode(t, proofgraph.NodeTypeAttestation, map[string]string{"tool": "read_file"}, 1, "agent-001", 1)

	pcd, err := exporter.ExportNode(node)
	require.NoError(t, err)

	assert.True(t, pcd.FourTests.Stoppable)
	assert.True(t, pcd.FourTests.Owned)
	assert.True(t, pcd.FourTests.Replayable)
	assert.True(t, pcd.FourTests.Escalatable)
	assert.Equal(t, "agent-001", pcd.FourTests.OwnerPrincipal)
}

func TestExporter_BundleSummaryFailsClosedOnMixedNodeEvidence(t *testing.T) {
	ctx := context.Background()
	store := proofgraph.NewInMemoryStore()
	require.NoError(t, store.StoreNode(ctx, newAIGPCompliantNode(t, proofgraph.NodeTypeAttestation, nil, 1, "agent-001", 1)))
	require.NoError(t, store.StoreNode(ctx, proofgraph.NewNode(proofgraph.NodeTypeEffect, nil, []byte(`{"decision":"ALLOW"}`), 2, "", 0)))

	bundle, err := NewExporter(ExporterConfig{}).ExportBundle(ctx, store, 1, 2)
	require.NoError(t, err)

	assert.Equal(t, 2, bundle.Count)
	assert.False(t, bundle.FourTestsSummary.Stoppable)
	assert.False(t, bundle.FourTestsSummary.Owned)
	assert.False(t, bundle.FourTestsSummary.Replayable)
	assert.False(t, bundle.FourTestsSummary.Escalatable)
}

func newAIGPCompliantNode(t *testing.T, kind proofgraph.NodeType, payload map[string]string, lamport uint64, principal string, seq uint64) *proofgraph.Node {
	t.Helper()

	fields := map[string]string{
		"decision":       "ALLOW",
		"stop_ref":       "guardian:kill-switch",
		"replay_hash":    testAIGPReplayHash,
		"escalation_ref": "approval:human-operator",
	}
	for k, v := range payload {
		fields[k] = v
	}

	payloadBytes, err := json.Marshal(fields)
	require.NoError(t, err)

	node := proofgraph.NewNode(kind, []string{testAIGPParentHash}, payloadBytes, lamport, principal, seq)
	require.NoError(t, node.SetSignature("sig-"+strings.Repeat("a", 16), proofgraph.SignaturePurposeAuthor))
	return node
}

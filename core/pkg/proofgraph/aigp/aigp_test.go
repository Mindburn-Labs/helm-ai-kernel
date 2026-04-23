package aigp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExportNode(t *testing.T) {
	exporter := NewExporter(ExporterConfig{
		Source:            "test-helm-instance",
		ProofGraphVersion: "v1.2",
	})

	payload := map[string]string{
		"tool":     "web_search",
		"decision": "ALLOW",
		"policy":   "default-allow",
	}
	payloadBytes, _ := json.Marshal(payload)

	node := proofgraph.NewNode(
		proofgraph.NodeTypeAttestation,
		[]string{"parent1"},
		payloadBytes,
		42,
		"agent-001",
		1,
	)

	pcd, err := exporter.ExportNode(node)
	require.NoError(t, err)

	// Verify PCD structure.
	assert.Equal(t, PCDVersion, pcd.Version)
	assert.Equal(t, "pcd:"+node.NodeHash, pcd.ID)
	assert.Equal(t, ActionToolExecution, pcd.Action.Type)
	assert.Equal(t, "agent-001", pcd.Action.Principal)
	assert.Equal(t, "ALLOW", pcd.Action.Decision)
	assert.Equal(t, "web_search", pcd.Action.Tool)
	assert.Equal(t, "default-allow", pcd.Action.PolicyRef)

	// Verify crypto evidence.
	assert.Equal(t, node.NodeHash, pcd.Evidence.NodeHash)
	assert.Equal(t, node.NodeHash, pcd.Evidence.GovernanceHash)
	assert.Equal(t, []string{"parent1"}, pcd.Evidence.ParentHashes)
	assert.Equal(t, "SHA-256", pcd.Evidence.HashAlgorithm)
	assert.Equal(t, uint64(42), pcd.Evidence.LamportClock)

	// Verify provenance.
	assert.Equal(t, "test-helm-instance", pcd.Provenance.Source)
	assert.Equal(t, "v1.2", pcd.Provenance.ProofGraphVersion)
	assert.Equal(t, node.NodeHash, pcd.Provenance.NodeID)

	// Verify 4TS compliance (HELM satisfies all four).
	assert.True(t, pcd.FourTests.Stoppable)
	assert.True(t, pcd.FourTests.Owned)
	assert.True(t, pcd.FourTests.Replayable)
	assert.True(t, pcd.FourTests.Escalatable)
	assert.Equal(t, "agent-001", pcd.FourTests.OwnerPrincipal)

	// Verify hash is populated.
	assert.NotEmpty(t, pcd.PCDHash)
	assert.Len(t, pcd.PCDHash, 64, "SHA-256 hex is 64 chars")
}

func TestExportNode_NilNode(t *testing.T) {
	exporter := NewExporter(ExporterConfig{})
	_, err := exporter.ExportNode(nil)
	assert.Error(t, err)
}

func TestExportNode_AllNodeTypes(t *testing.T) {
	exporter := NewExporter(ExporterConfig{})

	tests := []struct {
		kind     proofgraph.NodeType
		expected GovernanceActionType
	}{
		{proofgraph.NodeTypeIntent, ActionPolicyEval},
		{proofgraph.NodeTypeAttestation, ActionToolExecution},
		{proofgraph.NodeTypeEffect, ActionToolExecution},
		{proofgraph.NodeTypeTrustEvent, ActionTrustEvent},
		{proofgraph.NodeTypeCheckpoint, ActionCheckpoint},
		{proofgraph.NodeTypeMergeDecision, ActionPolicyEval},
	}

	for _, tt := range tests {
		t.Run(string(tt.kind), func(t *testing.T) {
			node := proofgraph.NewNode(tt.kind, nil, []byte("{}"), 1, "test", 0)
			pcd, err := exporter.ExportNode(node)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, pcd.Action.Type)
		})
	}
}

func TestPCDHash_Deterministic(t *testing.T) {
	pcd := &ProofCarryingDecision{
		Version:   PCDVersion,
		ID:        "pcd:test",
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Action: GovernanceAction{
			Type:      ActionToolExecution,
			Principal: "agent-1",
			Decision:  "ALLOW",
		},
		Evidence: CryptographicEvidence{
			GovernanceHash: "abc123",
			NodeHash:       "abc123",
			HashAlgorithm:  "SHA-256",
			LamportClock:   1,
		},
		Provenance: PCDProvenance{
			Source:            "test",
			ProofGraphVersion: "v1.2",
			NodeID:            "abc123",
			ExportTimestamp:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	h1 := pcd.ComputePCDHash()
	h2 := pcd.ComputePCDHash()
	assert.Equal(t, h1, h2, "PCD hash should be deterministic")
	assert.Len(t, h1, 64)
}

func TestExportRange(t *testing.T) {
	store := proofgraph.NewInMemoryStore()
	ctx := context.Background()

	// Populate the graph with nodes.
	graph := store.Graph()
	for i := 0; i < 5; i++ {
		payload, _ := json.Marshal(map[string]string{
			"tool":     "test_tool",
			"decision": "ALLOW",
		})
		_, err := graph.Append(proofgraph.NodeTypeAttestation, payload, "agent-1", uint64(i))
		require.NoError(t, err)
	}

	exporter := NewExporter(ExporterConfig{Source: "test"})

	pcds, err := exporter.ExportRange(ctx, store, 1, 5)
	require.NoError(t, err)
	assert.Len(t, pcds, 5)

	for _, pcd := range pcds {
		assert.Equal(t, PCDVersion, pcd.Version)
		assert.True(t, pcd.FourTests.Stoppable)
	}
}

func TestExportBundle(t *testing.T) {
	store := proofgraph.NewInMemoryStore()
	ctx := context.Background()

	graph := store.Graph()
	for i := 0; i < 3; i++ {
		payload, _ := json.Marshal(map[string]string{"decision": "ALLOW"})
		_, err := graph.Append(proofgraph.NodeTypeAttestation, payload, "agent-1", uint64(i))
		require.NoError(t, err)
	}

	exporter := NewExporter(ExporterConfig{Source: "test-instance"})

	bundle, err := exporter.ExportBundle(ctx, store, 1, 3)
	require.NoError(t, err)
	assert.Equal(t, PCDVersion, bundle.Version)
	assert.Equal(t, "test-instance", bundle.Source)
	assert.Equal(t, 3, bundle.Count)
	assert.Len(t, bundle.PCDs, 3)
	assert.True(t, bundle.FourTestsSummary.Stoppable)
	assert.True(t, bundle.FourTestsSummary.Owned)
	assert.True(t, bundle.FourTestsSummary.Replayable)
	assert.True(t, bundle.FourTestsSummary.Escalatable)

	// Verify JSON serialization round-trip.
	data, err := json.Marshal(bundle)
	require.NoError(t, err)
	assert.Contains(t, string(data), "aigp-pcd-v1")

	var decoded PCDBundle
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, bundle.Count, decoded.Count)
}

func TestNodeTypeMapping(t *testing.T) {
	assert.Equal(t, ActionPolicyEval, nodeTypeToAction(proofgraph.NodeTypeIntent))
	assert.Equal(t, ActionToolExecution, nodeTypeToAction(proofgraph.NodeTypeAttestation))
	assert.Equal(t, ActionToolExecution, nodeTypeToAction(proofgraph.NodeTypeEffect))
	assert.Equal(t, ActionTrustEvent, nodeTypeToAction(proofgraph.NodeTypeTrustEvent))
	assert.Equal(t, ActionCheckpoint, nodeTypeToAction(proofgraph.NodeTypeCheckpoint))
	assert.Equal(t, ActionPolicyEval, nodeTypeToAction(proofgraph.NodeTypeMergeDecision))
	assert.Equal(t, ActionToolExecution, nodeTypeToAction("unknown"))
}

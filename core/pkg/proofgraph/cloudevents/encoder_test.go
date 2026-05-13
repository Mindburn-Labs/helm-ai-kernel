package cloudevents

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixedClock returns a clock function that always returns the given time.
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// testNode creates a node for testing with the given kind and payload.
func testNode(kind proofgraph.NodeType, payload []byte, parents []string) *proofgraph.Node {
	frozen := time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)
	return proofgraph.NewNode(kind, parents, payload, 42, "agent-007", 5, fixedClock(frozen))
}

func TestEncode_SingleNode_Intent(t *testing.T) {
	payload, _ := json.Marshal(map[string]string{"action": "web_search", "target": "https://example.com"})
	node := testNode(proofgraph.NodeTypeIntent, payload, []string{"parent-abc"})

	enc := New(WithClock(fixedClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))))
	ce, err := enc.Encode(node)
	require.NoError(t, err)

	// Required CloudEvents attributes (section 2).
	assert.Equal(t, "1.0", ce.SpecVersion)
	assert.Equal(t, node.NodeHash, ce.ID)
	assert.Equal(t, "helm://proofgraph", ce.Source)
	assert.Equal(t, "helm.proofgraph.intent", ce.Type)

	// Optional attributes.
	assert.NotEmpty(t, ce.Time)
	assert.Equal(t, "application/json", ce.DataContentType)
	assert.Equal(t, "agent-007", ce.Subject)

	// HELM extension attributes.
	assert.Equal(t, node.NodeHash, ce.HelmNodeHash)
	assert.Equal(t, uint64(42), ce.HelmLamport)
	assert.Equal(t, uint64(5), ce.HelmPrincipalSeq)
	assert.Equal(t, "parent-abc", ce.HelmParents)

	// Data should be the payload.
	assert.JSONEq(t, string(payload), string(ce.Data))
}

func TestEncode_SingleNode_Attestation(t *testing.T) {
	payload, _ := json.Marshal(map[string]string{"decision": "ALLOW", "tool": "file_read"})
	node := testNode(proofgraph.NodeTypeAttestation, payload, nil)

	enc := New()
	ce, err := enc.Encode(node)
	require.NoError(t, err)

	assert.Equal(t, "helm.proofgraph.attestation", ce.Type)
	assert.Equal(t, "application/json", ce.DataContentType)
	assert.Empty(t, ce.HelmParents)
}

func TestEncode_SingleNode_Effect(t *testing.T) {
	payload, _ := json.Marshal(map[string]string{"effect": "file_write", "path": "/tmp/out.txt"})
	node := testNode(proofgraph.NodeTypeEffect, payload, []string{"p1", "p2", "p3"})

	enc := New()
	ce, err := enc.Encode(node)
	require.NoError(t, err)

	assert.Equal(t, "helm.proofgraph.effect", ce.Type)
	assert.Equal(t, "p1,p2,p3", ce.HelmParents)
}

func TestEncode_AllMajorNodeTypes(t *testing.T) {
	tests := []struct {
		kind         proofgraph.NodeType
		expectedType string
	}{
		{proofgraph.NodeTypeIntent, "helm.proofgraph.intent"},
		{proofgraph.NodeTypeAttestation, "helm.proofgraph.attestation"},
		{proofgraph.NodeTypeEffect, "helm.proofgraph.effect"},
		{proofgraph.NodeTypeTrustEvent, "helm.proofgraph.trust_event"},
		{proofgraph.NodeTypeCheckpoint, "helm.proofgraph.checkpoint"},
		{proofgraph.NodeTypeMergeDecision, "helm.proofgraph.merge_decision"},
		{proofgraph.NodeTypeTrustScore, "helm.proofgraph.trust_score"},
		{proofgraph.NodeTypeAgentKill, "helm.proofgraph.agent_kill"},
		{proofgraph.NodeTypeAgentRevive, "helm.proofgraph.agent_revive"},
		{proofgraph.NodeTypeSagaStart, "helm.proofgraph.saga_start"},
		{proofgraph.NodeTypeSagaCompensate, "helm.proofgraph.saga_compensate"},
		{proofgraph.NodeTypeVouch, "helm.proofgraph.vouch"},
		{proofgraph.NodeTypeSlash, "helm.proofgraph.slash"},
		{proofgraph.NodeTypeFederation, "helm.proofgraph.federation"},
		{proofgraph.NodeTypeHWAttestation, "helm.proofgraph.hw_attestation"},
		{proofgraph.NodeTypeZKProof, "helm.proofgraph.zk_proof"},
		{proofgraph.NodeTypeDecentralizedProof, "helm.proofgraph.decentralized_proof"},
	}

	enc := New()
	for _, tt := range tests {
		t.Run(string(tt.kind), func(t *testing.T) {
			node := testNode(tt.kind, []byte(`{"test":true}`), nil)
			ce, err := enc.Encode(node)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedType, ce.Type)
			assert.Equal(t, "1.0", ce.SpecVersion)
			assert.NotEmpty(t, ce.ID)
			assert.NotEmpty(t, ce.Source)
		})
	}
}

func TestEncode_RequiredAttributesAlwaysPresent(t *testing.T) {
	node := testNode(proofgraph.NodeTypeIntent, []byte(`{}`), nil)

	enc := New()
	ce, err := enc.Encode(node)
	require.NoError(t, err)

	// CloudEvents v1.0 section 2: specversion, id, source, type are REQUIRED.
	assert.NotEmpty(t, ce.SpecVersion, "specversion is required")
	assert.NotEmpty(t, ce.ID, "id is required")
	assert.NotEmpty(t, ce.Source, "source is required")
	assert.NotEmpty(t, ce.Type, "type is required")
}

func TestEncode_HELMExtensionAttributes(t *testing.T) {
	payload, _ := json.Marshal(map[string]string{"key": "value"})
	node := testNode(proofgraph.NodeTypeAttestation, payload, []string{"parent-1", "parent-2"})
	node.Sig = "sig-abc123"

	// Recompute hash after signature change.
	node.NodeHash = node.ComputeNodeHash()

	enc := New()
	ce, err := enc.Encode(node)
	require.NoError(t, err)

	assert.Equal(t, node.NodeHash, ce.HelmNodeHash)
	assert.Equal(t, uint64(42), ce.HelmLamport)
	assert.Equal(t, uint64(5), ce.HelmPrincipalSeq)
	assert.Equal(t, "sig-abc123", ce.HelmSignature)
	assert.Equal(t, "parent-1,parent-2", ce.HelmParents)
}

func TestEncode_CustomSource(t *testing.T) {
	node := testNode(proofgraph.NodeTypeIntent, []byte(`{}`), nil)

	enc := New(WithSource("helm://prod/us-east-1/cluster-42"))
	ce, err := enc.Encode(node)
	require.NoError(t, err)

	assert.Equal(t, "helm://prod/us-east-1/cluster-42", ce.Source)
}

func TestEncode_DeterministicWithInjectedClock(t *testing.T) {
	frozen := time.Date(2026, 4, 13, 10, 30, 0, 0, time.UTC)
	payload, _ := json.Marshal(map[string]string{"action": "test"})
	node := testNode(proofgraph.NodeTypeIntent, payload, nil)

	enc := New(WithClock(fixedClock(frozen)))

	ce1, err := enc.Encode(node)
	require.NoError(t, err)
	ce2, err := enc.Encode(node)
	require.NoError(t, err)

	// Same node with same encoder should produce identical events.
	assert.Equal(t, ce1.ID, ce2.ID)
	assert.Equal(t, ce1.Type, ce2.Type)
	assert.Equal(t, ce1.Source, ce2.Source)
	assert.Equal(t, ce1.Time, ce2.Time)
	assert.Equal(t, ce1.HelmLamport, ce2.HelmLamport)

	// Marshal both and compare.
	b1, _ := json.Marshal(ce1)
	b2, _ := json.Marshal(ce2)
	assert.Equal(t, string(b1), string(b2))
}

func TestEncode_TimeFallbackToClock(t *testing.T) {
	frozen := time.Date(2026, 6, 15, 8, 0, 0, 0, time.UTC)

	// Create a node with zero timestamp.
	node := &proofgraph.Node{
		NodeHash:     "deadbeef",
		Kind:         proofgraph.NodeTypeCheckpoint,
		Parents:      nil,
		Lamport:      1,
		Principal:    "system",
		PrincipalSeq: 0,
		Payload:      json.RawMessage(`{}`),
		Timestamp:    0, // No timestamp.
	}

	enc := New(WithClock(fixedClock(frozen)))
	ce, err := enc.Encode(node)
	require.NoError(t, err)

	// Time should come from the clock, not the node.
	expectedTime := frozen.UTC().Format(time.RFC3339Nano)
	assert.Equal(t, expectedTime, ce.Time)
}

func TestEncode_EmptyPayload(t *testing.T) {
	node := testNode(proofgraph.NodeTypeCheckpoint, nil, nil)

	enc := New()
	ce, err := enc.Encode(node)
	require.NoError(t, err)

	// Empty payload should become empty JSON object.
	assert.JSONEq(t, `{}`, string(ce.Data))
}

func TestEncode_NilNode(t *testing.T) {
	enc := New()
	ce, err := enc.Encode(nil)
	assert.Nil(t, ce)
	assert.ErrorIs(t, err, ErrNilNode)
}

func TestEncodeBatch(t *testing.T) {
	enc := New()
	payload, _ := json.Marshal(map[string]string{"batch": "true"})

	nodes := []*proofgraph.Node{
		testNode(proofgraph.NodeTypeIntent, payload, nil),
		testNode(proofgraph.NodeTypeAttestation, payload, nil),
		testNode(proofgraph.NodeTypeEffect, payload, nil),
	}

	events, err := enc.EncodeBatch(nodes)
	require.NoError(t, err)
	assert.Len(t, events, 3)

	assert.Equal(t, "helm.proofgraph.intent", events[0].Type)
	assert.Equal(t, "helm.proofgraph.attestation", events[1].Type)
	assert.Equal(t, "helm.proofgraph.effect", events[2].Type)
}

func TestEncodeBatch_NilSlice(t *testing.T) {
	enc := New()
	events, err := enc.EncodeBatch(nil)
	require.NoError(t, err)
	assert.NotNil(t, events)
	assert.Empty(t, events)
}

func TestEncodeBatch_EmptySlice(t *testing.T) {
	enc := New()
	events, err := enc.EncodeBatch([]*proofgraph.Node{})
	require.NoError(t, err)
	assert.NotNil(t, events)
	assert.Empty(t, events)
}

func TestEncodeBatch_NilNodeInBatch(t *testing.T) {
	enc := New()
	nodes := []*proofgraph.Node{
		testNode(proofgraph.NodeTypeIntent, []byte(`{}`), nil),
		nil, // This should cause an error.
	}

	events, err := enc.EncodeBatch(nodes)
	assert.Nil(t, events)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNilNode)
	assert.Contains(t, err.Error(), "batch index 1")
}

func TestEncodeJSON(t *testing.T) {
	payload, _ := json.Marshal(map[string]string{"action": "deploy"})
	node := testNode(proofgraph.NodeTypeIntent, payload, []string{"parent-x"})

	enc := New()
	data, err := enc.EncodeJSON(node)
	require.NoError(t, err)

	// Must be valid JSON.
	assert.True(t, json.Valid(data))

	// Unmarshal and verify structure.
	var ce CloudEvent
	require.NoError(t, json.Unmarshal(data, &ce))
	assert.Equal(t, "1.0", ce.SpecVersion)
	assert.Equal(t, "helm.proofgraph.intent", ce.Type)
	assert.Equal(t, node.NodeHash, ce.ID)
}

func TestEncodeJSON_NilNode(t *testing.T) {
	enc := New()
	data, err := enc.EncodeJSON(nil)
	assert.Nil(t, data)
	assert.ErrorIs(t, err, ErrNilNode)
}

func TestEncodeBatchJSON(t *testing.T) {
	enc := New()
	payload := []byte(`{"test": "value"}`)
	nodes := []*proofgraph.Node{
		testNode(proofgraph.NodeTypeIntent, payload, nil),
		testNode(proofgraph.NodeTypeEffect, payload, nil),
	}

	data, err := enc.EncodeBatchJSON(nodes)
	require.NoError(t, err)
	assert.True(t, json.Valid(data))

	// Must be a JSON array.
	var events []CloudEvent
	require.NoError(t, json.Unmarshal(data, &events))
	assert.Len(t, events, 2)
	assert.Equal(t, "helm.proofgraph.intent", events[0].Type)
	assert.Equal(t, "helm.proofgraph.effect", events[1].Type)
}

func TestEncodeBatchJSON_EmptySlice(t *testing.T) {
	enc := New()
	data, err := enc.EncodeBatchJSON([]*proofgraph.Node{})
	require.NoError(t, err)
	assert.True(t, json.Valid(data))
	assert.Equal(t, "[]", string(data))
}

func TestEncodeBatchJSON_NilNodeInBatch(t *testing.T) {
	enc := New()
	nodes := []*proofgraph.Node{nil}
	data, err := enc.EncodeBatchJSON(nodes)
	assert.Nil(t, data)
	assert.ErrorIs(t, err, ErrNilNode)
}

func TestJSONRoundTrip(t *testing.T) {
	payload, _ := json.Marshal(map[string]interface{}{
		"tool":     "web_search",
		"decision": "ALLOW",
		"risk":     0.42,
	})
	node := testNode(proofgraph.NodeTypeAttestation, payload, []string{"p1", "p2"})
	node.Sig = "ed25519-sig-xyz"
	node.NodeHash = node.ComputeNodeHash()

	enc := New(
		WithSource("helm://test-cluster"),
		WithClock(fixedClock(time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC))),
	)

	// Encode to JSON.
	data, err := enc.EncodeJSON(node)
	require.NoError(t, err)

	// Unmarshal back to CloudEvent.
	var ce CloudEvent
	require.NoError(t, json.Unmarshal(data, &ce))

	// Verify all fields survive the round trip.
	assert.Equal(t, "1.0", ce.SpecVersion)
	assert.Equal(t, node.NodeHash, ce.ID)
	assert.Equal(t, "helm://test-cluster", ce.Source)
	assert.Equal(t, "helm.proofgraph.attestation", ce.Type)
	assert.NotEmpty(t, ce.Time)
	assert.Equal(t, "application/json", ce.DataContentType)
	assert.Equal(t, "agent-007", ce.Subject)
	assert.Equal(t, node.NodeHash, ce.HelmNodeHash)
	assert.Equal(t, uint64(42), ce.HelmLamport)
	assert.Equal(t, uint64(5), ce.HelmPrincipalSeq)
	assert.Equal(t, "ed25519-sig-xyz", ce.HelmSignature)
	assert.Equal(t, "p1,p2", ce.HelmParents)
	assert.JSONEq(t, string(payload), string(ce.Data))

	// Re-marshal and compare (deterministic).
	data2, err := json.Marshal(ce)
	require.NoError(t, err)
	assert.Equal(t, string(data), string(data2))
}

func TestLargeBatch(t *testing.T) {
	const batchSize = 1000
	enc := New(WithClock(fixedClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))))

	nodes := make([]*proofgraph.Node, batchSize)
	for i := range batchSize {
		payload, _ := json.Marshal(map[string]interface{}{
			"index":  i,
			"action": "test",
		})
		kind := proofgraph.NodeTypeIntent
		if i%3 == 1 {
			kind = proofgraph.NodeTypeAttestation
		} else if i%3 == 2 {
			kind = proofgraph.NodeTypeEffect
		}
		nodes[i] = proofgraph.NewNode(
			kind, nil, payload, uint64(i+1), "agent-batch", uint64(i),
			fixedClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
		)
	}

	// Batch encode.
	events, err := enc.EncodeBatch(nodes)
	require.NoError(t, err)
	assert.Len(t, events, batchSize)

	// Verify first and last.
	assert.Equal(t, "helm.proofgraph.intent", events[0].Type)
	assert.Equal(t, nodes[0].NodeHash, events[0].ID)
	assert.Equal(t, nodes[batchSize-1].NodeHash, events[batchSize-1].ID)

	// Batch to JSON.
	data, err := enc.EncodeBatchJSON(nodes)
	require.NoError(t, err)
	assert.True(t, json.Valid(data))

	var decoded []CloudEvent
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Len(t, decoded, batchSize)
}

func TestNew_DefaultValues(t *testing.T) {
	enc := New()
	node := testNode(proofgraph.NodeTypeIntent, []byte(`{}`), nil)
	ce, err := enc.Encode(node)
	require.NoError(t, err)

	assert.Equal(t, "helm://proofgraph", ce.Source, "default source")
	assert.NotEmpty(t, ce.Time, "clock should default to time.Now")
}

func TestNew_MultipleOptions(t *testing.T) {
	frozen := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	enc := New(
		WithSource("helm://custom"),
		WithClock(fixedClock(frozen)),
	)

	// Create a node with zero timestamp to exercise clock fallback.
	node := &proofgraph.Node{
		NodeHash:  "abc",
		Kind:      proofgraph.NodeTypeCheckpoint,
		Lamport:   1,
		Principal: "sys",
		Payload:   json.RawMessage(`{}`),
		Timestamp: 0,
	}

	ce, err := enc.Encode(node)
	require.NoError(t, err)

	assert.Equal(t, "helm://custom", ce.Source)
	assert.Equal(t, frozen.UTC().Format(time.RFC3339Nano), ce.Time)
}

func TestEncode_NodeTimestampUsedWhenPresent(t *testing.T) {
	// Node has a specific timestamp. The encoder clock should NOT be used.
	clockCalled := false
	enc := New(WithClock(func() time.Time {
		clockCalled = true
		return time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	}))

	payload := []byte(`{"data":"test"}`)
	frozen := time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)
	node := proofgraph.NewNode(proofgraph.NodeTypeIntent, nil, payload, 1, "agent", 0, fixedClock(frozen))

	ce, err := enc.Encode(node)
	require.NoError(t, err)

	// Time should come from node timestamp, not the encoder clock.
	expectedTime := frozen.UTC().Format(time.RFC3339Nano)
	assert.Equal(t, expectedTime, ce.Time)
	assert.False(t, clockCalled, "encoder clock should not be called when node has timestamp")
}

func TestEncode_SignatureOmittedWhenEmpty(t *testing.T) {
	node := testNode(proofgraph.NodeTypeIntent, []byte(`{}`), nil)
	// Node created by testNode has no signature.

	enc := New()
	data, err := enc.EncodeJSON(node)
	require.NoError(t, err)

	// The JSON should have an empty helmsignature field (omitempty applies).
	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &raw))

	// helmsignature should be absent (omitempty on empty string).
	_, hasSig := raw["helmsignature"]
	assert.False(t, hasSig, "helmsignature should be omitted when empty")
}

func TestEncode_ParentsOmittedWhenEmpty(t *testing.T) {
	node := testNode(proofgraph.NodeTypeIntent, []byte(`{}`), nil)

	enc := New()
	data, err := enc.EncodeJSON(node)
	require.NoError(t, err)

	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &raw))

	// helmparents should be absent when there are no parents (empty string + omitempty).
	_, hasParents := raw["helmparents"]
	assert.False(t, hasParents, "helmparents should be omitted when empty")
}

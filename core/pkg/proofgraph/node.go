// Package proofgraph implements the cryptographic ProofGraph DAG for HELM.
// Every execution produces a chain of nodes: INTENT → ATTESTATION → EFFECT,
// with TRUST_EVENT and CHECKPOINT nodes for registry management.
package proofgraph

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/canonicalize"
)

// NodeType enumerates the types of nodes in the ProofGraph.
type NodeType string

const (
	NodeTypeIntent        NodeType = "INTENT"
	NodeTypeAttestation   NodeType = "ATTESTATION"
	NodeTypeEffect        NodeType = "EFFECT"
	NodeTypeTrustEvent    NodeType = "TRUST_EVENT"
	NodeTypeCheckpoint    NodeType = "CHECKPOINT"
	NodeTypeMergeDecision NodeType = "MERGE_DECISION"
	NodeTypeTrustScore    NodeType = "TRUST_SCORE"
	NodeTypeAgentKill      NodeType = "AGENT_KILL"
	NodeTypeAgentRevive    NodeType = "AGENT_REVIVE"
	NodeTypeSagaStart      NodeType = "SAGA_START"
	NodeTypeSagaCompensate NodeType = "SAGA_COMPENSATE"
	NodeTypeVouch          NodeType = "VOUCH"
	NodeTypeSlash          NodeType = "SLASH"
	NodeTypeFederation     NodeType = "FEDERATION"
	NodeTypeHWAttestation      NodeType = "HW_ATTESTATION"
	NodeTypeZKProof            NodeType = "ZK_PROOF"
	NodeTypeDecentralizedProof NodeType = "DECENTRALIZED_PROOF"
)

// Node is a single vertex in the ProofGraph DAG.
// Aligned with HELM Standard v1.2 Appendix B.1
type Node struct {
	NodeHash     string          `json:"node_hash"`
	Kind         NodeType        `json:"kind"`
	Parents      []string        `json:"parents"`
	Lamport      uint64          `json:"lamport"`
	Principal    string          `json:"principal"`
	PrincipalSeq uint64          `json:"principal_seq"`
	Payload      json.RawMessage `json:"payload"`
	Sig          string          `json:"sig"`
	Timestamp    int64           `json:"ts_unix_ms,omitempty"`
}

// ComputeNodeHash computes the deterministic hash of the node (excluding NodeHash itself).
// Uses JCS (RFC 8785) canonicalization via canonicalize.JCS() for cross-platform determinism.
// ComputeNodeHashE computes the deterministic hash, returning an error on failure.
func (n *Node) ComputeNodeHashE() (string, error) {
	// Create a temporary structure for hashing that excludes NodeHash and Timestamp for determinism
	type NodeJCS struct {
		Kind         NodeType        `json:"kind"`
		Parents      []string        `json:"parents"`
		Lamport      uint64          `json:"lamport"`
		Principal    string          `json:"principal"`
		PrincipalSeq uint64          `json:"principal_seq"`
		Payload      json.RawMessage `json:"payload"`
		Sig          string          `json:"sig"`
	}

	temp := NodeJCS{
		Kind:         n.Kind,
		Parents:      n.Parents,
		Lamport:      n.Lamport,
		Principal:    n.Principal,
		PrincipalSeq: n.PrincipalSeq,
		Payload:      n.Payload,
		Sig:          n.Sig,
	}

	// RFC 8785 (JCS): sorted keys, no HTML escaping, compact format, deterministic.
	data, err := canonicalize.JCS(temp)
	if err != nil {
		return "", fmt.Errorf("JCS canonicalization failed: %w", err)
	}

	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

// ComputeNodeHash computes the deterministic hash of the node (excluding NodeHash itself).
// Uses JCS (RFC 8785) canonicalization via canonicalize.JCS() for cross-platform determinism.
// Panics if canonicalization fails, as this is an invariant violation.
func (n *Node) ComputeNodeHash() string {
	hash, err := n.ComputeNodeHashE()
	if err != nil {
		panic(fmt.Sprintf("proofgraph: node hash computation failed: %v", err))
	}
	return hash
}

// Validate checks the node hash integrity.
func (n *Node) Validate() error {
	expected := n.ComputeNodeHash()
	if n.NodeHash != expected {
		return fmt.Errorf("node hash mismatch: got %s, want %s", n.NodeHash, expected)
	}
	return nil
}

// MaxPayloadSize is the maximum allowed size for a node payload (1 MiB).
const MaxPayloadSize = 1 << 20

// NewNode creates a properly initialized node.
// Per KERNEL_TCB §3: callers SHOULD pass a kernel authority clock.
// If no clock is provided, time.Now is used for backward compatibility.
// Returns an error if the payload is invalid JSON or exceeds MaxPayloadSize.
func NewNode(kind NodeType, parents []string, payload []byte, lamport uint64, principal string, principalSeq uint64, clock ...func() time.Time) *Node {
	now := time.Now
	if len(clock) > 0 && clock[0] != nil {
		now = clock[0]
	}
	if len(payload) > MaxPayloadSize {
		panic(fmt.Sprintf("proofgraph: payload size %d exceeds maximum %d", len(payload), MaxPayloadSize))
	}
	if len(payload) > 0 && !json.Valid(payload) {
		panic("proofgraph: payload is not valid JSON")
	}
	n := &Node{
		Kind:         kind,
		Parents:      parents,
		Payload:      json.RawMessage(payload),
		Lamport:      lamport,
		Principal:    principal,
		PrincipalSeq: principalSeq,
		Timestamp:    now().UnixMilli(),
	}
	n.NodeHash = n.ComputeNodeHash()
	return n
}

// EncodePayload is a helper to JSON-marshal a payload for node creation.
func EncodePayload(v any) ([]byte, error) {
	return json.Marshal(v)
}

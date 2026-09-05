package proofgraph

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

const EvidencePackLineageRootNodeSchemaV1 = "proofgraph-evidence-pack-lineage-root.v1"

var (
	ErrEvidencePackLineageConflict   = errors.New("evidence pack lineage conflict")
	ErrEvidencePackLineageTransition = errors.New("evidence pack lineage transition invalid")
	ErrEvidencePackLineageDangling   = errors.New("evidence pack lineage predecessor missing")
	ErrEvidencePackLineageClosed     = errors.New("evidence pack measurement lineage closed")
)

// EvidencePackLineageRootNode binds the hash of the already sealed effect-time
// pack to the frozen identities stored inside that pack. Later successor nodes
// must use this node, or a verified successor descending from it, as parent.
type EvidencePackLineageRootNode struct {
	SchemaVersion  string                        `json:"schema_version"`
	SealedPackRef  string                        `json:"sealed_pack_ref"`
	SealedPackHash string                        `json:"sealed_pack_hash"`
	Lineage        contracts.EvidencePackLineage `json:"lineage"`
}

func (r EvidencePackLineageRootNode) validate() error {
	if r.SchemaVersion != EvidencePackLineageRootNodeSchemaV1 {
		return fmt.Errorf("%w: root has unsupported schema_version", ErrEvidencePackLineageConflict)
	}
	if r.SealedPackRef == "" || len(r.SealedPackRef) > 512 || strings.IndexFunc(r.SealedPackRef, unicode.IsSpace) >= 0 {
		return fmt.Errorf("%w: sealed_pack_ref is invalid", ErrEvidencePackLineageConflict)
	}
	if !validEvidencePackSHA256(r.SealedPackHash) {
		return fmt.Errorf("%w: sealed_pack_hash is invalid", ErrEvidencePackLineageConflict)
	}
	if err := r.Lineage.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrEvidencePackLineageConflict, err)
	}
	return nil
}

// AppendEvidencePackRoot verifies and records the immutable starting point for
// one EvidencePack successor chain. Re-appending the same root is idempotent;
// attempting to bind the same sealed pack to different frozen identities is
// rejected as non-equivocation failure.
func (g *Graph) AppendEvidencePackRoot(sealedPackRef string, sealedPack *contracts.EvidencePack, principal string, seq uint64) (*Node, error) {
	if sealedPack == nil || sealedPack.Lineage == nil {
		return nil, fmt.Errorf("%w: sealed pack with frozen lineage is required", ErrEvidencePackLineageConflict)
	}
	sealedPackHash, err := contracts.ComputeEvidencePackHash(sealedPack)
	if err != nil || sealedPack.Attestation.PackHash != sealedPackHash {
		return nil, fmt.Errorf("%w: sealed pack attestation hash mismatch", ErrEvidencePackLineageConflict)
	}
	lineage := *sealedPack.Lineage
	root := EvidencePackLineageRootNode{
		SchemaVersion:  EvidencePackLineageRootNodeSchemaV1,
		SealedPackRef:  sealedPackRef,
		SealedPackHash: sealedPackHash,
		Lineage:        lineage,
	}
	if err := root.validate(); err != nil {
		return nil, err
	}
	payload, err := canonicalize.JCS(root)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize root: %v", ErrEvidencePackLineageConflict, err)
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	for _, node := range g.nodes {
		existing, ok := decodeEvidencePackLineageRootPayload(node.Payload)
		if !ok || (existing.SealedPackRef != sealedPackRef && existing.SealedPackHash != sealedPackHash) {
			continue
		}
		if err := node.Validate(); err != nil {
			return nil, fmt.Errorf("%w: existing sealed-pack root failed node integrity", ErrEvidencePackLineageConflict)
		}
		if existing == root {
			return node, nil
		}
		return nil, fmt.Errorf("%w: sealed pack already has a different frozen lineage", ErrEvidencePackLineageConflict)
	}
	return g.appendEvidencePackNodeLocked(NodeTypeAttestation, append([]string(nil), g.heads...), payload, principal, seq), nil
}

// AppendEvidencePackSuccessor validates the immutable record and its exact
// ProofGraph parent before appending. The graph is the idempotency and
// non-equivocation boundary for the in-memory reference implementation.
func (g *Graph) AppendEvidencePackSuccessor(successor contracts.EvidencePackSuccessor, predecessorNodeHash, principal string, seq uint64) (*Node, error) {
	sealed, err := sealEvidencePackSuccessorForAppend(successor)
	if err != nil {
		return nil, err
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	predecessor, ok := g.nodes[predecessorNodeHash]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrEvidencePackLineageDangling, predecessorNodeHash)
	}

	for _, node := range g.nodes {
		existing, decodeErr := DecodeEvidencePackSuccessorNode(node)
		if decodeErr != nil || existing.SuccessorID != sealed.SuccessorID {
			continue
		}
		if existing.SuccessorHash == sealed.SuccessorHash && len(node.Parents) == 1 && node.Parents[0] == predecessorNodeHash {
			return node, nil
		}
		return nil, fmt.Errorf("%w: successor identity already contains different evidence", ErrEvidencePackLineageConflict)
	}

	previousKind, err := validateEvidencePackPredecessor(predecessor, sealed)
	if err != nil {
		return nil, err
	}
	if err := validateEvidencePackTransition(previousKind, sealed.Kind); err != nil {
		return nil, err
	}
	if sealed.Kind != contracts.EvidencePackSuccessorOperationalEvaluation {
		for _, node := range g.nodes {
			existing, decodeErr := DecodeEvidencePackSuccessorNode(node)
			if decodeErr == nil && existing.SealedPackHash == sealed.SealedPackHash && existing.Lineage == sealed.Lineage && existing.FinalizesMeasurement() {
				return nil, fmt.Errorf("%w: %s", ErrEvidencePackLineageClosed, sealed.Lineage.WindowIdentity)
			}
		}
	}
	for _, node := range g.nodes {
		existing, decodeErr := DecodeEvidencePackSuccessorNode(node)
		if decodeErr == nil && existing.SealedPackRef == sealed.SealedPackRef && existing.SealedPackHash == sealed.SealedPackHash &&
			existing.Lineage == sealed.Lineage && existing.PredecessorRef == sealed.PredecessorRef && existing.PredecessorHash == sealed.PredecessorHash {
			return nil, fmt.Errorf("%w: predecessor already advanced for %s", ErrEvidencePackLineageConflict, sealed.Lineage.WindowIdentity)
		}
	}

	payload, err := canonicalize.JCS(sealed)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize successor: %v", ErrEvidencePackLineageConflict, err)
	}
	return g.appendEvidencePackNodeLocked(NodeTypeAttestation, []string{predecessorNodeHash}, payload, principal, seq), nil
}

func sealEvidencePackSuccessorForAppend(successor contracts.EvidencePackSuccessor) (contracts.EvidencePackSuccessor, error) {
	if successor.SuccessorID != "" || successor.SuccessorHash != "" {
		if err := successor.ValidateIntegrity(); err != nil {
			return contracts.EvidencePackSuccessor{}, err
		}
		return successor, nil
	}
	return successor.Seal()
}

func validateEvidencePackPredecessor(predecessor *Node, successor contracts.EvidencePackSuccessor) (contracts.EvidencePackSuccessorKind, error) {
	if err := predecessor.Validate(); err != nil {
		return "", fmt.Errorf("%w: predecessor node integrity: %v", ErrEvidencePackLineageConflict, err)
	}
	if root, ok := decodeEvidencePackLineageRootPayload(predecessor.Payload); ok {
		if successor.PredecessorRef != root.SealedPackRef || successor.PredecessorHash != root.SealedPackHash ||
			successor.SealedPackRef != root.SealedPackRef || successor.SealedPackHash != root.SealedPackHash ||
			successor.Lineage != root.Lineage {
			return "", fmt.Errorf("%w: successor does not match sealed root identity", ErrEvidencePackLineageConflict)
		}
		return "", nil
	}
	previous, err := DecodeEvidencePackSuccessorNode(predecessor)
	if err != nil {
		return "", fmt.Errorf("%w: parent is not an EvidencePack lineage node", ErrEvidencePackLineageDangling)
	}
	if successor.PredecessorRef != previous.SuccessorID || successor.PredecessorHash != previous.SuccessorHash ||
		successor.SealedPackRef != previous.SealedPackRef || successor.SealedPackHash != previous.SealedPackHash ||
		successor.Lineage != previous.Lineage {
		return "", fmt.Errorf("%w: successor does not preserve predecessor identity", ErrEvidencePackLineageConflict)
	}
	return previous.Kind, nil
}

func validateEvidencePackTransition(previous, next contracts.EvidencePackSuccessorKind) error {
	if previous == "" {
		if next != contracts.EvidencePackSuccessorOperationalEvaluation {
			return fmt.Errorf("%w: sealed root must first receive an operational evaluation", ErrEvidencePackLineageTransition)
		}
		return nil
	}
	if previous == contracts.EvidencePackSuccessorMeasurementFinal || previous == contracts.EvidencePackSuccessorMeasurementCensored {
		return fmt.Errorf("%w: terminal measurement has no successors", ErrEvidencePackLineageClosed)
	}
	if next == contracts.EvidencePackSuccessorOperationalEvaluation {
		return fmt.Errorf("%w: operational evaluation must directly follow the sealed root", ErrEvidencePackLineageTransition)
	}
	if previous != contracts.EvidencePackSuccessorOperationalEvaluation && previous != contracts.EvidencePackSuccessorMeasurementProgress {
		return fmt.Errorf("%w: measurement addendum has an invalid predecessor", ErrEvidencePackLineageTransition)
	}
	return nil
}

// DecodeEvidencePackSuccessorNode verifies both the ProofGraph node hash and
// the successor's own deterministic identity/content hash.
func DecodeEvidencePackSuccessorNode(node *Node) (contracts.EvidencePackSuccessor, error) {
	if node == nil {
		return contracts.EvidencePackSuccessor{}, fmt.Errorf("%w: node is required", ErrEvidencePackLineageDangling)
	}
	if node.Kind != NodeTypeAttestation {
		return contracts.EvidencePackSuccessor{}, fmt.Errorf("%w: successor node must be an ATTESTATION", ErrEvidencePackLineageConflict)
	}
	if err := node.Validate(); err != nil {
		return contracts.EvidencePackSuccessor{}, fmt.Errorf("%w: node integrity: %v", ErrEvidencePackLineageConflict, err)
	}
	return contracts.DecodeEvidencePackSuccessor(node.Payload)
}

func decodeEvidencePackLineageRootPayload(payload json.RawMessage) (EvidencePackLineageRootNode, bool) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var root EvidencePackLineageRootNode
	if err := decoder.Decode(&root); err != nil {
		return EvidencePackLineageRootNode{}, false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF || root.SchemaVersion != EvidencePackLineageRootNodeSchemaV1 || root.validate() != nil {
		return EvidencePackLineageRootNode{}, false
	}
	return root, true
}

func (g *Graph) appendEvidencePackNodeLocked(kind NodeType, parents []string, payload []byte, principal string, seq uint64) *Node {
	g.lamport++
	node := NewNode(kind, parents, payload, g.lamport, principal, seq, g.clock)
	g.nodes[node.NodeHash] = node

	remaining := make([]string, 0, len(g.heads)+1)
	for _, head := range g.heads {
		isParent := false
		for _, parent := range parents {
			if head == parent {
				isParent = true
				break
			}
		}
		if !isParent {
			remaining = append(remaining, head)
		}
	}
	g.heads = append(remaining, node.NodeHash)
	return node
}

func validEvidencePackSHA256(value string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	raw := strings.TrimPrefix(value, prefix)
	if len(raw) != 64 || strings.ToLower(raw) != raw {
		return false
	}
	decoded, err := hex.DecodeString(raw)
	return err == nil && len(decoded) == 32
}

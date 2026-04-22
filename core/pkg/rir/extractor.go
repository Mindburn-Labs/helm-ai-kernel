package rir

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// SourceArtifact represents a regulatory source document for extraction.
// Defined locally to avoid depending on the enterprise arc package.
type SourceArtifact struct {
	ArtifactID  string    `json:"artifact_id"`
	SourceID    string    `json:"source_id"`
	ContentHash string    `json:"content_hash,omitempty"`
	IngestedAt  time.Time `json:"ingested_at,omitempty"`
}
type Extractor struct {
	// Future: LLM Gateway dependency for semantic extraction
}

func NewExtractor() *Extractor {
	return &Extractor{}
}

// ExtractFromArtifact creates an RIRBundle from a SourceArtifact.
// Heuristic implementation.
func (e *Extractor) ExtractFromArtifact(ctx context.Context, artifact *SourceArtifact) (*RIRBundle, error) {
	if artifact == nil {
		return nil, fmt.Errorf("nil artifact")
	}

	bundleID := uuid.New().String()

	// Create a Root Node
	rootNode := Node{
		ID:      uuid.New().String(),
		Type:    NodeTypeGroup,
		Title:   "Regulation Root", // In reality, derived from artifact
		Content: "Extracted from " + artifact.SourceID,
	}

	nodes := make(map[string]Node)
	nodes[rootNode.ID] = rootNode

	// Create a SourceLink
	links := make(map[string]SourceLink)
	link := SourceLink{
		NodeID:           rootNode.ID,
		SourceArtifactID: artifact.ArtifactID,
		StartOffset:      0,
		EndOffset:        100, // Dummy
		SegmentHash:      "dummy-hash",
	}
	links[rootNode.ID] = link

	bundle := &RIRBundle{
		BundleID:    bundleID,
		Scope:       artifact.SourceID, // Simple mapping
		Version:     "0.0.1",
		RootNodeID:  rootNode.ID,
		Nodes:       nodes,
		SourceLinks: links,
		CreatedAt:   time.Now().UTC(),
	}

	// Compute Hash
	hash, err := ComputeBundleHash(bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to compute hash: %w", err)
	}
	bundle.ContentHash = hash

	return bundle, nil
}

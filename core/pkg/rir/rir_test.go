package rir_test

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/rir"
	"github.com/google/uuid"
)

func TestBundleHashingDeterminism(t *testing.T) {
	// Create two identical bundles with differently ordered nodes/links
	// Note: Our manual construction here respects map randomness, ensuring Hashing function handles sort.

	node1 := rir.Node{ID: "node-a", Title: "A"}
	node2 := rir.Node{ID: "node-b", Title: "B"}

	link1 := rir.SourceLink{NodeID: "node-a", StartOffset: 1}
	link2 := rir.SourceLink{NodeID: "node-b", StartOffset: 1}

	nodes := map[string]rir.Node{
		"node-a": node1,
		"node-b": node2,
	}
	links := map[string]rir.SourceLink{
		"node-a": link1,
		"node-b": link2,
	}

	bundle1 := &rir.RIRBundle{
		BundleID:    "test-bundle",
		Scope:       "test-scope",
		Version:     "1.0",
		Nodes:       nodes,
		SourceLinks: links,
	}

	// Create a copy, map iteration order might differ in Go runtime
	nodes2 := map[string]rir.Node{
		"node-b": node2,
		"node-a": node1,
	}
	links2 := map[string]rir.SourceLink{
		"node-b": link2,
		"node-a": link1,
	}

	bundle2 := &rir.RIRBundle{
		BundleID:    "test-bundle",
		Scope:       "test-scope",
		Version:     "1.0",
		Nodes:       nodes2,
		SourceLinks: links2,
	}

	hash1, err := rir.ComputeBundleHash(bundle1)
	if err != nil {
		t.Fatal(err)
	}

	hash2, err := rir.ComputeBundleHash(bundle2)
	if err != nil {
		t.Fatal(err)
	}

	if hash1 != hash2 {
		t.Errorf("Hashing is non-deterministic: %s != %s", hash1, hash2)
	}
}

func TestExtraction(t *testing.T) {
	artifact := &rir.SourceArtifact{
		ArtifactID:  uuid.New().String(),
		SourceID:    "eu-test",
		ContentHash: "hash123",
		IngestedAt:  time.Now(),
	}

	extractor := rir.NewExtractor()
	bundle, err := extractor.ExtractFromArtifact(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}

	if bundle.Scope != "eu-test" {
		t.Errorf("Expected scope eu-test, got %s", bundle.Scope)
	}
	if bundle.ContentHash == "" {
		t.Error("ContentHash should be computed")
	}
	if len(bundle.Nodes) == 0 {
		t.Error("Bundle should have nodes")
	}

	// Verify SourceLink exists
	rootID := bundle.RootNodeID
	if _, ok := bundle.SourceLinks[rootID]; !ok {
		t.Error("Root node should have a source link")
	}
}

package rir

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// ComputeBundleHash calculates a deterministic hash of the entire bundle.
func ComputeBundleHash(bundle *RIRBundle) (string, error) {
	// Create a canonical representation used ONLY for hashing
	// This avoids modifying the original struct
	canonical := struct {
		BundleID    string       `json:"bundle_id"`
		Scope       string       `json:"scope"`
		Version     string       `json:"version"`
		Nodes       []Node       `json:"nodes"`        // Sorted slice for determinism
		SourceLinks []SourceLink `json:"source_links"` // Sorted
	}{
		BundleID: bundle.BundleID,
		Scope:    bundle.Scope,
		Version:  bundle.Version,
	}

	// 1. Sort Nodes by ID
	nodes := make([]Node, 0, len(bundle.Nodes))
	for _, n := range bundle.Nodes {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].ID < nodes[j].ID
	})
	canonical.Nodes = nodes

	// 2. Sort SourceLinks by NodeID
	links := make([]SourceLink, 0, len(bundle.SourceLinks))
	for _, l := range bundle.SourceLinks {
		links = append(links, l)
	}
	sort.Slice(links, func(i, j int) bool {
		return links[i].NodeID < links[j].NodeID
	})
	canonical.SourceLinks = links

	data, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

package rir

import (
	"time"
)

// RIRBundle represents a complete package of regulations for a specific scope.
type RIRBundle struct {
	BundleID    string                `json:"bundle_id"`
	Scope       string                `json:"scope"` // e.g., "eu-gdpr", "us-hipaa"
	Version     string                `json:"version"`
	RootNodeID  string                `json:"root_node_id"`
	Nodes       map[string]Node       `json:"nodes"`
	SourceLinks map[string]SourceLink `json:"source_links"`
	CreatedAt   time.Time             `json:"created_at"`
	ContentHash string                `json:"content_hash"` // Merkle root or simpler hash of all nodes
}

// NodeType distinguishes between obligations, permissions, etc.
type NodeType string

const (
	NodeTypeObligation  NodeType = "obligation"
	NodeTypePermission  NodeType = "permission"
	NodeTypeProhibition NodeType = "prohibition"
	NodeTypeDefinition  NodeType = "definition"
	NodeTypeGroup       NodeType = "group" // Structural grouping (section, chapter)
)

// Node is the base unit of the regulation graph.
type Node struct {
	ID          string                 `json:"id"`
	Type        NodeType               `json:"type"`
	Title       string                 `json:"title"`
	Content     string                 `json:"content"`
	Evidence    []EvidenceRequirement  `json:"evidence_requirements,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"` // Thresholds, limits
	ChildrenIDs []string               `json:"children_ids,omitempty"`
}

// SourceLink connects a Node back to the ARC SourceArtifact.
type SourceLink struct {
	NodeID           string `json:"node_id"`
	SourceArtifactID string `json:"source_artifact_id"`
	StartOffset      int    `json:"start_offset"`
	EndOffset        int    `json:"end_offset"`
	SegmentHash      string `json:"segment_hash"` // Hash of the specific text segment
}

// EvidenceRequirement describes what must be produced to prove compliance.
type EvidenceRequirement struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	SchemaID    string `json:"schema_id,omitempty"` // Link to a receipt schema
	Mandatory   bool   `json:"mandatory"`
}

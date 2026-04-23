// Package aibom provides AI Bill of Materials (AI-BOM) tracking for governed
// components. It records model provenance, dataset lineage, software
// dependencies, and produces JCS-canonicalized content hashes so that BOMs
// integrate with HELM's receipt and evidence pack system.
package aibom

import (
	"time"
)

// AIBOM represents an AI Bill of Materials for a governed component.
// It tracks model provenance, dataset lineage, and software dependencies.
type AIBOM struct {
	BomID         string            `json:"bom_id"`
	FormatVersion string            `json:"format_version"` // "1.0.0"
	Component     string            `json:"component"`      // "helm-kernel", "llm-gateway"
	CreatedAt     time.Time         `json:"created_at"`
	Models        []ModelProvenance `json:"models"`
	Datasets      []DatasetLineage  `json:"datasets,omitempty"`
	Dependencies  []DependencyEntry `json:"dependencies"`
	ContentHash   string            `json:"content_hash"`
	Signature     string            `json:"signature,omitempty"`
	SignatureType string            `json:"signature_type,omitempty"`
}

// ModelProvenance tracks the origin and characteristics of an AI model.
type ModelProvenance struct {
	ModelID         string `json:"model_id"`
	Provider        string `json:"provider"` // "openai", "anthropic", "local", "huggingface"
	ModelName       string `json:"model_name"`
	ModelVersion    string `json:"model_version"`
	WeightsHash     string `json:"weights_hash,omitempty"`    // SHA-256 of model weights
	QuantizationFmt string `json:"quantization,omitempty"`    // "fp16", "int8", "bf16", "gguf"
	TrainingCutoff  string `json:"training_cutoff,omitempty"` // ISO date
	License         string `json:"license,omitempty"`         // SPDX license identifier
	Source          string `json:"source,omitempty"`          // URL or registry
	SafetyCard      string `json:"safety_card,omitempty"`     // Model card URL
	Parameters      string `json:"parameters,omitempty"`      // "8B", "70B", etc.
}

// DatasetLineage tracks training and RAG data sources.
type DatasetLineage struct {
	DatasetID string   `json:"dataset_id"`
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Hash      string   `json:"hash,omitempty"` // SHA-256 of dataset
	License   string   `json:"license,omitempty"`
	Sources   []string `json:"sources,omitempty"`    // URLs or registry IDs
	PIIStatus string   `json:"pii_status,omitempty"` // "none", "redacted", "present"
	BiasNote  string   `json:"bias_note,omitempty"`
}

// DependencyEntry tracks a software dependency (SPDX-aligned).
type DependencyEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`              // "go-module", "npm", "python", "system"
	Hash    string `json:"hash,omitempty"`    // SHA-256 of package
	License string `json:"license,omitempty"` // SPDX license ID
	SPDXID  string `json:"spdx_id,omitempty"`
}

// BOMDiff represents changes between two BOM versions.
type BOMDiff struct {
	OldBomID      string            `json:"old_bom_id"`
	NewBomID      string            `json:"new_bom_id"`
	ModelsAdded   []ModelProvenance `json:"models_added,omitempty"`
	ModelsRemoved []ModelProvenance `json:"models_removed,omitempty"`
	DepsAdded     []DependencyEntry `json:"deps_added,omitempty"`
	DepsRemoved   []DependencyEntry `json:"deps_removed,omitempty"`
	DepsChanged   []DepChange       `json:"deps_changed,omitempty"`
}

// DepChange tracks a version change in a dependency.
type DepChange struct {
	Name       string `json:"name"`
	OldVersion string `json:"old_version"`
	NewVersion string `json:"new_version"`
}

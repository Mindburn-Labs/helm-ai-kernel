// Package surface defines the public contracts for the HELM Surface Compiler.
//
// The Surface Compiler transforms Packs into surface bundles: deployable,
// provider-compatible execution packages with signed provenance. This OSS
// package defines the compiler interface and bundle types. The commercial
// HELM Platform provides the managed compilation environment.
package surface

// CompilerInput is the input to the surface compiler.
type CompilerInput struct {
	PackID          string            `json:"pack_id"`
	PackVersion     string            `json:"pack_version"`
	PhenotypeHash   string            `json:"phenotype_hash"`
	TargetProviders []string          `json:"target_providers"`
	Config          map[string]any    `json:"config,omitempty"`
}

// CompilerOutput is the result of a successful compilation.
type CompilerOutput struct {
	BundleID      string          `json:"bundle_id"`
	PackID        string          `json:"pack_id"`
	Bundles       []SurfaceBundle `json:"bundles"`
	CompilationID string          `json:"compilation_id"`
	ContentHash   string          `json:"content_hash"`
	Signature     string          `json:"signature,omitempty"`
}

// SurfaceBundle is a provider-specific deployable artifact.
type SurfaceBundle struct {
	BundleID    string         `json:"bundle_id"`
	ProviderID  string         `json:"provider_id"`
	Format      string         `json:"format"` // "wasm", "docker", "native"
	Artifact    []byte         `json:"artifact,omitempty"`
	ArtifactRef string         `json:"artifact_ref,omitempty"`
	Metadata    BundleMetadata `json:"metadata"`
	ContentHash string         `json:"content_hash"`
	Signature   string         `json:"signature,omitempty"`
}

// BundleMetadata carries provenance and compatibility info for a bundle.
type BundleMetadata struct {
	PackID          string   `json:"pack_id"`
	PackVersion     string   `json:"pack_version"`
	TargetProvider  string   `json:"target_provider"`
	Capabilities    []string `json:"capabilities"`
	MinKernelVersion string  `json:"min_kernel_version"`
}

// CompatibilityTarget specifies what a surface bundle must be compatible with.
type CompatibilityTarget struct {
	ProviderID    string   `json:"provider_id"`
	MinVersion    string   `json:"min_version"`
	MaxVersion    string   `json:"max_version,omitempty"`
	RequiredCaps  []string `json:"required_caps"`
}

// Compiler is the canonical interface for the surface compiler.
type Compiler interface {
	Compile(input *CompilerInput) (*CompilerOutput, error)
	ValidateBundle(bundle *SurfaceBundle) error
}

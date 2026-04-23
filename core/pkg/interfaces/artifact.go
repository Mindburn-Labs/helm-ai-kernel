package interfaces

// Artifact represents a canonicalized, content-addressed data object.
// This is the fundamental unit of data exchange in HELM.
type Artifact struct {
	// SchemaID identifies the JSON schema for validation.
	SchemaID string `json:"schema_id"`

	// ContentType is the MIME type of the content (e.g., "application/json", "text/plain").
	ContentType string `json:"content_type"`

	// CanonicalBytes holds the deterministic byte representation of the content.
	// For JSON, this MUST be JCS (RFC 8785).
	// For text, this MUST be UTF-8 normalized (NFC).
	CanonicalBytes []byte `json:"canonical_bytes"`

	// Digest is the SHA-256 multihash of the CanonicalBytes.
	// Format: "sha256:<hex_digest>"
	Digest string `json:"digest"`

	// Preview is a deterministic, human-readable truncation of the content.
	// It is NOT a substitute for the full content.
	Preview string `json:"preview"`

	// Metadata contains stable key-sorted metadata about the artifact.
	// Examples: "created_by", "source_tool", "timestamp".
	Metadata map[string]string `json:"metadata,omitempty"`
}

// ArtifactStore defines the interface for content-addressed storage.
type ArtifactStore interface {
	// Store persists an artifact and returns its Digest.
	// It MUST verify the Digest matches the CanonicalBytes before storing.
	Store(artifact *Artifact) (string, error)

	// Get retrieves an artifact by its Digest.
	Get(digest string) (*Artifact, error)

	// Exists checks if an artifact exists by its Digest.
	Exists(digest string) (bool, error)
}

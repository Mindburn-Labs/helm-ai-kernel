// Package trust holds the behavioral trust scorer and pack references.
package trust

// PackRef identifies a pack with its metadata.
type PackRef struct {
	// Name is the pack identifier (e.g., "org.example/my-pack")
	Name string `json:"name"`

	// Version is the semantic version
	Version string `json:"version"`

	// Hash is the SHA256 hash of the pack content
	Hash string `json:"hash"`

	// Certified indicates if this is a HELM-certified pack
	Certified bool `json:"certified"`

	// PublisherKeyID identifies the pack signer
	PublisherKeyID string `json:"publisher_key_id,omitempty"`
}

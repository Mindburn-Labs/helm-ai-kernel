package canonicalize

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"unicode/utf8"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/interfaces"
)

// Canonicalize converts a raw value into a canonical Artifact.
// It detects the content type and applies the appropriate canonicalization logic.
func Canonicalize(schemaID string, raw interface{}) (*interfaces.Artifact, error) {
	var canonicalBytes []byte
	var contentType string
	var err error

	switch v := raw.(type) {
	case string:
		contentType = "text/plain"
		// Normalize text to NFC (if not already, Go strings are usually UTF-8)
		// For strict canonicalization, we should ensure deterministic encoding.
		// Assuming UTF-8 here.
		if !utf8.ValidString(v) {
			return nil, fmt.Errorf("invalid UTF-8 string")
		}
		canonicalBytes = []byte(v)
	case []byte:
		contentType = "application/octet-stream"
		canonicalBytes = v
	default:
		// Default to JSON for structured data
		contentType = "application/json"
		canonicalBytes, err = JCS(v)
		if err != nil {
			return nil, fmt.Errorf("failed to canonicalize as JSON: %w", err)
		}
	}

	digest := ComputeArtifactHash(canonicalBytes)
	preview := generatePreview(canonicalBytes)

	return &interfaces.Artifact{
		SchemaID:       schemaID,
		ContentType:    contentType,
		CanonicalBytes: canonicalBytes,
		Digest:         digest,
		Preview:        preview,
		Metadata:       make(map[string]string),
	}, nil
}

// ComputeArtifactHash returns the SHA-256 multihash of the canonical bytes.
func ComputeArtifactHash(data []byte) string {
	hash := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(hash[:])
}

// generatePreview creates a deterministic, truncated preview of the content.
func generatePreview(data []byte) string {
	const maxPreviewLen = 50
	if len(data) <= maxPreviewLen {
		return string(data)
	}
	// Simple truncation for now. In production, might want context-aware logic
	// (e.g. valid JSON prefix) but raw byte truncation is deterministic.
	return string(data[:maxPreviewLen]) + "..."
}

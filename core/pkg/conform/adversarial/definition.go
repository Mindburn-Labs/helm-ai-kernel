package adversarial

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// DetectorRevision is bumped whenever mandatory adversarial detector semantics
// change. The executable digest remains the exact implementation identity;
// this revision gives downstream policy a stable compatibility key.
const DetectorRevision = "kernel-adversarial-detectors/v1.2.0"

// DefinitionDigest binds the ordered mandatory suite catalog and semantic
// revision into campaign provenance.
func DefinitionDigest() (string, error) {
	type definition struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	suites := AllSuites()
	definitions := make([]definition, 0, len(suites))
	for _, suite := range suites {
		definitions = append(definitions, definition{ID: suite.ID, Name: suite.Name})
	}
	payload, err := canonicalize.JCS(map[string]any{
		"revision": DetectorRevision,
		"suites":   definitions,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

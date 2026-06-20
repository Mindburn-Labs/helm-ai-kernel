package modelcatalog

import "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"

// hashCanonical returns a deterministic "sha256:"-prefixed digest over the JCS
// (RFC 8785) canonical form of value, matching the repo-wide canonicalization
// discipline used by EvidencePacks and ProofGraph.
func hashCanonical(value any) string {
	h, err := canonicalize.CanonicalHash(value)
	if err != nil {
		return ""
	}
	return "sha256:" + h
}

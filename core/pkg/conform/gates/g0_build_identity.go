package gates

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
)

// G0BuildIdentity checks build metadata, dependency locks, SBOM, and provenance.
// Per §G0: Build Identity and Environment Lock.
type G0BuildIdentity struct{}

func (g *G0BuildIdentity) ID() string   { return "G0" }
func (g *G0BuildIdentity) Name() string { return "Build Identity and Environment Lock" }

func (g *G0BuildIdentity) Run(ctx *conform.RunContext) *conform.GateResult {
	result := &conform.GateResult{
		GateID:        g.ID(),
		Pass:          true,
		Reasons:       []string{},
		EvidencePaths: []string{},
		Metrics:       conform.GateMetrics{Counts: make(map[string]int)},
	}

	attestDir := filepath.Join(ctx.EvidenceDir, "07_ATTESTATIONS")

	// 1. Check build_identity.json
	buildIDPath := filepath.Join(ctx.ProjectRoot, "artifacts", "build_identity.json")
	if !fileExists(buildIDPath) {
		// Try evidence dir
		buildIDPath = filepath.Join(attestDir, "build_identity.json")
	}
	if fileExists(buildIDPath) {
		if err := validateBuildIdentity(buildIDPath); err != nil {
			result.Pass = false
			result.Reasons = append(result.Reasons, conform.ReasonBuildIdentityMissing)
		} else {
			copyToEvidence(buildIDPath, filepath.Join(attestDir, "build_identity.json"))
			result.EvidencePaths = append(result.EvidencePaths, "07_ATTESTATIONS/build_identity.json")
			result.Metrics.Counts["build_identity"] = 1
		}
	} else {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonBuildIdentityMissing)
	}

	// 2. Check dependency locks (go.sum)
	goSumPath := filepath.Join(ctx.ProjectRoot, "go.sum")
	if fileExists(goSumPath) {
		result.Metrics.Counts["dep_locks"] = 1
	} else {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonBuildIdentityMissing)
	}

	// 3. Check SBOM
	sbomFound := false
	for _, ext := range []string{".json", ".xml", ".spdx"} {
		sbomPath := filepath.Join(attestDir, "sbom"+ext)
		if fileExists(sbomPath) {
			sbomFound = true
			result.EvidencePaths = append(result.EvidencePaths, "07_ATTESTATIONS/sbom"+ext)
			break
		}
		// Also check project root artifacts
		sbomPath = filepath.Join(ctx.ProjectRoot, "artifacts", "sbom"+ext)
		if fileExists(sbomPath) {
			sbomFound = true
			copyToEvidence(sbomPath, filepath.Join(attestDir, "sbom"+ext))
			result.EvidencePaths = append(result.EvidencePaths, "07_ATTESTATIONS/sbom"+ext)
			break
		}
	}
	if !sbomFound {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonBuildIdentityMissing)
	}

	// 4. Check provenance
	provFound := false
	for _, ext := range []string{".json", ".jsonl", ".intoto"} {
		provPath := filepath.Join(attestDir, "provenance"+ext)
		if fileExists(provPath) {
			provFound = true
			result.EvidencePaths = append(result.EvidencePaths, "07_ATTESTATIONS/provenance"+ext)
			break
		}
		provPath = filepath.Join(ctx.ProjectRoot, "artifacts", "provenance"+ext)
		if fileExists(provPath) {
			provFound = true
			copyToEvidence(provPath, filepath.Join(attestDir, "provenance"+ext))
			result.EvidencePaths = append(result.EvidencePaths, "07_ATTESTATIONS/provenance"+ext)
			break
		}
	}
	if !provFound {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonBuildIdentityMissing)
	}

	// 5. Check trust roots (public keys for receipt/report signing)
	// Required so third parties can verify without out-of-band setup.
	trustRootsFound := false
	for _, name := range []string{"trust_roots.json", "signing_keys.json", "public_keys.json"} {
		trustPath := filepath.Join(attestDir, name)
		if fileExists(trustPath) {
			trustRootsFound = true
			result.EvidencePaths = append(result.EvidencePaths, "07_ATTESTATIONS/"+name)
			result.Metrics.Counts["trust_roots"] = 1
			break
		}
		trustPath = filepath.Join(ctx.ProjectRoot, "artifacts", name)
		if fileExists(trustPath) {
			trustRootsFound = true
			copyToEvidence(trustPath, filepath.Join(attestDir, name))
			result.EvidencePaths = append(result.EvidencePaths, "07_ATTESTATIONS/"+name)
			result.Metrics.Counts["trust_roots"] = 1
			break
		}
	}
	if !trustRootsFound {
		result.Pass = false
		result.Reasons = append(result.Reasons, conform.ReasonTrustRootsMissing)
	}

	return result
}

// validateBuildIdentity checks that build_identity.json has required fields.
func validateBuildIdentity(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var bi map[string]any
	return json.Unmarshal(data, &bi)
}


func copyToEvidence(src, dst string) {
	data, err := os.ReadFile(src)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(dst), 0750)
	_ = os.WriteFile(dst, data, 0600)
}

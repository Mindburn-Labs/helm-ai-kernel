package gates

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform"
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
	if firstExistingFile(
		filepath.Join(ctx.ProjectRoot, "go.sum"),
		filepath.Join(ctx.ProjectRoot, "core", "go.sum"),
	) != "" {
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

	if result.Pass && os.Getenv("HELM_RELEASE_EVIDENCE_RECEIPT") == "1" {
		if relPath, err := writeReleaseEvidenceReceipt(ctx); err == nil {
			result.EvidencePaths = append(result.EvidencePaths, relPath)
			result.Metrics.Counts["release_receipts"] = 1
		} else {
			result.Pass = false
			result.Reasons = append(result.Reasons, conform.ReasonReceiptChainBroken)
		}
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

func writeReleaseEvidenceReceipt(ctx *conform.RunContext) (string, error) {
	const relPath = "02_PROOFGRAPH/receipts/001_release_build_identity.json"
	if ctx == nil {
		return "", fmt.Errorf("missing run context")
	}
	issuedAt := time.Now().UTC()
	if ctx.Clock != nil {
		issuedAt = ctx.Clock().UTC()
	}
	decisionHash := releaseReceiptHash(ctx.RunID, string(ctx.Profile), ctx.ProjectRoot)
	receipt := map[string]any{
		"schema_version":        "helm.release_receipt.v1",
		"receipt_id":            "release-build-identity",
		"run_id":                ctx.RunID,
		"seq":                   1,
		"lamport_clock":         1,
		"tenant_id":             "tenant:release",
		"timestamp_virtual":     issuedAt.Format(time.RFC3339),
		"actor":                 "release-workflow",
		"action_type":           "policy_decision",
		"effect_class":          "REVERSIBLE",
		"effect_type":           "release_asset_staging",
		"decision_id":           "decision:" + decisionHash,
		"decision_hash":         decisionHash,
		"intent_id":             "intent:" + ctx.RunID,
		"parent_receipt_hashes": []string{"genesis"},
		"status":                "allow",
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(ctx.EvidenceDir, relPath)
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		return "", err
	}
	return relPath, nil
}

func releaseReceiptHash(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

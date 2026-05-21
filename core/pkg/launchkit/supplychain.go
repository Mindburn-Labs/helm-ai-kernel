package launchkit

import (
	"fmt"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
)

type SupplyChainReport struct {
	ArtifactDigestVerified bool     `json:"artifact_digest_verified"`
	SignatureVerified      bool     `json:"signature_verified"`
	SBOMVerified           bool     `json:"sbom_verified"`
	ScanVerified           bool     `json:"scan_verified"`
	PromotionVerified      bool     `json:"promotion_verified"`
	ReasonCode             string   `json:"reason_code,omitempty"`
	Checks                 []string `json:"checks"`
}

func VerifySupplyChain(app registry.AppSpec) SupplyChainReport {
	report := SupplyChainReport{Checks: []string{}}
	imageDigest := digestFromImage(app.Install.Image)
	if app.Install.Image == "" || imageDigest == "" || app.Install.Digest == "" || imageDigest != app.Install.Digest {
		return report.withReason("ERR_LAUNCHKIT_ARTIFACT_DIGEST_NOT_PINNED")
	}
	report.ArtifactDigestVerified = true
	report.Checks = append(report.Checks, "image digest is pinned and matches install digest")

	evidence := app.SupplyChainEvidence
	if evidence.ArtifactDigest != app.Install.Digest {
		return report.withReason("ERR_LAUNCHKIT_ARTIFACT_DIGEST_MISMATCH")
	}
	report.Checks = append(report.Checks, "supply-chain evidence digest matches install digest")

	if strings.ToLower(evidence.SignatureTool) != "cosign" || evidence.SignatureRef == "" || !strings.Contains(evidence.SignatureRef, app.Install.Digest) {
		return report.withReason("ERR_LAUNCHKIT_COSIGN_SIGNATURE_REQUIRED")
	}
	report.SignatureVerified = true
	report.Checks = append(report.Checks, "cosign signature ref is bound to the pinned digest")

	if strings.ToLower(evidence.SBOMTool) != "syft" || evidence.SBOMRef == "" {
		return report.withReason("ERR_LAUNCHKIT_SBOM_REQUIRED")
	}
	report.SBOMVerified = true
	report.Checks = append(report.Checks, "syft SBOM ref is present")

	scanTool := strings.ToLower(evidence.VulnerabilityScanTool)
	if (scanTool != "grype" && scanTool != "trivy") || evidence.VulnerabilityScanRef == "" {
		return report.withReason("ERR_LAUNCHKIT_VULNERABILITY_SCAN_REQUIRED")
	}
	report.ScanVerified = true
	report.Checks = append(report.Checks, "vulnerability scan ref is present")

	if err := verifyPromotionEvidence(app.PromotionEvidence); err != nil {
		return report.withReason("ERR_LAUNCHKIT_PROMOTION_EVIDENCE_MISMATCH")
	}
	report.PromotionVerified = true
	report.Checks = append(report.Checks, "promotion evidence refs are tied to one workflow run")
	return report
}

func (r SupplyChainReport) withReason(reason string) SupplyChainReport {
	r.ReasonCode = reason
	return r
}

func digestFromImage(image string) string {
	index := strings.LastIndex(image, "@sha256:")
	if index < 0 {
		return ""
	}
	return "sha256:" + image[index+len("@sha256:"):]
}

func verifyPromotionEvidence(e registry.PromotionEvidenceSpec) error {
	refs := []string{
		e.ArtifactVerificationRef,
		e.LiveE2ERunID,
		e.EvidencePackRef,
		e.TeardownReceiptRef,
	}
	var workflow string
	for _, ref := range refs {
		if ref == "" {
			return fmt.Errorf("promotion evidence ref missing")
		}
		parts := strings.Split(ref, "/")
		if len(parts) < 3 || !strings.HasPrefix(parts[0], "github-actions:") {
			return fmt.Errorf("promotion evidence ref is not a github-actions ref: %s", ref)
		}
		current := strings.TrimPrefix(parts[0], "github-actions:") + "/" + parts[2]
		if workflow == "" {
			workflow = current
			continue
		}
		if workflow != current {
			return fmt.Errorf("promotion evidence refs are not tied to one workflow run")
		}
	}
	return nil
}

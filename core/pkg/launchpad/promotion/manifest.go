package promotion

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	"gopkg.in/yaml.v3"
)

const ManifestSchemaVersion = "helm.launchpad.artifacts.v1"

var promotableApps = map[string]struct{}{
	"openclaw": {},
	"hermes":   {},
	"opencode": {},
	"kilocode": {},
}

type Manifest struct {
	SchemaVersion    string          `json:"schema_version"`
	GeneratedAt      string          `json:"generated_at"`
	GitHubRunID      string          `json:"github_run_id,omitempty"`
	GitHubRunAttempt string          `json:"github_run_attempt,omitempty"`
	SourceSHA        string          `json:"source_sha,omitempty"`
	SourceTreeSHA256 string          `json:"source_tree_sha256,omitempty"`
	WorkflowRef      string          `json:"workflow_ref,omitempty"`
	SubjectName      string          `json:"subject_name,omitempty"`
	SubjectDigest    string          `json:"subject_digest,omitempty"`
	ManifestHash     string          `json:"manifest_hash,omitempty"`
	EgressProxy      *EgressProxy    `json:"egress_proxy,omitempty"`
	Artifacts        []ArtifactEntry `json:"artifacts"`
}

type EgressProxy struct {
	Component               string `json:"component,omitempty"`
	SourceSHA               string `json:"source_sha,omitempty"`
	SourceTreeSHA256        string `json:"source_tree_sha256,omitempty"`
	WorkflowRef             string `json:"workflow_ref,omitempty"`
	SubjectName             string `json:"subject_name,omitempty"`
	SubjectDigest           string `json:"subject_digest,omitempty"`
	Image                   string `json:"image"`
	Digest                  string `json:"digest"`
	SignatureTool           string `json:"signature_tool"`
	SignatureRef            string `json:"signature_ref"`
	SBOMTool                string `json:"sbom_tool"`
	SBOMRef                 string `json:"sbom_ref"`
	VulnerabilityScanTool   string `json:"vulnerability_scan_tool"`
	VulnerabilityScanRef    string `json:"vulnerability_scan_ref"`
	VulnerabilityScanStatus string `json:"vulnerability_scan_status"`
	ProvenanceRef           string `json:"provenance_ref"`
}

type ArtifactEntry struct {
	AppID                   string       `json:"app_id"`
	AppVersion              string       `json:"app_version"`
	SourceSHA               string       `json:"source_sha,omitempty"`
	SourceTreeSHA256        string       `json:"source_tree_sha256,omitempty"`
	WorkflowRef             string       `json:"workflow_ref,omitempty"`
	SubjectName             string       `json:"subject_name,omitempty"`
	SubjectDigest           string       `json:"subject_digest,omitempty"`
	UpstreamRepo            string       `json:"upstream_repo"`
	UpstreamRef             string       `json:"upstream_ref"`
	UpstreamCommit          string       `json:"upstream_commit"`
	LicenseSPDX             string       `json:"license_spdx"`
	LicenseRef              string       `json:"license_ref"`
	Redistribution          string       `json:"redistribution"`
	Image                   string       `json:"image"`
	Digest                  string       `json:"digest"`
	SignatureTool           string       `json:"signature_tool"`
	SignatureRef            string       `json:"signature_ref"`
	SBOMTool                string       `json:"sbom_tool"`
	SBOMRef                 string       `json:"sbom_ref"`
	VulnerabilityScanTool   string       `json:"vulnerability_scan_tool"`
	VulnerabilityScanRef    string       `json:"vulnerability_scan_ref"`
	VulnerabilityScanStatus string       `json:"vulnerability_scan_status"`
	ProvenanceRef           string       `json:"provenance_ref"`
	ArtifactVerificationRef string       `json:"artifact_verification_ref,omitempty"`
	LiveE2ERunID            string       `json:"live_e2e_run_id,omitempty"`
	EvidencePackRef         string       `json:"evidence_pack_ref,omitempty"`
	TeardownReceiptRef      string       `json:"teardown_receipt_ref,omitempty"`
	EgressProxy             *EgressProxy `json:"-"`
}

type EvidenceRefs struct {
	ArtifactVerificationRef string `json:"artifact_verification_ref"`
	LiveE2ERunID            string `json:"live_e2e_run_id"`
	EvidencePackRef         string `json:"evidence_pack_ref"`
	TeardownReceiptRef      string `json:"teardown_receipt_ref"`
}

func LoadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return Manifest{}, err
	}
	if manifest.SchemaVersion != ManifestSchemaVersion {
		return Manifest{}, fmt.Errorf("unsupported launchpad artifact manifest schema %q", manifest.SchemaVersion)
	}
	if len(manifest.Artifacts) == 0 {
		return Manifest{}, errors.New("launchpad artifact manifest has no artifacts")
	}
	return manifest, nil
}

func (m Manifest) Hash() (string, error) {
	clone := m
	clone.ManifestHash = ""
	data, err := json.Marshal(clone)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (m Manifest) Entry(appID string) (ArtifactEntry, bool) {
	for _, artifact := range m.Artifacts {
		if artifact.AppID == appID {
			if m.EgressProxy != nil && m.EgressProxy.Image != "" {
				proxy := *m.EgressProxy
				artifact.EgressProxy = &proxy
			}
			return artifact, true
		}
	}
	return ArtifactEntry{}, false
}

func ValidateArtifact(entry ArtifactEntry) error {
	if _, ok := promotableApps[entry.AppID]; !ok {
		return fmt.Errorf("app %s is not eligible for OSS Launchpad promotion", entry.AppID)
	}
	if entry.AppVersion == "" || entry.UpstreamRepo == "" || entry.UpstreamRef == "" || entry.UpstreamCommit == "" {
		return fmt.Errorf("app %s artifact manifest is missing pinned upstream identity", entry.AppID)
	}
	if strings.ToUpper(entry.LicenseSPDX) != "MIT" {
		return fmt.Errorf("app %s artifact manifest has unsupported license %q", entry.AppID, entry.LicenseSPDX)
	}
	if !strings.Contains(strings.ToLower(entry.Redistribution), "allowed") {
		return fmt.Errorf("app %s artifact manifest does not record redistribution allowance", entry.AppID)
	}
	if !registryDigest(entry.Digest) {
		return fmt.Errorf("app %s artifact manifest digest must be sha256:<64 lowercase hex>", entry.AppID)
	}
	if !strings.Contains(entry.Image, "@"+entry.Digest) {
		return fmt.Errorf("app %s artifact manifest image must be immutable image@%s", entry.AppID, entry.Digest)
	}
	if err := validateSubjectBinding("app "+entry.AppID, entry.Image, entry.Digest, entry.SubjectName, entry.SubjectDigest); err != nil {
		return err
	}
	if strings.ToLower(entry.SignatureTool) != "cosign" || entry.SignatureRef == "" {
		return fmt.Errorf("app %s artifact manifest requires cosign signature evidence", entry.AppID)
	}
	if strings.ToLower(entry.SBOMTool) != "syft" || entry.SBOMRef == "" {
		return fmt.Errorf("app %s artifact manifest requires syft SBOM evidence", entry.AppID)
	}
	switch strings.ToLower(entry.VulnerabilityScanTool) {
	case "grype", "trivy":
		if entry.VulnerabilityScanRef == "" {
			return fmt.Errorf("app %s artifact manifest requires vulnerability scan evidence", entry.AppID)
		}
	default:
		return fmt.Errorf("app %s artifact manifest requires grype or trivy vulnerability scan evidence", entry.AppID)
	}
	if strings.EqualFold(entry.VulnerabilityScanStatus, "failed") {
		return fmt.Errorf("app %s vulnerability scan failed and cannot be promoted", entry.AppID)
	}
	if entry.ProvenanceRef == "" {
		return fmt.Errorf("app %s artifact manifest requires provenance ref", entry.AppID)
	}
	return nil
}

func ValidateEgressProxyArtifact(proxy EgressProxy) error {
	if proxy.Image == "" || proxy.Digest == "" || proxy.SignatureRef == "" || proxy.SBOMRef == "" || proxy.VulnerabilityScanRef == "" {
		return errors.New("egress proxy artifact must declare image, digest, signature, SBOM, and vulnerability scan refs")
	}
	if proxy.Component != "" && proxy.Component != "egress-proxy" {
		return fmt.Errorf("egress proxy artifact has unexpected component %q", proxy.Component)
	}
	if !registryDigest(proxy.Digest) {
		return fmt.Errorf("egress proxy artifact digest must be sha256:<64 lowercase hex>")
	}
	if !strings.Contains(proxy.Image, "@"+proxy.Digest) {
		return fmt.Errorf("egress proxy artifact image must be immutable image@%s", proxy.Digest)
	}
	if err := validateSubjectBinding("egress proxy", proxy.Image, proxy.Digest, proxy.SubjectName, proxy.SubjectDigest); err != nil {
		return err
	}
	if strings.ToLower(proxy.SignatureTool) != "cosign" {
		return fmt.Errorf("egress proxy artifact requires cosign signature evidence")
	}
	if strings.ToLower(proxy.SBOMTool) != "syft" {
		return fmt.Errorf("egress proxy artifact requires syft SBOM evidence")
	}
	switch strings.ToLower(proxy.VulnerabilityScanTool) {
	case "grype", "trivy":
	default:
		return fmt.Errorf("egress proxy artifact requires grype or trivy vulnerability scan evidence")
	}
	if strings.EqualFold(proxy.VulnerabilityScanStatus, "failed") {
		return fmt.Errorf("egress proxy vulnerability scan failed and cannot be promoted")
	}
	if proxy.ProvenanceRef == "" {
		return fmt.Errorf("egress proxy artifact requires provenance ref")
	}
	return nil
}

func (m Manifest) EvidenceRefsFor(entry ArtifactEntry, overrides EvidenceRefs) (EvidenceRefs, error) {
	refs := EvidenceRefs{
		ArtifactVerificationRef: firstNonEmpty(overrides.ArtifactVerificationRef, entry.ArtifactVerificationRef),
		LiveE2ERunID:            firstNonEmpty(overrides.LiveE2ERunID, entry.LiveE2ERunID),
		EvidencePackRef:         firstNonEmpty(overrides.EvidencePackRef, entry.EvidencePackRef),
		TeardownReceiptRef:      firstNonEmpty(overrides.TeardownReceiptRef, entry.TeardownReceiptRef),
	}
	if refs.ArtifactVerificationRef == "" || refs.LiveE2ERunID == "" || refs.EvidencePackRef == "" || refs.TeardownReceiptRef == "" {
		return refs, errors.New("promotion manifest requires artifact verification, live e2e, EvidencePack, and teardown receipt refs")
	}
	if m.GitHubRunID != "" {
		runToken := "github-actions://" + m.GitHubRunID
		for name, ref := range map[string]string{
			"artifact_verification_ref": refs.ArtifactVerificationRef,
			"live_e2e_run_id":           refs.LiveE2ERunID,
			"evidence_pack_ref":         refs.EvidencePackRef,
			"teardown_receipt_ref":      refs.TeardownReceiptRef,
		} {
			if !strings.Contains(ref, runToken) {
				return refs, fmt.Errorf("promotion %s must be tied to current workflow run %s", name, m.GitHubRunID)
			}
		}
	}
	return refs, nil
}

func Promote(app registry.AppSpec, entry ArtifactEntry, refs EvidenceRefs) (registry.AppSpec, error) {
	if app.ID != entry.AppID {
		return registry.AppSpec{}, fmt.Errorf("artifact app %s does not match spec app %s", entry.AppID, app.ID)
	}
	if err := ValidateArtifact(entry); err != nil {
		return registry.AppSpec{}, err
	}
	if refs.ArtifactVerificationRef == "" || refs.LiveE2ERunID == "" || refs.EvidencePackRef == "" || refs.TeardownReceiptRef == "" {
		return registry.AppSpec{}, errors.New("promotion requires artifact verification, live e2e, EvidencePack, and teardown receipt refs")
	}

	out := app
	out.Version = entry.AppVersion
	out.Availability = registry.AvailabilityOSSSupported
	if out.SupportLevel == "" ||
		out.SupportLevel == registry.SupportLevelVerifyOnly ||
		out.SupportLevel == registry.SupportLevelDemo ||
		out.SupportLevel == registry.SupportLevelBlockedRepairRequired {
		out.SupportLevel = registry.SupportLevelOSSSupported
		if out.FrameworkContract.EgressProxy.Required || out.ModelGateway.LogicalSecret != "" {
			out.SupportLevel = registry.SupportLevelAgentLive
		}
	}
	out.Redistribution = entry.Redistribution
	out.Install.Strategy = "signed_oci"
	out.Install.Image = entry.Image
	out.Install.Digest = entry.Digest
	out.Install.Source = entry.UpstreamRepo
	out.Install.Ref = entry.UpstreamRef
	out.License.Status = "verified"
	out.License.SPDX = entry.LicenseSPDX
	out.License.URL = entry.LicenseRef
	out.SupplyChainEvidence = registry.SupplyChainEvidenceSpec{
		ArtifactDigest:        entry.Digest,
		SignatureTool:         entry.SignatureTool,
		SignatureRef:          entry.SignatureRef,
		SBOMTool:              entry.SBOMTool,
		SBOMRef:               entry.SBOMRef,
		VulnerabilityScanTool: entry.VulnerabilityScanTool,
		VulnerabilityScanRef:  entry.VulnerabilityScanRef,
	}
	if out.FrameworkContract.EgressProxy.Required {
		if entry.EgressProxy == nil {
			return registry.AppSpec{}, errors.New("promotion requires a signed egress proxy artifact for F2 provider-backed apps")
		}
		if err := ValidateEgressProxyArtifact(*entry.EgressProxy); err != nil {
			return registry.AppSpec{}, err
		}
		receiptRef := out.FrameworkContract.EgressProxy.ReceiptRef
		if strings.TrimSpace(receiptRef) == "" {
			receiptRef = "receipts/launchpad-egress-proxy.json"
		}
		out.FrameworkContract.EgressProxy = registry.EgressProxyContractSpec{
			Required:             true,
			Image:                entry.EgressProxy.Image,
			Digest:               entry.EgressProxy.Digest,
			SignatureRef:         entry.EgressProxy.SignatureRef,
			SBOMRef:              entry.EgressProxy.SBOMRef,
			VulnerabilityScanRef: entry.EgressProxy.VulnerabilityScanRef,
			ReceiptRef:           receiptRef,
		}
	}
	out.FrameworkContract.Images = syncFrameworkContractImages(out.FrameworkContract.Images, entry)
	out.PromotionEvidence = registry.PromotionEvidenceSpec{
		ArtifactVerificationRef: refs.ArtifactVerificationRef,
		LiveE2ERunID:            refs.LiveE2ERunID,
		EvidencePackRef:         refs.EvidencePackRef,
		TeardownReceiptRef:      refs.TeardownReceiptRef,
	}
	out.Conformance = registry.ConformanceSpec{
		LicenseVerified:      true,
		ArtifactVerified:     true,
		PolicyPackPresent:    true,
		SandboxVerified:      true,
		HealthcheckPassing:   true,
		E2EPassing:           true,
		TeardownVerified:     true,
		ReceiptVerified:      true,
		EvidencePackVerified: true,
	}
	out.EvidenceRequirements = ensureRequirements(out.EvidenceRequirements, entry.VulnerabilityScanTool)
	if out.Metadata == nil {
		out.Metadata = map[string]string{}
	}
	out.Metadata["upstream_commit"] = entry.UpstreamCommit
	out.Metadata["artifact_workflow_run"] = entry.ProvenanceRef
	out.Metadata["helm_oci_status"] = "promoted_from_signed_ci_artifact_manifest"
	out.Metadata["promotion_provenance_ref"] = entry.ProvenanceRef
	delete(out.Metadata, "blocker")
	return out, nil
}

func WriteAppSpec(path string, app registry.AppSpec) error {
	data, err := yaml.Marshal(app)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func ensureRequirements(existing []string, vulnTool string) []string {
	required := []string{
		"cpi_output",
		"kernel_verdict",
		"sandbox_grant",
		"launch_receipt",
		"install_receipt",
		"healthcheck_receipt",
		"teardown_receipt",
		"evidence_pack",
		"mcp_quarantine",
		"artifact_digest",
		"cosign_signature",
		"syft_sbom",
	}
	switch strings.ToLower(vulnTool) {
	case "trivy":
		required = append(required, "trivy_vulnerability_scan")
	default:
		required = append(required, "grype_vulnerability_scan")
	}
	out := append([]string{}, existing...)
	for _, req := range required {
		found := false
		for _, have := range out {
			if have == req {
				found = true
				break
			}
		}
		if !found {
			out = append(out, req)
		}
	}
	return out
}

func registryDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, ch := range strings.TrimPrefix(value, "sha256:") {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

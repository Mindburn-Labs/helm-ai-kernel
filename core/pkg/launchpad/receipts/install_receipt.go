package receipts

type InstallReceipt struct {
	AppID                       string `json:"app_id"`
	Digest                      string `json:"digest"`
	ArtifactSource              string `json:"artifact_source,omitempty"`
	SignatureVerificationResult string `json:"signature_verification_result,omitempty"`
	InstalledPath               string `json:"installed_path,omitempty"`
	RuntimeImageDigest          string `json:"runtime_image_digest,omitempty"`
	SBOMRef                     string `json:"sbom_ref,omitempty"`
}

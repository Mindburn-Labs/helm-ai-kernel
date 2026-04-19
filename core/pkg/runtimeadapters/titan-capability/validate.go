package titancapability

import (
	"fmt"
	"strings"
)

// ValidateEnvelope is the shared envelope-shape check used by every
// capability adapter. It performs presence + bundle-pin verification only;
// it does NOT verify the Ed25519 signature or the active policy bundle's
// own signature — that is the kernel guardian's job upstream.
//
// Returns one of:
//   - ErrEnvelopeIncomplete (wrapped) when a required field is empty.
//   - ErrPolicyBundleMismatch (wrapped) when the envelope's bundle SHA
//     does not match the kernel's pinned active bundle SHA.
//   - nil on success.
//
// Pure function — safe for hot-path execution. No I/O.
func ValidateEnvelope(env CapabilityEnvelope, activeBundleSHA string) error {
	if strings.TrimSpace(env.PolicyBundleSHA) == "" {
		return fmt.Errorf("%w: policy_bundle_sha is empty", ErrEnvelopeIncomplete)
	}
	if strings.TrimSpace(env.OrganID) == "" {
		return fmt.Errorf("%w: organ_id is empty", ErrEnvelopeIncomplete)
	}
	if strings.TrimSpace(env.SessionID) == "" {
		return fmt.Errorf("%w: session_id is empty", ErrEnvelopeIncomplete)
	}
	if env.SpendCapUSD < 0 {
		return fmt.Errorf("%w: spend_cap_usd is negative", ErrEnvelopeIncomplete)
	}
	if env.RetentionDays < 0 {
		return fmt.Errorf("%w: retention_days is negative", ErrEnvelopeIncomplete)
	}
	switch env.Mode {
	case ModePaper, ModeShadow, ModeLive:
	default:
		return fmt.Errorf("%w: mode is not paper|shadow|live", ErrEnvelopeIncomplete)
	}
	if activeBundleSHA != "" && env.PolicyBundleSHA != activeBundleSHA {
		return fmt.Errorf(
			"%w: envelope bundle %q != kernel active bundle %q",
			ErrPolicyBundleMismatch, env.PolicyBundleSHA, activeBundleSHA,
		)
	}
	return nil
}

// ValidateEvidencePack checks that an EvidencePackHeader has every
// required field populated and that ArtifactKind is in the adapter's
// allow-list. Adapters that gate learned-artefact promotion (model_change,
// factor_promote, data_source_activate) MUST call this before issuing
// an ALLOW verdict.
//
// Pure function — safe for hot-path execution. No I/O.
func ValidateEvidencePack(header EvidencePackHeader, allowedKinds []string) error {
	if !strings.HasPrefix(header.ArtifactSHA, "sha256:") {
		return fmt.Errorf("%w: artifact_sha must be sha256:<hex>", ErrEvidencePackInvalid)
	}
	if !strings.HasPrefix(header.LineageSHA, "sha256:") {
		return fmt.Errorf("%w: lineage_sha must be sha256:<hex>", ErrEvidencePackInvalid)
	}
	if !strings.HasPrefix(header.PolicyBundleSHA, "sha256:") {
		return fmt.Errorf("%w: policy_bundle_sha must be sha256:<hex>", ErrEvidencePackInvalid)
	}
	if !strings.HasPrefix(header.Signature, "ed25519:") {
		return fmt.Errorf("%w: signature must be ed25519:<hex>", ErrEvidencePackInvalid)
	}
	if header.ArtifactKind == "" {
		return fmt.Errorf("%w: artifact_kind is empty", ErrEvidencePackInvalid)
	}
	if header.ValidationReportSHA != "" && !strings.HasPrefix(header.ValidationReportSHA, "sha256:") {
		return fmt.Errorf("%w: validation_report_sha, when set, must be sha256:<hex>", ErrEvidencePackInvalid)
	}
	for _, k := range allowedKinds {
		if header.ArtifactKind == k {
			return nil
		}
	}
	return fmt.Errorf(
		"%w: artifact_kind %q not in allow-list %v",
		ErrUnknownArtifactKind, header.ArtifactKind, allowedKinds,
	)
}

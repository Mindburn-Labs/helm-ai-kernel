package evidence

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	proofanchor "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph/anchor"
)

// These statuses describe external proof checks, independently of seal signatures.
const (
	externalProofNotChecked   = "not-checked"
	externalProofUnverifiable = "unverifiable"
)

func createEvidenceAnchorReceipts(ctx context.Context, subjectRoot string, cfg *EvidencePackTrustConfig, anchor EvidencePackSealAnchor) ([]proofanchor.AnchorReceipt, error) {
	anchorType := strings.ToLower(strings.TrimSpace(firstNonEmpty(anchor.Type, anchorTypeFromConfig(cfg))))
	switch anchorType {
	case "", "local-dev":
		return nil, nil
	case "rekor", "rekor-v2":
		var opts []proofanchor.RekorOption
		if endpoint := anchorEndpoint(anchor, cfg); endpoint != "" {
			opts = append(opts, proofanchor.WithRekorURL(strings.TrimRight(endpoint, "/")))
		}
		return anchorEvidenceRoot(ctx, proofanchor.NewRekorBackend(opts...), subjectRoot)
	case "rfc3161":
		endpoint := anchorEndpoint(anchor, cfg)
		if endpoint == "" {
			return nil, errors.New("rfc3161 anchor URL is required")
		}
		return anchorEvidenceRoot(ctx, proofanchor.NewRFC3161Backend(endpoint), subjectRoot)
	default:
		return nil, fmt.Errorf("unsupported evidence anchor %q", anchorType)
	}
}

func anchorEvidenceRoot(ctx context.Context, backend proofanchor.AnchorBackend, subjectRoot string) ([]proofanchor.AnchorReceipt, error) {
	receipt, err := backend.Anchor(ctx, proofanchor.AnchorRequest{
		MerkleRoot:  subjectRoot,
		FromLamport: 0,
		ToLamport:   0,
		NodeCount:   0,
		HeadNodeIDs: []string{subjectRoot},
		Timestamp:   time.Now().UTC(),
	})
	if err != nil {
		return nil, err
	}
	return []proofanchor.AnchorReceipt{*receipt}, nil
}

func verifyEvidenceAnchorReceipts(ctx context.Context, seal EvidencePackSeal, cfg *EvidencePackTrustConfig, profile EvidenceTrustProfile) (string, []string) {
	profile = NormalizeEvidenceTrustProfile(profile)
	if len(seal.AnchorReceipts) == 0 {
		if !profileRequiresExternalTrust(profile) {
			return "local-only", nil
		}
		return "missing", []string{fmt.Sprintf("%s profile requires external anchor receipt", profile)}
	}
	for i := range seal.AnchorReceipts {
		if seal.AnchorReceipts[i].Request.MerkleRoot != seal.MerkleRoot {
			return "invalid", []string{"anchor receipt subject root mismatch"}
		}
	}
	if !profileRequiresExternalTrust(profile) {
		// Optional external evidence is retained, but no external check ran.
		return externalProofNotChecked, nil
	}
	var errs []string
	for i := range seal.AnchorReceipts {
		if err := verifyEvidenceAnchorReceipt(ctx, &seal.AnchorReceipts[i], cfg); err != nil {
			errs = append(errs, err.Error())
			if !errors.Is(err, proofanchor.ErrVerificationUnavailable) {
				return "invalid", errs
			}
		}
	}
	if len(errs) > 0 {
		return externalProofUnverifiable, errs
	}
	return "verified-externally", nil
}

func verifyEvidenceAnchorReceipt(ctx context.Context, receipt *proofanchor.AnchorReceipt, cfg *EvidencePackTrustConfig) error {
	if receipt.Backend != "rekor-v2" && receipt.Backend != "rfc3161" {
		return fmt.Errorf("unsupported anchor backend %q", receipt.Backend)
	}
	// Only verifier-owned configuration can select the backend and endpoint.
	// Neither the receipt backend nor its LogID is a trust root.
	configuredBackend := strings.ToLower(strings.TrimSpace(anchorTypeFromConfig(cfg)))
	if configuredBackend == "rekor" {
		configuredBackend = "rekor-v2"
	}
	if configuredBackend == "" || configuredBackend == "local-dev" {
		return fmt.Errorf("%w: external anchor backend is not configured; signature and trust NOT CHECKED", proofanchor.ErrVerificationUnavailable)
	}
	if receipt.Backend != configuredBackend {
		return fmt.Errorf("anchor receipt backend %q does not match configured backend %q", receipt.Backend, configuredBackend)
	}
	endpoint := strings.TrimSpace(anchorEndpoint(EvidencePackSealAnchor{}, cfg))
	if endpoint == "" {
		return fmt.Errorf("%w: external anchor URL is not configured; signature and trust NOT CHECKED", proofanchor.ErrVerificationUnavailable)
	}
	switch configuredBackend {
	case "rekor-v2":
		return proofanchor.NewRekorBackend(proofanchor.WithRekorURL(strings.TrimRight(endpoint, "/"))).Verify(ctx, receipt)
	case "rfc3161":
		return proofanchor.NewRFC3161Backend(endpoint).Verify(ctx, receipt)
	default:
		return fmt.Errorf("unsupported configured anchor backend %q", configuredBackend)
	}
}

func anchorTypeFromConfig(cfg *EvidencePackTrustConfig) string {
	if cfg == nil {
		return ""
	}
	return cfg.Anchor.Type
}

func anchorEndpoint(anchor EvidencePackSealAnchor, cfg *EvidencePackTrustConfig) string {
	if anchor.URL != "" || anchor.URI != "" {
		return firstNonEmpty(anchor.URL, anchor.URI)
	}
	if cfg == nil {
		return ""
	}
	return firstNonEmpty(cfg.Anchor.URL, cfg.Anchor.URI)
}

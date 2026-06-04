package evidence

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	proofanchor "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph/anchor"
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
		receipt := &seal.AnchorReceipts[i]
		if receipt.Request.MerkleRoot != seal.MerkleRoot {
			return "invalid", []string{"anchor receipt subject root mismatch"}
		}
		if profileRequiresExternalTrust(profile) {
			if err := verifyEvidenceAnchorReceipt(ctx, receipt, cfg); err != nil {
				return "invalid", []string{err.Error()}
			}
		}
	}
	return "verified-externally", nil
}

func verifyEvidenceAnchorReceipt(ctx context.Context, receipt *proofanchor.AnchorReceipt, cfg *EvidencePackTrustConfig) error {
	switch receipt.Backend {
	case "rekor-v2":
		var opts []proofanchor.RekorOption
		if endpoint := anchorEndpoint(EvidencePackSealAnchor{}, cfg); endpoint != "" {
			opts = append(opts, proofanchor.WithRekorURL(strings.TrimRight(endpoint, "/")))
		}
		return proofanchor.NewRekorBackend(opts...).Verify(ctx, receipt)
	case "rfc3161":
		endpoint := firstNonEmpty(anchorEndpoint(EvidencePackSealAnchor{}, cfg), receipt.LogID)
		if endpoint == "" {
			return errors.New("rfc3161 anchor URL is required")
		}
		return proofanchor.NewRFC3161Backend(endpoint).Verify(ctx, receipt)
	default:
		return fmt.Errorf("unsupported anchor backend %q", receipt.Backend)
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

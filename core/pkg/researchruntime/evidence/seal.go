package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/evidencepack"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
)

// SealInput carries all evidence to be sealed into a pack and receipt.
type SealInput struct {
	MissionID        string
	Sources          []researchruntime.SourceSnapshot
	Models           []researchruntime.ModelManifest
	Tools            []researchruntime.ToolInvocationManifest
	ArtifactHash     string
	PolicyBundleHash string
	Score            float64
}

// Seal creates an EvidencePack and PromotionReceipt from the mission's evidence.
// Uses evidencepack.Builder for pack construction and
// researchruntime.BuildPromotionReceipt for receipt hashing.
func Seal(_ context.Context, input SealInput) (*researchruntime.EvidencePack, *researchruntime.PromotionReceipt, error) {
	packID := uuid.NewString()

	// Use evidencepack.Builder to construct the pack.
	// actorDID="research-runtime", intentID=missionID, policyHash=PolicyBundleHash.
	builder := evidencepack.NewBuilder(packID, "research-runtime", input.MissionID, input.PolicyBundleHash)

	// Add source manifests.
	for i, s := range input.Sources {
		data, err := json.Marshal(s)
		if err != nil {
			continue
		}
		path := fmt.Sprintf("sources/%s.json", s.SourceID)
		if s.SourceID == "" {
			path = fmt.Sprintf("sources/source-%d.json", i)
		}
		builder.AddRawEntry(path, "application/json", data)
	}

	// Add model manifests.
	for i, m := range input.Models {
		data, err := json.Marshal(m)
		if err != nil {
			continue
		}
		// ModelManifest has no ID field; use Stage as the filename key.
		path := fmt.Sprintf("models/%s.json", m.Stage)
		if m.Stage == "" {
			path = fmt.Sprintf("models/model-%d.json", i)
		}
		builder.AddRawEntry(path, "application/json", data)
	}

	// Add tool invocation manifests.
	for i, t := range input.Tools {
		data, err := json.Marshal(t)
		if err != nil {
			continue
		}
		path := fmt.Sprintf("tools/%s.json", t.InvocationID)
		if t.InvocationID == "" {
			path = fmt.Sprintf("tools/tool-%d.json", i)
		}
		builder.AddRawEntry(path, "application/json", data)
	}

	// Builder.Build errors on zero entries — add a sentinel when the pack is empty.
	if len(input.Sources) == 0 && len(input.Models) == 0 && len(input.Tools) == 0 {
		meta := map[string]any{
			"mission_id":         input.MissionID,
			"artifact_hash":      input.ArtifactHash,
			"policy_bundle_hash": input.PolicyBundleHash,
			"score":              input.Score,
			"sealed_at":          time.Now().UTC().Format(time.RFC3339),
		}
		data, _ := json.Marshal(meta)
		builder.AddRawEntry("meta/mission.json", "application/json", data)
	}

	manifest, _, err := builder.Build()
	if err != nil {
		return nil, nil, fmt.Errorf("evidence: build pack: %w", err)
	}

	// Build EvidencePack domain object.
	pack := &researchruntime.EvidencePack{
		PackID:         manifest.PackID,
		MissionID:      input.MissionID,
		SourceManifest: input.Sources,
		ModelManifest:  input.Models,
		ToolManifest:   input.Tools,
		SealedAt:       time.Now(),
	}

	// Set TraceHash using CanonicalHash over the pack.
	traceHash, err := researchruntime.CanonicalHash(pack)
	if err != nil {
		return nil, nil, fmt.Errorf("evidence: trace hash: %w", err)
	}
	pack.TraceHash = traceHash

	// Build promotion receipt.
	receipt := researchruntime.PromotionReceipt{
		ReceiptID:        uuid.NewString(),
		MissionID:        input.MissionID,
		EvidencePackHash: manifest.ManifestHash,
		PublicationState: researchruntime.PublicationStateEligible,
		PolicyDecision:   "ALLOW",
		CreatedAt:        time.Now(),
	}

	// Use existing hash.go to compute ManifestHash (signs the receipt fields).
	sealed, err := researchruntime.BuildPromotionReceipt(receipt)
	if err != nil {
		return nil, nil, fmt.Errorf("evidence: build receipt: %w", err)
	}

	return pack, &sealed, nil
}

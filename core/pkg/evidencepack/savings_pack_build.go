package evidencepack

// quantum_posture: Pack assembly stores receipt and manifest signatures supplied by the configured signer.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// SavingsPackInputs is everything BuildSavingsEvidencePack binds together.
// Artifact byte slices are embedded verbatim so their hashes match the files
// the capture produced.
type SavingsPackInputs struct {
	PackID     string
	ActorDID   string
	RunID      string
	PolicyHash string

	ReceiptSets map[string]SpendReceiptSet
	// ReceiptSignatures holds the issuer's detached signatures per intent, keyed
	// by receipt entry name ("route_quote", "usage", "settlement", and
	// optionally "budget_verdict"). Required for every route_quote/usage/
	// settlement receipt in ReceiptSets.
	ReceiptSignatures map[string]map[string]DetachedSignature

	TaskSplitManifest []byte
	TaskResults       []byte
	ParityResults     []byte
	PriceBookConfig   []byte
	TrustedKeys       []byte

	Profile economic.RedactionProfile
}

// BuildSavingsEvidencePack computes the savings view from the inputs, binds
// receipts, artifacts, and views into a deterministic EvidencePack, and returns
// the manifest, content map, and the computed view.
func BuildSavingsEvidencePack(in SavingsPackInputs) (*Manifest, map[string][]byte, *SavingsView, error) {
	if len(in.TaskSplitManifest) == 0 || len(in.TaskResults) == 0 || len(in.ParityResults) == 0 {
		return nil, nil, nil, errors.New("savings evidence pack: task-split manifest, task results, and parity artifacts are required")
	}
	if len(in.PriceBookConfig) == 0 {
		return nil, nil, nil, errors.New("savings evidence pack: the price-book config snapshot is required")
	}
	if len(in.TrustedKeys) == 0 {
		return nil, nil, nil, errors.New("savings evidence pack: the trusted-key registry is required (offline verification is anchored to it)")
	}
	for intentID, set := range in.ReceiptSets {
		sigs := in.ReceiptSignatures[intentID]
		if set.RouteQuote != nil {
			if _, ok := sigs["route_quote"]; !ok {
				return nil, nil, nil, fmt.Errorf("savings evidence pack: intent %s route quote has no detached signature", intentID)
			}
		}
		if set.Usage != nil {
			if _, ok := sigs["usage"]; !ok {
				return nil, nil, nil, fmt.Errorf("savings evidence pack: intent %s usage receipt has no detached signature", intentID)
			}
		}
		if set.Settlement != nil {
			if _, ok := sigs["settlement"]; !ok {
				return nil, nil, nil, fmt.Errorf("savings evidence pack: intent %s settlement receipt has no detached signature", intentID)
			}
		}
	}

	var man SavingsTaskSplitManifest
	var res SavingsTaskResults
	var par SavingsParityResults
	if err := decodeStrict(in.TaskSplitManifest, &man, "task-split manifest"); err != nil {
		return nil, nil, nil, err
	}
	if err := decodeStrict(in.TaskResults, &res, "task results"); err != nil {
		return nil, nil, nil, err
	}
	if err := decodeStrict(in.ParityResults, &par, "parity pre-run"); err != nil {
		return nil, nil, nil, err
	}
	if err := ValidateSavingsArtifacts(&man, &res, &par); err != nil {
		return nil, nil, nil, err
	}
	if got := HashContent(in.ParityResults); got != man.SelectionFreeze.ParityResultsSHA256 {
		return nil, nil, nil, fmt.Errorf("savings evidence pack: parity artifact hash %s does not match the frozen selection's recorded %s", got, man.SelectionFreeze.ParityResultsSHA256)
	}

	priceBookSHA := HashContent(in.PriceBookConfig)
	for intentID, set := range in.ReceiptSets {
		if set.RouteQuote != nil && set.RouteQuote.ProviderPriceSnapshotHash != priceBookSHA {
			return nil, nil, nil, fmt.Errorf("savings evidence pack: intent %s was quoted on price snapshot %s, not the embedded price book %s", intentID, set.RouteQuote.ProviderPriceSnapshotHash, priceBookSHA)
		}
	}

	view, err := ComputeSavingsView(in.ReceiptSets, &man, &res, in.PriceBookConfig)
	if err != nil {
		return nil, nil, nil, err
	}
	view.SelectionFreeze.TaskSplitManifestSHA256 = HashContent(in.TaskSplitManifest)

	b := NewBuilder(in.PackID, in.ActorDID, in.RunID, in.PolicyHash)
	intentIDs := make([]string, 0, len(in.ReceiptSets))
	for intentID := range in.ReceiptSets {
		intentIDs = append(intentIDs, intentID)
	}
	sort.Strings(intentIDs)
	for _, intentID := range intentIDs {
		set := in.ReceiptSets[intentID]
		prefix := savingsReceiptsPrefix + intentID + "/"
		if set.RouteQuote != nil {
			if err := addJSON(b, prefix+"route_quote.json", set.RouteQuote); err != nil {
				return nil, nil, nil, err
			}
		}
		if set.Budget != nil {
			if err := addJSON(b, prefix+"budget_verdict.json", set.Budget); err != nil {
				return nil, nil, nil, err
			}
		}
		if set.Usage != nil {
			if err := addJSON(b, prefix+"usage.json", set.Usage); err != nil {
				return nil, nil, nil, err
			}
		}
		if set.Settlement != nil {
			if err := addJSON(b, prefix+"settlement.json", set.Settlement); err != nil {
				return nil, nil, nil, err
			}
		}
		if sigs := in.ReceiptSignatures[intentID]; len(sigs) > 0 {
			if err := addJSON(b, prefix+savingsSignaturesName, sigs); err != nil {
				return nil, nil, nil, err
			}
		}
	}

	b.AddRawEntry(savingsTaskSplitPath, "application/json", in.TaskSplitManifest)
	b.AddRawEntry(savingsTaskResultsPath, "application/json", in.TaskResults)
	b.AddRawEntry(savingsParityPath, "application/json", in.ParityResults)
	b.AddRawEntry(savingsPriceBookPath, "application/json", in.PriceBookConfig)
	if len(in.TrustedKeys) > 0 {
		b.AddRawEntry(savingsTrustedKeysPath, "application/json", in.TrustedKeys)
	}
	if err := addJSON(b, savingsViewPath, view); err != nil {
		return nil, nil, nil, err
	}
	if err := addJSON(b, spendRedactionProfilePath, in.Profile); err != nil {
		return nil, nil, nil, err
	}

	manifest, contents, err := b.Build()
	if err != nil {
		return nil, nil, nil, err
	}
	return manifest, contents, view, nil
}

// AttachManifestSignature signs the pack's manifest hash and adds
// manifest.sig.json to the content map. The signature is over the raw ASCII
// bytes of the manifest_hash string; sign is a caller-supplied closure so key
// custody stays with the caller (spend-proxy issuer, test key, HSM). Call it
// AFTER Build — the file is deliberately not a manifest entry.
func AttachManifestSignature(contents map[string][]byte, sign func(payload []byte) (keyID string, signature []byte, err error)) error {
	manifestJSON, ok := contents["manifest.json"]
	if !ok {
		return errors.New("savings evidence: manifest.json missing; build the pack first")
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		return fmt.Errorf("savings evidence: decode manifest for signing: %w", err)
	}
	if manifest.ManifestHash == "" {
		return errors.New("savings evidence: manifest has no hash to sign")
	}
	keyID, sigBytes, err := sign([]byte(manifest.ManifestHash))
	if err != nil {
		return fmt.Errorf("savings evidence: sign manifest hash: %w", err)
	}
	sig := SavingsManifestSignature{
		ManifestHash: manifest.ManifestHash,
		KeyID:        keyID,
		Signature:    base64.StdEncoding.EncodeToString(sigBytes),
	}
	data, err := json.MarshalIndent(&sig, "", "  ")
	if err != nil {
		return fmt.Errorf("savings evidence: marshal manifest signature: %w", err)
	}
	contents[SavingsManifestSigPath] = data
	return nil
}

package decisionreceipt

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidencepack"
)

// ImportOptions controls how an external receipt is imported into an EvidencePack.
type ImportOptions struct {
	FormatID     string    // "" = auto-detect
	PublicKeyHex string    // trusted key; empty caps classification at crypto_compatible_non_conformant
	PackID       string    // EvidencePack id; defaulted from format + receipt id if empty
	Now          time.Time // pack timestamp; left at the builder default if zero
}

// ImportResult is the outcome of importing an external receipt.
type ImportResult struct {
	Report       DecisionReport         `json:"report"`
	PackID       string                 `json:"pack_id"`
	ManifestHash string                 `json:"manifest_hash"`
	MerkleRoot   string                 `json:"entries_merkle_root,omitempty"`
	Entries      []string               `json:"entries"`
	Manifest     *evidencepack.Manifest `json:"-"`
	ContentMap   map[string][]byte      `json:"-"`
}

// ImportReceipt verifies an external decision receipt (or bundle) and re-anchors
// it as a content-addressed, tamper-evident HELM EvidencePack. The pack records
// the verbatim source, the normalized receipts (carrying their classification),
// and a compatibility manifest stating the classification + limitations — so the
// import is never mistaken for HELM-native execution proof.
//
// A receipt that fails verification is still imported (with classification
// "unverified" and report.Verified=false): re-anchoring an unverifiable claim is
// legitimate, honestly-labeled evidence.
func ImportReceipt(raw []byte, opts ImportOptions) (*ImportResult, error) {
	report, err := Default().VerifyBundle(raw, opts.FormatID, opts.PublicKeyHex)
	if err != nil {
		return nil, err
	}

	sourceVendor := ""
	if len(report.Receipts) > 0 {
		sourceVendor = report.Receipts[0].SourceVendor
	}
	packID := opts.PackID
	if packID == "" {
		packID = "external-receipt:" + report.FormatID
		if len(report.Receipts) > 0 {
			packID += ":" + report.Receipts[0].ReceiptID
		}
	}
	actorDID := "external:unknown"
	if sourceVendor != "" {
		actorDID = "external:" + sourceVendor
	}

	b := evidencepack.NewBuilder(packID, actorDID, "", "")
	if !opts.Now.IsZero() {
		b = b.WithCreatedAt(opts.Now)
	}

	if err := b.AddHostEvidence(report.FormatID, "source.json", raw); err != nil {
		return nil, fmt.Errorf("add source: %w", err)
	}
	for i := range report.Receipts {
		name := "external_" + sanitizeName(report.Receipts[i].ReceiptID)
		if name == "external_" {
			name = fmt.Sprintf("external_%d", i)
		}
		if err := b.AddReceipt(name, report.Receipts[i]); err != nil {
			return nil, fmt.Errorf("add receipt: %w", err)
		}
	}

	compat := map[string]any{
		"kind":           report.Kind,
		"format_id":      report.FormatID,
		"classification": report.Classification,
		"verified":       report.Verified,
		"limitations":    []string{"external decision receipt; decision-level proof only — not a HELM verdict-bound execution proof"},
		"checks":         report.Checks,
	}
	compatJSON, err := json.MarshalIndent(compat, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal compatibility manifest: %w", err)
	}
	b.AddRawEntry("compatibility/import_manifest.json", "application/json", compatJSON)

	manifest, contentMap, err := b.Build()
	if err != nil {
		return nil, fmt.Errorf("build evidence pack: %w", err)
	}
	entries := make([]string, 0, len(contentMap))
	for p := range contentMap {
		entries = append(entries, p)
	}
	sort.Strings(entries)

	return &ImportResult{
		Report:       report,
		PackID:       packID,
		ManifestHash: manifest.ManifestHash,
		MerkleRoot:   manifest.EntriesMerkleRoot,
		Entries:      entries,
		Manifest:     manifest,
		ContentMap:   contentMap,
	}, nil
}

// sanitizeName maps a receipt id to a filesystem-safe entry name.
func sanitizeName(id string) string {
	out := make([]rune, 0, len(id))
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

// quantum_posture: export verifies classical Ed25519 receipt signatures via
// the trusted-key registry and re-derives SHA-256 content hashes offline; no
// post-quantum primitives are used in this file.

package spendproxy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidencepack"
)

// ExportResult summarizes one exported spend EvidencePack.
type ExportResult struct {
	SpendIntentID     string   `json:"spend_intent_id"`
	PackID            string   `json:"pack_id"`
	ManifestHash      string   `json:"manifest_hash"`
	ReceiptsVerified  []string `json:"receipts_verified"`
	OfflineVerified   bool     `json:"offline_verified"`
	SignatureVerified bool     `json:"signature_verified"`
	SignatureKeyID    string   `json:"signature_key_id,omitempty"`
	OutputDir         string   `json:"output_dir"`
}

// ExportEvidencePacks reads the durable receipt log, groups receipts by spend
// intent, renders each complete-enough group into a spend EvidencePack via
// core/pkg/evidencepack, verifies every pack OFFLINE, checks the verdict
// signature against the trusted-key registry, and writes the pack contents
// under outDir/<spend_intent_id>/.
//
// intentFilter, when non-empty, exports only that spend intent.
func ExportEvidencePacks(receiptsDir, outDir, intentFilter string) ([]ExportResult, error) {
	records, err := LoadRecords(filepath.Join(receiptsDir, ReceiptLogName))
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("spendproxy: receipt log is empty; nothing to export")
	}
	keys, err := OpenTrustedKeys(receiptsDir)
	if err != nil {
		return nil, err
	}

	type group struct {
		set        evidencepack.SpendReceiptSet
		policyHash string
	}
	groups := make(map[string]*group)
	order := make([]string, 0)
	for _, rec := range records {
		if rec.SpendIntentID == "" {
			continue
		}
		if intentFilter != "" && rec.SpendIntentID != intentFilter {
			continue
		}
		g, ok := groups[rec.SpendIntentID]
		if !ok {
			g = &group{}
			groups[rec.SpendIntentID] = g
			order = append(order, rec.SpendIntentID)
		}
		switch rec.Kind {
		case RecordRouteQuote:
			if rec.RouteQuote != nil {
				g.set.RouteQuote = rec.RouteQuote
				g.policyHash = rec.RouteQuote.RoutePolicyHash
			}
		case RecordBudgetVerdict:
			g.set.Budget = rec.BudgetVerdict
		case RecordUsage:
			g.set.Usage = rec.Usage
		case RecordSettlement:
			g.set.Settlement = rec.Settlement
		}
	}
	if len(order) == 0 {
		return nil, fmt.Errorf("spendproxy: no receipts matched intent filter %q", intentFilter)
	}
	sort.Strings(order)

	results := make([]ExportResult, 0, len(order))
	for _, intentID := range order {
		g := groups[intentID]
		packID := "spendpack-" + intentID
		manifest, contents, err := evidencepack.BuildSpendEvidencePack(
			packID, "did:helm:spend-proxy", intentID, g.policyHash,
			g.set, economic.DefaultRedactionProfile(),
		)
		if err != nil {
			return nil, fmt.Errorf("spendproxy: build pack for %s: %w", intentID, err)
		}
		verification, err := evidencepack.VerifySpendEvidenceOffline(contents)
		if err != nil {
			return nil, fmt.Errorf("spendproxy: offline verify pack for %s: %w", intentID, err)
		}

		res := ExportResult{
			SpendIntentID:    intentID,
			PackID:           packID,
			ManifestHash:     manifest.ManifestHash,
			ReceiptsVerified: verification.ReceiptsVerified,
			OfflineVerified:  verification.OK,
		}
		if g.set.Budget != nil {
			res.SignatureKeyID = g.set.Budget.SignatureKeyID
			if err := keys.Verify(g.set.Budget); err != nil {
				return nil, fmt.Errorf("spendproxy: verdict signature for %s: %w", intentID, err)
			}
			res.SignatureVerified = true
		}

		dir := filepath.Join(outDir, intentID)
		if err := writePackContents(dir, contents); err != nil {
			return nil, err
		}
		res.OutputDir = dir
		results = append(results, res)
	}
	return results, nil
}

func writePackContents(dir string, contents map[string][]byte) error {
	for path, data := range contents {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			return fmt.Errorf("spendproxy: create pack dir: %w", err)
		}
		if err := os.WriteFile(full, data, 0o600); err != nil {
			return fmt.Errorf("spendproxy: write pack entry %s: %w", path, err)
		}
	}
	return nil
}

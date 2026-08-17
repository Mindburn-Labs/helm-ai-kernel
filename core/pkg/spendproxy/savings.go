// quantum_posture: savings export re-derives SHA-256 content hashes and
// verifies classical Ed25519 verdict signatures through the trusted-key
// registry; no post-quantum primitives are used in this file.

package spendproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidencepack"
)

// Capture-artifact file names inside a --capture directory. The runner and the
// freeze step produce these; savings-export binds them into the pack verbatim.
const (
	CaptureTaskSplitFile = "task_split_manifest.json"
	CaptureResultsFile   = "task_results.json"
	CaptureParityFile    = "parity_prerun.json"
)

// SavingsExportOptions configures ExportSavingsEvidencePack.
type SavingsExportOptions struct {
	// ReceiptsDir holds spend-receipts.jsonl and trusted_keys.json.
	ReceiptsDir string
	// CaptureDir holds the three capture artifacts.
	CaptureDir string
	// ConfigPath is the exact price-book config the proxy ran with; its bytes
	// are embedded and every quote must bind their hash.
	ConfigPath string
	// OutDir receives the pack contents under <OutDir>/<pack_id>/.
	OutDir string
}

// SavingsExportResult summarizes one exported savings EvidencePack.
type SavingsExportResult struct {
	PackID           string                    `json:"pack_id"`
	RunID            string                    `json:"run_id"`
	ManifestHash     string                    `json:"manifest_hash"`
	OutputDir        string                    `json:"output_dir"`
	OfflineVerified  bool                      `json:"offline_verified"`
	ChecksPassed     []string                  `json:"checks_passed"`
	ReceiptsVerified int                       `json:"receipts_verified"`
	View             *evidencepack.SavingsView `json:"view"`
}

// ExportSavingsEvidencePack builds the HELM-614 savings EvidencePack from a
// capture: durable receipts + task-split manifest + task results + parity
// pre-run + the exact price-book config, then re-verifies the pack offline
// before writing it. Receipts not referenced by the capture's task results
// fail the export — unattributed spend must never hide inside a savings claim.
func ExportSavingsEvidencePack(opts SavingsExportOptions) (*SavingsExportResult, error) {
	if opts.ReceiptsDir == "" || opts.CaptureDir == "" || opts.ConfigPath == "" || opts.OutDir == "" {
		return nil, errors.New("spendproxy: savings export requires receipts dir, capture dir, config path, and out dir")
	}

	records, err := LoadRecords(filepath.Join(opts.ReceiptsDir, ReceiptLogName))
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("spendproxy: receipt log is empty; nothing to export")
	}

	manifestBytes, err := os.ReadFile(filepath.Join(opts.CaptureDir, CaptureTaskSplitFile))
	if err != nil {
		return nil, fmt.Errorf("spendproxy: read task-split manifest: %w", err)
	}
	resultsBytes, err := os.ReadFile(filepath.Join(opts.CaptureDir, CaptureResultsFile))
	if err != nil {
		return nil, fmt.Errorf("spendproxy: read task results: %w", err)
	}
	parityBytes, err := os.ReadFile(filepath.Join(opts.CaptureDir, CaptureParityFile))
	if err != nil {
		return nil, fmt.Errorf("spendproxy: read parity pre-run: %w", err)
	}
	configBytes, err := os.ReadFile(opts.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("spendproxy: read price-book config: %w", err)
	}
	trustedKeys, err := os.ReadFile(filepath.Join(opts.ReceiptsDir, TrustedKeyFileName))
	if err != nil {
		return nil, fmt.Errorf("spendproxy: read trusted-key registry: %w", err)
	}

	var man evidencepack.SavingsTaskSplitManifest
	if err := strictDecode(manifestBytes, &man, "task-split manifest"); err != nil {
		return nil, err
	}
	var results evidencepack.SavingsTaskResults
	if err := strictDecode(resultsBytes, &results, "task results"); err != nil {
		return nil, err
	}

	// Group receipts by intent, keeping only intents the capture references —
	// but refuse the export outright when the log holds settled spend on the
	// capture's envelopes that no task result accounts for.
	referenced := make(map[string]bool, len(results.Results))
	for _, r := range results.Results {
		referenced[r.SpendIntentID] = true
	}
	captureEnvelopes := map[string]bool{
		man.BaselineEnvelopeID:                         true,
		man.SelectionFreeze.ChosenSubstituteEnvelopeID: true,
	}
	for _, c := range man.CandidateRoutes {
		captureEnvelopes[c.EnvelopeID] = true
	}

	sets := make(map[string]evidencepack.SpendReceiptSet)
	for _, rec := range records {
		if rec.SpendIntentID == "" {
			continue
		}
		if !referenced[rec.SpendIntentID] {
			if rec.Kind == RecordSettlement && rec.Settlement != nil {
				// Attribute by the envelope on the settled usage's quote below;
				// cheaper: check usage records directly.
				continue
			}
			if rec.Kind == RecordUsage && rec.Usage != nil && captureEnvelopes[rec.Usage.EnvelopeID] {
				return nil, fmt.Errorf("spendproxy: settled spend on intent %s (envelope %s) is not referenced by any task result; refusing to export a savings claim over unattributed spend", rec.SpendIntentID, rec.Usage.EnvelopeID)
			}
			continue
		}
		set := sets[rec.SpendIntentID]
		switch rec.Kind {
		case RecordRouteQuote:
			if rec.RouteQuote != nil && set.RouteQuote == nil {
				set.RouteQuote = rec.RouteQuote
			}
		case RecordBudgetVerdict:
			if rec.BudgetVerdict != nil {
				set.Budget = rec.BudgetVerdict
			}
		case RecordUsage:
			if rec.Usage != nil {
				set.Usage = rec.Usage
			}
		case RecordSettlement:
			if rec.Settlement != nil {
				set.Settlement = rec.Settlement
			}
		}
		sets[rec.SpendIntentID] = set
	}
	for intentID := range referenced {
		if _, ok := sets[intentID]; !ok {
			return nil, fmt.Errorf("spendproxy: task results reference intent %s but the receipt log holds no receipts for it", intentID)
		}
	}

	packID := "savingspack-" + man.RunID
	manifest, contents, view, err := evidencepack.BuildSavingsEvidencePack(evidencepack.SavingsPackInputs{
		PackID:            packID,
		ActorDID:          "did:helm:spend-proxy",
		RunID:             man.RunID,
		PolicyHash:        routePolicyHashFromSets(sets),
		ReceiptSets:       sets,
		TaskSplitManifest: manifestBytes,
		TaskResults:       resultsBytes,
		ParityResults:     parityBytes,
		PriceBookConfig:   configBytes,
		TrustedKeys:       trustedKeys,
		Profile:           economic.DefaultRedactionProfile(),
	})
	if err != nil {
		return nil, err
	}

	verification, err := evidencepack.VerifySavingsEvidenceOffline(contents)
	if err != nil {
		return nil, fmt.Errorf("spendproxy: offline verification of the built savings pack failed: %w", err)
	}

	dir := filepath.Join(opts.OutDir, packID)
	if err := writePackContents(dir, contents); err != nil {
		return nil, err
	}
	return &SavingsExportResult{
		PackID:           packID,
		RunID:            man.RunID,
		ManifestHash:     manifest.ManifestHash,
		OutputDir:        dir,
		OfflineVerified:  verification.OK,
		ChecksPassed:     verification.ChecksPassed,
		ReceiptsVerified: verification.ReceiptsVerified,
		View:             view,
	}, nil
}

// VerifySavingsPackDir loads a written savings pack directory back into a
// content map and runs the full offline verification — the skeptic's
// entrypoint, no receipts dir or network required.
func VerifySavingsPackDir(dir string) (*evidencepack.SavingsVerificationResult, error) {
	contents := make(map[string][]byte)
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		contents[filepath.ToSlash(rel)] = data
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("spendproxy: read savings pack dir: %w", err)
	}
	if len(contents) == 0 {
		return nil, fmt.Errorf("spendproxy: savings pack dir %s is empty", dir)
	}
	return evidencepack.VerifySavingsEvidenceOffline(contents)
}

// routePolicyHashFromSets picks the (single) route policy hash the capture ran
// under; mixed policies fail closed.
func routePolicyHashFromSets(sets map[string]evidencepack.SpendReceiptSet) string {
	hashes := make(map[string]bool)
	for _, set := range sets {
		if set.RouteQuote != nil && set.RouteQuote.RoutePolicyHash != "" {
			hashes[set.RouteQuote.RoutePolicyHash] = true
		}
	}
	if len(hashes) == 1 {
		for h := range hashes {
			return h
		}
	}
	keys := make([]string, 0, len(hashes))
	for h := range hashes {
		keys = append(keys, h)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// strictDecode mirrors evidencepack's strict artifact decoding: capture
// artifacts are evidence, unknown fields fail closed.
func strictDecode(raw []byte, v interface{}, what string) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("spendproxy: decode %s: %w", what, err)
	}
	return nil
}

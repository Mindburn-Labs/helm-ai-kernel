package workstation

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

var evidencePackDirs = []string{
	"02_PROOFGRAPH",
	"02_PROOFGRAPH/receipts",
	"03_TELEMETRY",
	"04_EXPORTS",
	"05_DIFFS",
	"06_LOGS",
	"07_ATTESTATIONS",
	"08_TAPES",
	"09_SCHEMAS",
	"12_REPORTS",
	"99_EXT/workstation",
}

// fileNameIdentifier is the grammar of an identifier that may become part of
// a file name: the shape of the ids this package generates (prefix, underscore,
// hex), with no separator, dot or other character a path could turn on.
var fileNameIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

// checkFileNameIdentifier refuses an identifier read from a receipt before it
// is used in a path. Receipts are input: a hand-written receipt_id is whatever
// its author typed.
func checkFileNameIdentifier(field, value string) error {
	if !fileNameIdentifier.MatchString(value) {
		return fmt.Errorf("%s %q is not a valid identifier: expected letters, digits, _ and -, at most 128 characters", field, value)
	}
	return nil
}

type EvidencePackExport struct {
	PackID       string            `json:"pack_id"`
	OutDir       string            `json:"out_dir"`
	RootHash     string            `json:"root_hash"`
	FileHashes   map[string]string `json:"file_hashes"`
	ReceiptID    string            `json:"receipt_id"`
	ReceiptHash  string            `json:"receipt_hash"`
	ProofNodes   int               `json:"proof_nodes"`
	ExportedAt   time.Time         `json:"exported_at"`
	ObservedOnly bool              `json:"observed_only"`
}

func ExportEvidencePack(result *ImportResult, outDir string) (EvidencePackExport, error) {
	if result == nil || result.Receipt == nil {
		return EvidencePackExport{}, errors.New("import result with receipt is required")
	}
	if outDir == "" {
		return EvidencePackExport{}, errors.New("output directory is required")
	}
	if err := checkFileNameIdentifier("receipt_id", result.Receipt.ReceiptID); err != nil {
		return EvidencePackExport{}, err
	}
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return EvidencePackExport{}, fmt.Errorf("create evidence pack: %w", err)
	}
	// Every write goes through the opened directory, which refuses a path that
	// leaves it, including through a link already present inside the pack.
	pack, err := os.OpenRoot(outDir)
	if err != nil {
		return EvidencePackExport{}, fmt.Errorf("open evidence pack: %w", err)
	}
	defer pack.Close()
	for _, dir := range evidencePackDirs {
		if err := pack.MkdirAll(dir, 0o750); err != nil {
			return EvidencePackExport{}, fmt.Errorf("create evidence pack dir %s: %w", dir, err)
		}
	}

	exportedAt := result.Receipt.CreatedAt
	if exportedAt.IsZero() {
		exportedAt = time.Unix(0, 0).UTC()
	}
	packID := "evidencepack-" + result.Receipt.ReceiptID
	files := map[string]any{
		"02_PROOFGRAPH/nodes.json":                                     result.ProofGraph,
		"02_PROOFGRAPH/receipts/" + result.Receipt.ReceiptID + ".json": result.Receipt,
		"05_DIFFS/artifact-hashes.json":                                result.Receipt.ArtifactHashes,
		"07_ATTESTATIONS/signature.json": map[string]any{
			"receipt_hash":  result.Receipt.ReceiptHash,
			"signature":     result.Receipt.Signature,
			"signer_key_id": result.Receipt.SignerKeyID,
		},
		"12_REPORTS/workstation-summary.json": Summary(result.Receipt),
		"99_EXT/workstation/operator-view.json": OperatorView{
			Runs: []OperatorRunSummary{{
				RunID:             result.Receipt.RunID,
				ReceiptID:         result.Receipt.ReceiptID,
				Goal:              result.Receipt.Goal,
				AgentSurface:      result.Receipt.AgentSurface,
				PolicyProfile:     result.Receipt.PolicyProfile,
				ToolActions:       len(result.Receipt.ToolActions),
				ChangedFiles:      len(result.Receipt.ChangedFiles),
				ValidationResults: len(result.Receipt.ValidationResults),
				MemoryEffects:     len(result.Receipt.MemoryEffects),
				RecurringLoops:    len(result.Receipt.RecurringLoopEffects),
				DeniedEffects:     len(result.Receipt.DeniedEffects),
				ReceiptHash:       result.Receipt.ReceiptHash,
				CreatedAt:         result.Receipt.CreatedAt,
			}},
		},
	}

	fileHashes := map[string]string{}
	for rel, value := range files {
		data, err := canonicalize.JCS(value)
		if err != nil {
			return EvidencePackExport{}, fmt.Errorf("canonicalize %s: %w", rel, err)
		}
		if err := pack.WriteFile(rel, append(data, '\n'), 0o600); err != nil {
			return EvidencePackExport{}, fmt.Errorf("write %s: %w", rel, err)
		}
		fileHashes[rel] = hashBytes(data)
	}
	rootHash := canonicalHashOrPanic(fileHashes)
	index := map[string]any{
		"pack_id":        packID,
		"format_version": "workstation-evidencepack.v1",
		"created_at":     exportedAt,
		"subject":        result.Receipt.RunID,
		"receipt_id":     result.Receipt.ReceiptID,
		"receipt_hash":   result.Receipt.ReceiptHash,
		"root_hash":      rootHash,
		"extensions":     []string{"workstation"},
		"files":          sortedStringMap(fileHashes),
	}
	if err := writeCanonicalIn(pack, "00_INDEX.json", index); err != nil {
		return EvidencePackExport{}, err
	}
	score := map[string]any{
		"score_schema":       "workstation-governance-score.v1",
		"observe_only":       true,
		"denied_effects":     len(result.Receipt.DeniedEffects),
		"memory_effects":     len(result.Receipt.MemoryEffects),
		"recurring_loops":    len(result.Receipt.RecurringLoopEffects),
		"receipt_signature":  result.Receipt.Signature != "",
		"raw_chat_required":  false,
		"deterministic_root": rootHash,
	}
	if err := writeCanonicalIn(pack, "01_SCORE.json", score); err != nil {
		return EvidencePackExport{}, err
	}
	return EvidencePackExport{
		PackID:       packID,
		OutDir:       outDir,
		RootHash:     rootHash,
		FileHashes:   sortedStringMap(fileHashes),
		ReceiptID:    result.Receipt.ReceiptID,
		ReceiptHash:  result.Receipt.ReceiptHash,
		ProofNodes:   len(result.ProofGraph),
		ExportedAt:   exportedAt,
		ObservedOnly: true,
	}, nil
}

func writeCanonical(path string, value any) error {
	data, err := canonicalize.JCS(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func writeCanonicalIn(dir *os.Root, name string, value any) error {
	data, err := canonicalize.JCS(value)
	if err != nil {
		return err
	}
	return dir.WriteFile(name, append(data, '\n'), 0o600)
}

func EvidencePackRequiredFiles() []string {
	files := []string{"00_INDEX.json", "01_SCORE.json"}
	for _, dir := range evidencePackDirs {
		files = append(files, dir)
	}
	sort.Strings(files)
	return files
}

func LoadEvidencePackIndex(path string) (map[string]any, error) {
	data, err := os.ReadFile(filepath.Join(path, "00_INDEX.json"))
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

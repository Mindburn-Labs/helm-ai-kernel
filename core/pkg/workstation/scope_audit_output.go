package workstation

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// WriteScopeAuditArtifacts writes the report, its Markdown and its evidence
// references into outDir, and with includeEvidencePack the evidence pack in
// its scope-audit-evidencepack subdirectory. outDir must be new or empty, as
// an evidence pack's directory must: in a used one a file left from an
// earlier audit would sit beside the new ones, and a file or directory linked
// to one elsewhere would be written through. Every file is created new
// through the opened directory, which refuses a path that leaves it.
func WriteScopeAuditArtifacts(report ScopeAuditReport, outDir string, includeEvidencePack bool) (ScopeAuditExport, error) {
	if outDir == "" {
		return ScopeAuditExport{}, errors.New("output directory is required")
	}
	root, err := openEmptyOutputDir(outDir, "scope audit")
	if err != nil {
		return ScopeAuditExport{}, err
	}
	defer root.Close()
	writer := newPackWriter(root)
	export := ScopeAuditExport{
		OutDir:           outDir,
		ReportPath:       filepath.Join(outDir, "scope-audit.json"),
		MarkdownPath:     filepath.Join(outDir, "scope-audit.md"),
		EvidenceRefsPath: filepath.Join(outDir, "evidence-refs.json"),
		FileHashes:       map[string]string{},
	}
	reportJSON, err := canonicalize.JCS(report)
	if err != nil {
		return ScopeAuditExport{}, fmt.Errorf("canonicalize scope audit JSON: %w", err)
	}
	refsJSON, err := canonicalize.JCS(report.EvidenceRefs)
	if err != nil {
		return ScopeAuditExport{}, fmt.Errorf("canonicalize evidence refs: %w", err)
	}
	for _, file := range []struct {
		name, what string
		data       []byte
	}{
		{"scope-audit.json", "scope audit JSON", append(reportJSON, '\n')},
		{"scope-audit.md", "scope audit Markdown", []byte(RenderScopeAuditMarkdown(report))},
		{"evidence-refs.json", "evidence refs", append(refsJSON, '\n')},
	} {
		if err := writer.create(file.name, file.data); err != nil {
			return ScopeAuditExport{}, fmt.Errorf("write %s: %w", file.what, err)
		}
		export.FileHashes[file.name] = hashBytes(file.data)
	}
	export.FileHashes = sortedStringMap(export.FileHashes)
	if includeEvidencePack {
		const packName = "scope-audit-evidencepack"
		if err := root.Mkdir(packName, 0o750); err != nil {
			return ScopeAuditExport{}, fmt.Errorf("create scope audit evidence pack: %w", err)
		}
		pack, err := root.OpenRoot(packName)
		if err != nil {
			return ScopeAuditExport{}, fmt.Errorf("open scope audit evidence pack: %w", err)
		}
		defer pack.Close()
		exported, err := writeScopeAuditEvidencePack(report, pack, filepath.Join(outDir, packName))
		if err != nil {
			return ScopeAuditExport{}, err
		}
		export.EvidencePackDir = exported.OutDir
		export.EvidencePackRootHash = exported.RootHash
	}
	return export, nil
}

type ScopeAuditEvidencePackExport struct {
	OutDir     string            `json:"out_dir"`
	RootHash   string            `json:"root_hash"`
	FileHashes map[string]string `json:"file_hashes"`
}

// writeScopeAuditEvidencePack writes the pack through an opened, empty
// directory: its subdirectories are created there, so none can be a link
// planted ahead of the export, and each file is created new.
func writeScopeAuditEvidencePack(report ScopeAuditReport, root *os.Root, outDir string) (ScopeAuditEvidencePackExport, error) {
	for _, dir := range []string{
		"02_PROOFGRAPH",
		"07_ATTESTATIONS",
		"12_REPORTS",
		"99_EXT/workstation",
	} {
		if err := root.MkdirAll(dir, 0o750); err != nil {
			return ScopeAuditEvidencePackExport{}, fmt.Errorf("create scope audit evidence dir %s: %w", dir, err)
		}
	}
	writer := newPackWriter(root)
	files := map[string]any{
		"07_ATTESTATIONS/source-receipts.json":  report.EvidenceRefs,
		"12_REPORTS/scope-audit.json":           report,
		"99_EXT/workstation/evidence-refs.json": report.EvidenceRefs,
		"99_EXT/workstation/operator-view.json": report.OperatorView,
	}
	names := make([]string, 0, len(files))
	for rel := range files {
		names = append(names, rel)
	}
	sort.Strings(names)
	fileHashes := map[string]string{}
	for _, rel := range names {
		data, err := canonicalize.JCS(files[rel])
		if err != nil {
			return ScopeAuditEvidencePackExport{}, fmt.Errorf("canonicalize %s: %w", rel, err)
		}
		if err := writer.create(rel, append(data, '\n')); err != nil {
			return ScopeAuditEvidencePackExport{}, fmt.Errorf("write %s: %w", rel, err)
		}
		fileHashes[rel] = hashBytes(data)
	}
	markdownRel := "12_REPORTS/scope-audit.md"
	markdown := []byte(RenderScopeAuditMarkdown(report))
	if err := writer.create(markdownRel, markdown); err != nil {
		return ScopeAuditEvidencePackExport{}, fmt.Errorf("write %s: %w", markdownRel, err)
	}
	fileHashes[markdownRel] = hashBytes(markdown)

	rootHash := canonicalHashOrPanic(fileHashes)
	index := map[string]any{
		"pack_id":        "scope-audit-" + hashBytes([]byte(rootHash))[:16],
		"format_version": "scope-audit-evidencepack.v1",
		"created_at":     report.GeneratedAt,
		"root_hash":      rootHash,
		"extensions":     []string{"workstation", "scope-audit"},
		"files":          sortedStringMap(fileHashes),
	}
	if err := writer.createCanonical("00_INDEX.json", index); err != nil {
		return ScopeAuditEvidencePackExport{}, err
	}
	score := map[string]any{
		"score_schema":          "scope-audit-score.v1",
		"out_of_scope_attempts": report.Summary.OutOfScopeAttempts,
		"missing_controls":      report.Summary.MissingControls,
		"denied_actions":        report.Summary.DeniedActions,
		"source_receipts":       len(report.EvidenceRefs),
		"raw_chat_required":     false,
		"deterministic_root":    rootHash,
	}
	if err := writer.createCanonical("01_SCORE.json", score); err != nil {
		return ScopeAuditEvidencePackExport{}, err
	}
	return ScopeAuditEvidencePackExport{OutDir: outDir, RootHash: rootHash, FileHashes: sortedStringMap(fileHashes)}, nil
}

func RenderScopeAuditMarkdown(report ScopeAuditReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Agent Scope Audit\n\n")
	fmt.Fprintf(&b, "- Generated at: %s\n", report.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "- Inputs: %d\n", report.Summary.InputFiles)
	fmt.Fprintf(&b, "- Actions: %d allowed=%d denied=%d tainted=%d\n", report.Summary.TotalActions, report.Summary.AllowedActions, report.Summary.DeniedActions, report.Summary.TaintedActions)
	fmt.Fprintf(&b, "- Out-of-scope attempts: %d\n", report.Summary.OutOfScopeAttempts)
	fmt.Fprintf(&b, "- Missing controls: %d\n", report.Summary.MissingControls)
	fmt.Fprintf(&b, "- Receipts of another signer, counted apart: %d (actions: %d)\n\n", report.Summary.UntrustedSignerReceipts, report.Summary.UntrustedSignerActions)
	fmt.Fprintf(&b, "## Boundaries\n\n")
	for _, boundary := range report.Boundaries {
		fmt.Fprintf(&b, "- %s: total=%d allow=%d deny=%d tainted=%d unknown=%d\n", boundary.Boundary, boundary.Total, boundary.Allowed, boundary.Denied, boundary.Tainted, boundary.Unknown)
	}
	if len(report.OutOfScopeAttempts) > 0 {
		fmt.Fprintf(&b, "\n## Out-of-Scope Attempts\n\n")
		for _, attempt := range report.OutOfScopeAttempts {
			fmt.Fprintf(&b, "- %s %s %s %s receipt=%s reason=%s\n", attempt.Boundary, attempt.EffectType, firstNonEmpty(attempt.ToolID, "-"), firstNonEmpty(attempt.Target, "-"), attempt.Receipt, firstNonEmpty(attempt.ReasonCode, "-"))
		}
	}
	if len(report.MissingControls) > 0 {
		fmt.Fprintf(&b, "\n## Missing Controls\n\n")
		for _, control := range report.MissingControls {
			fmt.Fprintf(&b, "- %s %s receipt=%s detail=%s\n", control.Boundary, control.Control, firstNonEmpty(control.Receipt, "-"), control.Detail)
		}
	}
	fmt.Fprintf(&b, "\n## Limitations\n\n")
	for _, limitation := range report.Limitations {
		fmt.Fprintf(&b, "- %s\n", limitation)
	}
	return b.String()
}

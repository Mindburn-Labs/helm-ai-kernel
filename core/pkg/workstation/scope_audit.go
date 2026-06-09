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
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

const ScopeAuditReportVersion = "scope_audit_report.v1"

var scopeAuditBoundaries = []string{
	"mcp",
	"filesystem",
	"network",
	"memory",
	"secret",
	"deploy",
	"payment",
	"loop",
	"shell",
}

type ScopeAuditReport struct {
	ReportVersion      string               `json:"report_version"`
	GeneratedAt        time.Time            `json:"generated_at"`
	Summary            ScopeAuditSummary    `json:"summary"`
	Boundaries         []BoundarySummary    `json:"boundaries"`
	OutOfScopeAttempts []OutOfScopeAttempt  `json:"out_of_scope_attempts"`
	MissingControls    []MissingControl     `json:"missing_controls"`
	MemoryWrites       []MemoryAuditItem    `json:"memory_writes"`
	RecurringLoops     []LoopAuditItem      `json:"recurring_loops"`
	HighImpactMetadata []HighImpactMetadata `json:"high_impact_metadata"`
	EvidenceRefs       []EvidenceRef        `json:"evidence_refs"`
	OperatorView       OperatorView         `json:"operator_view"`
	Limitations        []string             `json:"limitations"`
}

type ScopeAuditSummary struct {
	InputFiles         int `json:"input_files"`
	AgentRunReceipts   int `json:"agent_run_receipts"`
	DecisionReceipts   int `json:"decision_receipts"`
	TotalActions       int `json:"total_actions"`
	AllowedActions     int `json:"allowed_actions"`
	DeniedActions      int `json:"denied_actions"`
	TaintedActions     int `json:"tainted_actions"`
	UnknownMCPActions  int `json:"unknown_mcp_actions"`
	OutOfScopeAttempts int `json:"out_of_scope_attempts"`
	MissingControls    int `json:"missing_controls"`
	MemoryWrites       int `json:"memory_writes"`
	RecurringLoops     int `json:"recurring_loops"`
	HighImpactMetadata int `json:"high_impact_metadata"`
}

type BoundarySummary struct {
	Boundary    string   `json:"boundary"`
	EffectTypes []string `json:"effect_types"`
	Total       int      `json:"total"`
	Allowed     int      `json:"allowed"`
	Denied      int      `json:"denied"`
	Tainted     int      `json:"tainted"`
	Unknown     int      `json:"unknown"`
	ReceiptRefs []string `json:"receipt_refs"`
	ReasonCodes []string `json:"reason_codes"`
}

type OutOfScopeAttempt struct {
	Boundary    string            `json:"boundary"`
	RunID       string            `json:"run_id,omitempty"`
	EffectID    string            `json:"effect_id,omitempty"`
	EffectType  string            `json:"effect_type"`
	ToolID      string            `json:"tool_id,omitempty"`
	Action      string            `json:"action,omitempty"`
	Target      string            `json:"target,omitempty"`
	Verdict     string            `json:"verdict"`
	ReasonCode  string            `json:"reason_code,omitempty"`
	Reason      string            `json:"reason,omitempty"`
	Receipt     string            `json:"receipt"`
	Source      string            `json:"source"`
	OccurredAt  time.Time         `json:"occurred_at"`
	TaintLabels []string          `json:"taint_labels,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type MissingControl struct {
	Boundary   string `json:"boundary"`
	RunID      string `json:"run_id,omitempty"`
	EffectID   string `json:"effect_id,omitempty"`
	Control    string `json:"control"`
	ReasonCode string `json:"reason_code,omitempty"`
	Detail     string `json:"detail"`
	Receipt    string `json:"receipt,omitempty"`
}

type EvidenceRef struct {
	Kind             string   `json:"kind"`
	SourcePath       string   `json:"source_path"`
	RunID            string   `json:"run_id,omitempty"`
	ReceiptID        string   `json:"receipt_id,omitempty"`
	DecisionID       string   `json:"decision_id,omitempty"`
	ReceiptHash      string   `json:"receipt_hash"`
	SignaturePresent bool     `json:"signature_present"`
	EvidencePackRefs []string `json:"evidence_pack_refs,omitempty"`
}

type MemoryAuditItem struct {
	RunID       string    `json:"run_id"`
	EffectID    string    `json:"effect_id"`
	MemoryClass string    `json:"memory_class"`
	DataClass   string    `json:"data_class"`
	Sensitivity string    `json:"sensitivity"`
	TTLDays     uint32    `json:"ttl_days"`
	Purpose     string    `json:"purpose,omitempty"`
	ReviewState string    `json:"review_state,omitempty"`
	Verdict     string    `json:"verdict"`
	ReasonCode  string    `json:"reason_code,omitempty"`
	Receipt     string    `json:"receipt"`
	ObservedAt  time.Time `json:"observed_at"`
}

type LoopAuditItem struct {
	RunID      string    `json:"run_id"`
	EffectID   string    `json:"effect_id"`
	Schedule   string    `json:"schedule"`
	MaxRuntime string    `json:"max_runtime"`
	ToolScope  []string  `json:"tool_scope"`
	ExpiresAt  time.Time `json:"expires_at"`
	Verdict    string    `json:"verdict"`
	ReasonCode string    `json:"reason_code,omitempty"`
	Receipt    string    `json:"receipt"`
}

type HighImpactMetadata struct {
	Boundary   string            `json:"boundary"`
	RunID      string            `json:"run_id,omitempty"`
	EffectID   string            `json:"effect_id,omitempty"`
	EffectType string            `json:"effect_type"`
	ToolID     string            `json:"tool_id,omitempty"`
	Action     string            `json:"action,omitempty"`
	Target     string            `json:"target,omitempty"`
	Verdict    string            `json:"verdict"`
	Receipt    string            `json:"receipt"`
	Metadata   map[string]string `json:"metadata"`
}

type ScopeAuditExport struct {
	OutDir               string            `json:"out_dir"`
	ReportPath           string            `json:"report_path"`
	MarkdownPath         string            `json:"markdown_path"`
	EvidenceRefsPath     string            `json:"evidence_refs_path"`
	EvidencePackDir      string            `json:"evidence_pack_dir,omitempty"`
	EvidencePackRootHash string            `json:"evidence_pack_root_hash,omitempty"`
	FileHashes           map[string]string `json:"file_hashes"`
}

type scopeAuditBuilder struct {
	report      ScopeAuditReport
	boundaries  map[string]*BoundarySummary
	generatedAt time.Time
}

func BuildScopeAudit(paths ...string) (ScopeAuditReport, error) {
	files, err := expandJSONInputs(paths)
	if err != nil {
		return ScopeAuditReport{}, err
	}
	if len(files) == 0 {
		return ScopeAuditReport{}, errors.New("no workstation receipt JSON files found")
	}
	view, err := BuildOperatorView(files...)
	if err != nil {
		return ScopeAuditReport{}, err
	}
	builder := newScopeAuditBuilder(len(files), view)
	for _, file := range files {
		receipt, decision, err := loadWorkstationReceipt(file)
		if err != nil {
			return ScopeAuditReport{}, err
		}
		if receipt != nil {
			builder.addAgentRunReceipt(file, receipt)
		}
		if decision != nil {
			builder.addDecisionReceipt(file, decision)
		}
	}
	return builder.finish(), nil
}

func WriteScopeAuditArtifacts(report ScopeAuditReport, outDir string, includeEvidencePack bool) (ScopeAuditExport, error) {
	if outDir == "" {
		return ScopeAuditExport{}, errors.New("output directory is required")
	}
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return ScopeAuditExport{}, fmt.Errorf("create scope audit dir: %w", err)
	}
	export := ScopeAuditExport{
		OutDir:           outDir,
		ReportPath:       filepath.Join(outDir, "scope-audit.json"),
		MarkdownPath:     filepath.Join(outDir, "scope-audit.md"),
		EvidenceRefsPath: filepath.Join(outDir, "evidence-refs.json"),
		FileHashes:       map[string]string{},
	}
	if err := writeCanonical(export.ReportPath, report); err != nil {
		return ScopeAuditExport{}, fmt.Errorf("write scope audit JSON: %w", err)
	}
	if err := os.WriteFile(export.MarkdownPath, []byte(RenderScopeAuditMarkdown(report)), 0o600); err != nil {
		return ScopeAuditExport{}, fmt.Errorf("write scope audit Markdown: %w", err)
	}
	if err := writeCanonical(export.EvidenceRefsPath, report.EvidenceRefs); err != nil {
		return ScopeAuditExport{}, fmt.Errorf("write evidence refs: %w", err)
	}
	for rel, path := range map[string]string{
		"scope-audit.json":   export.ReportPath,
		"scope-audit.md":     export.MarkdownPath,
		"evidence-refs.json": export.EvidenceRefsPath,
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			return ScopeAuditExport{}, err
		}
		export.FileHashes[rel] = hashBytes(data)
	}
	export.FileHashes = sortedStringMap(export.FileHashes)
	if includeEvidencePack {
		packDir := filepath.Join(outDir, "scope-audit-evidencepack")
		pack, err := ExportScopeAuditEvidencePack(report, packDir)
		if err != nil {
			return ScopeAuditExport{}, err
		}
		export.EvidencePackDir = pack.OutDir
		export.EvidencePackRootHash = pack.RootHash
	}
	return export, nil
}

type ScopeAuditEvidencePackExport struct {
	OutDir     string            `json:"out_dir"`
	RootHash   string            `json:"root_hash"`
	FileHashes map[string]string `json:"file_hashes"`
}

func ExportScopeAuditEvidencePack(report ScopeAuditReport, outDir string) (ScopeAuditEvidencePackExport, error) {
	if outDir == "" {
		return ScopeAuditEvidencePackExport{}, errors.New("output directory is required")
	}
	dirs := []string{
		"02_PROOFGRAPH",
		"07_ATTESTATIONS",
		"12_REPORTS",
		"99_EXT/workstation",
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(outDir, dir), 0o750); err != nil {
			return ScopeAuditEvidencePackExport{}, fmt.Errorf("create scope audit evidence dir %s: %w", dir, err)
		}
	}
	files := map[string]any{
		"07_ATTESTATIONS/source-receipts.json":  report.EvidenceRefs,
		"12_REPORTS/scope-audit.json":           report,
		"99_EXT/workstation/evidence-refs.json": report.EvidenceRefs,
		"99_EXT/workstation/operator-view.json": report.OperatorView,
	}
	fileHashes := map[string]string{}
	for rel, value := range files {
		data, err := canonicalize.JCS(value)
		if err != nil {
			return ScopeAuditEvidencePackExport{}, fmt.Errorf("canonicalize %s: %w", rel, err)
		}
		if err := os.WriteFile(filepath.Join(outDir, rel), append(data, '\n'), 0o600); err != nil {
			return ScopeAuditEvidencePackExport{}, fmt.Errorf("write %s: %w", rel, err)
		}
		fileHashes[rel] = hashBytes(data)
	}
	markdownRel := "12_REPORTS/scope-audit.md"
	markdown := []byte(RenderScopeAuditMarkdown(report))
	if err := os.WriteFile(filepath.Join(outDir, markdownRel), markdown, 0o600); err != nil {
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
	if err := writeCanonical(filepath.Join(outDir, "00_INDEX.json"), index); err != nil {
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
	if err := writeCanonical(filepath.Join(outDir, "01_SCORE.json"), score); err != nil {
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
	fmt.Fprintf(&b, "- Missing controls: %d\n\n", report.Summary.MissingControls)
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

func newScopeAuditBuilder(inputFiles int, view OperatorView) *scopeAuditBuilder {
	report := ScopeAuditReport{
		ReportVersion: ScopeAuditReportVersion,
		GeneratedAt:   time.Unix(0, 0).UTC(),
		Summary: ScopeAuditSummary{
			InputFiles: inputFiles,
		},
		OperatorView: view,
		Limitations: []string{
			"Scope audit only covers receipts, wrapper decisions, and artifacts provided as input.",
			"It does not claim full desktop, browser, OS, or proprietary hosted-agent control.",
			"Secret values are never required and secret-like metadata is redacted unless it is a safe reference field.",
		},
	}
	builder := &scopeAuditBuilder{
		report:      report,
		boundaries:  map[string]*BoundarySummary{},
		generatedAt: time.Unix(0, 0).UTC(),
	}
	for _, boundary := range scopeAuditBoundaries {
		builder.boundaries[boundary] = &BoundarySummary{Boundary: boundary}
	}
	return builder
}

func (b *scopeAuditBuilder) addAgentRunReceipt(sourcePath string, receipt *contracts.AgentRunReceipt) {
	b.report.Summary.AgentRunReceipts++
	b.noteTime(receipt.CreatedAt)
	b.report.EvidenceRefs = append(b.report.EvidenceRefs, EvidenceRef{
		Kind:             "agent_run_receipt",
		SourcePath:       sourcePath,
		RunID:            receipt.RunID,
		ReceiptID:        receipt.ReceiptID,
		ReceiptHash:      receipt.ReceiptHash,
		SignaturePresent: receipt.Signature != "",
		EvidencePackRefs: sortedStrings(receipt.EvidencePackRefs),
	})
	for _, file := range receipt.ChangedFiles {
		b.addAction(scopeAuditAction{
			boundary:   "filesystem",
			runID:      receipt.RunID,
			effectID:   file.Path,
			effectType: contracts.EffectTypeWorkstationFileDraft,
			action:     "changed_file",
			target:     file.Path,
			verdict:    contracts.WorkstationVerdictAllow,
			receipt:    receipt.ReceiptID,
			source:     "agent_run_receipt",
			occurredAt: receipt.CreatedAt,
		})
	}
	actionsByID := map[string]contracts.AgentToolAction{}
	for _, action := range receipt.ToolActions {
		actionsByID[action.ActionID] = action
		b.addToolAction(receipt.RunID, receipt.ReceiptID, "agent_run_receipt", action)
	}
	for _, denied := range receipt.DeniedEffects {
		if _, ok := actionsByID[denied.EffectID]; ok {
			continue
		}
		b.addAction(scopeAuditAction{
			boundary:   boundaryForEffect(denied.EffectType, ""),
			runID:      receipt.RunID,
			effectID:   denied.EffectID,
			effectType: denied.EffectType,
			toolID:     denied.ToolID,
			action:     denied.Action,
			verdict:    contracts.WorkstationVerdictDeny,
			reasonCode: denied.ReasonCode,
			reason:     denied.Reason,
			receipt:    receipt.ReceiptID,
			source:     "agent_run_receipt",
			occurredAt: denied.OccurredAt,
		})
	}
	for _, memory := range receipt.MemoryEffects {
		b.report.MemoryWrites = append(b.report.MemoryWrites, MemoryAuditItem{
			RunID:       receipt.RunID,
			EffectID:    memory.EffectID,
			MemoryClass: memory.MemoryClass,
			DataClass:   memory.DataClass,
			Sensitivity: memory.Sensitivity,
			TTLDays:     memory.TTLDays,
			Purpose:     memory.Purpose,
			ReviewState: memory.ReviewState,
			Verdict:     memory.Verdict,
			ReasonCode:  memory.ReasonCode,
			Receipt:     receipt.ReceiptID,
			ObservedAt:  receipt.CreatedAt,
		})
		if memory.TTLDays == 0 {
			b.addMissingControl("memory", receipt.RunID, memory.EffectID, "memory.ttl_days", memory.ReasonCode, "memory write is missing ttl_days", receipt.ReceiptID)
		}
		if strings.TrimSpace(memory.Sensitivity) == "" {
			b.addMissingControl("memory", receipt.RunID, memory.EffectID, "memory.sensitivity", memory.ReasonCode, "memory write is missing sensitivity", receipt.ReceiptID)
		}
	}
	for _, loop := range receipt.RecurringLoopEffects {
		b.report.RecurringLoops = append(b.report.RecurringLoops, LoopAuditItem{
			RunID:      receipt.RunID,
			EffectID:   loop.EffectID,
			Schedule:   loop.Schedule,
			MaxRuntime: loop.MaxRuntime,
			ToolScope:  sortedStrings(loop.ToolScope),
			ExpiresAt:  loop.ExpiresAt,
			Verdict:    loop.Verdict,
			ReasonCode: loop.ReasonCode,
			Receipt:    receipt.ReceiptID,
		})
	}
}

func (b *scopeAuditBuilder) addDecisionReceipt(sourcePath string, receipt *contracts.WorkstationPolicyDecisionReceipt) {
	b.report.Summary.DecisionReceipts++
	b.noteTime(receipt.CreatedAt)
	b.report.EvidenceRefs = append(b.report.EvidenceRefs, EvidenceRef{
		Kind:             "policy_decision_receipt",
		SourcePath:       sourcePath,
		RunID:            receipt.Request.RunID,
		DecisionID:       receipt.DecisionID,
		ReceiptHash:      receipt.ReceiptHash,
		SignaturePresent: receipt.Signature != "",
	})
	b.addAction(scopeAuditAction{
		boundary:   boundaryForEffect(receipt.Request.EffectType, ""),
		runID:      receipt.Request.RunID,
		effectID:   receipt.Request.RequestID,
		effectType: receipt.Request.EffectType,
		toolID:     receipt.Request.ToolID,
		action:     receipt.Request.Action,
		target:     receipt.Request.Target,
		verdict:    receipt.Verdict,
		reasonCode: receipt.ReasonCode,
		reason:     receipt.Reason,
		receipt:    receipt.DecisionID,
		source:     "policy_decision_receipt",
		occurredAt: receipt.Request.OccurredAt,
		metadata:   receipt.Request.Metadata,
	})
}

func (b *scopeAuditBuilder) addToolAction(runID, receiptID, source string, action contracts.AgentToolAction) {
	b.addAction(scopeAuditAction{
		boundary:    boundaryForEffect(action.EffectType, action.Action),
		runID:       runID,
		effectID:    action.ActionID,
		effectType:  action.EffectType,
		toolID:      action.ToolID,
		action:      action.Action,
		target:      action.Target,
		verdict:     action.Verdict,
		reasonCode:  action.ReasonCode,
		receipt:     receiptID,
		source:      source,
		occurredAt:  action.OccurredAt,
		taintLabels: sortedStrings(action.TaintLabels),
		metadata:    action.Metadata,
	})
}

type scopeAuditAction struct {
	boundary    string
	runID       string
	effectID    string
	effectType  string
	toolID      string
	action      string
	target      string
	verdict     string
	reasonCode  string
	reason      string
	receipt     string
	source      string
	occurredAt  time.Time
	taintLabels []string
	metadata    map[string]string
}

func (b *scopeAuditBuilder) addAction(action scopeAuditAction) {
	if action.boundary == "" {
		action.boundary = "shell"
	}
	if action.verdict == "" {
		action.verdict = contracts.WorkstationVerdictAllow
	}
	b.noteTime(action.occurredAt)
	summary := b.boundary(action.boundary)
	summary.Total++
	summary.EffectTypes = appendUnique(summary.EffectTypes, action.effectType)
	summary.ReceiptRefs = appendUnique(summary.ReceiptRefs, action.receipt)
	if action.reasonCode != "" {
		summary.ReasonCodes = appendUnique(summary.ReasonCodes, action.reasonCode)
	}
	b.report.Summary.TotalActions++
	if strings.EqualFold(action.verdict, contracts.WorkstationVerdictDeny) {
		summary.Denied++
		b.report.Summary.DeniedActions++
	} else {
		summary.Allowed++
		b.report.Summary.AllowedActions++
	}
	tainted := len(action.taintLabels) > 0
	if tainted {
		summary.Tainted++
		b.report.Summary.TaintedActions++
	}
	unknown := isUnknownAction(action)
	if unknown {
		summary.Unknown++
		if action.boundary == "mcp" {
			b.report.Summary.UnknownMCPActions++
		}
	}
	if strings.EqualFold(action.verdict, contracts.WorkstationVerdictDeny) || (action.boundary == "mcp" && (tainted || unknown)) {
		reasonCode := action.reasonCode
		reason := action.reason
		if reasonCode == "" && action.boundary == "mcp" && (tainted || unknown) {
			reasonCode = "MCP_TAINTED_OR_UNKNOWN"
			reason = "MCP call is tainted or references an unknown tool/server"
		}
		b.report.OutOfScopeAttempts = append(b.report.OutOfScopeAttempts, OutOfScopeAttempt{
			Boundary:    action.boundary,
			RunID:       action.runID,
			EffectID:    action.effectID,
			EffectType:  action.effectType,
			ToolID:      action.toolID,
			Action:      action.action,
			Target:      action.target,
			Verdict:     action.verdict,
			ReasonCode:  reasonCode,
			Reason:      reason,
			Receipt:     action.receipt,
			Source:      action.source,
			OccurredAt:  action.occurredAt,
			TaintLabels: action.taintLabels,
			Metadata:    sanitizeMetadataForAudit(action.boundary, action.metadata),
		})
	}
	if action.boundary == "secret" || action.boundary == "deploy" || action.boundary == "payment" {
		metadata := sanitizeMetadataForAudit(action.boundary, action.metadata)
		b.report.HighImpactMetadata = append(b.report.HighImpactMetadata, HighImpactMetadata{
			Boundary:   action.boundary,
			RunID:      action.runID,
			EffectID:   action.effectID,
			EffectType: action.effectType,
			ToolID:     action.toolID,
			Action:     action.action,
			Target:     action.target,
			Verdict:    action.verdict,
			Receipt:    action.receipt,
			Metadata:   metadata,
		})
		b.addHighImpactMissingControls(action, metadata)
	}
	b.addReasonMissingControl(action)
}

func (b *scopeAuditBuilder) finish() ScopeAuditReport {
	b.report.GeneratedAt = b.generatedAt.UTC()
	for _, boundary := range scopeAuditBoundaries {
		summary := b.boundary(boundary)
		summary.EffectTypes = sortedStrings(summary.EffectTypes)
		summary.ReceiptRefs = sortedStrings(summary.ReceiptRefs)
		summary.ReasonCodes = sortedStrings(summary.ReasonCodes)
		b.report.Boundaries = append(b.report.Boundaries, *summary)
	}
	sort.SliceStable(b.report.OutOfScopeAttempts, func(i, j int) bool {
		a, c := b.report.OutOfScopeAttempts[i], b.report.OutOfScopeAttempts[j]
		return sortKey(a.OccurredAt, a.Boundary, a.Receipt, a.EffectID) < sortKey(c.OccurredAt, c.Boundary, c.Receipt, c.EffectID)
	})
	sort.SliceStable(b.report.MissingControls, func(i, j int) bool {
		a, c := b.report.MissingControls[i], b.report.MissingControls[j]
		return strings.Join([]string{a.Boundary, a.Receipt, a.EffectID, a.Control}, "\x00") < strings.Join([]string{c.Boundary, c.Receipt, c.EffectID, c.Control}, "\x00")
	})
	sort.SliceStable(b.report.MemoryWrites, func(i, j int) bool {
		a, c := b.report.MemoryWrites[i], b.report.MemoryWrites[j]
		return strings.Join([]string{a.RunID, a.EffectID, a.Receipt}, "\x00") < strings.Join([]string{c.RunID, c.EffectID, c.Receipt}, "\x00")
	})
	sort.SliceStable(b.report.RecurringLoops, func(i, j int) bool {
		a, c := b.report.RecurringLoops[i], b.report.RecurringLoops[j]
		return strings.Join([]string{a.RunID, a.EffectID, a.Receipt}, "\x00") < strings.Join([]string{c.RunID, c.EffectID, c.Receipt}, "\x00")
	})
	sort.SliceStable(b.report.HighImpactMetadata, func(i, j int) bool {
		a, c := b.report.HighImpactMetadata[i], b.report.HighImpactMetadata[j]
		return strings.Join([]string{a.Boundary, a.RunID, a.EffectID, a.Receipt}, "\x00") < strings.Join([]string{c.Boundary, c.RunID, c.EffectID, c.Receipt}, "\x00")
	})
	sort.SliceStable(b.report.EvidenceRefs, func(i, j int) bool {
		a, c := b.report.EvidenceRefs[i], b.report.EvidenceRefs[j]
		return strings.Join([]string{a.SourcePath, a.Kind, a.ReceiptID, a.DecisionID}, "\x00") < strings.Join([]string{c.SourcePath, c.Kind, c.ReceiptID, c.DecisionID}, "\x00")
	})
	b.report.Summary.OutOfScopeAttempts = len(b.report.OutOfScopeAttempts)
	b.report.Summary.MissingControls = len(b.report.MissingControls)
	b.report.Summary.MemoryWrites = len(b.report.MemoryWrites)
	b.report.Summary.RecurringLoops = len(b.report.RecurringLoops)
	b.report.Summary.HighImpactMetadata = len(b.report.HighImpactMetadata)
	return b.report
}

func (b *scopeAuditBuilder) boundary(name string) *BoundarySummary {
	if summary, ok := b.boundaries[name]; ok {
		return summary
	}
	summary := &BoundarySummary{Boundary: name}
	b.boundaries[name] = summary
	return summary
}

func (b *scopeAuditBuilder) noteTime(t time.Time) {
	if t.IsZero() {
		return
	}
	t = t.UTC()
	if t.After(b.generatedAt) {
		b.generatedAt = t
	}
}

func (b *scopeAuditBuilder) addReasonMissingControl(action scopeAuditAction) {
	switch action.reasonCode {
	case "OPERATE_PERMISSIONS_EMPTY":
		b.addMissingControl(action.boundary, action.runID, action.effectID, "operate.permissions", action.reasonCode, "operate permissions are empty for this policy profile", action.receipt)
	case "OPERATE_PERMISSION_NOT_GRANTED":
		b.addMissingControl(action.boundary, action.runID, action.effectID, "operate.permission."+action.boundary, action.reasonCode, "required operate permission is not granted", action.receipt)
	case "EGRESS_ALLOWLIST_EMPTY":
		b.addMissingControl("network", action.runID, action.effectID, "egress.allowlist", action.reasonCode, "network egress allowlist is empty", action.receipt)
	case "EGRESS_DESTINATION_NOT_ALLOWED":
		b.addMissingControl("network", action.runID, action.effectID, "egress.destination", action.reasonCode, "network destination is outside the allowlist", action.receipt)
	case "DRAFT_TARGET_OUTSIDE_WORKSPACE_SCOPE":
		b.addMissingControl("filesystem", action.runID, action.effectID, "draft.workspace_roots", action.reasonCode, "file target is outside the configured workspace roots", action.receipt)
	case "MEMORY_CLASS_DISALLOWED":
		b.addMissingControl("memory", action.runID, action.effectID, "memory.allowed_classes", action.reasonCode, "memory class is not allowed by policy", action.receipt)
	case "MEMORY_TTL_EXCEEDS_POLICY":
		b.addMissingControl("memory", action.runID, action.effectID, "memory.max_ttl_days", action.reasonCode, "memory TTL exceeds policy", action.receipt)
	case "RECURRING_LOOP_MISSING_SCHEDULE":
		b.addMissingControl("loop", action.runID, action.effectID, "recurring_loops.schedule", action.reasonCode, "recurring loop requires schedule", action.receipt)
	case "RECURRING_LOOP_MISSING_MAX_RUNTIME":
		b.addMissingControl("loop", action.runID, action.effectID, "recurring_loops.max_runtime", action.reasonCode, "recurring loop requires max runtime", action.receipt)
	case "RECURRING_LOOP_MISSING_TOOL_SCOPE":
		b.addMissingControl("loop", action.runID, action.effectID, "recurring_loops.tool_scope", action.reasonCode, "recurring loop requires tool scope", action.receipt)
	case "RECURRING_LOOP_MISSING_EXPIRATION":
		b.addMissingControl("loop", action.runID, action.effectID, "recurring_loops.expires_at", action.reasonCode, "recurring loop requires expiration", action.receipt)
	case "TAINTED_CONTEXT_REQUIRES_DENY":
		b.addMissingControl(action.boundary, action.runID, action.effectID, "taint.review", action.reasonCode, "tainted context cannot authorize operate-class effects", action.receipt)
	}
}

func (b *scopeAuditBuilder) addHighImpactMissingControls(action scopeAuditAction, metadata map[string]string) {
	switch action.boundary {
	case "secret":
		b.requireAnyMetadata(action, metadata, "secret.scope_or_ref", []string{"secret_scope", "secret_ref"}, "secret access should name a secret scope or secret reference")
		b.requireMetadata(action, metadata, "secret.redaction_ref", "redaction_ref", "secret audit should bind a redaction reference")
	case "deploy":
		for _, req := range []struct {
			control string
			key     string
			detail  string
		}{
			{"deploy.environment", "environment", "deploy audit should name the target environment"},
			{"deploy.artifact_digest", "artifact_digest", "deploy audit should bind the artifact digest"},
			{"deploy.approval_ref", "approval_ref", "deploy audit should bind the approval reference"},
			{"deploy.rollback_ref", "rollback_ref", "deploy audit should bind rollback evidence"},
			{"deploy.verification_ref", "verification_ref", "deploy audit should bind verification evidence"},
		} {
			b.requireMetadata(action, metadata, req.control, req.key, req.detail)
		}
	case "payment":
		for _, req := range []struct {
			control string
			key     string
			detail  string
		}{
			{"payment.amount", "amount", "payment audit should include amount"},
			{"payment.currency", "currency", "payment audit should include currency"},
			{"payment.counterparty_ref", "counterparty_ref", "payment audit should bind counterparty reference"},
			{"payment.spend_cap_ref", "spend_cap_ref", "payment audit should bind spend cap reference"},
			{"payment.idempotency_key", "idempotency_key", "payment audit should include idempotency key"},
			{"payment.ledger_ref", "ledger_ref", "payment audit should bind ledger reference"},
		} {
			b.requireMetadata(action, metadata, req.control, req.key, req.detail)
		}
	}
}

func (b *scopeAuditBuilder) requireMetadata(action scopeAuditAction, metadata map[string]string, control, key, detail string) {
	if strings.TrimSpace(metadata[key]) == "" {
		b.addMissingControl(action.boundary, action.runID, action.effectID, control, action.reasonCode, detail, action.receipt)
	}
}

func (b *scopeAuditBuilder) requireAnyMetadata(action scopeAuditAction, metadata map[string]string, control string, keys []string, detail string) {
	for _, key := range keys {
		if strings.TrimSpace(metadata[key]) != "" {
			return
		}
	}
	b.addMissingControl(action.boundary, action.runID, action.effectID, control, action.reasonCode, detail, action.receipt)
}

func (b *scopeAuditBuilder) addMissingControl(boundary, runID, effectID, control, reasonCode, detail, receipt string) {
	b.report.MissingControls = append(b.report.MissingControls, MissingControl{
		Boundary:   boundary,
		RunID:      runID,
		EffectID:   effectID,
		Control:    control,
		ReasonCode: reasonCode,
		Detail:     detail,
		Receipt:    receipt,
	})
}

func boundaryForEffect(effectType, action string) string {
	switch effectType {
	case contracts.EffectTypeWorkstationMCPToolCall:
		return "mcp"
	case contracts.EffectTypeWorkstationFileDraft, contracts.EffectTypeWorkstationFileWrite:
		return "filesystem"
	case contracts.EffectTypeWorkstationNetworkEgress:
		return "network"
	case contracts.EffectTypeWorkstationMemoryWrite:
		return "memory"
	case contracts.EffectTypeWorkstationSecretRead:
		return "secret"
	case contracts.EffectTypeWorkstationDeployPublish:
		return "deploy"
	case contracts.EffectTypeWorkstationPaymentInitiate:
		return "payment"
	case contracts.EffectTypeWorkstationRecurringLoop:
		return "loop"
	default:
		lower := strings.ToLower(action)
		switch {
		case strings.Contains(lower, "mcp"):
			return "mcp"
		case strings.Contains(lower, "file") || strings.Contains(lower, "write"):
			return "filesystem"
		case strings.Contains(lower, "network") || strings.Contains(lower, "egress"):
			return "network"
		case strings.Contains(lower, "memory"):
			return "memory"
		case strings.Contains(lower, "secret"):
			return "secret"
		case strings.Contains(lower, "deploy") || strings.Contains(lower, "publish"):
			return "deploy"
		case strings.Contains(lower, "payment") || strings.Contains(lower, "charge"):
			return "payment"
		case strings.Contains(lower, "loop") || strings.Contains(lower, "recurring"):
			return "loop"
		default:
			return "shell"
		}
	}
}

func isUnknownAction(action scopeAuditAction) bool {
	value := strings.ToLower(strings.Join([]string{action.toolID, action.target, action.action}, " "))
	return strings.Contains(value, "unknown") || strings.Contains(value, "untrusted")
}

func sanitizeMetadataForAudit(_ string, metadata map[string]string) map[string]string {
	if len(metadata) == 0 {
		return nil
	}
	out := map[string]string{}
	for key, value := range metadata {
		normalized := strings.ToLower(strings.TrimSpace(key))
		if normalized == "" {
			continue
		}
		if isAllowedSecretReferenceKey(normalized) || !secretLikeKey(normalized) {
			out[key] = value
			continue
		}
		out[key] = "[redacted]"
	}
	if len(out) == 0 {
		return nil
	}
	return sortedStringMap(out)
}

func isAllowedSecretReferenceKey(key string) bool {
	switch key {
	case "secret_scope", "secret_ref", "lease_ref", "redaction_ref":
		return true
	default:
		return false
	}
}

func secretLikeKey(key string) bool {
	for _, marker := range []string{"secret", "token", "password", "api_key", "credential", "private_key", "bearer"} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
}

func appendUnique(values []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func sortKey(t time.Time, parts ...string) string {
	return t.UTC().Format(time.RFC3339Nano) + "\x00" + strings.Join(parts, "\x00")
}

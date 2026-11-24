// Package workstation imports local agent-run artifacts into observe-only HELM
// Agent Run Receipts and deterministic ProofGraph nodes.
//
// quantum_posture: imported receipts use classical Ed25519 signing only; this
// package adds no post-quantum or hybrid cryptographic control.
package workstation

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
)

const (
	ManifestFile       = "run.manifest.json"
	DiffSummaryFile    = "git.diff-summary.json"
	ValidationFile     = "validation.json"
	ToolEventsFile     = "tool-events.ndjson"
	PolicyProfileFile  = "policy-profile.json"
	defaultActorType   = "agent"
	defaultSurface     = "codex"
	defaultWorkspaceID = "local-workstation"
)

type ImportOptions struct {
	SigningSeed []byte
}

type ImportResult struct {
	Receipt        *contracts.AgentRunReceipt `json:"receipt"`
	ProofGraph     []*proofgraph.Node         `json:"proofgraph"`
	PolicyProfile  contracts.WorkstationPolicyProfile
	ReplayRootHash string `json:"replay_root_hash"`
}

type RunManifest struct {
	RunID         string            `json:"run_id"`
	Goal          string            `json:"goal"`
	ActorID       string            `json:"actor_id"`
	ActorType     string            `json:"actor_type"`
	WorkspaceID   string            `json:"workspace_id"`
	WorkspacePath string            `json:"workspace_path"`
	Repository    string            `json:"repository"`
	AgentSurface  string            `json:"agent_surface"`
	PolicyProfile string            `json:"policy_profile"`
	StartedAt     time.Time         `json:"started_at"`
	CompletedAt   *time.Time        `json:"completed_at,omitempty"`
	SourceRefs    []string          `json:"source_refs,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type DiffSummary struct {
	Repository   string                       `json:"repository,omitempty"`
	BaseRef      string                       `json:"base_ref,omitempty"`
	HeadRef      string                       `json:"head_ref,omitempty"`
	ChangedFiles []contracts.AgentChangedFile `json:"changed_files"`
}

type ValidationArtifact struct {
	Commands []contracts.AgentValidationResult `json:"commands"`
}

type ToolEvent struct {
	EventID             string                              `json:"event_id"`
	Type                string                              `json:"type"`
	ToolID              string                              `json:"tool_id"`
	Action              string                              `json:"action"`
	EffectType          string                              `json:"effect_type"`
	EffectMode          string                              `json:"effect_mode"`
	Status              string                              `json:"status"`
	Verdict             string                              `json:"verdict"`
	ReasonCode          string                              `json:"reason_code"`
	Reason              string                              `json:"reason"`
	Target              string                              `json:"target"`
	OccurredAt          time.Time                           `json:"occurred_at"`
	Metadata            map[string]string                   `json:"metadata,omitempty"`
	TaintLabels         []string                            `json:"taint_labels,omitempty"`
	MemoryEffect        *contracts.AgentMemoryEffect        `json:"memory_effect,omitempty"`
	RecurringLoopEffect *contracts.AgentRecurringLoopEffect `json:"recurring_loop_effect,omitempty"`
}

func ImportArtifactDir(dir string, opts ImportOptions) (*ImportResult, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("artifact directory is required")
	}
	manifest, artifactHashes, err := readManifest(dir)
	if err != nil {
		return nil, err
	}
	diff, err := readOptionalJSON[DiffSummary](filepath.Join(dir, DiffSummaryFile))
	if err != nil {
		return nil, err
	}
	validation, err := readOptionalJSON[ValidationArtifact](filepath.Join(dir, ValidationFile))
	if err != nil {
		return nil, err
	}
	events, err := readToolEvents(filepath.Join(dir, ToolEventsFile))
	if err != nil {
		return nil, err
	}
	if diff != nil {
		artifactHashes[DiffSummaryFile] = mustHashFile(filepath.Join(dir, DiffSummaryFile))
		sortChangedFiles(diff.ChangedFiles)
	}
	if validation != nil {
		artifactHashes[ValidationFile] = mustHashFile(filepath.Join(dir, ValidationFile))
		sortValidation(validation.Commands)
	}
	if _, err := os.Stat(filepath.Join(dir, ToolEventsFile)); err == nil {
		artifactHashes[ToolEventsFile] = mustHashFile(filepath.Join(dir, ToolEventsFile))
	}
	if _, err := os.Stat(filepath.Join(dir, PolicyProfileFile)); err == nil {
		artifactHashes[PolicyProfileFile] = mustHashFile(filepath.Join(dir, PolicyProfileFile))
	}
	for _, path := range mustGlob(filepath.Join(dir, "receipts", "*.json")) {
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return nil, err
		}
		artifactHashes[filepath.ToSlash(rel)] = mustHashFile(path)
	}
	profile, err := readPolicyProfile(dir)
	if err != nil {
		return nil, err
	}
	return BuildReceipt(*manifest, optionalDiff(diff), optionalValidation(validation), events, profile, artifactHashes, opts)
}

func BuildReceipt(
	manifest RunManifest,
	diff DiffSummary,
	validation ValidationArtifact,
	events []ToolEvent,
	profile contracts.WorkstationPolicyProfile,
	artifactHashes map[string]string,
	opts ImportOptions,
) (*ImportResult, error) {
	normalizeManifest(&manifest)
	sortToolEvents(events)

	toolActions, memoryEffects, recurringEffects, deniedEffects := normalizeEvents(profile, events)
	changedFiles := append([]contracts.AgentChangedFile(nil), diff.ChangedFiles...)
	sortChangedFiles(changedFiles)
	for _, file := range changedFiles {
		toolActions = append(toolActions, contracts.AgentToolAction{
			ActionID:   deterministicID("file", manifest.RunID, file.Path, file.Status),
			ToolID:     "git.diff",
			Action:     "draft_file_change",
			EffectType: contracts.EffectTypeWorkstationFileDraft,
			EffectMode: contracts.WorkstationEffectModeDraft,
			Status:     "observed",
			Verdict:    contracts.WorkstationVerdictAllow,
			Target:     file.Path,
			OccurredAt: manifestTimestamp(manifest),
		})
	}
	sortToolActions(toolActions)
	sortMemoryEffects(memoryEffects)
	sortRecurringEffects(recurringEffects)
	sortDeniedEffects(deniedEffects)

	nodes, err := buildProofGraph(manifest, artifactHashes, changedFiles, validation.Commands, toolActions, memoryEffects, recurringEffects, deniedEffects)
	if err != nil {
		return nil, err
	}
	proofRefs := make([]string, 0, len(nodes))
	for _, node := range nodes {
		proofRefs = append(proofRefs, node.NodeHash)
	}

	evidenceRefs := []string{
		"artifact-root:" + canonicalHashOrPanic(artifactHashes),
	}
	receipt := &contracts.AgentRunReceipt{
		ReceiptVersion:       contracts.AgentRunReceiptVersion,
		ReceiptID:            deterministicID("arr", manifest.RunID, canonicalHashOrPanic(artifactHashes)),
		RunID:                manifest.RunID,
		Goal:                 manifest.Goal,
		Actor:                contracts.AgentRunActor{ActorID: manifest.ActorID, ActorType: manifest.ActorType},
		Workspace:            contracts.AgentRunWorkspace{WorkspaceID: manifest.WorkspaceID, Path: manifest.WorkspacePath, Repository: firstNonEmpty(manifest.Repository, diff.Repository)},
		AgentSurface:         manifest.AgentSurface,
		PolicyProfile:        firstNonEmpty(manifest.PolicyProfile, profile.ID),
		ArtifactHashes:       sortedStringMap(artifactHashes),
		ToolActions:          toolActions,
		ChangedFiles:         changedFiles,
		ValidationResults:    validation.Commands,
		MemoryEffects:        memoryEffects,
		RecurringLoopEffects: recurringEffects,
		DeniedEffects:        deniedEffects,
		ProofGraphRefs:       proofRefs,
		EvidencePackRefs:     evidenceRefs,
		CreatedAt:            manifestTimestamp(manifest),
		CompletedAt:          manifest.CompletedAt,
		SignerKeyID:          "workstation-observe-only-ed25519",
	}
	normalizeReceiptCollections(receipt)
	if err := signReceipt(receipt, opts.SigningSeed); err != nil {
		return nil, err
	}

	checkpoint, err := appendCheckpoint(nodes, manifest, receipt)
	if err != nil {
		return nil, err
	}
	nodes = append(nodes, checkpoint)

	replayRoot, err := canonicalize.CanonicalHash(struct {
		Receipt    *contracts.AgentRunReceipt `json:"receipt"`
		ProofGraph []*proofgraph.Node         `json:"proofgraph"`
	}{Receipt: receipt, ProofGraph: nodes})
	if err != nil {
		return nil, fmt.Errorf("compute replay root: %w", err)
	}
	return &ImportResult{Receipt: receipt, ProofGraph: nodes, PolicyProfile: profile, ReplayRootHash: replayRoot}, nil
}

func readManifest(dir string) (*RunManifest, map[string]string, error) {
	path := filepath.Join(dir, ManifestFile)
	manifest, err := readRequiredJSON[RunManifest](path)
	if err != nil {
		return nil, nil, err
	}
	return manifest, map[string]string{ManifestFile: mustHashFile(path)}, nil
}

func readPolicyProfile(dir string) (contracts.WorkstationPolicyProfile, error) {
	path := filepath.Join(dir, PolicyProfileFile)
	profile, err := readOptionalJSON[contracts.WorkstationPolicyProfile](path)
	if err != nil {
		return contracts.WorkstationPolicyProfile{}, err
	}
	if profile == nil {
		p := DefaultObserveDraftProfile()
		return p, nil
	}
	if profile.ID == "" {
		return contracts.WorkstationPolicyProfile{}, fmt.Errorf("%s: id is required", PolicyProfileFile)
	}
	return *profile, nil
}

func readRequiredJSON[T any](path string) (*T, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	var out T
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("parse %s: %w", filepath.Base(path), err)
	}
	return &out, nil
}

func readOptionalJSON[T any](path string) (*T, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat %s: %w", filepath.Base(path), err)
	}
	return readRequiredJSON[T](path)
}

func readToolEvents(path string) ([]ToolEvent, error) {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open %s: %w", filepath.Base(path), err)
	}
	defer file.Close()

	var events []ToolEvent
	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var event ToolEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", filepath.Base(path), lineNo, err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", filepath.Base(path), err)
	}
	return events, nil
}

func normalizeReceiptCollections(receipt *contracts.AgentRunReceipt) {
	if receipt.ArtifactHashes == nil {
		receipt.ArtifactHashes = map[string]string{}
	}
	if receipt.ToolActions == nil {
		receipt.ToolActions = []contracts.AgentToolAction{}
	}
	if receipt.ChangedFiles == nil {
		receipt.ChangedFiles = []contracts.AgentChangedFile{}
	}
	if receipt.ValidationResults == nil {
		receipt.ValidationResults = []contracts.AgentValidationResult{}
	}
	if receipt.MemoryEffects == nil {
		receipt.MemoryEffects = []contracts.AgentMemoryEffect{}
	}
	if receipt.RecurringLoopEffects == nil {
		receipt.RecurringLoopEffects = []contracts.AgentRecurringLoopEffect{}
	}
	if receipt.DeniedEffects == nil {
		receipt.DeniedEffects = []contracts.AgentDeniedEffect{}
	}
	if receipt.ProofGraphRefs == nil {
		receipt.ProofGraphRefs = []string{}
	}
	if receipt.EvidencePackRefs == nil {
		receipt.EvidencePackRefs = []string{}
	}
}

func WriteResult(path string, result *ImportResult) error {
	if result == nil {
		return errors.New("result is nil")
	}
	data, err := canonicalize.JCS(result)
	if err != nil {
		return err
	}
	if path == "" {
		_, err = io.Copy(io.Discard, bytes.NewReader(data))
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func Summary(receipt *contracts.AgentRunReceipt) map[string]any {
	if receipt == nil {
		return map[string]any{}
	}
	return map[string]any{
		"receipt_id":       receipt.ReceiptID,
		"run_id":           receipt.RunID,
		"goal":             receipt.Goal,
		"agent_surface":    receipt.AgentSurface,
		"policy_profile":   receipt.PolicyProfile,
		"tool_actions":     len(receipt.ToolActions),
		"changed_files":    len(receipt.ChangedFiles),
		"validation_count": len(receipt.ValidationResults),
		"memory_effects":   len(receipt.MemoryEffects),
		"recurring_loops":  len(receipt.RecurringLoopEffects),
		"denied_effects":   len(receipt.DeniedEffects),
		"proof_nodes":      len(receipt.ProofGraphRefs),
		"receipt_hash":     receipt.ReceiptHash,
	}
}

func LoadResult(path string) (*ImportResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var result ImportResult
	if err := json.Unmarshal(data, &result); err == nil && result.Receipt != nil {
		return &result, nil
	}
	var receipt contracts.AgentRunReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		return nil, err
	}
	return &ImportResult{Receipt: &receipt}, nil
}

func normalizeManifest(manifest *RunManifest) {
	if manifest.RunID == "" {
		manifest.RunID = deterministicID("run", manifest.Goal, manifest.WorkspacePath, manifest.AgentSurface)
	}
	if manifest.ActorID == "" {
		manifest.ActorID = "agent.local"
	}
	if manifest.ActorType == "" {
		manifest.ActorType = defaultActorType
	}
	if manifest.WorkspaceID == "" {
		manifest.WorkspaceID = defaultWorkspaceID
	}
	if manifest.AgentSurface == "" {
		manifest.AgentSurface = defaultSurface
	}
	if manifest.PolicyProfile == "" {
		manifest.PolicyProfile = contracts.PolicyProfileWorkstationObserveDraftV1
	}
}

func manifestTimestamp(manifest RunManifest) time.Time {
	if !manifest.StartedAt.IsZero() {
		return manifest.StartedAt.UTC()
	}
	if manifest.CompletedAt != nil && !manifest.CompletedAt.IsZero() {
		return manifest.CompletedAt.UTC()
	}
	return time.Unix(0, 0).UTC()
}

func optionalDiff(in *DiffSummary) DiffSummary {
	if in == nil {
		return DiffSummary{}
	}
	return *in
}

func optionalValidation(in *ValidationArtifact) ValidationArtifact {
	if in == nil {
		return ValidationArtifact{}
	}
	return *in
}

func mustHashFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return hashBytes(data)
}

func mustGlob(pattern string) []string {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		panic(err)
	}
	sort.Strings(matches)
	return matches
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func deterministicID(prefix string, parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return prefix + "_" + hex.EncodeToString(sum[:])[:24]
}

func canonicalHashOrPanic(v any) string {
	hash, err := canonicalize.CanonicalHash(v)
	if err != nil {
		panic(err)
	}
	return hash
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func sortedStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out[key] = in[key]
	}
	return out
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func containsFold(values []string, value string) bool {
	for _, candidate := range values {
		if strings.EqualFold(candidate, value) {
			return true
		}
	}
	return false
}

func sortToolEvents(events []ToolEvent) {
	sort.SliceStable(events, func(i, j int) bool {
		if !events[i].OccurredAt.Equal(events[j].OccurredAt) {
			return events[i].OccurredAt.Before(events[j].OccurredAt)
		}
		return events[i].EventID < events[j].EventID
	})
}

func sortToolActions(actions []contracts.AgentToolAction) {
	sort.SliceStable(actions, func(i, j int) bool {
		if !actions[i].OccurredAt.Equal(actions[j].OccurredAt) {
			return actions[i].OccurredAt.Before(actions[j].OccurredAt)
		}
		return actions[i].ActionID < actions[j].ActionID
	})
}

func sortChangedFiles(files []contracts.AgentChangedFile) {
	sort.SliceStable(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})
}

func sortValidation(results []contracts.AgentValidationResult) {
	sort.SliceStable(results, func(i, j int) bool {
		return results[i].Command < results[j].Command
	})
}

func sortMemoryEffects(effects []contracts.AgentMemoryEffect) {
	sort.SliceStable(effects, func(i, j int) bool {
		return effects[i].EffectID < effects[j].EffectID
	})
}

func sortRecurringEffects(effects []contracts.AgentRecurringLoopEffect) {
	sort.SliceStable(effects, func(i, j int) bool {
		return effects[i].EffectID < effects[j].EffectID
	})
}

func sortDeniedEffects(effects []contracts.AgentDeniedEffect) {
	sort.SliceStable(effects, func(i, j int) bool {
		if !effects[i].OccurredAt.Equal(effects[j].OccurredAt) {
			return effects[i].OccurredAt.Before(effects[j].OccurredAt)
		}
		return effects[i].EffectID < effects[j].EffectID
	})
}

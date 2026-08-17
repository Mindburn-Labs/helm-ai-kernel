// quantum_posture: savings evidence packs re-derive SHA-256 content hashes and
// verify classical Ed25519 BudgetVerdict signatures against an embedded
// trusted-key registry; no post-quantum primitives are used in this file.

// savings_evidence.go extends the spend EvidencePack (spend_evidence.go) with
// the paired-replay SAVINGS view required by the HELM-614 methodology:
//
//   - a task-split manifest (selection/holdout assignment + frozen selection),
//   - a per-task results artifact (pass/fail per route, no prompt bodies),
//   - a parity pre-run artifact (selection set across substitute candidates),
//   - the price-book snapshot (the exact config bytes every quote binds via
//     provider_price_snapshot_hash),
//   - per-call receipt sets for every governed call in the capture, and
//   - views/savings_view.json: cost-per-successful-task (CPST) per route on
//     the holdout set, the strict parity bar, and the savings claim bound to
//     capture-window prices.
//
// Everything in the view is recomputable offline from the pack bytes alone:
// VerifySavingsEvidenceOffline re-derives the manifest hash, re-hashes every
// receipt, recomputes CPST and pass rates from receipts + artifacts, checks
// paired task ids, checks that the frozen selection predates every holdout
// call, re-binds the price book, verifies verdict signatures against the
// embedded registry, and proves no prompt body leaked into views.
package evidencepack

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// Savings pack entry paths.
const (
	savingsReceiptsPrefix = "receipts/"

	savingsTaskSplitPath   = "artifacts/task_split_manifest.json"
	savingsTaskResultsPath = "artifacts/task_results.json"
	savingsParityPath      = "artifacts/parity_prerun.json"
	savingsPriceBookPath   = "artifacts/price_book_config.json"
	savingsTrustedKeysPath = "artifacts/trusted_keys.json"

	savingsViewPath = "views/savings_view.json"
)

// Subset and phase labels used by the task-split manifest and results.
const (
	SavingsSubsetSelection = "selection"
	SavingsSubsetHoldout   = "holdout"
	SavingsPhaseParity     = "parity"
	SavingsPhaseHoldout    = "holdout"
)

// SavingsClaimWording is the fixed time-binding wording required by the
// methodology: claims hold at capture-window prices only.
const SavingsClaimWording = "Savings at capture-window prices; every cost is bound to the per-call provider_price_snapshot_hash in the receipts. No forward-looking guarantee: a new price regime requires a new pack."

// SavingsTaskAssignment assigns one task id to the selection or holdout subset.
type SavingsTaskAssignment struct {
	TaskID string `json:"task_id"`
	Subset string `json:"subset"`
}

// SavingsCandidate names one substitute-candidate route used by the parity
// pre-run.
type SavingsCandidate struct {
	EnvelopeID string `json:"envelope_id"`
	ModelID    string `json:"model_id"`
}

// SavingsSelectionFreeze is the frozen substitute choice. It must be written
// (and committed) BEFORE any holdout capture; the offline verifier enforces
// FrozenAt < every holdout quote's CreatedAt.
type SavingsSelectionFreeze struct {
	FrozenAt                   time.Time `json:"frozen_at"`
	ChosenSubstituteEnvelopeID string    `json:"chosen_substitute_envelope_id"`
	ChosenSubstituteModelID    string    `json:"chosen_substitute_model_id"`
	ParityResultsSHA256        string    `json:"parity_results_sha256"`
	GitCommit                  string    `json:"git_commit,omitempty"`
	Rationale                  string    `json:"rationale,omitempty"`
}

// SavingsTaskSplitManifest is the task-split manifest artifact. Task ids only —
// prompt bodies live in the repo task set referenced by TaskSetSHA256 and never
// enter the pack.
type SavingsTaskSplitManifest struct {
	SchemaVersion      string                  `json:"schema_version"`
	RunID              string                  `json:"run_id"`
	TenantID           string                  `json:"tenant_id"`
	TaskSetSHA256      string                  `json:"task_set_sha256"`
	BaselineEnvelopeID string                  `json:"baseline_envelope_id"`
	BaselineModelID    string                  `json:"baseline_model_id"`
	CandidateRoutes    []SavingsCandidate      `json:"candidate_routes"`
	Tasks              []SavingsTaskAssignment `json:"tasks"`
	SelectionFreeze    SavingsSelectionFreeze  `json:"selection_freeze"`
}

// SavingsTaskSplitSchemaVersion is the accepted manifest schema version.
const SavingsTaskSplitSchemaVersion = "helm-savings-task-split.v1"

// SavingsTaskResult is one task execution on one route. ResponseSHA256 is the
// only trace of the model output; bodies stay off-graph.
type SavingsTaskResult struct {
	TaskID           string    `json:"task_id"`
	Phase            string    `json:"phase"`
	EnvelopeID       string    `json:"envelope_id"`
	RequestedModelID string    `json:"requested_model_id"`
	IdempotencyKey   string    `json:"idempotency_key"`
	SpendIntentID    string    `json:"spend_intent_id"`
	Passed           bool      `json:"passed"`
	FailureReason    string    `json:"failure_reason,omitempty"`
	HTTPStatus       int       `json:"http_status"`
	FinishReason     string    `json:"finish_reason,omitempty"`
	ResponseSHA256   string    `json:"response_sha256,omitempty"`
	CompletedAt      time.Time `json:"completed_at"`
}

// SavingsTaskResults is the per-task results artifact.
type SavingsTaskResults struct {
	SchemaVersion string              `json:"schema_version"`
	RunID         string              `json:"run_id"`
	Results       []SavingsTaskResult `json:"results"`
}

// SavingsTaskResultsSchemaVersion is the accepted results schema version.
const SavingsTaskResultsSchemaVersion = "helm-savings-task-results.v1"

// SavingsParityCandidateResult aggregates one route's selection-set outcome.
type SavingsParityCandidateResult struct {
	EnvelopeID        string `json:"envelope_id"`
	DispatchedModelID string `json:"dispatched_model_id"`
	TasksRun          int    `json:"tasks_run"`
	TasksPassed       int    `json:"tasks_passed"`
}

// SavingsParityResults is the parity pre-run artifact (selection set).
type SavingsParityResults struct {
	SchemaVersion    string                         `json:"schema_version"`
	RunID            string                         `json:"run_id"`
	SelectionTaskIDs []string                       `json:"selection_task_ids"`
	Baseline         SavingsParityCandidateResult   `json:"baseline"`
	Candidates       []SavingsParityCandidateResult `json:"candidates"`
}

// SavingsParitySchemaVersion is the accepted parity artifact schema version.
const SavingsParitySchemaVersion = "helm-savings-parity-prerun.v1"

// SavingsRouteStats is one route's recomputable holdout-window aggregate.
// SpendCents covers ALL settled spend on the route's envelope from the freeze
// instant on — successes, failures, and retries — per the CPST definition.
type SavingsRouteStats struct {
	Role              string `json:"role"`
	EnvelopeID        string `json:"envelope_id"`
	RequestedModelID  string `json:"requested_model_id"`
	DispatchedModelID string `json:"dispatched_model_id"`
	SettledCalls      int    `json:"settled_calls"`
	SpendCents        int64  `json:"spend_cents"`
	InputTokens       int64  `json:"input_tokens"`
	OutputTokens      int64  `json:"output_tokens"`
	TasksTotal        int    `json:"tasks_total"`
	TasksPassed       int    `json:"tasks_passed"`
	// CPSTMicroCents = SpendCents * 1_000_000 / TasksPassed, integer division
	// truncated toward zero. Zero when TasksPassed is zero (CPST undefined).
	CPSTMicroCents int64 `json:"cpst_micro_cents"`
}

// SavingsWindow is the capture window the claim is bound to. Start is the
// selection-freeze instant; End is the latest receipt timestamp observed on the
// holdout routes (informational — membership is defined by Start alone).
type SavingsWindow struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// SavingsFreezeBinding echoes the frozen selection into the view together with
// the artifact hashes the verifier re-derives.
type SavingsFreezeBinding struct {
	FrozenAt                   time.Time `json:"frozen_at"`
	TaskSplitManifestSHA256    string    `json:"task_split_manifest_sha256"`
	ParityResultsSHA256        string    `json:"parity_results_sha256"`
	GitCommit                  string    `json:"git_commit,omitempty"`
	ChosenSubstituteEnvelopeID string    `json:"chosen_substitute_envelope_id"`
	ChosenSubstituteModelID    string    `json:"chosen_substitute_model_id"`
}

// SavingsView is the business-readable savings claim. Every number is
// recomputable offline from the pack's receipts and artifacts.
type SavingsView struct {
	SchemaVersion            string               `json:"schema_version"`
	RunID                    string               `json:"run_id"`
	Wording                  string               `json:"wording"`
	CaptureWindow            SavingsWindow        `json:"capture_window"`
	PriceBookSHA256          string               `json:"price_book_sha256"`
	Baseline                 SavingsRouteStats    `json:"baseline"`
	Substitute               SavingsRouteStats    `json:"substitute"`
	ParityBarMet             bool                 `json:"parity_bar_met"`
	SavingsClaimValid        bool                 `json:"savings_claim_valid"`
	SavingsPerTaskMicroCents int64                `json:"savings_per_task_micro_cents"`
	SavingsPercentBps        int64                `json:"savings_percent_bps"`
	SelectionFreeze          SavingsFreezeBinding `json:"selection_freeze"`
	Notes                    []string             `json:"notes,omitempty"`
}

// SavingsViewSchemaVersion is the accepted savings view schema version.
const SavingsViewSchemaVersion = "helm-savings-view.v1"

// decodeStrict unmarshals JSON refusing unknown fields — pack artifacts are
// evidence, not best effort.
func decodeStrict(raw []byte, v interface{}, what string) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("savings evidence: decode %s: %w", what, err)
	}
	return nil
}

// ValidateSavingsArtifacts checks schema versions and internal consistency of
// the three savings artifacts.
func ValidateSavingsArtifacts(man *SavingsTaskSplitManifest, res *SavingsTaskResults, par *SavingsParityResults) error {
	if man.SchemaVersion != SavingsTaskSplitSchemaVersion {
		return fmt.Errorf("savings evidence: task-split manifest schema %q, want %q", man.SchemaVersion, SavingsTaskSplitSchemaVersion)
	}
	if res.SchemaVersion != SavingsTaskResultsSchemaVersion {
		return fmt.Errorf("savings evidence: task results schema %q, want %q", res.SchemaVersion, SavingsTaskResultsSchemaVersion)
	}
	if par.SchemaVersion != SavingsParitySchemaVersion {
		return fmt.Errorf("savings evidence: parity artifact schema %q, want %q", par.SchemaVersion, SavingsParitySchemaVersion)
	}
	if man.RunID == "" || man.RunID != res.RunID || man.RunID != par.RunID {
		return fmt.Errorf("savings evidence: run ids disagree (manifest %q, results %q, parity %q)", man.RunID, res.RunID, par.RunID)
	}
	if man.BaselineEnvelopeID == "" || man.BaselineModelID == "" {
		return errors.New("savings evidence: manifest baseline envelope and model are required")
	}
	if man.SelectionFreeze.FrozenAt.IsZero() {
		return errors.New("savings evidence: selection freeze timestamp is required")
	}
	if man.SelectionFreeze.ChosenSubstituteEnvelopeID == "" || man.SelectionFreeze.ChosenSubstituteModelID == "" {
		return errors.New("savings evidence: frozen substitute envelope and model are required")
	}
	chosenDeclared := false
	for _, c := range man.CandidateRoutes {
		if c.EnvelopeID == man.SelectionFreeze.ChosenSubstituteEnvelopeID && c.ModelID == man.SelectionFreeze.ChosenSubstituteModelID {
			chosenDeclared = true
		}
	}
	if !chosenDeclared {
		return errors.New("savings evidence: frozen substitute is not one of the declared candidate routes")
	}
	seen := make(map[string]string, len(man.Tasks))
	for _, t := range man.Tasks {
		if t.TaskID == "" {
			return errors.New("savings evidence: manifest task with empty id")
		}
		if t.Subset != SavingsSubsetSelection && t.Subset != SavingsSubsetHoldout {
			return fmt.Errorf("savings evidence: task %s has unknown subset %q", t.TaskID, t.Subset)
		}
		if _, dup := seen[t.TaskID]; dup {
			return fmt.Errorf("savings evidence: task %s assigned twice", t.TaskID)
		}
		seen[t.TaskID] = t.Subset
	}
	for _, r := range res.Results {
		if r.Phase != SavingsPhaseParity && r.Phase != SavingsPhaseHoldout {
			return fmt.Errorf("savings evidence: result for task %s has unknown phase %q", r.TaskID, r.Phase)
		}
		subset, ok := seen[r.TaskID]
		if !ok {
			return fmt.Errorf("savings evidence: result references unknown task %s", r.TaskID)
		}
		if r.Phase == SavingsPhaseHoldout && subset != SavingsSubsetHoldout {
			return fmt.Errorf("savings evidence: holdout result for non-holdout task %s", r.TaskID)
		}
		if r.Phase == SavingsPhaseParity && subset != SavingsSubsetSelection {
			return fmt.Errorf("savings evidence: parity result for non-selection task %s", r.TaskID)
		}
		if r.SpendIntentID == "" || r.EnvelopeID == "" {
			return fmt.Errorf("savings evidence: result for task %s is missing spend intent or envelope", r.TaskID)
		}
	}
	return nil
}

// ComputeSavingsView recomputes the full savings view from receipt sets and
// artifacts. The exporter uses it to render views/savings_view.json and the
// offline verifier re-runs it against the pack bytes, so a claim can never
// drift from what the receipts support.
func ComputeSavingsView(sets map[string]SpendReceiptSet, man *SavingsTaskSplitManifest, res *SavingsTaskResults, priceBookSHA256 string) (*SavingsView, error) {
	if err := validateSavingsReceiptSets(sets); err != nil {
		return nil, err
	}

	holdoutTasks := make(map[string]bool)
	for _, t := range man.Tasks {
		if t.Subset == SavingsSubsetHoldout {
			holdoutTasks[t.TaskID] = true
		}
	}
	if len(holdoutTasks) == 0 {
		return nil, errors.New("savings evidence: manifest declares no holdout tasks")
	}

	freeze := man.SelectionFreeze
	baseline := SavingsRouteStats{
		Role:             "baseline",
		EnvelopeID:       man.BaselineEnvelopeID,
		RequestedModelID: man.BaselineModelID,
	}
	substitute := SavingsRouteStats{
		Role:             "substitute",
		EnvelopeID:       freeze.ChosenSubstituteEnvelopeID,
		RequestedModelID: man.BaselineModelID,
	}

	// Holdout results: exactly one per task per route; count passes.
	type routeSeen map[string]bool
	baselineSeen, substituteSeen := routeSeen{}, routeSeen{}
	resultIntents := make(map[string]*SavingsTaskResult)
	for i := range res.Results {
		r := &res.Results[i]
		if prev, dup := resultIntents[r.SpendIntentID]; dup {
			return nil, fmt.Errorf("savings evidence: spend intent %s referenced by both task %s and task %s", r.SpendIntentID, prev.TaskID, r.TaskID)
		}
		resultIntents[r.SpendIntentID] = r
		if r.Phase != SavingsPhaseHoldout {
			continue
		}
		var stats *SavingsRouteStats
		var seen routeSeen
		switch r.EnvelopeID {
		case baseline.EnvelopeID:
			stats, seen = &baseline, baselineSeen
		case substitute.EnvelopeID:
			stats, seen = &substitute, substituteSeen
		default:
			return nil, fmt.Errorf("savings evidence: holdout result for task %s uses unknown envelope %q", r.TaskID, r.EnvelopeID)
		}
		if seen[r.TaskID] {
			return nil, fmt.Errorf("savings evidence: duplicate holdout result for task %s on envelope %s", r.TaskID, r.EnvelopeID)
		}
		seen[r.TaskID] = true
		stats.TasksTotal++
		if r.Passed {
			stats.TasksPassed++
		}
	}

	// Paired-ness: both routes must cover exactly the manifest holdout set.
	for task := range holdoutTasks {
		if !baselineSeen[task] {
			return nil, fmt.Errorf("savings evidence: holdout task %s has no baseline result", task)
		}
		if !substituteSeen[task] {
			return nil, fmt.Errorf("savings evidence: holdout task %s has no substitute result", task)
		}
	}
	if baseline.TasksTotal != len(holdoutTasks) || substitute.TasksTotal != len(holdoutTasks) {
		return nil, fmt.Errorf("savings evidence: holdout coverage mismatch (baseline %d, substitute %d, manifest %d)", baseline.TasksTotal, substitute.TasksTotal, len(holdoutTasks))
	}

	// Receipt sweep: settled spend per route from the freeze instant on, plus
	// dispatched-model truthfulness and freeze ordering.
	window := SavingsWindow{Start: freeze.FrozenAt}
	for intentID, set := range sets {
		result := resultIntents[intentID]
		quote := set.RouteQuote
		if result == nil {
			// Every receipt in the pack must be attributable to a task result —
			// unattributed spend would silently distort CPST.
			return nil, fmt.Errorf("savings evidence: receipt set %s is not referenced by any task result", intentID)
		}
		if quote == nil {
			return nil, fmt.Errorf("savings evidence: receipt set %s has no route quote", intentID)
		}
		if quote.EnvelopeID != result.EnvelopeID {
			return nil, fmt.Errorf("savings evidence: intent %s quote envelope %q does not match result envelope %q", intentID, quote.EnvelopeID, result.EnvelopeID)
		}
		if result.Phase == SavingsPhaseParity {
			if !quote.CreatedAt.Before(freeze.FrozenAt) {
				return nil, fmt.Errorf("savings evidence: parity call %s (task %s) at %s does not precede the selection freeze %s", intentID, result.TaskID, quote.CreatedAt.Format(time.RFC3339Nano), freeze.FrozenAt.Format(time.RFC3339Nano))
			}
			continue
		}
		// Holdout: the freeze must strictly precede every holdout call.
		if !freeze.FrozenAt.Before(quote.CreatedAt) {
			return nil, fmt.Errorf("savings evidence: holdout call %s (task %s) at %s does not follow the selection freeze %s", intentID, result.TaskID, quote.CreatedAt.Format(time.RFC3339Nano), freeze.FrozenAt.Format(time.RFC3339Nano))
		}
		var stats *SavingsRouteStats
		switch quote.EnvelopeID {
		case baseline.EnvelopeID:
			stats = &baseline
			if quote.ModelSubstituted {
				return nil, fmt.Errorf("savings evidence: baseline call %s reports model substitution", intentID)
			}
			if quote.SelectedModelID != man.BaselineModelID || quote.RequestedModelID != man.BaselineModelID {
				return nil, fmt.Errorf("savings evidence: baseline call %s routed %s -> %s, want %s unchanged", intentID, quote.RequestedModelID, quote.SelectedModelID, man.BaselineModelID)
			}
		case substitute.EnvelopeID:
			stats = &substitute
			if !quote.ModelSubstituted {
				return nil, fmt.Errorf("savings evidence: substitute call %s does not report ModelSubstituted", intentID)
			}
			if quote.RequestedModelID != man.BaselineModelID {
				return nil, fmt.Errorf("savings evidence: substitute call %s requested %q, want baseline %q", intentID, quote.RequestedModelID, man.BaselineModelID)
			}
			if quote.SelectedModelID != freeze.ChosenSubstituteModelID {
				return nil, fmt.Errorf("savings evidence: substitute call %s dispatched %q, want frozen choice %q", intentID, quote.SelectedModelID, freeze.ChosenSubstituteModelID)
			}
		default:
			return nil, fmt.Errorf("savings evidence: holdout call %s uses unknown envelope %q", intentID, quote.EnvelopeID)
		}
		if stats.DispatchedModelID == "" {
			stats.DispatchedModelID = quote.SelectedModelID
		}
		if result.Passed && (set.Usage == nil || set.Settlement == nil) {
			return nil, fmt.Errorf("savings evidence: passed holdout task %s (intent %s) has no settled usage", result.TaskID, intentID)
		}
		if set.Usage != nil {
			if set.Settlement == nil {
				return nil, fmt.Errorf("savings evidence: intent %s has usage without settlement", intentID)
			}
			if set.Usage.EnvelopeID != quote.EnvelopeID {
				return nil, fmt.Errorf("savings evidence: intent %s usage envelope %q disagrees with quote envelope %q", intentID, set.Usage.EnvelopeID, quote.EnvelopeID)
			}
			stats.SettledCalls++
			stats.SpendCents += set.Usage.BalanceDebitCents
			stats.InputTokens += set.Usage.InputTokens
			stats.OutputTokens += set.Usage.OutputTokens
			if set.Usage.CreatedAt.After(window.End) {
				window.End = set.Usage.CreatedAt
			}
		}
		if quote.CreatedAt.After(window.End) {
			window.End = quote.CreatedAt
		}
	}

	if baseline.TasksPassed > 0 {
		baseline.CPSTMicroCents = baseline.SpendCents * 1_000_000 / int64(baseline.TasksPassed)
	}
	if substitute.TasksPassed > 0 {
		substitute.CPSTMicroCents = substitute.SpendCents * 1_000_000 / int64(substitute.TasksPassed)
	}

	// Strict parity bar: substitute pass count >= baseline pass count over the
	// identical holdout set (equal denominators make rate comparison a count
	// comparison).
	parityBarMet := substitute.TasksPassed >= baseline.TasksPassed
	claimValid := parityBarMet && baseline.TasksPassed > 0 && substitute.TasksPassed > 0

	view := &SavingsView{
		SchemaVersion:     SavingsViewSchemaVersion,
		RunID:             man.RunID,
		Wording:           SavingsClaimWording,
		CaptureWindow:     window,
		PriceBookSHA256:   priceBookSHA256,
		Baseline:          baseline,
		Substitute:        substitute,
		ParityBarMet:      parityBarMet,
		SavingsClaimValid: claimValid,
		SelectionFreeze: SavingsFreezeBinding{
			FrozenAt:                   freeze.FrozenAt,
			ParityResultsSHA256:        freeze.ParityResultsSHA256,
			GitCommit:                  freeze.GitCommit,
			ChosenSubstituteEnvelopeID: freeze.ChosenSubstituteEnvelopeID,
			ChosenSubstituteModelID:    freeze.ChosenSubstituteModelID,
		},
	}
	if baseline.CPSTMicroCents > 0 && substitute.CPSTMicroCents > 0 {
		view.SavingsPerTaskMicroCents = baseline.CPSTMicroCents - substitute.CPSTMicroCents
		view.SavingsPercentBps = (baseline.CPSTMicroCents - substitute.CPSTMicroCents) * 10_000 / baseline.CPSTMicroCents
	}
	if !parityBarMet {
		view.Notes = append(view.Notes, "Parity bar FAILED: the substitute passed fewer holdout tasks than the baseline. No savings claim is made; this pack records the negative result.")
	}
	return view, nil
}

func validateSavingsReceiptSets(sets map[string]SpendReceiptSet) error {
	if len(sets) == 0 {
		return errors.New("savings evidence: at least one receipt set is required")
	}
	return nil
}

// SavingsPackInputs is everything BuildSavingsEvidencePack binds together.
// Artifact byte slices are embedded verbatim so their hashes match the files
// the capture produced.
type SavingsPackInputs struct {
	PackID     string
	ActorDID   string
	RunID      string
	PolicyHash string

	ReceiptSets map[string]SpendReceiptSet

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

	view, err := ComputeSavingsView(in.ReceiptSets, &man, &res, priceBookSHA)
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

// SavingsVerificationResult is the structured outcome of the offline
// verification: each named check maps to the HELM-614 walkthrough.
type SavingsVerificationResult struct {
	PackID       string `json:"pack_id"`
	ManifestHash string `json:"manifest_hash"`
	// ChecksPassed lists the named checks in walkthrough order:
	// receipts_rehashed, manifest_rederived, cpst_recomputed,
	// pass_rates_and_parity_recomputed, paired_task_ids,
	// selection_freeze_precedes_holdout, no_prompt_bodies, plus the
	// supplementary price_book_bound and verdict_signatures.
	ChecksPassed      []string `json:"checks_passed"`
	ReceiptsVerified  int      `json:"receipts_verified"`
	ParityBarMet      bool     `json:"parity_bar_met"`
	SavingsClaimValid bool     `json:"savings_claim_valid"`
	Offline           bool     `json:"offline"`
	OK                bool     `json:"ok"`
}

// VerifySavingsEvidenceOffline verifies a savings EvidencePack from its content
// map alone — no network, no provider console, no live ledger. It re-derives
// the manifest hash, re-hashes every receipt, recomputes the entire savings
// view from receipts + artifacts and requires it to match the embedded view,
// checks paired task ids, checks the freeze-precedes-holdout ordering,
// re-binds the price book hash, verifies verdict signatures against the
// embedded trusted-key registry, and scans views for prompt bodies.
func VerifySavingsEvidenceOffline(contents map[string][]byte) (*SavingsVerificationResult, error) {
	manifestJSON, ok := contents["manifest.json"]
	if !ok {
		return nil, errors.New("savings evidence verify: manifest.json missing")
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		return nil, fmt.Errorf("savings evidence verify: decode manifest: %w", err)
	}
	res := &SavingsVerificationResult{PackID: manifest.PackID, ManifestHash: manifest.ManifestHash, Offline: true}

	// (b) Manifest hash + per-entry content hashes re-derived from pack bytes.
	if err := verifyManifestIntegrity(&manifest, contents); err != nil {
		return res, err
	}
	res.ChecksPassed = append(res.ChecksPassed, "manifest_rederived")

	// (a) Every receipt re-hashed against its canonical content hash, with the
	// per-intent financial invariants re-validated.
	sets, receiptCount, err := collectSavingsReceiptSets(contents)
	if err != nil {
		return res, err
	}
	res.ReceiptsVerified = receiptCount
	res.ChecksPassed = append(res.ChecksPassed, "receipts_rehashed")

	// Artifacts.
	rawManifestArtifact, ok := contents[savingsTaskSplitPath]
	if !ok {
		return res, errors.New("savings evidence verify: task-split manifest missing from pack")
	}
	rawResults, ok := contents[savingsTaskResultsPath]
	if !ok {
		return res, errors.New("savings evidence verify: task results missing from pack")
	}
	rawParity, ok := contents[savingsParityPath]
	if !ok {
		return res, errors.New("savings evidence verify: parity artifact missing from pack")
	}
	rawPriceBook, ok := contents[savingsPriceBookPath]
	if !ok {
		return res, errors.New("savings evidence verify: price-book config missing from pack")
	}
	rawView, ok := contents[savingsViewPath]
	if !ok {
		return res, errors.New("savings evidence verify: savings view missing from pack")
	}

	var man SavingsTaskSplitManifest
	var results SavingsTaskResults
	var parity SavingsParityResults
	var embedded SavingsView
	if err := decodeStrict(rawManifestArtifact, &man, "task-split manifest"); err != nil {
		return res, err
	}
	if err := decodeStrict(rawResults, &results, "task results"); err != nil {
		return res, err
	}
	if err := decodeStrict(rawParity, &parity, "parity pre-run"); err != nil {
		return res, err
	}
	if err := decodeStrict(rawView, &embedded, "savings view"); err != nil {
		return res, err
	}
	if err := ValidateSavingsArtifacts(&man, &results, &parity); err != nil {
		return res, err
	}

	// Price-book binding: every quote's snapshot hash is the embedded config.
	priceBookSHA := HashContent(rawPriceBook)
	if embedded.PriceBookSHA256 != priceBookSHA {
		return res, fmt.Errorf("savings evidence verify: view price book hash %s does not match embedded config %s", embedded.PriceBookSHA256, priceBookSHA)
	}
	for intentID, set := range sets {
		if set.RouteQuote != nil && set.RouteQuote.ProviderPriceSnapshotHash != priceBookSHA {
			return res, fmt.Errorf("savings evidence verify: intent %s quoted on price snapshot %s, not the embedded price book %s", intentID, set.RouteQuote.ProviderPriceSnapshotHash, priceBookSHA)
		}
	}
	res.ChecksPassed = append(res.ChecksPassed, "price_book_bound")

	// Freeze-block artifact hashes.
	if got := HashContent(rawParity); got != man.SelectionFreeze.ParityResultsSHA256 {
		return res, fmt.Errorf("savings evidence verify: parity artifact hash %s does not match the frozen selection's recorded %s", got, man.SelectionFreeze.ParityResultsSHA256)
	}
	if got := HashContent(rawManifestArtifact); got != embedded.SelectionFreeze.TaskSplitManifestSHA256 {
		return res, fmt.Errorf("savings evidence verify: task-split manifest hash %s does not match the view's recorded %s", got, embedded.SelectionFreeze.TaskSplitManifestSHA256)
	}

	// (c)+(d)+(e)+(f) Recompute the entire view from receipts + artifacts.
	// ComputeSavingsView internally enforces paired task ids, holdout coverage,
	// truthful substitution, and the freeze-precedes-holdout ordering.
	recomputed, err := ComputeSavingsView(sets, &man, &results, priceBookSHA)
	if err != nil {
		return res, err
	}
	recomputed.SelectionFreeze.TaskSplitManifestSHA256 = embedded.SelectionFreeze.TaskSplitManifestSHA256
	if err := savingsViewsEqual(&embedded, recomputed); err != nil {
		return res, err
	}
	res.ChecksPassed = append(res.ChecksPassed,
		"cpst_recomputed",
		"pass_rates_and_parity_recomputed",
		"paired_task_ids",
		"selection_freeze_precedes_holdout",
	)
	res.ParityBarMet = embedded.ParityBarMet
	res.SavingsClaimValid = embedded.SavingsClaimValid

	// Verdict signatures against the embedded registry (when present, all
	// verdict receipts must verify; absence downgrades, it does not fail).
	if rawKeys, hasKeys := contents[savingsTrustedKeysPath]; hasKeys {
		if err := verifySavingsSignatures(rawKeys, sets); err != nil {
			return res, err
		}
		res.ChecksPassed = append(res.ChecksPassed, "verdict_signatures")
	}

	// (g) No prompt bodies in any business view.
	if err := verifyNoPromptBody(contents); err != nil {
		return res, err
	}
	res.ChecksPassed = append(res.ChecksPassed, "no_prompt_bodies")

	res.OK = true
	return res, nil
}

// collectSavingsReceiptSets walks receipts/<intent>/ entries, re-hashes each
// receipt, re-validates per-intent invariants, and groups them by intent.
func collectSavingsReceiptSets(contents map[string][]byte) (map[string]SpendReceiptSet, int, error) {
	intents := make(map[string]map[string][]byte)
	for path, data := range contents {
		if !strings.HasPrefix(path, savingsReceiptsPrefix) {
			continue
		}
		rest := strings.TrimPrefix(path, savingsReceiptsPrefix)
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) != 2 {
			return nil, 0, fmt.Errorf("savings evidence verify: unexpected receipt path %s", path)
		}
		group := intents[parts[0]]
		if group == nil {
			group = make(map[string][]byte, 4)
			intents[parts[0]] = group
		}
		group[parts[1]] = data
	}
	if len(intents) == 0 {
		return nil, 0, errors.New("savings evidence verify: pack contains no receipts")
	}

	sets := make(map[string]SpendReceiptSet, len(intents))
	receiptCount := 0
	for intentID, group := range intents {
		// Reuse the per-intent verification from the spend pack by projecting the
		// group onto the fixed spend-pack paths.
		projected := map[string][]byte{}
		for name, data := range group {
			switch name {
			case "route_quote.json":
				projected[spendRouteReceiptPath] = data
			case "budget_verdict.json":
				projected[spendBudgetReceiptPath] = data
			case "usage.json":
				projected[spendUsageReceiptPath] = data
			case "settlement.json":
				projected[spendSettlementReceiptPath] = data
			default:
				return nil, 0, fmt.Errorf("savings evidence verify: unexpected receipt entry %s for intent %s", name, intentID)
			}
		}
		var invariants []string
		verified, err := verifySpendReceipts(projected, &invariants)
		if err != nil {
			return nil, 0, fmt.Errorf("savings evidence verify: intent %s: %w", intentID, err)
		}
		receiptCount += len(verified)

		var set SpendReceiptSet
		if raw, ok := projected[spendRouteReceiptPath]; ok {
			set.RouteQuote = &economic.RouteQuote{}
			if err := json.Unmarshal(raw, set.RouteQuote); err != nil {
				return nil, 0, fmt.Errorf("savings evidence verify: intent %s route quote: %w", intentID, err)
			}
			if set.RouteQuote.SpendIntentID != intentID {
				return nil, 0, fmt.Errorf("savings evidence verify: receipt dir %s holds quote for intent %s", intentID, set.RouteQuote.SpendIntentID)
			}
		}
		if raw, ok := projected[spendBudgetReceiptPath]; ok {
			set.Budget = &economic.BudgetVerdictReceipt{}
			if err := json.Unmarshal(raw, set.Budget); err != nil {
				return nil, 0, fmt.Errorf("savings evidence verify: intent %s budget verdict: %w", intentID, err)
			}
		}
		if raw, ok := projected[spendUsageReceiptPath]; ok {
			set.Usage = &economic.UsageReceipt{}
			if err := json.Unmarshal(raw, set.Usage); err != nil {
				return nil, 0, fmt.Errorf("savings evidence verify: intent %s usage: %w", intentID, err)
			}
		}
		if raw, ok := projected[spendSettlementReceiptPath]; ok {
			set.Settlement = &economic.SettlementReceipt{}
			if err := json.Unmarshal(raw, set.Settlement); err != nil {
				return nil, 0, fmt.Errorf("savings evidence verify: intent %s settlement: %w", intentID, err)
			}
		}
		sets[intentID] = set
	}
	return sets, receiptCount, nil
}

// savingsViewsEqual compares the embedded view against the recomputed one
// field by field (numbers, ids, timestamps, and claim flags all included).
func savingsViewsEqual(embedded, recomputed *SavingsView) error {
	a, err := json.Marshal(embedded)
	if err != nil {
		return fmt.Errorf("savings evidence verify: marshal embedded view: %w", err)
	}
	b, err := json.Marshal(recomputed)
	if err != nil {
		return fmt.Errorf("savings evidence verify: marshal recomputed view: %w", err)
	}
	if string(a) != string(b) {
		return fmt.Errorf("savings evidence verify: embedded savings view does not match the view recomputed from receipts and artifacts\nembedded:   %s\nrecomputed: %s", string(a), string(b))
	}
	return nil
}

// savingsTrustedKeyFile mirrors the spend proxy's on-disk registry format
// (kept locally to preserve the evidencepack <- spendproxy dependency
// direction).
type savingsTrustedKeyFile struct {
	Version string `json:"version"`
	Keys    map[string]struct {
		Algorithm    string    `json:"algorithm"`
		PublicKey    string    `json:"public_key"`
		RegisteredAt time.Time `json:"registered_at"`
	} `json:"keys"`
}

// verifySavingsSignatures checks every budget verdict signature against the
// registry embedded in the pack. Unknown key ids fail closed.
func verifySavingsSignatures(rawKeys []byte, sets map[string]SpendReceiptSet) error {
	var file savingsTrustedKeyFile
	if err := json.Unmarshal(rawKeys, &file); err != nil {
		return fmt.Errorf("savings evidence verify: decode trusted keys: %w", err)
	}
	for intentID, set := range sets {
		if set.Budget == nil {
			continue
		}
		entry, ok := file.Keys[set.Budget.SignatureKeyID]
		if !ok {
			return fmt.Errorf("savings evidence verify: intent %s verdict signed by unknown key %q", intentID, set.Budget.SignatureKeyID)
		}
		raw := strings.TrimPrefix(entry.PublicKey, "ed25519:")
		pub, err := hex.DecodeString(raw)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return fmt.Errorf("savings evidence verify: registry key %q is not a valid ed25519 public key", set.Budget.SignatureKeyID)
		}
		if err := set.Budget.VerifySignature(ed25519.PublicKey(pub)); err != nil {
			return fmt.Errorf("savings evidence verify: intent %s verdict signature: %w", intentID, err)
		}
	}
	return nil
}

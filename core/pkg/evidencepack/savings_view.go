package evidencepack

// quantum_posture: The savings view binds token-priced amounts to the receipt price-book digest.

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// SavingsClaimWording is the fixed time-binding wording required by the
// methodology: claims hold at capture-window prices only.
const SavingsClaimWording = "Savings at capture-window prices; every cost is bound to the per-call provider_price_snapshot_hash in the receipts. No forward-looking guarantee: a new price regime requires a new pack."

// SavingsRouteStats is one route's recomputable holdout-window aggregate.
// Spend covers ALL settled spend on the route's envelope from the freeze
// instant on — successes, failures, and retries — per the CPST definition,
// on two bases:
//
//   - settled: the governed ledger's integer-cent debits. The SPEND3 engine
//     ceils every call to a whole cent (billing-conservative budget
//     enforcement), so at sub-cent per-call costs this basis quantizes.
//   - token-priced: exact micro-cent cost of the settled usage receipts'
//     token counts at the pack-embedded price book — the same snapshot every
//     receipt binds via provider_price_snapshot_hash.
//
// The savings claim compares the token-priced basis; the settled basis is
// disclosed alongside.
type SavingsRouteStats struct {
	Role              string `json:"role"`
	EnvelopeID        string `json:"envelope_id"`
	RequestedModelID  string `json:"requested_model_id"`
	DispatchedModelID string `json:"dispatched_model_id"`
	SettledCalls      int    `json:"settled_calls"`
	SpendCents        int64  `json:"spend_cents"`
	// TokenPricedMicroCents = sum over settled usage receipts of
	// input_tokens*input_price + output_tokens*output_price + request surcharge,
	// at the embedded price book.
	TokenPricedMicroCents int64 `json:"token_priced_micro_cents"`
	InputTokens           int64 `json:"input_tokens"`
	OutputTokens          int64 `json:"output_tokens"`
	TasksTotal            int   `json:"tasks_total"`
	TasksPassed           int   `json:"tasks_passed"`
	// CPSTSettledMicroCents = SpendCents * 1_000_000 / TasksPassed, integer
	// division truncated toward zero. Zero when TasksPassed is zero.
	CPSTSettledMicroCents int64 `json:"cpst_settled_micro_cents"`
	// CPSTTokenPricedMicroCents = TokenPricedMicroCents / TasksPassed, integer
	// division truncated toward zero. Zero when TasksPassed is zero.
	CPSTTokenPricedMicroCents int64 `json:"cpst_token_priced_micro_cents"`
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
// recomputable offline from the pack's receipts and artifacts. The savings
// comparison uses the token-priced basis (see SavingsRouteStats).
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

// SavingsBasisNote is always present in the view's notes: it names the basis
// of the savings comparison and discloses the settled-ledger quantization.
const SavingsBasisNote = "Savings compare the token-priced basis (settled usage receipts' token counts at the embedded, hash-bound price book). The settled basis is disclosed alongside: the governed ledger ceils every call to a whole cent, which quantizes sub-cent per-call costs."

// SavingsViewSchemaVersion is the accepted savings view schema version.
const SavingsViewSchemaVersion = "helm-savings-view.v1"

// savingsPriceBook is the minimal projection of the spend-proxy config the
// savings computation needs: per provider/model token prices. Parsed leniently
// (the config carries many other fields) but priced strictly — a settled model
// missing from the book fails closed.
type savingsPriceBook struct {
	Prices []struct {
		ProviderID            string `json:"provider_id"`
		ModelID               string `json:"model_id"`
		InputTokenMicroCents  int64  `json:"input_token_micro_cents"`
		OutputTokenMicroCents int64  `json:"output_token_micro_cents"`
		RequestCents          int64  `json:"request_cents"`
	} `json:"prices"`
}

func parseSavingsPriceBook(raw []byte) (map[string][3]int64, error) {
	var book savingsPriceBook
	if err := json.Unmarshal(raw, &book); err != nil {
		return nil, fmt.Errorf("savings evidence: parse price-book config: %w", err)
	}
	if len(book.Prices) == 0 {
		return nil, errors.New("savings evidence: price-book config declares no prices")
	}
	out := make(map[string][3]int64, len(book.Prices))
	for _, p := range book.Prices {
		out[p.ProviderID+"\x00"+p.ModelID] = [3]int64{p.InputTokenMicroCents, p.OutputTokenMicroCents, p.RequestCents}
	}
	return out, nil
}

// ComputeSavingsView recomputes the full savings view from receipt sets,
// artifacts, and the raw price-book config bytes. The exporter uses it to
// render views/savings_view.json and the offline verifier re-runs it against
// the pack bytes, so a claim can never drift from what the receipts support.
func ComputeSavingsView(sets map[string]SpendReceiptSet, man *SavingsTaskSplitManifest, res *SavingsTaskResults, priceBookRaw []byte) (*SavingsView, error) {
	if err := validateSavingsReceiptSets(sets); err != nil {
		return nil, err
	}
	priceBookSHA256 := HashContent(priceBookRaw)
	prices, err := parseSavingsPriceBook(priceBookRaw)
	if err != nil {
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
		// Forward completeness: every result must be backed by receipts in the
		// pack — a stripped receipt set must fail, not silently drop from the
		// aggregates.
		backing, ok := sets[r.SpendIntentID]
		if !ok || backing.RouteQuote == nil {
			return nil, fmt.Errorf("savings evidence: result for task %s (phase %s, envelope %s) references intent %s with no route-quote receipt in the pack", r.TaskID, r.Phase, r.EnvelopeID, r.SpendIntentID)
		}
		if r.Passed && (backing.Usage == nil || backing.Settlement == nil) {
			return nil, fmt.Errorf("savings evidence: passed task %s (intent %s) has no settled usage+settlement receipts", r.TaskID, r.SpendIntentID)
		}
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
			price, ok := prices[set.Usage.ProviderID+"\x00"+set.Usage.ModelID]
			if !ok {
				return nil, fmt.Errorf("savings evidence: intent %s settled on %s/%s which has no entry in the embedded price book", intentID, set.Usage.ProviderID, set.Usage.ModelID)
			}
			stats.SettledCalls++
			stats.SpendCents += set.Usage.BalanceDebitCents
			stats.TokenPricedMicroCents += set.Usage.InputTokens*price[0] + set.Usage.OutputTokens*price[1] + price[2]*1_000_000
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
		baseline.CPSTSettledMicroCents = baseline.SpendCents * 1_000_000 / int64(baseline.TasksPassed)
		baseline.CPSTTokenPricedMicroCents = baseline.TokenPricedMicroCents / int64(baseline.TasksPassed)
	}
	if substitute.TasksPassed > 0 {
		substitute.CPSTSettledMicroCents = substitute.SpendCents * 1_000_000 / int64(substitute.TasksPassed)
		substitute.CPSTTokenPricedMicroCents = substitute.TokenPricedMicroCents / int64(substitute.TasksPassed)
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
	if baseline.CPSTTokenPricedMicroCents > 0 && substitute.CPSTTokenPricedMicroCents > 0 {
		view.SavingsPerTaskMicroCents = baseline.CPSTTokenPricedMicroCents - substitute.CPSTTokenPricedMicroCents
		view.SavingsPercentBps = (baseline.CPSTTokenPricedMicroCents - substitute.CPSTTokenPricedMicroCents) * 10_000 / baseline.CPSTTokenPricedMicroCents
	}
	view.Notes = append(view.Notes, SavingsBasisNote)
	if !parityBarMet {
		view.Notes = append(view.Notes, "Parity bar FAILED: the substitute passed fewer holdout tasks than the baseline. No savings claim is made; this pack records the negative result.")
	}
	return view, nil
}

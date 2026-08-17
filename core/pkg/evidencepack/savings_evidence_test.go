// quantum_posture: fixtures sign BudgetVerdict receipts with a classical
// Ed25519 test key and hash content with SHA-256 to exercise the offline
// verifier; no post-quantum primitives are used in this file.

package evidencepack

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// savingsFixture is a complete paired capture: two selection tasks run through
// the baseline and two candidates (parity pre-run), a frozen selection, and two
// holdout tasks run through both routes, with fully-linked receipts.
type savingsFixture struct {
	inputs     SavingsPackInputs
	manifest   SavingsTaskSplitManifest
	results    SavingsTaskResults
	parity     SavingsParityResults
	priceSHA   string
	signingKey ed25519.PrivateKey
	keyID      string
}

const (
	fixTenant     = "tenant-sav"
	fixBaseEnv    = "env-baseline"
	fixCandAEnv   = "env-cand-small"
	fixCandBEnv   = "env-cand-mid"
	fixBaseModel  = "model-big"
	fixCandAModel = "model-small"
	fixCandBModel = "model-mid"
)

var fixFreeze = time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

// buildSavingsReceiptSet builds one fully-linked receipt set for a savings
// capture call.
func buildSavingsReceiptSet(t *testing.T, intentID, envelopeID, requestedModel, selectedModel string, substituted bool, at time.Time, debitCents int64, signer ed25519.PrivateKey, keyID, priceSHA string) SpendReceiptSet {
	t.Helper()

	decision := economicAllow(100_000, "sha256:env-sav")
	quote := economic.NewRouteQuote(
		"rq-"+intentID, fixTenant, intentID, envelopeID, "agent-sav",
		economic.ModelRoute{ProviderID: "digitalocean", ModelID: selectedModel, PriceSnapshotHash: priceSHA},
		debitCents, 50, "USD", "sha256:route-policy-sav", at.Add(10*time.Minute), decision,
	)
	quote.RequestedModelID = requestedModel
	quote.ModelSubstituted = substituted
	quote.CreatedAt = at
	quote.Reseal()

	budget := economic.NewBudgetVerdictReceipt(
		"bv-"+intentID, fixTenant, intentID, envelopeID, "agent-sav", "digitalocean", selectedModel,
		debitCents, 50, "USD", priceSHA, "sha256:route-policy-sav", "evidence://"+intentID, decision,
	)
	if err := budget.Seal(keyID, signer); err != nil {
		t.Fatalf("seal budget verdict: %v", err)
	}

	usage := economic.NewUsageReceipt(
		"ur-"+intentID, fixTenant, "rq-"+intentID, intentID, envelopeID, "agent-sav", "digitalocean", selectedModel,
		debitCents, debitCents, 0, "USD", "sha256:policy-sav", "evidence://"+intentID,
	)
	usage.ProviderRequestID = "prov-" + intentID
	usage.ProviderPriceSnapshotHash = priceSHA
	usage.InputTokens = 60
	usage.OutputTokens = 400
	usage.CreatedAt = at.Add(3 * time.Second)

	entries := []economic.SettlementLedgerEntry{
		{ID: "sle-" + intentID + "-debit", AccountID: "balance-sav", Direction: economic.SettlementDebit, AmountCents: usage.BalanceDebitCents, Currency: "USD", Reference: "balance:balance-sav"},
		{ID: "sle-" + intentID + "-credit", AccountID: "treasury-sav", Direction: economic.SettlementCredit, AmountCents: usage.BalanceDebitCents, Currency: "USD", Reference: "treasury:treasury-sav"},
	}
	settlement := economic.NewSettlementReceipt("settle-"+intentID, fixTenant, "ur-"+intentID, "rq-"+intentID, "treasury-sav", usage.ContentHash, "USD", "evidence://"+intentID, entries)

	usage.LedgerEntryIDs = []string{entries[0].ID, entries[1].ID}
	usage.SettlementReceiptHash = settlement.ContentHash
	usage.Reseal()
	settlement.SourceUsageReceiptHash = usage.ContentHash
	settlement.Reseal()

	return SpendReceiptSet{RouteQuote: quote, Budget: budget, Usage: usage, Settlement: settlement}
}

// buildSavingsFixture assembles the full capture. substituteFailsHoldout2
// flips the substitute result for hold-2 to failed, which breaks the parity
// bar (negative-result scenario).
func buildSavingsFixture(t *testing.T, substituteFailsHoldout2 bool) *savingsFixture {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyID := "spend-proxy-test"
	trustedKeys, err := json.MarshalIndent(map[string]any{
		"version": "spend-proxy-trusted-keys.v1",
		"keys": map[string]any{
			keyID: map[string]any{
				"algorithm":     "ed25519",
				"public_key":    "ed25519:" + hex.EncodeToString(pub),
				"registered_at": fixFreeze.Add(-2 * time.Hour),
			},
		},
	}, "", "  ")
	if err != nil {
		t.Fatalf("marshal trusted keys: %v", err)
	}

	priceBook := []byte(`{
  "prices": [
    {"provider_id": "digitalocean", "model_id": "model-big", "input_token_micro_cents": 10, "output_token_micro_cents": 70},
    {"provider_id": "digitalocean", "model_id": "model-small", "input_token_micro_cents": 5, "output_token_micro_cents": 45},
    {"provider_id": "digitalocean", "model_id": "model-mid", "input_token_micro_cents": 25, "output_token_micro_cents": 55}
  ]
}`)
	priceSHA := HashContent(priceBook)

	fix := &savingsFixture{priceSHA: priceSHA, signingKey: priv, keyID: keyID}

	sets := map[string]SpendReceiptSet{}
	sigs := map[string]map[string]DetachedSignature{}
	signSet := func(intentID string, set SpendReceiptSet) {
		m := map[string]DetachedSignature{}
		if set.RouteQuote != nil {
			m["route_quote"] = signDetachedForTest(t, priv, keyID, set.RouteQuote)
		}
		if set.Usage != nil {
			m["usage"] = signDetachedForTest(t, priv, keyID, set.Usage)
		}
		if set.Settlement != nil {
			m["settlement"] = signDetachedForTest(t, priv, keyID, set.Settlement)
		}
		sigs[intentID] = m
	}
	var results []SavingsTaskResult

	// Parity pre-run on the selection set (before the freeze): baseline plus two
	// candidates, every task passing except cand-mid failing sel-2.
	parityRoutes := []struct {
		env, selected string
		substituted   bool
		debit         int64
	}{
		{fixBaseEnv, fixBaseModel, false, 5},
		{fixCandAEnv, fixCandAModel, true, 2},
		{fixCandBEnv, fixCandBModel, true, 3},
	}
	parityAgg := map[string]*SavingsParityCandidateResult{}
	for ri, route := range parityRoutes {
		for si, task := range []string{"sel-1", "sel-2"} {
			intentID := fmt.Sprintf("int-parity-%s-%s", route.env, task)
			at := fixFreeze.Add(time.Duration(-60+ri*10+si) * time.Minute)
			sets[intentID] = buildSavingsReceiptSet(t, intentID, route.env, fixBaseModel, route.selected, route.substituted, at, route.debit, priv, keyID, priceSHA)
			signSet(intentID, sets[intentID])
			passed := !(route.env == fixCandBEnv && task == "sel-2")
			results = append(results, SavingsTaskResult{
				TaskID: task, Phase: SavingsPhaseParity, EnvelopeID: route.env,
				RequestedModelID: fixBaseModel, IdempotencyKey: "k-" + intentID, SpendIntentID: intentID,
				Passed: passed, HTTPStatus: 200, FinishReason: "stop",
				ResponseSHA256: "sha256:resp-" + intentID, CompletedAt: at.Add(4 * time.Second),
			})
			agg := parityAgg[route.env]
			if agg == nil {
				agg = &SavingsParityCandidateResult{EnvelopeID: route.env, DispatchedModelID: route.selected}
				parityAgg[route.env] = agg
			}
			agg.TasksRun++
			if passed {
				agg.TasksPassed++
			}
		}
	}

	fix.parity = SavingsParityResults{
		SchemaVersion:    SavingsParitySchemaVersion,
		RunID:            "run-sav-1",
		SelectionTaskIDs: []string{"sel-1", "sel-2"},
		Baseline:         *parityAgg[fixBaseEnv],
		Candidates:       []SavingsParityCandidateResult{*parityAgg[fixCandAEnv], *parityAgg[fixCandBEnv]},
	}
	parityBytes, err := json.MarshalIndent(&fix.parity, "", "  ")
	if err != nil {
		t.Fatalf("marshal parity: %v", err)
	}

	// Holdout capture (after the freeze): both routes over hold-1 and hold-2.
	// Baseline debits 10 cents per call, substitute 3 cents.
	for hi, task := range []string{"hold-1", "hold-2"} {
		at := fixFreeze.Add(time.Duration(10+hi) * time.Minute)

		baseIntent := "int-hold-" + task + "-base"
		sets[baseIntent] = buildSavingsReceiptSet(t, baseIntent, fixBaseEnv, fixBaseModel, fixBaseModel, false, at, 10, priv, keyID, priceSHA)
		signSet(baseIntent, sets[baseIntent])
		results = append(results, SavingsTaskResult{
			TaskID: task, Phase: SavingsPhaseHoldout, EnvelopeID: fixBaseEnv,
			RequestedModelID: fixBaseModel, IdempotencyKey: "k-" + baseIntent, SpendIntentID: baseIntent,
			Passed: true, HTTPStatus: 200, FinishReason: "stop",
			ResponseSHA256: "sha256:resp-" + baseIntent, CompletedAt: at.Add(4 * time.Second),
		})

		subIntent := "int-hold-" + task + "-sub"
		sets[subIntent] = buildSavingsReceiptSet(t, subIntent, fixCandAEnv, fixBaseModel, fixCandAModel, true, at.Add(30*time.Second), 3, priv, keyID, priceSHA)
		signSet(subIntent, sets[subIntent])
		subPassed := !(substituteFailsHoldout2 && task == "hold-2")
		failure := ""
		if !subPassed {
			failure = "check failed"
		}
		results = append(results, SavingsTaskResult{
			TaskID: task, Phase: SavingsPhaseHoldout, EnvelopeID: fixCandAEnv,
			RequestedModelID: fixBaseModel, IdempotencyKey: "k-" + subIntent, SpendIntentID: subIntent,
			Passed: subPassed, FailureReason: failure, HTTPStatus: 200, FinishReason: "stop",
			ResponseSHA256: "sha256:resp-" + subIntent, CompletedAt: at.Add(34 * time.Second),
		})
	}

	fix.results = SavingsTaskResults{SchemaVersion: SavingsTaskResultsSchemaVersion, RunID: "run-sav-1", Results: results}
	resultsBytes, err := json.MarshalIndent(&fix.results, "", "  ")
	if err != nil {
		t.Fatalf("marshal results: %v", err)
	}

	fix.manifest = SavingsTaskSplitManifest{
		SchemaVersion:      SavingsTaskSplitSchemaVersion,
		RunID:              "run-sav-1",
		TenantID:           fixTenant,
		TaskSetSHA256:      "sha256:task-set-fixture",
		BaselineEnvelopeID: fixBaseEnv,
		BaselineModelID:    fixBaseModel,
		CandidateRoutes: []SavingsCandidate{
			{EnvelopeID: fixCandAEnv, ModelID: fixCandAModel},
			{EnvelopeID: fixCandBEnv, ModelID: fixCandBModel},
		},
		Tasks: []SavingsTaskAssignment{
			{TaskID: "sel-1", Subset: SavingsSubsetSelection},
			{TaskID: "sel-2", Subset: SavingsSubsetSelection},
			{TaskID: "hold-1", Subset: SavingsSubsetHoldout},
			{TaskID: "hold-2", Subset: SavingsSubsetHoldout},
		},
		SelectionFreeze: SavingsSelectionFreeze{
			FrozenAt:                   fixFreeze,
			ChosenSubstituteEnvelopeID: fixCandAEnv,
			ChosenSubstituteModelID:    fixCandAModel,
			ParityResultsSHA256:        HashContent(parityBytes),
			GitCommit:                  "0000000000000000000000000000000000000000",
			Rationale:                  "cheapest candidate with selection-set parity",
		},
	}
	manifestBytes, err := json.MarshalIndent(&fix.manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	fix.inputs = SavingsPackInputs{
		PackID:            "savpack-run-sav-1",
		ActorDID:          "did:helm:spend-proxy",
		RunID:             "run-sav-1",
		PolicyHash:        "sha256:route-policy-sav",
		ReceiptSets:       sets,
		ReceiptSignatures: sigs,
		TaskSplitManifest: manifestBytes,
		TaskResults:       resultsBytes,
		ParityResults:     parityBytes,
		PriceBookConfig:   priceBook,
		TrustedKeys:       trustedKeys,
		Profile:           economic.DefaultRedactionProfile(),
	}
	return fix
}

func TestBuildAndVerifySavingsEvidenceOffline(t *testing.T) {
	fix := buildSavingsFixture(t, false)
	manifest, contents, view := buildSignedSavingsPack(t, fix)
	if manifest.ManifestHash == "" {
		t.Fatal("expected manifest hash")
	}

	// Settled basis: baseline 20 cents / 2 passed = 10_000_000 micro-cents per
	// task; substitute 6 cents / 2 passed = 3_000_000. Token-priced basis (60 in /
	// 400 out per call): baseline 28_600 per call -> CPST 28_600; substitute
	// 18_300 -> CPST 18_300; savings 10_300 per task = 3601 bps.
	if view.Baseline.SpendCents != 20 || view.Baseline.TasksPassed != 2 || view.Baseline.CPSTSettledMicroCents != 10_000_000 || view.Baseline.CPSTTokenPricedMicroCents != 28_600 {
		t.Fatalf("baseline stats wrong: %+v", view.Baseline)
	}
	if view.Substitute.SpendCents != 6 || view.Substitute.TasksPassed != 2 || view.Substitute.CPSTSettledMicroCents != 3_000_000 || view.Substitute.CPSTTokenPricedMicroCents != 18_300 {
		t.Fatalf("substitute stats wrong: %+v", view.Substitute)
	}
	if !view.ParityBarMet || !view.SavingsClaimValid {
		t.Fatalf("expected valid claim: %+v", view)
	}
	if view.SavingsPerTaskMicroCents != 10_300 || view.SavingsPercentBps != 3_601 {
		t.Fatalf("savings numbers wrong: per-task %d, bps %d", view.SavingsPerTaskMicroCents, view.SavingsPercentBps)
	}
	if view.CaptureWindow.Start != fixFreeze {
		t.Fatalf("window start = %s, want freeze %s", view.CaptureWindow.Start, fixFreeze)
	}
	if view.Baseline.DispatchedModelID != fixBaseModel || view.Substitute.DispatchedModelID != fixCandAModel {
		t.Fatalf("dispatched models wrong: %+v / %+v", view.Baseline, view.Substitute)
	}

	res, err := VerifySavingsEvidenceOffline(contents)
	if err != nil {
		t.Fatalf("offline verify: %v", err)
	}
	if !res.OK || !res.Offline || !res.ParityBarMet || !res.SavingsClaimValid {
		t.Fatalf("unexpected verification result: %+v", res)
	}
	for _, check := range []string{
		"manifest_rederived", "receipts_rehashed", "receipt_signatures",
		"manifest_signature", "price_book_bound",
		"cpst_recomputed", "pass_rates_and_parity_recomputed", "paired_task_ids",
		"selection_freeze_precedes_holdout", "verdict_signatures", "no_prompt_bodies",
	} {
		mustContain(t, res.ChecksPassed, check)
	}
	// 10 intents (6 parity + 4 holdout) x 4 receipts.
	if res.ReceiptsVerified != 40 {
		t.Fatalf("receipts verified = %d, want 40", res.ReceiptsVerified)
	}
}

func TestSavingsEvidence_NegativeParityResultIsStillAPack(t *testing.T) {
	fix := buildSavingsFixture(t, true)
	_, contents, view := buildSignedSavingsPack(t, fix)
	if view.ParityBarMet || view.SavingsClaimValid {
		t.Fatalf("expected failed parity bar: %+v", view)
	}
	if view.Substitute.TasksPassed != 1 || view.Baseline.TasksPassed != 2 {
		t.Fatalf("pass counts wrong: %+v / %+v", view.Baseline, view.Substitute)
	}
	foundNegative := false
	for _, note := range view.Notes {
		if strings.Contains(note, "Parity bar FAILED") {
			foundNegative = true
		}
	}
	if !foundNegative {
		t.Fatalf("expected explicit negative-result note, got %v", view.Notes)
	}
	// CPST still reported for both routes; the failed call's spend still counts.
	if view.Substitute.SpendCents != 6 {
		t.Fatalf("substitute spend must include failed-task spend: %+v", view.Substitute)
	}
	if view.Substitute.CPSTSettledMicroCents != 6_000_000 || view.Substitute.CPSTTokenPricedMicroCents != 36_600 {
		t.Fatalf("substitute CPST wrong: settled %d (want 6000000), token-priced %d (want 36600)", view.Substitute.CPSTSettledMicroCents, view.Substitute.CPSTTokenPricedMicroCents)
	}

	res, err := VerifySavingsEvidenceOffline(contents)
	if err != nil {
		t.Fatalf("offline verify of negative pack: %v", err)
	}
	if !res.OK || res.ParityBarMet || res.SavingsClaimValid {
		t.Fatalf("unexpected verification result: %+v", res)
	}
}

func TestSavingsEvidence_FreezeMustPrecedeHoldout(t *testing.T) {
	fix := buildSavingsFixture(t, false)
	// Move one holdout baseline call BEFORE the freeze.
	early := fix.inputs.ReceiptSets["int-hold-hold-1-base"]
	early.RouteQuote.CreatedAt = fixFreeze.Add(-1 * time.Minute)
	early.RouteQuote.Reseal()
	fix.inputs.ReceiptSets["int-hold-hold-1-base"] = early

	_, _, _, err := BuildSavingsEvidencePack(fix.inputs)
	if err == nil || !strings.Contains(err.Error(), "does not follow the selection freeze") {
		t.Fatalf("expected freeze-ordering failure, got: %v", err)
	}
}

func TestSavingsEvidence_UnpairedHoldoutRefused(t *testing.T) {
	fix := buildSavingsFixture(t, false)
	// Drop the substitute result for hold-2 (its receipts stay in the pack).
	var trimmed []SavingsTaskResult
	for _, r := range fix.results.Results {
		if r.TaskID == "hold-2" && r.Phase == SavingsPhaseHoldout && r.EnvelopeID == fixCandAEnv {
			continue
		}
		trimmed = append(trimmed, r)
	}
	fix.results.Results = trimmed
	raw, err := json.MarshalIndent(&fix.results, "", "  ")
	if err != nil {
		t.Fatalf("marshal trimmed results: %v", err)
	}
	fix.inputs.TaskResults = raw

	_, _, _, err = BuildSavingsEvidencePack(fix.inputs)
	if err == nil || !strings.Contains(err.Error(), "has no substitute result") {
		t.Fatalf("expected unpaired capture to be refused, got: %v", err)
	}
}

func TestSavingsEvidence_TamperedReceiptDetected(t *testing.T) {
	fix := buildSavingsFixture(t, false)
	_, contents, _ := buildSignedSavingsPack(t, fix)

	path := "receipts/int-hold-hold-1-base/usage.json"
	var usage economic.UsageReceipt
	if err := json.Unmarshal(contents[path], &usage); err != nil {
		t.Fatalf("decode usage: %v", err)
	}
	usage.BalanceDebitCents = 1
	usage.ActualAmountCents = 1
	usage.ProviderCostCents = 1
	tampered, _ := json.MarshalIndent(&usage, "", "  ")
	contents[path] = tampered

	if _, err := VerifySavingsEvidenceOffline(contents); err == nil {
		t.Fatal("expected tampered receipt to be detected")
	} else if !strings.Contains(err.Error(), "content hash mismatch") {
		t.Fatalf("expected content hash mismatch, got: %v", err)
	}
}

func TestSavingsEvidence_UnknownSignatureKeyFailsClosed(t *testing.T) {
	fix := buildSavingsFixture(t, false)
	// A registry holding only a DIFFERENT key: every signature must fail to
	// resolve.
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate other key: %v", err)
	}
	other, _ := json.MarshalIndent(map[string]any{
		"version": "spend-proxy-trusted-keys.v1",
		"keys": map[string]any{
			"someone-else": map[string]any{
				"algorithm":     "ed25519",
				"public_key":    "ed25519:" + hex.EncodeToString(otherPub),
				"registered_at": fixFreeze,
			},
		},
	}, "", "  ")
	fix.inputs.TrustedKeys = other

	_, contents, _ := buildSignedSavingsPack(t, fix)
	if _, err := VerifySavingsEvidenceOffline(contents); err == nil {
		t.Fatal("expected unknown signature key to fail closed")
	} else if !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("expected unknown-key error, got: %v", err)
	}
}

func TestSavingsEvidence_RegistryRequiredAtBuild(t *testing.T) {
	fix := buildSavingsFixture(t, false)
	fix.inputs.TrustedKeys = nil
	if _, _, _, err := BuildSavingsEvidencePack(fix.inputs); err == nil || !strings.Contains(err.Error(), "trusted-key registry is required") {
		t.Fatalf("expected registry requirement, got: %v", err)
	}
}

func TestSavingsEvidence_MissingReceiptSignatureRefusedAtBuild(t *testing.T) {
	fix := buildSavingsFixture(t, false)
	delete(fix.inputs.ReceiptSignatures["int-hold-hold-1-base"], "usage")
	if _, _, _, err := BuildSavingsEvidencePack(fix.inputs); err == nil || !strings.Contains(err.Error(), "no detached signature") {
		t.Fatalf("expected missing-signature refusal, got: %v", err)
	}
}

// TestSavingsForge_TamperedTokensRejected is the reviewer's forge scenario:
// token counts are OUTSIDE the sealed content-hash preimage, so a forger can
// rewrite them, recompute the view, and re-pin the (self-referential)
// manifest. Even when the manifest is RE-SIGNED with a leaked key, the
// per-receipt detached signature over the JCS payload must catch the rewrite.
func TestSavingsForge_TamperedTokensRejected(t *testing.T) {
	fix := buildSavingsFixture(t, false)
	_, contents, _ := buildSignedSavingsPack(t, fix)

	path := "receipts/int-hold-hold-1-base/usage.json"
	var usage economic.UsageReceipt
	if err := json.Unmarshal(contents[path], &usage); err != nil {
		t.Fatalf("decode usage: %v", err)
	}
	usage.OutputTokens *= 10 // NOT resealed: tokens are outside the preimage
	if !usage.HasCanonicalContentHash() {
		t.Fatal("precondition broken: token tamper should keep the sealed content hash valid")
	}
	raw, _ := json.MarshalIndent(&usage, "", "  ")
	contents[path] = raw

	// Forger recomputes the view from the doctored receipts and re-pins the
	// manifest — everything possible without the signing key.
	forgeRecomputeView(t, contents)
	forgeRepinManifest(t, contents)
	forgeResignManifest(t, fix, contents)

	if _, err := VerifySavingsEvidenceOffline(contents); err == nil {
		t.Fatal("expected forged token counts to be rejected")
	} else if !strings.Contains(err.Error(), "usage receipt signature does not verify") {
		t.Fatalf("expected usage signature failure, got: %v", err)
	}
}

// TestSavingsForge_BackdatedQuoteRejected: RouteQuote.CreatedAt is outside the
// sealed preimage; backdating must be caught by the detached signature.
func TestSavingsForge_BackdatedQuoteRejected(t *testing.T) {
	fix := buildSavingsFixture(t, false)
	_, contents, _ := buildSignedSavingsPack(t, fix)

	path := "receipts/int-hold-hold-1-base/route_quote.json"
	var quote economic.RouteQuote
	if err := json.Unmarshal(contents[path], &quote); err != nil {
		t.Fatalf("decode quote: %v", err)
	}
	quote.CreatedAt = quote.CreatedAt.Add(-2 * time.Hour) // NOT resealed
	if !quote.HasCanonicalContentHash() {
		t.Fatal("precondition broken: CreatedAt tamper should keep the sealed content hash valid")
	}
	raw, _ := json.MarshalIndent(&quote, "", "  ")
	contents[path] = raw

	forgeRepinManifest(t, contents)
	forgeResignManifest(t, fix, contents)

	if _, err := VerifySavingsEvidenceOffline(contents); err == nil {
		t.Fatal("expected backdated quote to be rejected")
	} else if !strings.Contains(err.Error(), "route_quote receipt signature does not verify") {
		t.Fatalf("expected quote signature failure, got: %v", err)
	}
}

// TestSavingsForge_StrippedReceiptsRejected: removing a holdout receipt set
// (to hide spend or a failure) must fail results->receipts completeness even
// with a re-pinned, re-signed manifest.
func TestSavingsForge_StrippedReceiptsRejected(t *testing.T) {
	fix := buildSavingsFixture(t, false)
	_, contents, _ := buildSignedSavingsPack(t, fix)

	for name := range contents {
		if strings.HasPrefix(name, "receipts/int-hold-hold-2-sub/") {
			delete(contents, name)
		}
	}
	forgeStripManifestEntries(t, contents, "receipts/int-hold-hold-2-sub/")
	forgeRepinManifest(t, contents)
	forgeResignManifest(t, fix, contents)

	if _, err := VerifySavingsEvidenceOffline(contents); err == nil {
		t.Fatal("expected stripped receipts to be rejected")
	} else if !strings.Contains(err.Error(), "no route-quote receipt in the pack") {
		t.Fatalf("expected completeness failure, got: %v", err)
	}
}

// TestSavingsForge_MissingRegistryRejected: a pack without the registry is
// self-attested and must not verify.
func TestSavingsForge_MissingRegistryRejected(t *testing.T) {
	fix := buildSavingsFixture(t, false)
	_, contents, _ := buildSignedSavingsPack(t, fix)
	delete(contents, "artifacts/trusted_keys.json")
	forgeStripManifestEntries(t, contents, "artifacts/trusted_keys.json")
	forgeRepinManifest(t, contents)
	forgeResignManifest(t, fix, contents)
	if _, err := VerifySavingsEvidenceOffline(contents); err == nil {
		t.Fatal("expected registry-less pack to be rejected")
	} else if !strings.Contains(err.Error(), "trusted-key registry missing") {
		t.Fatalf("expected registry-missing failure, got: %v", err)
	}
}

// TestSavingsForge_MissingManifestSignatureRejected: stripping manifest.sig.json
// (it is not a manifest entry) must fail closed.
func TestSavingsForge_MissingManifestSignatureRejected(t *testing.T) {
	fix := buildSavingsFixture(t, false)
	_, contents, _ := buildSignedSavingsPack(t, fix)
	delete(contents, SavingsManifestSigPath)
	if _, err := VerifySavingsEvidenceOffline(contents); err == nil {
		t.Fatal("expected signature-less manifest to be rejected")
	} else if !strings.Contains(err.Error(), "manifest.sig.json missing") {
		t.Fatalf("expected manifest-signature-missing failure, got: %v", err)
	}
}

// signDetachedForTest mirrors the spend proxy's detached signing: Ed25519 over
// the JCS canonicalization of the receipt payload.
func signDetachedForTest(t *testing.T, priv ed25519.PrivateKey, keyID string, payload any) DetachedSignature {
	t.Helper()
	canonical, err := canonicalize.JCS(payload)
	if err != nil {
		t.Fatalf("canonicalize payload: %v", err)
	}
	return DetachedSignature{KeyID: keyID, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonical))}
}

// buildSignedSavingsPack builds the pack and attaches the manifest signature
// with the fixture key — the shape a legitimate export produces.
func buildSignedSavingsPack(t *testing.T, fix *savingsFixture) (*Manifest, map[string][]byte, *SavingsView) {
	t.Helper()
	manifest, contents, view, err := BuildSavingsEvidencePack(fix.inputs)
	if err != nil {
		t.Fatalf("build savings pack: %v", err)
	}
	if err := AttachManifestSignature(contents, func(payload []byte) (string, []byte, error) {
		return fix.keyID, ed25519.Sign(fix.signingKey, payload), nil
	}); err != nil {
		t.Fatalf("attach manifest signature: %v", err)
	}
	return manifest, contents, view
}

// forgeRepinManifest recomputes every entry hash and the manifest hash after a
// forger has edited pack bytes — everything an attacker WITHOUT the signing
// key can regenerate.
func forgeRepinManifest(t *testing.T, contents map[string][]byte) {
	t.Helper()
	var manifest Manifest
	if err := json.Unmarshal(contents["manifest.json"], &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	for i, entry := range manifest.Entries {
		data, ok := contents[entry.Path]
		if !ok {
			t.Fatalf("manifest entry %s missing from contents", entry.Path)
		}
		manifest.Entries[i].ContentHash = HashContent(data)
		manifest.Entries[i].Size = int64(len(data))
	}
	hash, err := ComputeManifestHash(&manifest)
	if err != nil {
		t.Fatalf("recompute manifest hash: %v", err)
	}
	manifest.ManifestHash = hash
	root, err := ComputeEntriesMerkleRoot(manifest.Entries)
	if err != nil {
		t.Fatalf("recompute merkle root: %v", err)
	}
	manifest.EntriesMerkleRoot = root
	raw, err := json.MarshalIndent(&manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	contents["manifest.json"] = raw
}

// forgeRecomputeView recomputes views/savings_view.json from the (possibly
// doctored) pack receipts and artifacts — the forger's step after editing
// receipt bytes.
func forgeRecomputeView(t *testing.T, contents map[string][]byte) {
	t.Helper()
	sets, _, _, err := collectSavingsReceiptSets(contents)
	if err != nil {
		t.Fatalf("forge: collect receipts: %v", err)
	}
	var man SavingsTaskSplitManifest
	if err := decodeStrict(contents[savingsTaskSplitPath], &man, "manifest"); err != nil {
		t.Fatalf("forge: decode manifest artifact: %v", err)
	}
	var results SavingsTaskResults
	if err := decodeStrict(contents[savingsTaskResultsPath], &results, "results"); err != nil {
		t.Fatalf("forge: decode results: %v", err)
	}
	view, err := ComputeSavingsView(sets, &man, &results, contents[savingsPriceBookPath])
	if err != nil {
		t.Fatalf("forge: recompute view: %v", err)
	}
	view.SelectionFreeze.TaskSplitManifestSHA256 = HashContent(contents[savingsTaskSplitPath])
	raw, err := json.MarshalIndent(view, "", "  ")
	if err != nil {
		t.Fatalf("forge: marshal view: %v", err)
	}
	contents[savingsViewPath] = raw
}

// forgeStripManifestEntries drops manifest entries under a path prefix (used
// together with deleting the files themselves).
func forgeStripManifestEntries(t *testing.T, contents map[string][]byte, prefix string) {
	t.Helper()
	var manifest Manifest
	if err := json.Unmarshal(contents["manifest.json"], &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	kept := manifest.Entries[:0]
	for _, entry := range manifest.Entries {
		if !strings.HasPrefix(entry.Path, prefix) {
			kept = append(kept, entry)
		}
	}
	manifest.Entries = kept
	raw, err := json.MarshalIndent(&manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	contents["manifest.json"] = raw
}

// forgeResignManifest re-signs the re-pinned manifest with the fixture key —
// simulating the WORST case where the manifest-signing key leaked. The
// per-receipt detached signatures must still catch payload rewrites.
func forgeResignManifest(t *testing.T, fix *savingsFixture, contents map[string][]byte) {
	t.Helper()
	delete(contents, SavingsManifestSigPath)
	if err := AttachManifestSignature(contents, func(payload []byte) (string, []byte, error) {
		return fix.keyID, ed25519.Sign(fix.signingKey, payload), nil
	}); err != nil {
		t.Fatalf("re-sign manifest: %v", err)
	}
}

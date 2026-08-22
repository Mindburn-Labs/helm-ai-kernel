package spendproxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidencepack"
)

// testIntentID mirrors core/pkg/inferencegateway/ids.go (and the paired-replay
// runner) so results bind to receipts the way a real capture does.
func testIntentID(tenantID, idempotencyKey string) string {
	sum := sha256.Sum256([]byte(tenantID + "\x00" + idempotencyKey))
	return "si-" + hex.EncodeToString(sum[:])[:24]
}

// runSavingsCapture drives a complete paired capture through the live proxy
// fixture: parity pre-run on the selection set, a selection freeze, then the
// holdout set through both routes. It returns the capture dir.
func runSavingsCapture(t *testing.T, f *proxyFixture) string {
	t.Helper()
	const (
		tenant  = "tenant-test"
		runID   = "run-e2e"
		baseEnv = "env-direct"
		subEnv  = "env-sub"
	)
	captureDir := filepath.Join(t.TempDir(), "capture")
	if err := os.MkdirAll(captureDir, 0o750); err != nil {
		t.Fatalf("create capture dir: %v", err)
	}

	var results []evidencepack.SavingsTaskResult
	call := func(phase, env, task string) evidencepack.SavingsTaskResult {
		idem := runID + "-" + phase + "-" + env + "-" + task
		resp := f.post(t, "/v1/chat/completions", "base-model", env, idem, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s/%s/%s: status %d", phase, env, task, resp.StatusCode)
		}
		return evidencepack.SavingsTaskResult{
			TaskID: task, Phase: phase, EnvelopeID: env,
			RequestedModelID: "base-model", IdempotencyKey: idem,
			SpendIntentID: testIntentID(tenant, idem),
			Passed:        true, HTTPStatus: 200, FinishReason: "stop",
			ResponseSHA256: "sha256:e2e", CompletedAt: time.Now().UTC(),
		}
	}

	// Parity pre-run (selection set, both routes).
	for _, task := range []string{"sel-A", "sel-B"} {
		results = append(results, call(evidencepack.SavingsPhaseParity, baseEnv, task))
		results = append(results, call(evidencepack.SavingsPhaseParity, subEnv, task))
	}

	parity := evidencepack.SavingsParityResults{
		SchemaVersion:    evidencepack.SavingsParitySchemaVersion,
		RunID:            runID,
		SelectionTaskIDs: []string{"sel-A", "sel-B"},
		Baseline:         evidencepack.SavingsParityCandidateResult{EnvelopeID: baseEnv, DispatchedModelID: "base-model", TasksRun: 2, TasksPassed: 2},
		Candidates: []evidencepack.SavingsParityCandidateResult{
			{EnvelopeID: subEnv, DispatchedModelID: "mini-model", TasksRun: 2, TasksPassed: 2},
		},
	}
	parityBytes, err := json.MarshalIndent(&parity, "", "  ")
	if err != nil {
		t.Fatalf("marshal parity: %v", err)
	}
	if err := os.WriteFile(filepath.Join(captureDir, CaptureParityFile), parityBytes, 0o600); err != nil {
		t.Fatalf("write parity: %v", err)
	}

	// Selection freeze strictly between parity and holdout.
	time.Sleep(5 * time.Millisecond)
	frozenAt := time.Now().UTC()
	time.Sleep(5 * time.Millisecond)

	manifest := evidencepack.SavingsTaskSplitManifest{
		SchemaVersion:      evidencepack.SavingsTaskSplitSchemaVersion,
		RunID:              runID,
		TenantID:           tenant,
		TaskSetSHA256:      "sha256:test-task-set",
		BaselineEnvelopeID: baseEnv,
		BaselineModelID:    "base-model",
		CandidateRoutes:    []evidencepack.SavingsCandidate{{EnvelopeID: subEnv, ModelID: "mini-model"}},
		Tasks: []evidencepack.SavingsTaskAssignment{
			{TaskID: "sel-A", Subset: evidencepack.SavingsSubsetSelection},
			{TaskID: "sel-B", Subset: evidencepack.SavingsSubsetSelection},
			{TaskID: "hold-A", Subset: evidencepack.SavingsSubsetHoldout},
			{TaskID: "hold-B", Subset: evidencepack.SavingsSubsetHoldout},
		},
		SelectionFreeze: evidencepack.SavingsSelectionFreeze{
			FrozenAt:                   frozenAt,
			ChosenSubstituteEnvelopeID: subEnv,
			ChosenSubstituteModelID:    "mini-model",
			ParityResultsSHA256:        evidencepack.HashContent(parityBytes),
			GitCommit:                  "e2e-test",
			Rationale:                  "only candidate with selection parity",
		},
	}
	manifestBytes, err := json.MarshalIndent(&manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(captureDir, CaptureTaskSplitFile), manifestBytes, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	// Holdout capture through both routes.
	for _, task := range []string{"hold-A", "hold-B"} {
		results = append(results, call(evidencepack.SavingsPhaseHoldout, baseEnv, task))
		results = append(results, call(evidencepack.SavingsPhaseHoldout, subEnv, task))
	}

	resultsFile := evidencepack.SavingsTaskResults{
		SchemaVersion: evidencepack.SavingsTaskResultsSchemaVersion,
		RunID:         runID,
		Results:       results,
	}
	resultsBytes, err := json.MarshalIndent(&resultsFile, "", "  ")
	if err != nil {
		t.Fatalf("marshal results: %v", err)
	}
	if err := os.WriteFile(filepath.Join(captureDir, CaptureResultsFile), resultsBytes, 0o600); err != nil {
		t.Fatalf("write results: %v", err)
	}
	return captureDir
}

func TestSavingsExportEndToEnd(t *testing.T) {
	f := newProxyFixture(t)
	captureDir := runSavingsCapture(t, f)
	outDir := filepath.Join(t.TempDir(), "packs")

	res, err := ExportSavingsEvidencePack(SavingsExportOptions{
		ReceiptsDir:   f.receiptsDir,
		CaptureDir:    captureDir,
		ConfigPath:    f.configPath,
		OutDir:        outDir,
		SigningSecret: "0101010101010101010101010101010101010101010101010101010101010101",
	})
	if err != nil {
		t.Fatalf("savings export: %v", err)
	}
	if !res.OfflineVerified {
		t.Fatalf("pack did not offline-verify: %+v", res)
	}
	view := res.View
	if view.Baseline.TasksTotal != 2 || view.Baseline.TasksPassed != 2 ||
		view.Substitute.TasksTotal != 2 || view.Substitute.TasksPassed != 2 {
		t.Fatalf("holdout counts wrong: %+v / %+v", view.Baseline, view.Substitute)
	}
	if !view.ParityBarMet || !view.SavingsClaimValid {
		t.Fatalf("expected valid claim: %+v", view)
	}
	if view.Baseline.SettledCalls != 2 || view.Substitute.SettledCalls != 2 {
		t.Fatalf("settled calls wrong: %+v / %+v", view.Baseline, view.Substitute)
	}
	if view.Baseline.SpendCents <= 0 || view.Substitute.SpendCents <= 0 {
		t.Fatalf("spend must be positive: %+v / %+v", view.Baseline, view.Substitute)
	}
	// Settled basis mirrors the ledger debits exactly.
	wantBaseSettled := view.Baseline.SpendCents * 1_000_000 / int64(view.Baseline.TasksPassed)
	if view.Baseline.CPSTSettledMicroCents != wantBaseSettled {
		t.Fatalf("baseline settled CPST %d, want %d", view.Baseline.CPSTSettledMicroCents, wantBaseSettled)
	}
	// Token-priced basis: mock usage is 100 in / 20 out per call at
	// base-model 5000/10000 and mini-model 1000/2000 micro-cents per token.
	if view.Baseline.CPSTTokenPricedMicroCents != 700_000 {
		t.Fatalf("baseline token-priced CPST %d, want 700000", view.Baseline.CPSTTokenPricedMicroCents)
	}
	if view.Substitute.CPSTTokenPricedMicroCents != 140_000 {
		t.Fatalf("substitute token-priced CPST %d, want 140000", view.Substitute.CPSTTokenPricedMicroCents)
	}
	if view.SavingsPerTaskMicroCents != 560_000 || view.SavingsPercentBps != 8_000 {
		t.Fatalf("savings numbers wrong: per-task %d, bps %d", view.SavingsPerTaskMicroCents, view.SavingsPercentBps)
	}
	if view.Substitute.DispatchedModelID != "mini-model" || view.Baseline.DispatchedModelID != "base-model" {
		t.Fatalf("dispatched models wrong: %+v / %+v", view.Baseline, view.Substitute)
	}

	// The verdict_signatures check must have run (registry always present).
	found := false
	for _, c := range res.ChecksPassed {
		if c == "verdict_signatures" {
			found = true
		}
	}
	if !found {
		t.Fatalf("verdict_signatures check missing: %v", res.ChecksPassed)
	}

	// Skeptic path: re-verify the written pack directory offline.
	verification, err := VerifySavingsPackDir(res.OutputDir)
	if err != nil {
		t.Fatalf("verify pack dir: %v", err)
	}
	if !verification.OK || verification.ManifestHash != res.ManifestHash {
		t.Fatalf("pack dir verification mismatch: %+v vs manifest %s", verification, res.ManifestHash)
	}

	// Tamper with the written savings view; verification must fail.
	viewPath := filepath.Join(res.OutputDir, "views", "savings_view.json")
	raw, err := os.ReadFile(viewPath)
	if err != nil {
		t.Fatalf("read view: %v", err)
	}
	tampered := strings.Replace(string(raw), `"savings_claim_valid": true`, `"savings_claim_valid": false`, 1)
	if tampered == string(raw) {
		t.Fatal("tamper substitution did not apply")
	}
	if err := os.WriteFile(viewPath, []byte(tampered), 0o600); err != nil {
		t.Fatalf("write tampered view: %v", err)
	}
	if _, err := VerifySavingsPackDir(res.OutputDir); err == nil {
		t.Fatal("expected tampered view to fail verification")
	}
}

func TestSavingsExportRefusesUnattributedSpend(t *testing.T) {
	f := newProxyFixture(t)
	captureDir := runSavingsCapture(t, f)

	// A settled call on the baseline envelope that no task result references.
	resp := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "stray-spend-1", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stray call failed: %d", resp.StatusCode)
	}

	_, err := ExportSavingsEvidencePack(SavingsExportOptions{
		ReceiptsDir:   f.receiptsDir,
		CaptureDir:    captureDir,
		ConfigPath:    f.configPath,
		OutDir:        filepath.Join(t.TempDir(), "packs"),
		SigningSecret: "0101010101010101010101010101010101010101010101010101010101010101",
	})
	if err == nil || !strings.Contains(err.Error(), "unattributed spend") {
		t.Fatalf("expected unattributed-spend refusal, got: %v", err)
	}
}

func TestSavingsExportRequiresArtifacts(t *testing.T) {
	f := newProxyFixture(t)
	// Generate at least one receipt so the log exists.
	resp := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "warmup-1", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("warmup failed: %d", resp.StatusCode)
	}

	_, err := ExportSavingsEvidencePack(SavingsExportOptions{
		ReceiptsDir:   f.receiptsDir,
		CaptureDir:    t.TempDir(),
		ConfigPath:    f.configPath,
		OutDir:        t.TempDir(),
		SigningSecret: "0101010101010101010101010101010101010101010101010101010101010101",
	})
	if err == nil || !strings.Contains(err.Error(), "task-split manifest") {
		t.Fatalf("expected missing-manifest failure, got: %v", err)
	}
}

// TestSavingsExportAllowsDisclosedPreFreezeSpend: validation/smoke spend whose
// quote predates the freeze cannot enter CPST (which aggregates post-freeze
// holdout receipts only), so it is counted and disclosed instead of blocking
// the export. The in-window case stays fail-closed
// (TestSavingsExportRefusesUnattributedSpend).
func TestSavingsExportAllowsDisclosedPreFreezeSpend(t *testing.T) {
	f := newProxyFixture(t)
	// Smoke call BEFORE any capture artifact exists — exactly the live-capture
	// startup validation call.
	resp := f.post(t, "/v1/chat/completions", "base-model", "env-direct", "pre-freeze-smoke", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("smoke call failed: %d", resp.StatusCode)
	}
	captureDir := runSavingsCapture(t, f)

	res, err := ExportSavingsEvidencePack(SavingsExportOptions{
		ReceiptsDir:   f.receiptsDir,
		CaptureDir:    captureDir,
		ConfigPath:    f.configPath,
		OutDir:        filepath.Join(t.TempDir(), "packs"),
		SigningSecret: "0101010101010101010101010101010101010101010101010101010101010101",
	})
	if err != nil {
		t.Fatalf("pre-freeze smoke spend must not block export: %v", err)
	}
	if res.PreWindowUnattributedCalls != 1 {
		t.Fatalf("pre-window unattributed calls = %d, want 1 (disclosed)", res.PreWindowUnattributedCalls)
	}
	if !res.OfflineVerified {
		t.Fatalf("pack did not offline-verify: %+v", res)
	}
}

func TestSavingsExportRequiresSigningSeed(t *testing.T) {
	f := newProxyFixture(t)
	captureDir := runSavingsCapture(t, f)
	_, err := ExportSavingsEvidencePack(SavingsExportOptions{
		ReceiptsDir: f.receiptsDir,
		CaptureDir:  captureDir,
		ConfigPath:  f.configPath,
		OutDir:      t.TempDir(),
	})
	if err == nil || !strings.Contains(err.Error(), "signing seed") {
		t.Fatalf("expected signing-seed requirement, got: %v", err)
	}
}

func TestSavingsExportRejectsForeignSigningSeed(t *testing.T) {
	f := newProxyFixture(t)
	captureDir := runSavingsCapture(t, f)
	_, err := ExportSavingsEvidencePack(SavingsExportOptions{
		ReceiptsDir:   f.receiptsDir,
		CaptureDir:    captureDir,
		ConfigPath:    f.configPath,
		OutDir:        t.TempDir(),
		SigningSecret: "0202020202020202020202020202020202020202020202020202020202020202",
	})
	if err == nil || !strings.Contains(err.Error(), "not in the trusted-key registry") {
		t.Fatalf("expected foreign-seed refusal, got: %v", err)
	}
}

func TestSavingsExportRefusesUnsignedRecords(t *testing.T) {
	// Receipts captured by a pre-signature proxy (no payload signatures) must
	// be refused: the pack cannot anchor what was never signed.
	f := newProxyFixture(t)
	captureDir := runSavingsCapture(t, f)

	logPath := filepath.Join(f.receiptsDir, ReceiptLogName)
	records, err := LoadRecords(logPath)
	if err != nil {
		t.Fatalf("load records: %v", err)
	}
	stripped, err := os.OpenFile(logPath, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("truncate log: %v", err)
	}
	for _, rec := range records {
		rec.PayloadSignature = ""
		rec.PayloadSignatureKeyID = ""
		line, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal record: %v", err)
		}
		if _, err := stripped.Write(append(line, '\n')); err != nil {
			t.Fatalf("write record: %v", err)
		}
	}
	if err := stripped.Close(); err != nil {
		t.Fatalf("close log: %v", err)
	}

	_, err = ExportSavingsEvidencePack(SavingsExportOptions{
		ReceiptsDir:   f.receiptsDir,
		CaptureDir:    captureDir,
		ConfigPath:    f.configPath,
		OutDir:        t.TempDir(),
		SigningSecret: "0101010101010101010101010101010101010101010101010101010101010101",
	})
	if err == nil || !strings.Contains(err.Error(), "no detached signature") {
		t.Fatalf("expected unsigned-record refusal, got: %v", err)
	}
}

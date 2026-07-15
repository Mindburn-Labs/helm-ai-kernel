package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
)

func TestConformAdversarialRequiresExplicitTrustProfile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runConform([]string{"adversarial", "--bundle", t.TempDir()}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit=%d, want runtime/configuration error; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "--profile is required") {
		t.Fatalf("stderr=%q, want explicit trust profile error", stderr.String())
	}
}

func TestConformAdversarialRejectsReportInsideSealedPack(t *testing.T) {
	packDir := createMinimalVerifiableBundle(t)
	reportPath := filepath.Join(packDir, "12_REPORTS", "adversarial_campaign_report.json")
	var stdout, stderr bytes.Buffer
	code := runConform([]string{
		"adversarial",
		"--bundle", packDir,
		"--profile", "dev-local",
		"--report", reportPath,
	}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit=%d, want configuration error; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "outside the sealed EvidencePack") {
		t.Fatalf("stderr=%q, want sealed-pack mutation guard", stderr.String())
	}
	if _, err := os.Stat(reportPath); !os.IsNotExist(err) {
		t.Fatalf("rejected report path mutated the sealed EvidencePack: err=%v", err)
	}
}

func TestConformAdversarialRejectsUnknownTrustProfile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runConform([]string{
		"adversarial",
		"--bundle", t.TempDir(),
		"--profile", "trust-me",
		"--report", filepath.Join(t.TempDir(), "campaign.json"),
	}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "unsupported --profile") {
		t.Fatalf("exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestConformAdversarialRejectsEmptyEvidencePack(t *testing.T) {
	reportPath := filepath.Join(t.TempDir(), "campaign.json")
	var stdout, stderr bytes.Buffer
	code := runConform([]string{
		"adversarial",
		"--bundle", t.TempDir(),
		"--profile", "dev-local",
		"--report", reportPath,
		"--json",
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit=%d, want verification failure; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	report := readAdversarialCampaignReport(t, reportPath)
	if report.Pass || report.BundleVerified {
		t.Fatalf("empty evidence pack passed: %+v", report)
	}
	if report.Status != adversarialCampaignStatusBundleVerificationFailed {
		t.Fatalf("status=%q, want bundle verification failure", report.Status)
	}
	if report.ExecutedSuites != 0 || report.MandatorySuites != 10 {
		t.Fatalf("suite counts=%d/%d, want 0/10", report.ExecutedSuites, report.MandatorySuites)
	}
	if !strings.Contains(stdout.String(), `"bundle_verified": false`) {
		t.Fatalf("JSON output missing failed bundle verification: %s", stdout.String())
	}
}

func TestConformAdversarialRejectsVerifiedPackWithIncompleteCoverage(t *testing.T) {
	packDir := createMinimalVerifiableBundle(t)
	reportPath := filepath.Join(t.TempDir(), "campaign.json")
	var stdout, stderr bytes.Buffer
	code := runConform([]string{
		"adversarial",
		"--bundle", packDir,
		"--profile", "dev-local",
		"--report", reportPath,
		"--json",
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit=%d, want coverage failure; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	report := readAdversarialCampaignReport(t, reportPath)
	if report.Pass || !report.BundleVerified || report.CoverageVerified {
		t.Fatalf("uncovered pack result=%+v, want verified bundle with incomplete coverage", report)
	}
	if report.Status != adversarialCampaignStatusCoverageIncomplete || report.ExecutedSuites != 0 || report.MissingSuites == 0 {
		t.Fatalf("uncovered pack was treated as an executed campaign: %+v", report)
	}
}

func TestConformAdversarialPassesVerifiedPackDeterministically(t *testing.T) {
	packDir := createMinimalVerifiableBundle(t)
	populatePassingCampaignPack(t, packDir)
	reportDir := t.TempDir()
	reportA := filepath.Join(reportDir, "campaign-a.json")
	reportB := filepath.Join(reportDir, "campaign-b.json")

	for _, reportPath := range []string{reportA, reportB} {
		var stdout, stderr bytes.Buffer
		code := runConform([]string{
			"adversarial",
			"--bundle", packDir,
			"--profile", "dev-local",
			"--report", reportPath,
			"--json",
		}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("exit=%d, want pass; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
		}
	}

	dataA, err := os.ReadFile(reportA)
	if err != nil {
		t.Fatal(err)
	}
	dataB, err := os.ReadFile(reportB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dataA, dataB) {
		t.Fatalf("campaign reports are not deterministic:\nA=%s\nB=%s", dataA, dataB)
	}
	if bytes.Contains(dataA, []byte(packDir)) {
		t.Fatalf("campaign report leaked machine-local bundle path: %s", dataA)
	}
	if info, err := os.Stat(reportA); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("campaign report mode=%v err=%v, want 0600", info, err)
	}

	report := readAdversarialCampaignReport(t, reportA)
	if !report.Pass || !report.BundleVerified || !report.CoverageVerified || report.Status != adversarialCampaignStatusPassed {
		t.Fatalf("verified campaign did not pass: %+v", report)
	}
	if report.MandatorySuites != 10 || report.ExecutedSuites != 10 || report.PassedSuites != 10 || report.FailedSuites != 0 {
		t.Fatalf("suite counts=%+v, want all 10 passing", report)
	}
	if report.EvidenceRoot == "" || report.MerkleRoot == "" {
		t.Fatalf("campaign report missing deterministic evidence roots: %+v", report)
	}
	if _, err := os.Stat(filepath.Join(packDir, "12_REPORTS", "adversarial_campaign_report.json")); !os.IsNotExist(err) {
		t.Fatalf("strict verifier mutated sealed EvidencePack: err=%v", err)
	}
}

func TestConformAdversarialFailsVerifiedMaliciousPack(t *testing.T) {
	packDir := createMinimalVerifiableBundle(t)
	populatePassingCampaignPack(t, packDir)
	resealAdversarialPack(t, packDir)
	reportPath := filepath.Join(t.TempDir(), "campaign.json")

	var stdout, stderr bytes.Buffer
	code := runConform([]string{
		"adversarial",
		"--bundle", packDir,
		"--profile", "dev-local",
		"--report", reportPath,
		"--json",
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit=%d, want adversarial failure; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	report := readAdversarialCampaignReport(t, reportPath)
	if report.Pass || !report.BundleVerified || !report.CoverageVerified {
		t.Fatalf("malicious pack result=%+v, want verified bundle with failed suites", report)
	}
	if report.Status != adversarialCampaignStatusAdversarialFailed || report.ExecutedSuites != 10 || report.FailedSuites == 0 {
		t.Fatalf("malicious campaign did not execute/fail mandatory suites: %+v", report)
	}
}

func readAdversarialCampaignReport(t *testing.T, path string) adversarialCampaignReport {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var report adversarialCampaignReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("decode campaign report: %v\n%s", err, data)
	}
	return report
}

func resealAdversarialPack(t *testing.T, packDir string) {
	t.Helper()
	receiptPath := filepath.Join(packDir, "02_PROOFGRAPH", "receipts", "005_effect.json")
	data, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var receipt map[string]any
	if err := json.Unmarshal(data, &receipt); err != nil {
		t.Fatal(err)
	}
	// Reuse receipt-3 as the parent of both the approval and effect. Coverage
	// remains complete, while ADV-03 must detect the fork.
	receipt["parent_receipt_hashes"] = []string{"receipt-3"}
	writeCampaignJSON(t, receiptPath, receipt)
	reindexAndResealCampaignPack(t, packDir, "ep_adversarial_test")
}

func populatePassingCampaignPack(t *testing.T, packDir string) {
	t.Helper()
	receiptsDir := filepath.Join(packDir, "02_PROOFGRAPH", "receipts")
	if err := os.Remove(filepath.Join(receiptsDir, "r1.json")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(packDir, "08_TAPES"), filepath.Join(packDir, "99_EXT", "adversarial", "tools")} {
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	receipts := []struct {
		name  string
		value map[string]any
	}{
		{"001_policy.json", campaignReceipt("receipt-1", "decision-1", 1, "policy_decision", []string{"genesis"})},
		{"002_budget_decrement.json", campaignReceipt("receipt-2", "budget-1", 2, "budget_decrement", []string{"receipt-1"})},
		{"003_budget_exhausted.json", campaignReceipt("receipt-3", "budget-1", 3, "budget_exhausted", []string{"receipt-2"})},
		{"004_approval.json", campaignReceipt("receipt-4", "decision-1", 4, "approval_action", []string{"receipt-3"})},
		{"005_effect.json", campaignReceipt("receipt-5", "decision-1", 5, "effect_attempt", []string{"receipt-4"})},
	}
	receipts[4].value["effect_class"] = "E4"
	receipts[4].value["envelope_id"] = "envelope-1"
	receipts[4].value["envelope_hash"] = "sha256:envelope"
	for _, receipt := range receipts {
		writeCampaignJSON(t, filepath.Join(receiptsDir, receipt.name), receipt.value)
	}
	writeCampaignJSON(t, filepath.Join(packDir, "08_TAPES", "entry_001.json"), map[string]any{
		"value_hash": "sha256:value",
		"data_class": "internal",
	})
	writeCampaignJSON(t, filepath.Join(packDir, "99_EXT", "adversarial", "tools", "tool.json"), map[string]any{
		"name":       "campaign-tool",
		"signatures": []string{"sha256:signature"},
	})
	writeCampaignJSON(t, filepath.Join(packDir, "06_LOGS", "receipt_emission_panic.json"), map[string]any{"last_good_seq": 5})
	reindexAndResealCampaignPack(t, packDir, "ep_campaign_pass")
}

func campaignReceipt(receiptID, decisionID string, seq int, actionType string, parents []string) map[string]any {
	return map[string]any{
		"receipt_id":            receiptID,
		"decision_id":           decisionID,
		"decision_hash":         "sha256:" + decisionID,
		"status":                "APPLIED",
		"lamport_clock":         seq,
		"seq":                   seq,
		"action_type":           actionType,
		"tenant_id":             "tenant-1",
		"parent_receipt_hashes": parents,
	}
}

func writeCampaignJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func reindexAndResealCampaignPack(t *testing.T, packDir, packID string) {
	t.Helper()
	if err := os.Remove(filepath.Join(packDir, evidencepkg.EvidencePackSealPath)); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	type indexEntry struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	}
	entries := []indexEntry{}
	if err := filepath.WalkDir(packDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(packDir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "00_INDEX.json" || rel == evidencepkg.EvidencePackSealPath {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		entries = append(entries, indexEntry{Path: rel, SHA256: hex.EncodeToString(sum[:])})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	writeCampaignJSON(t, filepath.Join(packDir, "00_INDEX.json"), map[string]any{
		"version":    "1.0.0",
		"entries":    entries,
		"extensions": []string{"adversarial"},
	})
	if _, err := evidencepkg.SealEvidencePack(context.Background(), packDir, evidencepkg.SealEvidencePackOptions{
		PackID:  packID,
		DataDir: t.TempDir(),
	}); err != nil {
		t.Fatal(err)
	}
}

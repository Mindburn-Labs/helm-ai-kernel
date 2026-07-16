package main

// quantum_posture: fixtures exercise classical Ed25519 campaign and report
// attestations only; they do not claim post-quantum coverage.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
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
	configureAdversarialCommandTest(t)
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

func TestConformAdversarialRejectsReportOverArchive(t *testing.T) {
	configureAdversarialCommandTest(t)
	packDir := createMinimalVerifiableBundle(t)
	archivePath := filepath.Join(t.TempDir(), "evidence-pack.tar")
	if err := deterministicTarArchive(packDir, archivePath); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runConform([]string{
		"adversarial",
		"--bundle", archivePath,
		"--profile", "dev-local",
		"--report", archivePath,
	}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "outside the sealed EvidencePack") {
		t.Fatalf("exit=%d stdout=%s stderr=%s, want archive overwrite rejection", code, stdout.String(), stderr.String())
	}
	after, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("rejected archive report path changed the input archive")
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

func TestConformAdversarialRejectsSymlinkedDirectoryInput(t *testing.T) {
	configureAdversarialCommandTest(t)
	packDir := createMinimalVerifiableBundle(t)
	if err := os.Symlink(filepath.Join(packDir, "00_INDEX.json"), filepath.Join(packDir, "linked-index.json")); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := runConform([]string{
		"adversarial",
		"--bundle", packDir,
		"--profile", "dev-local",
		"--report", filepath.Join(t.TempDir(), "campaign.json"),
	}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "rejects symlink") {
		t.Fatalf("exit=%d stdout=%s stderr=%s, want symlink rejection", code, stdout.String(), stderr.String())
	}
}

func TestConformAdversarialBoundsSnapshotEntryCount(t *testing.T) {
	source := t.TempDir()
	if err := os.Mkdir(filepath.Join(source, "one"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(source, "two"), 0o750); err != nil {
		t.Fatal(err)
	}
	err := copyAdversarialEvidenceDirectory(source, filepath.Join(t.TempDir(), "snapshot"), 2)
	if err == nil || !strings.Contains(err.Error(), "exceeds 2 entries") {
		t.Fatalf("entry-bomb snapshot error = %v", err)
	}
}

func TestConformAdversarialRedactsImplicitTrustConfigPath(t *testing.T) {
	configureAdversarialCommandTest(t)
	packDir := createMinimalVerifiableBundle(t)
	configPath := filepath.Join(t.TempDir(), "private-machine-path", "evidence-pack.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HELM_EVIDENCE_TRUST_CONFIG", configPath)
	reportPath := filepath.Join(t.TempDir(), "campaign.json")
	var stdout, stderr bytes.Buffer
	code := runConform([]string{
		"adversarial",
		"--bundle", packDir,
		"--profile", "dev-local",
		"--report", reportPath,
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit=%d stdout=%s stderr=%s, want trust verification failure", code, stdout.String(), stderr.String())
	}
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(configPath)) {
		t.Fatalf("campaign report leaked implicit trust config path: %s", data)
	}
}

func TestConformAdversarialRejectsEmptyEvidencePack(t *testing.T) {
	configureAdversarialCommandTest(t)
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
	configureAdversarialCommandTest(t)
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
	attestationPublicKeyHex := configureAdversarialCommandTest(t)
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
	if report.RunnerProvenance.KernelCommit == "" || report.RunnerProvenance.ExecutableSHA256 == "" || report.RunnerProvenance.DetectorDefinitionSHA256 == "" {
		t.Fatalf("campaign report missing runner provenance: %+v", report.RunnerProvenance)
	}
	if err := verifyAdversarialCampaignReportAttestation(report, attestationPublicKeyHex); err != nil {
		t.Fatalf("campaign report attestation did not verify: %v", err)
	}
	if _, err := os.Stat(filepath.Join(packDir, "12_REPORTS", "adversarial_campaign_report.json")); !os.IsNotExist(err) {
		t.Fatalf("strict verifier mutated sealed EvidencePack: err=%v", err)
	}
}

func TestConformAdversarialFailsVerifiedMaliciousPack(t *testing.T) {
	attestationPublicKeyHex := configureAdversarialCommandTest(t)
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

	stdout.Reset()
	stderr.Reset()
	code = runConform([]string{
		"adversarial", "verify-report",
		"--report", reportPath,
		"--trusted-public-key", attestationPublicKeyHex,
	}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stdout.String(), "attestation: verified") {
		t.Fatalf("failed report verify exit=%d, want authenticated failure; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestConformAdversarialVerifyReportRejectsTamper(t *testing.T) {
	attestationPublicKeyHex := configureAdversarialCommandTest(t)
	packDir := createMinimalVerifiableBundle(t)
	populatePassingCampaignPack(t, packDir)
	reportPath := filepath.Join(t.TempDir(), "campaign.json")
	var stdout, stderr bytes.Buffer
	code := runConform([]string{
		"adversarial",
		"--bundle", packDir,
		"--profile", "dev-local",
		"--report", reportPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("campaign exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runConform([]string{
		"adversarial", "verify-report",
		"--report", reportPath,
		"--trusted-public-key", attestationPublicKeyHex,
		"--expected-kernel-commit", strings.Repeat("a", 40),
	}, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "attestation: verified") {
		t.Fatalf("verify exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	report := readAdversarialCampaignReport(t, reportPath)
	report.Pass = false
	tampered, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportPath, append(tampered, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = runConform([]string{
		"adversarial", "verify-report",
		"--report", reportPath,
		"--trusted-public-key", attestationPublicKeyHex,
	}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "signature verification failed") {
		t.Fatalf("tampered verify exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestConformAdversarialVerifyReportEmitsTypedAuthenticatedJSON(t *testing.T) {
	attestationPublicKeyHex := configureAdversarialCommandTest(t)
	packDir := createMinimalVerifiableBundle(t)
	populatePassingCampaignPack(t, packDir)
	reportPath := filepath.Join(t.TempDir(), "campaign.json")
	var stdout, stderr bytes.Buffer
	if code := runConform([]string{"adversarial", "--bundle", packDir, "--profile", "dev-local", "--report", reportPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("campaign exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var presentation map[string]any
	if err := json.Unmarshal(data, &presentation); err != nil {
		t.Fatal(err)
	}
	presentation["untrusted_presentation"] = "must-not-be-echoed"
	data, err = json.Marshal(presentation)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	code := runConform([]string{"adversarial", "verify-report", "--report", reportPath, "--trusted-public-key", attestationPublicKeyHex, "--json"}, &stdout, &stderr)
	if code != 0 || bytes.Contains(stdout.Bytes(), []byte("untrusted_presentation")) {
		t.Fatalf("verify exit=%d echoed untrusted JSON; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
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
	// Add a second child of receipt-2 after the exhaustion boundary. Coverage
	// remains complete while ADV-03, ADV-04, and ADV-09 all receive a real
	// negative control.
	receipt := campaignReceipt("receipt-6", "budget-1", 6, "budget_decrement", []string{"receipt-2"})
	writeCampaignJSON(t, filepath.Join(packDir, "02_PROOFGRAPH", "receipts", "006_fork_overdraft.json"), receipt)
	reindexAndResealCampaignPack(t, packDir, "ep_adversarial_test")
}

func populatePassingCampaignPack(t *testing.T, packDir string) {
	t.Helper()
	campaignPrivateKey, _ := adversarialCampaignTestKey()
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
	receipts[0].value = signAdversarialCampaignDocument(t, receipts[0].value, "campaign_signatures", campaignPrivateKey)
	receipts[3].value = signAdversarialCampaignDocument(t, receipts[3].value, "campaign_signatures", campaignPrivateKey)
	for _, receipt := range receipts {
		writeCampaignJSON(t, filepath.Join(receiptsDir, receipt.name), receipt.value)
	}
	value := []byte("campaign-tape-value")
	valueHash := sha256.Sum256(value)
	writeCampaignJSON(t, filepath.Join(packDir, "08_TAPES", "entry_001.json"), map[string]any{
		"value":      value,
		"value_hash": hex.EncodeToString(valueHash[:]),
		"data_class": "internal",
	})
	toolManifest := signAdversarialCampaignDocument(t, map[string]any{"name": "campaign-tool"}, "signatures", campaignPrivateKey)
	writeCampaignJSON(t, filepath.Join(packDir, "99_EXT", "adversarial", "tools", "tool.json"), toolManifest)
	writeCampaignJSON(t, filepath.Join(packDir, "06_LOGS", "receipt_emission_panic.json"), map[string]any{"last_good_seq": 5})
	reindexAndResealCampaignPack(t, packDir, "ep_campaign_pass")
}

func campaignReceipt(receiptID, decisionID string, seq int, actionType string, parents []string) map[string]any {
	return map[string]any{
		"receipt_id":            receiptID,
		"receipt_hash":          receiptID,
		"decision_id":           decisionID,
		"decision_hash":         "sha256:" + decisionID,
		"status":                "APPLIED",
		"lamport_clock":         seq,
		"seq":                   seq,
		"action_type":           actionType,
		"tenant_id":             "tenant-1",
		"envelope_id":           "envelope-1",
		"envelope_hash":         "sha256:envelope",
		"parent_receipt_hashes": parents,
	}
}

func configureAdversarialCommandTest(t *testing.T) string {
	t.Helper()
	_, campaignPublicKeyHex := adversarialCampaignTestKey()
	attestationSeed := sha256.Sum256([]byte("helm-adversarial-report-attestation-test-key-v1"))
	attestationPrivateKey := ed25519.NewKeyFromSeed(attestationSeed[:])
	attestationPublicKey := attestationPrivateKey.Public().(ed25519.PublicKey)
	t.Setenv("HELM_BOUNTY_CAMPAIGN_PUBLIC_KEY_HEX", campaignPublicKeyHex)
	t.Setenv("HELM_BOUNTY_EVALUATION_TIME_RFC3339", "2026-07-15T12:00:00Z")
	t.Setenv("HELM_KERNEL_COMMIT", strings.Repeat("a", 40))
	t.Setenv("HELM_SIGNING_KEY_HEX", hex.EncodeToString(attestationSeed[:]))
	previousCommit := commit
	commit = strings.Repeat("a", 40)
	t.Cleanup(func() { commit = previousCommit })
	return hex.EncodeToString(attestationPublicKey)
}

func adversarialCampaignTestKey() (ed25519.PrivateKey, string) {
	seed := sha256.Sum256([]byte("helm-adversarial-campaign-test-key-v1"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	return privateKey, hex.EncodeToString(privateKey.Public().(ed25519.PublicKey))
}

func signAdversarialCampaignDocument(t *testing.T, document map[string]any, field string, privateKey ed25519.PrivateKey) map[string]any {
	t.Helper()
	payload := make(map[string]any, len(document))
	for key, value := range document {
		if key != field {
			payload[key] = value
		}
	}
	canonical, err := canonicalize.JCS(payload)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyHash := sha256.Sum256(publicKey)
	payload[field] = []any{map[string]any{
		"algorithm": "ed25519",
		"key_id":    "sha256:" + hex.EncodeToString(keyHash[:]),
		"signature": hex.EncodeToString(ed25519.Sign(privateKey, canonical)),
	}}
	return payload
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

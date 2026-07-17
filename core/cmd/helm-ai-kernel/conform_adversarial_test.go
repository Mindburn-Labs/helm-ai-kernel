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
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform/adversarial"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

const (
	testAdversarialCampaignID  = "campaign-cli-test"
	testAdversarialRunID       = "run-cli-test-001"
	testReceiptSignatureDomain = "helm.bounty.receipt-signature/v1"
	testToolSignatureDomain    = "helm.bounty.tool-manifest-signature/v1"
)

func TestConformAdversarialDefinition(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runConform([]string{"adversarial", "definition"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("definition exit=%d stderr=%s", code, stderr.String())
	}
	var definition struct {
		Revision         string                                `json:"revision"`
		DefinitionSHA256 string                                `json:"definition_sha256"`
		MandatorySuites  int                                   `json:"mandatory_suites"`
		Suites           []adversarial.DetectorSuiteDefinition `json:"suites"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &definition); err != nil {
		t.Fatalf("decode definition: %v", err)
	}
	wantDigest, err := adversarial.DefinitionDigest()
	if err != nil {
		t.Fatal(err)
	}
	if definition.Revision != adversarial.DetectorRevision || definition.DefinitionSHA256 != wantDigest || definition.MandatorySuites != 10 || len(definition.Suites) != 10 {
		t.Fatalf("definition = %+v", definition)
	}

	stdout.Reset()
	stderr.Reset()
	if code := runConform([]string{"adversarial", "definition", "unexpected"}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "unexpected argument") {
		t.Fatalf("unexpected definition argument exit=%d stderr=%s", code, stderr.String())
	}
}

func TestReleaseWorkflowEmbedsFullCommitForAdversarialProvenance(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", ".."))
	workflowPath := filepath.Join(repoRoot, ".github", "workflows", "release.yml")
	workflow, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}
	if !bytes.Contains(workflow, []byte(`echo "commit=$(git rev-parse HEAD)"`)) {
		t.Fatal("release workflow must embed the full checked-out commit in published campaign runners")
	}
	if bytes.Contains(workflow, []byte(`echo "commit=$(git rev-parse --short`)) {
		t.Fatal("release workflow must not shorten the commit embedded in published campaign runners")
	}
}

func TestBountyMakeTargetsBindHighAssuranceInputs(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", ".."))
	makefile, err := os.ReadFile(filepath.Join(repoRoot, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	for _, required := range []string{
		`--storage-receipt "$(BOUNTY_STORAGE_RECEIPT)"`,
		`@test -n "$(BOUNTY_EXECUTABLE_SHA256)"`,
		`--expected-executable-sha256 "$(BOUNTY_EXECUTABLE_SHA256)"`,
	} {
		if !bytes.Contains(makefile, []byte(required)) {
			t.Fatalf("bounty Make targets do not bind required input %q", required)
		}
	}
}

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

func TestConformAdversarialRequiresCampaignAndRunIdentity(t *testing.T) {
	configureAdversarialCommandTest(t)
	t.Setenv(adversarial.CampaignIDEnv, "")
	t.Setenv(adversarial.CampaignRunIDEnv, "")
	var stdout, stderr bytes.Buffer
	code := runConform([]string{
		"adversarial",
		"--bundle", t.TempDir(),
		"--profile", "dev-local",
		"--report", filepath.Join(t.TempDir(), "campaign.json"),
	}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "--campaign-id is required") {
		t.Fatalf("exit=%d stdout=%s stderr=%s, want missing campaign identity rejection", code, stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = runConform([]string{
		"adversarial",
		"--bundle", t.TempDir(),
		"--profile", "dev-local",
		"--report", filepath.Join(t.TempDir(), "campaign.json"),
		"--campaign-id", testAdversarialCampaignID,
	}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "--run-id is required") {
		t.Fatalf("exit=%d stdout=%s stderr=%s, want missing run identity rejection", code, stdout.String(), stderr.String())
	}
}

func TestConformAdversarialPreservesFractionalEvaluationTime(t *testing.T) {
	configureAdversarialCommandTest(t)
	const evaluationTime = "2026-07-15T12:00:00.999Z"
	t.Setenv("HELM_BOUNTY_EVALUATION_TIME_RFC3339", evaluationTime)
	packDir := createMinimalVerifiableBundle(t)
	reportPath := filepath.Join(t.TempDir(), "campaign.json")
	var stdout, stderr bytes.Buffer
	code := runConform([]string{
		"adversarial",
		"--bundle", packDir,
		"--profile", "dev-local",
		"--report", reportPath,
	}, &stdout, &stderr)
	if code == 2 {
		t.Fatalf("exit=%d stdout=%s stderr=%s, want a signed campaign verdict", code, stdout.String(), stderr.String())
	}
	report := readAdversarialCampaignReport(t, reportPath)
	if report.EvaluationTime != evaluationTime {
		t.Fatalf("evaluation_time=%q, want exact %q", report.EvaluationTime, evaluationTime)
	}
}

func TestHashOpenExecutableImageSurvivesPathReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not permit replacing an open executable path")
	}
	dir := t.TempDir()
	executablePath := filepath.Join(dir, "runner")
	original := []byte("original-running-image")
	if err := os.WriteFile(executablePath, original, 0o700); err != nil {
		t.Fatal(err)
	}
	pinned, err := os.Open(executablePath)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.Close()
	replacementPath := filepath.Join(dir, "replacement")
	if err := os.WriteFile(replacementPath, []byte("replacement-at-path"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacementPath, executablePath); err != nil {
		t.Fatal(err)
	}

	got, err := hashOpenExecutableImage(pinned)
	if err != nil {
		t.Fatal(err)
	}
	wantHash := sha256.Sum256(original)
	want := "sha256:" + hex.EncodeToString(wantHash[:])
	if got != want {
		t.Fatalf("pinned executable digest=%q, want original image %q", got, want)
	}
}

func TestConformAdversarialRequiresDedicatedReportSigningKey(t *testing.T) {
	configureAdversarialCommandTest(t)
	t.Setenv(adversarialReportSigningKeyEnv, "")
	t.Setenv("HELM_SIGNING_KEY_HEX", strings.Repeat("00", ed25519.SeedSize))
	var stdout, stderr bytes.Buffer
	code := runConform([]string{
		"adversarial",
		"--bundle", t.TempDir(),
		"--profile", "dev-local",
		"--report", filepath.Join(t.TempDir(), "campaign.json"),
	}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), adversarialReportSigningKeyEnv) {
		t.Fatalf("exit=%d stdout=%s stderr=%s, want dedicated report-key rejection", code, stdout.String(), stderr.String())
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
	if report.CampaignID != testAdversarialCampaignID || report.RunID != testAdversarialRunID {
		t.Fatalf("campaign identity = %s/%s, want %s/%s", report.CampaignID, report.RunID, testAdversarialCampaignID, testAdversarialRunID)
	}
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

func TestConformAdversarialPropagatesExternallyVerifiedConformanceSignature(t *testing.T) {
	attestationPublicKeyHex := configureAdversarialCommandTest(t)
	packDir := createMinimalVerifiableBundle(t)
	populatePassingCampaignPack(t, packDir)
	seed := sha256.Sum256([]byte("helm-adversarial-report-attestation-test-key-v1"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	if _, err := conform.SignReport(packDir, "policy-test", "schemas-test", "fixture", func(payload []byte) (string, error) {
		return hex.EncodeToString(ed25519.Sign(privateKey, payload)), nil
	}); err != nil {
		t.Fatalf("sign conformance report: %v", err)
	}

	reportPath := filepath.Join(t.TempDir(), "campaign.json")
	var stdout, stderr bytes.Buffer
	code := runConform([]string{
		"adversarial",
		"--bundle", packDir,
		"--profile", "dev-local",
		"--trusted-public-key", attestationPublicKeyHex,
		"--report", reportPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit=%d stdout=%s stderr=%s, want verified detached-signature compatibility", code, stdout.String(), stderr.String())
	}
	report := readAdversarialCampaignReport(t, reportPath)
	if !report.Pass || !report.BundleVerified || !report.CoverageVerified {
		t.Fatalf("verified detached signature did not reach the bound detector snapshot: %+v", report)
	}
	if _, err := os.Stat(filepath.Join(packDir, "07_ATTESTATIONS", "conformance_report.sig")); err != nil {
		t.Fatalf("source conformance signature was modified: %v", err)
	}
}

func TestConformAdversarialReportMatchesPublicSchema(t *testing.T) {
	configureAdversarialCommandTest(t)
	packDir := createMinimalVerifiableBundle(t)
	populatePassingCampaignPack(t, packDir)
	reportPath := filepath.Join(t.TempDir(), "campaign.json")
	var stdout, stderr bytes.Buffer
	if code := runConform([]string{"adversarial", "--bundle", packDir, "--profile", "dev-local", "--report", reportPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("campaign exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", ".."))
	schemaPath := filepath.Join(repoRoot, "protocols", "json-schemas", "certification", "adversarial_campaign_report.v2.schema.json")
	schemaData, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	resourceURL := "file:///" + strings.ReplaceAll(schemaPath, string(filepath.Separator), "/")
	if err := compiler.AddResource(resourceURL, strings.NewReader(string(schemaData))); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(resourceURL)
	if err != nil {
		t.Fatalf("compile public campaign schema: %v", err)
	}
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var reportValue map[string]any
	if err := json.Unmarshal(reportData, &reportValue); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(reportValue); err != nil {
		t.Fatalf("generated campaign report violates public schema: %v", err)
	}
	delete(reportValue, "campaign_id")
	if err := schema.Validate(reportValue); err == nil {
		t.Fatal("public schema accepted a report without campaign_id")
	}
}

func TestConformAdversarialRejectsVerifiedPreFailingControl(t *testing.T) {
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
	if report.Pass || !report.BundleVerified || report.CoverageVerified {
		t.Fatalf("malicious pack result=%+v, want verified bundle with rejected positive controls", report)
	}
	if report.Status != adversarialCampaignStatusCoverageIncomplete || report.ExecutedSuites != 0 || report.MissingSuites == 0 {
		t.Fatalf("pre-failing controls were not rejected before campaign success: %+v", report)
	}

	stdout.Reset()
	stderr.Reset()
	code = runConform([]string{
		"adversarial", "verify-report",
		"--report", reportPath,
		"--trusted-public-key", attestationPublicKeyHex,
		"--expected-campaign-id", testAdversarialCampaignID,
		"--expected-run-id", testAdversarialRunID,
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
		"--expected-campaign-id", testAdversarialCampaignID,
		"--expected-run-id", testAdversarialRunID,
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
		"--expected-campaign-id", testAdversarialCampaignID,
		"--expected-run-id", testAdversarialRunID,
	}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "signature verification failed") {
		t.Fatalf("tampered verify exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestConformAdversarialVerifyReportRequiresReplayContext(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runConform([]string{
		"adversarial", "verify-report",
		"--report", filepath.Join(t.TempDir(), "campaign.json"),
		"--trusted-public-key", strings.Repeat("a", 64),
		"--expected-campaign-public-key", strings.Repeat("b", 64),
	}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "--expected-campaign-id") || !strings.Contains(stderr.String(), "--expected-run-id") {
		t.Fatalf("exit=%d stdout=%s stderr=%s, want mandatory replay context", code, stdout.String(), stderr.String())
	}
}

func TestConformAdversarialVerifyReportBindsExpectedContext(t *testing.T) {
	attestationPublicKeyHex := configureAdversarialCommandTest(t)
	packDir := createMinimalVerifiableBundle(t)
	populatePassingCampaignPack(t, packDir)
	reportPath := filepath.Join(t.TempDir(), "campaign.json")
	var stdout, stderr bytes.Buffer
	if code := runConform([]string{"adversarial", "--bundle", packDir, "--profile", "dev-local", "--report", reportPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("campaign exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	report := readAdversarialCampaignReport(t, reportPath)
	baseArgs := adversarialVerifyReportArgs(reportPath, attestationPublicKeyHex)
	matching := append(append([]string{}, baseArgs...),
		"--expected-kernel-commit", report.RunnerProvenance.KernelCommit,
		"--expected-executable-sha256", report.RunnerProvenance.ExecutableSHA256,
		"--expected-trust-profile", report.TrustProfile,
		"--expected-evidence-root", report.EvidenceRoot,
		"--expected-merkle-root", report.MerkleRoot,
		"--expected-evaluation-time", report.EvaluationTime,
		"--expected-detector-revision", report.RunnerProvenance.DetectorRevision,
		"--expected-detector-definition-sha256", report.RunnerProvenance.DetectorDefinitionSHA256,
	)
	stdout.Reset()
	stderr.Reset()
	if code := runConform(matching, &stdout, &stderr); code != 0 {
		t.Fatalf("matching context exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	for _, tc := range []struct {
		flag string
		want string
	}{
		{flag: "--expected-kernel-commit", want: "kernel commit mismatch"},
		{flag: "--expected-executable-sha256", want: "executable digest mismatch"},
		{flag: "--expected-trust-profile", want: "trust profile mismatch"},
		{flag: "--expected-campaign-id", want: "campaign id mismatch"},
		{flag: "--expected-run-id", want: "run id mismatch"},
		{flag: "--expected-evidence-root", want: "evidence root mismatch"},
		{flag: "--expected-merkle-root", want: "merkle root mismatch"},
		{flag: "--expected-evaluation-time", want: "evaluation time mismatch"},
		{flag: "--expected-detector-revision", want: "detector revision mismatch"},
		{flag: "--expected-detector-definition-sha256", want: "detector definition digest mismatch"},
	} {
		t.Run(tc.flag, func(t *testing.T) {
			stdout.Reset()
			stderr.Reset()
			args := append(append([]string{}, baseArgs...), tc.flag, "mismatched-context")
			if code := runConform(args, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("mismatch exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestConformAdversarialVerifyReportRejectsUnknownFields(t *testing.T) {
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
	code := runConform(append(adversarialVerifyReportArgs(reportPath, attestationPublicKeyHex), "--json"), &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "unknown field") {
		t.Fatalf("verify exit=%d accepted unknown JSON field; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestConformAdversarialVerifyReportRejectsDuplicateFields(t *testing.T) {
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
	duplicate := append([]byte(`{"schema_version":"helm.adversarial_campaign_report.v1",`), data[1:]...)
	if err := os.WriteFile(reportPath, duplicate, 0o600); err != nil {
		t.Fatal(err)
	}

	stdout.Reset()
	stderr.Reset()
	code := runConform(adversarialVerifyReportArgs(reportPath, attestationPublicKeyHex), &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), `duplicate JSON object key "schema_version"`) {
		t.Fatalf("verify exit=%d accepted duplicate JSON field; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestConformAdversarialVerifyReportRejectsNullOptionalFields(t *testing.T) {
	tests := []struct {
		name       string
		passingRun bool
		injectNull func(*testing.T, map[string]any)
	}{
		{
			name:       "nested verification optional field",
			passingRun: true,
			injectNull: func(t *testing.T, presentation map[string]any) {
				t.Helper()
				checks, ok := presentation["verification_checks"].([]any)
				if !ok {
					t.Fatal("verification_checks is not an array")
				}
				for _, value := range checks {
					check, ok := value.(map[string]any)
					if !ok {
						t.Fatal("verification check is not an object")
					}
					for _, field := range []string{"detail", "reason"} {
						if _, exists := check[field]; !exists {
							check[field] = nil
							return
						}
					}
				}
				t.Fatal("no verification check with an omitted optional field")
			},
		},
		{
			name: "top-level suites",
			injectNull: func(t *testing.T, presentation map[string]any) {
				t.Helper()
				if _, exists := presentation["suites"]; exists {
					t.Fatal("failed campaign unexpectedly contains suites")
				}
				presentation["suites"] = nil
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attestationPublicKeyHex := configureAdversarialCommandTest(t)
			packDir := createMinimalVerifiableBundle(t)
			if tc.passingRun {
				populatePassingCampaignPack(t, packDir)
			}
			reportPath := filepath.Join(t.TempDir(), "campaign.json")
			var stdout, stderr bytes.Buffer
			code := runConform([]string{"adversarial", "--bundle", packDir, "--profile", "dev-local", "--report", reportPath}, &stdout, &stderr)
			if tc.passingRun && code != 0 {
				t.Fatalf("campaign exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			if !tc.passingRun && code != 1 {
				t.Fatalf("incomplete campaign exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}

			data, err := os.ReadFile(reportPath)
			if err != nil {
				t.Fatal(err)
			}
			var presentation map[string]any
			if err := json.Unmarshal(data, &presentation); err != nil {
				t.Fatal(err)
			}
			tc.injectNull(t, presentation)
			writeCampaignJSON(t, reportPath, presentation)

			stdout.Reset()
			stderr.Reset()
			code = runConform(adversarialVerifyReportArgs(reportPath, attestationPublicKeyHex), &stdout, &stderr)
			if code != 2 || !strings.Contains(stderr.String(), "JSON null values are not allowed") {
				t.Fatalf("verify exit=%d accepted null-valued optional field; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestConformAdversarialVerifyReportRequiresCanonicalByteEncoding(t *testing.T) {
	attestationPublicKeyHex := configureAdversarialCommandTest(t)
	reportPath := filepath.Join(t.TempDir(), "campaign.json")
	var stdout, stderr bytes.Buffer
	code := runConform([]string{"adversarial", "--bundle", t.TempDir(), "--profile", "dev-local", "--report", reportPath}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("failed campaign exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	canonical, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}

	omittedRequired := bytes.Replace(canonical, []byte("  \"coverage_checks\": [],\n"), nil, 1)
	if bytes.Equal(omittedRequired, canonical) {
		t.Fatal("generated failed report did not contain canonical coverage_checks")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, canonical); err != nil {
		t.Fatal(err)
	}
	compact.WriteByte('\n')

	for name, mutated := range map[string][]byte{
		"omitted required field": omittedRequired,
		"alternate whitespace":   compact.Bytes(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(reportPath, mutated, 0o600); err != nil {
				t.Fatal(err)
			}
			stdout.Reset()
			stderr.Reset()
			code := runConform(adversarialVerifyReportArgs(reportPath, attestationPublicKeyHex), &stdout, &stderr)
			if code != 2 || !strings.Contains(stderr.String(), "campaign report is not in canonical byte encoding") {
				t.Fatalf("verify exit=%d accepted %s; stdout=%s stderr=%s", code, name, stdout.String(), stderr.String())
			}
		})
	}
}

func TestConformAdversarialVerifyReportRejectsSignedSemanticContradictions(t *testing.T) {
	attestationPublicKeyHex := configureAdversarialCommandTest(t)
	packDir := createMinimalVerifiableBundle(t)
	populatePassingCampaignPack(t, packDir)
	baseReportPath := filepath.Join(t.TempDir(), "campaign.json")
	var stdout, stderr bytes.Buffer
	if code := runConform([]string{"adversarial", "--bundle", packDir, "--profile", "dev-local", "--report", baseReportPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("campaign exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	base := readAdversarialCampaignReport(t, baseReportPath)

	tests := []struct {
		name   string
		mutate func(*adversarialCampaignReport)
		want   string
	}{
		{name: "bundle verdict", mutate: func(report *adversarialCampaignReport) { report.BundleVerified = false }, want: "bundle_verified"},
		{name: "coverage verdict", mutate: func(report *adversarialCampaignReport) { report.CoverageVerified = false }, want: "coverage_verified"},
		{name: "mandatory count", mutate: func(report *adversarialCampaignReport) { report.MandatorySuites-- }, want: "mandatory_suites"},
		{name: "executed count", mutate: func(report *adversarialCampaignReport) { report.ExecutedSuites-- }, want: "suite counters"},
		{name: "passed count", mutate: func(report *adversarialCampaignReport) { report.PassedSuites-- }, want: "suite counters"},
		{name: "missing suite result", mutate: func(report *adversarialCampaignReport) { report.Suites = report.Suites[:len(report.Suites)-1] }, want: "suite counters"},
		{name: "suite verdict", mutate: func(report *adversarialCampaignReport) { report.Suites[0].Pass = false }, want: "does not match its test results"},
		{name: "coverage counter", mutate: func(report *adversarialCampaignReport) { report.CoverageChecks[0].Covered = false }, want: "contradicts complete mutation evidence"},
		{name: "mutation binding", mutate: func(report *adversarialCampaignReport) { report.CoverageChecks[0].MutationID = "substituted/v1" }, want: "mutation_id"},
		{name: "mutation proof", mutate: func(report *adversarialCampaignReport) { report.CoverageChecks[0].MutationRejected = false }, want: "lacks complete positive-control and mutation evidence"},
		{name: "expected detector test", mutate: func(report *adversarialCampaignReport) { report.Suites[0].TestResults[0].TestID = "SUBSTITUTED-T1" }, want: "lacks expected detector test"},
		{name: "detector revision", mutate: func(report *adversarialCampaignReport) {
			report.RunnerProvenance.DetectorRevision = "kernel-adversarial-detectors/substituted"
		}, want: "detector_revision"},
		{name: "detector definition", mutate: func(report *adversarialCampaignReport) {
			report.RunnerProvenance.DetectorDefinitionSHA256 = "sha256:substituted"
		}, want: "detector_definition_sha256"},
		{name: "unknown status", mutate: func(report *adversarialCampaignReport) {
			report.Pass = false
			report.Status = adversarialCampaignStatus("invented")
		}, want: "unsupported status"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := json.Marshal(base)
			if err != nil {
				t.Fatal(err)
			}
			var report adversarialCampaignReport
			if err := json.Unmarshal(encoded, &report); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&report)
			if err := signAdversarialCampaignReport(&report); err != nil {
				t.Fatal(err)
			}
			data, err := marshalAdversarialCampaignReport(report)
			if err != nil {
				t.Fatal(err)
			}
			reportPath := filepath.Join(t.TempDir(), "signed-contradiction.json")
			if err := writeAdversarialCampaignReport(reportPath, data); err != nil {
				t.Fatal(err)
			}

			stdout.Reset()
			stderr.Reset()
			code := runConform(adversarialVerifyReportArgs(reportPath, attestationPublicKeyHex), &stdout, &stderr)
			if code != 1 || !strings.Contains(stderr.String(), "campaign report semantics are invalid") || !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("verify exit=%d accepted signed contradiction; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestAdversarialReportSignatureIsDomainSeparated(t *testing.T) {
	attestationPublicKeyHex := configureAdversarialCommandTest(t)
	packDir := createMinimalVerifiableBundle(t)
	populatePassingCampaignPack(t, packDir)
	reportPath := filepath.Join(t.TempDir(), "campaign.json")
	var stdout, stderr bytes.Buffer
	if code := runConform([]string{"adversarial", "--bundle", packDir, "--profile", "dev-local", "--report", reportPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("campaign exit=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	report := readAdversarialCampaignReport(t, reportPath)
	report.Attestation.Signature = ""
	barePayload, err := canonicalJSON(report)
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("helm-adversarial-report-attestation-test-key-v1"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	report.Attestation.Signature = hex.EncodeToString(ed25519.Sign(privateKey, barePayload))
	if err := verifyAdversarialCampaignReportAttestation(report, attestationPublicKeyHex); err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("bare cross-protocol signature error=%v, want domain-separated rejection", err)
	}
}

func TestAdversarialReportSignatureRejectsNonCanonicalEncoding(t *testing.T) {
	seed := sha256.Sum256([]byte("helm-adversarial-report-canonical-signature-test-key-v1"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKeyHex := hex.EncodeToString(privateKey.Public().(ed25519.PublicKey))
	report := adversarialCampaignReport{SchemaVersion: adversarialCampaignSchemaVersion}
	if err := signAdversarialCampaignReportWithKey(&report, privateKey, publicKeyHex); err != nil {
		t.Fatal(err)
	}
	canonicalSignature := report.Attestation.Signature
	uppercaseSignature := strings.ToUpper(canonicalSignature)
	if uppercaseSignature == canonicalSignature {
		t.Fatal("test signature unexpectedly contains no hexadecimal letters")
	}

	for _, signature := range []string{
		" " + canonicalSignature,
		canonicalSignature + " ",
		uppercaseSignature,
	} {
		report.Attestation.Signature = signature
		if err := verifyAdversarialCampaignReportAttestation(report, publicKeyHex); err == nil || !strings.Contains(err.Error(), "invalid campaign attestation signature encoding") {
			t.Fatalf("non-canonical signature %q error=%v, want encoding rejection", signature, err)
		}
	}
}

func TestAdversarialReportSigningKeyValidatesExpandedPrivateKey(t *testing.T) {
	seed := sha256.Sum256([]byte("helm-adversarial-report-expanded-key-test-v1"))
	expandedKey := ed25519.NewKeyFromSeed(seed[:])
	t.Setenv(adversarialReportSigningKeyEnv, hex.EncodeToString(expandedKey))
	privateKey, publicKeyHex, err := adversarialReportSigningKey()
	if err != nil {
		t.Fatalf("valid expanded key: %v", err)
	}
	if !bytes.Equal(privateKey, expandedKey) || publicKeyHex != hex.EncodeToString(expandedKey.Public().(ed25519.PublicKey)) {
		t.Fatal("expanded key was not preserved with its derived public key")
	}

	corruptedKey := append(ed25519.PrivateKey(nil), expandedKey...)
	corruptedKey[len(corruptedKey)-1] ^= 0x01
	t.Setenv(adversarialReportSigningKeyEnv, hex.EncodeToString(corruptedKey))
	if _, _, err := adversarialReportSigningKey(); err == nil || !strings.Contains(err.Error(), "public key does not match its seed") {
		t.Fatalf("corrupted expanded key error=%v, want consistency rejection", err)
	}
}

func TestAdversarialReportJSONRejectsExcessiveNesting(t *testing.T) {
	data := []byte(strings.Repeat("[", maxAdversarialJSONDepth+1) + "0" + strings.Repeat("]", maxAdversarialJSONDepth+1))
	if err := validateAdversarialJSONStructure(data); err == nil || !strings.Contains(err.Error(), "JSON nesting exceeds") {
		t.Fatalf("deep JSON err=%v, want bounded nesting rejection", err)
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
	receipts[0].value = signAdversarialCampaignDocument(t, receipts[0].value, "campaign_signatures", testReceiptSignatureDomain, campaignPrivateKey)
	receipts[3].value = signAdversarialCampaignDocument(t, receipts[3].value, "campaign_signatures", testReceiptSignatureDomain, campaignPrivateKey)
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
	toolManifest := signAdversarialCampaignDocument(t, map[string]any{
		"name":        "campaign-tool",
		"campaign_id": testAdversarialCampaignID,
		"run_id":      testAdversarialRunID,
	}, "signatures", testToolSignatureDomain, campaignPrivateKey)
	writeCampaignJSON(t, filepath.Join(packDir, "99_EXT", "adversarial", "tools", "tool.json"), toolManifest)
	writeCampaignJSON(t, filepath.Join(packDir, "06_LOGS", "receipt_emission_panic.json"), map[string]any{"last_good_seq": 5})
	reindexAndResealCampaignPack(t, packDir, "ep_campaign_pass")
}

func campaignReceipt(receiptID, decisionID string, seq int, actionType string, parents []string) map[string]any {
	receipt := map[string]any{
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
		"campaign_id":           testAdversarialCampaignID,
		"run_id":                testAdversarialRunID,
	}
	switch actionType {
	case "policy_decision":
		receipt["status"] = "ALLOW"
	case "approval_action":
		receipt["status"] = "APPROVED"
	case "budget_decrement", "budget_exhausted":
		receipt["budget_snapshot_ref"] = decisionID
	}
	return receipt
}

func configureAdversarialCommandTest(t *testing.T) string {
	t.Helper()
	_, campaignPublicKeyHex := adversarialCampaignTestKey()
	attestationSeed := sha256.Sum256([]byte("helm-adversarial-report-attestation-test-key-v1"))
	attestationPrivateKey := ed25519.NewKeyFromSeed(attestationSeed[:])
	attestationPublicKey := attestationPrivateKey.Public().(ed25519.PublicKey)
	t.Setenv("HELM_BOUNTY_CAMPAIGN_PUBLIC_KEY_HEX", campaignPublicKeyHex)
	t.Setenv(adversarial.CampaignIDEnv, testAdversarialCampaignID)
	t.Setenv(adversarial.CampaignRunIDEnv, testAdversarialRunID)
	t.Setenv("HELM_BOUNTY_EVALUATION_TIME_RFC3339", "2026-07-15T12:00:00Z")
	t.Setenv("HELM_KERNEL_COMMIT", strings.Repeat("a", 40))
	t.Setenv(adversarialReportSigningKeyEnv, hex.EncodeToString(attestationSeed[:]))
	t.Setenv(adversarialReportPublicKeyEnv, hex.EncodeToString(attestationPublicKey))
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

func signAdversarialCampaignDocument(t *testing.T, document map[string]any, field, domain string, privateKey ed25519.PrivateKey) map[string]any {
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
	domainSeparated := append(append([]byte(domain), 0), canonical...)
	payload[field] = []any{map[string]any{
		"algorithm": "ed25519",
		"key_id":    "sha256:" + hex.EncodeToString(keyHash[:]),
		"signature": hex.EncodeToString(ed25519.Sign(privateKey, domainSeparated)),
	}}
	return payload
}

func adversarialVerifyReportArgs(reportPath, trustedPublicKey string) []string {
	return []string{
		"adversarial", "verify-report",
		"--report", reportPath,
		"--trusted-public-key", trustedPublicKey,
		"--expected-campaign-id", testAdversarialCampaignID,
		"--expected-run-id", testAdversarialRunID,
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

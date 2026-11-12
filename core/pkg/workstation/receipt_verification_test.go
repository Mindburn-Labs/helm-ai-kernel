// quantum_posture: these tests cover classical Ed25519 receipt signatures
// only and do not claim post-quantum protection.
package workstation

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// verificationInputs writes one receipt per signature status the read model
// tells apart, each a denied network decision for a distinct run.
func verificationInputs(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	decide := func(runID string, seed []byte) *contracts.WorkstationPolicyDecisionReceipt {
		req := decisionRequest("network", "https://"+runID+".example")
		req.RunID = runID
		req.RequestID = "req-" + runID
		receipt, err := Decide(DefaultObserveDraftProfile(), req, DecisionOptions{SigningSeed: seed})
		if err != nil {
			t.Fatal(err)
		}
		return receipt
	}
	writeJSONFixture(t, filepath.Join(dir, "trusted.json"), decide("trusted", workstationTestSigningSeed()))
	writeJSONFixture(t, filepath.Join(dir, "other-key.json"), decide("other-key", []byte(strings.Repeat("z", ed25519.SeedSize))))

	unsigned := decide("unsigned", workstationTestSigningSeed())
	unsigned.Signature, unsigned.SignerKeyID = "", ""
	writeJSONFixture(t, filepath.Join(dir, "unsigned.json"), unsigned)

	altered := decide("altered", workstationTestSigningSeed())
	altered.Verdict = contracts.WorkstationVerdictAllow
	writeJSONFixture(t, filepath.Join(dir, "altered.json"), altered)

	malformed := decide("malformed", workstationTestSigningSeed())
	malformed.Signature = "not-hex"
	writeJSONFixture(t, filepath.Join(dir, "malformed.json"), malformed)

	retired, err := os.ReadFile(filepath.Join(repoRoot(t), "fixtures", "workstation", "reference", "receipts", "decision-network-deny.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "retired.json"), retired, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestOperatorViewChecksEverySignature(t *testing.T) {
	dir := verificationInputs(t)
	trust := TrustAnchor{PublicKey: workstationTestPublicKey(), Source: "test-anchor.pub"}
	view, err := BuildOperatorView(trust, dir)
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]string{}
	for _, run := range view.Runs {
		status[run.RunID] = run.SignatureStatus
	}
	want := map[string]string{
		"trusted":   SignatureTrustedKey,
		"other-key": SignatureUntrustedKey,
		"unsigned":  SignatureUnsigned,
		"altered":   SignatureInvalid,
		"malformed": SignatureInvalid,
	}
	for runID, wantStatus := range want {
		if status[runID] != wantStatus {
			t.Errorf("run %s status = %q, want %q", runID, status[runID], wantStatus)
		}
	}
	retired := 0
	for _, run := range view.Runs {
		if run.SignatureStatus == SignatureRetiredKey {
			retired++
		}
	}
	if retired != 1 || len(view.Runs) != 6 {
		t.Fatalf("runs = %d with %d signed by the retired key, want 6 and 1: %+v", len(view.Runs), retired, view.Runs)
	}

	// Only receipts whose signature holds reach the queues built from them.
	denied := map[string]bool{}
	for _, item := range view.DeniedTimeline {
		denied[item.RunID] = true
	}
	for _, runID := range []string{"unsigned", "altered", "malformed"} {
		if denied[runID] {
			t.Errorf("denied timeline carries %s, whose signature does not hold", runID)
		}
	}
	if !denied["trusted"] || !denied["other-key"] || len(view.DeniedTimeline) != 3 {
		t.Fatalf("denied timeline = %+v, want the three receipts whose signature holds", view.DeniedTimeline)
	}

	verification := view.Verification
	if verification == nil || verification.TrustAnchor != "test-anchor.pub" || verification.Counted() != 3 || len(verification.NotCounted) != 3 {
		t.Fatalf("verification = %+v", verification)
	}
	statements := strings.Join(verification.Statements(), "\n")
	for _, phrase := range []string{"3 of 6 input files match", "unsigned.json (unsigned)", "altered.json (invalid_signature)", "not counted", "test-anchor.pub", "1 counted receipts are signed by that key, 1 by another key", "retired built-in key"} {
		if !strings.Contains(statements, phrase) {
			t.Errorf("statements do not say %q:\n%s", phrase, statements)
		}
	}
	// R2: these sentences describe checks; the verifier's verdict words are
	// not theirs to use.
	for _, word := range []string{"VERIFIED", "UNVERIFIABLE", "FAILED", "PASS"} {
		if strings.Contains(statements, word) {
			t.Errorf("statements use the verifier verdict %q:\n%s", word, statements)
		}
	}
}

func TestOperatorViewWithoutAnAnchorSaysTrustWasNotChecked(t *testing.T) {
	dir := verificationInputs(t)
	view, err := BuildOperatorView(TrustAnchor{}, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range view.Runs {
		switch run.RunID {
		case "trusted", "other-key":
			if run.SignatureStatus != SignatureSignerNotChecked {
				t.Errorf("run %s status = %q, want %q", run.RunID, run.SignatureStatus, SignatureSignerNotChecked)
			}
		}
		if run.SignatureStatus == SignatureTrustedKey || run.SignatureStatus == "" {
			t.Errorf("run %s status = %q with no anchor", run.RunID, run.SignatureStatus)
		}
	}
	if statements := strings.Join(view.Verification.Statements(), "\n"); !strings.Contains(statements, "Signer trust was not checked") {
		t.Fatalf("statements do not say trust was unchecked:\n%s", statements)
	}
}

func TestScopeAuditCountsOnlyReceiptsWhoseSignatureHolds(t *testing.T) {
	dir := verificationInputs(t)
	trust := TrustAnchor{PublicKey: workstationTestPublicKey(), Source: "test-anchor.pub"}
	report, err := BuildScopeAudit(trust, dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.InputFiles != 6 || report.Summary.DecisionReceipts != 1 || report.Summary.DeniedActions != 1 || len(report.EvidenceRefs) != 1 || report.Summary.UntrustedSignerReceipts != 2 {
		t.Fatalf("summary = %+v refs = %d, want six inputs, one receipt by the trusted key and two by other keys counted apart", report.Summary, len(report.EvidenceRefs))
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, runID := range []string{"unsigned", "altered", "malformed"} {
		if strings.Contains(string(encoded), "https://"+runID+".example") {
			t.Errorf("report carries the target of %s, whose signature does not hold", runID)
		}
	}
	limitations := strings.Join(report.Limitations, "\n")
	if !strings.Contains(limitations, "unsigned.json (unsigned)") || !strings.Contains(limitations, "Signer trust was checked against test-anchor.pub") {
		t.Fatalf("limitations do not state the checks:\n%s", limitations)
	}

	onlyBad := t.TempDir()
	for _, name := range []string{"unsigned.json", "altered.json"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(onlyBad, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := BuildScopeAudit(trust, onlyBad); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("scope audit over inputs with no valid signature = %v, want a refusal that names the signature", err)
	}
}

// The report still fits its published schema with the checks stated in it.
func TestScopeAuditWithSignatureChecksFitsItsSchema(t *testing.T) {
	imported, err := ImportArtifactDir(filepath.Join(repoRoot(t), "fixtures", "workstation", "scope-audit-all-boundaries"), workstationTestImportOptions())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeJSONFixture(t, filepath.Join(dir, "signed.json"), imported.Receipt)
	unsigned := *imported.Receipt
	unsigned.Signature = ""
	writeJSONFixture(t, filepath.Join(dir, "unsigned.json"), &unsigned)
	report, err := BuildScopeAudit(TrustAnchor{PublicKey: workstationTestPublicKey(), Source: "test-anchor.pub"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.InputFiles != 2 || report.Summary.AgentRunReceipts != 1 {
		t.Fatalf("summary = %+v, want two inputs and one counted receipt", report.Summary)
	}
	validateSchemaValue(t, compileSchema(t, filepath.Join(repoRoot(t), "protocols", "json-schemas", "workstation", "scope_audit_report.v1.schema.json")), report)
}

// An evidence pack is written from a receipt in hand, not from files read
// back, so its operator view carries no signature status and stays
// byte-identical to packs written before the check existed.
func TestEvidencePackOperatorViewIsUnchanged(t *testing.T) {
	imported, err := ImportArtifactDir(filepath.Join(repoRoot(t), "fixtures", "workstation", "denied-memory"), workstationTestImportOptions())
	if err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(t.TempDir(), "pack")
	if _, err := ExportEvidencePack(imported, outDir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(outDir, "99_EXT", "workstation", "operator-view.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "signature_status") || strings.Contains(string(data), "verification") {
		t.Fatalf("evidence pack operator view gained signature fields: %s", data)
	}
}

func TestTrustMaterialIsDeniedUnderEveryProfile(t *testing.T) {
	permissive := DefaultObserveDraftProfile()
	permissive.Operate.Permissions = []string{
		contracts.WorkstationPermissionSecretRead, contracts.WorkstationPermissionFileWrite,
		contracts.WorkstationPermissionShellOperate, contracts.WorkstationPermissionNetworkEgress,
		contracts.WorkstationPermissionMCPMutate,
	}
	for _, class := range []string{"secret", "sensitive-file-write", "shell-operate", "mcp", "file", "shell"} {
		request := decisionRequest(class, "/home/agent/.helm-ai-kernel/keys/workstation-ed25519.seed")
		allowed, err := Decide(permissive, request, workstationTestDecisionOptions())
		if err != nil {
			t.Fatal(err)
		}
		options := workstationTestDecisionOptions()
		options.TrustMaterial = true
		denied, err := Decide(permissive, request, options)
		if err != nil {
			t.Fatal(err)
		}
		if denied.Verdict != contracts.WorkstationVerdictDeny || denied.ReasonCode != "TRUST_MATERIAL_ACCESS_DENIED" {
			t.Errorf("class %s with trust material = %s/%s (without: %s), want DENY/TRUST_MATERIAL_ACCESS_DENIED", class, denied.Verdict, denied.ReasonCode, allowed.Verdict)
		}
		if ok, err := VerifyDecisionReceiptSignature(denied); err != nil || !ok {
			t.Errorf("class %s denial is not signed: %v %v", class, ok, err)
		}
	}
	if got := denialFinality("TRUST_MATERIAL_ACCESS_DENIED"); got != contracts.DenialClassForbidden {
		t.Fatalf("finality = %q, want class_forbidden", got)
	}
	if got := denialFinality("EGRESS_DESTINATION_UNDETERMINED"); got != contracts.DenialInstanceParameter {
		t.Fatalf("finality = %q, want instance_parameter", got)
	}
}

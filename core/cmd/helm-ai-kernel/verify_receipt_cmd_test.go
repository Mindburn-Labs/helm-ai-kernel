// quantum_posture: these tests exercise classical Ed25519 receipt.v5
// verify-receipt checks only; they add no post-quantum assurance.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func persistEvaluateArtifacts(t *testing.T) (dataDir string, receipt *contracts.Receipt) {
	t.Helper()
	isolateVerifyReceiptTest(t)
	signer, err := helmcrypto.NewEd25519Signer("verify-receipt-test")
	if err != nil {
		t.Fatal(err)
	}
	dataDir = t.TempDir()
	store := &captureReceiptStore{}
	svc := &Services{DataDir: dataDir, ReceiptStore: store, ReceiptSigner: signer}
	decision := &contracts.DecisionRecord{
		ID:                 "dec-verify-receipt",
		Action:             "EXECUTE_TOOL",
		Verdict:            string(contracts.VerdictDeny),
		ReasonCode:         string(contracts.ReasonEmergencyStopFenced),
		PolicyContentHash:  "sha256:policy-content",
		PolicyDecisionHash: "sha256:pdp",
		InputContext:       map[string]any{"session_id": "session-verify-receipt"},
		Timestamp:          time.Unix(1700000000, 0).UTC(),
	}
	if err := persistDecisionReceipt(context.Background(), svc, decision, "agent.test", []byte("EXECUTE_TOOL:tool"), map[string]any{"source": "api.evaluate"}); err != nil {
		t.Fatalf("persist receipt: %v", err)
	}
	if store.stored == nil {
		t.Fatal("receipt was not stored")
	}
	return dataDir, store.stored
}

func persistEvaluateReceiptFile(t *testing.T) (receiptPath, keyPath string, receipt *contracts.Receipt) {
	t.Helper()
	dataDir, stored := persistEvaluateArtifacts(t)
	src := portableEvaluateReceiptPath(dataDir, stored.ReceiptID)
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read persisted evaluate receipt: %v", err)
	}
	offBox := filepath.Join(t.TempDir(), "evaluate-receipt.v5.json")
	if err := os.WriteFile(offBox, raw, 0o600); err != nil {
		t.Fatalf("copy receipt off-box: %v", err)
	}
	keySrc := portableEvaluatePublicKeyPath(dataDir, stored.ReceiptID)
	keyRaw, err := os.ReadFile(keySrc)
	if err != nil {
		t.Fatalf("read persisted public key: %v", err)
	}
	keyPath = filepath.Join(t.TempDir(), "expected-ed25519.pub")
	if err := os.WriteFile(keyPath, keyRaw, 0o644); err != nil {
		t.Fatalf("copy trusted key: %v", err)
	}
	return offBox, keyPath, stored
}

func isolateVerifyReceiptTest(t *testing.T) {
	t.Helper()
	t.Setenv("HELM_ADMIN_API_KEY", "")
	t.Setenv("HELM_URL", "")
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("http_proxy", "")
	t.Setenv("https_proxy", "")
}

func TestVerifyReceiptCLITrustedCopiedFile(t *testing.T) {
	receiptPath, keyPath, _ := persistEvaluateReceiptFile(t)
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "verify", "receipt",
		"--receipt", receiptPath,
		"--trusted-public-key-file", keyPath,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("verify receipt exit = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "integrity: true") || !strings.Contains(stdout.String(), "trusted:   true") {
		t.Fatalf("verify receipt output missing trusted integrity: %s", stdout.String())
	}
}

func TestVerifyReceiptCLITamperedVerdict(t *testing.T) {
	receiptPath, keyPath, _ := persistEvaluateReceiptFile(t)
	raw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), `"verdict": "DENY"`, `"verdict": "ALLOW"`, 1)
	if tampered == string(raw) {
		t.Fatal("receipt fixture did not contain signed DENY verdict")
	}
	tamperedPath := filepath.Join(t.TempDir(), "tampered-verdict.json")
	if err := os.WriteFile(tamperedPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "verify", "receipt",
		"--receipt", tamperedPath,
		"--trusted-public-key-file", keyPath,
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("tampered verdict exit = %d, want 1 stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "integrity: false") {
		t.Fatalf("tampered verdict output missing integrity=false: %s", stdout.String())
	}
}

func TestVerifyReceiptCLITamperedSignature(t *testing.T) {
	receiptPath, keyPath, _ := persistEvaluateReceiptFile(t)
	raw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	sig, _ := doc["signature"].(string)
	if sig == "" {
		t.Fatal("receipt missing signature")
	}
	doc["signature"] = strings.Repeat("0", len(sig))
	tampered, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	tamperedPath := filepath.Join(t.TempDir(), "tampered-signature.json")
	if err := os.WriteFile(tamperedPath, append(tampered, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "verify", "receipt",
		"--receipt", tamperedPath,
		"--trusted-public-key-file", keyPath,
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("tampered signature exit = %d, want 1 stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "integrity: false") {
		t.Fatalf("tampered signature output missing integrity=false: %s", stdout.String())
	}
}

func TestVerifyReceiptCLIMissingTrustedKey(t *testing.T) {
	receiptPath, _, _ := persistEvaluateReceiptFile(t)
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "verify", "receipt",
		"--receipt", receiptPath,
	}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("missing trusted key must not verify: stdout=%s", stdout.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("usage error leaked data to stdout: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "trusted-public-key-file") {
		t.Fatalf("missing key stderr = %s", stderr.String())
	}
}

func TestVerifyReceiptCLIWrongTrustedKey(t *testing.T) {
	receiptPath, _, _ := persistEvaluateReceiptFile(t)
	wrong := filepath.Join(t.TempDir(), "wrong-trusted.pub")
	if err := os.WriteFile(wrong, []byte(strings.Repeat("f", 64)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "verify", "receipt",
		"--receipt", receiptPath,
		"--trusted-public-key-file", wrong,
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("wrong-anchor exit = %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "integrity: true") || !strings.Contains(stdout.String(), "trusted:   false") {
		t.Fatalf("wrong-anchor output missing trust separation: %s", stdout.String())
	}
}

func TestVerifyReceiptCLIJSONReportsAdmissible(t *testing.T) {
	receiptPath, keyPath, stored := persistEvaluateReceiptFile(t)
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "verify", "receipt",
		"--receipt", receiptPath,
		"--trusted-public-key-file", keyPath,
		"--json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("json verify exit = %d stderr=%s", code, stderr.String())
	}
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("json report: %v\n%s", err, stdout.String())
	}
	if report["integrity_valid"] != true || report["signer_trusted"] != true {
		t.Fatalf("json report = %#v", report)
	}
	if report["receipt_id"] != stored.ReceiptID {
		t.Fatalf("json receipt_id = %v, want %s", report["receipt_id"], stored.ReceiptID)
	}
}

// TestVerifyReceiptCLIRefusesCaseVariantShadowMembers is helm-tracker#305
// defect A on this command. The signed DENY receipt is edited, with no key, so
// that its exactly-named verdict says ALLOW while "Verdict", further down,
// restores the signed value for a decoder that folds letter case. `jq
// .verdict` reads ALLOW from that file; the command must not call it
// admissible.
func TestVerifyReceiptCLIRefusesCaseVariantShadowMembers(t *testing.T) {
	receiptPath, keyPath, _ := persistEvaluateReceiptFile(t)
	raw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	shadowed := strings.Replace(string(raw), `"verdict": "DENY"`, `"verdict": "ALLOW"`, 1)
	if shadowed == string(raw) {
		t.Fatal("receipt fixture did not contain signed DENY verdict")
	}
	shadowed = strings.TrimRight(shadowed, " \n")
	shadowed = shadowed[:len(shadowed)-1] + `,"Verdict":"DENY"}`
	var exact map[string]any
	if err := json.Unmarshal([]byte(shadowed), &exact); err != nil {
		t.Fatal(err)
	}
	if exact["verdict"] != "ALLOW" {
		t.Fatalf("the planted file does not read ALLOW by exact name; the case proves nothing: %v", exact["verdict"])
	}
	shadowedPath := filepath.Join(t.TempDir(), "shadowed-verdict.json")
	if err := os.WriteFile(shadowedPath, []byte(shadowed), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"helm-ai-kernel", "verify", "receipt",
		"--receipt", shadowedPath,
		"--trusted-public-key-file", keyPath,
	}, &stdout, &stderr)
	if code == 0 || strings.Contains(stdout.String(), "ADMISSIBLE") {
		t.Fatalf("a file that reads ALLOW by exact name was verified: exit %d stdout=%s", code, stdout.String())
	}
	if !strings.Contains(stderr.String(), "letter case") {
		t.Fatalf("the refusal must name the letter-case collision: stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

// TestVerifyReceiptCLISaysWhatTheSignatureCovers: a receipt.v5 signature
// covers 13 members. The file's other members can be rewritten with no key and
// the command still exits 0 with integrity_valid true, which read as "the
// file is as it was signed". The report now names the members the signature
// covers and the members of this file it does not, in both output forms.
func TestVerifyReceiptCLISaysWhatTheSignatureCovers(t *testing.T) {
	receiptPath, keyPath, stored := persistEvaluateReceiptFile(t)
	raw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]any
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatal(err)
	}
	members["tool_name"], members["executor_id"], members["timestamp"] = "wire_transfer", "someone-else", "2031-01-01T00:00:00Z"
	// The signed-members report came from #305; #308 must also escape the
	// untrusted member names it adds to the human-readable output.
	const unsafeMember = "annotation\x1b[2J\nFORGED"
	members[unsafeMember] = "outside the signed envelope"
	rewritten, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	rewrittenPath := filepath.Join(t.TempDir(), "rewritten.json")
	if err := os.WriteFile(rewrittenPath, rewritten, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := Run([]string{"helm-ai-kernel", "verify", "receipt", "--receipt", rewrittenPath, "--trusted-public-key-file", keyPath, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("rewriting members outside the signed envelope is expected to leave the receipt admissible, which is the point: exit %d stderr=%s", code, stderr.String())
	}
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("json report: %v\n%s", err, stdout.String())
	}
	names := func(key string) map[string]bool {
		list, _ := report[key].([]any)
		out := map[string]bool{}
		for _, item := range list {
			name, _ := item.(string)
			out[name] = true
		}
		return out
	}
	signed, unsigned := names("signed_members"), names("unsigned_members")
	if len(signed) != 13 || !signed["verdict"] || !signed["receipt_id"] || !signed["session_id"] {
		t.Fatalf("signed_members must name the 13 members the signature covers, got %v", report["signed_members"])
	}
	for _, name := range []string{"tool_name", "executor_id", "timestamp", "key_id", "public_key_set", unsafeMember} {
		if !unsigned[name] || signed[name] {
			t.Fatalf("unsigned_members must name %q, a member of this file no signature covers: signed %v, unsigned %v", name, report["signed_members"], report["unsigned_members"])
		}
	}
	for name := range signed {
		if unsigned[name] {
			t.Fatalf("%q is listed as both signed and unsigned", name)
		}
	}
	// The signature is what covers the signed members, not a claim beside
	// them (mutant M34).
	if unsigned["signature"] || signed["signature"] {
		t.Fatalf("signature must be neither a signed nor an unsigned member: signed %v, unsigned %v", report["signed_members"], report["unsigned_members"])
	}
	scope, _ := report["integrity_scope"].(string)
	if report["integrity_valid"] != true || !strings.Contains(scope, "signed_members") || !strings.Contains(scope, "unsigned_members") {
		t.Fatalf("integrity_valid must come with what it covers: integrity_valid %v, integrity_scope %q", report["integrity_valid"], scope)
	}
	// Every receipt member the report echoes is one the signature covers.
	for _, echoed := range []string{"receipt_id", "decision_id", "verdict", "reason_code", "signature_version"} {
		if _, present := report[echoed]; !present || !signed[echoed] {
			t.Fatalf("the report echoes %q, which is absent or outside signed_members", echoed)
		}
	}
	if report["receipt_id"] != stored.ReceiptID {
		t.Fatalf("receipt_id = %v, want %s", report["receipt_id"], stored.ReceiptID)
	}

	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"helm-ai-kernel", "verify", "receipt", "--receipt", rewrittenPath, "--trusted-public-key-file", keyPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("text verify exit = %d stderr=%s", code, stderr.String())
	}
	text := stdout.String()
	for _, want := range []string{"integrity: true", "13 signed members", "unsigned:", "tool_name", "no signature covers"} {
		if !strings.Contains(text, want) {
			t.Fatalf("the text report must say what the signature covers and what it does not (missing %q):\n%s", want, text)
		}
	}
	if strings.Contains(text, "wire_transfer") {
		t.Fatalf("the text report prints the value of an unsigned member as if it were established:\n%s", text)
	}
	if strings.Contains(text, unsafeMember) || !strings.Contains(text, `annotation\x1b[2J\nFORGED`) {
		t.Fatalf("unsigned member names must retain their identity in JSON and be escaped in text: %q", text)
	}
}

// TestVerifyReceiptCLIRefusesAVersionMemberInAnotherLetterCase: a file whose
// only version member is "Signature_Version" skipped the receipt.v5
// signed-member checks, which look the member up by exact name, and was then
// decoded as receipt.v5 by encoding/json, which does not. It exited 0.
func TestVerifyReceiptCLIRefusesAVersionMemberInAnotherLetterCase(t *testing.T) {
	receiptPath, keyPath, _ := persistEvaluateReceiptFile(t)
	raw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(raw), `"signature_version"`) != 1 {
		t.Fatal("receipt fixture does not carry signature_version once")
	}
	variant := strings.Replace(string(raw), `"signature_version"`, `"Signature_Version"`, 1)
	var exact map[string]any
	if err := json.Unmarshal([]byte(variant), &exact); err != nil {
		t.Fatal(err)
	}
	if _, present := exact["signature_version"]; present {
		t.Fatal("the planted file still carries signature_version by exact name; the case proves nothing")
	}
	variantPath := filepath.Join(t.TempDir(), "variant-version.json")
	if err := os.WriteFile(variantPath, []byte(variant), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, format := range [][]string{nil, {"--json"}} {
		var stdout, stderr bytes.Buffer
		args := append([]string{"helm-ai-kernel", "verify", "receipt", "--receipt", variantPath, "--trusted-public-key-file", keyPath}, format...)
		code := Run(args, &stdout, &stderr)
		if code == 0 || stdout.Len() != 0 {
			t.Fatalf("a file with no signature_version by exact name was verified %v: exit %d stdout=%s", format, code, stdout.String())
		}
		if !strings.Contains(stderr.String(), "letter case") || !strings.Contains(stderr.String(), "signature_version") {
			t.Fatalf("the refusal must name the letter case of signature_version: %s", stderr.String())
		}
	}
}

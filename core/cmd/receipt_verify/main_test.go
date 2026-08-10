// quantum_posture: these tests exercise classical Ed25519 verification only.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

const (
	chainFixture           = "../../pkg/receiptverify/testdata/frozen-chain-2026.json"
	permitFixture          = "../../pkg/receiptverify/testdata/frozen-permit-2026.json"
	emptyGovernanceFixture = "../../../reference_packs/receipt-v5/executor_success_empty_governance.receipt.c14n.json"
)

type fixtureFile struct {
	PublicKeyHex string            `json:"public_key_hex"`
	KeyID        string            `json:"key_id"`
	Receipts     []json.RawMessage `json:"receipts,omitempty"`
	Permits      []json.RawMessage `json:"permits,omitempty"`
}

func loadFixture(t *testing.T, path string) fixtureFile {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f fixtureFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

type rawReceiptShape struct {
	name string
	raw  []byte
}

func wrapReceiptShapes(t *testing.T, receipt json.RawMessage) []rawReceiptShape {
	t.Helper()
	array, err := json.Marshal([]json.RawMessage{receipt})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := json.Marshal(map[string]any{"receipts": []json.RawMessage{receipt}})
	if err != nil {
		t.Fatal(err)
	}
	return []rawReceiptShape{
		{name: "single", raw: receipt},
		{name: "array", raw: array},
		{name: "bundle", raw: bundle},
	}
}

func TestParseReceiptsNormalizesAllRawShapes(t *testing.T) {
	receipt, err := os.ReadFile(emptyGovernanceFixture)
	if err != nil {
		t.Fatal(err)
	}
	for _, shape := range wrapReceiptShapes(t, receipt) {
		t.Run(shape.name, func(t *testing.T) {
			bundle, err := parseReceipts(shape.raw)
			if err != nil {
				t.Fatal(err)
			}
			if len(bundle.Receipts) != 1 || bundle.Receipts[0] == nil {
				t.Fatalf("parsed receipts = %#v, want one receipt", bundle.Receipts)
			}
			if got := bundle.Receipts[0].SignatureVersion; got != "receipt.v5" {
				t.Fatalf("signature_version = %q, want receipt.v5", got)
			}
		})
	}
}

func TestParseReceiptsRejectsMissingEmptySignedMemberInAllRawShapes(t *testing.T) {
	raw, err := os.ReadFile(emptyGovernanceFixture)
	if err != nil {
		t.Fatal(err)
	}
	var receipt map[string]json.RawMessage
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	delete(receipt, "policy_hash")
	tampered, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, shape := range wrapReceiptShapes(t, tampered) {
		t.Run(shape.name, func(t *testing.T) {
			_, err := parseReceipts(shape.raw)
			if err == nil || !strings.Contains(err.Error(), "policy_hash") {
				t.Fatalf("missing empty policy_hash error = %v", err)
			}
		})
	}
}

func TestParseReceiptsRejectsWrongSignedMemberTypes(t *testing.T) {
	raw, err := os.ReadFile(emptyGovernanceFixture)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		field string
		value json.RawMessage
		want  string
	}{
		{name: "string_member", field: "policy_hash", value: json.RawMessage(`0`), want: "must be a string"},
		{name: "lamport_clock", field: "lamport_clock", value: json.RawMessage(`"1"`), want: "must be an unsigned integer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var receipt map[string]json.RawMessage
			if err := json.Unmarshal(raw, &receipt); err != nil {
				t.Fatal(err)
			}
			receipt[tc.field] = tc.value
			tampered, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			_, err = parseReceipts(tampered)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("wrong %s type error = %v, want %q", tc.field, err, tc.want)
			}
		})
	}
}

// execute runs the CLI entrypoint with captured stdout/stderr.
func execute(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	outF, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	errF, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	code = run(args, outF, errF)
	outB, _ := os.ReadFile(outF.Name())
	errB, _ := os.ReadFile(errF.Name())
	return code, string(outB), string(errB)
}

func TestVerifiedChainExitsZero(t *testing.T) {
	fx := loadFixture(t, chainFixture)
	code, stdout, _ := execute(t, "--receipt", chainFixture, "--key", fx.PublicKeyHex)
	if code != 0 {
		t.Fatalf("exit %d, want 0; output:\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "VERIFIED — 3 receipt(s)") {
		t.Errorf("verdict line missing: %q", stdout)
	}
}

func TestWrongKeyExitsOne(t *testing.T) {
	code, stdout, _ := execute(t, "--receipt", chainFixture, "--key", strings.Repeat("a", 64))
	if code != 1 {
		t.Fatalf("exit %d, want 1; output:\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "NOT VERIFIED") {
		t.Errorf("verdict line missing: %q", stdout)
	}
}

func TestNoKeyIsAUsageErrorNotAVerdict(t *testing.T) {
	code, _, stderr := execute(t, "--receipt", chainFixture)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(stderr, "no verification key supplied") {
		t.Errorf("refusal must explain itself: %q", stderr)
	}
}

// TestBundleKeyRequiresExplicitOptIn is the CLI half of the embedded-key
// contract: the frozen fixture carries public_key_hex about itself, and that
// key must be unreachable without --allow-self-attested and reachable with it.
func TestBundleKeyRequiresExplicitOptIn(t *testing.T) {
	code, stdout, _ := execute(t, "--receipt", chainFixture, "--allow-self-attested")
	if code != 0 {
		t.Fatalf("--allow-self-attested did not use the bundle's embedded key: exit %d\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "self-attestation") {
		t.Errorf("a self-attested pass must say so in the verdict: %q", stdout)
	}
}

// TestCombinedBundleWithTwoKeys verifies receipts and permits signed by
// different keys in one bundle, which is the shape a counterparty actually
// receives.
func TestCombinedBundleWithTwoKeys(t *testing.T) {
	chain := loadFixture(t, chainFixture)
	permits := loadFixture(t, permitFixture)

	combined, err := json.Marshal(map[string]any{
		"receipts": chain.Receipts,
		"permits":  permits.Permits,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "combined.json")
	if err := os.WriteFile(path, combined, 0o644); err != nil {
		t.Fatal(err)
	}

	code, stdout, _ := execute(t,
		"--receipt", path,
		"--key", chain.PublicKeyHex,
		"--key", "issuer="+permits.PublicKeyHex,
		"--json",
	)
	if code != 0 {
		t.Fatalf("exit %d, want 0; output:\n%s", code, stdout)
	}
	var res receiptverify.Result
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("--json did not emit parseable JSON: %v\n%s", err, stdout)
	}
	if !res.Valid || res.Receipts != 3 || res.Permits != 1 {
		t.Fatalf("unexpected result: %+v", res)
	}
	permitChecked := false
	for _, c := range res.Checks {
		if c.Name == receiptverify.CheckPermit && c.Status == receiptverify.StatusPass {
			permitChecked = true
		}
	}
	if !permitChecked {
		t.Errorf("permit check did not run or did not pass: %+v", res.Checks)
	}
}

func TestTamperedPermitFailsTheBundle(t *testing.T) {
	chain := loadFixture(t, chainFixture)
	permits := loadFixture(t, permitFixture)

	var permit map[string]any
	if err := json.Unmarshal(permits.Permits[0], &permit); err != nil {
		t.Fatal(err)
	}
	permit["evidence_bindings"].(map[string]any)["sandbox_grant_hash"] = "sha256:forged"

	combined, err := json.Marshal(map[string]any{
		"receipts": chain.Receipts,
		"permits":  []any{permit},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "tampered.json")
	if err := os.WriteFile(path, combined, 0o644); err != nil {
		t.Fatal(err)
	}

	code, stdout, _ := execute(t,
		"--receipt", path,
		"--key", chain.PublicKeyHex,
		"--key", "issuer="+permits.PublicKeyHex,
	)
	if code != 1 {
		t.Fatalf("a bundle with a tampered evidence obligation exited %d, want 1\n%s", code, stdout)
	}
	if !strings.Contains(stdout, "permit") {
		t.Errorf("the failure should name the permit check: %q", stdout)
	}
}

func TestGarbageInputIsAUsageError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "garbage.json")
	if err := os.WriteFile(path, []byte("{\"hello\": 1}"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := execute(t, "--receipt", path, "--key", strings.Repeat("a", 64))
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(stderr, "holds no receipt") {
		t.Errorf("refusal must explain the accepted shapes: %q", stderr)
	}
}

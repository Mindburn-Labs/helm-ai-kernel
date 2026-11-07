// quantum_posture: these tests verify classical Ed25519 gateway receipts and
// recompute SHA-256 output hashes; no post-quantum claim.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

const gatewayChainFixture = "../../pkg/receiptverify/testdata/frozen-gateway-chain.json"

type gatewayFixture struct {
	PublicKeyHex    string            `json:"public_key_hex"`
	KeyID           string            `json:"key_id"`
	Receipts        []json.RawMessage `json:"receipts"`
	GatewayBindings map[string][]byte `json:"gateway_bindings"`
}

func loadGatewayFixture(t *testing.T) gatewayFixture {
	t.Helper()
	raw, err := os.ReadFile(gatewayChainFixture)
	if err != nil {
		t.Fatal(err)
	}
	var f gatewayFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Receipts) != 3 || len(f.GatewayBindings) != 3 {
		t.Fatalf("gateway fixture: %d receipts, %d bindings", len(f.Receipts), len(f.GatewayBindings))
	}
	return f
}

func receiptID(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var r struct {
		ReceiptID string `json:"receipt_id"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r.ReceiptID
}

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func bindingStatus(t *testing.T, stdout string) (receiptverify.Result, receiptverify.Status) {
	t.Helper()
	var res receiptverify.Result
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("--json did not emit parseable JSON: %v\n%s", err, stdout)
	}
	for _, c := range res.Checks {
		if c.Name == receiptverify.CheckBinding {
			return res, c.Status
		}
	}
	t.Fatalf("no binding check in %+v", res.Checks)
	return res, ""
}

// The documented offline command: an exported gateway chain verifies under
// the key published at GET /api/v1/receipt-keyring, bindings included.
func TestGatewayExportVerifiesWithItsBindings(t *testing.T) {
	f := loadGatewayFixture(t)
	code, stdout, stderr := execute(t, "--receipt", gatewayChainFixture, "--key", f.KeyID+"="+f.PublicKeyHex, "--json")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	res, status := bindingStatus(t, stdout)
	if status != receiptverify.StatusPass || !res.Valid || res.Bindings != 3 {
		t.Fatalf("result = %+v", res)
	}
	code, stdout, _ = execute(t, "--receipt", gatewayChainFixture, "--key", f.KeyID+"="+f.PublicKeyHex)
	if code != 0 || !strings.Contains(stdout, "3 binding(s)") || !strings.Contains(stdout, "binding") {
		t.Fatalf("human output, exit %d:\n%s", code, stdout)
	}
}

// --binding supplies a binding from a file for a receipt saved on its own,
// as GetAttemptReceipts returns them.
func TestBindingFlagChecksOneReceipt(t *testing.T) {
	f := loadGatewayFixture(t)
	key := f.KeyID + "=" + f.PublicKeyHex
	receipt := writeFile(t, "receipt.json", f.Receipts[0])
	id := receiptID(t, f.Receipts[0])
	binding := writeFile(t, "binding.json", f.GatewayBindings[id])

	code, stdout, stderr := execute(t, "--receipt", receipt, "--key", key, "--binding", id+"="+binding, "--json")
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if _, status := bindingStatus(t, stdout); status != receiptverify.StatusPass {
		t.Fatalf("binding check = %s", status)
	}

	// Without --binding the check is not applicable, never a pass.
	code, stdout, _ = execute(t, "--receipt", receipt, "--key", key, "--json")
	if _, status := bindingStatus(t, stdout); code != 0 || status != receiptverify.StatusNotApplicable {
		t.Fatalf("exit %d, binding check %s", code, status)
	}

	// Another receipt's binding, or a binding for a receipt the file does not
	// hold, fails verification.
	other := writeFile(t, "other.json", f.GatewayBindings[receiptID(t, f.Receipts[1])])
	for _, spec := range []string{id + "=" + other, receiptID(t, f.Receipts[1]) + "=" + binding} {
		code, stdout, _ = execute(t, "--receipt", receipt, "--key", key, "--binding", spec, "--json")
		if _, status := bindingStatus(t, stdout); code != 1 || status != receiptverify.StatusFail {
			t.Fatalf("--binding %s: exit %d, binding check %s", spec, code, status)
		}
	}

	// A malformed flag, an unreadable file or a receipt bound twice is a usage
	// error with no verdict.
	for _, args := range [][]string{
		{"--binding", binding},
		{"--binding", id + "="},
		{"--binding", id + "=" + filepath.Join(t.TempDir(), "missing.json")},
		{"--binding", id + "=" + binding, "--binding", id + "=" + binding},
	} {
		code, _, stderr := execute(t, append([]string{"--receipt", receipt, "--key", key}, args...)...)
		if code != 2 || !strings.Contains(stderr, "binding") {
			t.Fatalf("%v: exit %d, stderr %q", args, code, stderr)
		}
	}
	code, _, stderr = execute(t, "--receipt", gatewayChainFixture, "--key", key, "--binding", id+"="+binding)
	if code != 2 || !strings.Contains(stderr, "already has a binding") {
		t.Fatalf("rebinding a bundled receipt: exit %d, stderr %q", code, stderr)
	}
}

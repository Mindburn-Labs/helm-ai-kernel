// quantum_posture: these tests exercise classical Ed25519 receipt
// verification only; they add no signature scheme and claim no hybrid or
// post-quantum protection.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// frozenGatewayDenial is the DENIED receipt of the frozen gateway chain: a
// receipt.v5 receipt signed once by the gateway's receipt builder, whose
// signing key this repository does not hold. It returns the receipt as
// compact JSON and the --key argument that verifies it.
func frozenGatewayDenial(t *testing.T) ([]byte, string) {
	t.Helper()
	fx := loadGatewayFixture(t)
	var members map[string]any
	if err := json.Unmarshal(fx.Receipts[1], &members); err != nil {
		t.Fatal(err)
	}
	if members["status"] != "DENIED" || members["verdict"] != "DENY" || members["signature_version"] != "receipt.v5" {
		t.Fatalf("frozen gateway receipt[1] is not a receipt.v5 denial: %v", members)
	}
	raw, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	key := fx.KeyID + "=" + fx.PublicKeyHex
	if code, stdout, stderr := execute(t, "--receipt", writeFile(t, "denial.json", raw), "--key", key); code != 0 {
		t.Fatalf("the frozen denial does not verify on its own; the cases prove nothing: exit %d\n%s%s", code, stdout, stderr)
	}
	return raw, key
}

// TestCaseVariantShadowMembersAreNotVerified is helm-tracker#305 defect A at
// the command line. The frozen DENY receipt is edited, with no key, so that
// its exactly-named members say ADMITTED / ALLOW while "Status" and "Verdict"
// restore the signed values for a case-insensitive decoder. `jq .verdict`
// reads ALLOW; the verifier must not report VERIFIED for that file.
func TestCaseVariantShadowMembersAreNotVerified(t *testing.T) {
	raw, key := frozenGatewayDenial(t)
	shadowed := replaceReceiptJSON(t, raw, `"status":"DENIED"`, `"status":"ADMITTED"`)
	shadowed = replaceReceiptJSON(t, shadowed, `"verdict":"DENY"`, `"verdict":"ALLOW"`)
	shadowed = []byte(string(shadowed[:len(shadowed)-1]) + `,"Status":"DENIED","Verdict":"DENY"}`)

	var exact map[string]any
	if err := json.Unmarshal(shadowed, &exact); err != nil {
		t.Fatal(err)
	}
	if exact["verdict"] != "ALLOW" {
		t.Fatalf("the planted file does not read ALLOW by exact name; the case proves nothing: %v", exact)
	}
	for _, shape := range wrapReceiptShapes(t, shadowed) {
		t.Run(shape.name, func(t *testing.T) {
			code, stdout, stderr := execute(t, "--receipt", writeFile(t, "shadowed.json", shape.raw), "--key", key)
			if code != 2 || !strings.Contains(stderr, "letter case") || stdout != "" {
				t.Fatalf("a file that reads ALLOW by exact name: exit %d, want 2 with a letter-case refusal and no verdict\nstdout: %s\nstderr: %s",
					code, stdout, stderr)
			}
		})
	}
}

// replayAsLegacy re-splits the bytes a receipt.v5 signature covers into the
// eight colon-joined fields of the legacy v4 preimage and returns a receipt
// file with no signature_version that carries the same signature and claims
// ALLOW.
func replayAsLegacy(t *testing.T, signed []byte, signature string) []byte {
	t.Helper()
	parts := strings.Split(string(signed), ":")
	for i := 6; i < len(parts)-1; i++ {
		clock, err := strconv.ParseUint(parts[i], 10, 64)
		if err != nil || strconv.FormatUint(clock, 10) != parts[i] {
			continue
		}
		doc, err := json.Marshal(map[string]any{
			"receipt_id":    parts[0],
			"decision_id":   parts[1],
			"effect_id":     parts[2],
			"status":        parts[3],
			"output_hash":   parts[4],
			"prev_hash":     strings.Join(parts[5:i], ":"),
			"lamport_clock": clock,
			"args_hash":     strings.Join(parts[i+1:], ":"),
			"verdict":       "ALLOW",
			"tool_name":     "payments.transfer",
			"timestamp":     "2026-09-01T12:00:00Z",
			"signature":     signature,
		})
		if err != nil {
			t.Fatal(err)
		}
		return doc
	}
	t.Fatal("the signed receipt.v5 bytes hold no colon-delimited integer to stand in for lamport_clock; the case proves nothing")
	return nil
}

func requireLegacyRefusal(t *testing.T, code int, stdout, stderr string) {
	t.Helper()
	if code != 2 || stdout != "" {
		t.Fatalf("a receipt with no signature_version and no opt-in: exit %d, want 2 and no verdict\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	for _, want := range []string{"legacy", "signature_version", "--allow-legacy-v4"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("the refusal must say plainly what the receipt is and how to opt in (missing %q): %s", want, stderr)
		}
	}
}

// TestReceiptV5SignatureReplayedAsLegacyIsNotVerified is helm-tracker#305
// defect B at the command line, built from the frozen gateway chain alone: the
// bytes and signature of its receipt.v5 DENY receipt, re-read as a legacy
// receipt that says ALLOW.
func TestReceiptV5SignatureReplayedAsLegacyIsNotVerified(t *testing.T) {
	raw, key := frozenGatewayDenial(t)
	var genuine contracts.Receipt
	if err := json.Unmarshal(raw, &genuine); err != nil {
		t.Fatal(err)
	}
	signed, err := crypto.CanonicalizeReceiptV5(&genuine)
	if err != nil {
		t.Fatal(err)
	}
	forged := replayAsLegacy(t, signed, genuine.Signature)
	var planted map[string]any
	if err := json.Unmarshal(forged, &planted); err != nil {
		t.Fatal(err)
	}
	if _, versioned := planted["signature_version"]; versioned || planted["verdict"] != "ALLOW" {
		t.Fatalf("the planted file is not an unversioned ALLOW receipt: %s", forged)
	}
	path := writeFile(t, "replayed.json", forged)

	code, stdout, stderr := execute(t, "--receipt", path, "--key", key)
	if code == 0 {
		t.Fatalf("the signature of a frozen receipt.v5 DENY receipt was replayed as a legacy ALLOW receipt and VERIFIED:\n%s", stdout)
	}
	requireLegacyRefusal(t, code, stdout, stderr)
	code, stdout, stderr = execute(t, "--receipt", path, "--key", key, "--json")
	requireLegacyRefusal(t, code, stdout, stderr)
}

// legacyReceipt is a genuine legacy receipt: no signature_version, signed over
// the v4 preimage (eight fields joined with ":"). It returns the receipt file
// text and the --key argument that verifies it.
func legacyReceipt(t *testing.T, mutate func(members map[string]any)) ([]byte, string) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
	members := map[string]any{
		"receipt_id":    "rcpt-legacy-1",
		"decision_id":   "dec-legacy-1",
		"effect_id":     "eff-legacy-1",
		"status":        "EXECUTED",
		"output_hash":   "sha256:out-legacy-1",
		"prev_hash":     "",
		"lamport_clock": 1,
		"args_hash":     "sha256:args-legacy-1",
		"verdict":       "ALLOW",
		"tool_name":     "fs.write",
		"timestamp":     "2026-03-01T10:00:00Z",
		"key_id":        "legacy-key",
	}
	preimage := fmt.Sprintf("%s:%s:%s:%s:%s:%s:%d:%s", members["receipt_id"], members["decision_id"], members["effect_id"],
		members["status"], members["output_hash"], members["prev_hash"], members["lamport_clock"], members["args_hash"])
	members["signature"] = hex.EncodeToString(ed25519.Sign(key, []byte(preimage)))
	if mutate != nil {
		mutate(members)
	}
	raw, err := json.Marshal(members)
	if err != nil {
		t.Fatal(err)
	}
	return raw, "legacy-key=" + hex.EncodeToString(key.Public().(ed25519.PublicKey))
}

// TestLegacyReceiptIsNotCheckedByDefault: a genuine legacy receipt is not
// VERIFIED and not failed without the opt-in. It was not checked, which is
// exit 2 like every other input this command reports no verdict for.
func TestLegacyReceiptIsNotCheckedByDefault(t *testing.T) {
	raw, key := legacyReceipt(t, nil)
	for _, shape := range wrapReceiptShapes(t, raw) {
		t.Run(shape.name, func(t *testing.T) {
			code, stdout, stderr := execute(t, "--receipt", writeFile(t, "legacy.json", shape.raw), "--key", key)
			requireLegacyRefusal(t, code, stdout, stderr)
		})
	}
}

// TestAllowLegacyV4ChecksALegacyReceiptAndSaysSo: with --allow-legacy-v4 a
// legacy receipt is checked as before, and both output forms say that it is
// legacy and that its signature does not cover verdict, tool_name or
// timestamp. The second case is why they must: a file whose verdict, tool_name
// and timestamp were rewritten after signing still exits 0 under the opt-in.
func TestAllowLegacyV4ChecksALegacyReceiptAndSaysSo(t *testing.T) {
	signed, key := legacyReceipt(t, nil)
	rewritten, _ := legacyReceipt(t, func(members map[string]any) {
		members["verdict"], members["tool_name"], members["timestamp"] = "DENY", "payments.transfer", "2031-01-01T00:00:00Z"
	})
	for name, raw := range map[string][]byte{"as signed": signed, "unsigned members rewritten": rewritten} {
		t.Run(name, func(t *testing.T) {
			path := writeFile(t, "legacy.json", raw)
			code, stdout, stderr := execute(t, "--receipt", path, "--key", key, "--allow-legacy-v4")
			if code != 0 {
				t.Fatalf("an opted-in legacy receipt: exit %d, want 0\nstdout: %s\nstderr: %s", code, stdout, stderr)
			}
			for _, want := range []string{"VERIFIED — 1 receipt(s)", "1 LEGACY receipt(s)", "no signature_version", "--allow-legacy-v4",
				"does not cover verdict, tool_name or timestamp"} {
				if !strings.Contains(stdout, want) {
					t.Fatalf("the opted-in verdict must say plainly that the receipt is legacy and what is not covered (missing %q):\n%s", want, stdout)
				}
			}

			code, stdout, stderr = execute(t, "--receipt", path, "--key", key, "--allow-legacy-v4", "--json")
			if code != 0 {
				t.Fatalf("an opted-in legacy receipt with --json: exit %d, want 0\nstdout: %s\nstderr: %s", code, stdout, stderr)
			}
			var report struct {
				Valid           bool   `json:"valid"`
				LegacyReceipts  int    `json:"legacy_receipts"`
				PreimageVersion string `json:"preimage_version"`
				Checks          []struct {
					Name, Status, Detail string
				} `json:"checks"`
			}
			if err := json.Unmarshal([]byte(stdout), &report); err != nil {
				t.Fatalf("--json did not emit parseable JSON: %v\n%s", err, stdout)
			}
			if !report.Valid || report.LegacyReceipts != 1 || report.PreimageVersion != "v4-fields" {
				t.Fatalf("the JSON verdict must count the legacy receipt: %s", stdout)
			}
			named := false
			for _, check := range report.Checks {
				if check.Name == "identity" {
					named = strings.Contains(check.Detail, "legacy") && strings.Contains(check.Detail, "does not cover verdict, tool_name, timestamp")
				}
			}
			if !named {
				t.Fatalf("the JSON identity check must say what a legacy signature does not cover: %s", stdout)
			}
		})
	}

	// A member the legacy signature does cover still fails under the opt-in.
	tampered, _ := legacyReceipt(t, func(members map[string]any) { members["status"] = "DENIED" })
	if code, stdout, _ := execute(t, "--receipt", writeFile(t, "tampered.json", tampered), "--key", key, "--allow-legacy-v4"); code != 1 ||
		!strings.Contains(stdout, "NOT VERIFIED") {
		t.Fatalf("a legacy receipt with a rewritten signed member under the opt-in: exit %d, want 1\n%s", code, stdout)
	}

	// The opt-in changes nothing for a receipt.v5 file: no legacy wording.
	fx := loadGatewayFixture(t)
	code, stdout, _ := execute(t, "--receipt", gatewayChainFixture, "--key", fx.KeyID+"="+fx.PublicKeyHex, "--allow-legacy-v4")
	if code != 0 || strings.Contains(stdout, "LEGACY") || strings.Contains(stdout, "legacy v4") {
		t.Fatalf("a receipt.v5 chain under --allow-legacy-v4: exit %d, and it must not be called legacy\n%s", code, stdout)
	}
}

// TestHelpStatesTheLegacyAndLetterCaseRules: the two refusals a user can run
// into are in --help, with the flag that lifts the one that can be lifted.
func TestHelpStatesTheLegacyAndLetterCaseRules(t *testing.T) {
	code, stdout, stderr := execute(t, "--help")
	if code != 2 || stdout != "" {
		t.Fatalf("--help: exit %d with stdout %q, want usage on stderr and exit 2", code, stdout)
	}
	for _, want := range []string{"-allow-legacy-v4", "signature_version", "legacy", "letter", "does not cover verdict, tool_name or timestamp"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("--help does not mention %q:\n%s", want, stderr)
		}
	}
}

// TestHumanVerdictDoesNotClaimTheWholeReceiptWasSigned: the closing lines of a
// VERIFIED report say what a signature covers. A receipt.v5 signature covers
// 13 members, not the receipt.
func TestHumanVerdictDoesNotClaimTheWholeReceiptWasSigned(t *testing.T) {
	fx := loadFixture(t, chainFixture)
	code, stdout, _ := execute(t, "--receipt", chainFixture, "--key", fx.PublicKeyHex)
	if code != 0 {
		t.Fatalf("exit %d, want 0\n%s", code, stdout)
	}
	for _, overclaim := range []string{"bytes on disk", "These receipts were signed", "[+] integrity"} {
		if strings.Contains(stdout, overclaim) {
			t.Fatalf("the report still claims %q:\n%s", overclaim, stdout)
		}
	}
	for _, want := range []string{"[-] integrity", "compared with nothing", "not the whole receipt"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("the report must say what was and was not covered (missing %q):\n%s", want, stdout)
		}
	}
}

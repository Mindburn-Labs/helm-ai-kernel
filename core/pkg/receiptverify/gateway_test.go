// quantum_posture: these tests verify classical Ed25519 gateway receipts and
// recompute SHA-256 output hashes; no post-quantum claim.
package receiptverify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// frozenGatewayChain is a three-receipt gateway chain of one workspace (an
// escalation, a denial, the approved re-admission) signed by the gateway's
// own receipt builder with a fixed seed. Its generator is
// core/pkg/gateway/admission's TestFrozenGatewayChainIsWhatTheBuilderSigns;
// nothing here regenerates it.
func frozenGatewayChain(t *testing.T) ([]byte, Bundle, TrustRoot) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "frozen-gateway-chain.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Receipts) != 3 || len(b.GatewayBindings) != 3 || b.PublicKeyHex == "" || b.KeyID == "" {
		t.Fatalf("frozen gateway chain: %d receipts, %d bindings, key %q", len(b.Receipts), len(b.GatewayBindings), b.KeyID)
	}
	return raw, b, TrustRoot{Keys: map[string]string{b.KeyID: b.PublicKeyHex}}
}

func checkNamed(t *testing.T, res Result, name CheckName) Check {
	t.Helper()
	for _, c := range res.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %s check in %+v", name, res.Checks)
	return Check{}
}

// TestFrozenGatewayChainStillVerifies pins gateway receipt.v5 receipts and
// their helm.gateway.receipt-binding.v1 documents (helm-tracker#53): the
// committed signatures verify, the chain closes, and every output_hash is the
// SHA-256 of its supplied binding.
func TestFrozenGatewayChainStillVerifies(t *testing.T) {
	_, b, trust := frozenGatewayChain(t)
	res := VerifyBundle(b, trust)
	if !res.Valid || res.PreimageVersion != contracts.ReceiptSignatureV5 || res.Bindings != 3 {
		t.Fatalf("the frozen gateway chain no longer verifies: %+v", res)
	}
	for _, name := range []CheckName{CheckIdentity, CheckIntegrity, CheckPolicy, CheckExecution, CheckClosure, CheckBinding} {
		if c := checkNamed(t, res, name); c.Status != StatusPass {
			t.Errorf("%s = %s: %s", name, c.Status, c.Detail)
		}
	}
	for i, r := range b.Receipts {
		if !strings.HasPrefix(r.SessionID, "helm-gateway:") || r.LamportClock != uint64(i+1) {
			t.Fatalf("receipt[%d] is not a gateway chain receipt: %+v", i, r)
		}
	}
}

// Without bindings the binding check is not applicable, which is never a
// pass; the rest of the chain still verifies.
func TestGatewayBindingCheckIsNotApplicableWithoutBindings(t *testing.T) {
	_, b, trust := frozenGatewayChain(t)
	b.GatewayBindings = nil
	res := VerifyBundle(b, trust)
	if c := checkNamed(t, res, CheckBinding); c.Status != StatusNotApplicable {
		t.Fatalf("binding check without bindings = %+v", c)
	}
	if !res.Valid || res.Bindings != 0 {
		t.Fatalf("result = %+v", res)
	}

	// A partial set is checked and says what it did not check.
	_, b, _ = frozenGatewayChain(t)
	delete(b.GatewayBindings, b.Receipts[1].ReceiptID)
	res = VerifyBundle(b, trust)
	if c := checkNamed(t, res, CheckBinding); c.Status != StatusPass || !strings.Contains(c.Detail, "1 receipt(s) carry no binding") {
		t.Fatalf("partial bindings = %+v", c)
	}
}

func TestTamperedGatewayBindingFails(t *testing.T) {
	_, original, trust := frozenGatewayChain(t)
	first, second := original.Receipts[0].ReceiptID, original.Receipts[1].ReceiptID
	cases := map[string]func(b *Bundle){
		"changed byte": func(b *Bundle) {
			binding := bytes.Clone(b.GatewayBindings[first])
			binding = bytes.Replace(binding, []byte(`"state":"ESCALATED"`), []byte(`"state":"ADMITTED"`), 1)
			b.GatewayBindings[first] = binding
		},
		"a member no receipt field restates": func(b *Bundle) {
			binding := bytes.Clone(b.GatewayBindings[first])
			changed := bytes.Replace(binding, []byte(`"risk_class":"high"`), []byte(`"risk_class":"low"`), 1)
			if bytes.Equal(changed, binding) {
				panic("the frozen binding has no risk_class to change")
			}
			b.GatewayBindings[first] = changed
		},
		"another receipt's binding": func(b *Bundle) {
			b.GatewayBindings[first] = b.GatewayBindings[second]
		},
		"binding for an unknown receipt": func(b *Bundle) {
			b.GatewayBindings["0190a5b4-0000-7000-8000-0000000000ff"] = b.GatewayBindings[first]
		},
		"empty binding": func(b *Bundle) {
			b.GatewayBindings[first] = nil
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			_, b, _ := frozenGatewayChain(t)
			mutate(&b)
			res := VerifyBundle(b, trust)
			if c := checkNamed(t, res, CheckBinding); c.Status != StatusFail || res.Valid {
				t.Fatalf("a tampered binding was accepted: %+v", res)
			}
		})
	}
}

// A gap in an exported range fails closure whether or not the missing
// receipt's binding travels with the rest.
func TestGatewayChainGapFails(t *testing.T) {
	_, b, trust := frozenGatewayChain(t)
	missing := b.Receipts[1].ReceiptID
	b.Receipts = []*contracts.Receipt{b.Receipts[0], b.Receipts[2]}
	res := VerifyBundle(b, trust)
	if checkNamed(t, res, CheckClosure).Status != StatusFail || checkNamed(t, res, CheckBinding).Status != StatusFail || res.Valid {
		t.Fatalf("a chain with a gap verified: %+v", res)
	}
	delete(b.GatewayBindings, missing)
	res = VerifyBundle(b, trust)
	if checkNamed(t, res, CheckClosure).Status != StatusFail || checkNamed(t, res, CheckBinding).Status != StatusPass || res.Valid {
		t.Fatalf("a chain with a gap verified once its binding was dropped: %+v", res)
	}
}

// A binding can only describe the receipt that signed it: a receipt whose
// signed fields disagree with its binding fails even when the binding's hash
// is the receipt's output_hash and the signature is good.
func TestGatewayBindingMustAgreeWithTheSignedReceipt(t *testing.T) {
	_, frozen, _ := frozenGatewayChain(t)
	signer, err := crypto.NewEd25519SignerFromSeed(bytes.Repeat([]byte{0x33}, 32), "binding-test")
	if err != nil {
		t.Fatal(err)
	}
	trust := TrustRoot{Keys: map[string]string{signer.GetKeyID(): signer.PublicKey()}}
	base := frozen.Receipts[0]
	binding := frozen.GatewayBindings[base.ReceiptID]
	parsed, err := ParseGatewayBinding(binding)
	if err != nil {
		t.Fatal(err)
	}
	resign := func(t *testing.T, mutate func(r *contracts.Receipt, b *GatewayBinding)) Bundle {
		t.Helper()
		b := parsed
		r := *base
		r.Signature, r.SignatureProfile, r.SignatureAlgorithm, r.KeyID, r.PublicKeySet = "", "", "", "", nil
		mutate(&r, &b)
		raw, err := canonicalize.InteroperableJCS(b)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		r.OutputHash = hex.EncodeToString(sum[:])
		if err := signer.SignReceipt(&r); err != nil {
			t.Fatal(err)
		}
		return Bundle{Receipts: []*contracts.Receipt{&r}, GatewayBindings: map[string][]byte{r.ReceiptID: raw}}
	}
	// Known good: re-signed unchanged, the receipt and binding agree.
	if res := VerifyBundle(resign(t, func(*contracts.Receipt, *GatewayBinding) {}), trust); !res.Valid {
		t.Fatalf("re-signed frozen receipt does not verify: %+v", res)
	}
	for name, mutate := range map[string]func(r *contracts.Receipt, b *GatewayBinding){
		"tenant":    func(_ *contracts.Receipt, b *GatewayBinding) { b.TenantID = "tenant-b" },
		"workspace": func(_ *contracts.Receipt, b *GatewayBinding) { b.WorkspaceID = "ws-b" },
		"chain id":  func(r *contracts.Receipt, b *GatewayBinding) { r.SessionID = GatewayChainID("tenant-b", "ws-a") },
		"framing": func(r *contracts.Receipt, b *GatewayBinding) {
			b.ChainID, r.SessionID = "helm-gateway:tenant-a:ws-a", "helm-gateway:tenant-a:ws-a"
		},
		"sequence":    func(r *contracts.Receipt, _ *GatewayBinding) { r.LamportClock++ },
		"attempt":     func(_ *contracts.Receipt, b *GatewayBinding) { b.AttemptID = "0190a5b4-0000-7000-8000-000000000009" },
		"version":     func(_ *contracts.Receipt, b *GatewayBinding) { b.AttemptVersion = 3 },
		"effect id":   func(r *contracts.Receipt, _ *GatewayBinding) { r.EffectID = "other" },
		"state":       func(_ *contracts.Receipt, b *GatewayBinding) { b.State = "ADMITTED" },
		"verdict":     func(r *contracts.Receipt, _ *GatewayBinding) { r.Verdict = "ALLOW" },
		"reason code": func(_ *contracts.Receipt, b *GatewayBinding) { b.ReasonCode = "" },
		"policy hash": func(_ *contracts.Receipt, b *GatewayBinding) { b.PolicyHash = strings.Repeat("0", 64) },
		"args hash":   func(r *contracts.Receipt, _ *GatewayBinding) { r.ArgsHash = strings.Repeat("0", 64) },
		"no version":  func(_ *contracts.Receipt, b *GatewayBinding) { b.AttemptVersion = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			res := VerifyBundle(resign(t, mutate), trust)
			if c := checkNamed(t, res, CheckBinding); c.Status != StatusFail || res.Valid {
				t.Fatalf("a binding that disagrees with its receipt passed: %+v", res)
			}
			if checkNamed(t, res, CheckIdentity).Status != StatusPass {
				t.Fatal("the planted receipt is not validly signed; the case proves nothing")
			}
		})
	}
}

func TestParseGatewayBindingIsClosedAndCanonical(t *testing.T) {
	_, b, _ := frozenGatewayChain(t)
	good := b.GatewayBindings[b.Receipts[0].ReceiptID]
	if _, err := ParseGatewayBinding(good); err != nil {
		t.Fatalf("frozen binding refused: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(good, &document); err != nil {
		t.Fatal(err)
	}
	encode := func(mutate func(map[string]any)) []byte {
		clone := map[string]any{}
		for k, v := range document {
			clone[k] = v
		}
		mutate(clone)
		raw, err := canonicalize.JCS(clone)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for name, raw := range map[string][]byte{
		"extra member":       encode(func(m map[string]any) { m["grant"] = "all" }),
		"missing member":     encode(func(m map[string]any) { delete(m, "permit_id") }),
		"null quote":         encode(func(m map[string]any) { m["quote"] = nil }),
		"null versions":      encode(func(m map[string]any) { m["authority_versions"] = nil }),
		"other version":      encode(func(m map[string]any) { m["binding_version"] = "helm.gateway.receipt-binding.v2" }),
		"string sequence":    encode(func(m map[string]any) { m["seq"] = "1" }),
		"not canonical":      append([]byte(" "), good...),
		"reordered members":  bytes.Replace(good, []byte(`{"approval_digest"`), []byte(`{"zz":1,"approval_digest"`), 1),
		"duplicate member":   bytes.Replace(good, []byte(`{"approval_digest":`), []byte(`{"approval_digest":"","approval_digest":`), 1),
		"trailing value":     append(bytes.Clone(good), []byte(` {}`)...),
		"escaped equivalent": bytes.Replace(good, []byte(`"state":"ESCALATED"`), []byte(`"state":"ESCALATE`+"\\"+`u0044"`), 1),
	} {
		if _, err := ParseGatewayBinding(raw); err == nil {
			t.Errorf("%s: accepted %s", name, raw)
		}
	}
}

func TestGatewayChainIDFramesTenantAndWorkspace(t *testing.T) {
	if got := GatewayChainID("tenant-a", "ws-a"); got != "helm-gateway:8:tenant-a:4:ws-a" {
		t.Fatalf("chain id = %q", got)
	}
	if GatewayChainID("a:1:b", "c") == GatewayChainID("a", "b:1:c") {
		t.Fatal("two (tenant, workspace) pairs share a chain id")
	}
}

// EncodeGatewayBundle writes the document receipt_verify reads, keeping each
// envelope's exact bytes, and refuses a bundle it cannot vouch for.
func TestEncodeGatewayBundleRoundTrips(t *testing.T) {
	_, frozen, trust := frozenGatewayChain(t)
	var stored []GatewayReceipt
	for _, r := range frozen.Receipts {
		envelope, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		stored = append(stored, GatewayReceipt{ReceiptID: r.ReceiptID, Envelope: envelope, Binding: frozen.GatewayBindings[r.ReceiptID]})
	}
	doc, err := EncodeGatewayBundle(stored)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range stored {
		if !bytes.Contains(doc, s.Envelope) {
			t.Fatalf("the bundle does not hold receipt %s's exact bytes", s.ReceiptID)
		}
	}
	parsed, err := ParseBundle(doc)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.KeyID != frozen.KeyID || parsed.PublicKeyHex != "" {
		t.Fatalf("bundle key_id %q, public_key_hex %q", parsed.KeyID, parsed.PublicKeyHex)
	}
	if res := VerifyBundle(parsed, trust); !res.Valid || res.Bindings != 3 {
		t.Fatalf("encoded bundle does not verify: %+v", res)
	}
	if got := VerifyJSON(doc, []byte(`{"keys":{"`+frozen.KeyID+`":"`+frozen.PublicKeyHex+`"}}`)); got.Verdict != VerdictVerified {
		t.Fatalf("VerifyJSON = %+v", got)
	}

	for name, bad := range map[string][]GatewayReceipt{
		"empty":        nil,
		"no binding":   {{ReceiptID: stored[0].ReceiptID, Envelope: stored[0].Envelope}},
		"wrong id":     {{ReceiptID: stored[1].ReceiptID, Envelope: stored[0].Envelope, Binding: stored[0].Binding}},
		"duplicate":    {stored[0], stored[0]},
		"not receipt":  {{ReceiptID: "x", Envelope: []byte(`{"a":1`), Binding: []byte("{}")}},
		"two receipts": {{ReceiptID: stored[0].ReceiptID, Envelope: []byte("[" + string(stored[0].Envelope) + "," + string(stored[1].Envelope) + "]"), Binding: stored[0].Binding}},
	} {
		if _, err := EncodeGatewayBundle(bad); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
}

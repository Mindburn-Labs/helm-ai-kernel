// quantum_posture: these tests verify classical Ed25519 gateway receipts and
// recompute SHA-256 output hashes; no post-quantum claim.
package receiptverify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	if len(b.Receipts) != 4 || len(b.GatewayBindings) != 4 || b.PublicKeyHex == "" || b.KeyID == "" {
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
	if !res.Valid || res.PreimageVersion != contracts.ReceiptSignatureV5 || res.BindingsChecked != 4 || res.GatewayReceipts != 4 {
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
	if !res.Valid || res.BindingsChecked != 0 || res.GatewayReceipts != 4 {
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
	b.Receipts = []*contracts.Receipt{b.Receipts[0], b.Receipts[2], b.Receipts[3]}
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

// gatewayResigner re-signs the frozen chain's first receipt, with whatever
// binding bytes and receipt fields a case plants, under a test key: the
// binding's hash is always the signed output_hash, so only the field checks
// can refuse what it says.
type gatewayResigner struct {
	t      *testing.T
	signer *crypto.Ed25519Signer
	base   *contracts.Receipt
	parsed GatewayBinding
}

func newGatewayResigner(t *testing.T) gatewayResigner {
	t.Helper()
	_, frozen, _ := frozenGatewayChain(t)
	signer, err := crypto.NewEd25519SignerFromSeed(bytes.Repeat([]byte{0x33}, 32), "binding-test")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseGatewayBinding(frozen.GatewayBindings[frozen.Receipts[0].ReceiptID])
	if err != nil {
		t.Fatal(err)
	}
	return gatewayResigner{t: t, signer: signer, base: frozen.Receipts[0], parsed: parsed}
}

func (g gatewayResigner) trust() TrustRoot {
	return TrustRoot{Keys: map[string]string{g.signer.GetKeyID(): g.signer.PublicKey()}}
}

func (g gatewayResigner) raw(binding []byte, mutate func(r *contracts.Receipt)) Bundle {
	g.t.Helper()
	r := *g.base
	mutate(&r)
	r.Signature, r.SignatureProfile, r.SignatureAlgorithm, r.KeyID, r.PublicKeySet = "", "", "", "", nil
	sum := sha256.Sum256(binding)
	r.OutputHash = hex.EncodeToString(sum[:])
	if err := g.signer.SignReceipt(&r); err != nil {
		g.t.Fatal(err)
	}
	return Bundle{Receipts: []*contracts.Receipt{&r}, GatewayBindings: map[string][]byte{r.ReceiptID: binding}}
}

func (g gatewayResigner) bundle(mutate func(r *contracts.Receipt, b *GatewayBinding)) Bundle {
	g.t.Helper()
	b, planted := g.parsed, *g.base
	mutate(&planted, &b)
	raw, err := canonicalize.InteroperableJCS(b)
	if err != nil {
		g.t.Fatal(err)
	}
	return g.raw(raw, func(r *contracts.Receipt) { *r = planted })
}

// A binding can only describe the receipt that signed it: a receipt whose
// signed fields disagree with its binding fails even when the binding's hash
// is the receipt's output_hash and the signature is good. Each case names the
// row that must refuse it.
func TestGatewayBindingMustAgreeWithTheSignedReceipt(t *testing.T) {
	g := newGatewayResigner(t)
	// Known good: re-signed unchanged, the receipt and binding agree.
	if res := VerifyBundle(g.bundle(func(*contracts.Receipt, *GatewayBinding) {}), g.trust()); !res.Valid || res.BindingsChecked != 1 {
		t.Fatalf("re-signed frozen receipt does not verify: %+v", res)
	}
	attempt := g.parsed.AttemptID
	for name, test := range map[string]struct {
		mutate func(r *contracts.Receipt, b *GatewayBinding)
		want   string
	}{
		"tenant":    {func(_ *contracts.Receipt, b *GatewayBinding) { b.TenantID = "tenant-b" }, "chain_id framing"},
		"workspace": {func(_ *contracts.Receipt, b *GatewayBinding) { b.WorkspaceID = "ws-b" }, "chain_id framing"},
		"chain id":  {func(r *contracts.Receipt, b *GatewayBinding) { r.SessionID = GatewayChainID("tenant-b", "ws-a") }, "session_id"},
		"framing": {func(r *contracts.Receipt, b *GatewayBinding) {
			b.ChainID, r.SessionID = "helm-gateway:tenant-a:ws-a", "helm-gateway:tenant-a:ws-a"
		}, "chain_id framing"},
		"sequence":    {func(r *contracts.Receipt, _ *GatewayBinding) { r.LamportClock++ }, "lamport_clock"},
		"attempt":     {func(_ *contracts.Receipt, b *GatewayBinding) { b.AttemptID = "0190a5b4-0000-7000-8000-000000000009" }, "decision_id"},
		"version":     {func(_ *contracts.Receipt, b *GatewayBinding) { b.AttemptVersion = 3 }, "decision_id"},
		"effect id":   {func(r *contracts.Receipt, _ *GatewayBinding) { r.EffectID = "other" }, "effect_id"},
		"state":       {func(_ *contracts.Receipt, b *GatewayBinding) { b.State = "ADMITTED" }, "status"},
		"verdict":     {func(r *contracts.Receipt, _ *GatewayBinding) { r.Verdict = "ALLOW" }, "verdict"},
		"reason code": {func(_ *contracts.Receipt, b *GatewayBinding) { b.ReasonCode = "" }, "reason_code"},
		"policy hash": {func(_ *contracts.Receipt, b *GatewayBinding) { b.PolicyHash = strings.Repeat("0", 64) }, "policy_hash"},
		"args hash":   {func(r *contracts.Receipt, _ *GatewayBinding) { r.ArgsHash = strings.Repeat("0", 64) }, "args_hash"},
		// The receipt.v5 timestamp is outside the signed preimage; its row
		// against the signed decided_at is what binds it.
		"timestamp":         {func(r *contracts.Receipt, _ *GatewayBinding) { r.Timestamp = r.Timestamp.Add(time.Microsecond) }, "timestamp"},
		"timestamp missing": {func(r *contracts.Receipt, _ *GatewayBinding) { r.Timestamp = time.Time{} }, "timestamp"},
		// The guard: a binding that names no tenant, attempt, version or
		// sequence is refused even when every row would agree with it.
		"no tenant": {func(r *contracts.Receipt, b *GatewayBinding) {
			b.TenantID, b.ChainID = "", GatewayChainID("", b.WorkspaceID)
			r.SessionID = b.ChainID
		}, "names no tenant"},
		"no workspace": {func(r *contracts.Receipt, b *GatewayBinding) {
			b.WorkspaceID, b.ChainID = "", GatewayChainID(b.TenantID, "")
			r.SessionID = b.ChainID
		}, "names no tenant"},
		"no attempt": {func(r *contracts.Receipt, b *GatewayBinding) {
			b.AttemptID, r.EffectID, r.DecisionID = "", "", ":2"
		}, "names no tenant"},
		"no version": {func(r *contracts.Receipt, b *GatewayBinding) {
			b.AttemptVersion, r.DecisionID = 0, attempt+":0"
		}, "names no tenant"},
		"no sequence": {func(r *contracts.Receipt, b *GatewayBinding) { b.Seq, r.LamportClock = 0, 0 }, "names no tenant"},
	} {
		t.Run(name, func(t *testing.T) {
			res := VerifyBundle(g.bundle(test.mutate), g.trust())
			c := checkNamed(t, res, CheckBinding)
			if c.Status != StatusFail || res.Valid || !strings.Contains(c.Detail, test.want) || res.BindingsChecked != 0 {
				t.Fatalf("binding check = %+v, want a failure naming %q", c, test.want)
			}
			if checkNamed(t, res, CheckIdentity).Status != StatusPass {
				t.Fatal("the planted receipt is not validly signed; the case proves nothing")
			}
		})
	}

	// A binding_version the verifier does not know, or none, is refused,
	// never read as another version.
	var document map[string]any
	frozen := g.parsed
	encoded, err := canonicalize.InteroperableJCS(frozen)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"unknown version": func(m map[string]any) { m["binding_version"] = "helm.gateway.receipt-binding.v9" },
		"no version":      func(m map[string]any) { delete(m, "binding_version") },
		"numeric version": func(m map[string]any) { m["binding_version"] = 1 },
	} {
		clone := map[string]any{}
		for k, v := range document {
			clone[k] = v
		}
		mutate(clone)
		raw, err := canonicalize.JCS(clone)
		if err != nil {
			t.Fatal(err)
		}
		res := VerifyBundle(g.raw(raw, func(*contracts.Receipt) {}), g.trust())
		if c := checkNamed(t, res, CheckBinding); c.Status != StatusFail || res.Valid {
			t.Errorf("%s: binding check = %+v", name, c)
		}
	}
}

// A binding is checked only against a receipt.v5 signature: the legacy
// preimage does not cover session_id, verdict, reason_code or policy_hash, so
// those rows would compare unsigned fields.
func TestABindingNeedsAReceiptV5Signature(t *testing.T) {
	g := newGatewayResigner(t)
	_, frozen, _ := frozenGatewayChain(t)
	binding := frozen.GatewayBindings[g.base.ReceiptID]
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
	r := *g.base
	r.SignatureVersion, r.SignatureProfile, r.SignatureAlgorithm, r.PublicKeySet, r.KeyID = "", "", "", nil, "legacy-key"
	r.Signature = hex.EncodeToString(ed25519.Sign(key, canonicalizeV4(&r)))
	trust := TrustRoot{Keys: map[string]string{"legacy-key": hex.EncodeToString(key.Public().(ed25519.PublicKey))}}
	res := VerifyBundle(Bundle{Receipts: []*contracts.Receipt{&r}, GatewayBindings: map[string][]byte{r.ReceiptID: binding}}, trust)
	if checkNamed(t, res, CheckIdentity).Status != StatusPass || res.PreimageVersion != "v4-fields" {
		t.Fatalf("the planted v4 receipt does not verify as v4; the case proves nothing: %+v", res)
	}
	if c := checkNamed(t, res, CheckBinding); c.Status != StatusFail || res.Valid || !strings.Contains(c.Detail, "receipt.v5") {
		t.Fatalf("a v4 receipt's binding was checked: %+v", c)
	}
}

// Two receipts with one receipt id cannot have a binding placed on either:
// the check fails, and does not index out of range.
func TestDuplicateReceiptIDCannotPlaceABinding(t *testing.T) {
	_, b, trust := frozenGatewayChain(t)
	id := b.Receipts[0].ReceiptID
	b.Receipts = append(b.Receipts, b.Receipts[0])
	res := VerifyBundle(b, trust)
	if c := checkNamed(t, res, CheckBinding); c.Status != StatusFail || res.Valid || !strings.Contains(c.Detail, "more than one receipt") {
		t.Fatalf("binding check with a duplicated receipt id = %+v", c)
	}
	// Bound only on another receipt, the duplicate id is not placed at all.
	delete(b.GatewayBindings, id)
	res = VerifyBundle(b, trust)
	if c := checkNamed(t, res, CheckBinding); c.Status != StatusPass {
		t.Fatalf("binding check without a binding on the duplicate = %+v", c)
	}
}

// RequireGatewayBindings makes a pass cover every gateway receipt's gateway
// facts: a gateway receipt with no binding fails it, and the counts say what
// was covered either way.
func TestRequireGatewayBindings(t *testing.T) {
	require := Options{RequireGatewayBindings: true}
	_, b, trust := frozenGatewayChain(t)
	if res := VerifyBundleWith(b, trust, require); !res.Valid || res.GatewayReceipts != 4 || res.BindingsChecked != 4 {
		t.Fatalf("every binding supplied: %+v", res)
	}
	delete(b.GatewayBindings, b.Receipts[1].ReceiptID)
	if res := VerifyBundle(b, trust); !res.Valid || res.GatewayReceipts != 4 || res.BindingsChecked != 3 {
		t.Fatalf("one binding missing, not required: %+v", res)
	}
	res := VerifyBundleWith(b, trust, require)
	if c := checkNamed(t, res, CheckBinding); c.Status != StatusFail || res.Valid || res.BindingsChecked != 0 {
		t.Fatalf("one binding missing, required: %+v", res)
	}
	b.GatewayBindings = nil
	if res := VerifyBundleWith(b, trust, require); checkNamed(t, res, CheckBinding).Status != StatusFail || res.Valid {
		t.Fatalf("no binding, required: %+v", res)
	}
	// A chain with no gateway receipt has nothing to require.
	fx := loadFrozen(t)
	res = VerifyBundleWith(Bundle{Receipts: fx.Receipts}, fx.trust(), require)
	if !res.Valid || res.GatewayReceipts != 0 || checkNamed(t, res, CheckBinding).Status != StatusNotApplicable {
		t.Fatalf("a non-gateway chain under RequireGatewayBindings: %+v", res)
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

// outcomeResigner re-signs the frozen chain's outcome receipt (seq 4) with a
// planted outcome binding, under a test key.
func outcomeResigner(t *testing.T) (gatewayResigner, GatewayOutcomeBinding) {
	t.Helper()
	g := newGatewayResigner(t)
	_, frozen, _ := frozenGatewayChain(t)
	g.base = frozen.Receipts[3]
	parsed, err := ParseGatewayOutcomeBinding(frozen.GatewayBindings[g.base.ReceiptID])
	if err != nil {
		t.Fatal(err)
	}
	return g, parsed
}

// An outcome receipt is checked under helm.gateway.outcome-binding.v1's own
// table: an outcome state as status, no verdict, the attempt, version and
// session framing as for decisions, and the settlement time as timestamp.
func TestGatewayOutcomeBindingMustAgreeWithTheSignedReceipt(t *testing.T) {
	g, parsed := outcomeResigner(t)
	planted := func(mutate func(r *contracts.Receipt, b *GatewayOutcomeBinding)) Bundle {
		t.Helper()
		b, r := parsed, *g.base
		mutate(&r, &b)
		raw, err := canonicalize.InteroperableJCS(b)
		if err != nil {
			t.Fatal(err)
		}
		return g.raw(raw, func(p *contracts.Receipt) { *p = r })
	}
	if res := VerifyBundle(planted(func(*contracts.Receipt, *GatewayOutcomeBinding) {}), g.trust()); !res.Valid || res.BindingsChecked != 1 {
		t.Fatalf("re-signed frozen outcome receipt does not verify: %+v", res)
	}
	for name, test := range map[string]struct {
		mutate func(r *contracts.Receipt, b *GatewayOutcomeBinding)
		want   string
	}{
		"a verdict":        {func(r *contracts.Receipt, _ *GatewayOutcomeBinding) { r.Verdict = "ALLOW" }, "verdict"},
		"status":           {func(r *contracts.Receipt, _ *GatewayOutcomeBinding) { r.Status = "RECONCILED" }, "status"},
		"a decision state": {func(r *contracts.Receipt, b *GatewayOutcomeBinding) { r.Status, b.State = "ADMITTED", "ADMITTED" }, "not an outcome state"},
		"version":          {func(_ *contracts.Receipt, b *GatewayOutcomeBinding) { b.AttemptVersion = 8 }, "decision_id"},
		"attempt":          {func(r *contracts.Receipt, _ *GatewayOutcomeBinding) { r.EffectID = "other" }, "effect_id"},
		"workspace":        {func(_ *contracts.Receipt, b *GatewayOutcomeBinding) { b.WorkspaceID = "ws-b" }, "chain_id framing"},
		"session":          {func(r *contracts.Receipt, _ *GatewayOutcomeBinding) { r.SessionID = GatewayChainID("tenant-a", "ws-b") }, "session_id"},
		"sequence":         {func(r *contracts.Receipt, _ *GatewayOutcomeBinding) { r.LamportClock = 9 }, "lamport_clock"},
		"reason code":      {func(_ *contracts.Receipt, b *GatewayOutcomeBinding) { b.ReasonCode = "PERMIT_EXPIRED" }, "reason_code"},
		"policy hash":      {func(r *contracts.Receipt, _ *GatewayOutcomeBinding) { r.PolicyHash = strings.Repeat("0", 64) }, "policy_hash"},
		"args hash":        {func(_ *contracts.Receipt, b *GatewayOutcomeBinding) { b.ArgumentDigest = strings.Repeat("0", 64) }, "args_hash"},
		"settlement time":  {func(r *contracts.Receipt, _ *GatewayOutcomeBinding) { r.Timestamp = r.Timestamp.Add(time.Microsecond) }, "timestamp"},
		"no permit":        {func(_ *contracts.Receipt, b *GatewayOutcomeBinding) { b.PermitID = "" }, "names no tenant"},
		"no sequence":      {func(r *contracts.Receipt, b *GatewayOutcomeBinding) { b.Seq, r.LamportClock = 0, 0 }, "names no tenant"},
		"no attempt version": {func(r *contracts.Receipt, b *GatewayOutcomeBinding) {
			b.AttemptVersion, r.DecisionID = 0, b.AttemptID+":0"
		}, "names no tenant"},
	} {
		t.Run(name, func(t *testing.T) {
			res := VerifyBundle(planted(test.mutate), g.trust())
			c := checkNamed(t, res, CheckBinding)
			if c.Status != StatusFail || res.Valid || !strings.Contains(c.Detail, test.want) {
				t.Fatalf("binding check = %+v, want a failure naming %q", c, test.want)
			}
			if checkNamed(t, res, CheckIdentity).Status != StatusPass {
				t.Fatal("the planted receipt is not validly signed; the case proves nothing")
			}
		})
	}
	// A decision binding is not an outcome's: the frozen decision binding on
	// the outcome receipt fails, whichever table reads it.
	_, frozen, _ := frozenGatewayChain(t)
	swapped := g.raw(frozen.GatewayBindings[frozen.Receipts[2].ReceiptID], func(*contracts.Receipt) {})
	if res := VerifyBundle(swapped, g.trust()); checkNamed(t, res, CheckBinding).Status != StatusFail || res.Valid {
		t.Fatalf("a decision binding passed for an outcome receipt: %+v", res)
	}
}

func TestParseGatewayOutcomeBindingIsClosedAndCanonical(t *testing.T) {
	_, parsed := outcomeResigner(t)
	good, err := canonicalize.InteroperableJCS(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseGatewayOutcomeBinding(good); err != nil {
		t.Fatalf("frozen outcome binding refused: %v", err)
	}
	// A model call's money row is an object in the same closed shape.
	model := parsed
	model.SettledBy = "model_call"
	model.ModelCall = &GatewayOutcomeModelCall{State: "CONFIRMED", CurrencyCode: "USD", HeldMicros: "900", EstimatedMicros: "", ConfirmedMicros: "640",
		BillableMicros: "640", UsageDigest: strings.Repeat("ab", 32)}
	withModel, err := canonicalize.InteroperableJCS(model)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ParseGatewayOutcomeBinding(withModel); err != nil || got.ModelCall == nil || got.ModelCall.ConfirmedMicros != "640" {
		t.Fatalf("model call binding = %+v, %v", got.ModelCall, err)
	}
	encode := func(mutate func(map[string]any)) []byte {
		var clone map[string]any // a fresh copy each time: mutations nest
		if err := json.Unmarshal(good, &clone); err != nil {
			t.Fatal(err)
		}
		mutate(clone)
		raw, err := canonicalize.JCS(clone)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for name, raw := range map[string][]byte{
		"extra member":       encode(func(m map[string]any) { m["verdict"] = "ALLOW" }),
		"missing member":     encode(func(m map[string]any) { delete(m, "settled_at") }),
		"missing model_call": encode(func(m map[string]any) { delete(m, "model_call") }),
		"null exposures":     encode(func(m map[string]any) { m["exposures"] = nil }),
		"null versions":      encode(func(m map[string]any) { m["authority_versions"] = nil }),
		"extra observation":  encode(func(m map[string]any) { m["observation"].(map[string]any)["grant"] = "all" }),
		"decision version":   encode(func(m map[string]any) { m["binding_version"] = GatewayBindingVersion }),
		"model call member":  bytes.Replace(withModel, []byte(`"held_micros":"900"`), []byte(`"grant":"all","held_micros":"900"`), 1),
		"no currency":        bytes.Replace(withModel, []byte(`"currency_code":"USD",`), nil, 1),
		"not canonical":      append([]byte(" "), good...),
		"numeric readback":   bytes.Replace(good, []byte(`"readback_absent":false`), []byte(`"readback_absent":0`), 1),
	} {
		if _, err := ParseGatewayOutcomeBinding(raw); err == nil {
			t.Errorf("%s: accepted %s", name, raw)
		}
	}
}

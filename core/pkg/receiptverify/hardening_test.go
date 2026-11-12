// quantum_posture: these tests exercise classical Ed25519 receipt
// verification only; they add no signature scheme and claim no hybrid or
// post-quantum protection.
package receiptverify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// signedDenial is a genuine receipt.v5 DENY receipt of a gateway chain: signed
// by the kernel's own signer and serialized the way the kernel writes it. It
// returns the wire bytes, the trust root that verifies them, and that trust
// root as VerifyJSON reads it.
func signedDenial(t *testing.T) ([]byte, TrustRoot, []byte) {
	t.Helper()
	signer, err := crypto.NewEd25519SignerFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize), "hardening-test-key")
	if err != nil {
		t.Fatal(err)
	}
	r := &contracts.Receipt{
		ReceiptID:    "0190a5b4-0000-7000-8000-0000000000d1",
		DecisionID:   "0190a5b4-0000-7000-8000-0000000000a1:1",
		EffectID:     "0190a5b4-0000-7000-8000-0000000000a1",
		Status:       "DENIED",
		Timestamp:    time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
		OutputHash:   strings.Repeat("ab", 32),
		ArgsHash:     strings.Repeat("cd", 32),
		LamportClock: 1,
		Verdict:      "DENY",
		ReasonCode:   "MANDATE_LIMIT_EXCEEDED",
		PolicyHash:   strings.Repeat("ef", 32),
		SessionID:    GatewayChainID("tenant-a", "ws-a"),
		ToolName:     "payments.transfer",
	}
	if err := signer.SignReceipt(r); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	trust := TrustRoot{Keys: map[string]string{signer.GetKeyID(): signer.PublicKey()}}
	trustJSON, err := json.Marshal(map[string]any{"keys": trust.Keys})
	if err != nil {
		t.Fatal(err)
	}
	// The starting point is genuine: it verifies as issued, as a DENY.
	bundle, err := ParseBundle(raw)
	if err != nil {
		t.Fatalf("the genuine receipt does not parse: %v", err)
	}
	if res := VerifyBundle(bundle, trust); !res.Valid || bundle.Receipts[0].Verdict != "DENY" {
		t.Fatalf("the genuine DENY receipt does not verify; the cases prove nothing: %+v", res)
	}
	if got := VerifyJSON(raw, trustJSON); got.Verdict != VerdictVerified {
		t.Fatalf("the genuine DENY receipt does not verify through VerifyJSON: %+v", got)
	}
	return raw, trust, trustJSON
}

// receiptShapes wraps one receipt object in the three shapes ParseBundle
// accepts.
func receiptShapes(receipt []byte) map[string][]byte {
	return map[string][]byte{
		"single": receipt,
		"array":  []byte("[" + string(receipt) + "]"),
		"bundle": []byte(`{"receipts":[` + string(receipt) + `]}`),
	}
}

func replaceOnce(t *testing.T, raw []byte, old, replacement string) []byte {
	t.Helper()
	if bytes.Count(raw, []byte(old)) != 1 {
		t.Fatalf("the document does not contain %s exactly once", old)
	}
	return bytes.Replace(raw, []byte(old), []byte(replacement), 1)
}

// appendMembers adds members to the end of a JSON object's text.
func appendMembers(object []byte, members string) []byte {
	object = bytes.TrimSpace(object)
	return []byte(string(object[:len(object)-1]) + "," + members + "}")
}

// ---------------------------------------------------------------------------
// Defect A: member names that differ only in letter case
// ---------------------------------------------------------------------------

// TestCaseVariantMembersCannotShadowSignedFields is helm-tracker#305 defect A.
//
// encoding/json binds an object member to a struct field when their names are
// equal under case folding, and the last such member wins. A genuine signed
// DENY receipt can therefore be edited so that its exactly-named members say
// EXECUTED / ALLOW while "Status" and "Verdict", further down, restore the
// signed values for the Go verifier alone. Every reader that matches names
// exactly (jq, the JavaScript host of the WASM verifier) then reads ALLOW from
// a document the verifier calls VERIFIED. No key is needed to build it.
func TestCaseVariantMembersCannotShadowSignedFields(t *testing.T) {
	raw, trust, trustJSON := signedDenial(t)

	shadowed := replaceOnce(t, raw, `"status":"DENIED"`, `"status":"EXECUTED"`)
	shadowed = replaceOnce(t, shadowed, `"verdict":"DENY"`, `"verdict":"ALLOW"`)
	shadowed = appendMembers(shadowed, `"Status":"DENIED","Verdict":"DENY"`)

	// What a reader that matches member names exactly takes from the document.
	var exact map[string]any
	if err := json.Unmarshal(shadowed, &exact); err != nil {
		t.Fatal(err)
	}
	if exact["verdict"] != "ALLOW" || exact["status"] != "EXECUTED" {
		t.Fatalf("the planted document does not read ALLOW by exact name; the case proves nothing: %v", exact)
	}

	for name, doc := range receiptShapes(shadowed) {
		t.Run(name, func(t *testing.T) {
			bundle, err := ParseBundle(doc)
			if err == nil {
				res := VerifyBundleWith(bundle, trust, Options{})
				t.Fatalf("a document whose exactly-named members say verdict ALLOW was parsed; "+
					"the verifier read verdict %q and reported valid=%v", bundle.Receipts[0].Verdict, res.Valid)
			}
			if !strings.Contains(err.Error(), "letter case") {
				t.Fatalf("the refusal must name the letter-case collision, got: %v", err)
			}
			got := VerifyJSON(doc, trustJSON)
			if got.Verdict != VerdictFailed || got.Verification.Valid {
				t.Fatalf("VerifyJSON (the WASM entry point's verifier) = %s, want FAILED: %+v", got.Verdict, got)
			}
		})
	}

	// The same pair in the other order: the exactly-named member is last, so
	// the Go decoder reads ALLOW too and the signature no longer verifies. It
	// is refused at parse all the same, not left to the signature check.
	reversed := replaceOnce(t, raw, `"verdict":"DENY"`, `"Verdict":"DENY","verdict":"ALLOW"`)
	if _, err := ParseBundle(reversed); err == nil || !strings.Contains(err.Error(), "letter case") {
		t.Fatalf("a case-variant member before its exactly-named twin was parsed: %v", err)
	}
}

// TestCaseVariantSpellingsOfKnownMembersAreRejected covers the member that is
// written once, in the wrong letter case. encoding/json would still bind it to
// the struct field, so the verifier would act on a value that no exact-name
// reader sees. The known names come from the json tags of the types this
// package decodes into; each case is a document the unchanged parser accepted.
func TestCaseVariantSpellingsOfKnownMembersAreRejected(t *testing.T) {
	raw, _, _ := signedDenial(t)
	permitFixture := loadFrozenPermit(t)
	permit, err := json.Marshal(permitFixture.Permits[0])
	if err != nil {
		t.Fatal(err)
	}
	bundle := func(receipt, extra string) []byte {
		return []byte(`{"receipts":[` + receipt + `]` + extra + `}`)
	}
	for name, tc := range map[string]struct {
		doc  []byte
		want string // the exactly-spelled member the refusal names
	}{
		"unsigned receipt member": {replaceOnce(t, raw, `"tool_name":`, `"Tool_Name":`), `"tool_name"`},
		// Routes around the receipt.v5 signed-member contract: the raw scan
		// sees no signature_version, the typed decode sees receipt.v5.
		"signature_version":  {replaceOnce(t, raw, `"signature_version":`, `"Signature_Version":`), `"signature_version"`},
		"upper case":         {replaceOnce(t, raw, `"timestamp":`, `"TIMESTAMP":`), `"timestamp"`},
		"kelvin sign":        {replaceOnce(t, raw, `"key_id":`, `"`+"K"+`ey_id":`), `"key_id"`},
		"long s":             {replaceOnce(t, raw, `"signature":`, `"`+"ſ"+`ignature":`), `"signature"`},
		"nested struct":      {appendMembers(raw, `"provenance":{"Generated_By":"x","generated_at":"2026-09-01T12:00:00Z","context":"c"}`), `"generated_by"`},
		"struct in an array": {appendMembers(raw, `"witness_signatures":[{"Witness_ID":"w","signature":"00"}]`), `"witness_id"`},
		"receipt in an array": {[]byte("[" + string(replaceOnce(t, raw, `"tool_name":`, `"TOOL_NAME":`)) + "]"),
			`"tool_name"`},
		"receipt in a bundle":   {bundle(string(replaceOnce(t, raw, `"tool_name":`, `"tool_Name":`)), ""), `"tool_name"`},
		"bundle member":         {bundle(string(raw), `,"Public_Key_Hex":"00"`), `"public_key_hex"`},
		"bundle permits member": {bundle(string(raw), `,"Permits":[`+string(permit)+`]`), `"permits"`},
		"permit member": {bundle(string(raw), `,"permits":[`+string(replaceOnce(t, permit, `"permit_id":`, `"Permit_ID":`))+`]`),
			`"permit_id"`},
		"permit scope member": {bundle(string(raw), `,"permits":[`+string(replaceOnce(t, permit, `"allowed_action":`, `"Allowed_Action":`))+`]`),
			`"allowed_action"`},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseBundle(tc.doc)
			if err == nil {
				t.Fatalf("a member spelled in the wrong letter case was accepted: %s", tc.doc)
			}
			if !strings.Contains(err.Error(), "letter case") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the refusal must name the letter case and the member %s, got: %v", tc.want, err)
			}
		})
	}

	// What is not a struct member name is data, and stays accepted: unknown
	// members, and the keys of maps and free-form values, which encoding/json
	// matches exactly.
	for name, doc := range map[string][]byte{
		"unknown member":        appendMembers(raw, `"X-Custom":"1","padding":[[{"Status":"x"}]]`),
		"metadata keys":         appendMembers(raw, `"metadata":{"Verdict":"x","Status":"y","receipt_id":"z"}`),
		"evidence keys":         appendMembers(raw, `"evidence":{"Signature":"x"}`),
		"free-form subject":     appendMembers(raw, `"subject":{"Verdict":"x","nested":{"Status":"y"}}`),
		"unknown bundle member": bundle(string(raw), `,"comment":"kept","Exported_By":"someone"`),
		"permit evidence keys":  bundle(string(raw), `,"permits":[`+string(replaceOnce(t, permit, `"reviewed_spec_hash":`, `"Permit_ID":`))+`]`),
	} {
		t.Run("accepted/"+name, func(t *testing.T) {
			if _, err := ParseBundle(doc); err != nil {
				t.Fatalf("a document with no misspelled struct member was refused: %v\n%s", err, doc)
			}
		})
	}
}

// TestGatewayBindingMemberNamesAreMatchedExactly: a binding document is decoded
// into a typed struct too. A misspelled member was already refused, because
// the bytes are no longer their own canonical encoding; it is now refused for
// what it is.
func TestGatewayBindingMemberNamesAreMatchedExactly(t *testing.T) {
	g := newGatewayResigner(t)
	_, frozen, _ := frozenGatewayChain(t)
	binding := frozen.GatewayBindings[g.base.ReceiptID]
	variant := replaceOnce(t, binding, `"verdict":`, `"Verdict":`)
	if _, err := ParseGatewayBinding(variant); err == nil || !strings.Contains(err.Error(), "letter case") {
		t.Fatalf("ParseGatewayBinding with a misspelled member = %v, want a refusal naming letter case", err)
	}
	// Through the verifier, on a receipt that really signs the misspelled
	// bytes, so only the member-name check can refuse them.
	for _, member := range []string{`"verdict":`, `"binding_version":`} {
		misspelled := replaceOnce(t, binding, member, strings.ToUpper(member))
		res := VerifyBundle(g.raw(misspelled, func(*contracts.Receipt) {}), g.trust())
		if checkNamed(t, res, CheckIdentity).Status != StatusPass {
			t.Fatal("the planted receipt is not validly signed; the case proves nothing")
		}
		if c := checkNamed(t, res, CheckBinding); c.Status != StatusFail || res.Valid || !strings.Contains(c.Detail, "letter case") {
			t.Fatalf("binding check with a misspelled %s = %+v", member, c)
		}
	}
}

// ---------------------------------------------------------------------------
// Defect B: a receipt.v5 signature replayed as a legacy receipt
// ---------------------------------------------------------------------------

// replayAsLegacy re-splits the exact bytes a receipt.v5 signature covers into
// the eight colon-joined fields of the legacy v4 preimage, and returns a
// receipt document with no signature_version that carries the same signature
// and claims ALLOW. The v4 preimage does not cover verdict, tool_name or
// timestamp, so the document is free to say anything there.
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

// requireLegacyRefusal asserts res is the refusal of a legacy receipt: not
// valid, no check run, and one error that says what the receipt is and how to
// opt in.
func requireLegacyRefusal(t *testing.T, res Result) {
	t.Helper()
	if res.Valid {
		t.Fatalf("a receipt with no signature_version was VERIFIED without an opt-in: %+v", res)
	}
	if len(res.Checks) != 0 || len(res.Errors) != 1 {
		t.Fatalf("a legacy receipt must be refused before any check runs, with one error: %+v", res)
	}
	for _, want := range []string{"legacy", "signature_version", "AllowLegacyV4", "--allow-legacy-v4"} {
		if !strings.Contains(res.Errors[0], want) {
			t.Fatalf("the refusal must say plainly what the receipt is and how to opt in (missing %q): %s", want, res.Errors[0])
		}
	}
}

// TestReceiptV5SignatureDoesNotReplayAsALegacyReceipt is helm-tracker#305
// defect B.
//
// The legacy v4 preimage is eight fields joined with ":" with no escaping and
// no domain separation. The JCS bytes of a signed receipt.v5 envelope contain
// colons, so they can be read back as those eight fields, and a document
// without signature_version built from a genuine DENY receipt's bytes and
// signature verified as a legacy receipt saying ALLOW. No key is needed.
func TestReceiptV5SignatureDoesNotReplayAsALegacyReceipt(t *testing.T) {
	raw, trust, trustJSON := signedDenial(t)
	genuine, err := ParseBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := canonicalizeV5(genuine.Receipts[0])
	if err != nil {
		t.Fatal(err)
	}
	forged := replayAsLegacy(t, signed, genuine.Receipts[0].Signature)

	bundle, err := ParseBundle(forged)
	if err != nil {
		t.Fatalf("the replay document must reach the verifier: %v", err)
	}
	r := bundle.Receipts[0]
	if r.SignatureVersion != "" || r.Verdict != "ALLOW" || !bytes.Equal(canonicalizeV4(r), signed) {
		t.Fatalf("the planted document is not a legacy reading of the signed receipt.v5 bytes; the case proves nothing: %+v", r)
	}

	res := VerifyBundleWith(bundle, trust, Options{})
	if res.Valid {
		t.Fatalf("the signature of a receipt.v5 DENY receipt was replayed as a legacy receipt and VERIFIED with verdict %q: %+v",
			r.Verdict, res)
	}
	requireLegacyRefusal(t, res)
	requireLegacyRefusal(t, Verify(bundle.Receipts, trust))
	requireLegacyRefusal(t, VerifyBundle(bundle, trust))

	// The WASM entry point's verifier has no opt-in: the document is not
	// VERIFIED and not FAILED, it was not checked.
	got := VerifyJSON(forged, trustJSON)
	if got.Verdict != VerdictUnverifiable || got.Verification.Valid {
		t.Fatalf("VerifyJSON of a legacy receipt = %s, want UNVERIFIABLE: %+v", got.Verdict, got)
	}
	requireLegacyRefusal(t, got.Verification)
}

// ---------------------------------------------------------------------------
// Defect C: what the integrity check says it did
// ---------------------------------------------------------------------------

// TestIntegrityCheckSaysOnlyWhatItChecked: the integrity check recomputes each
// receipt's canonical chain hash and compares it with nothing, because a
// receipt does not carry its own hash. It must not claim the receipt's bytes
// were compared with what was signed, and it must not report a pass: a
// receipt whose unsigned members were rewritten after signing gets through it.
func TestIntegrityCheckSaysOnlyWhatItChecked(t *testing.T) {
	raw, trust, _ := signedDenial(t)
	rewritten := replaceOnce(t, raw, `"tool_name":"payments.transfer"`, `"tool_name":"something.else"`)
	rewritten = replaceOnce(t, rewritten, `"timestamp":"2026-09-01T12:00:00Z"`, `"timestamp":"2031-01-01T00:00:00Z"`)
	bundle, err := ParseBundle(rewritten)
	if err != nil {
		t.Fatal(err)
	}
	res := VerifyBundle(bundle, trust)
	integrity := checkNamed(t, res, CheckIntegrity)
	if !res.Valid {
		t.Fatalf("rewriting members outside the receipt.v5 envelope is expected to leave the receipt valid, which is the point: %+v", res)
	}
	if integrity.Status != StatusNotApplicable {
		t.Fatalf("the integrity check compared nothing and reported %s for a receipt rewritten after signing: %s", integrity.Status, integrity.Detail)
	}
	for _, overclaim := range []string{"bytes on disk", "signed bytes", "unaltered", "not altered"} {
		if strings.Contains(integrity.Detail, overclaim) {
			t.Fatalf("the integrity check passed a receipt rewritten after signing and still claims %q: %s", overclaim, integrity.Detail)
		}
	}
	for _, want := range []string{"chain hash", "compared with nothing", "tool_name", "timestamp"} {
		if !strings.Contains(integrity.Detail, want) {
			t.Fatalf("the integrity check must say exactly what it did (missing %q): %s", want, integrity.Detail)
		}
	}
}

// TestIntegrityDetailIsTrueOfAChain pins the three things the integrity
// detail says about a chain: a successor's signed prev_hash covers every
// member of its predecessor, it does not cover the three anchoring members,
// and nothing covers the unsigned members of the last receipt.
func TestIntegrityDetailIsTrueOfAChain(t *testing.T) {
	verify := func(mutate func(receipts []*contracts.Receipt)) Result {
		fx := loadFrozen(t)
		mutate(fx.Receipts)
		return Verify(fx.Receipts, fx.trust())
	}

	res := verify(func(receipts []*contracts.Receipt) {
		last := receipts[len(receipts)-1]
		last.ToolName, last.ExecutorID, last.KeyID = "something.else", "someone-else", "another-key"
		last.Timestamp = last.Timestamp.AddDate(5, 0, 0)
		last.Metadata = map[string]any{"rewritten": true}
	})
	integrity := checkNamed(t, res, CheckIntegrity)
	if !res.Valid || integrity.Status != StatusNotApplicable {
		t.Fatalf("rewriting the unsigned members of the last receipt is expected to leave the chain valid and integrity not_applicable: %+v", res)
	}
	for _, want := range []string{"compared with nothing", "closure check", `receipt[2] "` + loadFrozen(t).Receipts[2].ReceiptID + `" has no successor`} {
		if !strings.Contains(integrity.Detail, want) {
			t.Fatalf("the integrity detail must name the receipt nothing pins (missing %q): %s", want, integrity.Detail)
		}
	}

	res = verify(func(receipts []*contracts.Receipt) { receipts[1].ToolName = "something.else" })
	if res.Valid || checkNamed(t, res, CheckClosure).Status != StatusFail {
		t.Fatalf("rewriting an unsigned member of a receipt that has a successor must fail closure, as the integrity detail says: %+v", res)
	}
	if got := checkNamed(t, res, CheckIntegrity); got.Status == StatusPass {
		t.Fatalf("integrity reported a pass on a chain with a rewritten receipt: %+v", got)
	}

	res = verify(func(receipts []*contracts.Receipt) {
		receipts[1].LogID, receipts[1].LeafIndex = "another-log", 7
		receipts[1].Transparency = &contracts.TransparencyAnchor{Backend: "elsewhere"}
	})
	if !res.Valid {
		t.Fatalf("the anchoring members are outside the chain hash, as the integrity detail says; rewriting them broke the chain: %+v", res)
	}
}

// TestUnsignedMemberExamplesAreOutsideTheSignedEnvelope keeps the member names
// the verifier prints true: the ones it calls unsigned are receipt members the
// receipt.v5 envelope leaves out, and the ones it says a legacy signature
// covers are the eight the legacy preimage joins.
func TestUnsignedMemberExamplesAreOutsideTheSignedEnvelope(t *testing.T) {
	receipt := membersOf(reflect.TypeFor[contracts.Receipt]())
	envelope := membersOf(reflect.TypeFor[receiptV5SigningEnvelope]())
	if len(envelope.exact) != 13 {
		t.Fatalf("the receipt.v5 envelope has %d members, want 13", len(envelope.exact))
	}
	for _, name := range strings.Split(unsignedMemberExamples, ", ") {
		if _, ok := receipt.exact[name]; !ok {
			t.Errorf("%q is not a receipt member", name)
		}
		if _, signed := envelope.exact[name]; signed {
			t.Errorf("%q is inside the receipt.v5 envelope; the integrity detail calls it unsigned", name)
		}
	}

	legacy := strings.Split(strings.ReplaceAll(legacyV4Members, " and ", ", "), ", ")
	if len(legacy) != 8 {
		t.Fatalf("legacyV4Members names %d members, want 8: %q", len(legacy), legacy)
	}
	// Each named member is one the preimage really depends on, and the three
	// the refusal calls uncovered are ones it does not.
	base := &contracts.Receipt{ReceiptID: "r", DecisionID: "d", EffectID: "e", Status: "s", OutputHash: "o", PrevHash: "p", LamportClock: 1, ArgsHash: "a"}
	rewrite := func(name string) *contracts.Receipt {
		raw, err := json.Marshal(base)
		if err != nil {
			t.Fatal(err)
		}
		var members map[string]any
		if err := json.Unmarshal(raw, &members); err != nil {
			t.Fatal(err)
		}
		switch name {
		case "lamport_clock":
			members[name] = 2
		case "timestamp":
			members[name] = "2031-01-01T00:00:00Z"
		default:
			members[name] = "rewritten"
		}
		if raw, err = json.Marshal(members); err != nil {
			t.Fatal(err)
		}
		var out contracts.Receipt
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		return &out
	}
	for _, name := range legacy {
		if bytes.Equal(canonicalizeV4(rewrite(name)), canonicalizeV4(base)) {
			t.Errorf("legacyV4Members names %q, which the legacy preimage does not depend on", name)
		}
	}
	for _, name := range []string{"verdict", "tool_name", "timestamp"} {
		if !bytes.Equal(canonicalizeV4(rewrite(name)), canonicalizeV4(base)) {
			t.Errorf("the legacy preimage depends on %q; the refusal says it is not covered", name)
		}
	}
}

// ---------------------------------------------------------------------------
// The legacy opt-in
// ---------------------------------------------------------------------------

// legacyV4Receipt is a genuine legacy receipt: no signature_version, signed
// over the v4 preimage by a key of its own.
func legacyV4Receipt(t *testing.T) (*contracts.Receipt, TrustRoot) {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x53}, ed25519.SeedSize))
	r := &contracts.Receipt{
		ReceiptID:    "rcpt-legacy-1",
		DecisionID:   "dec-legacy-1",
		EffectID:     "eff-legacy-1",
		Status:       "EXECUTED",
		Timestamp:    time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC),
		OutputHash:   "sha256:out-legacy-1",
		ArgsHash:     "sha256:args-legacy-1",
		LamportClock: 1,
		Verdict:      "ALLOW",
		ToolName:     "fs.write",
		KeyID:        "legacy-key",
	}
	r.Signature = hex.EncodeToString(ed25519.Sign(key, canonicalizeV4(r)))
	return r, TrustRoot{Keys: map[string]string{"legacy-key": hex.EncodeToString(key.Public().(ed25519.PublicKey))}}
}

// TestLegacyReceiptIsCheckedOnlyUnderTheOptInAndSaysSo: with
// Options.AllowLegacyV4 a legacy receipt is checked as before. The result then
// counts it and says what its signature does not cover, because under the
// opt-in a receipt whose verdict, tool_name and timestamp were rewritten is
// still Valid.
func TestLegacyReceiptIsCheckedOnlyUnderTheOptInAndSaysSo(t *testing.T) {
	r, trust := legacyV4Receipt(t)
	chain := []*contracts.Receipt{r}

	requireLegacyRefusal(t, Verify(chain, trust))
	requireLegacyRefusal(t, VerifyBundleWith(Bundle{Receipts: chain}, trust, Options{RequireGatewayBindings: true}))
	// The refusal does not depend on the trust root: nothing was checked.
	requireLegacyRefusal(t, Verify(chain, TrustRoot{}))
	requireLegacyRefusal(t, Verify(chain, TrustRoot{AllowSelfAttested: true}))

	rewritten := *r
	rewritten.Verdict, rewritten.ToolName = "DENY", "payments.transfer"
	rewritten.Timestamp = r.Timestamp.AddDate(5, 0, 0)
	for name, receipt := range map[string]*contracts.Receipt{"as signed": r, "unsigned members rewritten": &rewritten} {
		t.Run(name, func(t *testing.T) {
			res := VerifyBundleWith(Bundle{Receipts: []*contracts.Receipt{receipt}}, trust, Options{AllowLegacyV4: true})
			if !res.Valid || res.LegacyReceipts != 1 || res.PreimageVersion != "v4-fields" {
				t.Fatalf("an opted-in legacy receipt must verify and be counted as legacy: %+v", res)
			}
			identity := checkNamed(t, res, CheckIdentity)
			for _, want := range []string{"legacy", "does not cover", "verdict", "tool_name", "timestamp"} {
				if !strings.Contains(identity.Detail, want) {
					t.Fatalf("an opted-in pass must say what a legacy signature does not cover (missing %q): %s", want, identity.Detail)
				}
			}
			if policy := checkNamed(t, res, CheckPolicy); policy.Status == StatusPass {
				t.Fatalf("the policy check passed for a receipt whose signature does not cover its verdict: %+v", policy)
			}
			if integrity := checkNamed(t, res, CheckIntegrity); integrity.Status != StatusNotApplicable ||
				!strings.Contains(integrity.Detail, "in a legacy receipt: verdict, tool_name, timestamp") {
				t.Fatalf("the integrity check must name what a legacy receipt leaves unsigned: %+v", integrity)
			}
		})
	}

	tampered := *r
	tampered.Status = "DENIED"
	if res := VerifyBundleWith(Bundle{Receipts: []*contracts.Receipt{&tampered}}, trust, Options{AllowLegacyV4: true}); res.Valid ||
		checkNamed(t, res, CheckIdentity).Status != StatusFail {
		t.Fatalf("a legacy receipt with a rewritten signed member verified under the opt-in: %+v", res)
	}
}

// resultJSON is a result as a consumer of receipt_verify --json reads it.
func resultJSON(t *testing.T, res Result) map[string]any {
	t.Helper()
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestLegacyReceiptInAVersionedChainIsNamed: a chain may hold receipts signed
// under different preimages. preimage_version named the first receipt's only,
// so a chain of a receipt.v5 receipt and a legacy one read "receipt.v5" with
// valid true. The result now names every preimage and how many receipts were
// checked under each, and preimage_version is "mixed" when there are two.
func TestLegacyReceiptInAVersionedChainIsNamed(t *testing.T) {
	raw, trust, _ := signedDenial(t)
	first, err := ParseBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	prev, err := contracts.ReceiptChainHash(first.Receipts[0])
	if err != nil {
		t.Fatal(err)
	}
	// A legacy receipt that really chains to the receipt.v5 one, so the
	// result is valid and nothing but the version members can show the mix.
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x53}, ed25519.SeedSize))
	legacy := &contracts.Receipt{
		ReceiptID: "rcpt-legacy-2", DecisionID: "dec-legacy-2", EffectID: "eff-legacy-2", Status: "EXECUTED",
		PrevHash: prev, LamportClock: 2, Verdict: "ALLOW", KeyID: "legacy-key",
	}
	legacy.Signature = hex.EncodeToString(ed25519.Sign(key, canonicalizeV4(legacy)))
	trust.Keys["legacy-key"] = hex.EncodeToString(key.Public().(ed25519.PublicKey))
	chain := []*contracts.Receipt{first.Receipts[0], legacy}

	res := Verify(chain, trust)
	requireLegacyRefusal(t, res)
	if !strings.Contains(res.Errors[0], `receipt[1] "rcpt-legacy-2"`) || !strings.Contains(res.Errors[0], "1 of 2") {
		t.Fatalf("the refusal must name the legacy receipt and how many there are: %s", res.Errors[0])
	}

	res = VerifyBundleWith(Bundle{Receipts: chain}, trust, Options{AllowLegacyV4: true})
	if !res.Valid || res.LegacyReceipts != 1 {
		t.Fatalf("the chain is expected to verify under the opt-in with one legacy receipt counted: %+v", res)
	}
	out := resultJSON(t, res)
	if out["preimage_version"] != "mixed" {
		t.Fatalf("preimage_version = %v for a chain of a receipt.v5 and a legacy receipt, want \"mixed\"", out["preimage_version"])
	}
	want := []any{
		map[string]any{"version": contracts.ReceiptSignatureV5, "receipts": float64(1)},
		map[string]any{"version": "v4-fields", "receipts": float64(1)},
	}
	if !reflect.DeepEqual(out["preimage_versions"], want) {
		t.Fatalf("preimage_versions = %v, want every preimage with its receipt count: %v", out["preimage_versions"], want)
	}
	if identity := checkNamed(t, res, CheckIdentity); identity.Status != StatusPass || !strings.Contains(identity.Detail, "of these, 1 legacy v4 receipt(s)") {
		t.Fatalf("the identity check must say how many of the receipts it passed are legacy: %+v", identity)
	}

	// A chain under one preimage keeps naming it, with the count beside it.
	fx := loadFrozen(t)
	out = resultJSON(t, Verify(fx.Receipts, fx.trust()))
	if out["preimage_version"] != contracts.ReceiptSignatureV5 ||
		!reflect.DeepEqual(out["preimage_versions"], []any{map[string]any{"version": contracts.ReceiptSignatureV5, "receipts": float64(3)}}) {
		t.Fatalf("a receipt.v5 chain reports preimage_version %v, preimage_versions %v", out["preimage_version"], out["preimage_versions"])
	}
}

// TestKeyIDInTheResultIsMarkedAsAClaim: key_id in a result is the first
// receipt's key_id member. No signature covers it and no key is chosen by it,
// so a result that carries it must say so beside it: a reader takes a key_id
// next to "valid": true for the key that verified.
func TestKeyIDInTheResultIsMarkedAsAClaim(t *testing.T) {
	raw, trust, _ := signedDenial(t)
	renamed := replaceOnce(t, raw, `"key_id":"hardening-test-key"`, `"key_id":"any-name-at-all"`)
	bundle, err := ParseBundle(renamed)
	if err != nil {
		t.Fatal(err)
	}
	res := VerifyBundle(bundle, trust)
	if !res.Valid {
		t.Fatalf("key_id is outside the signed envelope, so rewriting it is expected to leave the receipt valid: %+v", res)
	}
	out := resultJSON(t, res)
	if out["key_id"] != "any-name-at-all" {
		t.Fatalf("key_id = %v, want the receipt's member echoed", out["key_id"])
	}
	note, _ := out["key_id_note"].(string)
	for _, want := range []string{"unsigned", "claim", "not the key"} {
		if !strings.Contains(note, want) {
			t.Fatalf("a result that carries key_id must say what it is (key_id_note missing %q): %q", want, note)
		}
	}
	// No key_id, no note.
	without, err := ParseBundle(replaceOnce(t, raw, `"key_id":"hardening-test-key",`, ``))
	if err != nil {
		t.Fatal(err)
	}
	if out := resultJSON(t, VerifyBundle(without, trust)); out["key_id"] != nil || out["key_id_note"] != nil {
		t.Fatalf("a result with no key_id carries a note about one: %v", out)
	}
}

// TestOptedInReplayIsRefusedByItsReceiptID: the opt-in checks receipts issued
// before receipt.v5, and must still not accept a receipt.v5 signature read
// back as a legacy receipt. The replay cannot choose its receipt_id: the
// legacy preimage begins with it, and the signed bytes it replays are the JSON
// text of the receipt.v5 envelope, which begins with "{". A genuine legacy
// receipt_id never does, so that one character tells the two apart.
func TestOptedInReplayIsRefusedByItsReceiptID(t *testing.T) {
	raw, trust, _ := signedDenial(t)
	genuine, err := ParseBundle(raw)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := canonicalizeV5(genuine.Receipts[0])
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := ParseBundle(replayAsLegacy(t, signed, genuine.Receipts[0].Signature))
	if err != nil {
		t.Fatal(err)
	}
	r := bundle.Receipts[0]
	if !bytes.Equal(canonicalizeV4(r), signed) || !strings.HasPrefix(r.ReceiptID, `{"args_hash"`) {
		t.Fatalf("the planted document is not a legacy reading of the signed receipt.v5 bytes; the case proves nothing: %+v", r)
	}
	// The signature itself is good for these bytes: only the rule refuses it.
	for _, key := range trust.Keys {
		if ok, err := verifyEd25519(key, r.Signature, canonicalizeV4(r)); err != nil || !ok {
			t.Fatalf("the replayed signature does not verify over the legacy preimage; the case proves nothing: %v", err)
		}
	}

	res := VerifyBundleWith(bundle, trust, Options{AllowLegacyV4: true})
	identity := checkNamed(t, res, CheckIdentity)
	if res.Valid || identity.Status != StatusFail {
		t.Fatalf("the signature of a receipt.v5 DENY receipt was replayed as a legacy receipt and VERIFIED under the opt-in with verdict %q: %+v",
			r.Verdict, res)
	}
	for _, want := range []string{"receipt_id", `"{"`, "replay"} {
		if !strings.Contains(identity.Detail, want) {
			t.Fatalf("the refusal must say why the receipt is not a legacy receipt (missing %s): %s", want, identity.Detail)
		}
	}

	// A genuine legacy receipt is not caught by the rule.
	legacy, legacyTrust := legacyV4Receipt(t)
	if res := VerifyBundleWith(Bundle{Receipts: []*contracts.Receipt{legacy}}, legacyTrust, Options{AllowLegacyV4: true}); !res.Valid {
		t.Fatalf("a genuine legacy receipt no longer verifies under the opt-in: %+v", res)
	}
}

// ---------------------------------------------------------------------------
// The member-name rule agrees with encoding/json
// ---------------------------------------------------------------------------

// TestFoldNameMatchesEncodingJSON pins foldName to the decoder it stands in
// for. Every rune that has a case fold is offered to encoding/json as a
// one-letter member name; the decoder binds it to a struct field exactly when
// foldName says the two names are one.
func TestFoldNameMatchesEncodingJSON(t *testing.T) {
	fields := make([]reflect.StructField, 0, 26)
	for letter := 'a'; letter <= 'z'; letter++ {
		fields = append(fields, reflect.StructField{
			Name: "F" + string(letter-'a'+'A'),
			Type: reflect.TypeFor[*int](),
			Tag:  reflect.StructTag(`json:"` + string(letter) + `"`),
		})
	}
	probe := reflect.StructOf(fields)
	bound := func(name string) string {
		doc, err := json.Marshal(map[string]int{name: 1})
		if err != nil {
			t.Fatal(err)
		}
		target := reflect.New(probe)
		if err := json.Unmarshal(doc, target.Interface()); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < probe.NumField(); i++ {
			if !target.Elem().Field(i).IsNil() {
				return string(rune('a' + i))
			}
		}
		return ""
	}
	checked, variants := 0, 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !utf8.ValidRune(r) || (r > unicode.MaxASCII && unicode.SimpleFold(r) == r) {
			continue
		}
		name := string(r)
		want := bound(name)
		got := ""
		for letter := 'a'; letter <= 'z'; letter++ {
			if foldName(name) == foldName(string(letter)) {
				got = string(letter)
			}
		}
		if got != want {
			t.Fatalf("encoding/json binds member %q (%U) to field %q; foldName says %q", name, r, want, got)
		}
		if checked++; want != "" && name != want {
			variants++
		}
	}
	// 26 upper-case letters, the Kelvin sign and the long s.
	if variants != 28 {
		t.Fatalf("%d of %d names bound to a field spelled otherwise, want 28; the case proves less than it says", variants, checked)
	}
	for _, pair := range [][2]string{{"Tool_Name", "tool_name"}, {"Key_id", "key_id"}, {"ſignature", "signature"}} {
		if foldName(pair[0]) != foldName(pair[1]) {
			t.Errorf("foldName(%q) != foldName(%q)", pair[0], pair[1])
		}
	}
	// encoding/json does not fold separators: these stay different names.
	for _, pair := range [][2]string{{"keyid", "key_id"}, {"key-id", "key_id"}, {"status", "statu"}} {
		if foldName(pair[0]) == foldName(pair[1]) {
			t.Errorf("foldName(%q) == foldName(%q)", pair[0], pair[1])
		}
	}
}

// decodedTypes are the types this package decodes a document into. Their
// struct members are the names the parser matches exactly.
var decodedTypes = []reflect.Type{
	reflect.TypeFor[Bundle](),
	reflect.TypeFor[contracts.Receipt](),
	reflect.TypeFor[PermitRecord](),
	reflect.TypeFor[GatewayBinding](),
	reflect.TypeFor[GatewayOutcomeBinding](),
}

// TestMemberNamesAreTheOnesEncodingJSONBinds walks every struct reachable from
// the decoded types and checks the derived names against the decoder itself:
// it binds each name, binds its upper-case spelling too (the defect's
// premise), and knows no name the derivation missed. It also holds the walk's
// two assumptions: no reachable struct decodes itself, and no two members of
// one struct differ only in letter case.
func TestMemberNamesAreTheOnesEncodingJSONBinds(t *testing.T) {
	seen := map[reflect.Type]bool{}
	structs := 0
	var walk func(t reflect.Type)
	strict := func(target reflect.Type, name string) error {
		doc, err := json.Marshal(map[string]any{name: nil})
		if err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(bytes.NewReader(doc))
		decoder.DisallowUnknownFields()
		return decoder.Decode(reflect.New(target).Interface())
	}
	walk = func(typ reflect.Type) {
		for typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		if seen[typ] {
			return
		}
		seen[typ] = true
		selfDecoding := reflect.PointerTo(typ).Implements(jsonUnmarshalerType) || reflect.PointerTo(typ).Implements(textUnmarshalerType)
		switch typ.Kind() {
		case reflect.Map, reflect.Slice, reflect.Array:
			if !selfDecoding {
				walk(typ.Elem())
			}
		case reflect.Struct:
			if selfDecoding {
				// time.Time reads a string. Any other self-decoding struct
				// may read member names the walk cannot see.
				if typ != reflect.TypeFor[time.Time]() {
					t.Errorf("%s decodes itself; the member-name walk treats it as data. Extend the walk before decoding it here", typ)
				}
				return
			}
			structs++
			members := membersOf(typ)
			if len(members.exact) == 0 || len(members.folded) != len(members.exact) {
				t.Errorf("%s: %d member names fold to %d; two members differ only in letter case, or none were found",
					typ, len(members.exact), len(members.folded))
			}
			declared := 0
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				if field.Anonymous {
					t.Errorf("%s embeds %s; check membersOf's promotion against encoding/json before relying on it", typ, field.Type)
				}
				if field.IsExported() && field.Tag.Get("json") != "-" {
					declared++
				}
			}
			if declared != len(members.exact) {
				t.Errorf("%s declares %d JSON fields; membersOf derived %d", typ, declared, len(members.exact))
			}
			for name, fieldType := range members.exact {
				if err := strict(typ, name); err != nil {
					t.Errorf("%s: encoding/json does not bind derived member %q: %v", typ, name, err)
				}
				if err := strict(typ, strings.ToUpper(name)); err != nil {
					t.Errorf("%s: encoding/json no longer folds %q onto %q (%v); the member-name rule's premise changed", typ, strings.ToUpper(name), name, err)
				}
				walk(fieldType)
			}
			if err := strict(typ, "no_such_member"); err == nil {
				t.Errorf("%s: the strict decoder accepted an unknown member; the checks above prove nothing", typ)
			}
		}
	}
	for _, typ := range decodedTypes {
		walk(typ)
	}
	if structs < 15 {
		t.Fatalf("walked %d struct types; the receipt alone reaches more", structs)
	}
}

// TestCorpusHardeningDocumentsAreWhatTheirNamesSay keeps the native/WASM
// corpus cases for helm-tracker#305 honest. They expect a refusal, and a
// refusal is easy to get for the wrong reason: the shadowed document must read
// ALLOW by exact name while restoring the signed DENY for a folding decoder,
// and the legacy document must be a real replay, valid once a caller opts in.
func TestCorpusHardeningDocumentsAreWhatTheirNamesSay(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "wasm-json-corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus jsonCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	_, frozen, trust := frozenGatewayChain(t)
	denial := frozen.Receipts[1]

	shadowed := []byte(corpus.Documents["gateway_shadowed_verdict"])
	var exact map[string]any
	if err := json.Unmarshal(shadowed, &exact); err != nil {
		t.Fatal(err)
	}
	var folded contracts.Receipt
	if err := json.Unmarshal(shadowed, &folded); err != nil {
		t.Fatal(err)
	}
	if exact["verdict"] != "ALLOW" || exact["status"] != "ADMITTED" || folded.Verdict != "DENY" || folded.Status != "DENIED" ||
		folded.Signature != denial.Signature {
		t.Fatalf("gateway_shadowed_verdict does not read ALLOW by exact name over the frozen DENY signature: exact %v/%v, folded %s/%s",
			exact["status"], exact["verdict"], folded.Status, folded.Verdict)
	}
	if _, err := ParseBundle(shadowed); err == nil || !strings.Contains(err.Error(), "letter case") {
		t.Fatalf("gateway_shadowed_verdict is not refused for its letter case: %v", err)
	}
	if _, err := ParseBundle([]byte(corpus.Documents["gateway_case_variant_member"])); err == nil ||
		!strings.Contains(err.Error(), "letter case") || !strings.Contains(err.Error(), `"timestamp"`) {
		t.Fatalf("gateway_case_variant_member is not refused for the letter case of timestamp: %v", err)
	}

	// The decoy bundle reads ALLOW at its top level, holds the frozen DENY
	// receipt unchanged, and is refused for the members beside "receipts":
	// without them the same bundle verifies.
	decoy := []byte(corpus.Documents["gateway_bundle_decoy"])
	var top struct {
		Verdict  string            `json:"verdict"`
		Receipts []json.RawMessage `json:"receipts"`
	}
	if err := json.Unmarshal(decoy, &top); err != nil {
		t.Fatal(err)
	}
	if top.Verdict != "ALLOW" || len(top.Receipts) != 1 {
		t.Fatalf("gateway_bundle_decoy does not read ALLOW at its top level over one receipt: %s", decoy)
	}
	inner, err := ParseBundle([]byte(`{"receipts":[` + string(top.Receipts[0]) + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	if res := VerifyBundle(inner, trust); !res.Valid || inner.Receipts[0].Verdict != "DENY" || inner.Receipts[0].Signature != denial.Signature {
		t.Fatalf("the receipt inside gateway_bundle_decoy is not the frozen DENY, verified: %+v", res)
	}
	if _, err := ParseBundle(decoy); err == nil || !strings.Contains(err.Error(), "receipt member") {
		t.Fatalf("gateway_bundle_decoy is not refused for the receipt members at its top level: %v", err)
	}

	replay, err := ParseBundle([]byte(corpus.Documents["gateway_legacy_replay"]))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := canonicalizeV5(denial)
	if err != nil {
		t.Fatal(err)
	}
	r := replay.Receipts[0]
	if r.SignatureVersion != "" || r.Verdict != "ALLOW" || r.Signature != denial.Signature || !bytes.Equal(canonicalizeV4(r), signed) {
		t.Fatalf("gateway_legacy_replay is not a legacy reading of the frozen DENY receipt's signed bytes: %+v", r)
	}
	requireLegacyRefusal(t, VerifyBundle(replay, trust))
	// The signature is the frozen one over these very bytes, so only the
	// receipt_id rule keeps the opt-in from accepting it.
	if res := VerifyBundleWith(replay, trust, Options{AllowLegacyV4: true}); res.Valid ||
		!strings.Contains(checkNamed(t, res, CheckIdentity).Detail, "replay") {
		t.Fatalf("gateway_legacy_replay verifies under the opt-in, or is refused for another reason: %+v", res)
	}
}

type promotedMembers struct {
	Promoted string `json:"promoted"`
	Shadowed string `json:"shadowed"`
}

// PointerMembers is exported because encoding/json cannot allocate an embedded
// pointer to an unexported struct.
type PointerMembers struct {
	ThroughPointer string `json:"through_pointer"`
}

type namedEmbed struct {
	Inner string `json:"inner"`
}

// memberRules holds one field for each rule membersOf takes from
// encoding/json.
type memberRules struct {
	promotedMembers
	*PointerMembers
	namedEmbed  `json:"named_embed"`
	Tagged      string `json:"tagged,omitempty"`
	Untagged    string
	OptionsOnly string `json:",omitempty"`
	Skipped     string `json:"-"`
	Dash        string `json:"-,"`
	Shadowed    int    `json:"shadowed"`
	BadTag      string `json:"bad\"tag"`
	hidden      string
}

// TestMembersOfFollowsEncodingJSONFieldRules pins membersOf to the decoder on
// a struct that uses every field rule: tag names, tags without a name, "-",
// an invalid tag name, unexported fields, embedded structs with and without a
// tag, and an outer field that shadows a promoted one. encoding/json must bind
// exactly the names membersOf derives.
func TestMembersOfFollowsEncodingJSONFieldRules(t *testing.T) {
	_ = memberRules{}.hidden
	typ := reflect.TypeFor[memberRules]()
	members := membersOf(typ)
	binds := func(name string) bool {
		doc, err := json.Marshal(map[string]any{name: nil})
		if err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(bytes.NewReader(doc))
		decoder.DisallowUnknownFields()
		err = decoder.Decode(reflect.New(typ).Interface())
		if err != nil && !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("probing %q: %v", name, err)
		}
		return err == nil
	}
	want := []string{"promoted", "through_pointer", "named_embed", "tagged", "Untagged", "OptionsOnly", "-", "shadowed", "BadTag"}
	if len(members.exact) != len(want) {
		t.Fatalf("membersOf derived %d names, want %d: %v", len(members.exact), len(want), members.exact)
	}
	for _, name := range want {
		if _, ok := members.exact[name]; !ok {
			t.Errorf("membersOf did not derive %q", name)
		}
		if !binds(name) {
			t.Errorf("encoding/json does not bind %q; the expectation is wrong", name)
		}
	}
	for _, name := range []string{"Skipped", "hidden", "promotedMembers", "PointerMembers", "namedEmbed", "inner", `bad"tag`, "Dash", "no_such_member"} {
		if _, ok := members.exact[name]; ok {
			t.Errorf("membersOf derived %q, which is not a member", name)
		}
		if _, variant := members.folded[foldName(name)]; variant != binds(name) {
			t.Errorf("membersOf and encoding/json disagree on whether %q is a member in any letter case", name)
		}
	}
	if got := members.exact["shadowed"]; got.Kind() != reflect.Int {
		t.Errorf("the promoted field won over the outer one: shadowed is %s", got)
	}

	// The same rules through the parser: an exact name decodes, its variant is
	// refused, and names that are no member are data.
	for doc, wantErr := range map[string]bool{
		`{"promoted":"a","through_pointer":"b","named_embed":{"inner":"c"},"Untagged":"d","-":"e"}`: false,
		`{"Promoted":"a"}`:              true,
		`{"Through_Pointer":"b"}`:       true,
		`{"named_embed":{"Inner":"c"}}`: true,
		`{"untagged":"d"}`:              true,
		`{"Skipped":"x","skipped":"y"}`: false, // neither is a member: two names no field binds
		`{"Tagged":"x","tagged":"y"}`:   true,
		`{"Skipped":"x","hidden":"y"}`:  false,
		`{"namedEmbed":{"Inner":"c"}}`:  false,
	} {
		err := validateJSON([]byte(doc), typ)
		if (err != nil) != wantErr || (err != nil && !strings.Contains(err.Error(), "letter case")) {
			t.Errorf("validateJSON(%s) = %v, want refusal %v", doc, err, wantErr)
		}
	}
}

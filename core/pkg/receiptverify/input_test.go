// quantum_posture: these tests exercise parsing of classical Ed25519 receipt
// documents only; they add no signature scheme and claim no hybrid or
// post-quantum protection.
package receiptverify

import (
	"encoding/json"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// TestBundleTopLevelHoldsNoReceiptMember: the bundle form verifies the
// receipts inside "receipts". A member beside them that is named like a
// receipt member ("verdict", "tool_name") is what a reader of the document
// takes for the receipt's, and the verifier never looked at it: a genuine
// DENY receipt wrapped this way read ALLOW to jq and JSON.parse while the
// verifier answered VERIFIED. No key is needed to build it.
func TestBundleTopLevelHoldsNoReceiptMember(t *testing.T) {
	raw, trust, trustJSON := signedDenial(t)
	bundle := func(members string) []byte {
		return []byte(`{` + members + `"receipts":[` + string(raw) + `]}`)
	}

	decoy := bundle(`"verdict":"ALLOW","receipt_id":"rcpt-0001","tool_name":"wire_transfer",`)
	var exact map[string]any
	if err := json.Unmarshal(decoy, &exact); err != nil {
		t.Fatal(err)
	}
	if exact["verdict"] != "ALLOW" || exact["tool_name"] != "wire_transfer" {
		t.Fatalf("the planted bundle does not read ALLOW by exact name; the case proves nothing: %v", exact)
	}
	// The receipt inside is genuine and verifies when nothing surrounds it.
	clean, err := ParseBundle(bundle(""))
	if err != nil {
		t.Fatal(err)
	}
	if res := VerifyBundle(clean, trust); !res.Valid {
		t.Fatalf("the genuine receipt does not verify in a bundle; the case proves nothing: %+v", res)
	}

	parsed, err := ParseBundle(decoy)
	if err == nil {
		res := VerifyBundle(parsed, trust)
		t.Fatalf("a bundle whose top level reads verdict ALLOW was parsed; the verifier checked a receipt with verdict %q and reported valid=%v",
			parsed.Receipts[0].Verdict, res.Valid)
	}
	for _, want := range []string{"receipt member", `"receipts"`} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal must say the member belongs to a receipt, not to the bundle (missing %q): %v", want, err)
		}
	}
	if got := VerifyJSON(decoy, trustJSON); got.Verdict != VerdictFailed || got.Verification.Valid {
		t.Fatalf("VerifyJSON (the WASM entry point's verifier) = %s for the decoy bundle, want FAILED: %+v", got.Verdict, got)
	}

	// Every receipt member is refused at the top level of a bundle, in its own
	// spelling and in another letter case, unless it is one of the bundle's
	// own members. The names come from the receipt type, not from a list.
	own := membersOf(reflect.TypeFor[Bundle]()).exact
	receiptMembers := membersOf(reflect.TypeFor[contracts.Receipt]()).exact
	names := make([]string, 0, len(receiptMembers))
	for name := range receiptMembers {
		names = append(names, name)
	}
	sort.Strings(names)
	refused := 0
	for _, name := range names {
		if _, isOwn := own[name]; isOwn {
			continue
		}
		for _, spelling := range []string{name, strings.ToUpper(name)} {
			doc := bundle(strconv.Quote(spelling) + `:null,`)
			_, err := ParseBundle(doc)
			if err == nil || !strings.Contains(err.Error(), strconv.Quote(name)) {
				t.Errorf("a bundle with the receipt member %q at its top level, spelled %q, = %v, want a refusal naming it", name, spelling, err)
			} else if variant := spelling != name; variant != strings.Contains(err.Error(), "another letter case") {
				t.Errorf("the refusal of %q must say whether it is %q in another letter case: %v", spelling, name, err)
			}
		}
		refused++
	}
	if refused < 40 {
		t.Fatalf("only %d receipt members were tried; the receipt has more", refused)
	}

	// What is not a receipt member stays accepted: the bundle's own members
	// (key_id is one, and a receipt member too), and names no decoded type
	// knows, such as the paging members of the receipts API and a comment.
	for name, doc := range map[string][]byte{
		"bundle key members":    bundle(`"key_id":"k","public_key_hex":"00",`),
		"receipts API envelope": bundle(`"count":1,"has_more":false,"next_cursor":"",`),
		"comment":               bundle(`"comment":"kept","Exported_By":"someone",`),
	} {
		if _, err := ParseBundle(doc); err != nil {
			t.Errorf("%s: a bundle with no receipt member at its top level was refused: %v", name, err)
		}
	}
}

// TestLetterCaseRuleFollowsTheDecodedType pins where a member name in another
// letter case is refused: where encoding/json decodes a struct, because there
// it binds the member to a field and the verifier would act on a value that a
// reader matching names exactly does not see. A Go map, a free-form value and
// an object no type describes are matched exactly by encoding/json too, so two
// keys there that differ in letter case are two keys, and stay accepted.
// Writing one name twice is refused everywhere.
func TestLetterCaseRuleFollowsTheDecodedType(t *testing.T) {
	raw, trust, _ := signedDenial(t)
	receipt := reflect.TypeFor[contracts.Receipt]()

	// Struct positions, at every depth, on either side of the exact member.
	for name, doc := range map[string]string{
		"top level, variant last":  `{"verdict":"ALLOW","VERDICT":"DENY"}`,
		"top level, variant first": `{"Verdict":"DENY","verdict":"ALLOW"}`,
		"nested struct":            `{"provenance":{"generated_by":"a","Generated_By":"b"}}`,
		"struct in an array":       `{"witness_signatures":[{"witness_id":"w"},{"witness_id":"w","Witness_ID":"x"}]}`,
		"kelvin sign":              `{"key_id":"a","` + "\u212a" + `ey_id":"b"}`,
		"long s":                   `{"status":"a","` + "\u017f" + `tatus":"b"}`,
		"escaped member name":      `{"status":"a","\u0053tatus":"b"}`,
	} {
		t.Run("struct/"+name, func(t *testing.T) {
			if err := validateJSON([]byte(doc), receipt); err == nil || !strings.Contains(err.Error(), "letter case") {
				t.Fatalf("validateJSON(%s) as a receipt = %v, want a refusal naming letter case", doc, err)
			}
		})
	}

	// Maps and free-form values of a receipt: the documents below verified
	// before member names were matched exactly, and must again.
	for name, members := range map[string]string{
		"metadata keys":         `"metadata":{"a":1,"A":2}`,
		"metadata named like":   `"metadata":{"verdict":"x","Verdict":"y","Status":"z"}`,
		"free-form subject":     `"subject":{"verdict":"x","Verdict":"y","nested":{"a":1,"A":2}}`,
		"unknown member object": `"x-custom":{"a":1,"A":2},"X-Custom":1`,
	} {
		t.Run("data/"+name, func(t *testing.T) {
			bundle, err := ParseBundle(appendMembers(raw, members))
			if err != nil {
				t.Fatalf("keys of a map or free-form value that differ in letter case were refused: %v", err)
			}
			if res := VerifyBundle(bundle, trust); !res.Valid {
				t.Fatalf("the receipt no longer verifies: %+v", res)
			}
		})
	}
	t.Run("data/public_key_set keys", func(t *testing.T) {
		doc := replaceOnce(t, raw, `"public_key_set":{`, `"public_key_set":{"ED25519":"00",`)
		bundle, err := ParseBundle(doc)
		if err != nil {
			t.Fatalf("a public_key_set with ED25519 and ed25519 was refused: %v", err)
		}
		if keys := bundle.Receipts[0].PublicKeySet; len(keys) != 2 || keys["ED25519"] != "00" || keys["ed25519"] == "" {
			t.Fatalf("encoding/json no longer keeps both keys apart; the rule's premise changed: %v", keys)
		}
	})
	t.Run("data/metadata keys stay apart", func(t *testing.T) {
		bundle, err := ParseBundle(appendMembers(raw, `"metadata":{"a":1,"A":2}`))
		if err != nil {
			t.Fatal(err)
		}
		if meta := bundle.Receipts[0].Metadata; len(meta) != 2 {
			t.Fatalf("encoding/json no longer keeps metadata keys a and A apart; the rule's premise changed: %v", meta)
		}
	})

	// One name written twice is refused wherever it is.
	for name, tc := range map[string]struct {
		doc  []byte
		want string
	}{
		"metadata":       {appendMembers(raw, `"metadata":{"a":1,"a":2}`), `duplicate object member "a" at $.metadata`},
		"subject":        {appendMembers(raw, `"subject":{"n":{"a":1,"a":2}}`), `duplicate object member "a" at $.subject.n`},
		"unknown member": {appendMembers(raw, `"x-custom":{"a":1,"a":2}`), `duplicate object member "a" at $.x-custom`},
		"public_key_set": {replaceOnce(t, raw, `"public_key_set":{`, `"public_key_set":{"ed25519":"00",`), `duplicate object member "ed25519" at $.public_key_set`},
	} {
		t.Run("exact duplicate/"+name, func(t *testing.T) {
			if _, err := ParseBundle(tc.doc); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("an exact duplicate member = %v, want %q", err, tc.want)
			}
		})
	}

	// With no type to decode into, only exact duplicates are refused.
	for doc, wantErr := range map[string]bool{
		`{"a":1,"A":2}`:                       false,
		`{"outer":{"verdict":1,"VERDICT":2}}`: false,
		`[{"a":1},{"A":1}]`:                   false,
		`{"a":1,"a":2}`:                       true,
		`{"outer":[{"a":1,"\u0061":2}]}`:      true,
	} {
		if err := ValidateJSONStructure([]byte(doc)); (err != nil) != wantErr {
			t.Errorf("ValidateJSONStructure(%s) = %v, want refusal %v", doc, err, wantErr)
		}
	}
}

// TestRefusalsNameWhereTheMemberIs pins the member path a refusal carries. The
// path is rendered only when a refusal needs it, and must read as before.
func TestRefusalsNameWhereTheMemberIs(t *testing.T) {
	raw, _, _ := signedDenial(t)
	second := appendMembers(raw, `"witness_signatures":[{"witness_id":"w","signature":"00"},{"Witness_ID":"w","signature":"00"}]`)
	for want, doc := range map[string][]byte{
		`member "Witness_ID" at $.receipts[1].witness_signatures[1] is the member "witness_id" in another letter case`: []byte(`{"receipts":[` + string(raw) + `,` + string(second) + `]}`),
		`member "Witness_ID" at $[0].witness_signatures[1] is the member "witness_id" in another letter case`:          []byte(`[` + string(second) + `]`),
		`duplicate object member "b" at $.metadata.a[2]`:                                                               appendMembers(raw, `"metadata":{"a":[0,1,{"b":1,"b":2}]}`),
		`duplicate object member "receipt_id" at $`:                                                                    appendMembers(raw, `"receipt_id":"again"`),
	} {
		if _, err := ParseBundle(doc); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseBundle = %v, want a refusal holding %q", err, want)
		}
	}
}

// TestDeepNestingIsRefusedBeforeItIsWalked: a small document nested very
// deeply made the native parser build a member path at every level, which
// costs memory quadratic in the depth: 200 KB of brackets took 28 GB before
// it was refused. The native path now applies the nesting limit the WASM
// build has, on a pass that allocates nothing, before any recursive work.
func TestDeepNestingIsRefusedBeforeItIsWalked(t *testing.T) {
	raw, trust, trustJSON := signedDenial(t)
	// The receipt object is level 1 and metadata level 2.
	nested := func(arrays int) []byte {
		return appendMembers(raw, `"metadata":{"deep":`+strings.Repeat("[", arrays)+strings.Repeat("]", arrays)+`}`)
	}

	atLimit, err := ParseBundle(nested(MaxJSONDepth - 2))
	if err != nil {
		t.Fatalf("a document nested exactly %d levels was refused: %v", MaxJSONDepth, err)
	}
	if res := VerifyBundle(atLimit, trust); !res.Valid {
		t.Fatalf("a document nested exactly %d levels no longer verifies: %+v", MaxJSONDepth, res)
	}

	entryPoints := map[string]func(doc []byte) error{
		"ParseBundle":           func(doc []byte) error { _, err := ParseBundle(doc); return err },
		"ParseBundle, array":    func(doc []byte) error { _, err := ParseBundle([]byte("[" + string(doc) + "]")); return err },
		"ParseReceiptDocument":  func(doc []byte) error { _, err := ParseReceiptDocument(doc); return err },
		"ValidateJSONStructure": ValidateJSONStructure,
		"ParseGatewayBinding":   func(doc []byte) error { _, err := ParseGatewayBinding(doc); return err },
	}
	for _, arrays := range []int{MaxJSONDepth - 1, 1000, 100_000} {
		doc := nested(arrays)
		t.Run(strconv.Itoa(arrays+2)+" levels", func(t *testing.T) {
			for name, parse := range entryPoints {
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				err := parse(doc)
				runtime.ReadMemStats(&after)
				if err == nil || !strings.Contains(err.Error(), "nesting limit") {
					t.Fatalf("%s of a %d-byte document nested %d levels = %v, want the nesting limit refusal", name, len(doc), arrays+2, err)
				}
				// One copy of the input is the most any entry point may make
				// before it refuses; the quadratic walk took gigabytes.
				if grew := after.TotalAlloc - before.TotalAlloc; grew > uint64(2*len(doc))+1<<16 {
					t.Fatalf("%s allocated %d bytes refusing a %d-byte document; the limit must be checked before the document is walked", name, grew, len(doc))
				}
			}
			if got := VerifyJSON(doc, trustJSON); got.Verdict != VerdictFailed {
				t.Fatalf("VerifyJSON of a document nested %d levels = %s, want FAILED", arrays+2, got.Verdict)
			}
		})
	}

	// Brackets inside a string are data, not nesting.
	inString := appendMembers(raw, `"metadata":{"note":"`+strings.Repeat("[{", 500)+`\"`+strings.Repeat("[", 500)+`"}`)
	if _, err := ParseBundle(inString); err != nil {
		t.Fatalf("brackets inside a string were counted as nesting: %v", err)
	}
}

// TestBindingVersionMemberIsMatchedExactly: the binding check reads
// binding_version to choose the closed document it parses the bytes as. A
// binding whose only version member is spelled in another letter case names
// no binding_version to a reader matching names exactly, so the check must
// refuse the spelling and never act on the value.
func TestBindingVersionMemberIsMatchedExactly(t *testing.T) {
	_, frozen, _ := frozenGatewayChain(t)
	receipt := frozen.Receipts[0]
	for _, doc := range []string{
		`{"Binding_Version":"helm.gateway.receipt-binding.v9"}`,
		`{"BINDING_VERSION":"` + GatewayBindingVersion + `"}`,
	} {
		_, err := gatewayBindingMismatch(receipt, []byte(doc))
		if err == nil || !strings.Contains(err.Error(), "letter case") || !strings.Contains(err.Error(), `"binding_version"`) {
			t.Errorf("gatewayBindingMismatch(%s) = %v, want a refusal naming the letter case of binding_version", doc, err)
		}
		if err != nil && strings.Contains(err.Error(), "is not one this verifier knows") {
			t.Errorf("gatewayBindingMismatch(%s) acted on a binding_version no exact-name reader sees: %v", doc, err)
		}
	}
	// A version it does not know, spelled exactly, is still named as unknown.
	if _, err := gatewayBindingMismatch(receipt, []byte(`{"binding_version":"helm.gateway.receipt-binding.v9"}`)); err == nil ||
		!strings.Contains(err.Error(), "is not one this verifier knows") {
		t.Errorf("an unknown binding_version = %v, want the unknown-version refusal", err)
	}
}

// TestParseReceiptReadsExactlyOneReceipt: ParseReceipt is what a caller with
// one receipt per document uses (a file of an evidence bundle, verify receipt,
// a request body), so that the rules ParseBundle applies decide there too. It
// refuses everything that is not one receipt object, and its one option
// changes the signature-profile rule and nothing else.
func TestParseReceiptReadsExactlyOneReceipt(t *testing.T) {
	raw, trust, _ := signedDenial(t)
	receipt, err := ParseReceipt(raw)
	if err != nil {
		t.Fatal(err)
	}
	if res := Verify([]*contracts.Receipt{receipt}, trust); !res.Valid || receipt.Verdict != "DENY" {
		t.Fatalf("the parsed receipt does not verify as the DENY it is: %+v", res)
	}

	hybrid := replaceOnce(t, replaceOnce(t, raw, `"signature_profile":"classical"`, `"signature_profile":"hybrid"`),
		`"signature_algorithm":"ed25519"`, `"signature_algorithm":"ed25519+ml-dsa-65"`)
	if _, err := ParseReceipt(hybrid); err == nil || !strings.Contains(err.Error(), "signature metadata") {
		t.Fatalf("a receipt declaring a profile this package cannot verify = %v, want the signature metadata refusal", err)
	}
	parsed, err := ParseReceipt(hybrid, AnySignatureProfile)
	if err != nil || parsed.SignatureProfile != "hybrid" {
		t.Fatalf("AnySignatureProfile must leave the declared profile to the caller's verifier: %v", err)
	}

	shadow := appendMembers(replaceOnce(t, raw, `"verdict":"DENY"`, `"verdict":"ALLOW"`), `"Verdict":"DENY"`)
	for name, tc := range map[string]struct {
		doc  []byte
		want string
	}{
		"array":                         {[]byte("[" + string(raw) + "]"), "one receipt object"},
		"bundle":                        {[]byte(`{"receipts":[` + string(raw) + `]}`), "one receipt object"},
		"empty object":                  {[]byte(`{}`), "holds no receipt"},
		"empty input":                   {[]byte(" "), "input is empty"},
		"letter-case shadow":            {shadow, "letter case"},
		"verdict written twice":         {appendMembers(raw, `"verdict":"ALLOW"`), `duplicate object member "verdict"`},
		"variant signature_version":     {replaceOnce(t, raw, `"signature_version":`, `"Signature_Version":`), "letter case"},
		"missing receipt.v5 member":     {replaceOnce(t, raw, `"reason_code":"MANDATE_LIMIT_EXCEEDED",`, ``), `missing signed member "reason_code"`},
		"nested past the limit":         {appendMembers(raw, `"metadata":`+strings.Repeat("[", MaxJSONDepth)+strings.Repeat("]", MaxJSONDepth)), "nesting limit"},
		"trailing value":                {[]byte(string(raw) + `{}`), "trailing JSON value"},
		"shadow, any signature profile": {shadow, "letter case"},
	} {
		t.Run(name, func(t *testing.T) {
			var opts []ParseOption
			if strings.HasSuffix(name, "any signature profile") {
				opts = append(opts, AnySignatureProfile)
			}
			if got, err := ParseReceipt(tc.doc, opts...); err == nil || got != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ParseReceipt = %v, %v; want a refusal holding %q", got, err, tc.want)
			}
		})
	}

	// The names it reports as signed are the envelope's, in its order.
	signed := ReceiptV5SignedMembers()
	envelope := membersOf(reflect.TypeFor[receiptV5SigningEnvelope]()).exact
	if len(signed) != 13 || signed[0] != "signature_version" || signed[len(signed)-1] != "session_id" {
		t.Fatalf("ReceiptV5SignedMembers = %v, want the 13 envelope members in envelope order", signed)
	}
	for _, name := range signed {
		if _, ok := envelope[name]; !ok {
			t.Errorf("ReceiptV5SignedMembers names %q, which the receipt.v5 envelope does not sign", name)
		}
	}
}

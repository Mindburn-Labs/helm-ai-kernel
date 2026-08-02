package contracts

import (
	"bytes"
	"encoding/json"
	"sort"
	"testing"
)

// F-06: the V4 preimage joined fields with a bare ":" and escaped nothing, so
// moving a colon across a field boundary produced identical signed bytes for two
// structurally different records — one signature authenticating both. These are
// the regressions that must never come back.

func TestReceiptPreimageV5_ColonShiftDoesNotCollide(t *testing.T) {
	a := &Receipt{ReceiptID: "a", DecisionID: "b:c", Status: "OK"}
	b := &Receipt{ReceiptID: "a:b", DecisionID: "c", Status: "OK"}

	pa, err := ReceiptPreimageV5(a)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := ReceiptPreimageV5(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(pa) == string(pb) {
		t.Fatalf("two distinct receipts share a preimage — one signature would verify both:\n%s", pa)
	}
}

func TestDecisionPreimageV2_ColonShiftDoesNotCollide(t *testing.T) {
	// Hash-shaped values routinely contain a colon, which is exactly what made
	// the boundary between reason_code and phenotype_hash movable.
	a := &DecisionRecord{ID: "d", ReasonCode: "CODE:sha256", PhenotypeHash: "abc"}
	b := &DecisionRecord{ID: "d", ReasonCode: "CODE", PhenotypeHash: "sha256:abc"}

	pa, err := DecisionPreimageV2(a)
	if err != nil {
		t.Fatal(err)
	}
	pb, err := DecisionPreimageV2(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(pa) == string(pb) {
		t.Fatalf("two distinct decisions share a preimage — one signature would verify both:\n%s", pa)
	}
}

// An empty field and an absent field must not produce the same bytes either:
// that is why no envelope field carries omitempty.
func TestPreimages_EmptyFieldIsNotAnAbsentField(t *testing.T) {
	for _, name := range []string{"reason_code", "session_id", "policy_hash", "verdict"} {
		payload, err := ReceiptPreimageV5(&Receipt{ReceiptID: "r"})
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err := json.Unmarshal(payload, &got); err != nil {
			t.Fatal(err)
		}
		if _, present := got[name]; !present {
			t.Fatalf("%q is omitted when empty: an unset field and an empty one share a preimage", name)
		}
	}
}

// The preimage encoder relies on the envelope structs declaring their fields in
// lexicographic order — Go emits struct fields in declaration order. Reordering
// a field would silently change every signature this kernel produces, so pin it.
func TestPreimages_KeysAreSorted(t *testing.T) {
	cases := map[string]func() ([]byte, error){
		"receipt.v5": func() ([]byte, error) {
			return ReceiptPreimageV5(&Receipt{ReceiptID: "r"})
		},
		"decision_record.v2": func() ([]byte, error) {
			return DecisionPreimageV2(&DecisionRecord{ID: "d"})
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			payload, err := build()
			if err != nil {
				t.Fatal(err)
			}
			keys := preimageKeyOrder(t, payload)
			if !sort.StringsAreSorted(keys) {
				t.Fatalf("preimage keys are not lexicographic: %v", keys)
			}
		})
	}
}

// Golden bytes. A diff here means the signing contract changed: every previously
// issued signature of this version stops verifying. That requires a new version
// constant, not an edit to this expectation.
func TestPreimages_Golden(t *testing.T) {
	receipt, err := ReceiptPreimageV5(&Receipt{
		ReceiptID: "rcpt-1", DecisionID: "dec-1", EffectID: "eff-1", Status: "SUCCESS",
		OutputHash: "sha256:out", PrevHash: "GENESIS", LamportClock: 7, ArgsHash: "sha256:args",
		Verdict: "ALLOW", PolicyHash: "sha256:pol", SessionID: "sess-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantReceipt := `{"args_hash":"sha256:args","decision_id":"dec-1","effect_id":"eff-1","lamport_clock":7,"output_hash":"sha256:out","policy_hash":"sha256:pol","prev_hash":"GENESIS","reason_code":"","receipt_id":"rcpt-1","session_id":"sess-1","signature_version":"receipt.v5","status":"SUCCESS","verdict":"ALLOW"}`
	if string(receipt) != wantReceipt {
		t.Fatalf("receipt preimage changed\n got: %s\nwant: %s", receipt, wantReceipt)
	}

	decision, err := DecisionPreimageV2(&DecisionRecord{
		ID: "dec-1", Verdict: "DENY", Reason: "nope", ReasonCode: "POLICY_VIOLATION",
		PhenotypeHash: "sha256:phen", PolicyContentHash: "sha256:pol", EffectDigest: "sha256:eff",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantDecision := `{"effect_digest":"sha256:eff","id":"dec-1","phenotype_hash":"sha256:phen","policy_content_hash":"sha256:pol","reason_code":"POLICY_VIOLATION","reason_hash":"ca3704aa0b06f5954c79ee837faa152d84d6b2d42838f0637a15eda8337dbdce","signature_version":"decision_record.v2","verdict":"DENY"}`
	if string(decision) != wantDecision {
		t.Fatalf("decision preimage changed\n got: %s\nwant: %s", decision, wantDecision)
	}
}

// Free-text Reason is attested as a digest: editing the emitted explanation must
// change the preimage, but the prose itself must never appear inside it.
func TestDecisionPreimageV2_ReasonAttestedAsDigestOnly(t *testing.T) {
	base := &DecisionRecord{ID: "d", Verdict: "DENY", ReasonCode: "POLICY_VIOLATION", Reason: "blocked by rule 7"}
	before, err := DecisionPreimageV2(base)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(before, []byte("blocked by rule 7")) {
		t.Fatalf("free-text Reason leaked into the preimage: %s", before)
	}

	base.Reason = "blocked by rule 8"
	after, err := DecisionPreimageV2(base)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) == string(after) {
		t.Fatal("rewriting the explanation left the preimage unchanged — the reason is unattested")
	}
}

func TestPreimages_NilInputRejected(t *testing.T) {
	if _, err := ReceiptPreimageV5(nil); err == nil {
		t.Fatal("nil receipt must be rejected, not signed")
	}
	if _, err := DecisionPreimageV2(nil); err == nil {
		t.Fatal("nil decision must be rejected, not signed")
	}
}

// preimageKeyOrder returns the keys in the order they appear in the encoded
// object — json.Unmarshal into a map would lose exactly the property under test.
func preimageKeyOrder(t *testing.T, payload []byte) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(payload))
	if _, err := dec.Token(); err != nil { // opening '{'
		t.Fatalf("decode preimage: %v", err)
	}
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("decode preimage key: %v", err)
		}
		key, ok := tok.(string)
		if !ok {
			t.Fatalf("expected string key, got %T", tok)
		}
		keys = append(keys, key)
		var discard json.RawMessage
		if err := dec.Decode(&discard); err != nil {
			t.Fatalf("decode preimage value: %v", err)
		}
	}
	return keys
}

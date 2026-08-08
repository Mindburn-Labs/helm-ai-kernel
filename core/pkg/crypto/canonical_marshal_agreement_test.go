package crypto

import (
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// This file pins the resolution of the "two mutually incompatible canonical
// JSON encoders" defect. CanonicalMarshal is now an alias for
// canonicalize.JCS; if anyone reintroduces an independent encoder here, these
// tests fail with the exact inputs that used to diverge.

// TestCanonicalMarshalAgreesWithJCS covers the three inputs on which the
// former encoding/json-based CanonicalMarshal produced different bytes than
// canonicalize.JCS.
func TestCanonicalMarshalAgreesWithJCS(t *testing.T) {
	type nonLexicographic struct {
		Z string `json:"z"`
		A string `json:"a"`
	}

	cases := []struct {
		name  string
		value interface{}
		want  string
	}{
		{
			// Old behaviour: {"z":"1","a":"2"} — Go declaration order.
			// Reordering the two fields in the Go source silently changed
			// signed bytes.
			name:  "struct_fields_are_sorted_not_declaration_ordered",
			value: nonLexicographic{Z: "1", A: "2"},
			want:  `{"a":"2","z":"1"}`,
		},
		{
			// Old behaviour: {"v":"  "}. RFC 8785 Section 3.2.2.2
			// escapes only U+0000..U+001F, '"' and '\'.
			name:  "u2028_and_u2029_are_literal",
			value: map[string]string{"v": "\u2028\u2029"},
			want:  "{\"v\":\"\u2028\u2029\"}",
		},
		{
			// Old behaviour: {"v":"\\ufffd\\ufffd"} — the U+FFFD substitutions
			// that encoding/json inserts for ill-formed UTF-8 were themselves
			// escaped.
			name:  "u_fffd_substitutions_are_literal",
			value: map[string]string{"v": string([]byte{0xff, 0xfe})},
			want:  "{\"v\":\"\ufffd\ufffd\"}",
		},
		{
			name:  "html_chars_stay_unescaped",
			value: map[string]string{"v": "<a>&</a>"},
			want:  `{"v":"<a>&</a>"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cm, err := CanonicalMarshal(tc.value)
			if err != nil {
				t.Fatalf("CanonicalMarshal: %v", err)
			}
			jcs, err := canonicalize.JCS(tc.value)
			if err != nil {
				t.Fatalf("JCS: %v", err)
			}
			if string(cm) != string(jcs) {
				t.Fatalf("CanonicalMarshal and JCS disagree\n  CanonicalMarshal: %s\n  JCS:             %s", cm, jcs)
			}
			if string(cm) != tc.want {
				t.Fatalf("got %s want %s", cm, tc.want)
			}
		})
	}
}

// TestCanonicalMarshalCallSiteShapesAreByteStable freezes the bytes produced
// for the shapes the three in-repo CanonicalMarshal callers pass, so the
// switch to canonicalize.JCS is provably a no-op for signed and content-
// addressed artifacts rather than an assertion.
//
//   - translog.SignedTreeHead.SigningBytes (core/pkg/translog/sth.go:37) —
//     signed, and cross-published in EvidencePacks.
//   - CanonicalHasher.Hash (core/pkg/crypto/hasher.go:22).
//   - releasepermit.calculatePermitID (core/pkg/releasepermit/evaluate.go:282)
//     — a generic map decoded with UseNumber.
func TestCanonicalMarshalCallSiteShapesAreByteStable(t *testing.T) {
	// Shape 1: the STH signing payload. Its four Go fields already appear in
	// lexicographic order, which is exactly why the old encoder happened to
	// agree — a coincidence this test converts into a guarantee.
	type sthSigningPayloadShape struct {
		LogID     string `json:"log_id"`
		RootHash  string `json:"root_hash"`
		Timestamp string `json:"timestamp"`
		TreeSize  uint64 `json:"tree_size"`
	}
	sth := sthSigningPayloadShape{
		LogID:     "5f3c1a9b",
		RootHash:  "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		Timestamp: "2026-08-06T00:00:00Z",
		TreeSize:  7,
	}
	wantSTH := `{"log_id":"5f3c1a9b","root_hash":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08","timestamp":"2026-08-06T00:00:00Z","tree_size":7}`
	gotSTH, err := CanonicalMarshal(sth)
	if err != nil {
		t.Fatalf("CanonicalMarshal(sth): %v", err)
	}
	if string(gotSTH) != wantSTH {
		t.Fatalf("STH signing bytes changed\n got: %s\nwant: %s", gotSTH, wantSTH)
	}

	// Shape 2: CanonicalHasher over a map artifact.
	hash, err := NewCanonicalHasher().Hash(map[string]interface{}{"b": 2, "a": "x"})
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	canonicalBytes, err := CanonicalMarshal(map[string]interface{}{"b": 2, "a": "x"})
	if err != nil {
		t.Fatalf("CanonicalMarshal(map): %v", err)
	}
	if string(canonicalBytes) != `{"a":"x","b":2}` {
		t.Fatalf("hasher input bytes changed: %s", canonicalBytes)
	}
	if hash != canonicalize.HashBytes(canonicalBytes) {
		t.Fatalf("CanonicalHasher no longer hashes the canonical bytes")
	}

	// Shape 3: the generic map releasepermit builds before hashing. Keys and
	// values are ASCII and every number is a safe integer, so the bytes are
	// identical under the old and new encoders and RFC 8785 reproduces them.
	permitShape := map[string]interface{}{
		"schema":       "helm.release-permit/v1",
		"permit_id":    "",
		"decision":     "allow",
		"pull_request": 803,
		"reviews":      []interface{}{map[string]interface{}{"verdict": "approve", "blocking_findings": 0}},
	}
	wantPermit := `{"decision":"allow","permit_id":"","pull_request":803,"reviews":[{"blocking_findings":0,"verdict":"approve"}],"schema":"helm.release-permit/v1"}`
	gotPermit, err := CanonicalMarshal(permitShape)
	if err != nil {
		t.Fatalf("CanonicalMarshal(permit): %v", err)
	}
	if string(gotPermit) != wantPermit {
		t.Fatalf("permit digest input changed\n got: %s\nwant: %s", gotPermit, wantPermit)
	}
	if err := canonicalize.CheckInteroperableNumbers(permitShape); err != nil {
		t.Fatalf("permit shape must stay inside the interoperable subset: %v", err)
	}
}

// TestReceiptV5PreimageStaysInsideTheInteroperableSubset guards the artifact
// P2-3 is about to publish: every number in the receipt.v5 signing envelope
// must be one an RFC 8785 implementation renders identically. lamport_clock is
// the only numeric key, and it is a uint64 — so a value above 2^53-1 would
// make our canonical bytes unreproducible by a conformant verifier.
func TestReceiptV5PreimageStaysInsideTheInteroperableSubset(t *testing.T) {
	inRange := receiptV5SigningEnvelope{SignatureVersion: "receipt.v5", LamportClock: 9007199254740991}
	if err := canonicalize.CheckInteroperableNumbers(inRange); err != nil {
		t.Fatalf("lamport_clock at the safe-integer boundary must be accepted: %v", err)
	}
	outOfRange := receiptV5SigningEnvelope{SignatureVersion: "receipt.v5", LamportClock: 9007199254740992}
	if err := canonicalize.CheckInteroperableNumbers(outOfRange); err == nil {
		t.Fatal("lamport_clock beyond 2^53-1 must be rejected: its canonical bytes are not RFC 8785 reproducible")
	}
}

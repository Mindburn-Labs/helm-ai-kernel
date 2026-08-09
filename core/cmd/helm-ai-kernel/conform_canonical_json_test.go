package main

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

// canonicalJSON here produces the signed preimage of the external-failure HCV
// validation manifest (see writeExternalFailureValidationManifest). Until
// 2026-08-06 it was a private copy of the canonicalization algorithm that had
// drifted from core/pkg/canonicalize in two ways — code point key ordering and
// U+2028/U+2029 escaping. These tests hold it to the single kernel encoder so
// the drift cannot recur silently.
func TestConformCanonicalJSONIsTheKernelCanonicalizer(t *testing.T) {
	cases := []struct {
		name  string
		value any
		want  string
	}{
		{
			name:  "struct_fields_are_sorted",
			value: struct{ Z, A string }{Z: "1", A: "2"},
			want:  `{"A":"2","Z":"1"}`,
		},
		{
			name:  "u2028_and_u2029_are_literal",
			value: map[string]string{"v": "\u2028\u2029"},
			want:  "{\"v\":\"\u2028\u2029\"}",
		},
		{
			// UTF-16 code unit ordering: the supplementary-plane key sorts
			// first. A code point sort produces the opposite order.
			name:  "keys_sort_by_utf16_code_unit",
			value: map[string]int{"�": 1, "\U00010000": 2},
			want:  "{\"\U00010000\":2,\"�\":1}",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonicalJSON(tc.value)
			if err != nil {
				t.Fatalf("canonicalJSON: %v", err)
			}
			reference, err := canonicalize.JCS(tc.value)
			if err != nil {
				t.Fatalf("JCS: %v", err)
			}
			if string(got) != string(reference) {
				t.Fatalf("conform canonicalJSON diverged from canonicalize.JCS\n got: %q\nref: %q", got, reference)
			}
			if string(got) != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

// TestValidationManifestPreimageIsByteStable freezes the signed bytes of a
// fully populated manifest, so the switch to canonicalize.JCS is demonstrably
// a no-op for the artifact rather than an assertion about one.
func TestValidationManifestPreimageIsByteStable(t *testing.T) {
	issuedAt, err := time.Parse(time.RFC3339, "2026-08-06T00:00:00Z")
	if err != nil {
		t.Fatalf("parse time: %v", err)
	}
	manifest := externalFailureValidationManifest{
		ID:                    "KVM-HPR-2026-00001",
		HPRID:                 "HPR-2026-00001",
		HCVIDs:                []string{"HCV-2026-00001"},
		ExpectedVerdicts:      []string{"DENY"},
		EvidencePackHash:      "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		ConformanceResultHash: "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
		KernelCommit:          "abc123",
		IssuedAt:              issuedAt,
		Signer:                "0011223344556677889900112233445566778899001122334455667788990011",
	}
	got, err := canonicalJSON(manifest)
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	want := `{"conformance_result_hash":"sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",` +
		`"evidencepack_hash":"sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",` +
		`"expected_verdicts":["DENY"],"hcv_ids":["HCV-2026-00001"],"hpr_id":"HPR-2026-00001",` +
		`"id":"KVM-HPR-2026-00001","issued_at":"2026-08-06T00:00:00Z","kernel_commit":"abc123",` +
		// signature is present-and-empty in the preimage, not omitted: a
		// verifier reconstructs it by clearing the field, not deleting it.
		`"signature":"",` +
		`"signer":"0011223344556677889900112233445566778899001122334455667788990011"}`
	if string(got) != want {
		t.Fatalf("validation manifest signing bytes changed\n got: %s\nwant: %s", got, want)
	}
	if err := canonicalize.CheckInteroperableNumbers(manifest); err != nil {
		t.Fatalf("manifest must stay inside the interoperable subset: %v", err)
	}
}

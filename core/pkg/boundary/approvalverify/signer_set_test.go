package approvalverify

import (
	"errors"
	"strings"
	"testing"
)

func TestComputeSignerSetHashValidatesEvidenceAndCanonicalOrder(t *testing.T) {
	signers := []VerifiedSigner{
		{PrincipalID: "principal-a", CredentialID: "credential-a", DeviceID: "device-a", KeyID: "key-a", Role: "pack-admin", AssertionHash: signerSetSHARef("a")},
		{PrincipalID: "principal-b", CredentialID: "credential-b", DeviceID: "device-b", KeyID: "key-b", Role: "pack-admin", AssertionHash: signerSetSHARef("b")},
	}
	hash, err := ComputeSignerSetHash(signerSetSHARef("c"), signerSetSHARef("d"), "pack-admin", signers)
	if err != nil {
		t.Fatalf("ComputeSignerSetHash() error = %v", err)
	}
	if !canonicalSHA256Ref(hash) {
		t.Fatalf("ComputeSignerSetHash() = %q, want canonical sha256 ref", hash)
	}

	tests := map[string]func([]VerifiedSigner) []VerifiedSigner{
		"identity substitution": func(candidate []VerifiedSigner) []VerifiedSigner {
			candidate[0].PrincipalID = "principal-z"
			return candidate
		},
		"assertion substitution": func(candidate []VerifiedSigner) []VerifiedSigner {
			candidate[0].AssertionHash = "sha256:not-a-hash"
			return candidate
		},
		"role substitution": func(candidate []VerifiedSigner) []VerifiedSigner {
			candidate[0].Role = "other-role"
			return candidate
		},
		"duplicate credential": func(candidate []VerifiedSigner) []VerifiedSigner {
			candidate[1].CredentialID = candidate[0].CredentialID
			return candidate
		},
		"non-canonical order": func(candidate []VerifiedSigner) []VerifiedSigner {
			candidate[0], candidate[1] = candidate[1], candidate[0]
			return candidate
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := append([]VerifiedSigner(nil), signers...)
			if _, err := ComputeSignerSetHash(signerSetSHARef("c"), signerSetSHARef("d"), "pack-admin", mutate(candidate)); err == nil {
				t.Fatal("ComputeSignerSetHash() error = nil, want rejection")
			}
		})
	}

	duplicate := append([]VerifiedSigner(nil), signers...)
	duplicate[1].PrincipalID = duplicate[0].PrincipalID
	if _, err := ComputeSignerSetHash(signerSetSHARef("c"), signerSetSHARef("d"), "pack-admin", duplicate); !errors.Is(err, ErrDuplicateSigner) {
		t.Fatalf("duplicate signer error = %v, want ErrDuplicateSigner", err)
	}
}

func signerSetSHARef(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}

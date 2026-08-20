package evidence

// quantum_posture: these tests exercise classical Ed25519 self-attested seal
// trust gating only; they do not assert post-quantum signature resistance.

import (
	"strings"
	"testing"
)

// TestTrustedPublicKeyForSeal_RejectsSelfAttestedByDefault is the F-02 unit
// regression: under the default dev-local profile a "file-dev" seal used to be
// verified against the public key embedded in the seal itself, which proves
// only that the pack is self-consistent.
func TestTrustedPublicKeyForSeal_RejectsSelfAttestedByDefault(t *testing.T) {
	seal := EvidencePackSeal{}
	seal.Signer.KeyID = "file-dev:deadbeef"
	seal.Signer.Type = "file-dev"
	// A well-formed 32-byte hex key the attacker controls.
	seal.Signer.PublicKey = strings.Repeat("ab", 32)

	t.Setenv("HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX", "")
	t.Setenv("HELM_EVIDENCE_SIGNER_PUBLIC_KEY_HEX", "")
	t.Setenv("HELM_ALLOW_SELF_ATTESTED_EVIDENCE", "")

	key, err := trustedPublicKeyForSeal(seal, nil, EvidenceTrustProfileDevLocal, false)
	if err == nil {
		t.Fatal("self-attested seal was accepted under the default dev-local profile: " +
			"any keypair could sign its own evidence pack and verify")
	}
	if key != nil {
		t.Fatal("a trust key was returned alongside an error")
	}
	if !strings.Contains(err.Error(), "self-attested") {
		t.Fatalf("error should name self-attestation, got: %v", err)
	}
	if !strings.Contains(err.Error(), "--allow-self-attested") {
		t.Fatalf("error should name the explicit CLI opt-in, got: %v", err)
	}
	if strings.Contains(err.Error(), "--profile team|customer|high-assurance") {
		t.Fatalf("error should not recommend stricter profiles without a trust root, got: %v", err)
	}
}

// The escape hatch must still work, so the dev loop has a documented path.
func TestTrustedPublicKeyForSeal_AllowsSelfAttestedWithExplicitOptIn(t *testing.T) {
	seal := EvidencePackSeal{}
	seal.Signer.KeyID = "file-dev:deadbeef"
	seal.Signer.Type = "file-dev"
	seal.Signer.PublicKey = strings.Repeat("ab", 32)

	t.Setenv("HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX", "")
	t.Setenv("HELM_EVIDENCE_SIGNER_PUBLIC_KEY_HEX", "")
	t.Setenv("HELM_ALLOW_SELF_ATTESTED_EVIDENCE", "1")

	key, err := trustedPublicKeyForSeal(seal, nil, EvidenceTrustProfileDevLocal, true)
	if err != nil {
		t.Fatalf("explicit opt-in should be honoured: %v", err)
	}
	if len(key) == 0 {
		t.Fatal("expected the embedded key to be returned under explicit opt-in")
	}
}

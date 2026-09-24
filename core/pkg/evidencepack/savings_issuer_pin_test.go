// quantum_posture: this test pins classical Ed25519 issuer keys for the
// savings verifier; no post-quantum primitives are used in this file.

package evidencepack

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"
)

// Audit 13-04 / HELM-738: the savings verifier anchored every signature to a
// registry carried inside the pack, so an attacker's self-signed pack came
// back OK with no way to tell. Unpinned results are now marked self-attested,
// and pinned issuer keys replace the pack's own registry.
func TestSavingsVerifyIssuerPinning(t *testing.T) {
	fix := buildSavingsFixture(t, false)
	_, contents, _ := buildSignedSavingsPack(t, fix)
	issuerHex := hex.EncodeToString(fix.signingKey.Public().(ed25519.PublicKey))

	res, err := VerifySavingsEvidenceOffline(contents)
	if err != nil {
		t.Fatalf("unpinned verify: %v", err)
	}
	if !res.SelfAttested {
		t.Fatalf("unpinned result not marked self-attested: %+v", res)
	}

	res, err = VerifySavingsEvidenceOfflineWithIssuer(contents, map[string]string{fix.keyID: "ed25519:" + issuerHex})
	if err != nil {
		t.Fatalf("pinned verify: %v", err)
	}
	if res.SelfAttested || !res.OK {
		t.Fatalf("pinned result = %+v, want OK and not self-attested", res)
	}

	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySavingsEvidenceOfflineWithIssuer(contents, map[string]string{fix.keyID: hex.EncodeToString(otherPub)}); err == nil {
		t.Fatal("pack verified against a pinned key that did not sign it")
	}
	if _, err := VerifySavingsEvidenceOfflineWithIssuer(contents, map[string]string{"other-issuer": issuerHex}); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("signatures by an unpinned key id were accepted: %v", err)
	}
}

package crypto

// quantum_posture: classical Ed25519/SHA-256 only; no post-quantum assurance
// is claimed or provided by this file.

// Security regression tests for the Wave 1 trust-root findings.
//
// Each test below is a proof-of-concept exploit that FAILS on the pre-fix tree
// and passes once the corresponding remediation lands. They are regression
// guards, not illustrations: if any of them starts passing for the wrong reason
// the assertion messages name the exact invariant that broke.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// F-01: NewEd25519Signer took a key *identifier* and silently generated a fresh
// random keypair, so `--sign <seed>`, SYSTEM_BOOT_KEY and EVIDENCE_SIGNING_KEY
// never established a trust root. Signers built from real key material must be
// deterministic.
func TestF01_SignerFromSeedIsDeterministic(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}

	first, err := NewEd25519SignerFromSeed(seed, "trust-root")
	if err != nil {
		t.Fatalf("NewEd25519SignerFromSeed: %v", err)
	}
	second, err := NewEd25519SignerFromSeed(seed, "trust-root")
	if err != nil {
		t.Fatalf("NewEd25519SignerFromSeed: %v", err)
	}

	if first.PublicKey() != second.PublicKey() {
		t.Fatalf("same seed produced different public keys: %s vs %s — "+
			"key material is being discarded, so no receipt survives a restart",
			first.PublicKey(), second.PublicKey())
	}
}

// F-01 (cont): the operator-facing path. --sign, SYSTEM_BOOT_KEY and
// EVIDENCE_SIGNING_KEY all arrive as arbitrary strings; whichever form they take
// they must yield the same keypair on every run, or no previously issued receipt
// survives a restart.
func TestF01_SignerFromSecretIsDeterministicForEveryInputShape(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i * 7)
	}

	cases := []struct {
		name        string
		secret      string
		wantDerived bool
	}{
		{"hex seed", hex.EncodeToString(seed), false},
		{"base64 seed", base64.StdEncoding.EncodeToString(seed), false},
		{"passphrase", "correct horse battery staple", true},
		{"legacy label", "helm-evidence-bundle", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			first, derived, err := NewEd25519SignerFromSecret(tc.secret, "trust-root")
			if err != nil {
				t.Fatalf("NewEd25519SignerFromSecret: %v", err)
			}
			second, _, err := NewEd25519SignerFromSecret(tc.secret, "trust-root")
			if err != nil {
				t.Fatalf("NewEd25519SignerFromSecret: %v", err)
			}

			if first.PublicKey() != second.PublicKey() {
				t.Fatalf("same secret produced different public keys — trust root is not stable")
			}
			if derived != tc.wantDerived {
				t.Fatalf("derivedFromPassphrase = %v, want %v (operators must be warned about low-entropy secrets)",
					derived, tc.wantDerived)
			}
			if strings.Contains(first.GetKeyID(), tc.secret) {
				t.Fatal("the secret leaked into the key id, which is published in every receipt")
			}
		})
	}

	// Different secrets must not collide onto one identity.
	a, _, _ := NewEd25519SignerFromSecret("secret-a", "k")
	b, _, _ := NewEd25519SignerFromSecret("secret-b", "k")
	if a.PublicKey() == b.PublicKey() {
		t.Fatal("distinct secrets produced the same keypair")
	}
}

// F-01 (cont): an ephemeral signer must fail closed in production rather than
// silently minting a throwaway trust root.
func TestF01_EphemeralSignerRejectedInProduction(t *testing.T) {
	t.Setenv("HELM_PRODUCTION", "1")

	if _, err := NewEd25519Signer("evidence-key"); err == nil {
		t.Fatal("NewEd25519Signer returned an ephemeral signer under HELM_PRODUCTION=1; " +
			"it must fail closed so operators cannot ship an unstable trust root")
	}
}

// F-01 (cont): the key *identifier* must never carry key material into receipts.
// Callers previously passed the secret itself, which signer.go wrote into
// Receipt.KeyID in cleartext.
func TestF01_SeedIsNotLeakedAsKeyID(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand: %v", err)
	}
	signer, err := NewEd25519SignerFromSeed(seed, "release-signer")
	if err != nil {
		t.Fatalf("NewEd25519SignerFromSeed: %v", err)
	}

	if signer.GetKeyID() == hex.EncodeToString(seed) {
		t.Fatal("signer key id equals the seed — secret material would be published in every receipt")
	}
}

// F-07: Verify() hashed pubKeyHex ‖ sigHex ‖ data with no length prefixes and
// consulted a process-global cache BEFORE decoding or length-checking its
// inputs. Shifting bytes across the signature/data boundary produced an
// identical cache key, so a forged (signature, message) pair inherited the
// cached `true` of a genuine one without any ed25519 verification.
func TestF07_VerifyCannotBeForgedByCacheKeyCollision(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubHex := hex.EncodeToString(pub)

	// A genuine verification, which is what primed the cache in the original bug.
	genuineData := []byte("AB:decision-1:effect-1:OK")
	genuineSig := hex.EncodeToString(ed25519.Sign(priv, genuineData))

	ok, err := Verify(pubHex, genuineSig, genuineData)
	if err != nil {
		t.Fatalf("genuine verify errored: %v", err)
	}
	if !ok {
		t.Fatal("genuine signature failed to verify — test setup is wrong")
	}

	// Move the first two message characters onto the tail of the signature.
	// sigHex was hashed as a string and data as raw bytes, so appending them
	// literally kept H(pub ‖ sig ‖ data) byte-identical and the cache key matched.
	// Verified against unmodified main: this returned true with a 65-byte signature.
	forgedSig := genuineSig + string(genuineData[:2])
	forgedData := genuineData[2:]

	forgedOK, _ := Verify(pubHex, forgedSig, forgedData)
	if forgedOK {
		t.Fatal("a forged (signature, message) pair verified — the cache key is ambiguous " +
			"and is consulted before input validation, so ed25519.Verify never ran")
	}
}

// F-07 (cont): the same unframed-concatenation collision applied to
// Ed25519Verifier.Verify, which keyed on sha256(message ‖ signature).
func TestF07_VerifierStructCannotBeForgedByCacheKeyCollision(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	v, err := NewEd25519Verifier(pub)
	if err != nil {
		t.Fatalf("NewEd25519Verifier: %v", err)
	}

	msg := []byte("receipt-1:decision-1:ALLOW")
	sig := ed25519.Sign(priv, msg)
	if !v.Verify(msg, sig) {
		t.Fatal("genuine signature failed to verify — test setup is wrong")
	}

	// Shift the first signature byte onto the end of the message so that
	// forgedMsg ‖ forgedSig == msg ‖ sig. Verified against unmodified main:
	// this returned true with a 63-byte signature over a tampered message.
	forgedMsg := append(append([]byte{}, msg...), sig[0])
	forgedSig := sig[1:]

	if v.Verify(forgedMsg, forgedSig) {
		t.Fatal("Ed25519Verifier accepted a truncated signature over a tampered message")
	}
}

// F-07 (cont): malformed input must be rejected on its own merits, never served
// from a cache populated by a different call.
func TestF07_VerifyRejectsMalformedInputsBeforeAnyCacheHit(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubHex := hex.EncodeToString(pub)
	data := []byte("receipt-1:decision-1")
	sig := hex.EncodeToString(ed25519.Sign(priv, data))

	if _, err := Verify(pubHex, sig, data); err != nil {
		t.Fatalf("genuine verify errored: %v", err)
	}

	// Oversized signature: must be rejected on length, not answered from cache.
	if ok, err := Verify(pubHex, sig+"00", data); ok || err == nil {
		t.Fatalf("oversized signature accepted (ok=%v err=%v); length checks must precede any lookup", ok, err)
	}

	// Truncated public key: must be rejected on size.
	if ok, err := Verify(pubHex[:len(pubHex)-2], sig, data); ok || err == nil {
		t.Fatalf("undersized public key accepted (ok=%v err=%v)", ok, err)
	}
}

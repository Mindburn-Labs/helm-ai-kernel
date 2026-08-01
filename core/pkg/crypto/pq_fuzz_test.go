package crypto

// quantum_posture: fuzz coverage for the ML-DSA-65 and hybrid signing paths;
// these are test-only guardrails, not cryptographic controls.
//
// Fuzz targets for the post-quantum signing surfaces: ML-DSA-65 (FIPS 204,
// mldsa_signer.go / mldsa_verifier.go) and the Ed25519+ML-DSA-65 composite
// envelope (hybrid_signer.go / hybrid_verifier.go). Signature bytes, public
// keys and envelopes all arrive from the wire, so the invariants asserted
// here are the two that matter at a trust boundary: never panic, and never
// accept anything the honest key did not produce.
//
// There is deliberately no ML-KEM target: the kernel has no ML-KEM
// implementation. The only ML-KEM in-tree is tls.X25519MLKEM768 in
// core/pkg/crypto/tls, a Go stdlib curve preference with no kernel-owned
// encapsulation code to fuzz.

import (
	"encoding/hex"
	"strings"
	"testing"
)

// FuzzMLDSASignVerify fuzzes the ML-DSA-65 signing round-trip.
// Invariants:
//   - Sign never fails and never emits a non-hex signature, whatever the message
//   - a signature verifies over the message it was produced for
//   - a single flipped bit in the signature does not verify
//   - the signature does not carry over to a different message
func FuzzMLDSASignVerify(f *testing.F) {
	f.Add([]byte("verdict:allow|effect:deploy"))
	f.Add([]byte{})
	f.Add([]byte("unicode 你好世界 🚀"))
	f.Add([]byte{0x00, 0x01, 0x02, 0xff})

	// Keygen once per process: ML-DSA-65 key generation dwarfs a single
	// sign/verify, so doing it per iteration would starve the fuzzer.
	signer, err := NewMLDSASigner("fuzz-mldsa-signer")
	if err != nil {
		f.Fatalf("ml-dsa-65 keygen: %v", err)
	}

	f.Fuzz(func(t *testing.T, msg []byte) {
		sigHex, err := signer.Sign(msg)
		if err != nil {
			t.Fatalf("sign over %d bytes failed: %v", len(msg), err)
		}
		sig, err := hex.DecodeString(sigHex)
		if err != nil {
			t.Fatalf("signer emitted a non-hex signature: %v", err)
		}
		if !signer.Verify(msg, sig) {
			t.Fatal("ml-dsa-65 signature did not verify over the message it signed")
		}

		tampered := make([]byte, len(sig))
		copy(tampered, sig)
		tampered[len(tampered)/2] ^= 0x01
		if signer.Verify(msg, tampered) {
			t.Fatal("tampered ml-dsa-65 signature verified")
		}

		extended := make([]byte, 0, len(msg)+1)
		extended = append(append(extended, msg...), '.')
		if signer.Verify(extended, sig) {
			t.Fatal("ml-dsa-65 signature verified over a different message")
		}
	})
}

// FuzzMLDSAVerifyUntrusted fuzzes ML-DSA-65 verification in its production
// shape: the public key is honest and fixed (it comes from the receipt's
// PublicKeySet), the signature and message come from the wire.
// Invariants:
//   - VerifyMLDSA65 and NewMLDSAVerifier never panic on arbitrary input
//   - no signature the fuzzer produces verifies under the honest key
//   - a public key of the wrong size is rejected, never accepted
func FuzzMLDSAVerifyUntrusted(f *testing.F) {
	signer, err := NewMLDSASigner("fuzz-mldsa-verifier")
	if err != nil {
		f.Fatalf("ml-dsa-65 keygen: %v", err)
	}
	pubHex := signer.PublicKey()
	pubSize := len(signer.PublicKeyBytes())

	// The one authentic pair in the corpus: seeded so the fuzzer starts from a
	// structurally valid signature, and excused below so a mutation that
	// happens to restore it is not reported as a forgery.
	const authenticMsg = "fuzz corpus authentic ml-dsa-65 message"
	authenticSig, err := signer.Sign([]byte(authenticMsg))
	if err != nil {
		f.Fatalf("sign: %v", err)
	}

	f.Add(authenticSig, []byte("a different message"))
	f.Add(authenticSig[:len(authenticSig)-2], []byte(authenticMsg))
	f.Add("", []byte(""))
	f.Add("zz", []byte("not hex"))
	f.Add(strings.Repeat("00", 32), []byte("short signature"))

	f.Fuzz(func(t *testing.T, sigHex string, msg []byte) {
		ok, err := VerifyMLDSA65(pubHex, sigHex, msg)
		if ok && err != nil {
			t.Fatalf("ml-dsa-65 reported valid and errored at once: %v", err)
		}
		if ok && !(sigHex == authenticSig && string(msg) == authenticMsg) {
			t.Fatal("ml-dsa-65 accepted a signature the honest key never produced")
		}

		// Feed the same untrusted bytes in as key material: NewMLDSAVerifier
		// is the only length gate before the key is unmarshalled.
		raw, decErr := hex.DecodeString(sigHex)
		if decErr != nil {
			return
		}
		v, err := NewMLDSAVerifier(raw)
		if err != nil {
			return
		}
		if len(raw) != pubSize {
			t.Fatalf("accepted a %d-byte ml-dsa-65 public key (want %d)", len(raw), pubSize)
		}
		if v == nil {
			t.Fatal("nil ml-dsa-65 verifier without an error")
		}
		_ = v.Verify(msg, raw)
	})
}

// FuzzHybridEnvelopeVerify fuzzes the composite envelope parser and the
// fail-closed hybrid verification path. The envelope
// "hybrid:<128 hex chars>:<mldsa hex>" is split with raw index arithmetic over
// an attacker-controlled string (parseHybridSignature).
// Invariants:
//   - parsing never panics, whatever the envelope
//   - no envelope the fuzzer produces verifies under the honest key pair — in
//     particular a valid Ed25519 half never carries a broken ML-DSA half,
//     there is no downgrade to classical-only acceptance
//   - profile detection always returns a known profile
func FuzzHybridEnvelopeVerify(f *testing.F) {
	signer, err := NewHybridSigner("fuzz-hybrid")
	if err != nil {
		f.Fatalf("hybrid keygen: %v", err)
	}
	verifier, err := NewHybridVerifier(
		signer.Ed25519Signer().PublicKeyBytes(),
		signer.MLDSASigner().PublicKeyBytes(),
	)
	if err != nil {
		f.Fatalf("hybrid verifier: %v", err)
	}

	const authenticMsg = "fuzz corpus authentic hybrid message"
	authentic, err := signer.Sign([]byte(authenticMsg))
	if err != nil {
		f.Fatalf("hybrid sign: %v", err)
	}

	// "hybrid:<ed25519 hex>" with the post-quantum half removed — the
	// downgrade attempt the verifier must refuse.
	const ed25519HexLen = 128
	edOnly := authentic[:len(HybridSigPrefix)+len(HybridSigSeparator)+ed25519HexLen]

	f.Add(authentic, []byte("a different message"))
	f.Add(edOnly, []byte(authenticMsg))
	f.Add(edOnly+HybridSigSeparator, []byte(authenticMsg))
	f.Add(authentic[:len(authentic)-2], []byte(authenticMsg))
	f.Add(strings.Replace(authentic, "hybrid:", "Hybrid:", 1), []byte(authenticMsg))
	f.Add("hybrid:", []byte(""))
	f.Add("", []byte(""))

	f.Fuzz(func(t *testing.T, envelope string, msg []byte) {
		if verifier.Verify(msg, []byte(envelope)) &&
			!(envelope == authentic && string(msg) == authenticMsg) {
			t.Fatal("hybrid verifier accepted an envelope the honest keys never produced")
		}

		// Profile detection reads the same untrusted string.
		switch p := ReceiptSignatureProfile(envelope); p {
		case ReceiptProfileHybrid, ReceiptProfileClassical:
		default:
			t.Fatalf("unknown receipt signature profile %q", p)
		}
	})
}

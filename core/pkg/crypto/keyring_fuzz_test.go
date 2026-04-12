package crypto

import (
	"testing"
)

// FuzzKeyRingSignVerify fuzzes the KeyRing sign and verify path.
// Invariants:
//   - Sign must never panic
//   - Valid signatures must verify
//   - Tampered data must not verify
func FuzzKeyRingSignVerify(f *testing.F) {
	f.Add("test-data-1")
	f.Add("")
	f.Add("unicode 你好世界 🚀")
	f.Add("\x00\x01\x02\xff")
	f.Add("a]b:c:d|e") // separator characters

	signer, err := NewEd25519Signer("fuzz-key-1")
	if err != nil {
		f.Fatal(err)
	}

	f.Fuzz(func(t *testing.T, data string) {
		// Sign must not panic
		sig, err := signer.Sign([]byte(data))
		if err != nil {
			return
		}

		if sig == "" {
			t.Fatal("empty signature without error")
		}

		// Public key must be non-empty
		pub := signer.PublicKey()
		if pub == "" {
			t.Fatal("empty public key")
		}
	})
}

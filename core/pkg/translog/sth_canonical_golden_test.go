// quantum_posture: these goldens pin canonical signed-tree-head bytes and a
// classical Ed25519 signature over them from a fixed seed. They assert byte
// stability of the preimage only and claim no hybrid or post-quantum
// assurance for the transparency log.
package translog

import (
	"bytes"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// The signed tree head is the only signed artifact that went through
// crypto.CanonicalMarshal, the second canonical-JSON encoder that has now been
// folded into canonicalize.JCS. This test pins the exact signed bytes and the
// resulting Ed25519 signature from a fixed seed, so the fold is verifiably a
// no-op and any future canonicalizer change surfaces as a re-sign decision
// rather than a silent one.
//
// The signature below is reproducible by any Ed25519 implementation:
//
//	seed      = 32 bytes of 0x2a
//	message   = the sthCanonicalGolden bytes, verbatim, no trailing newline
//	signature = lowercase hex of ed25519(seed).Sign(message)
const (
	sthCanonicalGolden = `{"log_id":"5f3c1a9b","root_hash":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08","timestamp":"2026-08-06T00:00:00Z","tree_size":7}`
)

func sthGoldenSigner(t *testing.T) *crypto.Ed25519Signer {
	t.Helper()
	seed := bytes.Repeat([]byte{0x2a}, 32)
	signer, err := crypto.NewEd25519SignerFromSeed(seed, "sth-golden")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

func TestSTHSigningBytesAreCanonicalGolden(t *testing.T) {
	sth := &SignedTreeHead{
		TreeSize:  7,
		RootHash:  "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		Timestamp: "2026-08-06T00:00:00Z",
		LogID:     "5f3c1a9b",
	}
	got, err := sth.SigningBytes()
	if err != nil {
		t.Fatalf("SigningBytes: %v", err)
	}
	if string(got) != sthCanonicalGolden {
		t.Fatalf("STH signed bytes changed — this invalidates every published tree head\n got: %s\nwant: %s", got, sthCanonicalGolden)
	}
	if bytes.HasSuffix(got, []byte("\n")) {
		t.Fatal("STH signed bytes must not carry a trailing newline")
	}
}

func TestSTHSignatureIsReproducibleFromAFixedSeed(t *testing.T) {
	signer := sthGoldenSigner(t)
	root := [HashSize]byte{}
	rootBytes := []byte{
		0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65,
		0x9a, 0x2f, 0xea, 0xa0, 0xc5, 0x5a, 0xd0, 0x15,
		0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b, 0x82, 0x2c,
		0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08,
	}
	copy(root[:], rootBytes)

	when, err := time.Parse(time.RFC3339, "2026-08-06T00:00:00Z")
	if err != nil {
		t.Fatalf("parse time: %v", err)
	}
	sth, err := SignTreeHead(signer, "5f3c1a9b", 7, root, when)
	if err != nil {
		t.Fatalf("SignTreeHead: %v", err)
	}

	payload, err := sth.SigningBytes()
	if err != nil {
		t.Fatalf("SigningBytes: %v", err)
	}
	if string(payload) != sthCanonicalGolden {
		t.Fatalf("signed payload drifted\n got: %s\nwant: %s", payload, sthCanonicalGolden)
	}
	if err := VerifyTreeHead(sth, signer.PublicKey()); err != nil {
		t.Fatalf("VerifyTreeHead: %v", err)
	}

	// A third party reproduces this pair from the seed and the payload alone.
	const (
		wantPublicKey = "197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61"
		wantSignature = "ceb3ca17ae7e136bae670818fcf9e32b08c7f6f931e65111fd0ecb127b595c4c" +
			"74fdef9b0f06caf22d64f486a702e5d252503a6993fdd61735e9f7eab273b40c"
	)
	if sth.PublicKey != wantPublicKey {
		t.Fatalf("public key drifted: got %s want %s", sth.PublicKey, wantPublicKey)
	}
	if sth.Signature != wantSignature {
		t.Fatalf("signature over the canonical payload drifted — canonical bytes or the signer changed\n got: %s\nwant: %s", sth.Signature, wantSignature)
	}
}

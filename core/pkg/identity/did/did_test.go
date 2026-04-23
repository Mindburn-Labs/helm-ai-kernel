package did

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testPubKey is a well-known 32-byte Ed25519 public key for testing.
var testPubKey = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
}

func TestFromEd25519PublicKey(t *testing.T) {
	d, err := FromEd25519PublicKey(testPubKey)
	require.NoError(t, err)

	s := d.String()
	assert.True(t, len(s) > len("did:key:z"), "DID should be longer than prefix")
	assert.Contains(t, s, "did:key:z")
}

func TestFromEd25519PublicKey_WrongLength(t *testing.T) {
	_, err := FromEd25519PublicKey([]byte{0x01, 0x02, 0x03})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "32 bytes")
}

func TestRoundTrip(t *testing.T) {
	// Create DID from public key.
	d1, err := FromEd25519PublicKey(testPubKey)
	require.NoError(t, err)

	// Extract the public key from the DID.
	extracted, err := d1.PublicKeyBytes()
	require.NoError(t, err)
	assert.True(t, bytes.Equal(testPubKey, extracted), "round-trip: extracted key must equal original")

	// Recreate a DID from the extracted key — must be identical.
	d2, err := FromEd25519PublicKey(extracted)
	require.NoError(t, err)
	assert.Equal(t, d1, d2, "round-trip: recreated DID must equal original")
}

func TestValidate_WellFormed(t *testing.T) {
	d, err := FromEd25519PublicKey(testPubKey)
	require.NoError(t, err)
	assert.NoError(t, d.Validate())
}

func TestValidate_Malformed(t *testing.T) {
	tests := []struct {
		name string
		did  DID
		want string
	}{
		{"empty", DID(""), "empty DID"},
		{"no did prefix", DID("key:z6Mk"), "expected prefix"},
		{"wrong method", DID("did:web:example.com"), "expected prefix"},
		{"missing key", DID("did:key:"), "missing multibase"},
		{"wrong multibase", DID("did:key:f01"), "unsupported multibase prefix"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.did.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestDocument(t *testing.T) {
	d, err := FromEd25519PublicKey(testPubKey)
	require.NoError(t, err)

	doc, err := d.Document()
	require.NoError(t, err)
	require.NotNil(t, doc)

	// Context
	assert.Equal(t, []string{"https://www.w3.org/ns/did/v1"}, doc.Context)

	// ID matches the DID
	assert.Equal(t, d.String(), doc.ID)

	// Verification method
	require.Len(t, doc.VerificationMethod, 1)
	vm := doc.VerificationMethod[0]
	assert.Equal(t, ed25519VerificationKey2020, vm.Type)
	assert.Equal(t, d.String(), vm.Controller)
	assert.True(t, len(vm.PublicKeyMultibase) > 0)
	assert.Equal(t, byte('z'), vm.PublicKeyMultibase[0], "multibase prefix should be 'z'")

	// Authentication references verification method
	require.Len(t, doc.Authentication, 1)
	assert.Equal(t, vm.ID, doc.Authentication[0])

	// Assertion method
	require.Len(t, doc.AssertionMethod, 1)
	assert.Equal(t, vm.ID, doc.AssertionMethod[0])
}

func TestMethod(t *testing.T) {
	d, err := FromEd25519PublicKey(testPubKey)
	require.NoError(t, err)
	assert.Equal(t, "key", d.Method())
}

func TestMethod_Invalid(t *testing.T) {
	assert.Equal(t, "", DID("").Method())
	assert.Equal(t, "", DID("notadid").Method())
}

func TestFromHexPublicKey(t *testing.T) {
	hexKey := hex.EncodeToString(testPubKey)

	d, err := FromHexPublicKey(hexKey)
	require.NoError(t, err)

	// Should produce the same DID as FromEd25519PublicKey.
	d2, err := FromEd25519PublicKey(testPubKey)
	require.NoError(t, err)
	assert.Equal(t, d2, d)
}

func TestFromHexPublicKey_InvalidHex(t *testing.T) {
	_, err := FromHexPublicKey("not-valid-hex!!")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid hex")
}

func TestFromHexPublicKey_WrongLength(t *testing.T) {
	_, err := FromHexPublicKey("abcd")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "32 bytes")
}

func TestPublicKeyBytes_InvalidDID(t *testing.T) {
	_, err := DID("did:key:zINVALID").PublicKeyBytes()
	// Should fail during base58 decode or multicodec check.
	require.Error(t, err)
}

func TestBase58_RoundTrip(t *testing.T) {
	data := []byte{0xed, 0x01, 0xaa, 0xbb, 0xcc, 0xdd}
	encoded := encodeBase58(data)
	decoded, err := decodeBase58(encoded)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(data, decoded))
}

func TestBase58_LeadingZeros(t *testing.T) {
	data := []byte{0x00, 0x00, 0x01, 0x02}
	encoded := encodeBase58(data)
	decoded, err := decodeBase58(encoded)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(data, decoded))
}

func TestBase58_Empty(t *testing.T) {
	assert.Equal(t, "", encodeBase58(nil))
	decoded, err := decodeBase58("")
	require.NoError(t, err)
	assert.Equal(t, []byte{}, decoded)
}

func TestBase58_InvalidCharacter(t *testing.T) {
	_, err := decodeBase58("0OIl") // 0, O, I, l are not in base58
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid base58 character")
}

func TestDID_String(t *testing.T) {
	d := DID("did:key:z6MkTest")
	assert.Equal(t, "did:key:z6MkTest", d.String())
}

func TestDID_AllZeroKey(t *testing.T) {
	zeroKey := make([]byte, 32)
	d, err := FromEd25519PublicKey(zeroKey)
	require.NoError(t, err)

	extracted, err := d.PublicKeyBytes()
	require.NoError(t, err)
	assert.True(t, bytes.Equal(zeroKey, extracted))
}

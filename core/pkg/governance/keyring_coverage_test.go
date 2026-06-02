package governance

import "testing"

func TestKeyringNilProviderFallbackAndMarshalError(t *testing.T) {
	keyring := NewKeyring(nil)
	if len(keyring.PublicKey()) == 0 {
		t.Fatal("nil provider fallback should create a public key")
	}

	_, err := keyring.Sign(func() {})
	if err == nil {
		t.Fatal("non-marshalable payload should fail signing")
	}
}

func TestKeyringDeriveForTenantRejectsEmptyTenant(t *testing.T) {
	keyring := NewKeyring(nil)
	_, err := keyring.DeriveForTenant("")
	if err == nil {
		t.Fatal("empty tenantID should fail")
	}
}

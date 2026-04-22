package trust

import (
	"crypto"
	"crypto/ed25519"
	"testing"
)

func TestDeadcodeCoverage_TUFClient_UpdateAndDelegation(t *testing.T) {
	pub := ed25519.NewKeyFromSeed(make([]byte, 32)).Public()

	client, err := NewTUFClient(TUFClientConfig{
		RemoteURL: "https://tuf.example.invalid",
		RootKeys:  []crypto.PublicKey{pub},
	})
	if err != nil {
		t.Fatalf("NewTUFClient: %v", err)
	}

	if err := client.Update(); err == nil {
		t.Fatal("expected Update to fail until fetchAndVerify is implemented")
	}
	if err := client.VerifyDelegation("certified", "pack.ops.starter"); err == nil {
		t.Fatal("expected VerifyDelegation to fail without targets metadata")
	}
}

package trust

import (
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDeadcodeCoverage_TUFClient_UpdateAndDelegation(t *testing.T) {
	pub := ed25519.NewKeyFromSeed(make([]byte, 32)).Public()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), ".json")
		_ = json.NewEncoder(w).Encode(SignedRole{
			Signed: mustMarshal(RoleMetadata{
				Type:    role,
				Version: 1,
				Expires: time.Now().Add(time.Hour),
			}),
			Signatures: []TUFSignature{{KeyID: "root", Signature: "sig"}},
		})
	}))
	defer server.Close()

	client, err := NewTUFClient(TUFClientConfig{
		RemoteURL: server.URL,
		RootKeys:  []crypto.PublicKey{pub},
	})
	if err != nil {
		t.Fatalf("NewTUFClient: %v", err)
	}

	if err := client.Update(); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	if err := client.VerifyDelegation("certified", "pack.ops.starter"); err == nil {
		t.Fatal("expected VerifyDelegation to fail without targets metadata")
	}
}

package trust

import (
	"crypto"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDeadcodeCoverage_TUFClient_UpdateAndDelegation(t *testing.T) {
	pub, _ := tufTestRootKey()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), ".json")
		_ = json.NewEncoder(w).Encode(signedRoleForTUFTest(role, 1, time.Now().Add(time.Hour), nil))
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

package trust

import (
	"crypto"
	"encoding/json"
	"testing"
	"time"
)

func TestNewTUFClient(t *testing.T) {
	t.Run("requires remote URL", func(t *testing.T) {
		_, err := NewTUFClient(TUFClientConfig{})
		if err == nil {
			t.Error("expected error for missing remote URL")
		}
	})

	t.Run("requires root keys", func(t *testing.T) {
		_, err := NewTUFClient(TUFClientConfig{
			RemoteURL: "https://example.com/tuf",
		})
		if err == nil {
			t.Error("expected error for missing root keys")
		}
	})

	t.Run("creates client with valid config", func(t *testing.T) {
		client, err := NewTUFClient(TUFClientConfig{
			RemoteURL: "https://example.com/tuf",
			RootKeys:  []crypto.PublicKey{mockPublicKey{}},
		})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if client == nil {
			t.Error("expected non-nil client")
		}
	})
}

type mockPublicKey struct{}

// Equal implements crypto.PublicKey interface (Go 1.20+)
func (m mockPublicKey) Equal(x crypto.PublicKey) bool {
	_, ok := x.(mockPublicKey)
	return ok
}

func TestTUFClient_GetTargetInfo(t *testing.T) {
	// Create client with mock metadata
	client := &TUFClient{
		localMetadata: &TUFMetadata{
			Targets: &SignedRole{
				Signed: json.RawMessage(`{
					"_type": "targets",
					"version": 1,
					"expires": "2027-01-01T00:00:00Z",
					"targets": {
						"org.example/my-pack": {
							"length": 12345,
							"hashes": {"sha256": "abc123def456"}
						}
					}
				}`),
			},
		},
	}

	t.Run("finds existing target", func(t *testing.T) {
		info, err := client.GetTargetInfo("org.example/my-pack")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if info == nil {
			t.Fatal("expected non-nil target info")
		}
		if info.Hashes["sha256"] != "abc123def456" {
			t.Errorf("wrong hash: %s", info.Hashes["sha256"])
		}
	})

	t.Run("returns error for missing target", func(t *testing.T) {
		_, err := client.GetTargetInfo("org.example/nonexistent")
		if err == nil {
			t.Error("expected error for missing target")
		}
	})
}

func TestTUFClient_checkFreshness(t *testing.T) {
	client := &TUFClient{}

	t.Run("accepts fresh metadata", func(t *testing.T) {
		future := time.Now().Add(24 * time.Hour)
		signed := &SignedRole{
			Signed: mustMarshal(RoleMetadata{
				Type:    "timestamp",
				Version: 1,
				Expires: future,
			}),
		}

		err := client.checkFreshness(signed)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("rejects expired metadata", func(t *testing.T) {
		past := time.Now().Add(-24 * time.Hour)
		signed := &SignedRole{
			Signed: mustMarshal(RoleMetadata{
				Type:    "timestamp",
				Version: 1,
				Expires: past,
			}),
		}

		err := client.checkFreshness(signed)
		if err == nil {
			t.Error("expected error for expired metadata")
		}
	})
}

func TestTUFClient_verifyVersionIncrease(t *testing.T) {
	client := &TUFClient{}

	t.Run("allows version increase", func(t *testing.T) {
		oldRole := &SignedRole{
			Signed: mustMarshal(RoleMetadata{Version: 1}),
		}
		newRole := &SignedRole{
			Signed: mustMarshal(RoleMetadata{Version: 2}),
		}

		err := client.verifyVersionIncrease(newRole, oldRole)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("detects rollback", func(t *testing.T) {
		oldRole := &SignedRole{
			Signed: mustMarshal(RoleMetadata{Version: 5}),
		}
		newRole := &SignedRole{
			Signed: mustMarshal(RoleMetadata{Version: 3}),
		}

		err := client.verifyVersionIncrease(newRole, oldRole)
		if err == nil {
			t.Error("expected error for version rollback")
		}
	})
}

func TestMatchesPattern(t *testing.T) {
	tests := []struct {
		pattern  string
		packName string
		want     bool
	}{
		{"*", "anything", true},
		{"my-pack", "my-pack", true},
		{"my-pack", "other-pack", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.packName, func(t *testing.T) {
			got := matchesPattern(tt.pattern, tt.packName)
			if got != tt.want {
				t.Errorf("matchesPattern(%q, %q) = %v, want %v",
					tt.pattern, tt.packName, got, tt.want)
			}
		})
	}
}

func mustMarshal(v interface{}) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

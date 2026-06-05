package trust

import (
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

	t.Run("loads metadata from trust store", func(t *testing.T) {
		stored := &TUFMetadata{Targets: &SignedRole{Signed: mustMarshal(TargetsMetadata{})}}
		client, err := NewTUFClient(TUFClientConfig{
			RemoteURL:  "https://example.com/tuf",
			RootKeys:   []crypto.PublicKey{mockPublicKey{}},
			TrustStore: &memoryTUFTrustStore{metadata: stored},
		})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if client.localMetadata != stored {
			t.Fatal("expected stored metadata to be loaded")
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

	t.Run("returns error without targets metadata", func(t *testing.T) {
		_, err := (&TUFClient{}).GetTargetInfo("org.example/my-pack")
		if err == nil {
			t.Fatal("expected missing metadata error")
		}
	})

	t.Run("returns error for malformed targets metadata", func(t *testing.T) {
		bad := &TUFClient{localMetadata: &TUFMetadata{Targets: &SignedRole{Signed: []byte(`{`)}}}
		if _, err := bad.GetTargetInfo("org.example/my-pack"); err == nil {
			t.Fatal("expected malformed targets error")
		}
	})
}

func TestTUFClient_checkFreshness(t *testing.T) {
	client := &TUFClient{}

	t.Run("rejects nil role", func(t *testing.T) {
		if err := client.checkFreshness(nil); err == nil {
			t.Fatal("expected nil role error")
		}
	})

	t.Run("rejects malformed role", func(t *testing.T) {
		if err := client.checkFreshness(&SignedRole{Signed: []byte(`{`)}); err == nil {
			t.Fatal("expected malformed role error")
		}
	})

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

	t.Run("allows nil existing role", func(t *testing.T) {
		err := client.verifyVersionIncrease(&SignedRole{Signed: mustMarshal(RoleMetadata{Version: 1})}, nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("rejects malformed new role", func(t *testing.T) {
		err := client.verifyVersionIncrease(&SignedRole{Signed: []byte(`{`)}, &SignedRole{Signed: mustMarshal(RoleMetadata{Version: 1})})
		if err == nil {
			t.Fatal("expected malformed new role error")
		}
	})

	t.Run("rejects malformed existing role", func(t *testing.T) {
		err := client.verifyVersionIncrease(&SignedRole{Signed: mustMarshal(RoleMetadata{Version: 2})}, &SignedRole{Signed: []byte(`{`)})
		if err == nil {
			t.Fatal("expected malformed existing role error")
		}
	})

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

func TestTUFClient_UpdateEdges(t *testing.T) {
	t.Run("fails on expired timestamp", func(t *testing.T) {
		server := newTUFMetadataServer(t, map[string]*SignedRole{
			"timestamp": signedRoleForTUFTest("timestamp", 1, time.Now().Add(-time.Hour), nil),
		})
		client := newTUFHTTPClientForTest(server.URL)
		if err := client.Update(); err == nil {
			t.Fatal("expected expired timestamp error")
		}
	})

	t.Run("fails on snapshot fetch error", func(t *testing.T) {
		server := newTUFMetadataServer(t, map[string]*SignedRole{
			"timestamp": signedRoleForTUFTest("timestamp", 1, time.Now().Add(time.Hour), nil),
		})
		client := newTUFHTTPClientForTest(server.URL)
		if err := client.Update(); err == nil {
			t.Fatal("expected snapshot fetch error")
		}
	})

	t.Run("fails on targets fetch error", func(t *testing.T) {
		server := newTUFMetadataServer(t, map[string]*SignedRole{
			"timestamp": signedRoleForTUFTest("timestamp", 1, time.Now().Add(time.Hour), nil),
			"snapshot":  signedRoleForTUFTest("snapshot", 1, time.Now().Add(time.Hour), nil),
		})
		client := newTUFHTTPClientForTest(server.URL)
		if err := client.Update(); err == nil {
			t.Fatal("expected targets fetch error")
		}
	})

	t.Run("detects snapshot rollback", func(t *testing.T) {
		server := newTUFMetadataServer(t, map[string]*SignedRole{
			"timestamp": signedRoleForTUFTest("timestamp", 1, time.Now().Add(time.Hour), nil),
			"snapshot":  signedRoleForTUFTest("snapshot", 1, time.Now().Add(time.Hour), nil),
		})
		client := newTUFHTTPClientForTest(server.URL)
		client.localMetadata = &TUFMetadata{Snapshot: signedRoleForTUFTest("snapshot", 5, time.Now().Add(time.Hour), nil)}
		if err := client.Update(); err == nil {
			t.Fatal("expected rollback error")
		}
	})

	t.Run("fails when trust store save fails", func(t *testing.T) {
		targets := TargetsMetadata{
			RoleMetadata: RoleMetadata{Type: "targets", Version: 1, Expires: time.Now().Add(time.Hour)},
			Targets:      map[string]TargetInfo{},
		}
		server := newTUFMetadataServer(t, map[string]*SignedRole{
			"timestamp": signedRoleForTUFTest("timestamp", 1, time.Now().Add(time.Hour), nil),
			"snapshot":  signedRoleForTUFTest("snapshot", 1, time.Now().Add(time.Hour), nil),
			"targets":   signedRoleForTUFTest("targets", 1, time.Now().Add(time.Hour), targets),
		})
		store := &memoryTUFTrustStore{saveErr: errors.New("save failed")}
		client := newTUFHTTPClientForTest(server.URL)
		client.trustStore = store
		previousMetadata := &TUFMetadata{Snapshot: signedRoleForTUFTest("snapshot", 0, time.Now().Add(time.Hour), nil)}
		client.localMetadata = previousMetadata
		if err := client.Update(); err == nil {
			t.Fatal("expected save error")
		}
		if !store.saved {
			t.Fatal("expected save to be attempted")
		}
		if client.localMetadata != previousMetadata {
			t.Fatal("local metadata should not advance when persistence fails")
		}
	})
}

func TestTUFClient_fetchAndVerifyEdges(t *testing.T) {
	tests := []struct {
		name     string
		response func(http.ResponseWriter, *http.Request)
		noKeys   bool
	}{
		{
			name: "non-success status",
			response: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "broken", http.StatusInternalServerError)
			},
		},
		{
			name: "bad response json",
			response: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("{"))
			},
		},
		{
			name: "missing signed payload",
			response: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"signatures":[{"keyid":"root","sig":"sig"}]}`))
			},
		},
		{
			name: "missing signatures",
			response: func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(SignedRole{Signed: mustMarshal(RoleMetadata{Type: "timestamp", Expires: time.Now().Add(time.Hour)})})
			},
		},
		{
			name: "malformed role metadata",
			response: func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(SignedRole{Signed: []byte(`"not-object"`), Signatures: []TUFSignature{{KeyID: "root", Signature: "sig"}}})
			},
		},
		{
			name: "type mismatch",
			response: func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(SignedRole{Signed: mustMarshal(RoleMetadata{Type: "snapshot", Expires: time.Now().Add(time.Hour)}), Signatures: []TUFSignature{{KeyID: "root", Signature: "sig"}}})
			},
		},
		{
			name: "missing root keys",
			response: func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(SignedRole{Signed: mustMarshal(RoleMetadata{Type: "timestamp", Expires: time.Now().Add(time.Hour)}), Signatures: []TUFSignature{{KeyID: "root", Signature: "sig"}}})
			},
			noKeys: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(tt.response))
			defer server.Close()
			client := newTUFHTTPClientForTest(server.URL)
			if tt.noKeys {
				client.rootKeys = nil
			}
			if _, err := client.fetchAndVerify(TUFRoleTimestamp); err == nil {
				t.Fatal("expected fetchAndVerify error")
			}
		})
	}
}

func TestTUFClient_fetchAndVerifyRejectsTamperedSignature(t *testing.T) {
	role := signedRoleForTUFTest("timestamp", 1, time.Now().Add(time.Hour), nil)
	role.Signed = mustMarshal(RoleMetadata{Type: "timestamp", Version: 2, Expires: time.Now().Add(time.Hour)})
	server := newTUFMetadataServer(t, map[string]*SignedRole{
		"timestamp": role,
	})
	client := newTUFHTTPClientForTest(server.URL)

	if _, err := client.fetchAndVerify(TUFRoleTimestamp); err == nil {
		t.Fatal("expected tampered metadata signature to fail")
	}
}

func TestTUFClient_fetchAndVerifyHonorsTrustedRootThreshold(t *testing.T) {
	server := newTUFMetadataServer(t, map[string]*SignedRole{
		"timestamp": signedRoleForTUFTest("timestamp", 1, time.Now().Add(time.Hour), nil),
	})
	client := newTUFHTTPClientForTest(server.URL)
	client.localMetadata = &TUFMetadata{
		Root: &SignedRole{
			Signed: mustMarshal(RootMetadata{
				Roles: map[string]Role{
					string(TUFRoleTimestamp): {Threshold: 2},
				},
			}),
		},
	}

	if _, err := client.fetchAndVerify(TUFRoleTimestamp); err == nil {
		t.Fatal("expected threshold failure")
	}
}

func TestTUFClient_VerifyDelegationEdges(t *testing.T) {
	if err := (&TUFClient{}).VerifyDelegation("certified", "pack"); err == nil {
		t.Fatal("expected missing metadata error")
	}
	bad := &TUFClient{localMetadata: &TUFMetadata{Targets: &SignedRole{Signed: []byte(`{`)}}}
	if err := bad.VerifyDelegation("certified", "pack"); err == nil {
		t.Fatal("expected malformed targets error")
	}
	noDelegations := &TUFClient{localMetadata: &TUFMetadata{Targets: &SignedRole{Signed: mustMarshal(TargetsMetadata{})}}}
	if err := noDelegations.VerifyDelegation("certified", "pack"); err == nil {
		t.Fatal("expected missing delegations error")
	}
	missingRole := &TUFClient{localMetadata: &TUFMetadata{Targets: &SignedRole{Signed: mustMarshal(TargetsMetadata{Delegations: &Delegations{Roles: []DelegatedRole{{Name: "community", Paths: []string{"*"}}}}})}}}
	if err := missingRole.VerifyDelegation("certified", "pack"); err == nil {
		t.Fatal("expected missing delegation role error")
	}
	pathMismatch := &TUFClient{localMetadata: &TUFMetadata{Targets: &SignedRole{Signed: mustMarshal(TargetsMetadata{Delegations: &Delegations{Roles: []DelegatedRole{{Name: "certified", Paths: []string{"other"}}}}})}}}
	if err := pathMismatch.VerifyDelegation("certified", "pack"); err == nil {
		t.Fatal("expected delegation path mismatch error")
	}
}

func mustMarshal(v interface{}) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

type memoryTUFTrustStore struct {
	metadata *TUFMetadata
	loadErr  error
	saveErr  error
	saved    bool
}

func (s *memoryTUFTrustStore) Load() (*TUFMetadata, error) {
	return s.metadata, s.loadErr
}

func (s *memoryTUFTrustStore) Save(metadata *TUFMetadata) error {
	s.saved = true
	s.metadata = metadata
	return s.saveErr
}

func newTUFHTTPClientForTest(remoteURL string) *TUFClient {
	pub, _ := tufTestRootKey()
	return &TUFClient{
		remoteURL:  remoteURL,
		rootKeys:   []crypto.PublicKey{pub},
		httpClient: http.DefaultClient,
	}
}

func signedRoleForTUFTest(role string, version int, expires time.Time, metadata interface{}) *SignedRole {
	var signed json.RawMessage
	if metadata != nil {
		signed = mustMarshal(metadata)
	} else {
		signed = mustMarshal(RoleMetadata{Type: role, Version: version, Expires: expires})
	}
	return &SignedRole{
		Signed:     signed,
		Signatures: []TUFSignature{signTUFTestPayload(signed)},
	}
}

func signTUFTestPayload(signed json.RawMessage) TUFSignature {
	_, priv := tufTestRootKey()
	hash := sha256.Sum256(signed)
	sig := ed25519.Sign(priv, hash[:])
	return TUFSignature{
		KeyID:     tufTestRootKeyID(),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
}

func tufTestRootKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv
}

func tufTestRootKeyID() string {
	pub, _ := tufTestRootKey()
	keyID, err := ComputeKeyID(pub)
	if err != nil {
		panic(err)
	}
	return keyID
}

func newTUFMetadataServer(t *testing.T, roles map[string]*SignedRole) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), ".json")
		signed, ok := roles[role]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if err := json.NewEncoder(w).Encode(signed); err != nil {
			t.Errorf("Encode %s: %v", role, err)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

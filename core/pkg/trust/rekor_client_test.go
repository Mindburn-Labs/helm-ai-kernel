package trust

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewRekorClient(t *testing.T) {
	t.Run("requires log URL", func(t *testing.T) {
		_, err := NewRekorClient(RekorClientConfig{})
		if err == nil {
			t.Error("expected error for missing log URL")
		}
	})

	t.Run("creates client with valid config", func(t *testing.T) {
		client, err := NewRekorClient(RekorClientConfig{
			LogURL: "https://rekor.sigstore.dev",
		})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if client == nil {
			t.Error("expected non-nil client")
		}
	})
}

func TestRekorClient_verifyInclusionProof(t *testing.T) {
	client := &RekorClient{
		logURL: "https://rekor.sigstore.dev",
	}

	t.Run("rejects nil inclusion proof", func(t *testing.T) {
		entry := &RekorEntry{
			LogIndex:       1,
			InclusionProof: nil,
		}

		err := client.verifyInclusionProof(entry)
		if err == nil {
			t.Error("expected error for nil inclusion proof")
		}
	})

	t.Run("verifies valid inclusion proof", func(t *testing.T) {
		// Create a simple valid proof for a single-element tree
		// The verifier JSON-marshals entry.Body, so we need to match that
		body := RekorBody{
			Kind:       "helmpack",
			APIVersion: "v1",
		}

		// Marshal like the verifier does
		leafData, _ := json.Marshal(body)
		leafHash := computeLeafHash(leafData)

		entry := &RekorEntry{
			LogIndex: 0,
			Body:     body,
			InclusionProof: &InclusionProof{
				LogIndex: 0,
				RootHash: leafHash, // For single element, root = leaf
				TreeSize: 1,
				Hashes:   []string{}, // No siblings needed for single element
			},
		}

		err := client.verifyInclusionProof(entry)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestRekorClient_verifySignedTreeHead(t *testing.T) {
	t.Run("detects tree size regression", func(t *testing.T) {
		client := &RekorClient{
			trustedRoot: &SignedTreeHead{
				TreeSize: 100,
				RootHash: "abc123",
			},
		}

		entry := &RekorEntry{
			InclusionProof: &InclusionProof{
				TreeSize: 50, // Smaller than trusted
				RootHash: "def456",
			},
		}

		err := client.verifySignedTreeHead(entry)
		if err == nil {
			t.Error("expected error for tree size regression")
		}
	})

	t.Run("allows tree growth", func(t *testing.T) {
		client := &RekorClient{
			trustedRoot: &SignedTreeHead{
				TreeSize: 100,
				RootHash: "abc123",
			},
		}

		entry := &RekorEntry{
			InclusionProof: &InclusionProof{
				TreeSize: 150, // Larger than trusted
				RootHash: "def456",
			},
		}

		err := client.verifySignedTreeHead(entry)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestComputeLeafHash(t *testing.T) {
	data := []byte("test data")
	hash := computeLeafHash(data)

	// Should be base64 encoded
	_, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		t.Errorf("hash should be valid base64: %v", err)
	}

	// Should be deterministic
	hash2 := computeLeafHash(data)
	if hash != hash2 {
		t.Error("hash should be deterministic")
	}
}

func TestComputeRootFromProof(t *testing.T) {
	t.Run("returns leaf hash for empty proof", func(t *testing.T) {
		leafHash := base64.StdEncoding.EncodeToString([]byte("leaf"))

		root, err := computeRootFromProof(0, 1, leafHash, []string{})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if root != leafHash {
			t.Error("root should equal leaf for empty proof")
		}
	})

	t.Run("computes root with single sibling", func(t *testing.T) {
		leafHash := computeLeafHash([]byte("left"))
		siblingHash := computeLeafHash([]byte("right"))

		root, err := computeRootFromProof(0, 2, leafHash, []string{siblingHash})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		// Root should be different from inputs
		if root == leafHash || root == siblingHash {
			t.Error("root should combine both hashes")
		}
	})
}

func TestVerifyInclusionProofBytes(t *testing.T) {
	t.Run("rejects nil proof", func(t *testing.T) {
		err := VerifyInclusionProofBytes([]byte("data"), nil)
		if err == nil {
			t.Error("expected error for nil proof")
		}
	})

	t.Run("verifies matching proof", func(t *testing.T) {
		leafData := []byte("test leaf data")
		leafHash := computeLeafHash(leafData)

		proof := &InclusionProof{
			LogIndex: 0,
			RootHash: leafHash,
			TreeSize: 1,
			Hashes:   []string{},
		}

		err := VerifyInclusionProofBytes(leafData, proof)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("rejects mismatched root", func(t *testing.T) {
		leafData := []byte("test leaf data")

		proof := &InclusionProof{
			LogIndex: 0,
			RootHash: "wrong-root-hash",
			TreeSize: 1,
			Hashes:   []string{},
		}

		err := VerifyInclusionProofBytes(leafData, proof)
		if err == nil {
			t.Error("expected error for root mismatch")
		}
	})
}

func TestGetCheckpointRef(t *testing.T) {
	client := &RekorClient{}

	entry := &RekorEntry{
		LogID:    "rekor.sigstore.dev",
		LogIndex: 12345,
		InclusionProof: &InclusionProof{
			TreeSize: 100000,
			RootHash: "abc123xyz",
		},
	}

	ref := client.GetCheckpointRef(entry)

	if ref.LogID != entry.LogID {
		t.Errorf("wrong LogID: %s", ref.LogID)
	}
	if ref.LogIndex != entry.LogIndex {
		t.Errorf("wrong LogIndex: %d", ref.LogIndex)
	}
	if ref.TreeSize != entry.InclusionProof.TreeSize {
		t.Errorf("wrong TreeSize: %d", ref.TreeSize)
	}
	if ref.RootHash != entry.InclusionProof.RootHash {
		t.Errorf("wrong RootHash: %s", ref.RootHash)
	}
	if ref.VerifiedAt.IsZero() {
		t.Error("VerifiedAt should be set")
	}
}

func TestRekorClientHTTPFlows(t *testing.T) {
	body := RekorBody{Kind: "helmpack", APIVersion: "v1"}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	leafHash := computeLeafHash(bodyBytes)
	entry := RekorEntry{
		LogID:          RekorLogID,
		LogIndex:       0,
		IntegratedTime: 1700000000,
		Body:           body,
		InclusionProof: &InclusionProof{
			LogIndex: 0,
			RootHash: leafHash,
			TreeSize: 1,
			Hashes:   []string{},
		},
	}

	t.Run("VerifyEntry succeeds through search and fetch", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v1/index/retrieve":
				if r.Method != http.MethodPost {
					t.Fatalf("search method = %s", r.Method)
				}
				_ = json.NewEncoder(w).Encode([]string{"entry-1"})
			case "/api/v1/log/entries/entry-1":
				_ = json.NewEncoder(w).Encode(map[string]RekorEntry{"entry-1": entry})
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()

		client, err := NewRekorClient(RekorClientConfig{LogURL: server.URL})
		if err != nil {
			t.Fatalf("NewRekorClient: %v", err)
		}
		got, err := client.VerifyEntry("sha256:abc")
		if err != nil {
			t.Fatalf("VerifyEntry: %v", err)
		}
		if got.LogID != RekorLogID {
			t.Fatalf("entry = %+v", got)
		}
	})

	t.Run("search handles non-success bad json and empty ids", func(t *testing.T) {
		tests := []struct {
			name    string
			handler http.HandlerFunc
		}{
			{
				name: "server error",
				handler: func(w http.ResponseWriter, r *http.Request) {
					http.Error(w, "broken", http.StatusInternalServerError)
				},
			},
			{
				name: "bad json",
				handler: func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write([]byte("{"))
				},
			},
			{
				name: "empty ids",
				handler: func(w http.ResponseWriter, r *http.Request) {
					_ = json.NewEncoder(w).Encode([]string{})
				},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				server := httptest.NewServer(tt.handler)
				defer server.Close()
				client, err := NewRekorClient(RekorClientConfig{LogURL: server.URL})
				if err != nil {
					t.Fatalf("NewRekorClient: %v", err)
				}
				if _, err := client.searchByHash("sha256:abc"); err == nil {
					t.Fatal("expected search error")
				}
			})
		}
	})

	t.Run("search handles request construction and transport errors", func(t *testing.T) {
		badRequest := &RekorClient{logURL: "http://[::1", httpClient: http.DefaultClient}
		if _, err := badRequest.searchByHash("sha256:abc"); err == nil {
			t.Fatal("expected request construction error")
		}

		transportError := &RekorClient{
			logURL: "https://rekor.invalid",
			httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, assertAnError{}
			})},
		}
		if _, err := transportError.searchByHash("sha256:abc"); err == nil {
			t.Fatal("expected transport error")
		}
	})

	t.Run("fetch handles non-success bad json fallback and missing entry", func(t *testing.T) {
		tests := []struct {
			name    string
			handler http.HandlerFunc
			wantOK  bool
		}{
			{
				name: "server error",
				handler: func(w http.ResponseWriter, r *http.Request) {
					http.Error(w, "missing", http.StatusNotFound)
				},
			},
			{
				name: "bad json",
				handler: func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write([]byte("{"))
				},
			},
			{
				name: "fallback first entry",
				handler: func(w http.ResponseWriter, r *http.Request) {
					_ = json.NewEncoder(w).Encode(map[string]RekorEntry{"other": entry})
				},
				wantOK: true,
			},
			{
				name: "empty map",
				handler: func(w http.ResponseWriter, r *http.Request) {
					_ = json.NewEncoder(w).Encode(map[string]RekorEntry{})
				},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				server := httptest.NewServer(tt.handler)
				defer server.Close()
				client, err := NewRekorClient(RekorClientConfig{LogURL: server.URL})
				if err != nil {
					t.Fatalf("NewRekorClient: %v", err)
				}
				got, err := client.fetchEntry("entry-1")
				if tt.wantOK {
					if err != nil || got == nil {
						t.Fatalf("fetchEntry got %+v err=%v", got, err)
					}
					return
				}
				if err == nil {
					t.Fatal("expected fetch error")
				}
			})
		}
	})

	t.Run("VerifyEntry reports inclusion and tree-head failures", func(t *testing.T) {
		noProof := entry
		noProof.InclusionProof = nil
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v1/index/retrieve":
				_ = json.NewEncoder(w).Encode([]string{"entry-1"})
			case "/api/v1/log/entries/entry-1":
				_ = json.NewEncoder(w).Encode(map[string]RekorEntry{"entry-1": noProof})
			default:
				http.NotFound(w, r)
			}
		}))
		defer server.Close()
		client, err := NewRekorClient(RekorClientConfig{LogURL: server.URL})
		if err != nil {
			t.Fatalf("NewRekorClient: %v", err)
		}
		if _, err := client.VerifyEntry("sha256:abc"); err == nil {
			t.Fatal("expected inclusion proof failure")
		}

		regressionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v1/index/retrieve":
				_ = json.NewEncoder(w).Encode([]string{"entry-1"})
			case "/api/v1/log/entries/entry-1":
				_ = json.NewEncoder(w).Encode(map[string]RekorEntry{"entry-1": entry})
			default:
				http.NotFound(w, r)
			}
		}))
		defer regressionServer.Close()
		client, err = NewRekorClient(RekorClientConfig{
			LogURL:      regressionServer.URL,
			TrustedRoot: &SignedTreeHead{TreeSize: 2},
		})
		if err != nil {
			t.Fatalf("NewRekorClient regression: %v", err)
		}
		if _, err := client.VerifyEntry("sha256:abc"); err == nil {
			t.Fatal("expected signed tree head failure")
		}
	})
}

func TestRekorClientAdditionalProofEdges(t *testing.T) {
	client := &RekorClient{}

	if err := client.verifySignedTreeHead(&RekorEntry{}); err == nil {
		t.Fatal("expected missing proof error")
	}
	if _, err := computeRootFromProof(0, 1, "not-base64", []string{"also-not-base64"}); err == nil {
		t.Fatal("expected leaf decode error")
	}
	leafHash := computeLeafHash([]byte("right"))
	if _, err := computeRootFromProof(1, 2, leafHash, []string{"not-base64"}); err == nil {
		t.Fatal("expected proof decode error")
	}

	left := computeLeafHash([]byte("left"))
	right := computeLeafHash([]byte("right"))
	if _, err := computeRootFromProof(1, 2, right, []string{left}); err != nil {
		t.Fatalf("odd-index proof: %v", err)
	}

	if err := VerifyInclusionProofBytes([]byte("leaf"), &InclusionProof{
		LogIndex: 0,
		RootHash: "unused",
		TreeSize: 1,
		Hashes:   []string{"not-base64"},
	}); err == nil {
		t.Fatal("expected proof decode error")
	}

	mismatch := &RekorEntry{
		Body: RekorBody{Kind: "helmpack"},
		InclusionProof: &InclusionProof{
			LogIndex: 0,
			RootHash: "wrong-root",
			TreeSize: 1,
			Hashes:   []string{},
		},
	}
	if err := client.verifyInclusionProof(mismatch); err == nil {
		t.Fatal("expected inclusion root mismatch")
	}
}

type assertAnError struct{}

func (assertAnError) Error() string {
	return "transport failed"
}
